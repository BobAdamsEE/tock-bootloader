//! Boot-entry logic shared by every SAMV71 board: the memory map, the CAN
//! identity, the ways of asking to stay in the bootloader, and rollback.
//!
//! What differs between boards is passed in, so that a board's `main.rs` holds
//! its wiring and its policy and nothing else.

use kernel::hil;
use kernel::static_init;

use samv71q21b::efc::Efc;

/// CAN identifiers for the bootloader, ISO 15765-2 normal fixed addressing.
/// Target 0x41, tester 0xF1. Not a legislated OBD-II address.
pub const CAN_REQUEST_ID: u32 = 0x18DA_41F1;
pub const CAN_RESPONSE_ID: u32 = 0x18DA_F141;

/// Watchdog period, milliseconds.
///
/// Chosen against the slowest thing that legitimately runs without yielding,
/// which is a flash erase: ~0.6 s for the 192 KB kernel region, so ~5.6 s if
/// the whole 1792 KB application region is ever erased in one command. Eight
/// seconds clears that with room to spare while still catching a hang in a
/// useful time. The flash driver also pets the watchdog per page, so an erase
/// of any size is bounded by a single page operation rather than by the total.
///
/// The counter is clocked at SLCK/128 and WDV is 12 bits, so 16 s is the
/// ceiling; there is not much headroom above this value.
pub const WATCHDOG_PERIOD_MS: u32 = 8000;

/// Start of the kernel region; matches `prog` in layout.ld.
pub const KERNEL_START: u32 = 0x0001_0000;

/// Page holding the kernel integrity descriptor.
///
/// Placement is more constrained than it looks. The kernel region has content
/// at **both** ends: the image from 0x10000 (~87 KB), and Tock's kernel
/// attributes block at the very top, ending at 0x40000 with a "TOCK" magic --
/// which is how `tockloader` locates it. The descriptor has to miss both.
///
/// It also has to own its erase block outright. The EFC erases 16 pages (8 KB)
/// at a time, so writing this page erases everything from 0x3C000 to 0x3E000;
/// anything else living there would be destroyed. 0x3C000 is block-aligned and
/// that block is empty in every build so far.
///
/// The bounds this assumes, both checked or enforced elsewhere:
///   * the kernel image stays below 0x3C000 (176 KB; it is 87 KB today), and
///     `kernel_integrity::check` refuses a descriptor claiming otherwise
///   * the attributes block stays above 0x3E000
pub const KERNEL_DESCRIPTOR: u32 = 0x0003_C000;

/// Cold backup of the kernel, never executed where it lies.
///
/// The kernel is linked EXEC at KERNEL_START and is not position independent,
/// so this cannot simply be booted in place -- rollback copies it down over the
/// active slot. It mirrors the active region byte for byte, including the
/// descriptor at the same offset, so that any kernel fitting one fits the
/// other and the same `kernel_integrity::check` works on both.
pub const KERNEL_BACKUP: u32 = 0x0004_0000;
pub const KERNEL_BACKUP_DESCRIPTOR: u32 = KERNEL_BACKUP + (KERNEL_DESCRIPTOR - KERNEL_START);

/// End of the kernel region, and the size the backup mirrors.
pub const KERNEL_REGION_END: u32 = 0x0004_0000;

/// Reset Controller status register, and the value its `RSTTYP` field takes
/// for a user reset -- a high-to-low edge on NRST, which here means the button.
///
/// The others are 0 general (power-up), 1 backup, 2 watchdog and 3 software.
/// None of them is somebody standing at the board asking for the bootloader,
/// so none of them arms the window.
///
/// Reading `RSTC_SR` clears its `URSTS` bit as a side effect. Nothing else in
/// this bootloader reads that register, so there is nothing to disturb.
const RSTC_SR: u32 = 0x400E_1804;
const RSTTYP_USER_RESET: u32 = 4;

/// Word of SRAM holding `DOUBLE_RESET_MAGIC` while the window is open.
///
/// The linker reserves the top 16 bytes of SRAM for it -- the `retained`
/// region in layout.ld -- so startup does not zero it and it survives the
/// reset it exists to detect.
const DOUBLE_RESET_LOCATION: u32 = 0x2045_FFF0;

/// Value written there while the window is open. Taken, along with the scheme,
/// from the Adafruit nRF52 bootloader.
const DOUBLE_RESET_MAGIC: u32 = 0x005A_1AD5;

/// How many of the three `FLASH_EN` samples must read low to count as asserted.
///
/// Three -- the line is active low. Exists as a constant only so the assert
/// path can be exercised on a board where `FLASH_EN` is not wired: setting it
/// to 0 makes the *unconnected, pulled-up* pin count as asserted, which drives
/// every step of the check except the external signal itself. Leave it at 3.
const FLASH_EN_ASSERTED_LOW_COUNT: u32 = 3;

/// TC0 runs from the 32 kHz slow clock.
const TC_TICKS_PER_SECOND: u32 = 32_768;

/// What has to arrive to hold the board in the bootloader.
///
/// A single-frame ISO-TP `DiagnosticSessionControl(programming)` -- the same
/// request that asks the *application* to hand over, so the knock and the
/// normal path mean the same thing to a tester. Requiring a specific payload
/// rather than any frame on the request identifier keeps ordinary traffic, and
/// a tester probing with `TesterPresent`, from wedging the board in the
/// bootloader by accident.
const CAN_KNOCK: [u8; 3] = [0x02, 0x10, 0x02];

/// Configure MCAN1 for this board: 500 kbit/s arbitration, 2 Mbit/s data,
/// normal mode, and the acceptance filter for our request identifier.
///
/// Shared by the entry window and the ISO-TP transport, which must agree: a
/// window that listened with different bit timing would answer nothing and
/// look like a hardware fault.
pub fn configure_mcan(mcan: &samv71q21b::mcan::Mcan) {
    use kernel::hil::can::{Configure, ConfigureFd, Filter};

    // Must be set while the peripheral is still Disabled. Without it the
    // controller abandons a frame after one lost arbitration, which on a busy
    // bus means requests silently vanish.
    let _ = mcan.set_automatic_retransmission(true);
    let _ = mcan.set_bitrate(500_000);

    // CAN FD: 500 kbit/s arbitration, 2 Mbit/s data phase.
    //
    // PCK5 is 20 MHz, so 2 Mbit/s is 10 time quanta. Segments are written in
    // the register's "minus one" encoding, hence 6 and 1 for 7 and 2:
    //
    //   1 (sync) + 7 (seg1) + 2 (seg2) = 10 tq  ->  20 MHz / 10 = 2 Mbit/s
    //   sample point (1 + 7) / 10 = 80%
    //
    // 80% rather than the arbitration phase's 87.5% because the data phase has
    // no arbitration to resolve and a slightly earlier sample buys tolerance to
    // the transceiver loop delay. Setting this is also what puts the driver
    // into FD mode -- there is no separate switch.
    let _ = ConfigureFd::set_payload_bit_timing(
        mcan,
        kernel::hil::can::BitTiming {
            segment1: 6,
            segment2: 1,
            // M_CAN folds propagation delay into DTSEG1; there is no separate
            // field in DBTP, so this stays zero and the delay is already
            // accounted for in segment1 above.
            propagation: 0,
            sync_jump_width: 0,
            baud_rate_prescaler: 0,
        },
    );

    let _ = mcan.set_operation_mode(kernel::hil::can::OperationMode::Normal);

    // Accept the physical request identifier addressed to this node. 29-bit
    // normal fixed addressing: 0x18DA<target><source>, so 0x18DA41F1 is
    // "tester 0xF1 -> target 0x41". Deliberately not an OBD-II legislated
    // address: this board transmits as a tester at 0x18DB33F1 when running the
    // kernel, and answering the legislated addresses would collide with real
    // ECUs.
    let _ = mcan.enable_filter(kernel::hil::can::FilterParameters {
        number: 4,
        scale_bits: kernel::hil::can::ScaleBits::Bits32,
        identifier_mode: kernel::hil::can::IdentifierMode::List,
        fifo_number: 0,
        id: kernel::hil::can::Id::Extended(CAN_REQUEST_ID),
        mask: 0x1FFF_FFFF,
    });
}

/// Is the `FLASH_EN` line being held low?
///
/// A boot with the line released costs a clock enable, a pull-up settle and
/// three register reads -- call it tens of microseconds against the CAN window's
/// hundreds of milliseconds. That is the whole argument for preferring it where
/// the hardware has the line.
///
/// Entry has to be deliberate, so after those reads the pin must stay low for
/// `hold_ms`, measured on `tc`. Only a boot that is already reading low pays for
/// it. Zero skips the hold.
///
/// Reads the pin three times and requires agreement. A line long enough to
/// leave the board is long enough to pick up a transient, and the consequence
/// of a false read in either direction is bad: a spurious low strands a healthy
/// board in the bootloader, and a spurious high ignores an operator who is
/// standing there asking for it.
///
/// `pull` is the board's choice. Without an external pull-up the internal one
/// is the safety net, not the signal: an unconnected line must read high and
/// let the board boot. With an external one the internal one has to stay off,
/// as it would sit in parallel and raise the level a held line can reach.
pub fn flash_en_asserted(
    pin: &samv71q21b::gpio::GPIOPin<'static>,
    pull: kernel::hil::gpio::FloatingState,
    tc: &samv71q21b::tc::Tc<'static>,
    hold_ms: u32,
) -> bool {
    use kernel::hil::gpio::Configure;
    use kernel::hil::time::{Counter, Ticks, Time};

    pin.make_input();
    pin.set_floating_state(pull);

    // Let the pull-up charge whatever capacitance the line has before trusting
    // the first sample.
    for _ in 0..10_000 {
        cortexm7::support::nop();
    }

    let mut low = 0;
    for _ in 0..3 {
        if !pin.read() {
            low += 1;
        }
        for _ in 0..1_000 {
            cortexm7::support::nop();
        }
    }
    if low != FLASH_EN_ASSERTED_LOW_COUNT {
        return false;
    }
    if hold_ms == 0 {
        return true;
    }

    let _ = tc.start();
    let started = tc.now().into_u32();
    let hold = (hold_ms * TC_TICKS_PER_SECOND) / 1000;
    while tc_elapsed(tc, started) < hold {
        if pin.read() {
            return false;
        }
    }
    true
}

/// TC0 ticks elapsed since `started`, correct across the counter's rollover.
///
/// `Tc` presents a 32-bit counter, but its high half only advances inside the
/// overflow interrupt -- and nothing services interrupts here, before
/// `kernel_loop`. So throughout the entry windows the value really is the
/// 16-bit hardware counter, which rolls over about every two seconds at
/// 32 kHz. Subtracting those as `u32` yields a number near 2^32 the moment it
/// rolls, which reads as "window expired" and cuts the window short: a one in
/// twenty chance for the CAN window, one in four for the longer double-reset
/// one. Subtracting as `u16` is right either way, because the low half is the
/// hardware counter whether or not the high half is moving.
///
/// The ceiling this leaves is one rollover: any window under two seconds
/// measures correctly, and nothing here wants more.
fn tc_elapsed(tc: &samv71q21b::tc::Tc<'static>, started: u32) -> u32 {
    use kernel::hil::time::{Ticks, Time};

    (tc.now().into_u32() as u16).wrapping_sub(started as u16) as u32
}

/// Did the operator press reset twice in quick succession?
///
/// A word of SRAM survives the reset. The first press finds it empty, writes
/// the magic and waits; if a second press lands inside the window the board
/// comes back up with the magic still there and this returns true on the way
/// through. If the window closes first the word is cleared and the board boots
/// normally, so a single press costs the window and nothing else.
///
/// Gated on `RSTTYP` so only a press of NRST takes part. Without that gate the
/// window would be added to every boot -- including the software reset that
/// ends every `uds_flash.py --reset`, and the watchdog resets the boot-attempt
/// counter depends on -- half a second each, waiting for a signal that could
/// not have been sent. The gate is what buys a window long enough to use.
///
/// Unlike the CAN window this needs no peripheral beyond the timer, and unlike
/// `FLASH_EN` it needs no wiring. It is the escape hatch that works on a bare
/// board with nothing attached.
pub fn double_reset_requested(tc: &samv71q21b::tc::Tc<'static>, window_ms: u32) -> bool {
    use kernel::hil::time::{Counter, Ticks, Time};

    if window_ms == 0 {
        return false;
    }

    // Nothing but NRST takes part in this, on either side of the pair. Testing
    // that before reading the scratch word is what makes the word trustworthy:
    // SRAM contents after a power cycle are undefined, and a stale magic left
    // by a window that was interrupted by pulling the plug would otherwise
    // send the next power-up into the bootloader for no reason.
    let rsttyp = (unsafe { core::ptr::read_volatile(RSTC_SR as *const u32) } >> 8) & 0x7;
    if rsttyp != RSTTYP_USER_RESET {
        return false;
    }

    let scratch = DOUBLE_RESET_LOCATION as *mut u32;

    // A second press, inside the window the last one opened. Consume the magic
    // so that a third reset starts a fresh pair rather than latching here.
    if unsafe { core::ptr::read_volatile(scratch) } == DOUBLE_RESET_MAGIC {
        unsafe { core::ptr::write_volatile(scratch, 0) };
        return true;
    }

    // First press: arm, and hold the boot for the window. A reset arriving
    // before it closes is caught by the check above on the way back in.
    unsafe { core::ptr::write_volatile(scratch, DOUBLE_RESET_MAGIC) };

    let _ = tc.start();
    let started = tc.now().into_u32();
    let window = (window_ms * TC_TICKS_PER_SECOND) / 1000;
    while tc_elapsed(tc, started) < window {}

    unsafe { core::ptr::write_volatile(scratch, 0) };
    false
}

/// Listen on CAN for `window_ms`; return whether anyone knocked. Zero disables
/// the window entirely, MCAN bring-up included.
///
/// Polled rather than interrupt-driven on purpose: this runs before
/// `kernel_loop`, so nothing services an interrupt and the receive callbacks
/// would never fire. `Mcan::poll_receive` reads the same FIFO the callback path
/// reads, and reception into that FIFO depends on the filters rather than on
/// interrupt enables.
///
/// Leaves the controller back in init mode either way. On the jump path that
/// matters: the kernel configures MCAN1 from scratch and would find a
/// half-configured peripheral otherwise. On the stay path the transport
/// reconfigures it a moment later, so the extra cycle costs nothing.
pub fn can_entry_requested(
    mcan: &samv71q21b::mcan::Mcan,
    tc: &samv71q21b::tc::Tc<'static>,
    window_ms: u32,
) -> bool {
    use kernel::hil::time::{Counter, Ticks, Time};

    if window_ms == 0 {
        return false;
    }

    configure_mcan(mcan);
    if mcan.hw_enable_blocking().is_err() {
        // No bus, no escape hatch -- but never a reason not to boot.
        mcan.hw_disable_blocking();
        return false;
    }

    let _ = tc.start();
    let started = tc.now().into_u32();
    let window = (window_ms * TC_TICKS_PER_SECOND) / 1000;

    let mut knocked = false;
    loop {
        if let Some((id, data, len)) = mcan.poll_receive() {
            // `can::Id` has no `PartialEq`, hence the match rather than `==`.
            let ours = matches!(
                id,
                kernel::hil::can::Id::Extended(value) if value == CAN_REQUEST_ID
            );
            if ours && len >= CAN_KNOCK.len() && data[..CAN_KNOCK.len()] == CAN_KNOCK {
                knocked = true;
                break;
            }
        }
        if tc_elapsed(tc, started) >= window {
            break;
        }
    }

    mcan.hw_disable_blocking();
    knocked
}

/// Static page buffer for the slot copier. One buffer, taken and returned per
/// page; see `kernel_slot`.
static mut ROLLBACK_PAGE: samv71q21b::efc::Sam71Page =
    samv71q21b::efc::Sam71Page([0; samv71q21b::efc::PAGE_SIZE]);

/// Restore the backup over the active slot, if the backup is worth restoring.
///
/// Returns whether the caller should carry on booting. `false` means there was
/// nothing good to fall back to, and the board should hold in the bootloader.
///
/// Runs before any of the servers are wired up, which is deliberate: this is
/// the last chance to fix the kernel before the decision to jump, and the EFC
/// is already initialised by this point. It does not return on success -- the
/// board resets so the whole entry sequence, integrity check included, runs
/// again against the restored image rather than trusting this copy blindly.
pub fn try_rollback(efc: &'static Efc) -> bool {
    use bootloader::kernel_integrity::Verdict;

    // Only roll back to something that passes the same check the active slot
    // just failed. A backup that is itself corrupt is not an improvement.
    let (length, ok) = match bootloader::kernel_integrity::describe(
        KERNEL_BACKUP,
        KERNEL_BACKUP_DESCRIPTOR,
    ) {
        (Verdict::Match, len) => (len, true),
        _ => (0, false),
    };
    if !ok {
        return false;
    }

    let copier = unsafe {
        let page = &mut *core::ptr::addr_of_mut!(ROLLBACK_PAGE);
        static_init!(
            bootloader::kernel_slot::SlotCopier<'static, Efc>,
            bootloader::kernel_slot::SlotCopier::new(efc, page)
        )
    };
    hil::flash::HasClient::set_client(efc, copier);

    // The image first, then the descriptor that vouches for it. Losing power
    // between the two leaves the active slot without a valid descriptor, which
    // reads as "do not trust this" rather than as a stale claim that a
    // half-copied image is fine.
    let bytes = (KERNEL_REGION_END - KERNEL_START) as usize;
    if copier.copy(KERNEL_BACKUP, KERNEL_START, bytes).is_err() {
        return false;
    }
    let _ = length;

    // The descriptor came across with the rest of the region, since it lives at
    // the same offset in both slots -- so the active slot now describes itself
    // correctly with no extra write.
    unsafe {
        cortexm7::scb::reset();
    }
    #[allow(unreachable_code)]
    true
}
