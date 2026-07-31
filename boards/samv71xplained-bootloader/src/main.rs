//! Tock bootloader for the SAMV71 Xplained Ultra evaluation board.
//!
//! Hardware:
//!   - ATSAMV71Q21B, Cortex-M7, 300 MHz PCK / 150 MHz MCK
//!   - EDBG UART: USART1, RXD=PA21 (periph A), TXD=PB4 (periph D), 115200 baud
//!   - 2 MB internal flash (512-byte pages), 384 KB SRAM at 0x20400000
//!
//! Bootloader entry. The first four conditions set the entry magic in GPBR7;
//! the last two are read straight out of the backup registers by
//! `BootloaderEntryGpRegRet`. Any one of them holds the board here.
//!
//!   1. The kernel failed its integrity check and no backup was worth
//!      restoring -- see `kernel_integrity` and `try_rollback`.
//!   2. `FLASH_EN` held low -- see `FLASH_EN_PIN`.
//!   3. Two NRST presses inside `DOUBLE_RESET_WINDOW_MS`.
//!   4. A CAN knock inside `CAN_ENTRY_WINDOW_MS` -- see `CAN_KNOCK`.
//!   5. GPBR7 >= 0x90: the kernel, or a debugger, asked for the bootloader.
//!   6. GPBR6 >= 3: three boots without the kernel reporting itself healthy.

#![no_std]
#![cfg_attr(not(doc), no_main)]

mod flash_passthrough;

/// CAN identifiers for the bootloader, ISO 15765-2 normal fixed addressing.
/// Target 0x41, tester 0xF1. Not a legislated OBD-II address.
const CAN_REQUEST_ID: u32 = 0x18DA_41F1;
const CAN_RESPONSE_ID: u32 = 0x18DA_F141;

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
const WATCHDOG_PERIOD_MS: u32 = 8000;

/// Start of the kernel region; matches `prog` in layout.ld.
const KERNEL_START: u32 = 0x0001_0000;

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
const KERNEL_DESCRIPTOR: u32 = 0x0003_C000;

/// Cold backup of the kernel, never executed where it lies.
///
/// The kernel is linked EXEC at KERNEL_START and is not position independent,
/// so this cannot simply be booted in place -- rollback copies it down over the
/// active slot. It mirrors the active region byte for byte, including the
/// descriptor at the same offset, so that any kernel fitting one fits the
/// other and the same `kernel_integrity::check` works on both.
const KERNEL_BACKUP: u32 = 0x0004_0000;
const KERNEL_BACKUP_DESCRIPTOR: u32 = KERNEL_BACKUP + (KERNEL_DESCRIPTOR - KERNEL_START);

/// End of the kernel region, and the size the backup mirrors.
const KERNEL_REGION_END: u32 = 0x0004_0000;

use core::panic::PanicInfo;

use kernel::capabilities;
use kernel::hil;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::process::ProcessSlot;
use kernel::{create_capability, static_init};

use bootloader::null_scheduler::NullScheduler;

use bootloader_samv71::bootloader_entry_gpbr::BootloaderEntryGpRegRet;

use samv71q21b::chip::{Atsamv71q21b, Atsamv71q21bDefaultPeripherals};
use samv71q21b::efc::Efc;
use samv71q21b::gpio::PeripheralFunction;
use samv71q21b::gpbr::Gpbr;
use samv71q21b::pmc;
use samv71q21b::uart::Usart1;
use samv71q21b::xdmac;

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

const NUM_PROCS: usize = 0;

static mut PROCESSES: [ProcessSlot; NUM_PROCS] = [];

static mut CHIP: Option<&'static Atsamv71q21b<Atsamv71q21bDefaultPeripherals>> = None;

// Placed by the linker script. Both servers reach the attribute table and the
// flags through these rather than through hard-coded addresses, which is what
// lets the table move without touching either of them.
//
// `_relocated_*` rather than the conventional `_flags_address` /
// `_attributes_address`: this board puts the table in its own erase block at
// 0xE000 so that it can be rewritten at runtime. See layout.ld.
extern "C" {
    static _relocated_flags_address: u8;
    static _relocated_attributes_address: u8;
    static _etext: u8;
}

/// Reserve stack space (8 KB).
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x4000] = [0; 0x4000];

/// Bootloader flags at _relocated_flags_address (0xE000).
/// - Offset 14: version string (up to 8 bytes, null-terminated)
/// - Offset 32: kernel start address (4 bytes, little-endian)
///
/// The start address here is what `tockloader` reads and writes. This board
/// does *not* boot from it -- it jumps to `KERNEL_START`, a constant -- so
/// changing it changes what a tester reads back, not what runs.
#[used]
#[link_section = ".flags_relocated"]
static BOOTLOADER_FLAGS: [u8; 36] = {
    let mut f = [0u8; 36];
    // Version "0.1.0"
    f[14] = b'0'; f[15] = b'.'; f[16] = b'1'; f[17] = b'.'; f[18] = b'0';
    // Kernel start address: 0x00010000 (alias region, after 64 KB bootloader)
    f[32] = 0x00; f[33] = 0x00; f[34] = 0x01; f[35] = 0x00; // little-endian
    f
};

/// Board attributes baked into flash at _relocated_attributes_address (0xE200).
/// Each attribute: 8-byte key (null-padded) | 1-byte value length | 55-byte value.
///
/// Only the first four slots are populated here; the linker zero-fills the rest
/// of the sixteen, which read back as empty. Reflashing the bootloader restores
/// these defaults, so anything set over the bus is lost on the next reflash.
#[used]
#[link_section = ".attributes_relocated"]
static BOARD_ATTRIBUTES: [u8; 256] = {
    let mut d = [0u8; 256];
    // Attribute 0: board = "samv71xplained"
    d[0] = b'b'; d[1] = b'o'; d[2] = b'a'; d[3] = b'r'; d[4] = b'd';
    d[8] = 14;
    d[9] = b's'; d[10] = b'a'; d[11] = b'm'; d[12] = b'v'; d[13] = b'7';
    d[14] = b'1'; d[15] = b'x'; d[16] = b'p'; d[17] = b'l'; d[18] = b'a';
    d[19] = b'i'; d[20] = b'n'; d[21] = b'e'; d[22] = b'd';
    // Attribute 1: arch = "cortex-m7"
    d[64] = b'a'; d[65] = b'r'; d[66] = b'c'; d[67] = b'h';
    d[72] = 9;
    d[73] = b'c'; d[74] = b'o'; d[75] = b'r'; d[76] = b't'; d[77] = b'e';
    d[78] = b'x'; d[79] = b'-'; d[80] = b'm'; d[81] = b'7';
    // Attribute 2: jldevice = "ATSAMV71Q21B"
    d[128] = b'j'; d[129] = b'l'; d[130] = b'd'; d[131] = b'e';
    d[132] = b'v'; d[133] = b'i'; d[134] = b'c'; d[135] = b'e';
    d[136] = 12;
    d[137] = b'A'; d[138] = b'T'; d[139] = b'S'; d[140] = b'A';
    d[141] = b'M'; d[142] = b'V'; d[143] = b'7'; d[144] = b'1';
    d[145] = b'Q'; d[146] = b'2'; d[147] = b'1'; d[148] = b'B';
    // Attribute 3: appaddr = "0x70000"
    d[192] = b'a'; d[193] = b'p'; d[194] = b'p'; d[195] = b'a';
    d[196] = b'd'; d[197] = b'd'; d[198] = b'r';
    d[200] = 7;
    d[201] = b'0'; d[202] = b'x'; d[203] = b'7'; d[204] = b'0';
    d[205] = b'0'; d[206] = b'0'; d[207] = b'0';
    d
};

// ---------------------------------------------------------------------------
// Bootloader exit: reset the chip so it re-enters the entry check and then
// jumps to the kernel (GPBR7 will be 0 at that point).
// ---------------------------------------------------------------------------
fn bootloader_exit() {
    unsafe { cortexm7::scb::reset(); }
}

/// How long the bootloader listens on CAN before jumping to the kernel.
///
/// **Zero disables the window entirely**, MCAN bring-up included, which is what
/// a board with a `FLASH_EN` pin should use: the pin does the same job for the
/// price of a register read instead of a third of a second on every boot.
///
/// This board declares the pin below so the production path stays exercised,
/// but has no `FLASH_EN` line actually wired: PE3 reads its own pull-up and
/// never asks to stay. So the window is what does the work here, and it stays
/// at 100 ms -- ample against a host knocking every 10 ms, roughly ten chances
/// to land a frame, and a third of the original cost.
///
/// The window and the pin are independent on purpose. The window needs the CAN
/// subsystem to be working, which is precisely what may not be true; the pin
/// does not care.
const CAN_ENTRY_WINDOW_MS: u32 = 100;

/// How long after an NRST press a second press still counts as a double-reset.
///
/// **Zero disables it entirely.** Paid only on a reset that came from the pin
/// -- see `double_reset_requested` -- so power-up, watchdog recovery and the
/// software reset behind `ECUReset` all boot without it. That gate is what
/// makes half a second affordable, and half a second is what the scheme was
/// designed around: the Adafruit nRF52 bootloader this descends from uses
/// exactly that, and much less cannot be hit by hand.
///
/// It replaced a fixed 2,000,000-iteration nop loop carried over from that
/// same nRF52 code, which is the bug worth remembering: a cycle count is not a
/// duration. On the 64 MHz Cortex-M4 it was written for it came to roughly
/// 150 ms. On this 300 MHz Cortex-M7, dual-issuing the nop against the loop
/// counter and predicting the branch, it came to something on the order of
/// 15 ms -- still there, still correct, and entirely unreachable with a finger.
///
/// Must stay under two seconds; see `tc_elapsed`.
const DOUBLE_RESET_WINDOW_MS: u32 = 500;

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

/// Whether this board has a `FLASH_EN` line, and which pin it is.
///
/// Production boards carry one on PE3: **normally high, pulled low to hold the
/// board in the bootloader**. The polarity matters and is chosen so the failure
/// modes are safe -- an unconnected or broken line floats to the internal
/// pull-up, reads high, and the board boots. Only a deliberate ground holds it.
///
/// The converse is worth stating plainly: a harness fault that shorts this line
/// to ground stops the ECU booting. That is the cost of having the escape hatch
/// not depend on any working firmware.
const FLASH_EN_PIN: Option<usize> = Some(3);

/// SAMV71 peripheral ID for PIOE.
const PIOE_PID: u32 = 17;

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
fn configure_mcan(mcan: &samv71q21b::mcan::Mcan) {
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
/// Costs a clock enable, a pull-up settle and three register reads -- call it
/// tens of microseconds against the CAN window's hundreds of milliseconds. That
/// is the whole argument for preferring it where the hardware has the line.
///
/// Reads the pin three times and requires agreement. A line long enough to
/// leave the board is long enough to pick up a transient, and the consequence
/// of a false read in either direction is bad: a spurious low strands a healthy
/// board in the bootloader, and a spurious high ignores an operator who is
/// standing there asking for it.
fn flash_en_asserted(port: &samv71q21b::gpio::PortE<'static>, pin_index: usize) -> bool {
    use kernel::hil::gpio::{Configure, FloatingState, Input};

    let pin = port.pin(pin_index);
    pin.make_input();
    // The pull-up is the safety net, not the signal: an unconnected line must
    // read high and let the board boot.
    pin.set_floating_state(FloatingState::PullUp);

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
    low == FLASH_EN_ASSERTED_LOW_COUNT
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
fn double_reset_requested(tc: &samv71q21b::tc::Tc<'static>) -> bool {
    use kernel::hil::time::{Counter, Ticks, Time};

    if DOUBLE_RESET_WINDOW_MS == 0 {
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
    let window = (DOUBLE_RESET_WINDOW_MS * TC_TICKS_PER_SECOND) / 1000;
    while tc_elapsed(tc, started) < window {}

    unsafe { core::ptr::write_volatile(scratch, 0) };
    false
}

/// Listen on CAN for `CAN_ENTRY_WINDOW_MS`; return whether anyone knocked.
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
fn can_entry_requested(
    mcan: &samv71q21b::mcan::Mcan,
    tc: &samv71q21b::tc::Tc<'static>,
) -> bool {
    use kernel::hil::time::{Counter, Ticks, Time};

    if CAN_ENTRY_WINDOW_MS == 0 {
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
    let window = (CAN_ENTRY_WINDOW_MS * TC_TICKS_PER_SECOND) / 1000;

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
fn try_rollback(efc: &'static Efc) -> bool {
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

// ---------------------------------------------------------------------------
// Platform struct
// ---------------------------------------------------------------------------

pub struct Platform {
    bootloader: &'static bootloader::bootloader::Bootloader<
        'static,
        bootloader::uart_transport::UartTransport<'static, Usart1<'static>>,
        bootloader::flash_router::FlashPort<
            'static,
            flash_passthrough::Sam71FlashDirect,
        >,
    >,
    scheduler: &'static NullScheduler,
}

impl KernelResources<Atsamv71q21b<Atsamv71q21bDefaultPeripherals>> for Platform {
    type SyscallDriverLookup = Self;
    type SyscallFilter = ();
    type ProcessFault = ();
    type Scheduler = NullScheduler;
    type SchedulerTimer = ();
    type WatchDog = ();
    type ContextSwitchCallback = ();

    fn syscall_driver_lookup(&self) -> &Self::SyscallDriverLookup { self }
    fn syscall_filter(&self) -> &Self::SyscallFilter { &() }
    fn process_fault(&self) -> &Self::ProcessFault { &() }
    fn scheduler(&self) -> &Self::Scheduler { self.scheduler }
    fn scheduler_timer(&self) -> &Self::SchedulerTimer { &() }
    fn watchdog(&self) -> &Self::WatchDog { &() }
    fn context_switch_callback(&self) -> &Self::ContextSwitchCallback { &() }
}

impl SyscallDriverLookup for Platform {
    fn with_driver<F, R>(&self, _driver_num: usize, f: F) -> R
    where
        F: FnOnce(Option<&dyn kernel::syscall::SyscallDriver>) -> R,
    {
        f(None)
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe fn main() {
    // Arm the watchdog immediately, and note that this is the *only* chance to
    // decide. WDT_MR is write-once: the bootloader jumps to the kernel without
    // an intervening reset, so whatever is chosen here is what the kernel gets,
    // and the kernel cannot change it.
    //
    // This used to write WDDIS, because the 16-second default could fire
    // during crystal startup. WATCHDOG_PERIOD_MS is well clear of that, and
    // `Wdt::start` sets WDIDLEHLT and WDDBGHLT so an idle bootloader waiting
    // for a host, or a core halted in a debugger, does not reset. What resets
    // is a core that is *spinning*, which is the case worth catching.
    samv71q21b::wdt::Wdt::new().start(WATCHDOG_PERIOD_MS);

    // Change the flash slave's default master BEFORE any flash reads.
    // The I-Code bus as fixed default master (reset default) causes
    // I-Code prefetch activity to block EEFC page buffer fills from
    // D-Code/System/XDMAC writes. Setting DEFMSTR_TYPE=1 (Last Access
    // Master) allows the flash slave to accept writes from whichever
    // master accessed it last.
    // MATRIX_SCFG[2] at 0x40088048: SLOT_CYCLE=511, DEFMSTR_TYPE=1
    core::ptr::write_volatile(0x4008_8048 as *mut u32, 0x0001_01FF);
    // Also SCFG[3] in case flash maps to both slaves
    core::ptr::write_volatile(0x4008_804C as *mut u32, 0x0001_01FF);

    // Enable all peripheral clocks needed by the bootloader before
    // setup_clocks() enables PMC write-protection.  At reset WPEN=0 so
    // PCER0 is writable without a key sequence.
    //   PID 10 = PIOA  (PA21 USART1 RXD)
    //   PID 11 = PIOB  (PB4  USART1 TXD)
    //   PID 12 = PIOC  (PC9  LED1)
    //   PID 14 = USART1 (EDBG CDC)
    core::ptr::write_volatile(
        0x400E_0610 as *mut u32,
        (1u32 << 10) | (1u32 << 11) | (1u32 << 12) | (1u32 << 14),
    );
    // Drive PC9 (LED1, active-low) immediately so LED is on during all of init.
    core::ptr::write_volatile(0x400E_1200 as *mut u32, 1u32 << 9);  // PIOC_PER: PC9 → PIO
    core::ptr::write_volatile(0x400E_1210 as *mut u32, 1u32 << 9);  // PIOC_OER: PC9 output
    core::ptr::write_volatile(0x400E_1234 as *mut u32, 1u32 << 9);  // PIOC_CODR: PC9 LOW → LED on

    // Configure flash wait states BEFORE raising MCK to 150 MHz.
    // At 150 MHz, FWS=6 (7 cycles) is required.
    // CLOE (bit 26) intentionally OFF — stale EEFC read buffer causes
    // CRC mismatches during tockloader installs.
    core::ptr::write_volatile(0x400E_0C00 as *mut u32, 0x0000_0600);

    // Loads relocations and zeros BSS.
    samv71q21b::init();

    // -----------------------------------------------------------------------
    // Clocks: 12 MHz crystal → PLLA ×25 = 300 MHz PCK, 150 MHz MCK
    // -----------------------------------------------------------------------
    pmc::PMC.setup_clocks();

    // Deferred call state must be initialized before any DeferredCall::new()
    // (DefaultPeripherals includes MCAN which creates one).
    unsafe {
        kernel::deferred_call::initialize_deferred_call_state_unsafe::<
            cortexm7::thread_id::CortexMThreadIdProvider,
        >();
    }

    // -----------------------------------------------------------------------
    // Peripherals and flash wait states
    // -----------------------------------------------------------------------
    let mcan_msg_ram = static_init!(samv71q21b::mcan::MessageRam, samv71q21b::mcan::MessageRam::new());
    let peripherals = static_init!(
        Atsamv71q21bDefaultPeripherals,
        Atsamv71q21bDefaultPeripherals::new(mcan_msg_ram)
    );
    // Must configure wait states before running at full MCK speed.
    peripherals.efc.init();

    // Enable peripheral clocks needed by the bootloader.
    pmc::PMC.enable_peripheral_clock(samv71q21b::uart::USART1_PID);
    pmc::PMC.enable_peripheral_clock(xdmac::XDMAC_PID); // XDMAC for UART DMA receive
    pmc::PMC.enable_peripheral_clock(10); // PIOA — PA21 USART1 RXD
    pmc::PMC.enable_peripheral_clock(11); // PIOB — PB4  USART1 TXD
    pmc::PMC.enable_peripheral_clock(12); // PIOC — PC9 LED1, PC12/PC14 MCAN1
    // PIOE — PE3 FLASH_EN. The PIO controller needs its clock to synchronise
    // the input before PDSR reflects the pin.
    pmc::PMC.enable_peripheral_clock(PIOE_PID);

    // MCAN1: peripheral clock + PCK5 as the CAN core clock. The SAMV71 MCAN
    // takes its core clock from PCK5, not from a GCLK via PMC_PCR -- the
    // PMC_PCR GCLKEN bit is simply ignored for this peripheral.
    // PCK5 = PLLA / (14+1) = 20 MHz, which gives an exact 87.5% sample point
    // at 500 kbps (40 TQ per bit). Same numbers as the kernel board.
    pmc::PMC.enable_peripheral_clock(samv71q21b::mcan::MCAN1_PID);
    pmc::PMC.configure_pck(5, 2, 14);

    // TC0 channel 0 @ 32 kHz SLCK. The bootloader had no time source before;
    // ISO-TP needs one for its N_Bs / N_Cr timeouts and separation time.
    pmc::PMC.enable_peripheral_clock(samv71q21b::tc::TC0_CH0_PID);

    // MCAN message RAM base (CCFG_CAN0 in the Matrix). The controller forms
    // addresses as {CAN0DMABA[15:0], register_field[13:0], 2'b00}, so this
    // must hold the upper 16 bits of the SRAM base or every message RAM
    // access lands at 0x0000XXXX.
    unsafe {
        let ccfg_can0 = 0x4008_8110 as *mut u32;
        core::ptr::write_volatile(ccfg_can0, 0x2040_0000u32);
    }

    // -----------------------------------------------------------------------
    // Pin mux: USART1 EDBG CDC (PA21=RXD Periph A, PB4=TXD Periph D)
    // PB4 is JTAG TDI after reset; release it via CCFG_SYSIO bit 4.
    // -----------------------------------------------------------------------
    unsafe {
        let ccfg_sysio = 0x4008_8114 as *mut u32;
        core::ptr::write_volatile(ccfg_sysio,
            core::ptr::read_volatile(ccfg_sysio) | (1u32 << 4));
    }
    peripherals.pa.pin(21).select_peripheral(PeripheralFunction::A);
    peripherals.pb.pin(4).select_peripheral(PeripheralFunction::D);

    // Pin mux: MCAN1 — PC12 = RX, PC14 = TX (both Peripheral C).
    peripherals.pc.pin(12).select_peripheral(PeripheralFunction::C);
    peripherals.pc.pin(14).select_peripheral(PeripheralFunction::C);

    // -----------------------------------------------------------------------
    // Kernel object
    // -----------------------------------------------------------------------
    let board_kernel = static_init!(kernel::Kernel, kernel::Kernel::new(&PROCESSES));

    // -----------------------------------------------------------------------
    // Bootloader entry check (runs early to minimize wasted init time)
    // -----------------------------------------------------------------------
    let gpbr = static_init!(Gpbr, Gpbr::new());
    let bootloader_entry = static_init!(
        BootloaderEntryGpRegRet,
        BootloaderEntryGpRegRet::new(gpbr)
    );

    let bootloader_jumper = static_init!(
        bootloader_cortexm::jumper::CortexMJumper,
        bootloader_cortexm::jumper::CortexMJumper::new()
    );

    // Use PC9 (LED1 on SAMV71 Xplained Ultra) as the active indicator.
    // PC8 (LED0) appears to be faulty on this board.
    let led_pin = peripherals.pc.pin(9);
    let active_led = static_init!(
        kernel::hil::led::LedLow<'static, samv71q21b::gpio::GPIOPin<'static>>,
        kernel::hil::led::LedLow::new(led_pin)
    );

    let bootloader_notifier = static_init!(
        bootloader::active_notifier_ledon::ActiveNotifierLedon,
        bootloader::active_notifier_ledon::ActiveNotifierLedon::new(active_led)
    );

    let bootloader_enterer = static_init!(
        bootloader::bootloader::BootloaderEnterer<'static>,
        bootloader::bootloader::BootloaderEnterer::new_with_flags(
            bootloader_entry,
            bootloader_jumper,
            bootloader_notifier,
            0x0001_0000, // kernel region start; see layout.ld
            // Must be the relocated flags, not the linker's default at 0x400:
            // that region is zeroed on this board, so reading the start address
            // from it yields 0 and the bootloader silently never jumps.
            unsafe { (&_relocated_flags_address as *const u8) as u32 },
        )
    );

    // Check the kernel image before considering a jump to it. A mismatch is
    // reported by setting the ordinary bootloader-entry magic rather than by a
    // separate path, so there is one way to say "stay resident" and the entry
    // check clears it as usual.
    //
    // An absent or malformed descriptor is not a failure: it means nobody has
    // recorded a digest for this image, which is the normal state after a
    // debugger flash. See kernel_integrity.rs.
    match bootloader::kernel_integrity::check(KERNEL_START, KERNEL_DESCRIPTOR) {
        // Either the image does not match what was recorded, or a flash was
        // started and never finished. Both mean the kernel cannot be trusted.
        bootloader::kernel_integrity::Verdict::Mismatch
        | bootloader::kernel_integrity::Verdict::Interrupted => {
            // Roll back if there is a known-good backup to roll back to.
            // Failing that, hold here so it can be reflashed by hand.
            if !try_rollback(&peripherals.efc) {
                gpbr.set(samv71q21b::gpbr::GpbrIndex::Gpbr7, 0x90);
            }
        }
        bootloader::kernel_integrity::Verdict::Match
        | bootloader::kernel_integrity::Verdict::NoDescriptor => {}
    }

    // Three ways to ask the bootloader to stay, checked cheapest first, and all
    // ending in the same GPBR7 magic -- so there is still one way to say "stay
    // resident" and the entry check clears it as usual.
    //
    // The FLASH_EN pin is a register read. The other two cost real time on
    // every boot, which is the whole reason they are ordered this way: a board
    // with the pin wired sets both windows to 0 and pays nothing.
    //
    // Double-reset before the CAN window because catching one is a single word
    // of SRAM, so a double-tap enters the bootloader immediately instead of
    // sitting through a CAN window nobody is knocking on. On the other path it
    // costs its window before the CAN one opens, which `can_knock.py` does not
    // care about -- it floods continuously, so a window opening 500 ms later is
    // still a window it lands in.
    let asked_to_stay = match FLASH_EN_PIN {
        Some(index) => flash_en_asserted(&peripherals.pe, index),
        None => false,
    } || double_reset_requested(&peripherals.tc0)
        || can_entry_requested(&peripherals.mcan1, &peripherals.tc0);

    if asked_to_stay {
        gpbr.set(samv71q21b::gpbr::GpbrIndex::Gpbr7, 0x90);
    }

    // Decides: jump to kernel, or stay in bootloader.
    bootloader_enterer.check();

    // -----------------------------------------------------------------------
    // Capabilities
    // -----------------------------------------------------------------------
    let main_loop_capability = create_capability!(capabilities::MainLoopCapability);

    // -----------------------------------------------------------------------
    // UART: USART1 wired directly to the bootloader (uses hardware RTOR)
    // XDMAC provides DMA receive so full WritePage commands (516+ bytes)
    // arrive in a single buffer instead of being split across callbacks.
    // -----------------------------------------------------------------------
    peripherals.usart1.set_xdmac(&peripherals.xdmac);
    let usart1 = &peripherals.usart1;

    // -----------------------------------------------------------------------
    // Flash adapter
    // -----------------------------------------------------------------------
    let efc = &peripherals.efc;

    let efc_page_buf = static_init!(
        samv71q21b::efc::Sam71Page,
        samv71q21b::efc::Sam71Page::default()
    );

    let flash_adapter = static_init!(
        flash_passthrough::Sam71FlashDirect,
        flash_passthrough::Sam71FlashDirect::new(efc, efc_page_buf)
    );
    hil::flash::HasClient::set_client(efc, flash_adapter);

    let bl_page_buf = static_init!(
        bootloader::flash_large_to_small::FiveTwelvePage,
        bootloader::flash_large_to_small::FiveTwelvePage::default()
    );
    // One flash erase block of staging for the UART SetAttr/SetStartAddress
    // path, which rewrites the whole block rather than one page of it.
    let bl_stage = static_init!([u8; 8192], [0; 8192]);

    // -----------------------------------------------------------------------
    // CAN transport (ISO-TP over MCAN1)
    // -----------------------------------------------------------------------
    // ISO-TP sits between the raw controller and anything message-shaped. It
    // owns the CAN transmit/receive clients and the alarm; layers above it deal
    // only in whole messages.
    //
    // The bootloader has exactly one CAN client, so no virtualizer is needed.
    // It does inherit the acceptance-filter work done for the kernel: with GFC
    // set to reject unmatched frames, the filter installed here defines
    // reception.
    // Same configuration the entry window used a moment ago, applied again
    // because the window puts the controller back in init mode on its way
    // out. Shared so the two cannot disagree about bit timing.
    configure_mcan(&peripherals.mcan1);

    let isotp_frame = static_init!(
        [u8; kernel::hil::can::FD_CAN_PACKET_SIZE],
        [0; kernel::hil::can::FD_CAN_PACKET_SIZE]
    );
    let isotp_rx_frame = static_init!(
        [u8; kernel::hil::can::FD_CAN_PACKET_SIZE],
        [0; kernel::hil::can::FD_CAN_PACKET_SIZE]
    );
    let isotp = static_init!(
        bootloader::isotp::IsoTp<
            'static,
            samv71q21b::mcan::Mcan,
            samv71q21b::tc::Tc<'static>,
        >,
        bootloader::isotp::IsoTp::new(
            &peripherals.mcan1,
            &peripherals.tc0,
            kernel::hil::can::Id::Extended(CAN_REQUEST_ID),
            kernel::hil::can::Id::Extended(CAN_RESPONSE_ID),
            isotp_frame,
            isotp_rx_frame,
        )
    );
    kernel::hil::time::Alarm::set_alarm_client(&peripherals.tc0, isotp);
    kernel::hil::can::Transmit::set_client(&peripherals.mcan1, Some(isotp));
    kernel::hil::can::Receive::set_client(&peripherals.mcan1, Some(isotp));

    let can_transport = static_init!(
        bootloader::can_transport::CanTransport<
            'static,
            samv71q21b::mcan::Mcan,
            samv71q21b::tc::Tc<'static>,
        >,
        bootloader::can_transport::CanTransport::new(&peripherals.mcan1, isotp)
    );
    isotp.set_client(can_transport);
    kernel::hil::can::Controller::set_client(&peripherals.mcan1, Some(can_transport));


    // -----------------------------------------------------------------------
    // Two protocols, one per wire
    // -----------------------------------------------------------------------
    // CAN carries UDS -- the destination architecture. UART keeps speaking the
    // tockloader protocol, because that is what stock `tockloader` speaks and
    // it is the recovery channel: a botched CAN reflash must not take the way
    // back with it.
    //
    // This supersedes `DualTransport`, which existed to put *one* protocol on
    // both wires. With a different protocol per wire each server simply owns
    // its own transport, so the mux is no longer in the path.
    //
    // Both servers drive the same flash, so it is virtualized. Only one host
    // talks at a time in practice, and `MuxFlash` serializes the operations
    // regardless.
    let uart_transport = static_init!(
        bootloader::uart_transport::UartTransport<'static, Usart1<'static>>,
        bootloader::uart_transport::UartTransport::new(usart1)
    );

    // `capsules_core`'s MuxFlash cannot be used: it records the owning client
    // only after issuing the operation, and this EFC completes inside the call.
    // See bootloader::flash_router.
    let flash_router = static_init!(
        bootloader::flash_router::FlashRouter<'static, flash_passthrough::Sam71FlashDirect>,
        bootloader::flash_router::FlashRouter::new(flash_adapter)
    );
    hil::flash::HasClient::set_client(flash_adapter, flash_router);

    let flash_for_tockloader = static_init!(
        bootloader::flash_router::FlashPort<'static, flash_passthrough::Sam71FlashDirect>,
        bootloader::flash_router::FlashPort::new(
            flash_router,
            bootloader::flash_router::Which::A
        )
    );
    let flash_for_uds = static_init!(
        bootloader::flash_router::FlashPort<'static, flash_passthrough::Sam71FlashDirect>,
        bootloader::flash_router::FlashPort::new(
            flash_router,
            bootloader::flash_router::Which::B
        )
    );

    let bootloader = static_init!(
        bootloader::bootloader::Bootloader<
            'static,
            bootloader::uart_transport::UartTransport<'static, Usart1<'static>>,
            bootloader::flash_router::FlashPort<
                'static,
                flash_passthrough::Sam71FlashDirect,
            >,
        >,
        bootloader::bootloader::Bootloader::new_with_table(
            uart_transport,
            flash_for_tockloader,
            &bootloader_exit,
            bl_page_buf,
            &mut bootloader::bootloader::BUF,
            // Refuse writes and erases below the kernel: the whole 64 KB rom
            // region is the bootloader's, including the vector table and the
            // attribute table at 0xE000. The UDS server uses the same floor
            // (see the design document, sections 13.4, 13.5 and 14).
            0x0001_0000,
            // This board moved its table out of the block holding its own code
            // so that it can be rewritten at runtime; see layout.ld.
            unsafe { (&_relocated_flags_address as *const u8) as usize },
            unsafe { (&_relocated_attributes_address as *const u8) as usize },
            // Its own staging block. Separate from the UDS server's rather than
            // shared, because the two servers are independent owners and a
            // TakeCell can only be held by one of them -- sharing would turn a
            // concurrent write into a silent refusal on whichever asked second.
            Some(bl_stage),
        )
    );

    let uds_page_buf = static_init!(
        bootloader::flash_large_to_small::FiveTwelvePage,
        bootloader::flash_large_to_small::FiveTwelvePage::default()
    );
    let uds_buf = static_init!([u8; 600], [0; 600]);
    // One flash erase block of staging for attribute and start-address writes.
    // The table shares its block with the vector table, so the block is rewritten
    // whole rather than a page at a time; see `uds::BLOCK_PAGES`.
    let uds_stage = static_init!([u8; 8192], [0; 8192]);

    let uds = static_init!(
        bootloader::uds::UdsServer<
            'static,
            bootloader::can_transport::CanTransport<
                'static,
                samv71q21b::mcan::Mcan,
                samv71q21b::tc::Tc<'static>,
            >,
            bootloader::flash_router::FlashPort<
                'static,
                flash_passthrough::Sam71FlashDirect,
            >,
        >,
        bootloader::uds::UdsServer::new(
            can_transport,
            flash_for_uds,
            &bootloader_exit,
            uds_page_buf,
            uds_buf,
            uds_stage,
            0x0007_0000, // application region start, reported by DID 0xF200
            // Lowest writable address: the end of the bootloader's own region,
            // so the kernel is reachable over CAN. A development-tool
            // decision -- seed/key is all that stands in front of it. Section
            // 14 of the design document records why, and what the production
            // variant does instead.
            0x0001_0000,
            0x0020_0000, // end of the 2 MB flash alias
            // The attribute table and the flags. Both sit below the write floor
            // and so are reachable only through their DIDs, never by address.
            unsafe { (&_relocated_attributes_address as *const u8) as u32 },
            unsafe { (&_relocated_flags_address as *const u8) as u32 },
            // End of the running bootloader. A staged rewrite of any erase block
            // below this is refused, because erasing it would delete the code
            // doing the erasing. The table sits at 0xE000, well above, which is
            // what makes attribute writes possible at all -- see layout.ld.
            unsafe { (&_etext as *const u8) as u32 },
        )
    );

    hil::uart::Transmit::set_transmit_client(usart1, uart_transport);
    hil::uart::Receive::set_receive_client(usart1, uart_transport);
    bootloader::transport::BootloaderTransport::set_client(uart_transport, bootloader);
    bootloader::transport::BootloaderTransport::set_client(can_transport, uds);
    hil::flash::HasClient::set_client(flash_for_tockloader, bootloader);
    hil::flash::HasClient::set_client(flash_for_uds, uds);

    // -----------------------------------------------------------------------
    // Chip and platform
    // -----------------------------------------------------------------------
    let null_scheduler = static_init!(NullScheduler, NullScheduler::new());

    let platform = Platform {
        bootloader,
        scheduler: null_scheduler,
    };

    let chip = static_init!(
        Atsamv71q21b<Atsamv71q21bDefaultPeripherals>,
        Atsamv71q21b::new(peripherals)
    );
    CHIP = Some(chip);

    // Enable NVIC IRQs for the two peripherals the bootloader uses.
    // WFI wakes only for ISER-enabled interrupts (SEVONPEND=0 on Cortex-M7).
    // Using enable_all() is unsafe here: service_pending_interrupts() calls
    // assert!(handled, ...) for every interrupt, so any unhandled peripheral
    // (SUPC=0, RSTC=1, RTT=3 ...) firing spuriously causes a panic → loop{}.
    cortexm7::nvic::Nvic::new(14).enable(); // USART1 — EDBG CDC bootloader UART
    cortexm7::nvic::Nvic::new(58).enable(); // XDMAC  — DMA transfer complete
    cortexm7::nvic::Nvic::new(samv71q21b::mcan::MCAN1_PID).enable(); // MCAN1 INT0
    cortexm7::nvic::Nvic::new(38).enable(); // MCAN1 INT1
    cortexm7::nvic::Nvic::new(samv71q21b::tc::TC0_CH0_PID).enable(); // TC0_CH0 — ISO-TP timers
    // EFC interrupt not needed — flash commands use synchronous IAP from ROM.

    // Bring the transport up and begin listening for bootloader commands.
    // Start both servers: the tockloader protocol on UART, UDS on CAN. Each
    // brings its own transport up and posts a receive buffer.
    platform.bootloader.start();
    uds.start();

    kernel::deferred_call::DeferredCallClient::register(&peripherals.mcan1);


    board_kernel.kernel_loop(
        &platform,
        chip,
        None::<&kernel::ipc::IPC<0>>,
        &main_loop_capability,
    );
}

#[cfg(not(test))]
#[panic_handler]
pub unsafe fn panic_fmt(_pi: &PanicInfo) -> ! {
    loop {}
}
