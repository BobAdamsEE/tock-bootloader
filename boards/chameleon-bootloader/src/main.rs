//! Tock bootloader for the Chameleon board (PCA-0001-01).
//!
//! DRAFT, written before the first board exists: nothing here has run on
//! Chameleon hardware. See README.md.
//!
//! Hardware:
//!   - ATSAMV71Q21B, Cortex-M7, 300 MHz PCK / 150 MHz MCK from a 20 MHz crystal
//!   - CAN B: MCAN1 (PC12 RX, PC14 TX) via TJA1057. The only way in over a
//!     wire: USART1's pins are LIN A here, so there is no UART recovery channel
//!     and the tockloader protocol is not built. SWD on J2 is the last resort.
//!   - 2 MB internal flash (512-byte pages), 384 KB SRAM at 0x20400000
//!
//! Bootloader entry. The first three conditions set the entry magic in GPBR7;
//! the last two are read straight out of the backup registers by
//! `BootloaderEntryGpRegRet`. Any one of them holds the board here.
//!
//!   1. The kernel failed its integrity check and no backup was worth
//!      restoring -- see `kernel_integrity` and `entry::try_rollback`.
//!   2. A sustained negative voltage on `FLASH_EN` (J1 pin 22) -- see
//!      `FLASH_EN_PIN`.
//!   3. A CAN knock inside `CAN_ENTRY_WINDOW_MS` -- see `entry::CAN_KNOCK`.
//!   4. GPBR7 >= 0x90: the kernel, or a debugger, asked for the bootloader.
//!   5. GPBR6 >= 3: three boots without the kernel reporting itself healthy.

#![no_std]
#![cfg_attr(not(doc), no_main)]

#[path = "../../samv71xplained-bootloader/src/flash_passthrough.rs"]
mod flash_passthrough;

use core::panic::PanicInfo;

use kernel::capabilities;
use kernel::hil;
use kernel::platform::{KernelResources, SyscallDriverLookup};
use kernel::process::ProcessSlot;
use kernel::{create_capability, static_init};

use bootloader::null_scheduler::NullScheduler;

use bootloader_samv71::bootloader_entry_gpbr::BootloaderEntryGpRegRet;
use bootloader_samv71::entry::{
    self, CAN_REQUEST_ID, CAN_RESPONSE_ID, KERNEL_DESCRIPTOR, KERNEL_START, WATCHDOG_PERIOD_MS,
};

use samv71q21b::chip::{Atsamv71q21b, Atsamv71q21bDefaultPeripherals};
use samv71q21b::gpio::{GPIOPin, PeripheralFunction};
use samv71q21b::gpbr::Gpbr;
use samv71q21b::pmc;

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

/// Y1. The Xplained Ultra's is 12 MHz; assuming that here would put PLLA at
/// 500 MHz.
const CRYSTAL_HZ: u32 = 20_000_000;

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
    // Attribute 0: board = "chameleon"
    d[0] = b'b'; d[1] = b'o'; d[2] = b'a'; d[3] = b'r'; d[4] = b'd';
    d[8] = 9;
    d[9] = b'c'; d[10] = b'h'; d[11] = b'a'; d[12] = b'm'; d[13] = b'e';
    d[14] = b'l'; d[15] = b'e'; d[16] = b'o'; d[17] = b'n';
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
/// Left on for the prototypes even though this board has the `FLASH_EN` line
/// that was meant to replace it: the line has never been exercised on hardware,
/// and the window costs nothing that matters on a bench. Set it to 0 once
/// `FLASH_EN` has been proven on a real board, as the window is 100 ms added to
/// every wake and needs CAN B working, which is what may be broken.
const CAN_ENTRY_WINDOW_MS: u32 = 100;

/// Off. There is no reset button: NRST reaches only U17 and the debug header,
/// and anyone at the debug header has better options.
const DOUBLE_RESET_WINDOW_MS: u32 = 0;

/// `FLASH_EN` is J1 pin 22, through R48 to PE3, with R54 to +3V3.
///
/// Entry takes a deliberate negative voltage on J1 pin 22, such as a 9 V battery
/// with its positive terminal on ground. An open or grounded line reads high and
/// the board boots, so a harness fault cannot strand it. R54 sets that, and the
/// internal pull-up stays off.
const FLASH_EN_PIN: usize = 3;

/// How long `FLASH_EN` must stay asserted, so that only a sustained voltage
/// holds the board here and a transient on the harness does not.
const FLASH_EN_HOLD_MS: u32 = 100;

/// Make `pin` a push-pull output at `high`, without its reset-default pull-up.
/// The level is set first so the pin never glitches through the other state.
fn drive(pin: &GPIOPin, high: bool) {
    if high {
        pin.set();
    } else {
        pin.clear();
    }
    pin.enable();
    pin.enable_output();
    pin.disable_pull_up();
}

/// Put every pin that controls something outside the MCU in a known state.
/// Runs before the clock setup, which can take 62 ms on the crystal alone.
///
/// The kernel's `safe_state` does the same again, so keep the two in step: this
/// one is what covers a bootloader that stays resident, and the time before the
/// kernel gets there.
fn safe_state(p: &Atsamv71q21bDefaultPeripherals) {
    // Keep ourselves powered once CAN or IGN has woken us.
    drive(p.pc.pin(1), true); // MAIN_HOLD

    // U17 is a window watchdog and SET0 = SET1 = 0 (R109, R110) leaves it
    // running from power-up, wanting a WDI falling edge 10.35-92.7 ms after
    // the last, or WDO cycles the +3V3 buck. SET0 = 1, SET1 = 0 disables it.
    // A flash erase holds the core for far longer than that window, so it stays
    // disabled here. The internal watchdog covers a hang.
    drive(p.pc.pin(17), true); // WD_SET0
    drive(p.pc.pin(18), false); // WD_SET1
    drive(p.pc.pin(16), false); // WDI: must not float while disabled

    // Everything that drives a load stays off.
    drive(p.pc.pin(19), false); // VEXT_EN
    for pin in [10, 11, 13] {
        drive(p.pa.pin(pin), false); // HSO-DIAG-EN, HSO0-uC, HSO1-uC
    }
    for pin in [0, 2, 4, 6, 24, 25, 26, 27] {
        drive(p.pd.pin(pin), false); // LSO0-3 ENABLE and IN
    }

    // Transceivers. LIN stays disabled, as nothing here drives LIN.
    drive(p.pa.pin(22), false); // LINA EN
    drive(p.pd.pin(17), false); // LINB EN
    drive(p.pc.pin(11), false); // CANB_SILENT: normal mode
    drive(p.pd.pin(19), true); // CANA_EN and ~CANA_STB: normal mode, and
    drive(p.pd.pin(20), true); // PB2 is left recessive by its pull-up

    drive(p.pa.pin(24), false); // SD_PWR_EN: card off
    drive(p.pa.pin(5), true); // EEPROM ~WC: write-protected
}

// ---------------------------------------------------------------------------
// Platform struct
// ---------------------------------------------------------------------------

pub struct Platform {
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
    // Arm the watchdog immediately; WDT_MR is write-once, so this is the only
    // chance to decide. See the Xplained board for the reasoning.
    samv71q21b::wdt::Wdt::new().start(WATCHDOG_PERIOD_MS);

    // Change the flash slave's default master BEFORE any flash reads. See the
    // Xplained board: the reset default blocks EEFC page buffer fills.
    core::ptr::write_volatile(0x4008_8048 as *mut u32, 0x0001_01FF);
    core::ptr::write_volatile(0x4008_804C as *mut u32, 0x0001_01FF);

    // PMC PCER0: PIOA(10), PIOB(11), PIOC(12), PIOD(16), PIOE(17). At reset
    // WPEN=0, so this is writable without a key sequence.
    core::ptr::write_volatile(
        0x400E_0610 as *mut u32,
        (1u32 << 10) | (1u32 << 11) | (1u32 << 12) | (1u32 << 16) | (1u32 << 17),
    );

    // Configure flash wait states BEFORE raising MCK to 150 MHz: FWS=6.
    // CLOE (bit 26) intentionally OFF, as on the Xplained board.
    core::ptr::write_volatile(0x400E_0C00 as *mut u32, 0x0000_0600);

    // Relocations and BSS are already done: the reset handler does them now.
    <Atsamv71q21b<Atsamv71q21bDefaultPeripherals> as kernel::platform::chip::Chip>::init();

    // Deferred call state must be initialized before any DeferredCall::new()
    // (DefaultPeripherals includes MCAN which creates one).
    kernel::deferred_call::initialize_deferred_call_state_unsafe::<
        cortexm7::thread_id::CortexMThreadIdProvider,
    >();

    let mcan_msg_ram = static_init!(samv71q21b::mcan::MessageRam, samv71q21b::mcan::MessageRam::new());
    let peripherals = static_init!(
        Atsamv71q21bDefaultPeripherals,
        Atsamv71q21bDefaultPeripherals::new(mcan_msg_ram)
    );

    // Ahead of the clocks: U17 has to be off before its 92.7 ms is up.
    safe_state(peripherals);

    // -----------------------------------------------------------------------
    // Clocks: 20 MHz crystal → PLLA ×15 = 300 MHz PCK, 150 MHz MCK
    // -----------------------------------------------------------------------
    pmc::PMC.setup_clocks(CRYSTAL_HZ);

    // Must configure wait states before running at full MCK speed.
    peripherals.efc.init();

    // MCAN1: peripheral clock + PCK5 as the CAN core clock, PLLA / 15 = 20 MHz.
    // That comes from the PLL, so it is the same as the Xplained board's.
    pmc::PMC.enable_peripheral_clock(samv71q21b::mcan::MCAN1_PID);
    pmc::PMC.configure_pck(5, 2, 14);

    // TC0 channel 0 @ 32 kHz SLCK, for the ISO-TP timers.
    pmc::PMC.enable_peripheral_clock(samv71q21b::tc::TC0_CH0_PID);

    // MCAN message RAM base (CCFG_CAN0 in the Matrix). See the Xplained board.
    core::ptr::write_volatile(0x4008_8110 as *mut u32, 0x2040_0000u32);

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

    // No LEDs on this board.
    let bootloader_notifier = static_init!(
        bootloader::active_notifier_null::ActiveNotifierNull,
        bootloader::active_notifier_null::ActiveNotifierNull::new()
    );

    let bootloader_enterer = static_init!(
        bootloader::bootloader::BootloaderEnterer<'static>,
        bootloader::bootloader::BootloaderEnterer::new_with_flags(
            bootloader_entry,
            bootloader_jumper,
            bootloader_notifier,
            KERNEL_START,
            // Must be the relocated flags; see the Xplained board.
            (&_relocated_flags_address as *const u8) as u32,
        )
    );

    // Check the kernel image before considering a jump to it. See the Xplained
    // board for what each verdict means.
    match bootloader::kernel_integrity::check(KERNEL_START, KERNEL_DESCRIPTOR) {
        bootloader::kernel_integrity::Verdict::Mismatch
        | bootloader::kernel_integrity::Verdict::Interrupted => {
            if !entry::try_rollback(&peripherals.efc) {
                gpbr.set(samv71q21b::gpbr::GpbrIndex::Gpbr7, 0x90);
            }
        }
        bootloader::kernel_integrity::Verdict::Match
        | bootloader::kernel_integrity::Verdict::NoDescriptor => {}
    }

    // Ways of asking to stay, cheapest first, all ending in the same GPBR7
    // magic. R54 is the pull-up here, so the internal one stays off.
    let asked_to_stay = entry::flash_en_asserted(
        peripherals.pe.pin(FLASH_EN_PIN),
        kernel::hil::gpio::FloatingState::PullNone,
        &peripherals.tc0,
        FLASH_EN_HOLD_MS,
    ) || entry::double_reset_requested(&peripherals.tc0, DOUBLE_RESET_WINDOW_MS)
        || entry::can_entry_requested(&peripherals.mcan1, &peripherals.tc0, CAN_ENTRY_WINDOW_MS);

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

    // -----------------------------------------------------------------------
    // CAN transport (ISO-TP over MCAN1)
    // -----------------------------------------------------------------------
    // The entry window puts the controller back in init mode on its way out.
    entry::configure_mcan(&peripherals.mcan1);

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
    // UDS on CAN, the only server: there is no UART here to run the tockloader
    // protocol on, and so no second flash client to route between.
    // -----------------------------------------------------------------------
    let uds_page_buf = static_init!(
        bootloader::flash_large_to_small::FiveTwelvePage,
        bootloader::flash_large_to_small::FiveTwelvePage::default()
    );
    let uds_buf = static_init!([u8; 600], [0; 600]);
    // One flash erase block of staging for attribute and start-address writes;
    // see `uds::BLOCK_PAGES`.
    let uds_stage = static_init!([u8; 8192], [0; 8192]);

    let uds = static_init!(
        bootloader::uds::UdsServer<
            'static,
            bootloader::can_transport::CanTransport<
                'static,
                samv71q21b::mcan::Mcan,
                samv71q21b::tc::Tc<'static>,
            >,
            flash_passthrough::Sam71FlashDirect,
        >,
        bootloader::uds::UdsServer::new(
            can_transport,
            flash_adapter,
            &bootloader_exit,
            uds_page_buf,
            uds_buf,
            uds_stage,
            0x0007_0000, // application region start, reported by DID 0xF200
            KERNEL_START, // lowest writable address; a development-tool decision
            0x0020_0000, // end of the 2 MB flash alias
            (&_relocated_attributes_address as *const u8) as u32,
            (&_relocated_flags_address as *const u8) as u32,
            // End of the running bootloader; a staged rewrite below it is
            // refused. See layout.ld.
            (&_etext as *const u8) as u32,
        )
    );

    bootloader::transport::BootloaderTransport::set_client(can_transport, uds);
    hil::flash::HasClient::set_client(flash_adapter, uds);

    // -----------------------------------------------------------------------
    // Chip and platform
    // -----------------------------------------------------------------------
    let null_scheduler = static_init!(NullScheduler, NullScheduler::new());

    let platform = Platform {
        scheduler: null_scheduler,
    };

    let chip = static_init!(
        Atsamv71q21b<Atsamv71q21bDefaultPeripherals>,
        Atsamv71q21b::new(peripherals)
    );
    CHIP = Some(chip);

    // Only the interrupts handled here; `service_pending_interrupts` panics on
    // any other. EFC is not needed: flash commands use synchronous IAP from ROM.
    cortexm7::nvic::Nvic::new(samv71q21b::mcan::MCAN1_PID).enable(); // MCAN1 INT0
    cortexm7::nvic::Nvic::new(38).enable(); // MCAN1 INT1
    cortexm7::nvic::Nvic::new(samv71q21b::tc::TC0_CH0_PID).enable(); // TC0_CH0 — ISO-TP timers

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
