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
//!   2. `FLASH_EN` read low -- see `FLASH_EN_PIN`.
//!   3. Two NRST presses inside `DOUBLE_RESET_WINDOW_MS`.
//!   4. A CAN knock inside `CAN_ENTRY_WINDOW_MS` -- see `CAN_KNOCK`.
//!   5. GPBR7 >= 0x90: the kernel, or a debugger, asked for the bootloader.
//!   6. GPBR6 >= 3: three boots without the kernel reporting itself healthy.

#![no_std]
#![cfg_attr(not(doc), no_main)]

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
use samv71q21b::gpio::PeripheralFunction;
use samv71q21b::gpbr::Gpbr;
use samv71q21b::pmc;
use samv71q21b::uart::Usart1;
use samv71q21b::xdmac;

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

/// The Xplained Ultra's crystal.
const CRYSTAL_HZ: u32 = 12_000_000;

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

    // Relocations and BSS are already done: the reset handler does them now.
    <Atsamv71q21b<Atsamv71q21bDefaultPeripherals> as kernel::platform::chip::Chip>::init();

    // -----------------------------------------------------------------------
    // Clocks: 12 MHz crystal → PLLA ×25 = 300 MHz PCK, 150 MHz MCK
    // -----------------------------------------------------------------------
    pmc::PMC.setup_clocks(CRYSTAL_HZ);

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
            if !entry::try_rollback(&peripherals.efc) {
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
        // No external pull-up here, so the internal one is what makes an
        // unconnected line read high. No hold: nothing is wired to this pin.
        Some(index) => entry::flash_en_asserted(
            peripherals.pe.pin(index),
            kernel::hil::gpio::FloatingState::PullUp,
            &peripherals.tc0,
            0,
        ),
        None => false,
    } || entry::double_reset_requested(&peripherals.tc0, DOUBLE_RESET_WINDOW_MS)
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
