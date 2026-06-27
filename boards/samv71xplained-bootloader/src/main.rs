//! Tock bootloader for the SAMV71 Xplained Ultra evaluation board.
//!
//! Hardware:
//!   - ATSAMV71Q21B, Cortex-M7, 300 MHz PCK / 150 MHz MCK
//!   - EDBG UART: USART1, RXD=PA21 (periph A), TXD=PB4 (periph D), 115200 baud
//!   - 2 MB internal flash (512-byte pages), 384 KB SRAM at 0x20400000
//!
//! Bootloader entry (evaluated in order):
//!   1. GPBR7 >= 0x90: kernel explicitly requested reboot into bootloader.
//!   2. Double-reset: two resets within the detection window.

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

/// Reserve stack space (8 KB).
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x4000] = [0; 0x4000];

/// Bootloader flags at _flags_address (0x400).
/// - Offset 14: version string (up to 8 bytes, null-terminated)
/// - Offset 32: kernel start address (4 bytes, little-endian)
#[used]
#[link_section = ".flags"]
static BOOTLOADER_FLAGS: [u8; 36] = {
    let mut f = [0u8; 36];
    // Version "0.1.0"
    f[14] = b'0'; f[15] = b'.'; f[16] = b'1'; f[17] = b'.'; f[18] = b'0';
    // Kernel start address: 0x00008000 (alias region, after 32 KB bootloader)
    f[32] = 0x00; f[33] = 0x80; f[34] = 0x00; f[35] = 0x00; // little-endian
    f
};

/// Board attributes baked into flash at _attributes_address (0x600).
/// Each attribute: 8-byte key (null-padded) | 1-byte value length | 55-byte value.
#[used]
#[link_section = ".attributes"]
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
    // Attribute 3: appaddr = "0x40000"
    d[192] = b'a'; d[193] = b'p'; d[194] = b'p'; d[195] = b'a';
    d[196] = b'd'; d[197] = b'd'; d[198] = b'r';
    d[200] = 7;
    d[201] = b'0'; d[202] = b'x'; d[203] = b'4'; d[204] = b'0';
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

// ---------------------------------------------------------------------------
// Platform struct
// ---------------------------------------------------------------------------

pub struct Platform {
    bootloader: &'static bootloader::bootloader::Bootloader<
        'static,
        Usart1<'static>,
        flash_passthrough::Sam71FlashDirect,
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
    // Disable the watchdog immediately. WDT_MR is write-once; the default
    // ~16-second timeout can fire during crystal startup and reset the chip.
    // WDT_MR = 0x400E1854, WDDIS = bit 15.
    core::ptr::write_volatile(0x400E_1854 as *mut u32, 0x0000_8000);

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
    pmc::PMC.enable_peripheral_clock(12); // PIOC — PC9  LED1

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
        bootloader::bootloader::BootloaderEnterer::new(
            bootloader_entry,
            bootloader_jumper,
            bootloader_notifier
        )
    );

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

    // -----------------------------------------------------------------------
    // Bootloader core
    // -----------------------------------------------------------------------
    let bootloader = static_init!(
        bootloader::bootloader::Bootloader<
            'static,
            Usart1<'static>,
            flash_passthrough::Sam71FlashDirect,
        >,
        bootloader::bootloader::Bootloader::new(
            usart1,
            flash_adapter,
            &bootloader_exit,
            bl_page_buf,
            &mut bootloader::bootloader::BUF
        )
    );

    hil::uart::Transmit::set_transmit_client(usart1, bootloader);
    hil::uart::Receive::set_receive_client(usart1, bootloader);
    hil::flash::HasClient::set_client(flash_adapter, bootloader);

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
    // EFC interrupt not needed — flash commands use synchronous IAP from ROM.

    // Start the UART and begin listening for bootloader commands.
    platform.bootloader.start();

    // Register MCAN deferred call (created by DefaultPeripherals but unused
    // in the bootloader). verify_setup requires created == registered.
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
