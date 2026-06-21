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

use bootloader::bootloader_entry_always::BootloaderEntryAlways;

use samv71q21b::chip::{Atsamv71q21b, Atsamv71q21bDefaultPeripherals};
use samv71q21b::efc::Efc;
use samv71q21b::gpio::PeripheralFunction;
use samv71q21b::pmc;
use samv71q21b::uart::Usart1;

// ---------------------------------------------------------------------------
// Platform constants
// ---------------------------------------------------------------------------

const NUM_PROCS: usize = 0;

static mut PROCESSES: [ProcessSlot; NUM_PROCS] = [];

static mut CHIP: Option<&'static Atsamv71q21b<Atsamv71q21bDefaultPeripherals>> = None;

/// Reserve stack space (8 KB).
#[no_mangle]
#[link_section = ".stack_buffer"]
pub static mut STACK_MEMORY: [u8; 0x2000] = [0; 0x2000];

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
    // At 150 MHz, FWS=6 (7 cycles) is required. CLOE enables cache.
    // EFC_FMR at 0x400E0C00: FWS=6 (bits 11:8) | CLOE (bit 26).
    core::ptr::write_volatile(0x400E_0C00 as *mut u32, 0x0400_0600);

    // Loads relocations and zeros BSS.
    samv71q21b::init();

    // -----------------------------------------------------------------------
    // Clocks: 12 MHz crystal → PLLA ×25 = 300 MHz PCK, 150 MHz MCK
    // -----------------------------------------------------------------------
    pmc::PMC.setup_clocks();

    // -----------------------------------------------------------------------
    // Peripherals and flash wait states
    // -----------------------------------------------------------------------
    let peripherals = static_init!(
        Atsamv71q21bDefaultPeripherals,
        Atsamv71q21bDefaultPeripherals::new()
    );
    // Must configure wait states before running at full MCK speed.
    peripherals.efc.init();

    // Enable peripheral clocks needed by the bootloader.
    pmc::PMC.enable_peripheral_clock(samv71q21b::uart::USART1_PID);
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
    // Always stay in bootloader mode. No kernel exists at 0x00008000 yet;
    // BootloaderEntryGpRegRet would jump there on every cold boot (GPBR7
    // is 0 at power-up), landing in empty flash → HardFault → loop{}.
    let bootloader_entry = static_init!(
        BootloaderEntryAlways,
        BootloaderEntryAlways::new()
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
    // -----------------------------------------------------------------------
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
    cortexm7::nvic::Nvic::new(6).enable();  // EFC   — flash write/erase

    // Start the UART and begin listening for bootloader commands.
    platform.bootloader.start();

    // Use minimal NVIC loop — the Tock kernel_loop has unresolved issues
    // on SAMV71 (interrupts not serviced correctly with NullScheduler).
    loop {
        unsafe {
            while let Some(interrupt) = cortexm7::nvic::next_pending() {
                match interrupt {
                    14 => peripherals.usart1.handle_interrupt(),
                    6 => peripherals.efc.handle_interrupt(),
                    _ => {}
                }
                let n = cortexm7::nvic::Nvic::new(interrupt);
                n.clear_pending();
                n.enable();
            }
            cortexm7::support::wfi();
        }
    }
}

#[cfg(not(test))]
#[panic_handler]
pub unsafe fn panic_fmt(_pi: &PanicInfo) -> ! {
    loop {}
}
