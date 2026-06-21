//! Decide whether to enter the bootloader based on the SAMV71 General Purpose
//! Backup Registers (GPBR).
//!
//! GPBR7 is preserved across soft resets, allowing the running kernel to write
//! a magic value and then reset in order to reboot into the bootloader.
//! A double-reset detection scheme (using the last word of SRAM) is also
//! included as a fallback for boards where software-initiated resets are not
//! convenient.

use kernel::utilities::cells::VolatileCell;
use kernel::utilities::StaticRef;
use samv71q21b::gpbr::GpbrIndex;

/// Magic value written to GPBR7 by the kernel to request a reboot into the
/// bootloader.
const DFU_MAGIC_TOCK_BOOTLOADER1: u32 = 0x90;

/// Magic value written to GPBR7 by the first bootloader when it decides *not*
/// to stay active, so that a chained second bootloader (if present) will stay.
const DFU_MAGIC_TOCK_BOOTLOADER2: u32 = 0x91;

/// Magic value stored in the double-reset RAM location during the window after
/// a first reset. Taken from the Adafruit nRF52 bootloader.
const DFU_DBL_RESET_MAGIC: u32 = 0x5A1AD5;

/// Scratch word at the very end of SAMV71Q21B SRAM (384 KB: 0x20400000–0x2045FFFF).
/// Must be reserved by the linker script so it is not zeroed at startup.
const DOUBLE_RESET_MEMORY_LOCATION: StaticRef<VolatileCell<u32>> =
    unsafe { StaticRef::new(0x2045FFF0 as *const VolatileCell<u32>) };

pub struct BootloaderEntryGpRegRet {
    samv71_gpbr: &'static samv71q21b::gpbr::Gpbr,
    double_reset: StaticRef<VolatileCell<u32>>,
}

impl BootloaderEntryGpRegRet {
    pub fn new(samv71_gpbr: &'static samv71q21b::gpbr::Gpbr) -> BootloaderEntryGpRegRet {
        BootloaderEntryGpRegRet {
            samv71_gpbr,
            double_reset: DOUBLE_RESET_MEMORY_LOCATION,
        }
    }
}

impl bootloader::interfaces::BootloaderEntry for BootloaderEntryGpRegRet {
    fn stay_in_bootloader(&self) -> bool {
        // If the kernel set GPBR7 to the bootloader-entry magic, stay active.
        if self.samv71_gpbr.get(GpbrIndex::Gpbr7) >= DFU_MAGIC_TOCK_BOOTLOADER1 {
            self.samv71_gpbr.set(GpbrIndex::Gpbr7, 0);
            return true;
        }

        // If GPBR7 holds the chaining magic, stay active unconditionally.
        // (Reached when value < DFU_MAGIC_TOCK_BOOTLOADER1; kept for parity
        // with the nRF52 implementation.)
        if self.samv71_gpbr.get(GpbrIndex::Gpbr7) >= DFU_MAGIC_TOCK_BOOTLOADER2 {
            self.samv71_gpbr.set(GpbrIndex::Gpbr7, 0);
            return true;
        }

        // Double-reset: if the magic is already in RAM, a second reset happened
        // within the detection window.
        if self.double_reset.get() == DFU_DBL_RESET_MAGIC {
            self.double_reset.set(0);
            return true;
        }

        // First reset of a potential double-reset: set the magic and spin.
        // If a second reset arrives before the loop exits, the check above will
        // fire on re-entry.
        self.double_reset.set(DFU_DBL_RESET_MAGIC);
        for _ in 0..2_000_000 {
            cortexm7::support::nop();
        }
        self.double_reset.set(0);

        // Write the chaining magic so a second bootloader (if flashed) will stay.
        self.samv71_gpbr.set(GpbrIndex::Gpbr7, DFU_MAGIC_TOCK_BOOTLOADER2);

        false
    }
}
