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
///
/// This is only meaningful when the jump target is *another bootloader*, which
/// consumes and clears the value later in the same boot:
///
/// ```text
/// 0x00400000  Tock Bootloader          <- writes 0x91, jumps
/// 0x00408000  Tock Bootloader (second) <- sees 0x91, stays, clears it
/// ```
///
/// When the jump target is the kernel — the normal case — nothing consumes it,
/// so it survives into the next boot and the entry check below reads it as
/// "stay in the bootloader". Writing it unconditionally therefore makes boots
/// alternate kernel / bootloader forever. It is gated behind
/// `chain_next_bootloader` for that reason; see [`BootloaderEntryGpRegRet::new`].
const DFU_MAGIC_TOCK_BOOTLOADER2: u32 = 0x91;

/// Magic value stored in the double-reset RAM location during the window after
/// a first reset. Taken from the Adafruit nRF52 bootloader.
const DFU_DBL_RESET_MAGIC: u32 = 0x5A1AD5;

/// Boots that may be attempted without the kernel reporting itself healthy
/// before the bootloader stops trying.
///
/// The counter lives in GPBR6: the bootloader increments it on the way out,
/// and a kernel that gets as far as its main loop clears it (see
/// `clear_boot_attempts`). A kernel that never gets that far therefore leaves
/// it climbing.
///
/// What this does and does not give you is worth being precise about. The
/// kernel's panic handler prints and **halts**; it does not reset. So the
/// counter advances once per *reset*, not once per crash, and this is not
/// automatic recovery from a boot loop. What it is, is an escape hatch that
/// needs no debugger and no button: reset a board with a broken kernel three
/// times and the fourth boot stays in the bootloader, ready to be reflashed.
/// Adding a watchdog later would turn the same mechanism into genuine
/// automatic recovery without changing anything here.
const BOOT_ATTEMPT_LIMIT: u32 = 3;

/// GPBR holding the boot-attempt counter. GPBR7 is the bootloader-entry magic.
const BOOT_ATTEMPT_INDEX: GpbrIndex = GpbrIndex::Gpbr6;

/// Clear the boot-attempt counter, declaring the kernel healthy.
///
/// Called by the kernel once it reaches its main loop. Anything earlier would
/// defeat the purpose -- the point is to distinguish a kernel that runs from
/// one that faults on the way up.
pub fn clear_boot_attempts(gpbr: &samv71q21b::gpbr::Gpbr) {
    gpbr.set(BOOT_ATTEMPT_INDEX, 0);
}

/// Scratch word at the very end of SAMV71Q21B SRAM (384 KB: 0x20400000–0x2045FFFF).
/// Must be reserved by the linker script so it is not zeroed at startup.
const DOUBLE_RESET_MEMORY_LOCATION: StaticRef<VolatileCell<u32>> =
    unsafe { StaticRef::new(0x2045FFF0 as *const VolatileCell<u32>) };

pub struct BootloaderEntryGpRegRet {
    samv71_gpbr: &'static samv71q21b::gpbr::Gpbr,
    double_reset: StaticRef<VolatileCell<u32>>,
    /// Whether to write [`DFU_MAGIC_TOCK_BOOTLOADER2`] when jumping out of the
    /// bootloader. Only correct when the jump target is a second, chained
    /// bootloader that will consume the value in the same boot.
    chain_next_bootloader: bool,
}

impl BootloaderEntryGpRegRet {
    /// Standard configuration: this is the only bootloader, and it jumps to the
    /// kernel.
    ///
    /// The chaining magic is not written, because nothing would consume it and
    /// it would be misread as a bootloader-entry request on the next boot.
    pub fn new(samv71_gpbr: &'static samv71q21b::gpbr::Gpbr) -> BootloaderEntryGpRegRet {
        BootloaderEntryGpRegRet {
            samv71_gpbr,
            double_reset: DOUBLE_RESET_MEMORY_LOCATION,
            chain_next_bootloader: false,
        }
    }

    /// Chained configuration: this bootloader jumps to a *second* Tock
    /// bootloader rather than to the kernel.
    ///
    /// Behaves exactly like the upstream nRF52 `BootloaderEntryGpRegRet`,
    /// writing the chaining magic on the way out so the second bootloader stays
    /// resident. Only use this when a second bootloader really is flashed.
    pub fn new_chained(samv71_gpbr: &'static samv71q21b::gpbr::Gpbr) -> BootloaderEntryGpRegRet {
        BootloaderEntryGpRegRet {
            samv71_gpbr,
            double_reset: DOUBLE_RESET_MEMORY_LOCATION,
            chain_next_bootloader: true,
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
        //
        // Unreachable in practice: the `>=` test above already matches every
        // value this one could, so 0x91 is handled there. Kept verbatim for
        // parity with the upstream nRF52 implementation, which has the same
        // redundancy.
        if self.samv71_gpbr.get(GpbrIndex::Gpbr7) >= DFU_MAGIC_TOCK_BOOTLOADER2 {
            self.samv71_gpbr.set(GpbrIndex::Gpbr7, 0);
            return true;
        }

        // Too many boots without the kernel ever reporting itself healthy.
        // Clear the counter on the way in: this boot has done its job by
        // delivering you here, and whatever gets flashed next deserves a fresh
        // set of attempts rather than inheriting the old kernel's failures.
        if self.samv71_gpbr.get(BOOT_ATTEMPT_INDEX) >= BOOT_ATTEMPT_LIMIT {
            self.samv71_gpbr.set(BOOT_ATTEMPT_INDEX, 0);
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

        // Write the chaining magic so a second bootloader (if flashed) will
        // stay -- but only when there actually is one. Otherwise clear GPBR7,
        // so a stale magic cannot be misread as a bootloader-entry request on
        // the next boot.
        self.samv71_gpbr.set(
            GpbrIndex::Gpbr7,
            if self.chain_next_bootloader {
                DFU_MAGIC_TOCK_BOOTLOADER2
            } else {
                0
            },
        );

        // Count this attempt. Incrementing *before* the jump rather than after
        // a failure is what makes the scheme work at all: there is no "after"
        // to run code in when a kernel faults on the way up. A healthy kernel
        // undoes this from its main loop.
        //
        // Saturating, so a board left resetting for a very long time cannot
        // wrap the counter back below the limit and start booting a broken
        // kernel again.
        let attempts = self.samv71_gpbr.get(BOOT_ATTEMPT_INDEX);
        self.samv71_gpbr
            .set(BOOT_ATTEMPT_INDEX, attempts.saturating_add(1));

        false
    }
}
