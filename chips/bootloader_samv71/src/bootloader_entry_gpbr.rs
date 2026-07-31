//! Decide whether to enter the bootloader based on the SAMV71 General Purpose
//! Backup Registers (GPBR).
//!
//! GPBR7 is preserved across soft resets, allowing the running kernel to write
//! a magic value and then reset in order to reboot into the bootloader.
//!
//! Everything decided here is decided from the backup registers alone. The
//! conditions that have to *observe* something first -- `FLASH_EN`, a CAN
//! knock, a double-reset -- live in the board's `main.rs`, because each needs a
//! peripheral and a real timebase, and each ends by writing the same GPBR7
//! magic this reads. That keeps one meaning of "stay resident" and leaves this
//! file with no notion of how long anything takes.

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

/// Boots that may be attempted without the kernel reporting itself healthy
/// before the bootloader stops trying.
///
/// The counter lives in GPBR6: the bootloader increments it on the way out,
/// and a kernel that gets as far as its main loop clears it (see
/// `clear_boot_attempts`). A kernel that never gets that far therefore leaves
/// it climbing.
///
/// What this does and does not give you is worth being precise about. The
/// kernel's panic handler prints and **halts**; it does not reset. So on its
/// own this counts *resets*, not crashes -- an escape hatch needing no debugger
/// and no button, rather than automatic recovery.
///
/// The watchdog (`samv71q21b::wdt`, armed by the bootloader) is what closes
/// that gap: a kernel that stops reaching its main loop stops petting it and
/// the chip resets, so the attempts accrue on their own. A kernel that halts in
/// the panic handler still does not, since the handler runs with the core
/// spinning rather than idle -- so both paths matter.
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

pub struct BootloaderEntryGpRegRet {
    samv71_gpbr: &'static samv71q21b::gpbr::Gpbr,
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

        // No double-reset check here: the board's `main.rs` owns that, along
        // with FLASH_EN and the CAN window, and writes GPBR7 above if it fires.
        // It used to live here as a busy loop of 2,000,000 nops, which is a
        // duration only on the part it was written for -- the same source line
        // meant ~150 ms on a 64 MHz Cortex-M4 and ~15 ms on this 300 MHz
        // Cortex-M7, which is short enough that nobody could press the button
        // twice fast enough. Measuring against a real timebase needs a timer,
        // and a timer is a peripheral this file has no business holding.

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
