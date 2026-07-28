//! Copy the kernel between the active slot and its cold backup.
//!
//! # Why a copy rather than two bootable slots
//!
//! Textbook A/B keeps two images and boots whichever is current, which needs
//! either flash bank remapping or a position-independent image. This part has
//! neither: there is no bank swap, and the kernel is linked `EXEC` with its
//! entry at the active slot's address. An image sitting in the backup region
//! would not run there.
//!
//! So the backup is *cold*: never executed where it lies, only copied down over
//! the active slot when the active one is unusable. The property that matters
//! is preserved -- a bad update falls back to a known-good image -- and the
//! kernel keeps a single link address. The cost is that rollback takes a flash
//! copy rather than a pointer swap, which happens only on failure.
//!
//! # What "known good" means here
//!
//! The image that was previously installed. The host copies the active slot to
//! the backup *before* overwriting it, so the backup is by construction an
//! image that was running on this board. If that one was itself broken, a
//! rollback restores something that also fails and the board holds in the
//! bootloader -- the same place it would have stopped anyway.
//!
//! # Interrupted copies
//!
//! A copy writes the destination's integrity descriptor last, after the image,
//! and the caller is expected to invalidate it first. Losing power mid-copy
//! therefore leaves the destination without a valid descriptor rather than with
//! a stale one that claims a half-written image is fine. For the active slot
//! that means the same "do not trust this" state section 17 already defines.

use kernel::hil;
use kernel::utilities::cells::TakeCell;
use kernel::ErrorCode;

/// Bytes copied per iteration. Matches the flash page so one read maps to one
/// write with no buffering in between.
pub const PAGE: usize = 512;

/// Copies whole pages between two flash regions.
///
/// Holds its own page buffer and acts as its own flash client so that the
/// buffer comes back after each write. The SAMV71 EFC completes synchronously
/// -- `write_complete` runs before `write_page` returns -- so the loop below
/// can take the buffer again on the next iteration. This is the same reason
/// `flash_router` exists, and it works with an asynchronous driver only in the
/// sense that it would then need restructuring, which is called out here rather
/// than discovered later.
pub struct SlotCopier<'a, F: hil::flash::Flash + 'static> {
    flash: &'a F,
    page: TakeCell<'static, F::Page>,
}

impl<'a, F: hil::flash::Flash> SlotCopier<'a, F> {
    pub fn new(flash: &'a F, page: &'static mut F::Page) -> SlotCopier<'a, F> {
        SlotCopier {
            flash,
            page: TakeCell::new(page),
        }
    }

    /// Copy `len` bytes from `src` to `dst`, both page-aligned addresses.
    ///
    /// Reads the source directly: flash is memory-mapped and nothing here has
    /// written it, so there is no dirty cache line to worry about. Writes go
    /// through the driver, which erases as needed and pets the watchdog per
    /// page -- a 176 KB copy takes long enough to matter.
    pub fn copy(&self, src: u32, dst: u32, len: usize) -> Result<(), ErrorCode> {
        if src % PAGE as u32 != 0 || dst % PAGE as u32 != 0 {
            return Err(ErrorCode::INVAL);
        }

        let pages = len.div_ceil(PAGE);
        for i in 0..pages {
            let from = src as usize + i * PAGE;
            let to = dst as usize + i * PAGE;

            let page = self.page.take().ok_or(ErrorCode::NOMEM)?;
            {
                let buf = page.as_mut();
                if buf.len() < PAGE {
                    self.page.replace(page);
                    return Err(ErrorCode::SIZE);
                }
                let source = unsafe { core::slice::from_raw_parts(from as *const u8, PAGE) };
                buf[..PAGE].copy_from_slice(source);
            }

            if let Err((e, page)) = self.flash.write_page(to / PAGE, page) {
                self.page.replace(page);
                return Err(e);
            }

            // The driver returned the buffer through `write_complete` before
            // `write_page` returned. If it did not, the next `take` fails and
            // the copy stops rather than silently writing the wrong page.
            if self.page.is_none() {
                return Err(ErrorCode::FAIL);
            }
        }

        Ok(())
    }
}

impl<F: hil::flash::Flash> hil::flash::Client<F> for SlotCopier<'_, F> {
    fn read_complete(&self, page: &'static mut F::Page, _result: Result<(), hil::flash::Error>) {
        self.page.replace(page);
    }

    fn write_complete(&self, page: &'static mut F::Page, _result: Result<(), hil::flash::Error>) {
        self.page.replace(page);
    }

    fn erase_complete(&self, _result: Result<(), hil::flash::Error>) {}
}
