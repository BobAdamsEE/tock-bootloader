//! Direct flash adapter for SAMV71 — bypasses FlashLargeToSmall.
//!
//! The SAMV71's flash pages (512 bytes) are the same size as the bootloader's
//! FiveTwelvePage, so no large-to-small mapping is needed.  FlashLargeToSmall
//! has a bug where its internal page-size fallback (4096) causes an
//! out-of-bounds panic on chips whose pages are smaller than that.

use bootloader::flash_large_to_small::FiveTwelvePage;
use kernel::hil::flash;
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;
use samv71q21b::efc::{Efc, Sam71Page};

pub struct Sam71FlashDirect {
    efc: &'static Efc,
    client: OptionalCell<&'static dyn flash::Client<Self>>,
    efc_page: TakeCell<'static, Sam71Page>,
    client_page: TakeCell<'static, FiveTwelvePage>,
}

impl Sam71FlashDirect {
    pub fn new(efc: &'static Efc, efc_page: &'static mut Sam71Page) -> Self {
        Sam71FlashDirect {
            efc,
            client: OptionalCell::empty(),
            efc_page: TakeCell::new(efc_page),
            client_page: TakeCell::empty(),
        }
    }
}

impl<'a, C: flash::Client<Self>> flash::HasClient<'a, C> for Sam71FlashDirect {
    fn set_client(&'a self, client: &'a C) {
        let client_ref: &'static dyn flash::Client<Self> =
            unsafe { core::mem::transmute(client as &dyn flash::Client<Self>) };
        self.client.set(client_ref);
    }
}

impl flash::Flash for Sam71FlashDirect {
    type Page = FiveTwelvePage;

    fn read_page(
        &self,
        page_number: usize,
        buf: &'static mut FiveTwelvePage,
    ) -> Result<(), (ErrorCode, &'static mut FiveTwelvePage)> {
        const FLASH_BASE: usize = 0x0040_0000;
        const PAGE_SIZE: usize = 512;
        const PAGE_COUNT: usize = 4096;
        if page_number >= PAGE_COUNT {
            return Err((ErrorCode::INVAL, buf));
        }
        let addr = FLASH_BASE + page_number * PAGE_SIZE;
        let src = unsafe { core::slice::from_raw_parts(addr as *const u8, PAGE_SIZE) };
        buf.0.copy_from_slice(src);
        self.client.map(|c| c.read_complete(buf, Ok(())));
        Ok(())
    }

    fn write_page(
        &self,
        page_number: usize,
        buf: &'static mut FiveTwelvePage,
    ) -> Result<(), (ErrorCode, &'static mut FiveTwelvePage)> {
        self.client_page.replace(buf);
        self.efc_page.take().map_or_else(
            || Err((ErrorCode::BUSY, self.client_page.take().unwrap())),
            |efc_buf| {
                efc_buf.0.copy_from_slice(&self.client_page.map_or([0u8; 512], |p| p.0));
                self.efc
                    .write_page(page_number, efc_buf)
                    .map_err(|e| {
                        self.efc_page.replace(e.1);
                        (ErrorCode::FAIL, self.client_page.take().unwrap())
                    })
            },
        )
    }

    fn erase_page(&self, page_number: usize) -> Result<(), ErrorCode> {
        self.efc.erase_page(page_number)
    }
}

impl flash::Client<Efc> for Sam71FlashDirect {
    fn read_complete(
        &self,
        _pagebuffer: &'static mut Sam71Page,
        _result: Result<(), flash::Error>,
    ) {
        // Reads are synchronous — the callback in read_page above fires
        // inline, so the EFC's read_complete is never used.
    }

    fn write_complete(
        &self,
        pagebuffer: &'static mut Sam71Page,
        result: Result<(), flash::Error>,
    ) {
        self.efc_page.replace(pagebuffer);
        if let Some(client_buf) = self.client_page.take() {
            self.client.map(|c| c.write_complete(client_buf, result));
        }
    }

    fn erase_complete(&self, result: Result<(), flash::Error>) {
        self.client.map(|c| c.erase_complete(result));
    }
}
