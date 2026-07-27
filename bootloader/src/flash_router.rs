//! Share one flash between two clients, safely for a *synchronous* driver.
//!
//! `capsules_core`'s `MuxFlash` cannot be used here. It records which client
//! owns the in-flight operation only *after* issuing it:
//!
//! ```text
//!     node.buffer.take().map_or_else(|| { flash.erase_page(n) }, ...);
//!     node.operation.set(Op::Idle);
//!     self.inflight.set(node);          // too late
//! ```
//!
//! The SAMV71 EFC completes inside the call -- `erase_page` invokes
//! `erase_complete` before returning, because flash commands run synchronously
//! from ROM IAP with no interrupt. The completion therefore arrives while
//! `inflight` is still empty and is dropped, and the client waits forever.
//!
//! This router sets the owner *before* forwarding, so a completion that
//! arrives during the call still routes correctly. It works equally well with
//! an asynchronous driver.
//!
//! Two ports only, which is all the bootloader needs: one for the tockloader
//! protocol on UART, one for UDS on CAN.

use core::cell::Cell;

use kernel::hil::flash::{Client, Error, Flash, HasClient};
use kernel::utilities::cells::OptionalCell;
use kernel::ErrorCode;

#[derive(Copy, Clone, PartialEq)]
pub enum Which {
    A,
    B,
}

pub struct FlashRouter<'a, F: Flash + 'static> {
    flash: &'a F,
    client_a: OptionalCell<&'a dyn Client<FlashPort<'a, F>>>,
    client_b: OptionalCell<&'a dyn Client<FlashPort<'a, F>>>,
    /// Port that issued the operation currently in progress.
    owner: Cell<Which>,
}

impl<'a, F: Flash> FlashRouter<'a, F> {
    pub fn new(flash: &'a F) -> FlashRouter<'a, F> {
        FlashRouter {
            flash,
            client_a: OptionalCell::empty(),
            client_b: OptionalCell::empty(),
            owner: Cell::new(Which::A),
        }
    }

    pub fn set_client(&self, which: Which, client: &'a dyn Client<FlashPort<'a, F>>) {
        match which {
            Which::A => self.client_a.set(client),
            Which::B => self.client_b.set(client),
        }
    }

    fn with_owner<R>(&self, f: impl FnOnce(Option<&'a dyn Client<FlashPort<'a, F>>>) -> R) -> R {
        match self.owner.get() {
            Which::A => f(self.client_a.get()),
            Which::B => f(self.client_b.get()),
        }
    }
}

impl<'a, F: Flash> Client<F> for FlashRouter<'a, F> {
    fn read_complete(&self, pagebuffer: &'static mut F::Page, result: Result<(), Error>) {
        self.with_owner(move |client| {
            if let Some(client) = client {
                client.read_complete(pagebuffer, result);
            }
        });
    }

    fn write_complete(&self, pagebuffer: &'static mut F::Page, result: Result<(), Error>) {
        self.with_owner(move |client| {
            if let Some(client) = client {
                client.write_complete(pagebuffer, result);
            }
        });
    }

    fn erase_complete(&self, result: Result<(), Error>) {
        self.with_owner(move |client| {
            if let Some(client) = client {
                client.erase_complete(result);
            }
        });
    }
}

/// One client's view of the shared flash.
pub struct FlashPort<'a, F: Flash + 'static> {
    router: &'a FlashRouter<'a, F>,
    which: Which,
}

impl<'a, F: Flash> FlashPort<'a, F> {
    pub fn new(router: &'a FlashRouter<'a, F>, which: Which) -> FlashPort<'a, F> {
        FlashPort { router, which }
    }
}

impl<'a, F: Flash> Flash for FlashPort<'a, F> {
    type Page = F::Page;

    fn read_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (ErrorCode, &'static mut Self::Page)> {
        // Claim ownership first: the completion may arrive before this returns.
        self.router.owner.set(self.which);
        self.router.flash.read_page(page_number, buf)
    }

    fn write_page(
        &self,
        page_number: usize,
        buf: &'static mut Self::Page,
    ) -> Result<(), (ErrorCode, &'static mut Self::Page)> {
        self.router.owner.set(self.which);
        self.router.flash.write_page(page_number, buf)
    }

    fn erase_page(&self, page_number: usize) -> Result<(), ErrorCode> {
        self.router.owner.set(self.which);
        self.router.flash.erase_page(page_number)
    }
}

impl<'a, F: Flash, C: Client<FlashPort<'a, F>>> HasClient<'a, C> for FlashPort<'a, F> {
    fn set_client(&'a self, client: &'a C) {
        self.router.set_client(self.which, client);
    }
}
