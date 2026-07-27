//! Run the bootloader on two transports at once.
//!
//! Reflashing over CAN is the goal, but UART is the recovery channel: if a CAN
//! reflash goes wrong, the way back must not itself depend on CAN. This listens
//! on both and routes each response back to whichever side asked.
//!
//! # Buffers
//!
//! The bootloader owns exactly one buffer, and both sides need one to listen
//! on, so this holds a spare. The bootloader never inspects buffer identity --
//! it takes whatever arrives and hands back whatever it finishes with -- so the
//! two circulate freely. They must be the same size.
//!
//! # Only one conversation at a time
//!
//! The bootloader is a single state machine with a single buffer, so two hosts
//! talking at once would corrupt it. A message arriving while another is being
//! handled is therefore **dropped**, and that side goes back to listening. The
//! host sees no response and retries, which is exactly how it already behaves
//! when a message is lost. In practice one host is talking and the other side
//! is idle.
//!
//! "Being handled" starts when a message is delivered upwards and ends when
//! the bootloader asks for the next one. That is the right boundary because a
//! multi-part response -- `ReadRange` transmits repeatedly before asking for
//! another command -- must count as still busy throughout.

use core::cell::Cell;

use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

use crate::transport::{BootloaderTransport, BootloaderTransportClient};

#[derive(Copy, Clone, PartialEq)]
pub enum Port {
    A,
    B,
}

pub struct DualTransport<'a, A: BootloaderTransport<'a> + 'a, B: BootloaderTransport<'a> + 'a> {
    a: &'a A,
    b: &'a B,
    client: OptionalCell<&'a dyn BootloaderTransportClient>,

    /// Side that delivered the message currently being handled.
    active: Cell<Port>,
    /// A message has been delivered upwards and not yet finished with.
    busy: Cell<bool>,

    /// Buffer not currently parked with either side, if any.
    spare: TakeCell<'static, [u8]>,
    a_listening: Cell<bool>,
    b_listening: Cell<bool>,
}

impl<'a, A: BootloaderTransport<'a>, B: BootloaderTransport<'a>> DualTransport<'a, A, B> {
    pub fn new(a: &'a A, b: &'a B, spare: &'static mut [u8]) -> DualTransport<'a, A, B> {
        DualTransport {
            a,
            b,
            client: OptionalCell::empty(),
            active: Cell::new(Port::A),
            busy: Cell::new(false),
            spare: TakeCell::new(spare),
            a_listening: Cell::new(false),
            b_listening: Cell::new(false),
        }
    }

    /// Park `buffer` with whichever side is not listening, else keep it spare.
    fn arm(&self, buffer: &'static mut [u8]) {
        if !self.a_listening.get() {
            match self.a.receive_message(buffer) {
                Ok(()) => {
                    self.a_listening.set(true);
                    return;
                }
                Err((_e, buffer)) => {
                    self.spare.replace(buffer);
                    return;
                }
            }
        }
        if !self.b_listening.get() {
            match self.b.receive_message(buffer) {
                Ok(()) => {
                    self.b_listening.set(true);
                    return;
                }
                Err((_e, buffer)) => {
                    self.spare.replace(buffer);
                    return;
                }
            }
        }
        self.spare.replace(buffer);
    }

    fn set_listening(&self, port: Port, listening: bool) {
        match port {
            Port::A => self.a_listening.set(listening),
            Port::B => self.b_listening.set(listening),
        }
    }

    fn on_received(
        &self,
        port: Port,
        buffer: &'static mut [u8],
        len: usize,
        result: Result<(), ErrorCode>,
    ) {
        self.set_listening(port, false);

        if self.busy.get() {
            // Another conversation is in progress. Drop this and listen again;
            // the host will retry.
            self.arm(buffer);
            return;
        }

        self.busy.set(true);
        self.active.set(port);
        self.client
            .map(move |client| client.message_received(buffer, len, result));
    }

    fn on_transmitted(&self, _port: Port, buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.client
            .map(move |client| client.message_transmitted(buffer, result));
    }
}

impl<'a, A: BootloaderTransport<'a>, B: BootloaderTransport<'a>> BootloaderTransport<'a>
    for DualTransport<'a, A, B>
{
    fn set_client(&self, client: &'a dyn BootloaderTransportClient) {
        self.client.set(client);
    }

    fn configure(&self) -> Result<(), ErrorCode> {
        let ra = self.a.configure();
        let rb = self.b.configure();
        // One side failing must not disable the other; report the first error
        // so a board can notice, but keep going either way.
        ra.and(rb)
    }

    fn receive_message(
        &self,
        buffer: &'static mut [u8],
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        // The bootloader asking for the next command is what ends the current
        // conversation.
        self.busy.set(false);
        self.arm(buffer);

        // A spare left over from startup lets the second side start listening
        // too.
        if let Some(spare) = self.spare.take() {
            if !self.a_listening.get() || !self.b_listening.get() {
                self.arm(spare);
            } else {
                self.spare.replace(spare);
            }
        }
        Ok(())
    }

    fn transmit_message(
        &self,
        buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        match self.active.get() {
            Port::A => self.a.transmit_message(buffer, len),
            Port::B => self.b.transmit_message(buffer, len),
        }
    }
}

/// One side of a [`DualTransport`].
///
/// A single type cannot implement [`BootloaderTransportClient`] twice, so each
/// sub-transport gets its own tagged shim to call back into.
pub struct DualPort<'a, A: BootloaderTransport<'a> + 'a, B: BootloaderTransport<'a> + 'a> {
    dual: &'a DualTransport<'a, A, B>,
    port: Port,
}

impl<'a, A: BootloaderTransport<'a>, B: BootloaderTransport<'a>> DualPort<'a, A, B> {
    pub fn new(dual: &'a DualTransport<'a, A, B>, port: Port) -> DualPort<'a, A, B> {
        DualPort { dual, port }
    }
}

impl<'a, A: BootloaderTransport<'a>, B: BootloaderTransport<'a>> BootloaderTransportClient
    for DualPort<'a, A, B>
{
    fn message_transmitted(&self, buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.dual.on_transmitted(self.port, buffer, result);
    }

    fn message_received(
        &self,
        buffer: &'static mut [u8],
        len: usize,
        result: Result<(), ErrorCode>,
    ) {
        self.dual.on_received(self.port, buffer, len, result);
    }
}
