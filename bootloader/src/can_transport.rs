//! [`BootloaderTransport`] over CAN, using ISO-TP for segmentation.
//!
//! The bootloader protocol is unchanged: the same `tockloader-proto` command
//! and response bytes travel in ISO-TP payloads instead of across a UART. A
//! command is one ISO-TP message, so the protocol decoder always sees a
//! complete command in one delivery -- which incidentally removes the failure
//! mode that made the UART path fragile, where a 516-byte page write could be
//! split across several receive callbacks and lose data.
//!
//! # On the escape byte
//!
//! `tockloader-proto` escapes `0xFC` in its byte stream, which ISO-TP makes
//! redundant: the transport already knows where a message starts and ends. The
//! escaping is kept anyway, because dropping it would mean changing the
//! encoder and decoder on both ends for no functional gain -- and it disappears
//! entirely at Phase 10, when UDS replaces `tockloader-proto` altogether.
//! Removing it now would be throwaway work.

use kernel::hil::can;
use kernel::hil::time::Alarm;
use kernel::utilities::cells::OptionalCell;
use kernel::ErrorCode;

use crate::isotp::{IsoTp, IsoTpClient};
use crate::transport::{BootloaderTransport, BootloaderTransportClient};

pub struct CanTransport<'a, C: can::Can + 'static, A: Alarm<'a> + 'a> {
    can: &'a C,
    isotp: &'a IsoTp<'a, C, A>,
    client: OptionalCell<&'a dyn BootloaderTransportClient>,
}

impl<'a, C: can::Can, A: Alarm<'a>> CanTransport<'a, C, A> {
    pub fn new(can: &'a C, isotp: &'a IsoTp<'a, C, A>) -> CanTransport<'a, C, A> {
        CanTransport {
            can,
            isotp,
            client: OptionalCell::empty(),
        }
    }
}

impl<'a, C: can::Can, A: Alarm<'a>> BootloaderTransport<'a> for CanTransport<'a, C, A> {
    fn set_client(&self, client: &'a dyn BootloaderTransportClient) {
        self.client.set(client);
    }

    fn configure(&self) -> Result<(), ErrorCode> {
        // Enabling is asynchronous; reception starts from the `enabled`
        // callback. A buffer handed over before then is simply parked by
        // ISO-TP and used once frames start arriving.
        can::Controller::enable(self.can)
    }

    fn receive_message(
        &self,
        buffer: &'static mut [u8],
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        self.isotp.receive_message(buffer)
    }

    fn transmit_message(
        &self,
        buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        self.isotp.transmit_message(buffer, len)
    }
}

impl<'a, C: can::Can, A: Alarm<'a>> IsoTpClient for CanTransport<'a, C, A> {
    fn message_transmitted(&self, buffer: &'static mut [u8], result: Result<(), ErrorCode>) {
        self.client
            .map(move |client| client.message_transmitted(buffer, result));
    }

    fn message_received(
        &self,
        buffer: &'static mut [u8],
        len: usize,
        result: Result<(), ErrorCode>,
    ) {
        self.client
            .map(move |client| client.message_received(buffer, len, result));
    }
}

impl<'a, C: can::Can, A: Alarm<'a>> can::ControllerClient for CanTransport<'a, C, A> {
    fn state_changed(&self, _state: can::State) {}

    fn enabled(&self, status: Result<(), ErrorCode>) {
        if status.is_ok() {
            // Frames only reach ISO-TP once reception has been started; the
            // peripheral's FIFO fills either way, so skipping this looks
            // healthy from the register side and delivers nothing.
            let _ = self.isotp.start_receive();
        }
    }

    fn disabled(&self, _status: Result<(), ErrorCode>) {}
}
