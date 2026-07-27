//! [`BootloaderTransport`] over a UART.
//!
//! Message framing comes from the UART's receive-timeout mode: a message is
//! whatever arrives before the line goes idle for `UART_RECEIVE_TIMEOUT` bit
//! periods. That is the same behaviour the bootloader relied on before the
//! transport was abstracted, so the wire protocol is unchanged.

use core::cell::Cell;

use kernel::hil;
use kernel::utilities::cells::OptionalCell;
use kernel::ErrorCode;

use crate::transport::{BootloaderTransport, BootloaderTransportClient};

/// Idle time, in bit periods, that ends a received message.
///
/// Unchanged from the value the bootloader used before the transport was
/// abstracted. Some chips scale it: the SAMV71 driver applies a x5 multiplier
/// so the window tolerates the gaps introduced by the EDBG USB-CDC bridge.
const UART_RECEIVE_TIMEOUT: u8 = 250;

const BAUD_RATE: u32 = 115200;

pub struct UartTransport<'a, U: hil::uart::UartAdvanced<'a> + 'a> {
    uart: &'a U,
    client: OptionalCell<&'a dyn BootloaderTransportClient>,
    /// Length requested for the in-flight receive, so the buffer can be handed
    /// back intact.
    receiving: Cell<bool>,
}

impl<'a, U: hil::uart::UartAdvanced<'a>> UartTransport<'a, U> {
    pub fn new(uart: &'a U) -> UartTransport<'a, U> {
        UartTransport {
            uart,
            client: OptionalCell::empty(),
            receiving: Cell::new(false),
        }
    }
}

impl<'a, U: hil::uart::UartAdvanced<'a>> BootloaderTransport<'a> for UartTransport<'a, U> {
    fn set_client(&self, client: &'a dyn BootloaderTransportClient) {
        self.client.set(client);
    }

    fn configure(&self) -> Result<(), ErrorCode> {
        self.uart.configure(hil::uart::Parameters {
            baud_rate: BAUD_RATE,
            width: hil::uart::Width::Eight,
            stop_bits: hil::uart::StopBits::One,
            parity: hil::uart::Parity::None,
            hw_flow_control: false,
        })
    }

    fn receive_message(
        &self,
        buffer: &'static mut [u8],
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        let len = buffer.len();
        self.receiving.set(true);
        match self.uart.receive_automatic(buffer, len, UART_RECEIVE_TIMEOUT) {
            Ok(()) => Ok(()),
            Err((e, buffer)) => {
                self.receiving.set(false);
                Err((e, buffer))
            }
        }
    }

    fn transmit_message(
        &self,
        buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        self.uart.transmit_buffer(buffer, len)
    }
}

impl<'a, U: hil::uart::UartAdvanced<'a>> hil::uart::TransmitClient for UartTransport<'a, U> {
    fn transmitted_buffer(
        &self,
        buffer: &'static mut [u8],
        _tx_len: usize,
        result: Result<(), ErrorCode>,
    ) {
        self.client.map(move |client| {
            client.message_transmitted(buffer, result);
        });
    }
}

impl<'a, U: hil::uart::UartAdvanced<'a>> hil::uart::ReceiveClient for UartTransport<'a, U> {
    fn received_buffer(
        &self,
        buffer: &'static mut [u8],
        rx_len: usize,
        result: Result<(), ErrorCode>,
        _error: hil::uart::Error,
    ) {
        self.receiving.set(false);
        self.client.map(move |client| {
            client.message_received(buffer, rx_len, result);
        });
    }
}
