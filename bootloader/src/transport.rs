//! Transport abstraction for the bootloader protocol.
//!
//! The bootloader exchanges whole messages: a command arrives, a response goes
//! back. How those messages are delimited is the transport's problem, not the
//! protocol's. Over UART a message ends when the line goes idle; over CAN it
//! ends when an ISO-TP transfer completes. Keeping that behind a trait means
//! the command handling in [`crate::bootloader`] does not change when the wire
//! does.
//!
//! Buffers are passed by ownership, matching the rest of Tock: the transport
//! holds the buffer for the duration of the operation and hands it back in the
//! completion callback.

use kernel::ErrorCode;

/// A bidirectional, message-oriented link to the host.
pub trait BootloaderTransport<'a> {
    /// Set the client receiving completion callbacks. Must be called before
    /// any other method.
    fn set_client(&self, client: &'a dyn BootloaderTransportClient);

    /// Bring the link up. Called once, from `Bootloader::start`.
    fn configure(&self) -> Result<(), ErrorCode>;

    /// Begin receiving one message into `buffer`.
    ///
    /// Completion is reported through
    /// [`BootloaderTransportClient::message_received`]. Exactly one receive or
    /// transmit may be outstanding at a time, which the bootloader guarantees
    /// by always owning a single buffer.
    fn receive_message(
        &self,
        buffer: &'static mut [u8],
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;

    /// Send the first `len` bytes of `buffer` as one message.
    ///
    /// Completion is reported through
    /// [`BootloaderTransportClient::message_transmitted`].
    fn transmit_message(
        &self,
        buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])>;
}

/// Completion callbacks from a [`BootloaderTransport`].
pub trait BootloaderTransportClient {
    /// A message finished sending; `buffer` is returned to the caller.
    fn message_transmitted(&self, buffer: &'static mut [u8], result: Result<(), ErrorCode>);

    /// A message arrived in `buffer`, `len` bytes long.
    ///
    /// `result` reports a transport-level failure. The bootloader treats an
    /// error, or a zero-length message, as noise and simply listens again --
    /// opening a serial port is enough to generate both.
    fn message_received(
        &self,
        buffer: &'static mut [u8],
        len: usize,
        result: Result<(), ErrorCode>,
    );
}
