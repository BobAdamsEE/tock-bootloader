//! ISO-TP (ISO 15765-2) transport for the bootloader.
//!
//! Carries messages larger than a CAN frame by splitting them into a First
//! Frame plus Consecutive Frames, with the receiver granting permission to
//! send through Flow Control frames.
//!
//! ```text
//!   single frame      0x0L data...              L <= 7
//!   first frame       0x1H LL data...           length = HLL, 12 bits
//!   consecutive frame 0x2S data...              S = sequence number, wraps 0..15
//!   flow control      0x3F BS STmin             F = 0 clear-to-send, 1 wait, 2 overflow
//! ```
//!
//! Scope is deliberately narrow, because the bootloader is strictly
//! request/response over one pair of identifiers:
//!
//! * One connection. There is no addressing extension and no support for
//!   several concurrent conversations.
//! * Half duplex. A transmission is refused while a reception is in progress
//!   and vice versa; the bootloader never does both at once.
//! * Classic CAN only, so a consecutive frame carries 7 bytes.
//!
//! # Flow control we advertise
//!
//! As receiver this grants `BS = 0` and `STmin = 0`: send the whole message
//! without waiting for further flow control. Section 4 of the design document
//! suggested `BS = 8` to provide back-pressure while flash writes were in
//! flight, but that does not apply here -- the bootloader assembles a complete
//! message *before* touching flash, so there is nothing to push back against.
//! The cost of the alternative is real: every block boundary is a stop-and-wait
//! round trip, and with a USB-attached host each one can cost milliseconds.

use core::cell::Cell;

use kernel::hil::can;
use kernel::hil::time::{Alarm, AlarmClient, ConvertTicks};
use kernel::utilities::cells::{OptionalCell, TakeCell};
use kernel::ErrorCode;

/// Bytes carried by a classic CAN frame.
const FRAME_LEN: usize = can::STANDARD_CAN_PACKET_SIZE;
/// Payload bytes in a single frame (one PCI byte).
const SF_MAX: usize = FRAME_LEN - 1;
/// Payload bytes in a first frame (two PCI bytes).
const FF_DATA: usize = FRAME_LEN - 2;
/// Payload bytes in a consecutive frame (one PCI byte).
const CF_DATA: usize = FRAME_LEN - 1;

/// Largest message expressible without the 2016 escape encoding.
pub const MAX_MESSAGE_LEN: usize = 4095;

const PCI_SF: u8 = 0x00;
const PCI_FF: u8 = 0x10;
const PCI_CF: u8 = 0x20;
const PCI_FC: u8 = 0x30;
const PCI_MASK: u8 = 0xF0;

const FS_CTS: u8 = 0;
const FS_WAIT: u8 = 1;
const FS_OVFLW: u8 = 2;

/// Flow control this end grants as receiver. See the module documentation.
const RX_BLOCK_SIZE: u8 = 0;
const RX_STMIN: u8 = 0;

/// Sender waiting for a flow control frame, milliseconds (ISO 15765-2 N_Bs).
const N_BS_MS: u32 = 1000;
/// Receiver waiting for the next consecutive frame, milliseconds (N_Cr).
const N_CR_MS: u32 = 1000;

/// Completion callbacks for whole messages.
pub trait IsoTpClient {
    fn message_transmitted(&self, buffer: &'static mut [u8], result: Result<(), ErrorCode>);
    fn message_received(&self, buffer: &'static mut [u8], len: usize, result: Result<(), ErrorCode>);
}

#[derive(Copy, Clone, PartialEq)]
enum State {
    /// Nothing in flight. A reception may start at any time.
    Idle,
    /// Received a first frame; collecting consecutive frames.
    RxAssembling,
    /// Sent a first frame or finished a block; waiting for flow control.
    TxWaitFlowControl,
    /// Clear to send; a consecutive frame is with the CAN driver.
    TxSending,
    /// Holding off for the separation time the receiver asked for.
    TxSeparation,
}

pub struct IsoTp<'a, C: can::Can + 'static, A: Alarm<'a> + 'a> {
    can: &'a C,
    alarm: &'a A,

    /// Identifier this end receives on, and the one it transmits on.
    rx_id: can::Id,
    tx_id: can::Id,

    client: OptionalCell<&'a dyn IsoTpClient>,
    state: Cell<State>,

    /// Scratch for the CAN frame currently being transmitted.
    frame: TakeCell<'static, [u8; FRAME_LEN]>,

    /// Frame buffer handed to the CAN driver for reception. The driver keeps
    /// it until reception is stopped.
    rx_frame: TakeCell<'static, [u8; FRAME_LEN]>,

    /// Message being assembled, and how much of it has arrived.
    rx_buffer: TakeCell<'static, [u8]>,
    rx_len: Cell<usize>,
    rx_offset: Cell<usize>,
    rx_next_sn: Cell<u8>,

    /// Message being sent, and how much has gone out.
    tx_buffer: TakeCell<'static, [u8]>,
    tx_len: Cell<usize>,
    tx_offset: Cell<usize>,
    tx_next_sn: Cell<u8>,
    /// Frames still allowed in this block; 0 means unlimited.
    tx_block_remaining: Cell<u8>,
    tx_block_size: Cell<u8>,
    tx_stmin_ms: Cell<u32>,
}

impl<'a, C: can::Can, A: Alarm<'a>> IsoTp<'a, C, A> {
    pub fn new(
        can: &'a C,
        alarm: &'a A,
        rx_id: can::Id,
        tx_id: can::Id,
        frame: &'static mut [u8; FRAME_LEN],
        rx_frame: &'static mut [u8; FRAME_LEN],
    ) -> IsoTp<'a, C, A> {
        IsoTp {
            can,
            alarm,
            rx_id,
            tx_id,
            client: OptionalCell::empty(),
            state: Cell::new(State::Idle),
            frame: TakeCell::new(frame),
            rx_frame: TakeCell::new(rx_frame),
            rx_buffer: TakeCell::empty(),
            rx_len: Cell::new(0),
            rx_offset: Cell::new(0),
            rx_next_sn: Cell::new(1),
            tx_buffer: TakeCell::empty(),
            tx_len: Cell::new(0),
            tx_offset: Cell::new(0),
            tx_next_sn: Cell::new(1),
            tx_block_remaining: Cell::new(0),
            tx_block_size: Cell::new(0),
            tx_stmin_ms: Cell::new(0),
        }
    }

    pub fn set_client(&self, client: &'a dyn IsoTpClient) {
        self.client.set(client);
    }

    /// Begin delivering received frames.
    ///
    /// Must be called once the controller is enabled. Without it the frames
    /// still land in the peripheral's receive FIFO -- so the FIFO fill level
    /// looks healthy -- but the driver never raises the FIFO interrupt and
    /// nothing is ever handed up.
    pub fn start_receive(&self) -> Result<(), ErrorCode> {
        match self.rx_frame.take() {
            Some(frame) => match can::Receive::start_receive_process(self.can, frame) {
                Ok(()) => Ok(()),
                Err((e, frame)) => {
                    self.rx_frame.replace(frame);
                    Err(e)
                }
            },
            None => Err(ErrorCode::ALREADY),
        }
    }

    /// Provide the buffer that incoming messages are assembled into.
    pub fn receive_message(
        &self,
        buffer: &'static mut [u8],
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.rx_buffer.is_some() {
            return Err((ErrorCode::BUSY, buffer));
        }
        self.rx_buffer.replace(buffer);
        self.rx_offset.set(0);
        self.rx_len.set(0);
        Ok(())
    }

    /// Send `len` bytes as one message.
    pub fn transmit_message(
        &self,
        buffer: &'static mut [u8],
        len: usize,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        if self.state.get() != State::Idle {
            return Err((ErrorCode::BUSY, buffer));
        }
        if len > MAX_MESSAGE_LEN || len > buffer.len() {
            return Err((ErrorCode::SIZE, buffer));
        }

        self.tx_len.set(len);
        self.tx_offset.set(0);
        self.tx_next_sn.set(1);

        if len <= SF_MAX {
            // Single frame: the whole message fits alongside its PCI byte.
            let mut frame = [0u8; FRAME_LEN];
            frame[0] = PCI_SF | (len as u8);
            frame[1..1 + len].copy_from_slice(&buffer[..len]);
            self.tx_buffer.replace(buffer);
            self.tx_offset.set(len);
            self.state.set(State::TxSending);
            self.send_frame(&frame);
        } else {
            let mut frame = [0u8; FRAME_LEN];
            frame[0] = PCI_FF | ((len >> 8) as u8 & 0x0F);
            frame[1] = (len & 0xFF) as u8;
            frame[2..].copy_from_slice(&buffer[..FF_DATA]);
            self.tx_buffer.replace(buffer);
            self.tx_offset.set(FF_DATA);
            self.state.set(State::TxWaitFlowControl);
            self.send_frame(&frame);
            self.arm(N_BS_MS);
        }
        Ok(())
    }

    /// Copy `data` into the scratch frame and hand it to the CAN driver.
    fn send_frame(&self, data: &[u8; FRAME_LEN]) {
        if let Some(frame) = self.frame.take() {
            frame.copy_from_slice(data);
            if let Err((_e, frame)) = can::Transmit::send(self.can, self.tx_id, frame, FRAME_LEN) {
                self.frame.replace(frame);
                self.fail_transmit();
            }
        }
    }

    fn send_flow_control(&self, fs: u8) {
        let mut frame = [0u8; FRAME_LEN];
        frame[0] = PCI_FC | fs;
        frame[1] = RX_BLOCK_SIZE;
        frame[2] = RX_STMIN;
        self.send_frame(&frame);
    }

    /// Send the next consecutive frame of the message being transmitted.
    fn send_consecutive(&self) {
        let offset = self.tx_offset.get();
        let len = self.tx_len.get();
        let take = core::cmp::min(CF_DATA, len - offset);

        let mut frame = [0u8; FRAME_LEN];
        frame[0] = PCI_CF | (self.tx_next_sn.get() & 0x0F);
        self.tx_buffer.map(|buffer| {
            frame[1..1 + take].copy_from_slice(&buffer[offset..offset + take]);
        });

        self.tx_offset.set(offset + take);
        self.tx_next_sn.set(self.tx_next_sn.get().wrapping_add(1) & 0x0F);
        if self.tx_block_size.get() != 0 {
            self.tx_block_remaining
                .set(self.tx_block_remaining.get().saturating_sub(1));
        }

        self.state.set(State::TxSending);
        self.send_frame(&frame);
    }

    fn arm(&self, ms: u32) {
        let now = self.alarm.now();
        let dt = self.alarm.ticks_from_ms(ms);
        self.alarm.set_alarm(now, dt);
    }

    fn disarm(&self) {
        let _ = self.alarm.disarm();
    }

    fn finish_transmit(&self, result: Result<(), ErrorCode>) {
        self.disarm();
        self.state.set(State::Idle);
        if let Some(buffer) = self.tx_buffer.take() {
            self.client
                .map(move |client| client.message_transmitted(buffer, result));
        }
    }

    fn fail_transmit(&self) {
        self.finish_transmit(Err(ErrorCode::FAIL));
    }

    fn finish_receive(&self, len: usize, result: Result<(), ErrorCode>) {
        self.disarm();
        self.state.set(State::Idle);
        self.rx_offset.set(0);
        self.rx_len.set(0);
        if let Some(buffer) = self.rx_buffer.take() {
            self.client
                .map(move |client| client.message_received(buffer, len, result));
        }
    }

    // -- Frame handling -----------------------------------------------------

    fn handle_single_frame(&self, data: &[u8; FRAME_LEN]) {
        let len = (data[0] & 0x0F) as usize;
        if len == 0 || len > SF_MAX {
            return;
        }
        let fits = self.rx_buffer.map_or(false, |buffer| {
            if buffer.len() < len {
                return false;
            }
            buffer[..len].copy_from_slice(&data[1..1 + len]);
            true
        });
        if fits {
            self.finish_receive(len, Ok(()));
        }
    }

    fn handle_first_frame(&self, data: &[u8; FRAME_LEN]) {
        let len = (((data[0] & 0x0F) as usize) << 8) | data[1] as usize;

        // A length of zero here means the 2016 escape encoding, which this
        // implementation does not need: the bootloader's largest message is a
        // 512-byte page plus its header.
        if len == 0 || len > MAX_MESSAGE_LEN {
            self.send_flow_control(FS_OVFLW);
            return;
        }
        let fits = self
            .rx_buffer
            .map_or(false, |buffer| buffer.len() >= len);
        if !fits {
            self.send_flow_control(FS_OVFLW);
            return;
        }

        self.rx_buffer.map(|buffer| {
            buffer[..FF_DATA].copy_from_slice(&data[2..]);
        });
        self.rx_len.set(len);
        self.rx_offset.set(FF_DATA);
        self.rx_next_sn.set(1);
        self.state.set(State::RxAssembling);

        self.send_flow_control(FS_CTS);
        self.arm(N_CR_MS);
    }

    fn handle_consecutive_frame(&self, data: &[u8; FRAME_LEN]) {
        if self.state.get() != State::RxAssembling {
            return;
        }
        let sn = data[0] & 0x0F;
        if sn != self.rx_next_sn.get() {
            // A gap means frames were lost; abandoning is the only safe move,
            // since the assembled message would otherwise be silently wrong.
            self.finish_receive(0, Err(ErrorCode::FAIL));
            return;
        }
        self.rx_next_sn.set(sn.wrapping_add(1) & 0x0F);

        let offset = self.rx_offset.get();
        let remaining = self.rx_len.get() - offset;
        let take = core::cmp::min(CF_DATA, remaining);
        self.rx_buffer.map(|buffer| {
            buffer[offset..offset + take].copy_from_slice(&data[1..1 + take]);
        });
        self.rx_offset.set(offset + take);

        if self.rx_offset.get() >= self.rx_len.get() {
            self.finish_receive(self.rx_len.get(), Ok(()));
        } else {
            self.arm(N_CR_MS);
        }
    }

    fn handle_flow_control(&self, data: &[u8; FRAME_LEN]) {
        if self.state.get() != State::TxWaitFlowControl {
            return;
        }
        match data[0] & 0x0F {
            FS_CTS => {
                self.disarm();
                self.tx_block_size.set(data[1]);
                self.tx_block_remaining.set(data[1]);
                // STmin 0x01..0x7F is milliseconds; 0xF1..0xF9 is 100..900 us,
                // which rounds up to 1 ms here -- the alarm cannot express it
                // and erring long is harmless.
                self.tx_stmin_ms.set(match data[2] {
                    0 => 0,
                    v @ 0x01..=0x7F => v as u32,
                    0xF1..=0xF9 => 1,
                    _ => 0,
                });
                self.send_consecutive();
            }
            FS_WAIT => {
                // Receiver is not ready yet; keep waiting.
                self.arm(N_BS_MS);
            }
            _ => {
                // Overflow, or a reserved status: the message cannot be
                // delivered.
                self.fail_transmit();
            }
        }
    }
}

impl<'a, C: can::Can, A: Alarm<'a>> can::ReceiveClient<FRAME_LEN> for IsoTp<'a, C, A> {
    fn message_received(
        &self,
        id: can::Id,
        buffer: &mut [u8; FRAME_LEN],
        _len: usize,
        status: Result<(), can::Error>,
    ) {
        if status.is_err() {
            return;
        }
        // The hardware filter should already have done this, but a mismatched
        // identifier must never be assembled into the message.
        let (want, got) = (id_raw(self.rx_id), id_raw(id));
        if want != got {
            return;
        }

        match buffer[0] & PCI_MASK {
            PCI_SF => self.handle_single_frame(buffer),
            PCI_FF => self.handle_first_frame(buffer),
            PCI_CF => self.handle_consecutive_frame(buffer),
            PCI_FC => self.handle_flow_control(buffer),
            _ => {}
        }
    }

    fn stopped(&self, buffer: &'static mut [u8; FRAME_LEN]) {
        self.rx_frame.replace(buffer);
    }
}

impl<'a, C: can::Can, A: Alarm<'a>> can::TransmitClient<FRAME_LEN> for IsoTp<'a, C, A> {
    fn transmit_complete(
        &self,
        status: Result<(), can::Error>,
        frame: &'static mut [u8; FRAME_LEN],
    ) {
        self.frame.replace(frame);

        if status.is_err() {
            if self.state.get() != State::Idle && self.tx_buffer.is_some() {
                self.fail_transmit();
            }
            return;
        }

        if self.state.get() != State::TxSending {
            // The frame just sent was a flow control frame, not part of a
            // message this end is transmitting.
            return;
        }

        if self.tx_offset.get() >= self.tx_len.get() {
            self.finish_transmit(Ok(()));
            return;
        }

        // More to send: either the block is exhausted and the receiver must
        // authorise the next one, or we continue after the separation time.
        if self.tx_block_size.get() != 0 && self.tx_block_remaining.get() == 0 {
            self.state.set(State::TxWaitFlowControl);
            self.arm(N_BS_MS);
        } else if self.tx_stmin_ms.get() > 0 {
            self.state.set(State::TxSeparation);
            self.arm(self.tx_stmin_ms.get());
        } else {
            self.send_consecutive();
        }
    }
}

impl<'a, C: can::Can, A: Alarm<'a>> AlarmClient for IsoTp<'a, C, A> {
    fn alarm(&self) {
        match self.state.get() {
            State::TxSeparation => self.send_consecutive(),
            State::TxWaitFlowControl => self.fail_transmit(),
            State::RxAssembling => self.finish_receive(0, Err(ErrorCode::FAIL)),
            _ => {}
        }
    }
}

fn id_raw(id: can::Id) -> u32 {
    match id {
        can::Id::Standard(v) => v as u32,
        can::Id::Extended(v) => v,
    }
}
