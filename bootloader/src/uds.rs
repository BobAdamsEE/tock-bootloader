//! A UDS (ISO 14229-1) server for reprogramming.
//!
//! Implements the subset a bootloader actually needs, driving the same
//! `hil::flash::Flash` the tockloader protocol uses. The EFC quirks that flash
//! implementation carries -- 16-page erase blocks, no implicit erase inside
//! `write_page`, the already-erased guard -- are its business, not this
//! module's.
//!
//! ```text
//!   0x10  DiagnosticSessionControl   default / programming
//!   0x11  ECUReset                   hard reset
//!   0x22  ReadDataByIdentifier       identification DIDs
//!   0x27  SecurityAccess             seed / key
//!   0x2E  WriteDataByIdentifier
//!   0x31  RoutineControl             erase memory, check memory
//!   0x34  RequestDownload
//!   0x36  TransferData
//!   0x37  RequestTransferExit
//!   0x3E  TesterPresent
//! ```
//!
//! # Response pending
//!
//! Erasing and CRC-checking take far longer than P2 (50 ms), so both answer
//! immediately with NRC 0x78 "response pending", do the work, and then send the
//! real response. The transport owns a single buffer, so the sequence is:
//! send 0x78, get the buffer back from the transmit completion, use it to run
//! the operation, then send the final response with it.
//!
//! # Security
//!
//! `SecurityAccess` here is seed/key with a fixed constant. That is
//! obfuscation, not security -- the "secret" lives in the same flash the
//! attacker is trying to write. It exists because tools expect it. The control
//! that would actually matter is verifying a signature over the image before
//! jumping to it, which belongs in the bootloader's entry path.

use core::cell::Cell;

use kernel::hil;
use kernel::utilities::cells::TakeCell;
use kernel::ErrorCode;

use crate::bootloader_crc;
use crate::transport::{BootloaderTransport, BootloaderTransportClient};

// Services.
const SID_DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
const SID_ECU_RESET: u8 = 0x11;
const SID_READ_DATA_BY_IDENTIFIER: u8 = 0x22;
const SID_SECURITY_ACCESS: u8 = 0x27;
const SID_WRITE_DATA_BY_IDENTIFIER: u8 = 0x2E;
const SID_ROUTINE_CONTROL: u8 = 0x31;
const SID_REQUEST_DOWNLOAD: u8 = 0x34;
const SID_TRANSFER_DATA: u8 = 0x36;
const SID_REQUEST_TRANSFER_EXIT: u8 = 0x37;
const SID_TESTER_PRESENT: u8 = 0x3E;

const POSITIVE_RESPONSE_OFFSET: u8 = 0x40;
const NEGATIVE_RESPONSE: u8 = 0x7F;

// Negative response codes.
const NRC_SERVICE_NOT_SUPPORTED: u8 = 0x11;
const NRC_SUBFUNCTION_NOT_SUPPORTED: u8 = 0x12;
const NRC_INCORRECT_LENGTH: u8 = 0x13;
const NRC_CONDITIONS_NOT_CORRECT: u8 = 0x22;
const NRC_REQUEST_SEQUENCE_ERROR: u8 = 0x24;
const NRC_REQUEST_OUT_OF_RANGE: u8 = 0x31;
const NRC_SECURITY_ACCESS_DENIED: u8 = 0x33;
const NRC_INVALID_KEY: u8 = 0x35;
const NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED: u8 = 0x70;
const NRC_TRANSFER_DATA_SUSPENDED: u8 = 0x71;
const NRC_GENERAL_PROGRAMMING_FAILURE: u8 = 0x72;
const NRC_WRONG_BLOCK_SEQUENCE_COUNTER: u8 = 0x73;
const NRC_RESPONSE_PENDING: u8 = 0x78;

// Sessions.
const SESSION_DEFAULT: u8 = 0x01;
const SESSION_PROGRAMMING: u8 = 0x02;

// Routine identifiers.
const ROUTINE_ERASE_MEMORY: u16 = 0xFF00;
const ROUTINE_CHECK_MEMORY: u16 = 0x0202;
const ROUTINE_START: u8 = 0x01;

// Data identifiers.
const DID_BOOT_SOFTWARE_IDENTIFICATION: u16 = 0xF180;
const DID_ACTIVE_SESSION: u16 = 0xF186;
const DID_APPLICATION_START_ADDRESS: u16 = 0xF200;

/// Payload bytes per `TransferData`, chosen to be exactly one flash page so a
/// block maps to a single write with no buffering in between.
const TRANSFER_BLOCK: usize = 512;
/// `maxNumberOfBlockLength` reported by `RequestDownload`: the block plus the
/// service and sequence bytes that precede it.
const MAX_BLOCK_LENGTH: u16 = (TRANSFER_BLOCK + 2) as u16;

/// XORed with the seed to form the expected key. Not a secret; see the module
/// documentation.
const SECURITY_KEY_XOR: u32 = 0x534F_434B;

#[derive(Copy, Clone, PartialEq)]
enum Security {
    Locked,
    SeedIssued(u32),
    Unlocked,
}

/// What the server is doing between receiving a request and answering it.
#[derive(Copy, Clone, PartialEq)]
enum Job {
    None,
    /// 0x78 sent; erase from `page` up to but not including `end`.
    Erase { page: usize, end: usize },
    /// Writing one downloaded block.
    Write,
    /// 0x78 sent; CRC over `address` for `remaining` more bytes.
    Crc {
        address: u32,
        remaining: u32,
        crc: u32,
    },
    /// Positive response sent for ECUReset; reset once it is on the wire.
    Reset,
}

pub struct UdsServer<'a, T: BootloaderTransport<'a> + 'a, F: hil::flash::Flash + 'static> {
    transport: &'a T,
    flash: &'a F,
    reset_function: &'a (dyn Fn() + 'a),

    page_buffer: TakeCell<'static, F::Page>,
    /// The message buffer, held while a job runs.
    buffer: TakeCell<'static, [u8]>,

    session: Cell<u8>,
    security: Cell<Security>,
    job: Cell<Job>,

    /// Active `RequestDownload`.
    download_active: Cell<bool>,
    download_address: Cell<u32>,
    download_remaining: Cell<u32>,
    next_block_sequence: Cell<u8>,

    /// Guards against recursing once per page.
    ///
    /// The SAMV71 flash driver completes inside the call, so a naive
    /// "issue the next page from the completion callback" chain would consume
    /// a stack frame per page -- hundreds of them for a kernel-sized erase.
    /// `stepping` says a driving loop is already running, so the completion
    /// only has to flag that it should go round again.
    stepping: Cell<bool>,
    step_again: Cell<bool>,

    /// Where the application region starts, used to bound writes.
    app_start: u32,
    flash_end: u32,
}

impl<'a, T: BootloaderTransport<'a>, F: hil::flash::Flash> UdsServer<'a, T, F> {
    pub fn new(
        transport: &'a T,
        flash: &'a F,
        reset_function: &'a (dyn Fn() + 'a),
        page_buffer: &'static mut F::Page,
        buffer: &'static mut [u8],
        app_start: u32,
        flash_end: u32,
    ) -> UdsServer<'a, T, F> {
        UdsServer {
            transport,
            flash,
            reset_function,
            page_buffer: TakeCell::new(page_buffer),
            buffer: TakeCell::new(buffer),
            session: Cell::new(SESSION_DEFAULT),
            security: Cell::new(Security::Locked),
            job: Cell::new(Job::None),
            download_active: Cell::new(false),
            download_address: Cell::new(0),
            download_remaining: Cell::new(0),
            next_block_sequence: Cell::new(1),
            stepping: Cell::new(false),
            step_again: Cell::new(false),
            app_start,
            flash_end,
        }
    }

    pub fn start(&self) {
        let _ = self.transport.configure();
        self.buffer.take().map(|buffer| {
            let _ = self.transport.receive_message(buffer);
        });
    }

    fn listen(&self) {
        self.buffer.take().map(|buffer| {
            let _ = self.transport.receive_message(buffer);
        });
    }

    fn send(&self, buffer: &'static mut [u8], len: usize) {
        if let Err((_e, buffer)) = self.transport.transmit_message(buffer, len) {
            self.buffer.replace(buffer);
            self.listen();
        }
    }

    fn send_negative(&self, buffer: &'static mut [u8], sid: u8, nrc: u8) {
        buffer[0] = NEGATIVE_RESPONSE;
        buffer[1] = sid;
        buffer[2] = nrc;
        self.send(buffer, 3);
    }

    /// Answer "still working" so the tester extends its timeout to P2*.
    fn send_pending(&self, buffer: &'static mut [u8], sid: u8) {
        self.send_negative(buffer, sid, NRC_RESPONSE_PENDING);
    }

    fn programming_session(&self) -> bool {
        self.session.get() == SESSION_PROGRAMMING
    }

    fn unlocked(&self) -> bool {
        self.security.get() == Security::Unlocked
    }

    fn page_size(&self) -> usize {
        self.page_buffer.map_or(512, |page| page.as_mut().len())
    }

    // -- Request dispatch ---------------------------------------------------

    fn handle(&self, buffer: &'static mut [u8], len: usize) {
        if len == 0 {
            self.buffer.replace(buffer);
            self.listen();
            return;
        }
        let sid = buffer[0];

        match sid {
            SID_DIAGNOSTIC_SESSION_CONTROL => self.session_control(buffer, len),
            SID_ECU_RESET => self.ecu_reset(buffer, len),
            SID_READ_DATA_BY_IDENTIFIER => self.read_data_by_identifier(buffer, len),
            SID_SECURITY_ACCESS => self.security_access(buffer, len),
            SID_WRITE_DATA_BY_IDENTIFIER => self.write_data_by_identifier(buffer, len),
            SID_ROUTINE_CONTROL => self.routine_control(buffer, len),
            SID_REQUEST_DOWNLOAD => self.request_download(buffer, len),
            SID_TRANSFER_DATA => self.transfer_data(buffer, len),
            SID_REQUEST_TRANSFER_EXIT => self.request_transfer_exit(buffer, len),
            SID_TESTER_PRESENT => self.tester_present(buffer, len),
            _ => self.send_negative(buffer, sid, NRC_SERVICE_NOT_SUPPORTED),
        }
    }

    fn session_control(&self, buffer: &'static mut [u8], len: usize) {
        if len < 2 {
            return self.send_negative(buffer, SID_DIAGNOSTIC_SESSION_CONTROL, NRC_INCORRECT_LENGTH);
        }
        let sub = buffer[1] & 0x7F;
        match sub {
            SESSION_DEFAULT | SESSION_PROGRAMMING => {
                self.session.set(sub);
                if sub == SESSION_DEFAULT {
                    // Leaving the programming session drops any unlock and any
                    // download in progress.
                    self.security.set(Security::Locked);
                    self.download_active.set(false);
                }
                buffer[0] = SID_DIAGNOSTIC_SESSION_CONTROL + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = sub;
                // P2 = 50 ms, P2* = 5000 ms, both in the units ISO 14229 uses
                // (1 ms and 10 ms respectively).
                buffer[2] = 0x00;
                buffer[3] = 0x32;
                buffer[4] = 0x01;
                buffer[5] = 0xF4;
                self.send(buffer, 6);
            }
            _ => self.send_negative(
                buffer,
                SID_DIAGNOSTIC_SESSION_CONTROL,
                NRC_SUBFUNCTION_NOT_SUPPORTED,
            ),
        }
    }

    fn ecu_reset(&self, buffer: &'static mut [u8], len: usize) {
        if len < 2 {
            return self.send_negative(buffer, SID_ECU_RESET, NRC_INCORRECT_LENGTH);
        }
        let sub = buffer[1] & 0x7F;
        if sub != 0x01 {
            return self.send_negative(buffer, SID_ECU_RESET, NRC_SUBFUNCTION_NOT_SUPPORTED);
        }
        // Answer first, reset once the response is actually on the wire.
        buffer[0] = SID_ECU_RESET + POSITIVE_RESPONSE_OFFSET;
        buffer[1] = sub;
        self.job.set(Job::Reset);
        self.send(buffer, 2);
    }

    fn read_data_by_identifier(&self, buffer: &'static mut [u8], len: usize) {
        if len < 3 {
            return self.send_negative(buffer, SID_READ_DATA_BY_IDENTIFIER, NRC_INCORRECT_LENGTH);
        }
        let did = ((buffer[1] as u16) << 8) | buffer[2] as u16;

        match did {
            DID_BOOT_SOFTWARE_IDENTIFICATION => {
                const NAME: &[u8] = b"TOCKBL 0.1.0";
                buffer[0] = SID_READ_DATA_BY_IDENTIFIER + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = (did >> 8) as u8;
                buffer[2] = did as u8;
                buffer[3..3 + NAME.len()].copy_from_slice(NAME);
                self.send(buffer, 3 + NAME.len());
            }
            DID_ACTIVE_SESSION => {
                buffer[0] = SID_READ_DATA_BY_IDENTIFIER + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = (did >> 8) as u8;
                buffer[2] = did as u8;
                buffer[3] = self.session.get();
                self.send(buffer, 4);
            }
            DID_APPLICATION_START_ADDRESS => {
                let addr = self.app_start;
                buffer[0] = SID_READ_DATA_BY_IDENTIFIER + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = (did >> 8) as u8;
                buffer[2] = did as u8;
                buffer[3..7].copy_from_slice(&addr.to_be_bytes());
                self.send(buffer, 7);
            }
            _ => self.send_negative(
                buffer,
                SID_READ_DATA_BY_IDENTIFIER,
                NRC_REQUEST_OUT_OF_RANGE,
            ),
        }
    }

    fn security_access(&self, buffer: &'static mut [u8], len: usize) {
        if len < 2 {
            return self.send_negative(buffer, SID_SECURITY_ACCESS, NRC_INCORRECT_LENGTH);
        }
        if !self.programming_session() {
            return self.send_negative(buffer, SID_SECURITY_ACCESS, NRC_CONDITIONS_NOT_CORRECT);
        }
        let sub = buffer[1];

        match sub {
            0x01 => {
                // Seed derived from the flash end address so it is not a fixed
                // constant, which is the most this scheme can honestly offer.
                let seed = self.flash_end.rotate_left(7) ^ 0xA5A5_1234;
                self.security.set(Security::SeedIssued(seed));
                buffer[0] = SID_SECURITY_ACCESS + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = sub;
                buffer[2..6].copy_from_slice(&seed.to_be_bytes());
                self.send(buffer, 6);
            }
            0x02 => {
                if len < 6 {
                    return self.send_negative(buffer, SID_SECURITY_ACCESS, NRC_INCORRECT_LENGTH);
                }
                let key = u32::from_be_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]);
                match self.security.get() {
                    Security::SeedIssued(seed) if key == seed ^ SECURITY_KEY_XOR => {
                        self.security.set(Security::Unlocked);
                        buffer[0] = SID_SECURITY_ACCESS + POSITIVE_RESPONSE_OFFSET;
                        buffer[1] = sub;
                        self.send(buffer, 2);
                    }
                    Security::SeedIssued(_) => {
                        // A wrong key returns to locked, so a guesser must ask
                        // for a fresh seed each attempt.
                        self.security.set(Security::Locked);
                        self.send_negative(buffer, SID_SECURITY_ACCESS, NRC_INVALID_KEY);
                    }
                    _ => self.send_negative(
                        buffer,
                        SID_SECURITY_ACCESS,
                        NRC_REQUEST_SEQUENCE_ERROR,
                    ),
                }
            }
            _ => self.send_negative(buffer, SID_SECURITY_ACCESS, NRC_SUBFUNCTION_NOT_SUPPORTED),
        }
    }

    fn write_data_by_identifier(&self, buffer: &'static mut [u8], len: usize) {
        if len < 3 {
            return self.send_negative(buffer, SID_WRITE_DATA_BY_IDENTIFIER, NRC_INCORRECT_LENGTH);
        }
        if !self.unlocked() {
            return self.send_negative(
                buffer,
                SID_WRITE_DATA_BY_IDENTIFIER,
                NRC_SECURITY_ACCESS_DENIED,
            );
        }
        // No writable identifiers yet; the service exists so a tester sees a
        // well-formed refusal rather than "service not supported".
        self.send_negative(
            buffer,
            SID_WRITE_DATA_BY_IDENTIFIER,
            NRC_REQUEST_OUT_OF_RANGE,
        )
    }

    fn tester_present(&self, buffer: &'static mut [u8], len: usize) {
        if len < 2 {
            return self.send_negative(buffer, SID_TESTER_PRESENT, NRC_INCORRECT_LENGTH);
        }
        // Suppress-positive-response bit set: stay silent, per ISO 14229.
        if buffer[1] & 0x80 != 0 {
            self.buffer.replace(buffer);
            self.listen();
            return;
        }
        buffer[0] = SID_TESTER_PRESENT + POSITIVE_RESPONSE_OFFSET;
        buffer[1] = 0x00;
        self.send(buffer, 2);
    }

    fn routine_control(&self, buffer: &'static mut [u8], len: usize) {
        if len < 4 {
            return self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_INCORRECT_LENGTH);
        }
        if !self.unlocked() {
            return self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_SECURITY_ACCESS_DENIED);
        }
        let sub = buffer[1];
        let routine = ((buffer[2] as u16) << 8) | buffer[3] as u16;

        if sub != ROUTINE_START {
            return self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_SUBFUNCTION_NOT_SUPPORTED);
        }

        match routine {
            ROUTINE_ERASE_MEMORY => {
                if len < 12 {
                    return self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_INCORRECT_LENGTH);
                }
                let address = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
                let size = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
                if !self.range_ok(address, size) {
                    return self.send_negative(
                        buffer,
                        SID_ROUTINE_CONTROL,
                        NRC_REQUEST_OUT_OF_RANGE,
                    );
                }
                let page_size = self.page_size() as u32;
                let first = (address / page_size) as usize;
                let last = ((address + size + page_size - 1) / page_size) as usize;
                self.job.set(Job::Erase {
                    page: first,
                    end: last,
                });
                // Erasing 8 KB blocks takes far longer than P2.
                self.send_pending(buffer, SID_ROUTINE_CONTROL);
            }
            ROUTINE_CHECK_MEMORY => {
                if len < 12 {
                    return self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_INCORRECT_LENGTH);
                }
                let address = u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]);
                let size = u32::from_be_bytes([buffer[8], buffer[9], buffer[10], buffer[11]]);
                if !self.range_ok(address, size) {
                    return self.send_negative(
                        buffer,
                        SID_ROUTINE_CONTROL,
                        NRC_REQUEST_OUT_OF_RANGE,
                    );
                }
                self.job.set(Job::Crc {
                    address,
                    remaining: size,
                    crc: 0xFFFF_FFFF,
                });
                self.send_pending(buffer, SID_ROUTINE_CONTROL);
            }
            _ => self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_REQUEST_OUT_OF_RANGE),
        }
    }

    fn range_ok(&self, address: u32, size: u32) -> bool {
        size > 0
            && address >= self.app_start
            && address.checked_add(size).map_or(false, |e| e <= self.flash_end)
    }

    fn request_download(&self, buffer: &'static mut [u8], len: usize) {
        // dataFormatIdentifier, addressAndLengthFormatIdentifier, then a
        // 4-byte address and 4-byte size.
        if len < 11 {
            return self.send_negative(buffer, SID_REQUEST_DOWNLOAD, NRC_INCORRECT_LENGTH);
        }
        if !self.unlocked() {
            return self.send_negative(buffer, SID_REQUEST_DOWNLOAD, NRC_SECURITY_ACCESS_DENIED);
        }
        if self.download_active.get() {
            return self.send_negative(
                buffer,
                SID_REQUEST_DOWNLOAD,
                NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED,
            );
        }
        if buffer[1] != 0x00 {
            // No compression or encryption is supported.
            return self.send_negative(buffer, SID_REQUEST_DOWNLOAD, NRC_REQUEST_OUT_OF_RANGE);
        }
        if buffer[2] != 0x44 {
            // Only 4-byte address and 4-byte length.
            return self.send_negative(buffer, SID_REQUEST_DOWNLOAD, NRC_REQUEST_OUT_OF_RANGE);
        }
        let address = u32::from_be_bytes([buffer[3], buffer[4], buffer[5], buffer[6]]);
        let size = u32::from_be_bytes([buffer[7], buffer[8], buffer[9], buffer[10]]);

        if !self.range_ok(address, size) || address as usize % self.page_size() != 0 {
            return self.send_negative(buffer, SID_REQUEST_DOWNLOAD, NRC_REQUEST_OUT_OF_RANGE);
        }

        self.download_active.set(true);
        self.download_address.set(address);
        self.download_remaining.set(size);
        self.next_block_sequence.set(1);

        buffer[0] = SID_REQUEST_DOWNLOAD + POSITIVE_RESPONSE_OFFSET;
        buffer[1] = 0x20; // lengthFormatIdentifier: maxNumberOfBlockLength is 2 bytes
        buffer[2] = (MAX_BLOCK_LENGTH >> 8) as u8;
        buffer[3] = MAX_BLOCK_LENGTH as u8;
        self.send(buffer, 4);
    }

    fn transfer_data(&self, buffer: &'static mut [u8], len: usize) {
        if len < 2 {
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_INCORRECT_LENGTH);
        }
        if !self.download_active.get() {
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_REQUEST_SEQUENCE_ERROR);
        }
        let sequence = buffer[1];
        let expected = self.next_block_sequence.get();

        if sequence != expected {
            // Repeating the previous block is how a tester recovers from a lost
            // response, and must not be treated as an error.
            if sequence == expected.wrapping_sub(1) {
                buffer[0] = SID_TRANSFER_DATA + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = sequence;
                return self.send(buffer, 2);
            }
            return self.send_negative(
                buffer,
                SID_TRANSFER_DATA,
                NRC_WRONG_BLOCK_SEQUENCE_COUNTER,
            );
        }

        let data_len = len - 2;
        if data_len == 0 || data_len > TRANSFER_BLOCK {
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_INCORRECT_LENGTH);
        }
        if data_len as u32 > self.download_remaining.get() {
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_REQUEST_OUT_OF_RANGE);
        }

        // Copy into the page buffer, padding a short final block with the
        // erased value so the whole page is well defined.
        let page_size = self.page_size();
        let copied = self.page_buffer.map_or(false, |page| {
            let page = page.as_mut();
            for byte in page.iter_mut() {
                *byte = 0xFF;
            }
            page[..data_len].copy_from_slice(&buffer[2..2 + data_len]);
            let _ = page_size;
            true
        });
        if !copied {
            return self.send_negative(
                buffer,
                SID_TRANSFER_DATA,
                NRC_GENERAL_PROGRAMMING_FAILURE,
            );
        }

        let page_number = (self.download_address.get() as usize) / page_size;
        self.buffer.replace(buffer);
        self.job.set(Job::Write);

        if let Some(page) = self.page_buffer.take() {
            if let Err((_e, page)) = self.flash.write_page(page_number, page) {
                self.page_buffer.replace(page);
                self.job.set(Job::None);
                if let Some(buffer) = self.buffer.take() {
                    self.send_negative(
                        buffer,
                        SID_TRANSFER_DATA,
                        NRC_GENERAL_PROGRAMMING_FAILURE,
                    );
                }
                return;
            }
            // Advance now; the completion only has to report it.
            self.download_address
                .set(self.download_address.get() + data_len as u32);
            self.download_remaining
                .set(self.download_remaining.get() - data_len as u32);
            self.next_block_sequence.set(expected.wrapping_add(1));
        }
    }

    fn request_transfer_exit(&self, buffer: &'static mut [u8], _len: usize) {
        if !self.download_active.get() {
            return self.send_negative(
                buffer,
                SID_REQUEST_TRANSFER_EXIT,
                NRC_REQUEST_SEQUENCE_ERROR,
            );
        }
        if self.download_remaining.get() != 0 {
            // The tester stopped early; the image would be incomplete.
            self.download_active.set(false);
            return self.send_negative(
                buffer,
                SID_REQUEST_TRANSFER_EXIT,
                NRC_TRANSFER_DATA_SUSPENDED,
            );
        }
        self.download_active.set(false);
        buffer[0] = SID_REQUEST_TRANSFER_EXIT + POSITIVE_RESPONSE_OFFSET;
        self.send(buffer, 1);
    }

    // -- Long-running jobs --------------------------------------------------

    /// Continue whatever was deferred behind a 0x78, now that the buffer is
    /// back from transmitting it.
    fn resume_job(&self, buffer: &'static mut [u8]) {
        match self.job.get() {
            Job::Erase { .. } | Job::Crc { .. } => {
                self.buffer.replace(buffer);
                self.step();
            }
            Job::Reset => {
                self.buffer.replace(buffer);
                (self.reset_function)();
            }
            _ => {
                self.buffer.replace(buffer);
                self.listen();
            }
        }
    }

    /// Drive the current multi-page job forward.
    ///
    /// Iterative rather than recursive: with a synchronous flash driver the
    /// completion callback lands while this is still on the stack, so it sets
    /// `step_again` and this loop picks the work up instead of nesting.
    fn step(&self) {
        if self.stepping.get() {
            self.step_again.set(true);
            return;
        }
        self.stepping.set(true);

        loop {
            self.step_again.set(false);

            match self.job.get() {
                Job::Erase { page, end } => {
                    if page >= end {
                        self.job.set(Job::None);
                        self.stepping.set(false);
                        return self.finish_routine(ROUTINE_ERASE_MEMORY, None);
                    }
                    // Advance first so the completion just reports progress.
                    self.job.set(Job::Erase {
                        page: page + 1,
                        end,
                    });
                    if self.flash.erase_page(page).is_err() {
                        self.job.set(Job::None);
                        self.stepping.set(false);
                        return self.fail_routine();
                    }
                }
                Job::Crc {
                    address, remaining, ..
                } => {
                    if remaining == 0 {
                        let crc = match self.job.get() {
                            Job::Crc { crc, .. } => crc,
                            _ => 0,
                        };
                        self.job.set(Job::None);
                        self.stepping.set(false);
                        return self.finish_routine(
                            ROUTINE_CHECK_MEMORY,
                            Some(crc ^ 0xFFFF_FFFF),
                        );
                    }
                    let page_size = self.page_size();
                    match self.page_buffer.take() {
                        Some(page) => {
                            if let Err((_e, page)) =
                                self.flash.read_page(address as usize / page_size, page)
                            {
                                self.page_buffer.replace(page);
                                self.job.set(Job::None);
                                self.stepping.set(false);
                                return self.fail_routine();
                            }
                        }
                        None => {
                            self.job.set(Job::None);
                            self.stepping.set(false);
                            return self.fail_routine();
                        }
                    }
                }
                _ => break,
            }

            if !self.step_again.get() {
                // The driver has not completed yet; its callback will call
                // back into here.
                break;
            }
        }

        self.stepping.set(false);
    }

    fn finish_routine(&self, routine: u16, value: Option<u32>) {
        if let Some(buffer) = self.buffer.take() {
            buffer[0] = SID_ROUTINE_CONTROL + POSITIVE_RESPONSE_OFFSET;
            buffer[1] = ROUTINE_START;
            buffer[2] = (routine >> 8) as u8;
            buffer[3] = routine as u8;
            match value {
                Some(v) => {
                    buffer[4..8].copy_from_slice(&v.to_be_bytes());
                    self.send(buffer, 8);
                }
                None => self.send(buffer, 4),
            }
        }
    }

    fn fail_routine(&self) {
        if let Some(buffer) = self.buffer.take() {
            self.send_negative(buffer, SID_ROUTINE_CONTROL, NRC_GENERAL_PROGRAMMING_FAILURE);
        }
    }
}

impl<'a, T: BootloaderTransport<'a>, F: hil::flash::Flash> BootloaderTransportClient
    for UdsServer<'a, T, F>
{
    fn message_received(
        &self,
        buffer: &'static mut [u8],
        len: usize,
        result: Result<(), ErrorCode>,
    ) {
        if result.is_err() {
            self.buffer.replace(buffer);
            self.listen();
            return;
        }
        self.handle(buffer, len);
    }

    fn message_transmitted(&self, buffer: &'static mut [u8], _result: Result<(), ErrorCode>) {
        match self.job.get() {
            Job::None => {
                self.buffer.replace(buffer);
                self.listen();
            }
            // A 0x78 or a final response just went out; either continue the
            // job or, if it finished, go back to listening.
            _ => self.resume_job(buffer),
        }
    }
}

impl<'a, T: BootloaderTransport<'a>, F: hil::flash::Flash> hil::flash::Client<F>
    for UdsServer<'a, T, F>
{
    fn read_complete(
        &self,
        pagebuffer: &'static mut F::Page,
        _result: Result<(), hil::flash::Error>,
    ) {
        if let Job::Crc {
            address,
            remaining,
            crc,
        } = self.job.get()
        {
            let page_size = pagebuffer.as_mut().len();
            let offset = address as usize % page_size;
            let take = core::cmp::min(page_size - offset, remaining as usize);

            let mut new_crc = crc;
            for i in 0..take {
                let index = (new_crc ^ pagebuffer.as_mut()[offset + i] as u32) & 0xFF;
                new_crc = bootloader_crc::CRC32_TABLE[index as usize] ^ (new_crc >> 8);
            }
            self.page_buffer.replace(pagebuffer);
            self.job.set(Job::Crc {
                address: address + take as u32,
                remaining: remaining - take as u32,
                crc: new_crc,
            });
            self.step();
        } else {
            self.page_buffer.replace(pagebuffer);
        }
    }

    fn write_complete(
        &self,
        pagebuffer: &'static mut F::Page,
        result: Result<(), hil::flash::Error>,
    ) {
        self.page_buffer.replace(pagebuffer);
        if self.job.get() != Job::Write {
            return;
        }
        self.job.set(Job::None);

        if let Some(buffer) = self.buffer.take() {
            if result.is_err() {
                self.send_negative(buffer, SID_TRANSFER_DATA, NRC_GENERAL_PROGRAMMING_FAILURE);
            } else {
                buffer[0] = SID_TRANSFER_DATA + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = self.next_block_sequence.get().wrapping_sub(1);
                self.send(buffer, 2);
            }
        }
    }

    fn erase_complete(&self, result: Result<(), hil::flash::Error>) {
        if let Job::Erase { .. } = self.job.get() {
            if result.is_err() {
                self.job.set(Job::None);
                return self.fail_routine();
            }
            // `step` already advanced the page counter; just drive it onwards.
            self.step();
        }
    }
}
