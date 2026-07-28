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
//!   0x35  RequestUpload
//!   0x36  TransferData               carries data either way
//!   0x37  RequestTransferExit
//!   0x3E  TesterPresent
//! ```
//!
//! # Transfers
//!
//! One at a time, in one direction, as ISO 14229 requires -- so download and
//! upload share the address, remaining-length and block-sequence state. Upload
//! exists because every `tockloader` channel needs `read_range`: without it
//! there is no listing installed applications, no inspecting them, and no
//! reading an image back to verify it.
//!
//! # Attributes
//!
//! `tockloader` reads the board's attribute table -- `board`, `arch`,
//! `appaddr` and friends -- before almost every command, and its serial channel
//! already fetches them through protocol commands rather than by reading flash
//! directly. This server does the same over UDS: one vendor DID per record,
//! `0xF2A0 + index`. That keeps the raw addresses of the table out of the write
//! range entirely, which matters because the table sits inside the bootloader's
//! own erase block.
//!
//! Two addresses sit alongside them and are easy to confuse:
//!
//! ```text
//!   0xF200  application region start   where applications live; fixed by the
//!                                      build, so read-only
//!   0xF201  kernel start address       where the bootloader jumps; lives in
//!                                      the flags, so writable
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
const SID_REQUEST_UPLOAD: u8 = 0x35;
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
/// Where the bootloader jumps. Deliberately a different identifier from
/// `0xF200`: that one answers "where do applications live" and is fixed by the
/// build, this one is the kernel entry stored in the flags, and the two have
/// been confused before precisely because they were once the same number.
const DID_KERNEL_START_ADDRESS: u16 = 0xF201;
/// One DID per attribute record, `DID_ATTRIBUTE_BASE + index`. Chosen above the
/// runtime application's 0xF210-0xF212 so a single DID map covers both.
const DID_ATTRIBUTE_BASE: u16 = 0xF2A0;
/// How many records `tockloader` iterates over.
const ATTRIBUTE_COUNT: u16 = 16;
const DID_ATTRIBUTE_LAST: u16 = DID_ATTRIBUTE_BASE + ATTRIBUTE_COUNT - 1;
/// One record: an 8-byte key, a 1-byte value length, and 55 bytes of value.
const ATTRIBUTE_RECORD: usize = 64;

/// Where the start address lives inside the bootloader flags, little-endian.
const FLAGS_START_ADDRESS_OFFSET: usize = 32;

/// Pages in one flash erase block.
///
/// The flash driver erases a whole block before writing a page that is not
/// already blank, so a single-page write into the attribute table takes the
/// vector table, the flags and the start of the bootloader's own text with it.
/// That is why a write here stages the entire block in RAM, patches it, and
/// writes it back page by page in ascending order: the first write triggers the
/// one erase and the rest find the block already clean.
///
/// Staging is necessary but not sufficient -- see `block_is_self`.
const BLOCK_PAGES: usize = 16;

/// Payload bytes per `TransferData`, chosen to be exactly one flash page so a
/// block maps to a single write with no buffering in between.
const TRANSFER_BLOCK: usize = 512;
/// `maxNumberOfBlockLength` reported by `RequestDownload` and `RequestUpload`:
/// the block plus the service and sequence bytes that precede it. It bounds
/// the request when downloading and the response when uploading.
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

/// Which direction a transfer is going, if one is open at all.
///
/// ISO 14229 allows one at a time, so download and upload share the address,
/// remaining-length and block-sequence state rather than duplicating it.
#[derive(Copy, Clone, PartialEq)]
enum Transfer {
    None,
    Download,
    Upload,
}

/// Whether a staged block rewrite can go ahead.
#[derive(Copy, Clone, PartialEq)]
enum Stage {
    Ready,
    /// The block holds the running bootloader; see `block_is_self`.
    WouldEraseSelf,
    /// Bad bounds or no staging buffer -- a bug rather than a layout fact.
    Unusable,
}

/// What the server is doing between receiving a request and answering it.
#[derive(Copy, Clone, PartialEq)]
enum Job {
    None,
    /// 0x78 sent; erase from `page` up to but not including `end`.
    Erase { page: usize, end: usize },
    /// Writing one downloaded block.
    Write,
    /// Reading the page that answers one upload block.
    Read,
    /// Reading the page that holds a flash-backed identifier.
    DidRead,
    /// 0x78 sent; copying the erase block into the staging buffer, `page` of
    /// `end`, before patching it.
    StageRead { page: usize, end: usize },
    /// Writing the patched staging buffer back, `page` of `end`.
    StageWrite { page: usize, end: usize },
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
    /// One erase block of RAM, used only while rewriting the attribute table or
    /// the flags. See `BLOCK_PAGES`.
    stage: TakeCell<'static, [u8]>,

    session: Cell<u8>,
    security: Cell<Security>,
    job: Cell<Job>,

    /// Active `RequestDownload` or `RequestUpload`.
    transfer: Cell<Transfer>,
    transfer_address: Cell<u32>,
    transfer_remaining: Cell<u32>,
    next_block_sequence: Cell<u8>,
    /// Where the block just handed out came from, so that a tester repeating
    /// the previous sequence number gets the same bytes again rather than an
    /// error. The download direction can re-acknowledge a repeat cheaply; the
    /// upload direction has to re-read, which needs these.
    prev_block_address: Cell<u32>,
    prev_block_len: Cell<usize>,

    /// The identifier a deferred `0x22` or `0x2E` is answering, so the response
    /// can echo it once the flash work finishes.
    pending_did: Cell<u16>,
    /// What a `DidRead` is fetching: where, how much, and whether to reverse it
    /// on the way out. The flags store the start address little-endian while
    /// UDS puts addresses on the wire big-endian, so that one is reversed and
    /// the attribute records are not.
    did_address: Cell<u32>,
    did_len: Cell<usize>,
    did_reverse: Cell<bool>,
    /// The bytes a staged rewrite will patch in, and how many of them are
    /// meaningful. Held here rather than in the message buffer because that
    /// buffer is reused to send the 0x78 before the work starts.
    patch: Cell<[u8; ATTRIBUTE_RECORD]>,
    patch_len: Cell<usize>,
    /// Where the patch goes within the staging buffer, and which flash page the
    /// buffer starts at.
    patch_offset: Cell<usize>,
    stage_first_page: Cell<usize>,

    /// Guards against recursing once per page.
    ///
    /// The SAMV71 flash driver completes inside the call, so a naive
    /// "issue the next page from the completion callback" chain would consume
    /// a stack frame per page -- hundreds of them for a kernel-sized erase.
    /// `stepping` says a driving loop is already running, so the completion
    /// only has to flag that it should go round again.
    stepping: Cell<bool>,
    step_again: Cell<bool>,

    /// Where the application region starts. Reported by DID 0xF200, which
    /// means "where do applications live" -- it is not a permission boundary,
    /// and must not be confused with `write_floor` below.
    app_start: u32,
    /// Lowest address any transfer, erase or CRC may touch.
    ///
    /// This is the end of the bootloader's own region, not the start of the
    /// application region: the kernel is deliberately reachable, so that a
    /// development board can be updated over CAN without a debugger. What
    /// stays unreachable is the bootloader itself -- including the attribute
    /// table, whose 8 KB erase block holds the vector table (design document
    /// section 13.5).
    ///
    /// The kernel being writable from the bus is a development-tool decision,
    /// taken knowing that seed/key is the only thing in front of it. Section
    /// 14 records it, and the production variant closes it with signature
    /// verification rather than by narrowing this.
    write_floor: u32,
    flash_end: u32,
    /// The attribute table and the bootloader flags. Reachable through their
    /// DIDs only: both sit below `write_floor`, so no transfer, erase or CRC
    /// can name them by address.
    attributes_address: u32,
    flags_address: u32,
    /// End of the bootloader's own vectors and text (`_etext`).
    ///
    /// A staged rewrite refuses any erase block below this; see
    /// `block_is_self`.
    text_end: u32,
}

impl<'a, T: BootloaderTransport<'a>, F: hil::flash::Flash> UdsServer<'a, T, F> {
    pub fn new(
        transport: &'a T,
        flash: &'a F,
        reset_function: &'a (dyn Fn() + 'a),
        page_buffer: &'static mut F::Page,
        buffer: &'static mut [u8],
        stage: &'static mut [u8],
        app_start: u32,
        write_floor: u32,
        flash_end: u32,
        attributes_address: u32,
        flags_address: u32,
        text_end: u32,
    ) -> UdsServer<'a, T, F> {
        UdsServer {
            transport,
            flash,
            reset_function,
            page_buffer: TakeCell::new(page_buffer),
            buffer: TakeCell::new(buffer),
            stage: TakeCell::new(stage),
            session: Cell::new(SESSION_DEFAULT),
            security: Cell::new(Security::Locked),
            job: Cell::new(Job::None),
            transfer: Cell::new(Transfer::None),
            prev_block_address: Cell::new(0),
            prev_block_len: Cell::new(0),
            transfer_address: Cell::new(0),
            transfer_remaining: Cell::new(0),
            next_block_sequence: Cell::new(1),
            stepping: Cell::new(false),
            step_again: Cell::new(false),
            pending_did: Cell::new(0),
            did_address: Cell::new(0),
            did_len: Cell::new(0),
            did_reverse: Cell::new(false),
            patch: Cell::new([0; ATTRIBUTE_RECORD]),
            patch_len: Cell::new(0),
            patch_offset: Cell::new(0),
            stage_first_page: Cell::new(0),
            app_start,
            write_floor,
            flash_end,
            attributes_address,
            flags_address,
            text_end,
        }
    }

    /// Would rewriting the erase block at `block_start` destroy the code doing
    /// the rewriting?
    ///
    /// Established on hardware, 2026-07-28. Staging the block in RAM is not
    /// enough on its own: the erase takes effect immediately, and on this
    /// layout the block that holds the attribute table also holds the vector
    /// table and the first pages of the bootloader's `.text`. The instruction
    /// cache carried execution just far enough to write page 0 back before the
    /// next fetch missed and found erased flash. Fifteen pages stayed blank and
    /// the board needed a debugger.
    ///
    /// So the rule is narrower than "stage it": a block may be rewritten only
    /// if the bootloader is not executing out of it. That is a property of
    /// where the linker put things, which is why it is checked here rather than
    /// assumed -- move the attribute table above `_etext` and these writes
    /// begin working with no change to this file.
    fn block_is_self(&self, block_start: usize) -> bool {
        block_start < self.text_end as usize
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
            SID_REQUEST_UPLOAD => self.request_upload(buffer, len),
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
                    // transfer in progress.
                    self.security.set(Security::Locked);
                    self.transfer.set(Transfer::None);
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
            DID_KERNEL_START_ADDRESS => {
                let address = self.flags_address as usize + FLAGS_START_ADDRESS_OFFSET;
                self.read_from_flash(buffer, did, address, 4, true);
            }
            DID_ATTRIBUTE_BASE..=DID_ATTRIBUTE_LAST => {
                // Unrestricted, like the other identification DIDs: reading the
                // table is what `tockloader` does before it knows whether it
                // even wants to program anything, and it changes nothing.
                let index = (did - DID_ATTRIBUTE_BASE) as usize;
                let address = self.attributes_address as usize + index * ATTRIBUTE_RECORD;
                self.read_from_flash(buffer, did, address, ATTRIBUTE_RECORD, false);
            }
            _ => self.send_negative(
                buffer,
                SID_READ_DATA_BY_IDENTIFIER,
                NRC_REQUEST_OUT_OF_RANGE,
            ),
        }
    }

    /// Answer a DID from flash.
    ///
    /// Everything reachable this way -- attribute records and the flags -- sits
    /// wholly inside one page, so a single read serves the whole response.
    fn read_from_flash(
        &self,
        buffer: &'static mut [u8],
        did: u16,
        address: usize,
        len: usize,
        reverse: bool,
    ) {
        let page_size = self.page_size();
        if address % page_size + len > page_size || buffer.len() < 3 + len {
            return self.send_negative(
                buffer,
                SID_READ_DATA_BY_IDENTIFIER,
                NRC_GENERAL_PROGRAMMING_FAILURE,
            );
        }

        self.pending_did.set(did);
        self.did_address.set(address as u32);
        self.did_len.set(len);
        self.did_reverse.set(reverse);
        self.job.set(Job::DidRead);
        self.buffer.replace(buffer);

        let failed = match self.page_buffer.take() {
            Some(page) => match self.flash.read_page(address / page_size, page) {
                Ok(()) => false,
                Err((_e, page)) => {
                    self.page_buffer.replace(page);
                    true
                }
            },
            None => true,
        };
        if failed {
            self.job.set(Job::None);
            if let Some(buffer) = self.buffer.take() {
                self.send_negative(
                    buffer,
                    SID_READ_DATA_BY_IDENTIFIER,
                    NRC_GENERAL_PROGRAMMING_FAILURE,
                );
            }
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
        let did = ((buffer[1] as u16) << 8) | buffer[2] as u16;

        // Copy the payload out before anything else: `buffer` is handed to the
        // transport to carry the 0x78, so nothing may still be borrowing it,
        // and a record is small enough that a copy costs nothing.
        let mut data = [0u8; ATTRIBUTE_RECORD];
        let data_len = core::cmp::min(len, buffer.len()) - 3;
        if data_len > ATTRIBUTE_RECORD {
            return self.send_negative(
                buffer,
                SID_WRITE_DATA_BY_IDENTIFIER,
                NRC_INCORRECT_LENGTH,
            );
        }
        data[..data_len].copy_from_slice(&buffer[3..3 + data_len]);
        let data = &data[..data_len];

        // Work out what to write and where, but do not touch flash yet: the
        // rewrite is long enough to need a 0x78 first.
        let (address, patch_len) = match did {
            DID_KERNEL_START_ADDRESS => {
                if data.len() != 4 {
                    return self.send_negative(
                        buffer,
                        SID_WRITE_DATA_BY_IDENTIFIER,
                        NRC_INCORRECT_LENGTH,
                    );
                }
                // On the wire big-endian, like every other UDS address; in the
                // flags little-endian, because that is what the bootloader's
                // own entry path and `tockloader` both read.
                let address = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                if address < self.write_floor || address >= self.flash_end {
                    return self.send_negative(
                        buffer,
                        SID_WRITE_DATA_BY_IDENTIFIER,
                        NRC_REQUEST_OUT_OF_RANGE,
                    );
                }
                let mut patch = [0u8; ATTRIBUTE_RECORD];
                patch[..4].copy_from_slice(&address.to_le_bytes());
                self.patch.set(patch);
                (
                    self.flags_address as usize + FLAGS_START_ADDRESS_OFFSET,
                    4,
                )
            }
            DID_ATTRIBUTE_BASE..=DID_ATTRIBUTE_LAST => {
                // A short request writes a short record; the rest is zeroed, so
                // a value can be cleared as well as set.
                let mut patch = [0u8; ATTRIBUTE_RECORD];
                patch[..data.len()].copy_from_slice(data);
                self.patch.set(patch);
                let index = (did - DID_ATTRIBUTE_BASE) as usize;
                (
                    self.attributes_address as usize + index * ATTRIBUTE_RECORD,
                    ATTRIBUTE_RECORD,
                )
            }
            // Fixed by the build, so there is nowhere to put a new value. The
            // writable equivalent is the `appaddr` attribute.
            DID_APPLICATION_START_ADDRESS
            | DID_BOOT_SOFTWARE_IDENTIFICATION
            | DID_ACTIVE_SESSION => {
                return self.send_negative(
                    buffer,
                    SID_WRITE_DATA_BY_IDENTIFIER,
                    NRC_CONDITIONS_NOT_CORRECT,
                )
            }
            _ => {
                return self.send_negative(
                    buffer,
                    SID_WRITE_DATA_BY_IDENTIFIER,
                    NRC_REQUEST_OUT_OF_RANGE,
                )
            }
        };

        match self.stage_block(address, patch_len) {
            Stage::Ready => {}
            // Refused rather than attempted: writing this block would erase the
            // code performing the write. `conditionsNotCorrect` is the honest
            // answer -- the identifier is real and the request well formed, the
            // board just cannot carry it out from where it is running.
            Stage::WouldEraseSelf => {
                return self.send_negative(
                    buffer,
                    SID_WRITE_DATA_BY_IDENTIFIER,
                    NRC_CONDITIONS_NOT_CORRECT,
                )
            }
            Stage::Unusable => {
                return self.send_negative(
                    buffer,
                    SID_WRITE_DATA_BY_IDENTIFIER,
                    NRC_GENERAL_PROGRAMMING_FAILURE,
                )
            }
        }
        self.pending_did.set(did);
        self.job.set(Job::StageRead {
            page: 0,
            end: BLOCK_PAGES,
        });
        self.send_pending(buffer, SID_WRITE_DATA_BY_IDENTIFIER);
    }

    /// Set up a staged rewrite of the erase block holding `address`.
    ///
    /// Returns whether the request is one this can actually carry out; the work
    /// itself starts once the 0x78 is on the wire.
    fn stage_block(&self, address: usize, patch_len: usize) -> Stage {
        let page_size = self.page_size();
        let first_page = (address / page_size) & !(BLOCK_PAGES - 1);
        let block_start = first_page * page_size;

        if self.block_is_self(block_start) {
            return Stage::WouldEraseSelf;
        }
        // The patch has to land inside the block being staged. It always does
        // for the two DIDs above, but a mistake here would write the patch into
        // whatever the offset happened to reach, so it is checked rather than
        // assumed.
        if address < block_start || address + patch_len > block_start + BLOCK_PAGES * page_size {
            return Stage::Unusable;
        }
        if self.stage.map_or(true, |s| s.len() < BLOCK_PAGES * page_size) {
            return Stage::Unusable;
        }

        self.stage_first_page.set(first_page);
        self.patch_offset.set(address - block_start);
        self.patch_len.set(patch_len);
        Stage::Ready
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
            && address >= self.write_floor
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
        if self.transfer.get() != Transfer::None {
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

        self.transfer.set(Transfer::Download);
        self.transfer_address.set(address);
        self.transfer_remaining.set(size);
        self.next_block_sequence.set(1);

        buffer[0] = SID_REQUEST_DOWNLOAD + POSITIVE_RESPONSE_OFFSET;
        buffer[1] = 0x20; // lengthFormatIdentifier: maxNumberOfBlockLength is 2 bytes
        buffer[2] = (MAX_BLOCK_LENGTH >> 8) as u8;
        buffer[3] = MAX_BLOCK_LENGTH as u8;
        self.send(buffer, 4);
    }

    /// `RequestUpload`: the tester wants to read flash back.
    ///
    /// The mirror of `request_download`, with two deliberate differences. The
    /// address need not be page-aligned, because a reader has no reason to
    /// care where pages fall and `read_range` does not: an unaligned start
    /// simply makes the first block short. And `maxNumberOfBlockLength` is the
    /// same 514, which for this direction bounds the *response*.
    fn request_upload(&self, buffer: &'static mut [u8], len: usize) {
        if len < 11 {
            return self.send_negative(buffer, SID_REQUEST_UPLOAD, NRC_INCORRECT_LENGTH);
        }
        // Reading flash back is how firmware is extracted, so it sits behind
        // the same unlock as writing it. CheckMemory already took that view.
        if !self.unlocked() {
            return self.send_negative(buffer, SID_REQUEST_UPLOAD, NRC_SECURITY_ACCESS_DENIED);
        }
        if self.transfer.get() != Transfer::None {
            return self.send_negative(
                buffer,
                SID_REQUEST_UPLOAD,
                NRC_UPLOAD_DOWNLOAD_NOT_ACCEPTED,
            );
        }
        if buffer[1] != 0x00 {
            return self.send_negative(buffer, SID_REQUEST_UPLOAD, NRC_REQUEST_OUT_OF_RANGE);
        }
        if buffer[2] != 0x44 {
            return self.send_negative(buffer, SID_REQUEST_UPLOAD, NRC_REQUEST_OUT_OF_RANGE);
        }
        let address = u32::from_be_bytes([buffer[3], buffer[4], buffer[5], buffer[6]]);
        let size = u32::from_be_bytes([buffer[7], buffer[8], buffer[9], buffer[10]]);

        if !self.range_ok(address, size) {
            return self.send_negative(buffer, SID_REQUEST_UPLOAD, NRC_REQUEST_OUT_OF_RANGE);
        }

        self.transfer.set(Transfer::Upload);
        self.transfer_address.set(address);
        self.transfer_remaining.set(size);
        self.next_block_sequence.set(1);
        self.prev_block_len.set(0);

        buffer[0] = SID_REQUEST_UPLOAD + POSITIVE_RESPONSE_OFFSET;
        buffer[1] = 0x20;
        buffer[2] = (MAX_BLOCK_LENGTH >> 8) as u8;
        buffer[3] = MAX_BLOCK_LENGTH as u8;
        self.send(buffer, 4);
    }

    /// Read one block for an upload and answer with it.
    ///
    /// `address` and `take` are passed rather than read from the transfer
    /// state, so that repeating the previous block re-reads exactly what was
    /// sent before.
    fn upload_block(&self, buffer: &'static mut [u8], address: u32, take: usize) {
        let page_size = self.page_size();
        self.buffer.replace(buffer);
        self.job.set(Job::Read);
        self.prev_block_address.set(address);
        self.prev_block_len.set(take);

        match self.page_buffer.take() {
            Some(page) => {
                if let Err((_e, page)) = self.flash.read_page(address as usize / page_size, page) {
                    self.page_buffer.replace(page);
                    self.job.set(Job::None);
                    if let Some(buffer) = self.buffer.take() {
                        self.send_negative(
                            buffer,
                            SID_TRANSFER_DATA,
                            NRC_GENERAL_PROGRAMMING_FAILURE,
                        );
                    }
                }
            }
            None => {
                self.job.set(Job::None);
                if let Some(buffer) = self.buffer.take() {
                    self.send_negative(
                        buffer,
                        SID_TRANSFER_DATA,
                        NRC_GENERAL_PROGRAMMING_FAILURE,
                    );
                }
            }
        }
    }

    fn transfer_data_upload(&self, buffer: &'static mut [u8], len: usize) {
        // The request carries no data in this direction; the response does.
        if len < 2 {
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_INCORRECT_LENGTH);
        }
        let sequence = buffer[1];
        let expected = self.next_block_sequence.get();

        if sequence != expected {
            if sequence == expected.wrapping_sub(1) && self.prev_block_len.get() > 0 {
                // Re-send the last block. The tester lost our response, which
                // is not an error on its part.
                let address = self.prev_block_address.get();
                let take = self.prev_block_len.get();
                return self.upload_block(buffer, address, take);
            }
            return self.send_negative(
                buffer,
                SID_TRANSFER_DATA,
                NRC_WRONG_BLOCK_SEQUENCE_COUNTER,
            );
        }

        let remaining = self.transfer_remaining.get() as usize;
        if remaining == 0 {
            // Everything asked for has been handed over; the tester should
            // have sent RequestTransferExit instead.
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_REQUEST_SEQUENCE_ERROR);
        }

        // One page at most, and never across a page boundary, so a block is
        // always satisfied by a single read.
        let address = self.transfer_address.get();
        let page_size = self.page_size();
        let offset = address as usize % page_size;
        let take = core::cmp::min(core::cmp::min(page_size - offset, remaining), TRANSFER_BLOCK);

        self.upload_block(buffer, address, take);
    }

    fn transfer_data(&self, buffer: &'static mut [u8], len: usize) {
        match self.transfer.get() {
            Transfer::Upload => return self.transfer_data_upload(buffer, len),
            Transfer::None => {
                return self.send_negative(
                    buffer,
                    SID_TRANSFER_DATA,
                    NRC_REQUEST_SEQUENCE_ERROR,
                )
            }
            Transfer::Download => {}
        }
        if len < 2 {
            return self.send_negative(buffer, SID_TRANSFER_DATA, NRC_INCORRECT_LENGTH);
        }
        if self.transfer.get() != Transfer::Download {
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
        if data_len as u32 > self.transfer_remaining.get() {
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

        let page_number = (self.transfer_address.get() as usize) / page_size;
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
            self.transfer_address
                .set(self.transfer_address.get() + data_len as u32);
            self.transfer_remaining
                .set(self.transfer_remaining.get() - data_len as u32);
            self.next_block_sequence.set(expected.wrapping_add(1));
        }
    }

    fn request_transfer_exit(&self, buffer: &'static mut [u8], _len: usize) {
        match self.transfer.get() {
            Transfer::None => {
                return self.send_negative(
                    buffer,
                    SID_REQUEST_TRANSFER_EXIT,
                    NRC_REQUEST_SEQUENCE_ERROR,
                )
            }
            Transfer::Download => {
                if self.transfer_remaining.get() != 0 {
                    // The tester stopped early; the image would be incomplete.
                    self.transfer.set(Transfer::None);
                    return self.send_negative(
                        buffer,
                        SID_REQUEST_TRANSFER_EXIT,
                        NRC_TRANSFER_DATA_SUSPENDED,
                    );
                }
            }
            // Stopping a read early is the tester's business: nothing on the
            // board is left half-finished by it, unlike an aborted download.
            Transfer::Upload => {}
        }
        self.transfer.set(Transfer::None);
        buffer[0] = SID_REQUEST_TRANSFER_EXIT + POSITIVE_RESPONSE_OFFSET;
        self.send(buffer, 1);
    }

    // -- Long-running jobs --------------------------------------------------

    /// Continue whatever was deferred behind a 0x78, now that the buffer is
    /// back from transmitting it.
    fn resume_job(&self, buffer: &'static mut [u8]) {
        match self.job.get() {
            Job::Erase { .. } | Job::Crc { .. } | Job::StageRead { .. } => {
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
                Job::StageRead { page, end } => {
                    if page >= end {
                        // The block is in RAM; patch it and start putting it
                        // back. Nothing has been erased yet, so a failure up to
                        // this point costs nothing.
                        self.apply_patch();
                        self.job.set(Job::StageWrite { page: 0, end });
                        continue;
                    }
                    // Advance first, so the completion knows the page it just
                    // read was `page - 1`, as the erase job does.
                    self.job.set(Job::StageRead {
                        page: page + 1,
                        end,
                    });
                    let first = self.stage_first_page.get();
                    match self.page_buffer.take() {
                        Some(pb) => {
                            if let Err((_e, pb)) = self.flash.read_page(first + page, pb) {
                                self.page_buffer.replace(pb);
                                self.job.set(Job::None);
                                self.stepping.set(false);
                                return self.fail_did_write();
                            }
                        }
                        None => {
                            self.job.set(Job::None);
                            self.stepping.set(false);
                            return self.fail_did_write();
                        }
                    }
                }
                Job::StageWrite { page, end } => {
                    if page >= end {
                        self.job.set(Job::None);
                        self.stepping.set(false);
                        return self.finish_did_write();
                    }
                    self.job.set(Job::StageWrite {
                        page: page + 1,
                        end,
                    });
                    let first = self.stage_first_page.get();
                    let page_size = self.page_size();
                    // Fill the page buffer from the staging copy. Ascending
                    // order matters: the first write finds the block dirty and
                    // erases it, and every later one finds it clean.
                    let filled = match self.page_buffer.take() {
                        Some(pb) => {
                            let ok = self.stage.map_or(false, |s| {
                                let from = page * page_size;
                                if from + page_size > s.len() {
                                    return false;
                                }
                                pb.as_mut().copy_from_slice(&s[from..from + page_size]);
                                true
                            });
                            if !ok {
                                self.page_buffer.replace(pb);
                                None
                            } else {
                                Some(pb)
                            }
                        }
                        None => None,
                    };
                    match filled {
                        Some(pb) => {
                            if let Err((_e, pb)) = self.flash.write_page(first + page, pb) {
                                self.page_buffer.replace(pb);
                                self.job.set(Job::None);
                                self.stepping.set(false);
                                return self.fail_did_write();
                            }
                        }
                        None => {
                            self.job.set(Job::None);
                            self.stepping.set(false);
                            return self.fail_did_write();
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

    /// Overwrite the staged block with the bytes the tester asked for.
    ///
    /// Bounds were settled in `stage_block`; this cannot silently write short
    /// because a mismatch there refuses the request before any flash is
    /// touched.
    fn apply_patch(&self) {
        let offset = self.patch_offset.get();
        let len = self.patch_len.get();
        let patch = self.patch.get();
        self.stage.map(|s| {
            if offset + len <= s.len() {
                s[offset..offset + len].copy_from_slice(&patch[..len]);
            }
        });
    }

    fn finish_did_write(&self) {
        if let Some(buffer) = self.buffer.take() {
            let did = self.pending_did.get();
            buffer[0] = SID_WRITE_DATA_BY_IDENTIFIER + POSITIVE_RESPONSE_OFFSET;
            buffer[1] = (did >> 8) as u8;
            buffer[2] = did as u8;
            self.send(buffer, 3);
        }
    }

    /// Report a failed staged rewrite.
    ///
    /// If this happens partway through `StageWrite` the block is left
    /// incomplete, and on the SAMV71 that block holds the vector table -- the
    /// board will need a debugger. There is nothing this can do about that
    /// beyond saying so; the window exists because the attribute table shares
    /// an erase block with the bootloader, which is a layout fact.
    fn fail_did_write(&self) {
        if let Some(buffer) = self.buffer.take() {
            self.send_negative(
                buffer,
                SID_WRITE_DATA_BY_IDENTIFIER,
                NRC_GENERAL_PROGRAMMING_FAILURE,
            );
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
        } else if let Job::StageRead { page, .. } = self.job.get() {
            // `step` advanced the counter before issuing the read, so the page
            // that just arrived is the one before it.
            let page_size = pagebuffer.as_mut().len();
            let done = page.saturating_sub(1);
            let ok = self.stage.map_or(false, |s| {
                let to = done * page_size;
                if to + page_size > s.len() {
                    return false;
                }
                s[to..to + page_size].copy_from_slice(pagebuffer.as_mut());
                true
            });
            self.page_buffer.replace(pagebuffer);
            if !ok {
                self.job.set(Job::None);
                return self.fail_did_write();
            }
            self.step();
        } else if self.job.get() == Job::DidRead {
            let page_size = pagebuffer.as_mut().len();
            let offset = self.did_address.get() as usize % page_size;
            let did = self.pending_did.get();
            let len = self.did_len.get();
            let reverse = self.did_reverse.get();

            let copied = self.buffer.map_or(false, |buffer| {
                if offset + len > page_size || buffer.len() < 3 + len {
                    return false;
                }
                buffer[0] = SID_READ_DATA_BY_IDENTIFIER + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = (did >> 8) as u8;
                buffer[2] = did as u8;
                buffer[3..3 + len].copy_from_slice(&pagebuffer.as_mut()[offset..offset + len]);
                if reverse {
                    buffer[3..3 + len].reverse();
                }
                true
            });
            self.page_buffer.replace(pagebuffer);
            self.job.set(Job::None);

            if let Some(buffer) = self.buffer.take() {
                if copied {
                    self.send(buffer, 3 + len);
                } else {
                    self.send_negative(
                        buffer,
                        SID_READ_DATA_BY_IDENTIFIER,
                        NRC_GENERAL_PROGRAMMING_FAILURE,
                    );
                }
            }
        } else if self.job.get() == Job::Read {
            let page_size = pagebuffer.as_mut().len();
            let address = self.prev_block_address.get();
            let take = self.prev_block_len.get();
            let offset = address as usize % page_size;

            let copied = self.buffer.map_or(false, |buffer| {
                if buffer.len() < 2 + take || offset + take > page_size {
                    return false;
                }
                buffer[0] = SID_TRANSFER_DATA + POSITIVE_RESPONSE_OFFSET;
                buffer[1] = self.next_block_sequence.get();
                buffer[2..2 + take].copy_from_slice(&pagebuffer.as_mut()[offset..offset + take]);
                true
            });
            self.page_buffer.replace(pagebuffer);
            self.job.set(Job::None);

            if let Some(buffer) = self.buffer.take() {
                if !copied {
                    return self.send_negative(
                        buffer,
                        SID_TRANSFER_DATA,
                        NRC_GENERAL_PROGRAMMING_FAILURE,
                    );
                }
                // Only advance once the block is built. A repeat of the same
                // sequence number before this point therefore re-reads the
                // same bytes rather than skipping ahead.
                if address == self.transfer_address.get() {
                    self.transfer_address.set(address + take as u32);
                    self.transfer_remaining
                        .set(self.transfer_remaining.get() - take as u32);
                    self.next_block_sequence
                        .set(self.next_block_sequence.get().wrapping_add(1));
                }
                self.send(buffer, 2 + take);
            }
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

        if let Job::StageWrite { .. } = self.job.get() {
            if result.is_err() {
                self.job.set(Job::None);
                return self.fail_did_write();
            }
            // `step` already advanced the page counter; drive it onwards.
            return self.step();
        }

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
