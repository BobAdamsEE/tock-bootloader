//! Implements the Tock bootloader.

use core::cell::Cell;
use core::cmp;
use kernel::ErrorCode;

use kernel::hil;
use kernel::utilities::cells::TakeCell;
use kernel::utilities::cells::VolatileCell;
use kernel::utilities::StaticRef;

use crate::bootloader_crc;
use crate::transport::{BootloaderTransport, BootloaderTransportClient};
use crate::interfaces;

// Main buffer that commands are received into and sent from.
// Need a buffer big enough for 512 byte pages.
pub static mut BUF: [u8; 600] = [0; 600];

// How long to wait, in bit periods, after receiving a byte for the next
// byte before timing out and calling `receive_complete`.
// At 16× oversampling and 115200 baud one byte takes 160 bit periods, so
// the timeout must exceed that to avoid splitting multi-byte commands.

// Get the addresses in flash of key components from the linker file.
extern "C" {
    static _flags_address: u8;
    static _attributes_address: u8;
}

// Bootloader constants
const ESCAPE_CHAR: u8 = 0xFC;

/// One attribute record: 8-byte key, 1-byte length, 55 bytes of value.
const ATTRIBUTE_RECORD: usize = 64;

/// Pages in one flash erase block.
///
/// `write_page` erases a whole block before writing a page that is not already
/// blank, so a single-page read-modify-write of the attribute table erases the
/// block and puts back exactly one page of it. Writes here therefore stage the
/// entire block, patch it, and write it back in ascending page order: the first
/// write triggers the one erase and the rest find the block already clean.
///
/// Sixteen matches the SAMV71 EFC. A part that erases in smaller units simply
/// stages more than it needs to, which is harmless.
const BLOCK_PAGES: usize = 16;

const RES_PONG: u8 = 0x11;
const RES_BADADDR: u8 = 0x12;
const RES_INTERNAL_ERROR: u8 = 0x13;
const RES_BADARGS: u8 = 0x14;
const RES_OK: u8 = 0x15;
const RES_UNKNOWN: u8 = 0x16;
const RES_READ_RANGE: u8 = 0x20;
const RES_GET_ATTR: u8 = 0x22;
const RES_CRCIF: u8 = 0x23;
const RES_INFO: u8 = 0x25;

#[derive(Copy, Clone, PartialEq)]
enum State {
    Idle,
    Info,
    ErasePage,
    GetAttribute {
        index: u8,
    },
    /// Copying the erase block holding the attribute table into `stage`,
    /// `page` of `end`, before patching it. See `BLOCK_PAGES`.
    StageRead {
        page: usize,
        end: usize,
    },
    /// Writing the patched block back, `page` of `end`.
    StageWrite {
        page: usize,
        end: usize,
    },
    WriteFlashPage,
    ReadRange {
        address: u32,
        length: u16,
        remaining_length: u16,
    },
    Crc {
        address: u32,
        remaining_length: u32,
        crc: u32,
    },
}

/// This struct handles whether we should enter the bootloader or go straight to
/// the kernel.
pub struct BootloaderEnterer<'a> {
    entry_decider: &'a dyn interfaces::BootloaderEntry,
    jumper: &'a dyn interfaces::Jumper,
    active_notifier: &'a mut dyn interfaces::ActiveNotifier,
    /// This is the address of flash where the flags region of the bootloader
    /// start. We need this to determine what address to jump to.
    bootloader_flags_address: u32,
    /// Lowest address a kernel may start at: the end of the bootloader's own
    /// region. Supplied by the board rather than hardcoded so it cannot drift
    /// out of step with the region actually reserved — a stale constant would
    /// either accept a kernel start inside the bootloader or reject a real one.
    kernel_region_start: u32,
}

impl<'a> BootloaderEnterer<'a> {
    pub fn new(
        entry_decider: &'a dyn interfaces::BootloaderEntry,
        jumper: &'a dyn interfaces::Jumper,
        active_notifier: &'a mut dyn interfaces::ActiveNotifier,
        kernel_region_start: u32,
    ) -> BootloaderEnterer<'a> {
        Self::new_with_flags(
            entry_decider,
            jumper,
            active_notifier,
            kernel_region_start,
            unsafe { (&_flags_address as *const u8) as u32 },
        )
    }

    /// Same, for a board that has moved its flags.
    ///
    /// This is the one that decides where to jump, so a board that relocates
    /// its flags and forgets to say so here does not get a wrong kernel -- it
    /// gets no kernel at all. The start address reads back as zero, falls below
    /// `kernel_region_start`, and the board sits in the bootloader looking
    /// perfectly healthy. Measured 2026-07-28, and the reason this constructor
    /// exists rather than a second `extern` symbol.
    pub fn new_with_flags(
        entry_decider: &'a dyn interfaces::BootloaderEntry,
        jumper: &'a dyn interfaces::Jumper,
        active_notifier: &'a mut dyn interfaces::ActiveNotifier,
        kernel_region_start: u32,
        flags_address: u32,
    ) -> BootloaderEnterer<'a> {
        BootloaderEnterer {
            entry_decider,
            jumper,
            active_notifier,
            bootloader_flags_address: flags_address,
            kernel_region_start,
        }
    }

    pub fn check(&mut self) {
        if !self.entry_decider.stay_in_bootloader() {
            // Jump to the kernel and start the real code (or stay if no kernel).
            self.jump();
        } else {
            // Staying in the bootloader, allow a custom active notification to
            // start.
            self.active_notifier.active();
        }
    }

    fn jump(&mut self) {
        // Address of the start address in the flags region is 32 bytes from the start.
        let start_address_memory_location = self.bootloader_flags_address + 32;

        let start_address_ptr: StaticRef<VolatileCell<u32>> =
            unsafe { StaticRef::new(start_address_memory_location as *const VolatileCell<u32>) };

        let start_address = start_address_ptr.get();

        // Validate start_address before dereferencing it. The kernel lives
        // above the bootloader's own region and below the end of flash.
        // Values outside that mean the flags region has never been written
        // (zeroed) or is fully erased (0xFFFFFFFF), so no kernel is installed.
        //
        // The lower bound comes from the board rather than a constant so that
        // it cannot drift out of step with the region actually reserved -- a
        // kernel start inside the bootloader would be nonsense, and one just
        // above a stale constant would jump into empty flash.
        if start_address < self.kernel_region_start || start_address >= 0x0020_0000 {
            self.active_notifier.active();
            return;
        }

        // Read the kernel's initial SP from its vector table to detect a kernel
        // region that exists in the address space but has not been programmed.
        // Erased flash reads as 0xFFFFFFFF which is not a valid stack pointer.
        let kernel_sp_ptr: StaticRef<VolatileCell<u32>> =
            unsafe { StaticRef::new(start_address as *const VolatileCell<u32>) };
        if kernel_sp_ptr.get() == 0xFFFF_FFFF {
            self.active_notifier.active();
            return;
        }

        self.jumper.jump(start_address);
    }
}

/// The main bootloader code.
pub struct Bootloader<'a, T: BootloaderTransport<'a> + 'a, F: hil::flash::Flash + 'static> {
    transport: &'a T,
    flash: &'a F,
    reset_function: &'a (dyn Fn() + 'a),
    page_buffer: TakeCell<'static, F::Page>,
    buffer: TakeCell<'static, [u8]>,
    /// One erase block of RAM, used only while rewriting the attribute table or
    /// the flags. Absent means those writes are refused rather than attempted.
    stage: TakeCell<'static, [u8]>,
    state: Cell<State>,
    /// The bytes a staged rewrite will patch in, where in the staged block they
    /// go, and which flash page the block starts at. Held here because the
    /// message buffer is needed for the response.
    patch: Cell<[u8; ATTRIBUTE_RECORD]>,
    patch_len: Cell<usize>,
    patch_offset: Cell<usize>,
    stage_first_page: Cell<usize>,
    /// Guards against recursing once per page: the flash driver may complete
    /// inside the call, so the completion flags that the loop should go round
    /// again rather than starting a nested one. Same reason as `uds.rs`.
    stepping: Cell<bool>,
    step_again: Cell<bool>,
    flags_address: usize,
    attributes_address: usize,
    /// First address the bootloader will let a client write or erase.
    ///
    /// Everything below it is the bootloader's own flash region: the vector
    /// table, the flags at `_flags_address`, the attribute table at
    /// `_attributes_address`, and the code itself. The board supplies the
    /// whole region rather than just `_stext.._etext`, and that matters more
    /// than it looks:
    ///
    /// * On the default layout the flags and attributes sit *below* `_stext`,
    ///   so a bound starting there leaves them writable by raw address, and a
    ///   raw write into the attribute table block-erases the bootloader out
    ///   from under itself (see the SAMV71 EFC's `write_page`, which erases a
    ///   16-page block when the target page is dirty). Attribute writes go
    ///   through `SetAttr`, which stages the block; this bound is what stops
    ///   anyone reaching the same flash by address instead.
    /// * Erase granularity is coarser than a page. Erasing a page just above
    ///   the bootloader's last byte can still take out the block containing
    ///   its last byte, so the bound has to sit on a region boundary, not on
    ///   `_etext`.
    protected_end: u32,
}

impl<'a, T: BootloaderTransport<'a> + 'a, F: hil::flash::Flash + 'a> Bootloader<'a, T, F> {
    pub fn new(
        transport: &'a T,
        flash: &'a F,
        reset_function: &'a (dyn Fn() + 'a),
        page_buffer: &'static mut F::Page,
        buffer: &'static mut [u8],
        protected_end: u32,
    ) -> Bootloader<'a, T, F> {
        Self::new_with_table(
            transport,
            flash,
            reset_function,
            page_buffer,
            buffer,
            protected_end,
            unsafe { (&_flags_address as *const u8) as usize },
            unsafe { (&_attributes_address as *const u8) as usize },
            None,
        )
    }

    /// Same, for a board that has moved its attribute table.
    ///
    /// The default position sits inside the erase block holding the vector
    /// table and the start of the bootloader's code, which makes the table
    /// unwritable at runtime on parts that erase in blocks. A board that moves
    /// it has to tell both servers where it went, and this is how the UART one
    /// is told.
    pub fn new_with_table(
        transport: &'a T,
        flash: &'a F,
        reset_function: &'a (dyn Fn() + 'a),
        page_buffer: &'static mut F::Page,
        buffer: &'static mut [u8],
        protected_end: u32,
        flags_address: usize,
        attributes_address: usize,
        stage: Option<&'static mut [u8]>,
    ) -> Bootloader<'a, T, F> {
        Bootloader {
            transport: transport,
            flash: flash,
            reset_function: reset_function,
            page_buffer: TakeCell::new(page_buffer),
            buffer: TakeCell::new(buffer),
            stage: match stage {
                Some(s) => TakeCell::new(s),
                None => TakeCell::empty(),
            },
            state: Cell::new(State::Idle),
            patch: Cell::new([0; ATTRIBUTE_RECORD]),
            patch_len: Cell::new(0),
            patch_offset: Cell::new(0),
            stage_first_page: Cell::new(0),
            stepping: Cell::new(false),
            step_again: Cell::new(false),
            flags_address,
            attributes_address,
            protected_end,
        }
    }

    /// Begin rewriting the erase block that holds `address`.
    ///
    /// The patch itself is already in `self.patch`; this works out which block
    /// to stage and starts reading it. A refusal here answers the client rather
    /// than touching flash, which matters because the alternative -- writing
    /// the page directly -- erases the surrounding block and restores one page
    /// of it.
    fn begin_staged_write(&self, address: usize, patch_len: usize) {
        let page_size = self.page_buffer.map_or(512, |page| page.as_mut().len());
        let first_page = (address / page_size) & !(BLOCK_PAGES - 1);
        let block_start = first_page * page_size;
        let block_len = BLOCK_PAGES * page_size;

        // Refuse rather than half-do it: without staging there is no way to put
        // back the rest of the block, and a board that erases its own attribute
        // table and 15 neighbouring pages is worse off than one that said no.
        let ok = self.stage.map_or(false, |s| s.len() >= block_len)
            && address >= block_start
            && address + patch_len <= block_start + block_len;
        if !ok {
            self.state.set(State::Idle);
            return self.send_response(RES_INTERNAL_ERROR);
        }

        self.stage_first_page.set(first_page);
        self.patch_offset.set(address - block_start);
        self.patch_len.set(patch_len);
        self.state.set(State::StageRead {
            page: 0,
            end: BLOCK_PAGES,
        });
        self.step();
    }

    /// Drive a staged rewrite forward.
    ///
    /// Iterative rather than recursive: the SAMV71 flash driver completes
    /// inside the call, so chaining "issue the next page from the completion"
    /// would nest a stack frame per page. `stepping` says a loop is already
    /// running and the completion only has to ask for another turn.
    fn step(&self) {
        if self.stepping.get() {
            self.step_again.set(true);
            return;
        }
        self.stepping.set(true);

        loop {
            self.step_again.set(false);

            match self.state.get() {
                State::StageRead { page, end } => {
                    if page >= end {
                        // The block is in RAM. Patch it and start putting it
                        // back; nothing has been erased yet, so a failure up to
                        // here has cost nothing.
                        self.apply_patch();
                        self.state.set(State::StageWrite { page: 0, end });
                        continue;
                    }
                    // Advance first, so the completion knows the page that just
                    // arrived was `page`.
                    self.state.set(State::StageRead { page: page + 1, end });
                    let first = self.stage_first_page.get();
                    match self.page_buffer.take() {
                        Some(pb) => {
                            if let Err((_e, pb)) = self.flash.read_page(first + page, pb) {
                                self.page_buffer.replace(pb);
                                self.stepping.set(false);
                                self.state.set(State::Idle);
                                return self.send_response(RES_INTERNAL_ERROR);
                            }
                        }
                        None => {
                            self.stepping.set(false);
                            self.state.set(State::Idle);
                            return self.send_response(RES_INTERNAL_ERROR);
                        }
                    }
                }
                State::StageWrite { page, end } => {
                    if page >= end {
                        self.stepping.set(false);
                        self.state.set(State::Idle);
                        return self.send_response(RES_OK);
                    }
                    self.state.set(State::StageWrite { page: page + 1, end });
                    let first = self.stage_first_page.get();
                    let page_size = self.page_buffer.map_or(512, |p| p.as_mut().len());
                    // Ascending order matters: the first write finds the block
                    // dirty and erases it, and every later one finds it clean.
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
                            if ok {
                                Some(pb)
                            } else {
                                self.page_buffer.replace(pb);
                                None
                            }
                        }
                        None => None,
                    };
                    match filled {
                        Some(pb) => {
                            if let Err((_e, pb)) = self.flash.write_page(first + page, pb) {
                                self.page_buffer.replace(pb);
                                self.stepping.set(false);
                                self.state.set(State::Idle);
                                return self.send_response(RES_INTERNAL_ERROR);
                            }
                        }
                        None => {
                            self.stepping.set(false);
                            self.state.set(State::Idle);
                            return self.send_response(RES_INTERNAL_ERROR);
                        }
                    }
                }
                _ => break,
            }

            if !self.step_again.get() {
                // The driver has not completed yet; its callback comes back
                // into here.
                break;
            }
        }

        self.stepping.set(false);
    }

    /// Overwrite the staged block with the bytes the client asked for. Bounds
    /// were settled in `begin_staged_write`.
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

    pub fn start(&self) {
        // Bring the link up and start listening. What "a message" means on the
        // wire is the transport's business; see `crate::transport`.
        let _ = self.transport.configure();

        self.buffer.take().map(|buffer| {
            let _ = self.transport.receive_message(buffer);
        });
    }

    // Helper function for sending single byte responses.
    fn send_response(&self, response: u8) {
        self.buffer.take().map(|buffer| {
            buffer[0] = ESCAPE_CHAR;
            buffer[1] = response;
            let _ = self.transport.transmit_message(buffer, 2);
        });
    }
}

impl<'a, T: BootloaderTransport<'a> + 'a, F: hil::flash::Flash + 'a> BootloaderTransportClient
    for Bootloader<'a, T, F>
{
    fn message_transmitted(&self, buffer: &'static mut [u8], error: Result<(), ErrorCode>) {
        if error.is_err() {
            // self.led.clear();
        } else {
            match self.state.get() {
                // Check if there is more to be read, and if so, read it and
                // send it.
                State::ReadRange {
                    address,
                    length: _,
                    remaining_length,
                } => {
                    // We have sent some of the read range to the client.
                    // We are either done, or need to setup the next read.
                    if remaining_length == 0 {
                        self.state.set(State::Idle);
                        let _ =
                            self.transport.receive_message(buffer);
                    } else {
                        self.buffer.replace(buffer);
                        self.page_buffer.take().map(move |page| {
                            let page_size = page.as_mut().len();
                            let _ = self.flash.read_page(address as usize / page_size, page);
                        });
                    }
                }

                _ => {
                    let _ = self.transport.receive_message(buffer);
                }
            }
        }
    }

    fn message_received(
        &self,
        buffer: &'static mut [u8],
        rx_len: usize,
        rval: Result<(), ErrorCode>,
    ) {
        if rval.is_err() || rx_len == 0 {
            let _ = self.transport.receive_message(buffer);
            return;
        }

        let mut decoder = tock_bootloader_protocol::CommandDecoder::new();
        let mut need_reset = false;
        let mut buf = Some(buffer);

        for i in 0..rx_len {
            if need_reset {
                decoder.reset();
                need_reset = false;
            }

            let byte = buf.as_ref().unwrap()[i];
            match decoder.receive(byte) {
                Ok(None) => {}
                Ok(Some(tock_bootloader_protocol::Command::Ping)) => {
                    let buffer = buf.take().unwrap();
                    self.buffer.replace(buffer);
                    self.send_response(RES_PONG);
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::Reset)) => {
                    need_reset = true;
                    if i == rx_len - 1 {
                        break;
                    }
                }
                Ok(Some(tock_bootloader_protocol::Command::Info)) => {
                    let buffer = buf.take().unwrap();
                    self.state.set(State::Info);
                    self.buffer.replace(buffer);
                    self.page_buffer.take().map(move |page| {
                        let page_index = self.flags_address / page.as_mut().len();
                        let _ = self.flash.read_page(page_index, page);
                    });
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::ReadRange { address, length })) => {
                    let buffer = buf.take().unwrap();
                    self.state.set(State::ReadRange {
                        address,
                        length,
                        remaining_length: length,
                    });
                    self.buffer.replace(buffer);
                    self.page_buffer.take().map(move |page| {
                        let page_size = page.as_mut().len();
                        let _ = self.flash.read_page(address as usize / page_size, page);
                    });
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::WritePage { address, data })) => {
                    let buffer = buf.take().unwrap();
                    self.page_buffer.take().map(move |page| {
                        let page_size = page.as_mut().len();
                        if page_size != data.len() {
                            buffer[0] = ESCAPE_CHAR;
                            buffer[1] = RES_BADARGS;
                            self.page_buffer.replace(page);
                            self.state.set(State::Idle);
                            let _ = self.transport.transmit_message(buffer, 2);
                        } else if address < self.protected_end {
                            buffer[0] = ESCAPE_CHAR;
                            buffer[1] = RES_BADADDR;
                            self.page_buffer.replace(page);
                            self.state.set(State::Idle);
                            let _ = self.transport.transmit_message(buffer, 2);
                        } else {
                            for i in 0..page_size {
                                page.as_mut()[i] = data[i];
                            }
                            self.state.set(State::WriteFlashPage);
                            self.buffer.replace(buffer);
                            let _ = self.flash.write_page(address as usize / page_size, page);
                        }
                    });
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::ErasePage { address })) => {
                    let buffer = buf.take().unwrap();
                    // Erase had no address check at all, while WritePage did.
                    // Erasing the bootloader is at least as destructive as
                    // writing it -- more so on a flash whose erase granularity
                    // is a multiple of the page size, because a single erase
                    // takes out neighbours the caller never named.
                    if address < self.protected_end {
                        buffer[0] = ESCAPE_CHAR;
                        buffer[1] = RES_BADADDR;
                        self.state.set(State::Idle);
                        let _ = self.transport.transmit_message(buffer, 2);
                    } else {
                        self.state.set(State::ErasePage);
                        self.buffer.replace(buffer);
                        let page_size = self.page_buffer.map_or(512, |page| page.as_mut().len());
                        let _ = self.flash.erase_page(address as usize / page_size);
                    }
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::CrcIntFlash { address, length })) => {
                    let buffer = buf.take().unwrap();
                    self.state.set(State::Crc {
                        address,
                        remaining_length: length,
                        crc: 0xFFFFFFFF,
                    });
                    self.buffer.replace(buffer);
                    self.page_buffer.take().map(move |page| {
                        let page_size = page.as_mut().len();
                        let _ = self.flash.read_page(address as usize / page_size, page);
                    });
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::GetAttr { index })) => {
                    let buffer = buf.take().unwrap();
                    self.state.set(State::GetAttribute { index: index });
                    self.buffer.replace(buffer);
                    self.page_buffer.take().map(move |page| {
                        let page_len = page.as_mut().len();
                        let read_address = self.attributes_address + (index as usize * 64);
                        let page_index = read_address / page_len;
                        let _ = self.flash.read_page(page_index, page);
                    });
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::SetAttr { index, key, value })) => {
                    let buffer = buf.take().unwrap();
                    // Build the record now, while the command's borrowed slices
                    // are still in scope, and keep it out of the message buffer
                    // so that buffer is free for the response.
                    let mut record = [0u8; ATTRIBUTE_RECORD];
                    record[..8].copy_from_slice(&key[..8]);
                    record[8] = value.len() as u8;
                    let n = cmp::min(value.len(), ATTRIBUTE_RECORD - 9);
                    record[9..9 + n].copy_from_slice(&value[..n]);
                    self.patch.set(record);

                    let address = self.attributes_address + (index as usize * ATTRIBUTE_RECORD);
                    self.buffer.replace(buffer);
                    self.begin_staged_write(address, ATTRIBUTE_RECORD);
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::SetStartAddress { address })) => {
                    let buffer = buf.take().unwrap();
                    let mut record = [0u8; ATTRIBUTE_RECORD];
                    record[..4].copy_from_slice(&address.to_le_bytes());
                    self.patch.set(record);

                    let at = self.flags_address + 32;
                    self.buffer.replace(buffer);
                    self.begin_staged_write(at, 4);
                    break;
                }
                Ok(Some(tock_bootloader_protocol::Command::Exit)) => {
                    (self.reset_function)();
                    break;
                }
                Ok(Some(_)) => {
                    let buffer = buf.take().unwrap();
                    self.buffer.replace(buffer);
                    self.send_response(RES_UNKNOWN);
                    break;
                }
                Err(tock_bootloader_protocol::Error::BadArguments) => {
                    let buffer = buf.take().unwrap();
                    self.buffer.replace(buffer);
                    self.send_response(RES_BADARGS);
                    break;
                }
                Err(_) => {
                    let buffer = buf.take().unwrap();
                    self.buffer.replace(buffer);
                    self.send_response(RES_INTERNAL_ERROR);
                    break;
                }
            };
        }

        if let Some(buffer) = buf {
            let _ = self.transport.receive_message(buffer);
        }
    }
}

impl<'a, T: BootloaderTransport<'a> + 'a, F: hil::flash::Flash + 'a> hil::flash::Client<F>
    for Bootloader<'a, T, F>
{
    fn read_complete(&self, pagebuffer: &'static mut F::Page, _result: Result<(), hil::flash::Error>) {
        match self.state.get() {
            // We just read the bootloader info page (page 2). Extract the
            // version and generate a response JSON blob.
            State::Info => {
                self.state.set(State::Idle);
                self.buffer.take().map(move |buffer| {
                    buffer[0] = ESCAPE_CHAR;
                    buffer[1] = RES_INFO;
                    let mut index = 3;

                    // Insert the first part of the JSON blob into the buffer.
                    let str01 = "{\"version\":\"";
                    for i in 0..str01.len() {
                        buffer[index] = str01.as_bytes()[i];
                        index += 1;
                    }

                    // Calculate where in the page the flags start.
                    let page_offset = self.flags_address % pagebuffer.as_mut().len();

                    // Version string is at most 8 bytes long, and starts
                    // at index 14 in the bootloader page.
                    for i in 0..8 {
                        let b = pagebuffer.as_mut()[i + 14 + page_offset];
                        if b == 0 {
                            break;
                        }
                        buffer[index] = b;
                        index += 1;
                    }

                    // Do start address
                    let str02 = "\", \"start_address\":\"0x";
                    for i in 0..str02.len() {
                        buffer[index] = str02.as_bytes()[i];
                        index += 1;
                    }
                    for i in 0..8 {
                        let b = (pagebuffer.as_mut()[32 + page_offset + 3 - (i / 2)]
                            >> (((i + 1) % 2) * 4))
                            & 0x0F;
                        buffer[index] = char::from_digit(b.into(), 16).unwrap_or('?') as u8;
                        index += 1;
                    }
                    let str02 = "\", ";
                    for i in 0..str02.len() {
                        buffer[index] = str02.as_bytes()[i];
                        index += 1;
                    }

                    // Insert the last half of the JSON blob into the buffer.
                    let str02 = "\"name\":\"Tock Bootloader\"}";
                    for i in 0..str02.len() {
                        buffer[index] = str02.as_bytes()[i];
                        index += 1;
                    }

                    // Need to insert the string length as the first byte
                    // after the header.
                    buffer[2] = index as u8 - 3;
                    index += 1;

                    // Rest should be 0.
                    for i in index..195 {
                        buffer[i] = 0;
                    }

                    self.page_buffer.replace(pagebuffer);
                    let _ = self.transport.transmit_message(buffer, 195);
                });
            }

            // We just read the correct page for this attribute. Copy it to
            // the out buffer and send it back to the client.
            State::GetAttribute { index } => {
                self.state.set(State::Idle);
                self.buffer.take().map(move |buffer| {
                    buffer[0] = ESCAPE_CHAR;
                    buffer[1] = RES_GET_ATTR;
                    let mut j = 2;

                    // Need to calculate where in the page to look for this
                    // attribute with attributes starting at address 0x600 and
                    // where each has length of 64 bytes.
                    let page_len = pagebuffer.as_mut().len();
                    let read_address = self.attributes_address + (index as usize * 64);
                    let page_offset = read_address % page_len;

                    for i in 0..64 {
                        let b = pagebuffer.as_mut()[page_offset + i];
                        if b == ESCAPE_CHAR {
                            // Need to escape the escape character.
                            buffer[j] = ESCAPE_CHAR;
                            j += 1;
                        }
                        buffer[j] = b;
                        j += 1;
                    }

                    self.page_buffer.replace(pagebuffer);
                    let _ = self.transport.transmit_message(buffer, j);
                });
            }

            // One page of the erase block has arrived; copy it into the staging
            // buffer. `step` advanced the counter before issuing the read, so
            // the page that just arrived is the one before it.
            State::StageRead { page, .. } => {
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
                    self.state.set(State::Idle);
                    return self.send_response(RES_INTERNAL_ERROR);
                }
                self.step();
            }

            // Pass what we have read so far to the client.
            State::ReadRange {
                address,
                length,
                remaining_length,
            } => {
                // Take what we need to read out of this page and send it
                // on uart. If this is the first message be sure to send the
                // header.
                self.buffer.take().map(move |buffer| {
                    let mut index = 0;
                    if length == remaining_length {
                        buffer[0] = ESCAPE_CHAR;
                        buffer[1] = RES_READ_RANGE;
                        index = 2;
                    }

                    let page_size = pagebuffer.as_mut().len();
                    // This will get us our offset into the page.
                    let page_index = address as usize % page_size;
                    // Length is either the rest of the page or how much we have left.
                    let len = cmp::min(page_size - page_index, remaining_length as usize);
                    // Make sure we don't overflow the buffer.
                    let copy_len = cmp::min(len, buffer.len() - index);

                    // Copy what we read from the page buffer to the user buffer.
                    // Keep track of how much was actually copied.
                    let mut actually_copied = 0;
                    for i in 0..copy_len {
                        // Make sure we don't overflow the buffer. We need to
                        // have at least two open bytes in the buffer
                        if index >= (buffer.len() - 1) {
                            break;
                        }

                        // Normally do the copy and check if this needs to be
                        // escaped.
                        actually_copied += 1;
                        let b = pagebuffer.as_mut()[page_index + i];
                        if b == ESCAPE_CHAR {
                            // Need to escape the escape character.
                            buffer[index] = ESCAPE_CHAR;
                            index += 1;
                        }
                        buffer[index] = b;
                        index += 1;
                    }

                    // Update our state.
                    let new_address = address as usize + actually_copied;
                    let new_remaining_length = remaining_length as usize - actually_copied;
                    self.state.set(State::ReadRange {
                        address: new_address as u32,
                        length,
                        remaining_length: new_remaining_length as u16,
                    });

                    // And send the buffer to the client.
                    self.page_buffer.replace(pagebuffer);
                    let _ = self.transport.transmit_message(buffer, index);
                });
            }

            // We have some data to calculate the CRC on.
            State::Crc {
                address,
                remaining_length,
                crc,
            } => {
                let page_size = pagebuffer.as_mut().len();
                // This will get us our offset into the page.
                let page_index = address as usize % page_size;
                // Length is either the rest of the page or how much we have left.
                let len = cmp::min(page_size - page_index, remaining_length as usize);

                // Iterate all bytes in the page that are relevant to the CRC
                // and include them in the CRC calculation.
                let mut new_crc = crc;
                for i in 0..len {
                    let v1 = (new_crc ^ pagebuffer.as_mut()[page_index + i] as u32) & 0xFF;
                    let v2 = bootloader_crc::CRC32_TABLE[v1 as usize];
                    new_crc = v2 ^ (new_crc >> 8);
                }

                // Update our state.
                let new_address = address + len as u32;
                let new_remaining_length = remaining_length - len as u32;

                // Check if we are done
                if new_remaining_length == 0 {
                    // Last XOR before sending to client.
                    new_crc = new_crc ^ 0xFFFFFFFF;

                    self.state.set(State::Idle);
                    self.buffer.take().map(move |buffer| {
                        buffer[0] = ESCAPE_CHAR;
                        buffer[1] = RES_CRCIF;
                        buffer[2] = ((new_crc >> 0) & 0xFF) as u8;
                        buffer[3] = ((new_crc >> 8) & 0xFF) as u8;
                        buffer[4] = ((new_crc >> 16) & 0xFF) as u8;
                        buffer[5] = ((new_crc >> 24) & 0xFF) as u8;
                        // And send the buffer to the client.
                        self.page_buffer.replace(pagebuffer);
                        let _ = self.transport.transmit_message(buffer, 6);
                    });
                } else {
                    // More CRC to do!
                    self.state.set(State::Crc {
                        address: new_address,
                        remaining_length: new_remaining_length,
                        crc: new_crc,
                    });
                    let _ = self
                        .flash
                        .read_page(new_address as usize / page_size, pagebuffer);
                }
            }

            _ => {}
        }
    }

    fn write_complete(&self, pagebuffer: &'static mut F::Page, _result: Result<(), hil::flash::Error>) {
        self.page_buffer.replace(pagebuffer);

        match self.state.get() {
            // Writing flash page done, send OK.
            State::WriteFlashPage => {
                self.state.set(State::Idle);
                self.buffer.take().map(move |buffer| {
                    buffer[0] = ESCAPE_CHAR;
                    buffer[1] = RES_OK;
                    let _ = self.transport.transmit_message(buffer, 2);
                });
            }

            // One page of the staged block is down; `step` already advanced the
            // counter, so just drive it onwards. It sends the response once the
            // whole block is back.
            State::StageWrite { .. } => {
                self.step();
            }

            _ => {
                self.buffer.take().map(|buffer| {
                    let _ = self.transport.receive_message(buffer);
                });
            }
        }
    }

    fn erase_complete(&self, _result: Result<(), hil::flash::Error>) {
        match self.state.get() {
            // Page erased, return OK
            State::ErasePage => {
                self.state.set(State::Idle);
                self.buffer.take().map(move |buffer| {
                    buffer[0] = ESCAPE_CHAR;
                    buffer[1] = RES_OK;
                    let _ = self.transport.transmit_message(buffer, 2);
                });
            }

            _ => {
                self.buffer.take().map(|buffer| {
                    let _ = self.transport.receive_message(buffer);
                });
            }
        }
    }
}
