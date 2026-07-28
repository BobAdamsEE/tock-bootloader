//! Check the kernel image against a SHA-256 digest before jumping to it.
//!
//! # What this is for, and what it is not
//!
//! This catches a **corrupt or truncated kernel**: a reflash interrupted by
//! power loss, a transfer that died halfway, a bad erase. On a development
//! board that is the failure that actually happens, and without this check the
//! result is a board that resets into nothing and needs a debugger.
//!
//! It is **not** a security control, and must not be described as one. The
//! digest lives in the same writable flash as the image it describes, so
//! anyone who can rewrite the kernel can rewrite the digest to match. Against a
//! deliberate attacker this is worth exactly as much as the CRC32 the
//! bootloader already had -- which is to say nothing.
//!
//! SHA-256 is used anyway, rather than reusing that CRC32, for one reason: the
//! descriptor becomes **signable** later without a format change. A signature
//! over a SHA-256 digest is the ordinary construction; a signature over a
//! CRC32 is meaningless, because a CRC is trivially forgeable to any target
//! value. When the production variant adds verification into the reserved
//! bootloader space (design document section 14), it signs this digest and the
//! layout below stays as it is.
//!
//! # Descriptor
//!
//! 48 bytes, in the last page of the kernel region so that it is inside the
//! writable area and can be updated by the same UDS flow that writes the
//! kernel:
//!
//! ```text
//!   0  4   magic   "TKIV", little endian
//!   4  4   version, currently 1
//!   8  4   length of the hashed image in bytes
//!  12  4   reserved, zero
//!  16  32  SHA-256 of [kernel_start, kernel_start + length)
//! ```
//!
//! # Three states, because absence is ambiguous
//!
//! A descriptor that is missing, erased or malformed yields
//! [`Verdict::NoDescriptor`] and the board boots normally. That is a
//! considered choice: flashing the kernel with a debugger writes no descriptor,
//! and a check that bricked the board whenever someone used J-Link would be
//! worse than no check at all.
//!
//! But failing open on absence leaves a hole, and it is exactly the power-loss
//! case. If no descriptor exists -- immediately after a debugger flash, say --
//! and a reflash is then interrupted half way, the board comes up with a
//! truncated kernel and *no* record that anything went wrong, so it boots it.
//! Absence cannot distinguish "nobody recorded a digest" from "somebody was
//! part way through writing one".
//!
//! Hence a third state. A flashing tool writes [`MAGIC_IN_PROGRESS`] *before*
//! touching the kernel and replaces it with the real descriptor afterwards, so
//! an interruption at any point in between leaves a positive marker rather than
//! silence, and [`Verdict::Interrupted`] holds the board in the bootloader.
//!
//! This depends on the flashing tool doing its half; `uds_flash.py` does. A
//! tool that does not gets the same fail-open behaviour as a debugger flash,
//! which is the honest fallback rather than a guarantee.

use sha2::{Digest, Sha256};

/// `"TKIV"` -- Tock Kernel Integrity Vector. A complete descriptor.
const MAGIC: u32 = 0x5649_4B54;

/// `"TKIP"` -- the same descriptor mid-write. Written before the kernel is
/// touched and replaced by [`MAGIC`] once the image is complete and verified,
/// so that an interruption anywhere in between is detectable.
pub const MAGIC_IN_PROGRESS: u32 = 0x5049_4B54;

const VERSION: u32 = 1;

/// Bytes the descriptor occupies. The page holding it is reserved entirely.
pub const DESCRIPTOR_LEN: usize = 48;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// No usable descriptor. Boot anyway; see the module documentation.
    NoDescriptor,
    /// The image matches the digest it carries.
    Match,
    /// A descriptor is present and the image does not match it.
    Mismatch,
    /// A flash was started and never finished. The image cannot be trusted
    /// even if it happens to look plausible.
    Interrupted,
}

/// Read `len` bytes of flash at `address`.
///
/// Flash is memory-mapped and nothing in this path has written it, so a plain
/// read is coherent -- there is no dirty cache line to worry about, unlike the
/// message-RAM paths elsewhere in this tree.
unsafe fn flash(address: u32, len: usize) -> &'static [u8] {
    core::slice::from_raw_parts(address as *const u8, len)
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

/// Check the kernel at `kernel_start` against the descriptor at
/// `descriptor_address`.
///
/// `descriptor_address` is also the upper bound on the image: the descriptor
/// sits above the kernel, so a length reaching it is malformed rather than
/// merely large.
/// Like [`check`], but also reports the image length the descriptor claims.
///
/// Rollback needs the length as well as the verdict, and reading the descriptor
/// twice would leave room for the two answers to disagree.
pub fn describe(kernel_start: u32, descriptor_address: u32) -> (Verdict, usize) {
    let verdict = check(kernel_start, descriptor_address);
    let descriptor = unsafe { flash(descriptor_address, DESCRIPTOR_LEN) };
    let length = if verdict == Verdict::Match {
        u32_at(descriptor, 8) as usize
    } else {
        0
    };
    (verdict, length)
}

pub fn check(kernel_start: u32, descriptor_address: u32) -> Verdict {
    let descriptor = unsafe { flash(descriptor_address, DESCRIPTOR_LEN) };

    // Checked before the version, and before anything else: a half-written
    // descriptor may have nothing else valid in it, and the whole point is
    // that this state is recognised without depending on the rest.
    if u32_at(descriptor, 0) == MAGIC_IN_PROGRESS {
        return Verdict::Interrupted;
    }

    if u32_at(descriptor, 0) != MAGIC || u32_at(descriptor, 4) != VERSION {
        return Verdict::NoDescriptor;
    }

    let length = u32_at(descriptor, 8);
    // A length of zero, or one that runs into the descriptor itself, means the
    // descriptor is corrupt rather than that the image is. Treat it as absent:
    // refusing to boot on a garbled descriptor would turn a bad *write of 48
    // bytes* into a bricked board, which is exactly the outcome this module
    // exists to avoid.
    if length == 0 || kernel_start.saturating_add(length) > descriptor_address {
        return Verdict::NoDescriptor;
    }

    let image = unsafe { flash(kernel_start, length as usize) };

    let mut hasher = Sha256::new();
    hasher.update(image);
    let digest = hasher.finalize();

    if digest.as_slice() == &descriptor[16..48] {
        Verdict::Match
    } else {
        Verdict::Mismatch
    }
}
