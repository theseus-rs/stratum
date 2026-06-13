//! Builds an embedded ad-hoc code signature (`CSMAGIC_EMBEDDED_SIGNATURE`) for a Mach-O image.
//!
//! Only the pieces arm64 macOS requires to accept an ad-hoc binary are emitted: a single
//! `CodeDirectory` (SHA-256) wrapped in a `SuperBlob`. All fields are big-endian.

use crate::consts::{
    CS_ADHOC, CS_CODEDIRECTORY_VERSION, CS_EXECSEG_MAIN_BINARY, CS_HASH_SIZE_SHA256,
    CS_HASHTYPE_SHA256, CS_PAGE_SHIFT, CS_PAGE_SIZE, CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_CODEDIRECTORY,
};
use crate::convert::{u32_from_u64, u32_from_usize, usize_from_u64};
use crate::sha256::sha256;
use stratum_oir::{ByteWriter, Endianness, Error, Result};

extern crate alloc;
use alloc::vec::Vec;

const SUPERBLOB_HEADER: u32 = 12; // magic + length + count
const INDEX_ENTRY: u32 = 8; // type + offset
const CD_FIXED_HEADER: u32 = 88; // through execSegFlags (version 0x20400)

fn code_slots(code_limit: u64) -> u64 {
    code_limit.div_ceil(CS_PAGE_SIZE)
}

/// The exact size, in bytes, the signature for `ident` over `code_limit` bytes will occupy.
#[must_use]
pub fn signature_size(ident: &str, code_limit: u64) -> u32 {
    let ident_len = u32_from_usize(ident.len()).saturating_add(1);
    let slots = u32_from_u64(code_slots(code_limit));
    let hashes = slots.saturating_mul(u32::from(CS_HASH_SIZE_SHA256));
    let cd_len = CD_FIXED_HEADER
        .saturating_add(ident_len)
        .saturating_add(hashes);
    SUPERBLOB_HEADER.saturating_add(INDEX_ENTRY).saturating_add(cd_len)
}

/// Builds the embedded signature blob.
///
/// `image` must contain at least the first `code_limit` bytes of the file; those bytes are
/// hashed page by page. `exec_seg_limit` is the file size of the `__TEXT` segment.
///
/// # Errors
///
/// Returns an error if `image` is shorter than `code_limit`.
pub fn build(image: &[u8], ident: &str, code_limit: u64, exec_seg_limit: u64) -> Result<Vec<u8>> {
    let limit = usize_from_u64(code_limit);
    let covered = image
        .get(..limit)
        .ok_or(Error::Malformed("image shorter than code limit"))?;

    let ident_len = u32_from_usize(ident.len()).saturating_add(1);
    let slots = code_slots(code_limit);
    let slot_count = u32_from_u64(slots);
    let hashes_len = slot_count.saturating_mul(u32::from(CS_HASH_SIZE_SHA256));
    let cd_len = CD_FIXED_HEADER
        .saturating_add(ident_len)
        .saturating_add(hashes_len);
    let cd_offset = SUPERBLOB_HEADER.saturating_add(INDEX_ENTRY);
    let total = cd_offset.saturating_add(cd_len);
    let code_limit32 = u32_from_u64(code_limit);

    let mut w = ByteWriter::new(Endianness::Big);
    // SuperBlob header.
    w.write_u32(CSMAGIC_EMBEDDED_SIGNATURE);
    w.write_u32(total);
    w.write_u32(1); // one sub-blob
    // Index: CodeDirectory.
    w.write_u32(CSSLOT_CODEDIRECTORY);
    w.write_u32(cd_offset);

    // CodeDirectory.
    w.write_u32(CSMAGIC_CODEDIRECTORY);
    w.write_u32(cd_len);
    w.write_u32(CS_CODEDIRECTORY_VERSION);
    w.write_u32(CS_ADHOC);
    w.write_u32(CD_FIXED_HEADER + ident_len); // hashOffset
    w.write_u32(CD_FIXED_HEADER); // identOffset
    w.write_u32(0); // nSpecialSlots
    w.write_u32(slot_count); // nCodeSlots
    w.write_u32(code_limit32);
    w.write_u8(CS_HASH_SIZE_SHA256);
    w.write_u8(CS_HASHTYPE_SHA256);
    w.write_u8(0); // platform
    w.write_u8(CS_PAGE_SHIFT);
    w.write_u32(0); // spare2
    w.write_u32(0); // scatterOffset
    w.write_u32(0); // teamOffset
    w.write_u32(0); // spare3
    w.write_u64(0); // codeLimit64
    w.write_u64(0); // execSegBase
    w.write_u64(exec_seg_limit);
    w.write_u64(CS_EXECSEG_MAIN_BINARY);

    // Identifier.
    w.write_bytes(ident.as_bytes());
    w.write_u8(0);

    // Code-page hashes.
    let page = usize_from_u64(CS_PAGE_SIZE);
    for chunk in covered.chunks(page) {
        w.write_bytes(&sha256(chunk));
    }

    w.finish()
}

#[cfg(test)]
mod tests {
    use super::{build, signature_size};
    use crate::convert::usize_from_u32;

    #[test]
    fn size_matches_built_length() {
        let image = [0u8; 0x4000];
        let size = signature_size("stratum", 0x4000);
        let blob = build(&image, "stratum", 0x4000, 0x4000).unwrap();
        assert_eq!(usize_from_u32(size), blob.len());
    }

    #[test]
    fn build_rejects_image_shorter_than_code_limit() {
        let image = [0u8; 0x10];
        assert!(build(&image, "stratum", 0x4000, 0x4000).is_err());
    }
}
