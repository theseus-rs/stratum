//! Checked, endian-aware byte primitives shared by every codec.
//!
//! Binary parsing normally leans on slicing, indexing, `unwrap`, and panics; all of which
//! are denied workspace-wide. [`ByteReader`] and [`ByteWriter`] provide the same ergonomics
//! through fully checked operations that return [`Result`] instead.

use crate::alloc_prelude::*;
use crate::error::{Error, Result};
use crate::target::Endianness;

/// A forward, bounds-checked cursor over a byte buffer.
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    endian: Endianness,
    offset: usize,
}

impl<'a> ByteReader<'a> {
    /// Creates a reader positioned at the start of `data`.
    #[must_use]
    pub fn new(data: &'a [u8], endian: Endianness) -> Self {
        Self {
            data,
            endian,
            offset: 0,
        }
    }

    /// The current byte offset.
    #[must_use]
    pub fn position(&self) -> usize {
        self.offset
    }

    /// The number of bytes left to read.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Returns `true` if the cursor has consumed every byte.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Moves the cursor to an absolute `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if `offset` is past the end of the buffer.
    pub fn seek(&mut self, offset: usize) -> Result<()> {
        if offset > self.data.len() {
            return Err(Error::UnexpectedEof {
                offset,
                needed: 0,
                len: self.data.len(),
            });
        }
        self.offset = offset;
        Ok(())
    }

    /// Advances the cursor by `count` bytes without reading them.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `count` bytes remain.
    pub fn skip(&mut self, count: usize) -> Result<()> {
        self.read_bytes(count).map(|_| ())
    }

    /// Reads `count` bytes and advances the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `count` bytes remain.
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Error::UnexpectedEof {
            offset: self.offset,
            needed: count,
            len: self.data.len(),
        })?;
        let slice = self
            .data
            .get(self.offset..end)
            .ok_or(Error::UnexpectedEof {
                offset: self.offset,
                needed: count,
                len: self.data.len(),
            })?;
        self.offset = end;
        Ok(slice)
    }

    /// Reads a `count`-byte slice at an absolute `offset` without moving the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the range is out of bounds.
    pub fn peek_at(&self, offset: usize, count: usize) -> Result<&'a [u8]> {
        let end = offset.checked_add(count).ok_or(Error::UnexpectedEof {
            offset,
            needed: count,
            len: self.data.len(),
        })?;
        self.data.get(offset..end).ok_or(Error::UnexpectedEof {
            offset,
            needed: count,
            len: self.data.len(),
        })
    }

    /// Reads a single byte.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_bytes(1)?;
        bytes.first().copied().ok_or(Error::UnexpectedEof {
            offset: self.offset,
            needed: 1,
            len: self.data.len(),
        })
    }

    /// Reads a `u16` in the reader's endianness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16> {
        let raw: [u8; 2] = self.read_array()?;
        Ok(match self.endian {
            Endianness::Little => u16::from_le_bytes(raw),
            Endianness::Big => u16::from_be_bytes(raw),
        })
    }

    /// Reads a `u32` in the reader's endianness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32> {
        let raw: [u8; 4] = self.read_array()?;
        Ok(match self.endian {
            Endianness::Little => u32::from_le_bytes(raw),
            Endianness::Big => u32::from_be_bytes(raw),
        })
    }

    /// Reads a `u64` in the reader's endianness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than eight bytes remain.
    pub fn read_u64(&mut self) -> Result<u64> {
        let raw: [u8; 8] = self.read_array()?;
        Ok(match self.endian {
            Endianness::Little => u64::from_le_bytes(raw),
            Endianness::Big => u64::from_be_bytes(raw),
        })
    }

    /// Reads an unsigned LEB128 value (used by WebAssembly and DWARF).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedLeb128`] if the value does not terminate within ten bytes
    /// (enough for any `u64`), or [`Error::UnexpectedEof`] if the buffer ends first.
    pub fn read_uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_u8()?;
            let low = u64::from(byte & 0x7f);
            if shift >= 64 || (shift == 63 && low > 1) {
                return Err(Error::MalformedLeb128);
            }
            result |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
    }

    /// Reads a signed LEB128 value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedLeb128`] on overflow or [`Error::UnexpectedEof`] if the
    /// buffer ends mid-value.
    pub fn read_sleb128(&mut self) -> Result<i64> {
        let mut result: i64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.read_u8()?;
            if shift >= 64 {
                return Err(Error::MalformedLeb128);
            }
            result |= i64::from(byte & 0x7f)
                .checked_shl(shift)
                .ok_or(Error::MalformedLeb128)?;
            shift += 7;
            if byte & 0x80 == 0 {
                if shift < 64 && byte & 0x40 != 0 {
                    result |= (-1_i64).wrapping_shl(shift);
                }
                return Ok(result);
            }
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.read_bytes(N)?;
        let mut array = [0_u8; N];
        array.copy_from_slice(slice);
        Ok(array)
    }
}

/// A growable byte buffer with endian-aware writes, in-place patching, and symbolic fixups.
#[derive(Debug, Clone)]
pub struct ByteWriter {
    data: Vec<u8>,
    endian: Endianness,
    labels: Vec<(u32, u64)>,
    fixups: Vec<Fixup>,
}

#[derive(Debug, Clone, Copy)]
struct Fixup {
    at: usize,
    width: FixupWidth,
    label: u32,
    addend: i64,
}

#[derive(Debug, Clone, Copy)]
enum FixupWidth {
    W32,
    W64,
}

impl ByteWriter {
    /// Creates an empty writer.
    #[must_use]
    pub fn new(endian: Endianness) -> Self {
        Self {
            data: Vec::new(),
            endian,
            labels: Vec::new(),
            fixups: Vec::new(),
        }
    }

    /// The number of bytes written so far (also the offset of the next write).
    #[must_use]
    pub fn position(&self) -> usize {
        self.data.len()
    }

    /// Appends a single byte.
    pub fn write_u8(&mut self, value: u8) {
        self.data.push(value);
    }

    /// Appends a `u16` in the writer's endianness.
    pub fn write_u16(&mut self, value: u16) {
        let raw = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.data.extend_from_slice(&raw);
    }

    /// Appends a `u32` in the writer's endianness.
    pub fn write_u32(&mut self, value: u32) {
        let raw = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.data.extend_from_slice(&raw);
    }

    /// Appends a `u64` in the writer's endianness.
    pub fn write_u64(&mut self, value: u64) {
        let raw = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.data.extend_from_slice(&raw);
    }

    /// Appends a raw byte slice verbatim.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    /// Appends `count` zero bytes.
    pub fn write_zeros(&mut self, count: usize) {
        self.data.resize(self.data.len().saturating_add(count), 0);
    }

    /// Appends an unsigned LEB128 value.
    pub fn write_uleb128(&mut self, mut value: u64) {
        loop {
            let mut byte = u8::try_from(value & 0x7f).unwrap_or(0);
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            self.data.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    /// Appends a signed LEB128 value.
    pub fn write_sleb128(&mut self, mut value: i64) {
        loop {
            let byte = u8::try_from(value & 0x7f).unwrap_or(0);
            value >>= 7;
            let sign_bit = byte & 0x40 != 0;
            let done = (value == 0 && !sign_bit) || (value == -1 && sign_bit);
            self.data.push(if done { byte } else { byte | 0x80 });
            if done {
                break;
            }
        }
    }

    /// Pads the buffer with zero bytes until its length is a multiple of `align`.
    ///
    /// An `align` of `0` or `1` is a no-op.
    pub fn align_to(&mut self, align: usize) {
        if align <= 1 {
            return;
        }
        let rem = self.data.len() % align;
        if rem != 0 {
            self.write_zeros(align - rem);
        }
    }

    /// Overwrites four bytes at `offset` with `value`, in the writer's endianness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the range lies outside the buffer.
    pub fn patch_u32(&mut self, offset: usize, value: u32) -> Result<()> {
        let raw = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.patch_bytes(offset, &raw)
    }

    /// Overwrites eight bytes at `offset` with `value`, in the writer's endianness.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if the range lies outside the buffer.
    pub fn patch_u64(&mut self, offset: usize, value: u64) -> Result<()> {
        let raw = match self.endian {
            Endianness::Little => value.to_le_bytes(),
            Endianness::Big => value.to_be_bytes(),
        };
        self.patch_bytes(offset, &raw)
    }

    fn patch_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or(Error::Malformed("patch offset overflow"))?;
        let dst = self
            .data
            .get_mut(offset..end)
            .ok_or(Error::Malformed("patch out of bounds"))?;
        dst.copy_from_slice(bytes);
        Ok(())
    }

    /// Records that `label` resolves to `value` for later [`apply_fixups`](Self::apply_fixups).
    pub fn define_label(&mut self, label: u32, value: u64) {
        for entry in &mut self.labels {
            if entry.0 == label {
                entry.1 = value;
                return;
            }
        }
        self.labels.push((label, value));
    }

    /// Reserves a 32-bit slot to be filled with the value of `label` (plus `addend`) when
    /// [`apply_fixups`](Self::apply_fixups) runs.
    pub fn fixup_u32(&mut self, label: u32, addend: i64) {
        let at = self.data.len();
        self.write_u32(0);
        self.fixups.push(Fixup {
            at,
            width: FixupWidth::W32,
            label,
            addend,
        });
    }

    /// Reserves a 64-bit slot to be filled with the value of `label` (plus `addend`).
    pub fn fixup_u64(&mut self, label: u32, addend: i64) {
        let at = self.data.len();
        self.write_u64(0);
        self.fixups.push(Fixup {
            at,
            width: FixupWidth::W64,
            label,
            addend,
        });
    }

    /// Resolves every recorded fixup against the defined labels.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UndefinedLabel`] if a fixup references a label that was never
    /// defined, or [`Error::ValueOutOfRange`] if a resolved value does not fit a 32-bit slot.
    pub fn apply_fixups(&mut self) -> Result<()> {
        let pending = core::mem::take(&mut self.fixups);
        for fixup in pending {
            let base = self
                .labels
                .iter()
                .find_map(|&(label, value)| (label == fixup.label).then_some(value))
                .ok_or(Error::UndefinedLabel)?;
            let resolved = i128::from(base) + i128::from(fixup.addend);
            let resolved = u64::try_from(resolved)
                .map_err(|_| Error::ValueOutOfRange("negative fixup result"))?;
            match fixup.width {
                FixupWidth::W32 => {
                    let narrow = u32::try_from(resolved)
                        .map_err(|_| Error::ValueOutOfRange("fixup exceeds 32 bits"))?;
                    self.patch_u32(fixup.at, narrow)?;
                }
                FixupWidth::W64 => self.patch_u64(fixup.at, resolved)?,
            }
        }
        Ok(())
    }

    /// Consumes the writer, applying any outstanding fixups and returning the bytes.
    ///
    /// # Errors
    ///
    /// Propagates failures from [`apply_fixups`](Self::apply_fixups).
    pub fn finish(mut self) -> Result<Vec<u8>> {
        self.apply_fixups()?;
        Ok(self.data)
    }

    /// Returns the bytes written so far without resolving fixups.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteReader, ByteWriter};
    use crate::error::Error;
    use crate::target::Endianness;

    #[test]
    fn round_trips_fixed_width_integers() {
        let mut w = ByteWriter::new(Endianness::Little);
        w.write_u8(0x12);
        w.write_u16(0x3456);
        w.write_u32(0x89ab_cdef);
        w.write_u64(0x0102_0304_0506_0708);
        let bytes = w.finish().unwrap();

        let mut r = ByteReader::new(&bytes, Endianness::Little);
        assert_eq!(r.read_u8().unwrap(), 0x12);
        assert_eq!(r.read_u16().unwrap(), 0x3456);
        assert_eq!(r.read_u32().unwrap(), 0x89ab_cdef);
        assert_eq!(r.read_u64().unwrap(), 0x0102_0304_0506_0708);
        assert!(r.is_empty());
    }

    #[test]
    fn endianness_is_honoured() {
        let mut be = ByteWriter::new(Endianness::Big);
        be.write_u32(0x0a0b_0c0d);
        assert_eq!(be.as_bytes(), &[0x0a, 0x0b, 0x0c, 0x0d]);

        let mut le = ByteWriter::new(Endianness::Little);
        le.write_u32(0x0a0b_0c0d);
        assert_eq!(le.as_bytes(), &[0x0d, 0x0c, 0x0b, 0x0a]);
    }

    #[test]
    fn uleb128_round_trips() {
        for value in [0_u64, 1, 127, 128, 300, 0xffff_ffff, u64::MAX] {
            let mut w = ByteWriter::new(Endianness::Little);
            w.write_uleb128(value);
            let bytes = w.finish().unwrap();
            let mut r = ByteReader::new(&bytes, Endianness::Little);
            assert_eq!(r.read_uleb128().unwrap(), value);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn sleb128_round_trips() {
        for value in [0_i64, 1, -1, 63, -64, 64, -65, i64::MIN, i64::MAX] {
            let mut w = ByteWriter::new(Endianness::Little);
            w.write_sleb128(value);
            let bytes = w.finish().unwrap();
            let mut r = ByteReader::new(&bytes, Endianness::Little);
            assert_eq!(r.read_sleb128().unwrap(), value);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn reads_past_end_error() {
        let bytes = [0_u8; 2];
        let mut r = ByteReader::new(&bytes, Endianness::Little);
        assert!(matches!(r.read_u32(), Err(Error::UnexpectedEof { .. })));
    }

    #[test]
    fn fixups_resolve_labels() {
        let mut w = ByteWriter::new(Endianness::Little);
        w.fixup_u32(7, 4);
        w.define_label(7, 0x1000);
        let bytes = w.finish().unwrap();
        assert_eq!(bytes, 0x1004_u32.to_le_bytes());
    }

    #[test]
    fn undefined_label_is_an_error() {
        let mut w = ByteWriter::new(Endianness::Little);
        w.fixup_u64(1, 0);
        assert!(matches!(w.apply_fixups(), Err(Error::UndefinedLabel)));
    }

    #[test]
    fn align_pads_with_zeros() {
        let mut w = ByteWriter::new(Endianness::Little);
        w.write_u8(1);
        w.align_to(4);
        assert_eq!(w.as_bytes(), &[1, 0, 0, 0]);
    }

    #[test]
    fn patch_rejects_out_of_bounds() {
        let mut w = ByteWriter::new(Endianness::Little);
        w.write_u32(0);
        assert!(w.patch_u32(8, 1).is_err());
    }

    #[test]
    fn peek_at_reads_without_advancing_and_validates_bounds() {
        let r = ByteReader::new(&[1, 2, 3, 4], Endianness::Little);
        assert_eq!(r.peek_at(1, 2).unwrap(), &[2, 3]);
        assert!(r.peek_at(3, 2).is_err());
        assert!(r.peek_at(usize::MAX, 1).is_err());
    }

    #[test]
    fn read_bytes_reports_offset_overflow() {
        let mut r = ByteReader::new(&[1, 2, 3, 4], Endianness::Little);
        r.read_u8().unwrap();
        assert!(r.read_bytes(usize::MAX).is_err());
    }

    #[test]
    fn leb128_overflow_is_rejected() {
        let mut unsigned = ByteReader::new(&[0xFF; 11], Endianness::Little);
        assert!(unsigned.read_uleb128().is_err());
        let mut signed = ByteReader::new(&[0xFF; 11], Endianness::Little);
        assert!(signed.read_sleb128().is_err());
    }

    #[test]
    fn align_to_one_is_a_no_op() {
        let mut w = ByteWriter::new(Endianness::Little);
        w.write_u8(1);
        w.align_to(1);
        assert_eq!(w.finish().unwrap().len(), 1);
    }

    #[test]
    fn patches_and_fixups_cover_both_endians_and_widths() {
        let mut be = ByteWriter::new(Endianness::Big);
        be.write_u32(0);
        be.write_u64(0);
        be.patch_u32(0, 0x0102_0304).unwrap();
        be.patch_u64(4, 0x0102_0304_0506_0708).unwrap();
        let bytes = be.finish().unwrap();
        assert_eq!(bytes.first(), Some(&0x01));

        let mut w = ByteWriter::new(Endianness::Little);
        w.fixup_u32(7, 0);
        w.fixup_u64(11, 0);
        w.define_label(7, 0x10);
        w.define_label(11, 0x20);
        w.define_label(7, 0x30);
        let out = w.finish().unwrap();
        assert_eq!(out.len(), 12);
    }
}
