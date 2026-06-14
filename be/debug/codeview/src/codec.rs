//! Encodes and decodes a [`DebugTable`] as a `CodeView` `C13` debug blob.

use crate::consts::{
    CV_SIGNATURE_C13, DEBUG_S_FILECHKSMS, DEBUG_S_LINES, DEBUG_S_STRINGTABLE, DEBUG_S_SYMBOLS,
    LF_HAVE_COLUMNS, S_END, S_FRAMEPROC, S_GPROC32, SUBSECTION_ALIGN, T_NOTYPE,
};
use crate::table::{DebugTable, FuncEntry, LineEntry};
use stratum_oir::{ByteReader, ByteWriter, Endianness, Error, Result};

extern crate alloc;
use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const SEGMENT_ONE: u16 = 1;
const CHECKSUM_KIND_MD5: u8 = 1;
const CHECKSUM_SIZE_MD5: usize = 16;
const LINE_FLAG_STATEMENT: u32 = 0x8000_0000;
const LINE_START_MASK: u32 = 0x00ff_ffff;
const LINE_DELTA_SHIFT: u32 = 24;
const LINE_DELTA_MAX: u32 = 0x7f;
const FRAMEPROC_BYTES: usize = 26;
const GPROC_FIXED_BYTES: usize = 35;

#[derive(Debug, Clone, Copy)]
struct FileMapEntry {
    file: u32,
    string_offset: u32,
    checksum_offset: u32,
}

fn writer() -> ByteWriter {
    ByteWriter::new(Endianness::Little)
}

/// Encodes `table` into a `CodeView` `C13` debug blob.
///
/// The emitted C13 stream contains `DEBUG_S_STRINGTABLE`, `DEBUG_S_FILECHKSMS`,
/// `DEBUG_S_LINES`, and `DEBUG_S_SYMBOLS` subsections. Procedures are represented with
/// `S_GPROC32`/`S_FRAMEPROC`/`S_END` records and no full PDB type stream (`T_NOTYPE`).
///
/// # Errors
///
/// Returns an error if an address, line delta, name, or length field does not fit the `CodeView`
/// field width.
pub fn encode(table: &DebugTable) -> Result<Vec<u8>> {
    let files = collect_files(&table.lines)?;
    let strings = build_string_table(&files)?;
    let checksums = build_file_checksums(&files)?;
    let lines = build_lines_payload(&table.lines, &files)?;
    let syms = build_symbols_payload(&table.funcs)?;

    let mut w = writer();
    w.write_u32(CV_SIGNATURE_C13);
    emit_subsection(&mut w, DEBUG_S_STRINGTABLE, &strings)?;
    emit_subsection(&mut w, DEBUG_S_FILECHKSMS, &checksums)?;
    emit_subsection(&mut w, DEBUG_S_LINES, &lines)?;
    emit_subsection(&mut w, DEBUG_S_SYMBOLS, &syms)?;
    w.finish()
}

fn emit_subsection(w: &mut ByteWriter, kind: u32, payload: &[u8]) -> Result<()> {
    w.write_u32(kind);
    w.write_u32(u32_of_usize(payload.len(), "subsection")?);
    w.write_bytes(payload);
    w.align_to(SUBSECTION_ALIGN);
    Ok(())
}

fn collect_files(lines: &[LineEntry]) -> Result<Vec<FileMapEntry>> {
    let mut files = Vec::new();
    for line in lines {
        if files
            .iter()
            .all(|entry: &FileMapEntry| entry.file != line.file)
        {
            files.push(FileMapEntry {
                file: line.file,
                string_offset: 0,
                checksum_offset: 0,
            });
        }
    }

    let mut string_offset = 1u32;
    let mut checksum_offset = 0u32;
    for entry in &mut files {
        entry.string_offset = string_offset;
        entry.checksum_offset = checksum_offset;
        let name_len = u32_of_usize(file_name(entry.file).len(), "file name")?;
        string_offset = string_offset
            .checked_add(name_len)
            .and_then(|value| value.checked_add(1))
            .ok_or(Error::ValueOutOfRange("string table"))?;
        let checksum_record = 6usize
            .checked_add(CHECKSUM_SIZE_MD5)
            .ok_or(Error::ValueOutOfRange("file checksums"))?;
        checksum_offset = checksum_offset
            .checked_add(align4_u32(checksum_record)?)
            .ok_or(Error::ValueOutOfRange("file checksums"))?;
    }
    Ok(files)
}

fn file_name(file: u32) -> String {
    let mut name = "file:".to_string();
    name.push_str(&file.to_string());
    name
}

fn build_string_table(files: &[FileMapEntry]) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_u8(0);
    for file in files {
        let name = file_name(file.file);
        w.write_bytes(name.as_bytes());
        w.write_u8(0);
    }
    w.finish()
}

fn build_file_checksums(files: &[FileMapEntry]) -> Result<Vec<u8>> {
    let mut w = writer();
    for file in files {
        w.write_u32(file.string_offset);
        w.write_u8(
            u8::try_from(CHECKSUM_SIZE_MD5).map_err(|_| Error::ValueOutOfRange("checksum"))?,
        );
        w.write_u8(CHECKSUM_KIND_MD5);
        w.write_zeros(CHECKSUM_SIZE_MD5);
        w.align_to(SUBSECTION_ALIGN);
    }
    w.finish()
}

fn build_lines_payload(lines: &[LineEntry], files: &[FileMapEntry]) -> Result<Vec<u8>> {
    let mut w = writer();
    let base = lines.iter().map(|line| line.address).min().unwrap_or(0);
    let end = lines
        .iter()
        .map(|line| line.address.saturating_add(line.length))
        .max()
        .unwrap_or(base);
    w.write_u32(u32_of_u64(base, "line base address")?);
    w.write_u16(SEGMENT_ONE);
    w.write_u16(LF_HAVE_COLUMNS);
    w.write_u32(u32_of_u64(end.saturating_sub(base), "line code size")?);

    for file in files {
        let count = lines.iter().filter(|line| line.file == file.file).count();
        w.write_u32(file.checksum_offset);
        w.write_u32(u32_of_usize(count, "line count")?);
        let block_size = 12usize
            .checked_add(
                count
                    .checked_mul(12)
                    .ok_or(Error::ValueOutOfRange("line block"))?,
            )
            .ok_or(Error::ValueOutOfRange("line block"))?;
        w.write_u32(u32_of_usize(block_size, "line block")?);
        for line in lines.iter().filter(|line| line.file == file.file) {
            w.write_u32(line_offset(line.address.saturating_sub(base))?);
            w.write_u32(line_flags(line.start, line.end)?);
        }
        for line in lines.iter().filter(|line| line.file == file.file) {
            w.write_u16(u16_of_u32(line.start, "start column")?);
            w.write_u16(u16_of_u32(line.end, "end column")?);
        }
    }
    w.finish()
}

fn line_offset(offset: u64) -> Result<u32> {
    u32_of_u64(offset, "line offset")
}

fn line_flags(start: u32, end: u32) -> Result<u32> {
    if start > LINE_START_MASK {
        return Err(Error::ValueOutOfRange("line start"));
    }
    let delta = end.saturating_sub(start);
    if delta > LINE_DELTA_MAX {
        return Err(Error::ValueOutOfRange("line delta"));
    }
    Ok(start | (delta << LINE_DELTA_SHIFT) | LINE_FLAG_STATEMENT)
}

fn build_symbols_payload(funcs: &[FuncEntry]) -> Result<Vec<u8>> {
    let mut w = writer();
    for func in funcs {
        emit_gproc32(&mut w, func)?;
        emit_frameproc(&mut w)?;
        emit_symbol_record(&mut w, S_END, &[])?;
    }
    w.finish()
}

fn emit_gproc32(w: &mut ByteWriter, func: &FuncEntry) -> Result<()> {
    let mut payload = writer();
    payload.write_u32(0);
    payload.write_u32(0);
    payload.write_u32(0);
    payload.write_u32(u32_of_u64(func.length, "function length")?);
    payload.write_u32(0);
    payload.write_u32(u32_of_u64(func.length, "function debug end")?);
    payload.write_u32(T_NOTYPE);
    payload.write_u32(u32_of_u64(func.address, "function address")?);
    payload.write_u16(SEGMENT_ONE);
    payload.write_u8(0);
    payload.write_bytes(func.name.as_bytes());
    payload.write_u8(0);
    emit_symbol_record(w, S_GPROC32, &payload.finish()?)
}

fn emit_frameproc(w: &mut ByteWriter) -> Result<()> {
    let mut payload = writer();
    payload.write_u32(0);
    payload.write_u32(0);
    payload.write_u32(0);
    payload.write_u32(0);
    payload.write_u32(0);
    payload.write_u16(0);
    payload.write_u32(0);
    emit_symbol_record(w, S_FRAMEPROC, &payload.finish()?)
}

fn emit_symbol_record(w: &mut ByteWriter, kind: u16, payload: &[u8]) -> Result<()> {
    let record_len = payload
        .len()
        .checked_add(2)
        .ok_or(Error::ValueOutOfRange("symbol record"))?;
    w.write_u16(u16_of_usize(record_len, "symbol record")?);
    w.write_u16(kind);
    w.write_bytes(payload);
    w.align_to(SUBSECTION_ALIGN);
    Ok(())
}

/// Decodes a `CodeView` `C13` debug blob into a [`DebugTable`].
///
/// # Errors
///
/// Returns an error on a bad signature, a truncated subsection, a malformed line/file checksum
/// graph, or a malformed symbol record.
pub fn decode(bytes: &[u8]) -> Result<DebugTable> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    if r.read_u32()? != CV_SIGNATURE_C13 {
        return Err(Error::BadMagic);
    }

    let mut table = DebugTable::new();
    let mut strings = Vec::new();
    let mut checksums = Vec::new();
    while r.remaining() >= 8 {
        let kind = r.read_u32()?;
        let len = usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("subsection len"))?;
        let payload = r.read_bytes(len)?.to_vec();
        let pad = (SUBSECTION_ALIGN - (len % SUBSECTION_ALIGN)) % SUBSECTION_ALIGN;
        r.skip(pad)?;
        match kind {
            DEBUG_S_STRINGTABLE => strings = payload,
            DEBUG_S_FILECHKSMS => checksums = decode_checksums(&payload, &strings)?,
            DEBUG_S_LINES => table.lines = decode_lines(&payload, &checksums)?,
            DEBUG_S_SYMBOLS => table.funcs = decode_symbols(&payload)?,
            _ => {}
        }
    }
    if !r.is_empty() {
        return Err(Error::Malformed("trailing subsection header"));
    }
    Ok(table)
}

fn decode_checksums(payload: &[u8], strings: &[u8]) -> Result<Vec<(u32, u32)>> {
    let mut r = ByteReader::new(payload, Endianness::Little);
    let mut checksums = Vec::new();
    while !r.is_empty() {
        let record_offset = u32_of_usize(r.position(), "checksum offset")?;
        let string_offset = r.read_u32()?;
        let checksum_len = usize::from(r.read_u8()?);
        let _kind = r.read_u8()?;
        r.skip(checksum_len)?;
        let pad = (SUBSECTION_ALIGN - ((6 + checksum_len) % SUBSECTION_ALIGN)) % SUBSECTION_ALIGN;
        r.skip(pad)?;
        checksums.push((record_offset, file_id_from_string(strings, string_offset)?));
    }
    Ok(checksums)
}

fn file_id_from_string(strings: &[u8], offset: u32) -> Result<u32> {
    let start = usize::try_from(offset).map_err(|_| Error::ValueOutOfRange("string offset"))?;
    let tail = strings.get(start..).ok_or(Error::UnexpectedEof {
        offset: start,
        needed: 1,
        len: strings.len(),
    })?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated string table entry"))?;
    let raw = tail
        .get(0..len)
        .ok_or(Error::Malformed("string table entry"))?;
    let text = core::str::from_utf8(raw).map_err(|_| Error::Malformed("string table utf8"))?;
    text.strip_prefix("file:")
        .ok_or(Error::Malformed("file string prefix"))?
        .parse::<u32>()
        .map_err(|_| Error::Malformed("file string id"))
}

fn decode_lines(payload: &[u8], checksums: &[(u32, u32)]) -> Result<Vec<LineEntry>> {
    let mut r = ByteReader::new(payload, Endianness::Little);
    let base = r.read_u32()?;
    let _segment = r.read_u16()?;
    let flags = r.read_u16()?;
    let code_size = r.read_u32()?;
    let has_columns = flags & LF_HAVE_COLUMNS != 0;
    let mut lines = Vec::new();
    while !r.is_empty() {
        let file_checksum = r.read_u32()?;
        let count = usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("line count"))?;
        let block_size =
            usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("block size"))?;
        let expected = 12usize
            .checked_add(
                count
                    .checked_mul(if has_columns { 12 } else { 8 })
                    .ok_or(Error::ValueOutOfRange("line block"))?,
            )
            .ok_or(Error::ValueOutOfRange("line block"))?;
        if block_size != expected {
            return Err(Error::Malformed("line block size"));
        }
        let file = checksum_file(checksums, file_checksum)?;
        let mut decoded = Vec::with_capacity(count);
        for _ in 0..count {
            let offset = r.read_u32()?;
            let raw_flags = r.read_u32()?;
            let start = raw_flags & LINE_START_MASK;
            let delta = (raw_flags >> LINE_DELTA_SHIFT) & LINE_DELTA_MAX;
            decoded.push(LineEntry {
                address: u64::from(base) + u64::from(offset),
                length: 0,
                file,
                start,
                end: start.saturating_add(delta),
            });
        }
        if has_columns {
            for _ in &decoded {
                let _start_column = r.read_u16()?;
                let _end_column = r.read_u16()?;
            }
        }
        lines.extend(decoded);
    }
    set_line_lengths(&mut lines, u64::from(base) + u64::from(code_size));
    Ok(lines)
}

fn checksum_file(checksums: &[(u32, u32)], offset: u32) -> Result<u32> {
    checksums
        .iter()
        .find_map(|(checksum_offset, file)| (*checksum_offset == offset).then_some(*file))
        .ok_or(Error::Malformed("line file checksum offset"))
}

fn set_line_lengths(lines: &mut [LineEntry], code_end: u64) {
    let mut iter = lines.iter_mut().peekable();
    while let Some(line) = iter.next() {
        line.length = iter.peek().map_or_else(
            || code_end.saturating_sub(line.address),
            |next| next.address.saturating_sub(line.address),
        );
    }
}

fn decode_symbols(payload: &[u8]) -> Result<Vec<FuncEntry>> {
    // `ByteReader` advances monotonically; malformed records fail on the checked reads below.
    let mut r = ByteReader::new(payload, Endianness::Little);
    let mut funcs = Vec::new();
    while !r.is_empty() {
        let len = usize::from(r.read_u16()?);
        if len < 2 {
            return Err(Error::Malformed("symbol record length"));
        }
        let kind = r.read_u16()?;
        let data_len = len.saturating_sub(2);
        let data = r.read_bytes(data_len)?.to_vec();
        let pad = (SUBSECTION_ALIGN - ((len + 2) % SUBSECTION_ALIGN)) % SUBSECTION_ALIGN;
        r.skip(pad)?;
        if kind == S_GPROC32 {
            funcs.push(decode_gproc32(&data)?);
        } else if kind == S_FRAMEPROC && data_len != FRAMEPROC_BYTES {
            return Err(Error::Malformed("frameproc size"));
        }
    }
    Ok(funcs)
}

fn decode_gproc32(data: &[u8]) -> Result<FuncEntry> {
    if data.len() < GPROC_FIXED_BYTES {
        return Err(Error::Malformed("gproc32 size"));
    }
    let mut r = ByteReader::new(data, Endianness::Little);
    r.skip(12)?;
    let length = u64::from(r.read_u32()?);
    r.skip(12)?;
    let address = u64::from(r.read_u32()?);
    let _segment = r.read_u16()?;
    let _flags = r.read_u8()?;
    let name = read_c_string(data, r.position())?;
    Ok(FuncEntry {
        address,
        length,
        name,
    })
}

fn read_c_string(bytes: &[u8], offset: usize) -> Result<String> {
    let tail = bytes.get(offset..).ok_or(Error::UnexpectedEof {
        offset,
        needed: 1,
        len: bytes.len(),
    })?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated symbol name"))?;
    let raw = tail.get(0..len).ok_or(Error::Malformed("symbol name"))?;
    core::str::from_utf8(raw)
        .map(ToOwned::to_owned)
        .map_err(|_| Error::Malformed("symbol name utf8"))
}

fn u32_of_usize(value: usize, what: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn u16_of_usize(value: usize, what: &'static str) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn align4_u32(value: usize) -> Result<u32> {
    let aligned = value
        .checked_add(3)
        .map(|sum| sum & !3)
        .ok_or(Error::ValueOutOfRange("alignment"))?;
    u32_of_usize(aligned, "alignment")
}

fn u32_of_u64(value: u64, what: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn u16_of_u32(value: u32, what: &'static str) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

#[cfg(test)]
mod tests {
    use super::{
        align4_u32, collect_files, decode_symbols, line_flags, line_offset, read_c_string,
        u16_of_u32, u16_of_usize, u32_of_usize,
    };
    use crate::table::LineEntry;

    #[test]
    fn conversion_helpers_reject_unrepresentable_values() {
        assert!(line_offset(u64::from(u32::MAX) + 1).is_err());
        assert!(line_flags(0x0100_0000, 0x0100_0001).is_err());
        assert!(line_flags(1, 0x81).is_err());
        assert!(u32_of_usize(usize::MAX, "usize").is_err());
        assert!(u16_of_usize(usize::from(u16::MAX) + 1, "usize").is_err());
        assert!(u16_of_u32(u32::from(u16::MAX) + 1, "u32").is_err());
        assert!(align4_u32(usize::MAX).is_err());
    }

    #[test]
    fn duplicate_files_and_malformed_symbols_are_covered() {
        let lines = [
            LineEntry {
                file: 7,
                start: 1,
                end: 2,
                address: 0,
                length: 0,
            },
            LineEntry {
                file: 7,
                start: 2,
                end: 3,
                address: 4,
                length: 0,
            },
        ];
        let files = collect_files(&lines).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files.first().map(|file| file.file), Some(7));

        assert!(read_c_string(b"x\0", 3).is_err());
        assert!(decode_symbols(&[1, 0]).is_err());
    }
}
