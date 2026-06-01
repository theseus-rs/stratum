//! Encodes and decodes a [`DebugTable`] as real DWARF v5 sections.
//!
//! The public [`encode`] blob is a tiny deterministic section package containing
//! `.debug_abbrev`, `.debug_info`, `.debug_line`, `.debug_str`, and `.debug_aranges`. The
//! section payloads are standard DWARF; function provenance lives in `DW_TAG_subprogram` DIEs
//! with `DW_AT_low_pc`, `DW_AT_high_pc`, and `DW_AT_name` (`DW_FORM_strp`).

use crate::consts::{
    ADDRESS_SIZE, DW_AT_BYTE_SIZE, DW_AT_ENCODING, DW_AT_HIGH_PC, DW_AT_LOW_PC, DW_AT_NAME,
    DW_AT_STMT_LIST, DW_AT_TYPE, DW_ATE_UNSIGNED, DW_CHILDREN_NO, DW_CHILDREN_YES, DW_FORM_ADDR,
    DW_FORM_DATA1, DW_FORM_DATA8, DW_FORM_REF4, DW_FORM_SEC_OFFSET, DW_FORM_STRING, DW_FORM_STRP,
    DW_LNCT_PATH, DW_LNE_END_SEQUENCE, DW_LNE_SET_ADDRESS, DW_LNS_ADVANCE_LINE, DW_LNS_ADVANCE_PC,
    DW_LNS_COPY, DW_LNS_EXTENDED, DW_LNS_SET_COLUMN, DW_LNS_SET_FILE, DW_TAG_BASE_TYPE,
    DW_TAG_COMPILE_UNIT, DW_TAG_SUBPROGRAM, DW_TAG_VARIABLE, DW_UT_COMPILE, DWARF_VERSION,
    OPCODE_BASE, STANDARD_OPCODE_LENGTHS,
};
use crate::table::{DebugTable, FuncEntry, LineEntry};
use stratum_oir::{ByteReader, ByteWriter, Endianness, Error, Result};

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const PACKAGE_MAGIC: &[u8] = b"STRATDWF";
const PACKAGE_VERSION: u16 = 1;
const SECTION_ABBREV: u8 = 1;
const SECTION_INFO: u8 = 2;
const SECTION_LINE: u8 = 3;
const SECTION_STR: u8 = 4;
const SECTION_ARANGES: u8 = 5;
const SECTION_COUNT: u8 = 5;

const ABBREV_CU: u64 = 1;
const ABBREV_SUBPROGRAM: u64 = 2;
const ABBREV_BASE_TYPE: u64 = 3;
const ABBREV_VARIABLE: u64 = 4;

/// Standard DWARF sections emitted by this codec.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DwarfSections {
    /// `.debug_abbrev` payload.
    pub abbrev: Vec<u8>,
    /// `.debug_info` payload.
    pub info: Vec<u8>,
    /// `.debug_line` payload.
    pub line: Vec<u8>,
    /// `.debug_str` payload.
    pub strings: Vec<u8>,
    /// `.debug_aranges` payload.
    pub aranges: Vec<u8>,
}

fn writer() -> ByteWriter {
    ByteWriter::new(Endianness::Little)
}

/// Encodes `table` into a deterministic package of standard DWARF sections.
///
/// # Errors
///
/// Returns an error if a length or offset field does not fit its DWARF32 encoding.
pub fn encode(table: &DebugTable) -> Result<Vec<u8>> {
    let sections = encode_sections(table)?;
    package_sections(&sections)
}

/// Encodes `table` into individual DWARF section payloads.
///
/// # Errors
///
/// Returns an error if a length or offset field does not fit its DWARF32 encoding.
pub fn encode_sections(table: &DebugTable) -> Result<DwarfSections> {
    let strings = StringTable::from_table(table)?;
    let debug_line = build_line(table)?;
    let debug_abbrev = build_abbrev()?;
    let debug_info = build_info(table, &strings)?;
    let debug_aranges = build_aranges(table)?;
    Ok(DwarfSections {
        abbrev: debug_abbrev,
        info: debug_info,
        line: debug_line,
        strings: strings.bytes,
        aranges: debug_aranges,
    })
}

/// Decodes a DWARF section package produced by [`encode`] into a [`DebugTable`].
///
/// # Errors
///
/// Returns an error on truncated input, malformed sections, unsupported DWARF encodings, or a
/// missing required section.
pub fn decode(bytes: &[u8]) -> Result<DebugTable> {
    let sections = unpackage_sections(bytes)?;
    decode_sections(&sections)
}

/// Decodes individual DWARF sections into a [`DebugTable`].
///
/// Function records are sourced from `DW_TAG_subprogram` DIEs in `.debug_info`; no line-program
/// trailer is accepted or required.
///
/// # Errors
///
/// Returns an error if required sections are malformed or inconsistent.
pub fn decode_sections(sections: &DwarfSections) -> Result<DebugTable> {
    let lines = decode_line(&sections.line)?;
    let funcs = decode_info(&sections.info, &sections.strings)?;
    Ok(DebugTable { lines, funcs })
}

fn package_sections(sections: &DwarfSections) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_bytes(PACKAGE_MAGIC);
    w.write_u16(PACKAGE_VERSION);
    w.write_u8(SECTION_COUNT);
    write_section(&mut w, SECTION_ABBREV, &sections.abbrev)?;
    write_section(&mut w, SECTION_INFO, &sections.info)?;
    write_section(&mut w, SECTION_LINE, &sections.line)?;
    write_section(&mut w, SECTION_STR, &sections.strings)?;
    write_section(&mut w, SECTION_ARANGES, &sections.aranges)?;
    w.finish()
}

fn write_section(w: &mut ByteWriter, id: u8, bytes: &[u8]) -> Result<()> {
    w.write_u8(id);
    w.write_u32(u32_len(bytes.len(), "section length")?);
    w.write_bytes(bytes);
    Ok(())
}

fn unpackage_sections(bytes: &[u8]) -> Result<DwarfSections> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    if r.read_bytes(PACKAGE_MAGIC.len())? != PACKAGE_MAGIC {
        return Err(Error::BadMagic);
    }
    if r.read_u16()? != PACKAGE_VERSION {
        return Err(Error::Malformed("dwarf package version"));
    }
    let count = r.read_u8()?;
    let mut sections = DwarfSections::default();
    for _ in 0..count {
        let id = r.read_u8()?;
        let len = usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("section len"))?;
        let payload = r.read_bytes(len)?.to_vec();
        match id {
            SECTION_ABBREV => sections.abbrev = payload,
            SECTION_INFO => sections.info = payload,
            SECTION_LINE => sections.line = payload,
            SECTION_STR => sections.strings = payload,
            SECTION_ARANGES => sections.aranges = payload,
            _ => return Err(Error::Malformed("unknown dwarf section")),
        }
    }
    if !r.is_empty() {
        return Err(Error::Malformed("trailing package bytes"));
    }
    if sections.abbrev.is_empty() || sections.info.is_empty() || sections.line.is_empty() {
        return Err(Error::Malformed("missing required dwarf section"));
    }
    Ok(sections)
}

struct StringTable {
    bytes: Vec<u8>,
    entries: Vec<(String, u32)>,
}

impl StringTable {
    fn from_table(table: &DebugTable) -> Result<Self> {
        let mut strings = Self {
            bytes: Vec::new(),
            entries: Vec::new(),
        };
        strings.intern("compile_unit")?;
        strings.intern("usize")?;
        strings.intern("provenance_variable")?;
        for func in &table.funcs {
            strings.intern(&func.name)?;
        }
        Ok(strings)
    }

    fn intern(&mut self, value: &str) -> Result<u32> {
        if let Some((_, offset)) = self.entries.iter().find(|(name, _)| name == value) {
            return Ok(*offset);
        }
        let offset = u32_len(self.bytes.len(), "debug_str offset")?;
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
        self.entries.push((value.to_string(), offset));
        Ok(offset)
    }

    fn offset(&self, value: &str) -> Result<u32> {
        self.entries
            .iter()
            .find_map(|(name, offset)| (name == value).then_some(*offset))
            .ok_or(Error::Malformed("missing debug string"))
    }
}

fn build_abbrev() -> Result<Vec<u8>> {
    let mut w = writer();
    abbrev_header(&mut w, ABBREV_CU, DW_TAG_COMPILE_UNIT, DW_CHILDREN_YES);
    abbrev_attr(&mut w, DW_AT_NAME, DW_FORM_STRP);
    abbrev_attr(&mut w, DW_AT_LOW_PC, DW_FORM_ADDR);
    abbrev_attr(&mut w, DW_AT_HIGH_PC, DW_FORM_DATA8);
    abbrev_attr(&mut w, DW_AT_STMT_LIST, DW_FORM_SEC_OFFSET);
    abbrev_end_attrs(&mut w);

    abbrev_header(&mut w, ABBREV_SUBPROGRAM, DW_TAG_SUBPROGRAM, DW_CHILDREN_NO);
    abbrev_attr(&mut w, DW_AT_NAME, DW_FORM_STRP);
    abbrev_attr(&mut w, DW_AT_LOW_PC, DW_FORM_ADDR);
    abbrev_attr(&mut w, DW_AT_HIGH_PC, DW_FORM_DATA8);
    abbrev_end_attrs(&mut w);

    abbrev_header(&mut w, ABBREV_BASE_TYPE, DW_TAG_BASE_TYPE, DW_CHILDREN_NO);
    abbrev_attr(&mut w, DW_AT_NAME, DW_FORM_STRP);
    abbrev_attr(&mut w, DW_AT_ENCODING, DW_FORM_DATA1);
    abbrev_attr(&mut w, DW_AT_BYTE_SIZE, DW_FORM_DATA1);
    abbrev_end_attrs(&mut w);

    abbrev_header(&mut w, ABBREV_VARIABLE, DW_TAG_VARIABLE, DW_CHILDREN_NO);
    abbrev_attr(&mut w, DW_AT_NAME, DW_FORM_STRP);
    abbrev_attr(&mut w, DW_AT_TYPE, DW_FORM_REF4);
    abbrev_end_attrs(&mut w);

    w.write_uleb128(0);
    w.finish()
}

fn abbrev_header(w: &mut ByteWriter, code: u64, tag: u64, children: u8) {
    w.write_uleb128(code);
    w.write_uleb128(tag);
    w.write_u8(children);
}

fn abbrev_attr(w: &mut ByteWriter, name: u64, form: u64) {
    w.write_uleb128(name);
    w.write_uleb128(form);
}

fn abbrev_end_attrs(w: &mut ByteWriter) {
    w.write_uleb128(0);
    w.write_uleb128(0);
}

fn build_info(table: &DebugTable, strings: &StringTable) -> Result<Vec<u8>> {
    let (low_pc, high_pc) = address_bounds(table);
    let mut body = writer();
    body.write_u16(DWARF_VERSION);
    body.write_u8(DW_UT_COMPILE);
    body.write_u8(ADDRESS_SIZE);
    body.write_u32(0); // abbrev offset

    body.write_uleb128(ABBREV_CU);
    body.write_u32(strings.offset("compile_unit")?);
    body.write_u64(low_pc);
    body.write_u64(high_pc.saturating_sub(low_pc));
    body.write_u32(0); // `.debug_line` section offset

    let base_type_offset = u32_len(body.position().saturating_add(4), "base type offset")?;
    body.write_uleb128(ABBREV_BASE_TYPE);
    body.write_u32(strings.offset("usize")?);
    body.write_u8(DW_ATE_UNSIGNED);
    body.write_u8(ADDRESS_SIZE);

    body.write_uleb128(ABBREV_VARIABLE);
    body.write_u32(strings.offset("provenance_variable")?);
    body.write_u32(base_type_offset);

    for func in &table.funcs {
        body.write_uleb128(ABBREV_SUBPROGRAM);
        body.write_u32(strings.offset(&func.name)?);
        body.write_u64(func.address);
        body.write_u64(func.length);
    }
    body.write_uleb128(0); // end CU children

    let body = body.finish()?;
    let mut w = writer();
    w.write_u32(u32_len(body.len(), "debug_info length")?);
    w.write_bytes(&body);
    w.finish()
}

fn address_bounds(table: &DebugTable) -> (u64, u64) {
    let line_ranges = table
        .lines
        .iter()
        .map(|line| (line.address, line.address.saturating_add(line.length)));
    let func_ranges = table
        .funcs
        .iter()
        .map(|func| (func.address, func.address.saturating_add(func.length)));
    let mut ranges = line_ranges.chain(func_ranges);
    let Some((first_low, first_high)) = ranges.next() else {
        return (0, 0);
    };
    ranges.fold(
        (first_low, first_high),
        |(low, high), (range_low, range_high)| (low.min(range_low), high.max(range_high)),
    )
}

fn build_line(table: &DebugTable) -> Result<Vec<u8>> {
    let prologue = build_line_prologue(table)?;
    let program = build_line_program(table)?;
    let header_length = u32_len(prologue.len(), "dwarf line header")?;
    let body_len = 2_usize
        .saturating_add(1)
        .saturating_add(1)
        .saturating_add(4)
        .saturating_add(prologue.len())
        .saturating_add(program.len());
    let unit_length = u32_len(body_len, "dwarf line unit length")?;

    let mut w = writer();
    w.write_u32(unit_length);
    w.write_u16(DWARF_VERSION);
    w.write_u8(ADDRESS_SIZE);
    w.write_u8(0); // segment selector size
    w.write_u32(header_length);
    w.write_bytes(&prologue);
    w.write_bytes(&program);
    w.finish()
}

fn build_line_prologue(table: &DebugTable) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_u8(1); // minimum instruction length
    w.write_u8(1); // maximum operations per instruction
    w.write_u8(1); // default is stmt
    w.write_u8(0); // line base
    w.write_u8(1); // line range
    w.write_u8(OPCODE_BASE);
    w.write_bytes(&STANDARD_OPCODE_LENGTHS);

    w.write_u8(1); // directory entry formats
    w.write_uleb128(u64::from(DW_LNCT_PATH));
    w.write_uleb128(u64::from(DW_FORM_STRING));
    w.write_uleb128(1); // directories count
    w.write_u8(0); // empty directory name

    w.write_u8(1); // file entry formats
    w.write_uleb128(u64::from(DW_LNCT_PATH));
    w.write_uleb128(u64::from(DW_FORM_STRING));
    let nfiles = u64::from(table.max_file()).saturating_add(1);
    w.write_uleb128(nfiles);
    for file in 0..nfiles {
        write_file_name(&mut w, file);
    }
    w.finish()
}

fn write_file_name(w: &mut ByteWriter, file: u64) {
    let digits = decimal_bytes(file);
    w.write_bytes(b"file");
    w.write_bytes(&digits);
    w.write_u8(0);
}

fn decimal_bytes(mut value: u64) -> Vec<u8> {
    let mut reversed = Vec::new();
    if value == 0 {
        reversed.push(b'0');
    }
    while value != 0 {
        let digit = u8::try_from(value % 10).unwrap_or(0);
        reversed.push(b'0'.saturating_add(digit));
        value /= 10;
    }
    reversed.into_iter().rev().collect()
}

fn build_line_program(table: &DebugTable) -> Result<Vec<u8>> {
    let mut w = writer();
    for line in &table.lines {
        w.write_u8(DW_LNS_EXTENDED);
        w.write_uleb128(9); // one opcode byte plus an eight-byte address
        w.write_u8(DW_LNE_SET_ADDRESS);
        w.write_u64(line.address);

        w.write_u8(DW_LNS_SET_FILE);
        w.write_uleb128(u64::from(line.file));

        w.write_u8(DW_LNS_ADVANCE_LINE);
        w.write_sleb128(i64::from(line.start) - 1);

        w.write_u8(DW_LNS_SET_COLUMN);
        w.write_uleb128(u64::from(line.end));

        w.write_u8(DW_LNS_COPY);

        w.write_u8(DW_LNS_ADVANCE_PC);
        w.write_uleb128(line.length);

        w.write_u8(DW_LNS_EXTENDED);
        w.write_uleb128(1);
        w.write_u8(DW_LNE_END_SEQUENCE);
    }
    w.finish()
}

fn build_aranges(table: &DebugTable) -> Result<Vec<u8>> {
    let mut entries = writer();
    for func in &table.funcs {
        entries.write_u64(func.address);
        entries.write_u64(func.length);
    }
    entries.write_u64(0);
    entries.write_u64(0);
    let entries = entries.finish()?;

    let header_len = 2_usize + 4 + 1 + 1;
    let padding = (16 - (header_len % 16)) % 16;
    let body_len = header_len
        .saturating_add(padding)
        .saturating_add(entries.len());

    let mut w = writer();
    w.write_u32(u32_len(body_len, "debug_aranges length")?);
    w.write_u16(2); // `.debug_aranges` version
    w.write_u32(0); // `.debug_info` offset
    w.write_u8(ADDRESS_SIZE);
    w.write_u8(0); // segment size
    w.write_zeros(padding);
    w.write_bytes(&entries);
    w.finish()
}

fn decode_line(bytes: &[u8]) -> Result<Vec<LineEntry>> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    let unit_length = usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("unit len"))?;
    let unit_end = r
        .position()
        .checked_add(unit_length)
        .ok_or(Error::Malformed("unit len overflow"))?;
    if unit_end > bytes.len() {
        return Err(Error::UnexpectedEof {
            offset: unit_end,
            needed: 0,
            len: bytes.len(),
        });
    }
    if r.read_u16()? != DWARF_VERSION {
        return Err(Error::Malformed("unsupported DWARF line version"));
    }
    if r.read_u8()? != ADDRESS_SIZE {
        return Err(Error::Malformed("unsupported address size"));
    }
    if r.read_u8()? != 0 {
        return Err(Error::Malformed("unsupported segment selector"));
    }
    let header_length =
        usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("header len"))?;
    let program_start = r
        .position()
        .checked_add(header_length)
        .ok_or(Error::Malformed("header len overflow"))?;
    if program_start > unit_end {
        return Err(Error::Malformed("line header past unit"));
    }
    r.seek(program_start)?;
    let lines = decode_line_program(&mut r, unit_end)?;
    if r.position() != unit_end {
        return Err(Error::Malformed("line program length"));
    }
    Ok(lines)
}

#[derive(Debug, Clone, Copy)]
struct Registers {
    address: u64,
    file: u32,
    line: i64,
    column: u32,
}

impl Registers {
    const fn reset() -> Self {
        Self {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
        }
    }
}

fn decode_line_program(r: &mut ByteReader<'_>, unit_end: usize) -> Result<Vec<LineEntry>> {
    let mut lines = Vec::new();
    let mut regs = Registers::reset();
    let mut pending: Option<LineEntry> = None;

    while r.position() < unit_end {
        let opcode = r.read_u8()?;
        match opcode {
            DW_LNS_EXTENDED => {
                decode_extended_line(r, unit_end, &mut regs, &mut pending, &mut lines)?;
            }
            DW_LNS_COPY => {
                pending = Some(LineEntry {
                    address: regs.address,
                    length: 0,
                    file: regs.file,
                    start: u32::try_from(regs.line.max(0))
                        .map_err(|_| Error::Malformed("line value"))?,
                    end: regs.column,
                });
            }
            DW_LNS_ADVANCE_PC => regs.address = regs.address.saturating_add(r.read_uleb128()?),
            DW_LNS_ADVANCE_LINE => regs.line = regs.line.saturating_add(r.read_sleb128()?),
            DW_LNS_SET_FILE => {
                regs.file =
                    u32::try_from(r.read_uleb128()?).map_err(|_| Error::Malformed("file index"))?;
            }
            DW_LNS_SET_COLUMN => {
                regs.column =
                    u32::try_from(r.read_uleb128()?).map_err(|_| Error::Malformed("column"))?;
            }
            _ => return Err(Error::Malformed("unexpected line opcode")),
        }
    }
    Ok(lines)
}

fn decode_extended_line(
    r: &mut ByteReader<'_>,
    unit_end: usize,
    regs: &mut Registers,
    pending: &mut Option<LineEntry>,
    lines: &mut Vec<LineEntry>,
) -> Result<()> {
    let len = usize::try_from(r.read_uleb128()?).map_err(|_| Error::Malformed("ext len"))?;
    let ext_end = r
        .position()
        .checked_add(len)
        .ok_or(Error::Malformed("ext len overflow"))?;
    if ext_end > unit_end || len == 0 {
        return Err(Error::Malformed("bad extended opcode length"));
    }
    let sub = r.read_u8()?;
    match sub {
        DW_LNE_SET_ADDRESS => {
            if len != 9 {
                return Err(Error::Malformed("bad set_address length"));
            }
            regs.address = r.read_u64()?;
        }
        DW_LNE_END_SEQUENCE => {
            if len != 1 {
                return Err(Error::Malformed("bad end_sequence length"));
            }
            if let Some(mut entry) = pending.take() {
                entry.length = regs.address.saturating_sub(entry.address);
                lines.push(entry);
            }
            *regs = Registers::reset();
        }
        _ => r.seek(ext_end)?,
    }
    // The opcode arms above either validate a fixed payload length before reading it or
    // seek directly to `ext_end`, so a post-match length mismatch is unreachable.
    Ok(())
}

fn decode_info(info: &[u8], strings: &[u8]) -> Result<Vec<FuncEntry>> {
    let mut r = ByteReader::new(info, Endianness::Little);
    let unit_length = usize::try_from(r.read_u32()?).map_err(|_| Error::Malformed("info len"))?;
    let unit_end = r
        .position()
        .checked_add(unit_length)
        .ok_or(Error::Malformed("info len overflow"))?;
    if unit_end > info.len() {
        return Err(Error::UnexpectedEof {
            offset: unit_end,
            needed: 0,
            len: info.len(),
        });
    }
    if r.read_u16()? != DWARF_VERSION {
        return Err(Error::Malformed("unsupported DWARF info version"));
    }
    if r.read_u8()? != DW_UT_COMPILE {
        return Err(Error::Malformed("unsupported unit type"));
    }
    if r.read_u8()? != ADDRESS_SIZE {
        return Err(Error::Malformed("unsupported info address size"));
    }
    if r.read_u32()? != 0 {
        return Err(Error::Malformed("unsupported abbrev offset"));
    }

    if r.read_uleb128()? != ABBREV_CU {
        return Err(Error::Malformed("missing compile unit DIE"));
    }
    r.skip(4)?; // name
    r.skip(8)?; // low pc
    r.skip(8)?; // high pc length
    r.skip(4)?; // stmt list

    let mut funcs = Vec::new();
    while r.position() < unit_end {
        let code = r.read_uleb128()?;
        match code {
            0 => break,
            ABBREV_BASE_TYPE => {
                r.skip(4)?;
                r.skip(1)?;
                r.skip(1)?;
            }
            ABBREV_VARIABLE => {
                r.skip(4)?;
                r.skip(4)?;
            }
            ABBREV_SUBPROGRAM => {
                let name_offset = r.read_u32()?;
                let address = r.read_u64()?;
                let length = r.read_u64()?;
                funcs.push(FuncEntry {
                    address,
                    length,
                    name: read_strp(strings, name_offset)?,
                });
            }
            _ => return Err(Error::Malformed("unknown DIE abbreviation")),
        }
    }
    if r.position() > unit_end {
        return Err(Error::Malformed("DIE past unit"));
    }
    Ok(funcs)
}

fn read_strp(strings: &[u8], offset: u32) -> Result<String> {
    let start = usize::try_from(offset).map_err(|_| Error::Malformed("strp offset"))?;
    let tail = strings.get(start..).ok_or(Error::UnexpectedEof {
        offset: start,
        needed: 1,
        len: strings.len(),
    })?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated debug string"))?;
    let raw = tail
        .get(..len)
        .ok_or(Error::Malformed("debug string slice"))?;
    String::from_utf8(raw.to_vec()).map_err(|_| Error::Malformed("utf8 debug string"))
}

fn u32_len(value: usize, what: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

#[cfg(test)]
mod tests {
    use super::u32_len;

    #[test]
    fn u32_len_rejects_values_that_do_not_fit() {
        assert!(u32_len(usize::MAX, "length").is_err());
    }
}
