use stratum_dwarf::{
    DebugTable, DwarfSections, FuncEntry, LineEntry, decode, decode_sections, encode,
    encode_sections,
};
use stratum_oir::{Error, Result};

const MAGIC: &[u8] = b"STRATDWF";
const VERSION: u16 = 1;
#[test]
fn debug_table_empty_reports_both_states() {
    assert!(DebugTable::new().is_empty());
    assert!(!sample_table().is_empty());
}

#[test]
fn string_table_deduplicates_repeated_names() {
    let table = DebugTable {
        lines: Vec::new(),
        funcs: vec![FuncEntry {
            address: 0x1000,
            length: 0x10,
            name: "usize".to_owned(),
        }],
    };

    let sections = encode_sections(&table).unwrap();
    assert_eq!(decode_sections(&sections).unwrap(), table);
}

#[test]
fn packaged_decode_rejects_bad_magic() {
    assert!(decode(b"NOTMAGIC").is_err());
}

#[test]
fn packaged_decode_rejects_bad_version() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    write_u16(&mut bytes, VERSION.saturating_add(1));
    bytes.push(0);

    assert!(decode(&bytes).is_err());
}

#[test]
fn packaged_decode_rejects_unknown_section_id() {
    let bytes = package(&[(0xff, Vec::new())]).unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn packaged_decode_rejects_trailing_bytes() {
    let mut bytes = encode(&sample_table()).unwrap();
    bytes.push(0xaa);

    assert!(decode(&bytes).is_err());
}

#[test]
fn packaged_decode_rejects_missing_required_sections() {
    let bytes = package(&[]).unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn line_decode_rejects_unit_past_section_end() {
    let mut sections = base_sections().unwrap();
    sections.line = line_unit(u32::MAX, 0, &[]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_wrong_version() {
    let mut sections = base_sections().unwrap();
    patch(&mut sections.line, 4, &4_u16.to_le_bytes()).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_wrong_address_size() {
    let mut sections = base_sections().unwrap();
    let address_size = sections.line.get_mut(6).unwrap();
    *address_size = 4;

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_segment_selector() {
    let mut sections = base_sections().unwrap();
    let segment_selector = sections.line.get_mut(7).unwrap();
    *segment_selector = 1;

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_header_past_unit() {
    let mut sections = base_sections().unwrap();
    sections.line = line_unit(8, 1, &[]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_program_that_runs_past_unit() {
    let mut sections = base_sections().unwrap();
    sections.line = line_unit(9, 0, &[4, 1]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_unknown_standard_opcode() {
    let mut sections = base_sections().unwrap();
    sections.line = line_section(&[6]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_zero_length_extended_opcode() {
    let mut sections = base_sections().unwrap();
    sections.line = line_section(&[0, 0]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_extended_opcode_past_unit() {
    let mut sections = base_sections().unwrap();
    sections.line = line_unit(10, 0, &[0, 2, 1]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_bad_set_address_length() {
    let mut sections = base_sections().unwrap();
    sections.line = line_section(&[0, 1, 2]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_rejects_bad_end_sequence_length() {
    let mut sections = base_sections().unwrap();
    sections.line = line_section(&[0, 2, 1, 0]).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn line_decode_accepts_unknown_extended_opcode_by_skipping_it() {
    let mut sections = base_sections().unwrap();
    sections.line = line_section(&[0, 2, 0x7f, 0xaa]).unwrap();

    let decoded = decode_sections(&sections).unwrap();
    assert_eq!(decoded, DebugTable::new());
}

#[test]
fn line_decode_accepts_end_sequence_without_pending_row() {
    let mut sections = base_sections().unwrap();
    sections.line = line_section(&[0, 1, 1]).unwrap();

    let decoded = decode_sections(&sections).unwrap();
    assert_eq!(decoded, DebugTable::new());
}

#[test]
fn line_decode_materializes_pending_row_on_end_sequence() {
    let table = DebugTable {
        lines: vec![LineEntry {
            address: 0x1234,
            length: 7,
            file: 2,
            start: 5,
            end: 9,
        }],
        funcs: Vec::new(),
    };
    let sections = encode_sections(&table).unwrap();

    assert_eq!(decode_sections(&sections).unwrap(), table);
}

#[test]
fn info_decode_rejects_unit_past_section_end() {
    let mut sections = base_sections().unwrap();
    patch(&mut sections.info, 0, &u32::MAX.to_le_bytes()).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_wrong_version() {
    let mut sections = base_sections().unwrap();
    patch(&mut sections.info, 4, &4_u16.to_le_bytes()).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_wrong_unit_type() {
    let mut sections = base_sections().unwrap();
    let unit_type = sections.info.get_mut(6).unwrap();
    *unit_type = 0xff;

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_wrong_address_size() {
    let mut sections = base_sections().unwrap();
    let address_size = sections.info.get_mut(7).unwrap();
    *address_size = 4;

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_nonzero_abbrev_offset() {
    let mut sections = base_sections().unwrap();
    patch(&mut sections.info, 8, &1_u32.to_le_bytes()).unwrap();

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_missing_compile_unit_die() {
    let mut sections = base_sections().unwrap();
    let compile_unit_code = sections.info.get_mut(12).unwrap();
    *compile_unit_code = 0;

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_unknown_die_abbreviation() {
    let mut sections = base_sections().unwrap();
    let first_child_code = sections.info.get_mut(37).unwrap();
    *first_child_code = 0x7f;

    assert!(decode_sections(&sections).is_err());
}

#[test]
fn info_decode_rejects_die_that_runs_past_unit() {
    let mut sections = base_sections().unwrap();
    patch(&mut sections.info, 0, &34_u32.to_le_bytes()).unwrap();

    assert!(decode_sections(&sections).is_err());
}

fn sample_table() -> DebugTable {
    DebugTable {
        lines: vec![LineEntry {
            address: 0x1000,
            length: 4,
            file: 0,
            start: 1,
            end: 3,
        }],
        funcs: vec![FuncEntry {
            address: 0x1000,
            length: 4,
            name: "main".to_owned(),
        }],
    }
}

fn base_sections() -> Result<DwarfSections> {
    encode_sections(&DebugTable::new())
}

fn package(sections: &[(u8, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    write_u16(&mut bytes, VERSION);
    bytes.push(u8::try_from(sections.len()).map_err(|_| Error::ValueOutOfRange("section count"))?);
    for (id, payload) in sections {
        bytes.push(*id);
        write_u32(
            &mut bytes,
            u32::try_from(payload.len()).map_err(|_| Error::ValueOutOfRange("payload length"))?,
        );
        bytes.extend_from_slice(payload);
    }
    Ok(bytes)
}

fn line_section(program: &[u8]) -> Result<Vec<u8>> {
    let unit_length = u32::try_from(8_usize.saturating_add(program.len()))
        .map_err(|_| Error::ValueOutOfRange("line unit length"))?;
    line_unit(unit_length, 0, program)
}

fn line_unit(unit_length: u32, header_length: u32, program: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    write_u32(&mut bytes, unit_length);
    write_u16(&mut bytes, 5);
    bytes.push(8);
    bytes.push(0);
    write_u32(&mut bytes, header_length);
    let header_len =
        usize::try_from(header_length).map_err(|_| Error::ValueOutOfRange("header length"))?;
    bytes.resize(bytes.len().saturating_add(header_len), 0);
    bytes.extend_from_slice(program);
    Ok(bytes)
}

fn patch(bytes: &mut [u8], offset: usize, replacement: &[u8]) -> Option<()> {
    let end = offset.checked_add(replacement.len())?;
    let target = bytes.get_mut(offset..end)?;
    target.copy_from_slice(replacement);
    Some(())
}

fn write_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
