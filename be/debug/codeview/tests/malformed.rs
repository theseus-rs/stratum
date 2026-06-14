use stratum_codeview::{DebugTable, FuncEntry, LineEntry, decode, encode};
use stratum_oir::{ByteWriter, Endianness, Error, Result};

const CV_SIGNATURE_C13: u32 = 4;
const DEBUG_S_SYMBOLS: u32 = 0xF1;
const DEBUG_S_LINES: u32 = 0xF2;
const DEBUG_S_STRINGTABLE: u32 = 0xF3;
const DEBUG_S_FILECHKSMS: u32 = 0xF4;
const LF_HAVE_COLUMNS: u16 = 1;
const S_FRAMEPROC: u16 = 0x1012;
const S_GPROC32: u16 = 0x1110;

fn empty_c13() -> ByteWriter {
    let mut bytes = ByteWriter::new(Endianness::Little);
    bytes.write_u32(CV_SIGNATURE_C13);
    bytes
}

fn emit_subsection(writer: &mut ByteWriter, kind: u32, payload: &[u8]) -> Result<()> {
    writer.write_u32(kind);
    writer.write_u32(
        u32::try_from(payload.len()).map_err(|_| Error::ValueOutOfRange("payload length"))?,
    );
    writer.write_bytes(payload);
    writer.align_to(4);
    Ok(())
}

fn finish(writer: ByteWriter) -> Result<Vec<u8>> {
    writer.finish()
}

fn strings_payload(text: &[u8]) -> Result<Vec<u8>> {
    let mut strings = ByteWriter::new(Endianness::Little);
    strings.write_u8(0);
    strings.write_bytes(text);
    strings.write_u8(0);
    finish(strings)
}

fn checksum_payload(string_offset: u32) -> Result<Vec<u8>> {
    let mut checksums = ByteWriter::new(Endianness::Little);
    checksums.write_u32(string_offset);
    checksums.write_u8(0);
    checksums.write_u8(0);
    checksums.align_to(4);
    finish(checksums)
}

fn line_payload(flags: u16, count: u32, block_size: u32) -> Result<Vec<u8>> {
    let mut lines = ByteWriter::new(Endianness::Little);
    lines.write_u32(0x1000);
    lines.write_u16(1);
    lines.write_u16(flags);
    lines.write_u32(4);
    lines.write_u32(0);
    lines.write_u32(count);
    lines.write_u32(block_size);
    if count != 0 {
        lines.write_u32(0);
        lines.write_u32(0x8000_0001);
        if flags & LF_HAVE_COLUMNS != 0 {
            lines.write_u16(1);
            lines.write_u16(1);
        }
    }
    finish(lines)
}

fn codeview_with_sections(sections: &[(u32, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut bytes = empty_c13();
    for (kind, payload) in sections {
        emit_subsection(&mut bytes, *kind, payload)?;
    }
    finish(bytes)
}

#[test]
fn decode_rejects_bad_signature_and_trailing_header() {
    assert!(matches!(decode(&[]), Err(Error::UnexpectedEof { .. })));

    let mut bad_magic = ByteWriter::new(Endianness::Little);
    bad_magic.write_u32(0);
    assert!(matches!(
        decode(&finish(bad_magic).unwrap()),
        Err(Error::BadMagic)
    ));

    let mut trailing = empty_c13();
    trailing.write_u32(DEBUG_S_LINES);
    assert!(decode(&finish(trailing).unwrap()).is_err());
}

#[test]
fn debug_table_reports_empty_only_without_rows() {
    assert!(DebugTable::new().is_empty());

    let table = DebugTable {
        lines: vec![LineEntry {
            address: 0,
            length: 1,
            file: 0,
            start: 1,
            end: 2,
        }],
        funcs: Vec::new(),
    };
    assert!(!table.is_empty());
}

#[test]
fn encode_rejects_out_of_range_line_offset() {
    let table = DebugTable {
        lines: vec![LineEntry {
            address: u64::from(u32::MAX) + 1,
            length: 1,
            file: 0,
            start: 1,
            end: 2,
        }],
        funcs: Vec::new(),
    };

    assert!(encode(&table).is_err());
}

#[test]
fn encode_rejects_out_of_range_line_start() {
    let table = DebugTable {
        lines: vec![LineEntry {
            address: 0,
            length: 1,
            file: 0,
            start: 0x0100_0000,
            end: 0x0100_0001,
        }],
        funcs: Vec::new(),
    };

    assert!(encode(&table).is_err());
}

#[test]
fn encode_rejects_out_of_range_line_delta() {
    let table = DebugTable {
        lines: vec![LineEntry {
            address: 0,
            length: 1,
            file: 0,
            start: 1,
            end: 0x81,
        }],
        funcs: Vec::new(),
    };

    assert!(encode(&table).is_err());
}

#[test]
fn encode_round_trips_duplicate_file_rows() {
    let table = DebugTable {
        lines: vec![
            LineEntry {
                address: 0,
                length: 4,
                file: 7,
                start: 1,
                end: 2,
            },
            LineEntry {
                address: 4,
                length: 3,
                file: 7,
                start: 2,
                end: 3,
            },
        ],
        funcs: Vec::new(),
    };

    let decoded = decode(&encode(&table).unwrap()).unwrap();

    assert_eq!(decoded, table);
}

#[test]
fn decode_ignores_unknown_subsections() {
    let bytes = codeview_with_sections(&[(0xFFFF, Vec::new())]).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert!(decoded.is_empty());
}

#[test]
fn decode_rejects_bad_line_block_size() {
    let bytes = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, strings_payload(b"file:0").unwrap()),
        (DEBUG_S_FILECHKSMS, checksum_payload(1).unwrap()),
        (DEBUG_S_LINES, line_payload(LF_HAVE_COLUMNS, 1, 23).unwrap()),
    ])
    .unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_accepts_empty_column_line_block() {
    let bytes = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, strings_payload(b"file:0").unwrap()),
        (DEBUG_S_FILECHKSMS, checksum_payload(1).unwrap()),
        (DEBUG_S_LINES, line_payload(LF_HAVE_COLUMNS, 0, 12).unwrap()),
    ])
    .unwrap();

    let decoded = decode(&bytes).unwrap();
    assert!(decoded.lines.is_empty());
}

#[test]
fn decode_accepts_line_block_without_columns() {
    let bytes = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, strings_payload(b"file:0").unwrap()),
        (DEBUG_S_FILECHKSMS, checksum_payload(1).unwrap()),
        (DEBUG_S_LINES, line_payload(0, 1, 20).unwrap()),
    ])
    .unwrap();

    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.lines.len(), 1);
}

#[test]
fn decode_rejects_wrong_frameproc_size() {
    let mut symbols = ByteWriter::new(Endianness::Little);
    symbols.write_u16(2);
    symbols.write_u16(S_FRAMEPROC);
    symbols.align_to(4);
    let bytes = codeview_with_sections(&[(DEBUG_S_SYMBOLS, finish(symbols).unwrap())]).unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_rejects_short_gproc32_record() {
    let mut symbols = ByteWriter::new(Endianness::Little);
    symbols.write_u16(2 + 34);
    symbols.write_u16(S_GPROC32);
    symbols.write_zeros(34);
    symbols.align_to(4);
    let bytes = codeview_with_sections(&[(DEBUG_S_SYMBOLS, finish(symbols).unwrap())]).unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_rejects_unterminated_symbol_name() {
    let mut payload = ByteWriter::new(Endianness::Little);
    payload.write_zeros(12);
    payload.write_u32(1);
    payload.write_zeros(12);
    payload.write_u32(0x1000);
    payload.write_u16(1);
    payload.write_u8(0);
    payload.write_bytes(b"main");

    let data = finish(payload).unwrap();
    let mut symbols = ByteWriter::new(Endianness::Little);
    symbols.write_u16(u16::try_from(data.len() + 2).unwrap());
    symbols.write_u16(S_GPROC32);
    symbols.write_bytes(&data);
    symbols.align_to(4);
    let bytes = codeview_with_sections(&[(DEBUG_S_SYMBOLS, finish(symbols).unwrap())]).unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_rejects_invalid_utf8_symbol_name() {
    let mut payload = ByteWriter::new(Endianness::Little);
    payload.write_zeros(12);
    payload.write_u32(1);
    payload.write_zeros(12);
    payload.write_u32(0x1000);
    payload.write_u16(1);
    payload.write_u8(0);
    payload.write_bytes(&[0xff, 0]);

    let data = finish(payload).unwrap();
    let mut symbols = ByteWriter::new(Endianness::Little);
    symbols.write_u16(u16::try_from(data.len() + 2).unwrap());
    symbols.write_u16(S_GPROC32);
    symbols.write_bytes(&data);
    symbols.align_to(4);
    let bytes = codeview_with_sections(&[(DEBUG_S_SYMBOLS, finish(symbols).unwrap())]).unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_rejects_missing_string_table_entry() {
    let bytes = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, vec![0]),
        (DEBUG_S_FILECHKSMS, checksum_payload(2).unwrap()),
    ])
    .unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_rejects_invalid_utf8_string_table_entry() {
    let bytes = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, strings_payload(&[0xff]).unwrap()),
        (DEBUG_S_FILECHKSMS, checksum_payload(1).unwrap()),
    ])
    .unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_rejects_bad_string_table_entry() {
    let bytes = codeview_with_sections(&[
        (DEBUG_S_STRINGTABLE, strings_payload(b"path:0").unwrap()),
        (DEBUG_S_FILECHKSMS, checksum_payload(1).unwrap()),
    ])
    .unwrap();

    assert!(decode(&bytes).is_err());
}

#[test]
fn encode_rejects_out_of_range_function_address() {
    let table = DebugTable {
        lines: Vec::new(),
        funcs: vec![FuncEntry {
            address: u64::from(u32::MAX) + 1,
            length: 1,
            name: String::from("main"),
        }],
    };

    assert!(encode(&table).is_err());
}
