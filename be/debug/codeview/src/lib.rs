#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

mod adapt;
mod codec;
mod consts;
mod table;

pub use adapt::{apply_to_object, from_object};
pub use codec::{decode, encode};
pub use table::{DebugTable, FuncEntry, LineEntry};

#[cfg(test)]
mod tests {
    use super::{DebugTable, FuncEntry, LineEntry, decode, encode};
    use crate::consts::{
        CV_SIGNATURE_C13, DEBUG_S_FILECHKSMS, DEBUG_S_LINES, DEBUG_S_STRINGTABLE, DEBUG_S_SYMBOLS,
        LF_HAVE_COLUMNS,
    };
    use stratum_oir::{ByteReader, ByteWriter, Endianness};

    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    fn sample_table() -> DebugTable {
        DebugTable {
            lines: vec![
                LineEntry {
                    address: 0x1400_1000,
                    length: 6,
                    file: 0,
                    start: 0,
                    end: 18,
                },
                LineEntry {
                    address: 0x1400_1006,
                    length: 10,
                    file: 1,
                    start: 18,
                    end: 44,
                },
            ],
            funcs: vec![FuncEntry {
                address: 0x1400_1000,
                length: 0x10,
                name: "mainCRTStartup".to_string(),
            }],
        }
    }

    #[test]
    fn round_trips_debug_table() {
        let table = sample_table();
        let bytes = encode(&table).unwrap();
        assert_eq!(decode(&bytes).unwrap(), table);
    }

    #[test]
    fn encode_is_deterministic() {
        let table = sample_table();
        assert_eq!(encode(&table).unwrap(), encode(&table).unwrap());
    }

    #[test]
    fn empty_table_round_trips() {
        let table = DebugTable::new();
        let bytes = encode(&table).unwrap();
        assert_eq!(decode(&bytes).unwrap(), table);
    }

    #[test]
    fn emits_full_c13_subsection_set() {
        let bytes = encode(&sample_table()).unwrap();
        let kinds = subsection_kinds(&bytes).unwrap();
        assert_eq!(
            kinds,
            vec![
                DEBUG_S_STRINGTABLE,
                DEBUG_S_FILECHKSMS,
                DEBUG_S_LINES,
                DEBUG_S_SYMBOLS,
            ]
        );
    }

    #[test]
    fn subsection_kinds_rejects_bad_signature() {
        assert!(subsection_kinds(&0_u32.to_le_bytes()).is_err());
    }

    #[test]
    fn rejects_bad_signature() {
        let mut bytes = encode(&sample_table()).unwrap();
        *bytes.first_mut().unwrap() = 0xFF;
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_partial_subsection_header() {
        assert!(decode(&[4, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn rejects_short_symbol_record() {
        let mut payload = ByteWriter::new(Endianness::Little);
        payload.write_u16(1);
        let mut bytes = ByteWriter::new(Endianness::Little);
        bytes.write_u32(CV_SIGNATURE_C13);
        emit_test_subsection(&mut bytes, DEBUG_S_SYMBOLS, &payload.finish().unwrap());
        assert!(decode(&bytes.finish().unwrap()).is_err());
    }

    #[test]
    fn rejects_line_checksum_offset_without_file() {
        let mut strings = ByteWriter::new(Endianness::Little);
        strings.write_u8(0);
        strings.write_bytes(b"file:0");
        strings.write_u8(0);

        let mut checksums = ByteWriter::new(Endianness::Little);
        checksums.write_u32(1);
        checksums.write_u8(0);
        checksums.write_u8(0);
        checksums.align_to(4);

        let mut lines = ByteWriter::new(Endianness::Little);
        lines.write_u32(0x1000);
        lines.write_u16(1);
        lines.write_u16(LF_HAVE_COLUMNS);
        lines.write_u32(4);
        lines.write_u32(8);
        lines.write_u32(1);
        lines.write_u32(24);
        lines.write_u32(0);
        lines.write_u32(0x8000_0001);
        lines.write_u16(1);
        lines.write_u16(1);

        let mut bytes = ByteWriter::new(Endianness::Little);
        bytes.write_u32(CV_SIGNATURE_C13);
        emit_test_subsection(&mut bytes, DEBUG_S_STRINGTABLE, &strings.finish().unwrap());
        emit_test_subsection(&mut bytes, DEBUG_S_FILECHKSMS, &checksums.finish().unwrap());
        emit_test_subsection(&mut bytes, DEBUG_S_LINES, &lines.finish().unwrap());
        assert!(decode(&bytes.finish().unwrap()).is_err());
    }

    fn subsection_kinds(bytes: &[u8]) -> stratum_oir::Result<Vec<u32>> {
        let mut reader = ByteReader::new(bytes, Endianness::Little);
        if reader.read_u32()? != CV_SIGNATURE_C13 {
            return Err(stratum_oir::Error::BadMagic);
        }
        let mut kinds = Vec::new();
        while !reader.is_empty() {
            let kind = reader.read_u32()?;
            let len = usize::try_from(reader.read_u32()?)
                .map_err(|_| stratum_oir::Error::Malformed("subsection len"))?;
            reader.skip(len)?;
            let pad = (4 - (len % 4)) % 4;
            reader.skip(pad)?;
            kinds.push(kind);
        }
        Ok(kinds)
    }

    fn emit_test_subsection(writer: &mut ByteWriter, kind: u32, payload: &[u8]) {
        writer.write_u32(kind);
        writer.write_u32(u32::try_from(payload.len()).unwrap());
        writer.write_bytes(payload);
        writer.align_to(4);
    }
}
