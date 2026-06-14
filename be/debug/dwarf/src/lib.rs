#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(test)]
extern crate std;

mod adapt;
mod codec;
mod consts;
mod table;

pub use adapt::{apply_to_object, from_object};
pub use codec::{DwarfSections, decode, decode_sections, encode, encode_sections};
pub use table::{DebugTable, FuncEntry, LineEntry};

#[cfg(test)]
mod tests {
    use super::{DebugTable, FuncEntry, LineEntry, decode, encode};

    extern crate alloc;
    use alloc::string::ToString;
    use alloc::vec;

    fn sample_table() -> DebugTable {
        DebugTable {
            lines: vec![
                LineEntry {
                    address: 0x1000,
                    length: 4,
                    file: 0,
                    start: 0,
                    end: 12,
                },
                LineEntry {
                    address: 0x1004,
                    length: 8,
                    file: 0,
                    start: 12,
                    end: 31,
                },
                LineEntry {
                    address: 0x2000,
                    length: 16,
                    file: 3,
                    start: 100,
                    end: 140,
                },
            ],
            funcs: vec![FuncEntry {
                address: 0x1000,
                length: 0x28,
                name: "_start".to_string(),
            }],
        }
    }

    #[test]
    fn round_trips_debug_table() {
        let table = sample_table();
        let bytes = encode(&table).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(table, back);
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
    fn rejects_truncated() {
        let table = sample_table();
        let bytes = encode(&table).unwrap();
        let head = bytes.get(..3).unwrap();
        assert!(decode(head).is_err());
    }
}
