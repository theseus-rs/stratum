//! The neutral debug table the `CodeView` codec encodes and decodes.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

/// One machine-address range mapped to a source location (`file`, line/byte `[start, end)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineEntry {
    /// Inclusive start address of the code run.
    pub address: u64,
    /// Length of the run in bytes.
    pub length: u64,
    /// Source file index (a [`FileId`](stratum_diagnostics::FileId) raw value).
    pub file: u32,
    /// Inclusive source line/byte position within the file.
    pub start: u32,
    /// Exclusive source line/byte position within the file.
    pub end: u32,
}

/// A function entry pairing a name with its code range, for compile-unit provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncEntry {
    /// Entry address.
    pub address: u64,
    /// Code length in bytes.
    pub length: u64,
    /// Function name.
    pub name: String,
}

/// The neutral debug table: line provenance plus a function table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DebugTable {
    /// Address↔source line rows, in insertion order.
    pub lines: Vec<LineEntry>,
    /// Function entries, in insertion order.
    pub funcs: Vec<FuncEntry>,
}

impl DebugTable {
    /// Creates an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if the table carries no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.funcs.is_empty()
    }
}
