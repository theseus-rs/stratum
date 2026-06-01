//! Neutral debug information: the seam that surfaces machine addresses back to source.
//!
//! [`DebugInfo`] holds a table of [`LineRecord`]s, each mapping a half-open machine address
//! range to a source [`Span`]. This is the format-independent currency that DWARF
//! (ELF/Mach-O/Wasm) and `CodeView` (PE) encode to and decode from, and it is what lets a
//! disassembly or a lifted image point back at HIR/Source. Variable, type, and scope
//! information is intentionally omitted until the MIR/LIR/codegen stages exist to populate
//! it meaningfully.

use crate::alloc_prelude::*;
use stratum_diagnostics::Span;

/// Associates a contiguous run of machine addresses with the source location that produced
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRecord {
    /// Inclusive start address.
    pub address: u64,
    /// Length of the address run in bytes.
    pub length: u64,
    /// Source span the run was lowered from.
    pub span: Span,
}

impl LineRecord {
    /// The exclusive end address of the run.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.address.saturating_add(self.length)
    }

    /// Returns `true` if `address` falls within this record's range.
    #[must_use]
    pub const fn contains(self, address: u64) -> bool {
        address >= self.address && address < self.end()
    }
}

/// A symbolic function entry, pairing a name with its code range, for compile-unit metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionRecord {
    /// Interned function name.
    pub name: stratum_arena::Symbol,
    /// Entry address.
    pub address: u64,
    /// Code length in bytes.
    pub length: u64,
}

/// The neutral debug table attached to an [`ObjectModule`](crate::ObjectModule).
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    lines: Vec<LineRecord>,
    functions: Vec<FunctionRecord>,
}

impl DebugInfo {
    /// Creates an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a line mapping.
    pub fn add_line(&mut self, record: LineRecord) {
        self.lines.push(record);
    }

    /// Records a function entry.
    pub fn add_function(&mut self, record: FunctionRecord) {
        self.functions.push(record);
    }

    /// The line records, in insertion order.
    #[must_use]
    pub fn lines(&self) -> &[LineRecord] {
        &self.lines
    }

    /// The function records, in insertion order.
    #[must_use]
    pub fn functions(&self) -> &[FunctionRecord] {
        &self.functions
    }

    /// Returns `true` if there is no debug information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty() && self.functions.is_empty()
    }

    /// Finds the source span mapped to `address`, if any.
    #[must_use]
    pub fn span_at(&self, address: u64) -> Option<Span> {
        self.lines
            .iter()
            .find_map(|record| record.contains(address).then_some(record.span))
    }
}

#[cfg(test)]
mod tests {
    use super::{DebugInfo, LineRecord};
    use stratum_diagnostics::{FileId, Span};

    fn span(start: u32, end: u32) -> Span {
        Span::new(FileId::from_raw(0), start, end)
    }

    #[test]
    fn line_record_range_math() {
        let record = LineRecord {
            address: 0x1000,
            length: 4,
            span: span(0, 1),
        };
        assert_eq!(record.end(), 0x1004);
        assert!(record.contains(0x1000));
        assert!(record.contains(0x1003));
        assert!(!record.contains(0x1004));
    }

    #[test]
    fn span_lookup_by_address() {
        let mut debug = DebugInfo::new();
        assert!(debug.is_empty());
        debug.add_line(LineRecord {
            address: 0x1000,
            length: 4,
            span: span(0, 3),
        });
        debug.add_line(LineRecord {
            address: 0x1004,
            length: 4,
            span: span(3, 6),
        });
        assert_eq!(debug.span_at(0x1002), Some(span(0, 3)));
        assert_eq!(debug.span_at(0x1005), Some(span(3, 6)));
        assert_eq!(debug.span_at(0x2000), None);
        assert_eq!(debug.lines().len(), 2);
        assert!(!debug.is_empty());
    }
}
