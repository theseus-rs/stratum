//! Neutral debug information: the seam that surfaces machine addresses back to source.
//!
//! [`DebugInfo`] holds address-to-source provenance plus optional richer debug metadata. The
//! line/function table is the stable format-independent currency that DWARF, `CodeView`, and PDB
//! codecs encode to and decode from. PDB-specific streams also need source files, compilands,
//! type records, public/global/local symbols, lexical scopes, and the PE↔PDB RSDS identity; those
//! are represented here in neutral form without forcing object codecs to understand PDB streams.

use crate::alloc_prelude::*;
use crate::{Error, Result};
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

/// Companion debug file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugFileFormat {
    /// Microsoft PDB, normally referenced by a PE/COFF RSDS `CodeView` record.
    Pdb,
    /// Unknown or format-specific debug file kind.
    Other(u32),
}

/// Identity record that lets an object locate and verify a companion debug file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalDebugFile {
    /// Companion debug file format.
    format: DebugFileFormat,
    /// Path recorded in the object file.
    path: String,
    /// Format-specific identifier bytes, such as an RSDS/PDB GUID.
    identifier: Vec<u8>,
    /// Format-specific revision, such as a PDB age.
    age: Option<u32>,
}

impl ExternalDebugFile {
    /// Creates a validated companion debug-file identity.
    ///
    /// # Errors
    ///
    /// Returns an error when a PDB identity does not contain a 16-byte GUID and an age.
    pub fn new(
        format: DebugFileFormat,
        path: String,
        identifier: Vec<u8>,
        age: Option<u32>,
    ) -> Result<Self> {
        if format == DebugFileFormat::Pdb && identifier.len() != 16 {
            return Err(Error::Malformed("PDB debug identifier must be 16 bytes"));
        }
        if format == DebugFileFormat::Pdb && age.is_none() {
            return Err(Error::Malformed("PDB debug age is missing"));
        }
        Ok(Self {
            format,
            path,
            identifier,
            age,
        })
    }

    /// Creates a PDB identity from an RSDS GUID, age, and path.
    #[must_use]
    pub fn pdb(path: String, guid: [u8; 16], age: u32) -> Self {
        Self {
            format: DebugFileFormat::Pdb,
            path,
            identifier: guid.to_vec(),
            age: Some(age),
        }
    }

    /// Companion debug-file format.
    #[must_use]
    pub const fn format(&self) -> DebugFileFormat {
        self.format
    }

    /// Path recorded in the object file.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Format-specific identifier bytes.
    #[must_use]
    pub fn identifier(&self) -> &[u8] {
        &self.identifier
    }

    /// Format-specific revision, if any.
    #[must_use]
    pub const fn age(&self) -> Option<u32> {
        self.age
    }

    /// Returns the PDB GUID when this record is a valid PDB identity.
    #[must_use]
    pub fn pdb_guid(&self) -> Option<[u8; 16]> {
        if self.format != DebugFileFormat::Pdb {
            return None;
        }
        <[u8; 16]>::try_from(self.identifier.as_slice()).ok()
    }

    /// Returns the PDB age when this record is a valid PDB identity.
    #[must_use]
    pub const fn pdb_age(&self) -> Option<u32> {
        if matches!(self.format, DebugFileFormat::Pdb) {
            self.age
        } else {
            None
        }
    }
}

/// A source file known to debug metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFileRecord {
    /// Raw source file id, normally matching [`Span::file`](stratum_diagnostics::Span::file).
    pub file: u32,
    /// Path recorded in the debug format.
    pub path: String,
    /// Format-specific checksum kind, if present.
    pub checksum_kind: u8,
    /// Checksum bytes, if present.
    pub checksum: Vec<u8>,
}

/// A compilation unit / compiland entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileUnitRecord {
    /// User-facing compiland name.
    pub name: String,
    /// Object file or module path, if known.
    pub object: String,
    /// Source file ids referenced by this compiland.
    pub files: Vec<u32>,
}

/// Stable type identifier used by debug records.
pub type DebugTypeId = u32;

/// Neutral classification for rich debug type records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugTypeKind {
    /// A primitive scalar type.
    Primitive,
    /// Pointer/reference-like type.
    Pointer,
    /// Function type.
    Function,
    /// Struct/class/union-style aggregate.
    Aggregate,
    /// Enum type.
    Enum,
    /// Array type.
    Array,
    /// Typedef or alias.
    Alias,
    /// Format-specific or currently unclassified type.
    Other(u32),
}

/// One field/member of an aggregate debug type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugField {
    /// Field name.
    pub name: String,
    /// Field type id.
    pub ty: DebugTypeId,
    /// Byte offset within the containing type.
    pub offset: u64,
}

/// A rich type record decoded from or encoded to a debug format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugTypeRecord {
    /// Format-neutral type id.
    pub id: DebugTypeId,
    /// Type classification.
    pub kind: DebugTypeKind,
    /// Display name.
    pub name: String,
    /// Size in bytes, or `0` when unknown.
    pub size: u64,
    /// Referenced type ids, interpreted by `kind`.
    pub references: Vec<DebugTypeId>,
    /// Aggregate fields.
    pub fields: Vec<DebugField>,
    /// Raw format-specific record kind for loss-checked preservation.
    pub raw_kind: u32,
    /// Raw record bytes when a codec preserves an unknown or richer record.
    pub raw: Vec<u8>,
}

/// Symbol classification used by debug metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DebugSymbolKind {
    /// Public symbol.
    Public,
    /// Global symbol.
    Global,
    /// Local symbol.
    Local,
    /// Procedure/function symbol.
    Function,
    /// Data symbol.
    Data,
    /// Unknown format-specific symbol kind.
    Other(u32),
}

/// A debug symbol record, independent from the object symbol table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugSymbolRecord {
    /// Symbol name.
    pub name: String,
    /// Symbol address or RVA.
    pub address: u64,
    /// Symbol byte length, if known.
    pub length: u64,
    /// Referenced debug type id, if present.
    pub ty: Option<DebugTypeId>,
    /// Symbol classification.
    pub kind: DebugSymbolKind,
    /// Raw format-specific record kind.
    pub raw_kind: u32,
    /// Raw symbol bytes for records not fully modeled.
    pub raw: Vec<u8>,
}

/// A local variable scoped to a lexical range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugVariableRecord {
    /// Variable name.
    pub name: String,
    /// Type id, if known.
    pub ty: Option<DebugTypeId>,
    /// Address, frame offset, or format-specific location value.
    pub location: i64,
    /// Raw format-specific location expression bytes.
    pub raw_location: Vec<u8>,
}

/// A lexical scope with local variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexicalScopeRecord {
    /// Scope id in insertion order.
    pub id: u32,
    /// Parent scope id, if nested.
    pub parent: Option<u32>,
    /// Inclusive start address.
    pub address: u64,
    /// Scope length in bytes.
    pub length: u64,
    /// Local variables declared in this scope.
    pub variables: Vec<DebugVariableRecord>,
}

/// The neutral debug table attached to an [`ObjectModule`](crate::ObjectModule).
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    lines: Vec<LineRecord>,
    functions: Vec<FunctionRecord>,
    sources: Vec<SourceFileRecord>,
    units: Vec<CompileUnitRecord>,
    types: Vec<DebugTypeRecord>,
    symbols: Vec<DebugSymbolRecord>,
    scopes: Vec<LexicalScopeRecord>,
    external_files: Vec<ExternalDebugFile>,
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

    /// Records a source file.
    pub fn add_source(&mut self, record: SourceFileRecord) {
        self.sources.push(record);
    }

    /// Records a compilation unit.
    pub fn add_compile_unit(&mut self, record: CompileUnitRecord) {
        self.units.push(record);
    }

    /// Records a rich debug type.
    pub fn add_type(&mut self, record: DebugTypeRecord) {
        self.types.push(record);
    }

    /// Records a debug symbol.
    pub fn add_symbol(&mut self, record: DebugSymbolRecord) {
        self.symbols.push(record);
    }

    /// Records a lexical scope.
    pub fn add_scope(&mut self, record: LexicalScopeRecord) {
        self.scopes.push(record);
    }

    /// Records a companion debug file identity.
    pub fn add_external_file(&mut self, file: ExternalDebugFile) {
        self.external_files.push(file);
    }

    /// Records or replaces a companion debug file identity with the same format and path.
    pub fn upsert_external_file(&mut self, file: ExternalDebugFile) {
        if let Some(existing) = self
            .external_files
            .iter_mut()
            .find(|existing| existing.format == file.format && existing.path == file.path)
        {
            *existing = file;
        } else {
            self.external_files.push(file);
        }
    }

    /// Records or replaces a companion PDB identity.
    pub fn upsert_pdb_file(&mut self, path: String, guid: [u8; 16], age: u32) {
        self.upsert_external_file(ExternalDebugFile::pdb(path, guid, age));
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

    /// Source file records, in insertion order.
    #[must_use]
    pub fn sources(&self) -> &[SourceFileRecord] {
        &self.sources
    }

    /// Compilation units, in insertion order.
    #[must_use]
    pub fn compile_units(&self) -> &[CompileUnitRecord] {
        &self.units
    }

    /// Rich debug type records, in insertion order.
    #[must_use]
    pub fn types(&self) -> &[DebugTypeRecord] {
        &self.types
    }

    /// Debug symbols, in insertion order.
    #[must_use]
    pub fn symbols(&self) -> &[DebugSymbolRecord] {
        &self.symbols
    }

    /// Lexical scopes, in insertion order.
    #[must_use]
    pub fn scopes(&self) -> &[LexicalScopeRecord] {
        &self.scopes
    }

    /// Companion debug file identities, in insertion order.
    #[must_use]
    pub fn external_files(&self) -> &[ExternalDebugFile] {
        &self.external_files
    }

    /// Returns `true` if there is no debug information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
            && self.functions.is_empty()
            && self.sources.is_empty()
            && self.units.is_empty()
            && self.types.is_empty()
            && self.symbols.is_empty()
            && self.scopes.is_empty()
            && self.external_files.is_empty()
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
    use super::{DebugFileFormat, DebugInfo, ExternalDebugFile, LineRecord};
    use crate::alloc_prelude::*;
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

    #[test]
    fn external_debug_file_validates_pdb_identity() {
        let other = ExternalDebugFile::new(
            DebugFileFormat::Other(1),
            "app.dwo".to_string(),
            vec![1, 2, 3],
            None,
        )
        .unwrap();
        assert_eq!(other.format(), DebugFileFormat::Other(1));
        assert_eq!(other.identifier(), &[1, 2, 3]);
        assert_eq!(other.age(), None);
        assert_eq!(other.pdb_guid(), None);
        assert_eq!(other.pdb_age(), None);

        assert!(
            ExternalDebugFile::new(
                DebugFileFormat::Pdb,
                "app.pdb".to_string(),
                vec![1; 15],
                Some(1),
            )
            .is_err()
        );
        assert!(
            ExternalDebugFile::new(
                DebugFileFormat::Pdb,
                "app.pdb".to_string(),
                vec![1; 16],
                None,
            )
            .is_err()
        );
        let pdb = ExternalDebugFile::pdb("app.pdb".to_string(), [2; 16], 3);
        assert_eq!(pdb.path(), "app.pdb");
        assert_eq!(pdb.pdb_guid(), Some([2; 16]));
        assert_eq!(pdb.pdb_age(), Some(3));
    }

    #[test]
    fn external_debug_file_upsert_replaces_same_format_and_path() {
        let mut debug = DebugInfo::new();
        debug.upsert_pdb_file("app.pdb".to_string(), [1; 16], 1);
        debug.upsert_pdb_file("app.pdb".to_string(), [2; 16], 2);
        debug.upsert_pdb_file("other.pdb".to_string(), [3; 16], 3);

        assert_eq!(debug.external_files().len(), 2);
        let app = debug.external_files().first().unwrap();
        assert_eq!(app.path(), "app.pdb");
        assert_eq!(app.pdb_guid(), Some([2; 16]));
        assert_eq!(app.pdb_age(), Some(2));
        let other = debug.external_files().get(1).unwrap();
        assert_eq!(other.path(), "other.pdb");
    }
}
