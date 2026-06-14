//! In-memory PDB model used by the codec and OIR adapters.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::consts::{FEATURE_VC140, PDB_VERSION_VC70};

/// One named stream entry from the PDB stream map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedStream {
    /// Stream name.
    pub name: String,
    /// MSF stream index.
    pub stream: u32,
}

/// Basic PDB stream metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbInfo {
    /// PDB stream version.
    pub version: u32,
    /// Timestamp/signature field.
    pub signature: u32,
    /// PDB age.
    pub age: u32,
    /// PDB GUID.
    pub guid: [u8; 16],
    /// Named stream table.
    pub named_streams: Vec<NamedStream>,
    /// Feature codes.
    pub features: Vec<u32>,
    /// Path used by the companion PE `CodeView` debug directory.
    pub path: String,
}

impl Default for PdbInfo {
    fn default() -> Self {
        Self {
            version: PDB_VERSION_VC70,
            signature: 0,
            age: 1,
            guid: [0; 16],
            named_streams: Vec::new(),
            features: alloc::vec![FEATURE_VC140],
            path: "stratum.pdb".into(),
        }
    }
}

/// Type classification used by PDB type streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdbTypeKind {
    /// Primitive scalar.
    Primitive,
    /// Pointer or reference.
    Pointer,
    /// Function type.
    Function,
    /// Class/struct/union.
    Aggregate,
    /// Enum.
    Enum,
    /// Array.
    Array,
    /// Typedef/alias.
    Alias,
    /// Unknown `CodeView` type kind.
    Other(u32),
}

/// One field/member carried by a PDB aggregate type record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbFieldRecord {
    /// Field name.
    pub name: String,
    /// Field type index.
    pub type_index: u32,
    /// Byte offset within the containing type.
    pub offset: u64,
}

/// One PDB TPI/IPI type record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbTypeRecord {
    /// `CodeView` type index.
    pub index: u32,
    /// `CodeView` leaf kind.
    pub raw_kind: u16,
    /// Neutral kind.
    pub kind: PdbTypeKind,
    /// Display name.
    pub name: String,
    /// Size in bytes, when known.
    pub size: u64,
    /// Referenced type indexes.
    pub references: Vec<u32>,
    /// Aggregate fields.
    pub fields: Vec<PdbFieldRecord>,
    /// Raw record payload for loss preservation.
    pub raw: Vec<u8>,
}

/// Symbol classification used by PDB symbol streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdbSymbolKind {
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
    /// Unknown `CodeView` symbol kind.
    Other(u32),
}

/// One `CodeView` symbol record carried by a module, public, or global stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSymbolRecord {
    /// `CodeView` symbol kind.
    pub raw_kind: u16,
    /// Neutral kind.
    pub kind: PdbSymbolKind,
    /// Symbol name.
    pub name: String,
    /// RVA/address.
    pub address: u64,
    /// Byte length, when known.
    pub length: u64,
    /// Referenced type index, when present.
    pub type_index: Option<u32>,
    /// Raw payload for loss preservation.
    pub raw: Vec<u8>,
}

/// One address-to-source line record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PdbLineRecord {
    /// RVA/address.
    pub address: u64,
    /// Byte length.
    pub length: u64,
    /// Source file id.
    pub file: u32,
    /// Source start offset.
    pub start: u32,
    /// Source end offset.
    pub end: u32,
}

/// One source file referenced by a PDB module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbSourceRecord {
    /// Source file id used by line records.
    pub file: u32,
    /// Source path.
    pub path: String,
    /// Checksum kind, if present.
    pub checksum_kind: u8,
    /// Checksum bytes, if present.
    pub checksum: Vec<u8>,
}

/// A local variable scoped to a PDB lexical range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbVariableRecord {
    /// Variable name.
    pub name: String,
    /// Type index, when known.
    pub type_index: Option<u32>,
    /// Address, frame offset, or format-specific location value.
    pub location: i64,
    /// Raw format-specific location expression bytes.
    pub raw_location: Vec<u8>,
}

/// One lexical scope within a PDB module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbScopeRecord {
    /// Scope id in insertion order.
    pub id: u32,
    /// Parent scope id, if nested.
    pub parent: Option<u32>,
    /// Inclusive start address.
    pub address: u64,
    /// Scope length in bytes.
    pub length: u64,
    /// Local variables declared in this scope.
    pub variables: Vec<PdbVariableRecord>,
}

/// One module/compiland stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbModule {
    /// Module/compiland name.
    pub name: String,
    /// Object file path/name.
    pub object: String,
    /// Source file paths.
    pub sources: Vec<PdbSourceRecord>,
    /// Line records.
    pub lines: Vec<PdbLineRecord>,
    /// Module-local symbol records.
    pub symbols: Vec<PdbSymbolRecord>,
    /// Lexical scopes.
    pub scopes: Vec<PdbScopeRecord>,
    /// MSF stream index. The writer updates this during layout.
    pub stream: u32,
}

/// Raw stream preservation entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PdbRawStream {
    /// MSF stream index.
    pub index: u32,
    /// Optional stream name.
    pub name: Option<String>,
    /// Stream bytes.
    pub data: Vec<u8>,
}

/// Full PDB model.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PdbFile {
    /// PDB stream metadata.
    pub info: PdbInfo,
    /// TPI records.
    pub types: Vec<PdbTypeRecord>,
    /// IPI records.
    pub ids: Vec<PdbTypeRecord>,
    /// Module streams.
    pub modules: Vec<PdbModule>,
    /// Global symbol records.
    pub globals: Vec<PdbSymbolRecord>,
    /// Public symbol records.
    pub publics: Vec<PdbSymbolRecord>,
    /// Preserved unknown streams.
    pub raw_streams: Vec<PdbRawStream>,
}
