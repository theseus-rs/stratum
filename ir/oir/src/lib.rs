#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

#[doc(hidden)]
pub mod alloc_prelude {
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

mod bridge;
mod bytes;
mod debug;
mod dump;
mod error;
mod linkage;
mod model;
mod reloc;
mod target;

pub use bridge::OirBridge;
pub use bytes::{ByteReader, ByteWriter};
pub use debug::{
    CompileUnitRecord, DebugField, DebugFileFormat, DebugInfo, DebugSymbolKind, DebugSymbolRecord,
    DebugTypeId, DebugTypeKind, DebugTypeRecord, DebugVariableRecord, ExternalDebugFile,
    FunctionRecord, LexicalScopeRecord, LineRecord, SourceFileRecord,
};
pub use error::{Error, Result};
pub use linkage::{Export, Import};
pub use model::{
    FormatFacts, ObjectModule, RelocationId, Section, SectionFlags, SectionId, SectionKind,
    Segment, SymbolBinding, SymbolEntry, SymbolFlags, SymbolId, SymbolKind, WasmFacts, WasmSection,
};
pub use reloc::{RelocKind, Relocation};
pub use target::{Architecture, BinaryFormat, Endianness, PtrWidth, TargetSpec};

pub use stratum_arena::Symbol;
