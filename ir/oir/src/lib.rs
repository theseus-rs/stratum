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
pub use debug::{DebugInfo, FunctionRecord, LineRecord};
pub use error::{Error, Result};
pub use linkage::{Export, Import};
pub use model::{
    ObjectModule, RelocationId, Section, SectionFlags, SectionId, SectionKind, Segment,
    SymbolBinding, SymbolEntry, SymbolFlags, SymbolId, SymbolKind,
};
pub use reloc::{RelocKind, Relocation};
pub use target::{Architecture, BinaryFormat, Endianness, PtrWidth, TargetSpec};

pub use stratum_arena::Symbol;
