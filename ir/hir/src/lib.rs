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
mod context;
mod dump;
mod error;
mod node;
mod types;

pub use bridge::HirBridge;
pub use context::{HirContext, HirNodeId, HirTypeId};
pub use error::{Error, Result};
pub use node::{
    BinaryOp, DeclFlags, Designator, EnumVariant, Field, HirInit, HirNode, InitEntry, Param,
    PostfixOp, QualifiedType, RecordKind, StorageClass, UnaryOp,
};
pub use types::{HirType, IntWidth, Qualifiers, TagKind};
