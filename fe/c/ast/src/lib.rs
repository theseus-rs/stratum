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

mod dump;
mod error;
mod node;
mod ops;
mod tree;

pub use error::{Error, Result};
pub use node::{
    CNode, DeclSpecifiers, Declarator, Derivation, Designator, Enumerator, FieldDecl,
    InitDeclarator, InitItem, ParamDecl, StorageClass, TypeName, TypeQualifier, TypeSpecifier,
};
pub use ops::{AssignOp, BinaryOp, PostfixOp, UnaryOp};
pub use tree::{CAst, CNodeId};
