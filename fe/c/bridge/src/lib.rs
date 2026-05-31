//! Lowering of the C AST into Stratum HIR.
#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

#[doc(hidden)]
pub mod alloc_prelude {
    pub use alloc::boxed::Box;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod bridge;
pub mod error;
mod expr;
mod lit;
pub mod lower;
pub mod raise;
mod stmt;
#[cfg(test)]
mod test_utils;
mod ty;

pub use bridge::CBridge;
pub use error::{Error, Result};
pub use lower::{LowerResult, lower};
pub use raise::raise;
