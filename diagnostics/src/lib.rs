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

mod diagnostic;
mod error;
mod source_map;
mod span;

pub use diagnostic::{Diagnostic, Label, Severity};
pub use error::{Error, Result};
pub use source_map::{FileId, LineCol, Origin, SourceFile, SourceMap};
pub use span::Span;
