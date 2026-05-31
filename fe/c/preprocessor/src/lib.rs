//! C preprocessor: includes, macros, and conditionals.

#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

#[doc(hidden)]
pub mod alloc_prelude {
    pub use alloc::collections::VecDeque;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

pub mod error;
pub mod eval;
pub mod include;
pub mod macros;
pub mod preprocessor;
pub mod util;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
#[cfg(any(test, feature = "std"))]
pub use include::FsIncludeResolver;
pub use include::{IncludeResolver, MapIncludeResolver};
pub use preprocessor::preprocess;
