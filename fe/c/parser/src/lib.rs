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

mod decl;
mod error;
mod expr;
mod finalize;
mod parser;
mod stmt;

pub use error::{Error, Result};
pub use finalize::{FinalizeResult, finalize};
pub use parser::{ParseResult, parse};

#[cfg(test)]
mod tests;
