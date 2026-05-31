#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

#[doc(hidden)]
pub mod alloc_prelude {
    pub use alloc::boxed::Box;
    pub use alloc::format;
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

mod analyze;
mod symbol;

pub use analyze::{SemaResult, analyze};
pub use symbol::{SymbolInfo, SymbolKind, SymbolTable};

#[cfg(test)]
mod tests;
