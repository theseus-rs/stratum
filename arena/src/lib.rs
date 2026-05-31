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

mod error;
mod id;
mod interner;
mod store;

pub use error::{Error, Result};
pub use id::Id;
pub use interner::{Interner, Symbol};
pub use store::Arena;
