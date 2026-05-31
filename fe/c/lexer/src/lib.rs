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

mod error;
mod lexer;
mod token;

pub use error::{Error, Result};
pub use lexer::{LexResult, lex};
pub use token::{Keyword, PpToken, PpTokenKind, Punctuator, Token, TokenKind};

#[cfg(test)]
mod tests;
