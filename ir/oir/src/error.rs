//! Error type shared across the object model and its codecs.

use core::fmt;

/// Errors produced while building, reading, or writing an [`ObjectModule`](crate::ObjectModule).
#[derive(Debug)]
pub enum Error {
    /// An underlying arena or interner reached its capacity.
    Arena(stratum_arena::Error),
    /// A reader ran past the end of its buffer.
    UnexpectedEof {
        /// The byte offset that was requested.
        offset: usize,
        /// The number of bytes requested at that offset.
        needed: usize,
        /// The total length of the buffer.
        len: usize,
    },
    /// A LEB128 value did not terminate within the allowed number of bytes.
    MalformedLeb128,
    /// A magic number, signature, or tag did not match the expected value.
    BadMagic,
    /// A structural invariant of the format was violated.
    Malformed(&'static str),
    /// A value did not fit the width required by the format (e.g. a 64-bit offset in a
    /// 32-bit field).
    ValueOutOfRange(&'static str),
    /// A label referenced by a fixup was never defined.
    UndefinedLabel,
    /// The requested capability is recognised but not implemented for this format yet.
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arena(err) => write!(f, "{err}"),
            Self::UnexpectedEof {
                offset,
                needed,
                len,
            } => write!(
                f,
                "unexpected end of input: needed {needed} byte(s) at offset {offset} but buffer is {len} byte(s)"
            ),
            Self::MalformedLeb128 => write!(f, "malformed LEB128 value"),
            Self::BadMagic => write!(f, "bad magic number or signature"),
            Self::Malformed(what) => write!(f, "malformed object: {what}"),
            Self::ValueOutOfRange(what) => write!(f, "value out of range: {what}"),
            Self::UndefinedLabel => write!(f, "fixup referenced an undefined label"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Arena(err) => Some(err),
            _ => None,
        }
    }
}

impl From<stratum_arena::Error> for Error {
    fn from(err: stratum_arena::Error) -> Self {
        Self::Arena(err)
    }
}

/// Convenience result alias for object operations.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;
    use std::error::Error as _;

    #[test]
    fn display_is_specific() {
        assert_eq!(
            Error::UnexpectedEof {
                offset: 4,
                needed: 2,
                len: 5,
            }
            .to_string(),
            "unexpected end of input: needed 2 byte(s) at offset 4 but buffer is 5 byte(s)"
        );
        assert_eq!(Error::BadMagic.to_string(), "bad magic number or signature");
        assert_eq!(
            Error::Malformed("bad header").to_string(),
            "malformed object: bad header"
        );
    }

    #[test]
    fn arena_errors_chain_as_source() {
        let err = Error::from(stratum_arena::Error::ArenaFull);
        assert!(err.source().is_some());
        assert!(Error::BadMagic.source().is_none());
    }

    #[test]
    fn display_covers_remaining_variants() {
        assert_eq!(
            Error::from(stratum_arena::Error::ArenaFull).to_string(),
            stratum_arena::Error::ArenaFull.to_string()
        );
        assert_eq!(Error::MalformedLeb128.to_string(), "malformed LEB128 value");
        assert_eq!(
            Error::ValueOutOfRange("too big").to_string(),
            "value out of range: too big"
        );
        assert_eq!(
            Error::UndefinedLabel.to_string(),
            "fixup referenced an undefined label"
        );
        assert_eq!(
            Error::Unsupported("no pdb").to_string(),
            "unsupported: no pdb"
        );
    }
}
