use core::fmt;

#[derive(Debug)]
pub enum Error {
    InternerFull,
    UnknownSymbol,
    ArenaFull,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InternerFull => write!(f, "interner exceeded u32::MAX symbols"),
            Self::UnknownSymbol => write!(f, "symbol does not belong to this interner"),
            Self::ArenaFull => write!(f, "arena exceeded u32::MAX elements"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;

    #[test]
    fn display_messages_are_specific() {
        assert_eq!(
            Error::InternerFull.to_string(),
            "interner exceeded u32::MAX symbols"
        );
        assert_eq!(
            Error::UnknownSymbol.to_string(),
            "symbol does not belong to this interner"
        );
        assert_eq!(
            Error::ArenaFull.to_string(),
            "arena exceeded u32::MAX elements"
        );
    }
}
