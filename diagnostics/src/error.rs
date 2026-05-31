use crate::source_map::FileId;
use core::fmt;

#[derive(Debug)]
pub enum Error {
    SourceMapFull,
    UnknownFile(FileId),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMapFull => write!(f, "source map exceeded u32::MAX files"),
            Self::UnknownFile(id) => write!(f, "span refers to unknown {id:?}"),
        }
    }
}

impl core::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alloc_prelude::*;

    #[test]
    fn format_errors() {
        assert_eq!(
            Error::SourceMapFull.to_string(),
            "source map exceeded u32::MAX files"
        );
        assert_eq!(
            Error::UnknownFile(FileId::from_raw(42)).to_string(),
            "span refers to unknown FileId(42)"
        );
    }
}
