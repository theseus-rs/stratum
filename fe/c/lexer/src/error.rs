use core::fmt;

#[derive(Debug)]
pub enum Error {
    Arena(stratum_arena::Error),
    Diagnostics(stratum_diagnostics::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arena(err) => write!(f, "{err}"),
            Self::Diagnostics(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Arena(err) => Some(err),
            Self::Diagnostics(err) => Some(err),
        }
    }
}

impl From<stratum_arena::Error> for Error {
    fn from(err: stratum_arena::Error) -> Self {
        Self::Arena(err)
    }
}

impl From<stratum_diagnostics::Error> for Error {
    fn from(err: stratum_diagnostics::Error) -> Self {
        Self::Diagnostics(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;
    use std::error::Error as _;

    #[test]
    fn display_and_source_forward_inner_errors() {
        let arena = Error::from(stratum_arena::Error::InternerFull);
        assert_eq!(arena.to_string(), "interner exceeded u32::MAX symbols");
        assert!(arena.source().is_some());

        let diagnostics = Error::from(stratum_diagnostics::Error::SourceMapFull);
        assert_eq!(
            diagnostics.to_string(),
            "source map exceeded u32::MAX files"
        );
        assert!(diagnostics.source().is_some());
    }
}
