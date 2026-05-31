use core::fmt;

#[derive(Debug)]
pub enum Error {
    Arena(stratum_arena::Error),
    Diagnostics(stratum_diagnostics::Error),
    Lexer(stratum_c_lexer::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arena(err) => write!(f, "{err}"),
            Self::Diagnostics(err) => write!(f, "{err}"),
            Self::Lexer(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for Error {}

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

impl From<stratum_c_lexer::Error> for Error {
    fn from(err: stratum_c_lexer::Error) -> Self {
        Self::Lexer(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;

    #[test]
    fn display_forwards_inner_errors() {
        let arena = Error::from(stratum_arena::Error::ArenaFull);
        assert_eq!(arena.to_string(), "arena exceeded u32::MAX elements");

        let diagnostics = Error::from(stratum_diagnostics::Error::SourceMapFull);
        assert_eq!(
            diagnostics.to_string(),
            "source map exceeded u32::MAX files"
        );

        let lexer = Error::from(stratum_c_lexer::Error::from(
            stratum_arena::Error::InternerFull,
        ));
        assert_eq!(lexer.to_string(), "interner exceeded u32::MAX symbols");
    }
}
