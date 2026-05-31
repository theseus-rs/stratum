use core::fmt;

#[derive(Debug)]
pub enum Error {
    Arena(stratum_arena::Error),
    Diagnostics(stratum_diagnostics::Error),
    Lowering(stratum_c_bridge::Error),
    Parser(stratum_c_parser::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arena(err) => write!(f, "{err}"),
            Self::Diagnostics(err) => write!(f, "{err}"),
            Self::Lowering(err) => write!(f, "{err}"),
            Self::Parser(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Arena(err) => Some(err),
            Self::Diagnostics(err) => Some(err),
            Self::Lowering(err) => Some(err),
            Self::Parser(err) => Some(err),
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

impl From<stratum_c_bridge::Error> for Error {
    fn from(err: stratum_c_bridge::Error) -> Self {
        Self::Lowering(err)
    }
}

impl From<stratum_c_parser::Error> for Error {
    fn from(err: stratum_c_parser::Error) -> Self {
        Self::Parser(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;
    use std::error::Error as _;

    #[test]
    fn display_and_sources_forward_inner_errors() {
        let cases = [
            Error::from(stratum_arena::Error::ArenaFull),
            Error::from(stratum_diagnostics::Error::UnknownFile(
                stratum_diagnostics::FileId::from_raw(0),
            )),
            Error::from(stratum_c_bridge::Error::from(
                stratum_arena::Error::ArenaFull,
            )),
            Error::from(stratum_c_parser::Error::from(
                stratum_c_ast::Error::InconsistentNodeStorage,
            )),
        ];

        for err in cases {
            assert!(!err.to_string().is_empty());
            assert!(err.source().is_some());
        }
    }
}
