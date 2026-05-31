use core::fmt;

#[derive(Debug)]
pub enum Error {
    Ast(stratum_c_ast::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ast(err) => write!(f, "{err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Ast(err) => Some(err),
        }
    }
}

impl From<stratum_c_ast::Error> for Error {
    fn from(err: stratum_c_ast::Error) -> Self {
        Self::Ast(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;
    use std::error::Error as _;

    #[test]
    fn display_and_source_forward_ast_error() {
        let err = Error::from(stratum_c_ast::Error::InconsistentNodeStorage);
        assert!(!err.to_string().is_empty());
        assert!(err.source().is_some());
    }
}
