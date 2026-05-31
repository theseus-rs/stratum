use core::fmt;

#[derive(Debug)]
pub enum Error {
    Arena(stratum_arena::Error),
    Ast(stratum_c_ast::Error),
    Hir(stratum_hir::Error),
    UnexpectedAstNode(&'static str),
    UnexpectedHirNode(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arena(err) => write!(f, "{err}"),
            Self::Ast(err) => write!(f, "{err}"),
            Self::Hir(err) => write!(f, "{err}"),
            Self::UnexpectedAstNode(context) => {
                write!(f, "unexpected AST node while lowering {context}")
            }
            Self::UnexpectedHirNode(context) => {
                write!(f, "unexpected HIR node while raising {context}")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Arena(err) => Some(err),
            Self::Ast(err) => Some(err),
            Self::Hir(err) => Some(err),
            Self::UnexpectedAstNode(_) | Self::UnexpectedHirNode(_) => None,
        }
    }
}

impl From<stratum_arena::Error> for Error {
    fn from(err: stratum_arena::Error) -> Self {
        Self::Arena(err)
    }
}

impl From<stratum_c_ast::Error> for Error {
    fn from(err: stratum_c_ast::Error) -> Self {
        Self::Ast(err)
    }
}

impl From<stratum_hir::Error> for Error {
    fn from(err: stratum_hir::Error) -> Self {
        Self::Hir(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;
    use std::error::Error as _;

    #[test]
    fn display_and_source_cover_all_variants() {
        let cases = [
            Error::from(stratum_arena::Error::ArenaFull),
            Error::from(stratum_c_ast::Error::InconsistentNodeStorage),
            Error::from(stratum_hir::Error::from(stratum_arena::Error::ArenaFull)),
            Error::UnexpectedAstNode("unit test"),
            Error::UnexpectedHirNode("unit test"),
        ];

        for err in cases {
            assert!(!err.to_string().is_empty());
            if matches!(
                err,
                Error::UnexpectedAstNode(_) | Error::UnexpectedHirNode(_)
            ) {
                assert!(err.source().is_none());
            } else {
                assert!(err.source().is_some());
            }
        }
    }
}
