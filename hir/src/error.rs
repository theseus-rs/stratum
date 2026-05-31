use core::fmt;

#[derive(Debug)]
pub enum Error {
    Arena(stratum_arena::Error),
    InconsistentNodeStorage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arena(err) => write!(f, "{err}"),
            Self::InconsistentNodeStorage => {
                write!(f, "HIR node arena and span storage are inconsistent")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Arena(err) => Some(err),
            Self::InconsistentNodeStorage => None,
        }
    }
}

impl From<stratum_arena::Error> for Error {
    fn from(err: stratum_arena::Error) -> Self {
        Self::Arena(err)
    }
}

pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::alloc_prelude::*;
    use std::error::Error as _;

    #[test]
    fn display_and_sources_are_specific() {
        let arena = Error::from(stratum_arena::Error::ArenaFull);
        assert_eq!(arena.to_string(), "arena exceeded u32::MAX elements");
        assert!(arena.source().is_some());

        let inconsistent = Error::InconsistentNodeStorage;
        assert_eq!(
            inconsistent.to_string(),
            "HIR node arena and span storage are inconsistent"
        );
        assert!(inconsistent.source().is_none());
    }
}
