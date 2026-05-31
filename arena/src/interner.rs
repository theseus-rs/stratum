//! String interning.

use crate::alloc_prelude::*;
use core::fmt;
use stratum_utils::HashMap;

/// An interned string, represented as a small copyable handle.
///
/// Symbols are produced by an [`Interner`] and are only meaningful relative to the
/// interner that created them. Equality of `Symbol`s implies equality of the underlying
/// strings (within one interner), which makes identifier comparisons `O(1)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Symbol(u32);

impl Symbol {
    /// Returns the raw index backing this symbol.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for Symbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Symbol({})", self.0)
    }
}

/// Interns strings so that each distinct string is stored once and compared by handle.
///
/// # Examples
///
/// ```
/// use stratum_arena::Interner;
///
/// let mut interner = Interner::new();
/// let a = interner.intern("count").unwrap();
/// let b = interner.intern("count").unwrap();
/// let c = interner.intern("total").unwrap();
/// assert_eq!(a, b);
/// assert_ne!(a, c);
/// assert_eq!(interner.resolve(a).unwrap(), "count");
/// ```
#[derive(Debug, Default)]
pub struct Interner {
    lookup: HashMap<String, Symbol>,
    strings: Vec<String>,
}

impl Interner {
    /// Creates an empty interner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            lookup: HashMap::default(),
            strings: Vec::new(),
        }
    }

    /// Returns the [`Symbol`] for `text`, inserting it if not already present.
    ///
    /// # Errors
    ///
    /// Returns an error if more than `u32::MAX` distinct strings are interned.
    pub fn intern(&mut self, text: &str) -> crate::Result<Symbol> {
        if let Some(symbol) = self.lookup.get(text) {
            return Ok(*symbol);
        }
        let raw = u32::try_from(self.strings.len()).map_err(|_| crate::Error::InternerFull)?;
        let symbol = Symbol(raw);
        self.strings.push(text.to_string());
        self.lookup.insert(text.to_string(), symbol);
        Ok(symbol)
    }

    /// Returns the string previously interned as `symbol`.
    ///
    /// # Errors
    ///
    /// Returns an error if `symbol` was not produced by this interner.
    pub fn resolve(&self, symbol: Symbol) -> crate::Result<&str> {
        match self.strings.get(symbol.0 as usize) {
            Some(text) => Ok(text.as_str()),
            None => Err(crate::Error::UnknownSymbol),
        }
    }

    /// Returns the string for `symbol`, or `None` if it is unknown to this interner.
    #[must_use]
    pub fn try_resolve(&self, symbol: Symbol) -> Option<&str> {
        self.strings.get(symbol.0 as usize).map(String::as_str)
    }

    /// Returns the [`Symbol`] for `text` if it has already been interned, without inserting.
    #[must_use]
    pub fn get(&self, text: &str) -> Option<Symbol> {
        self.lookup.get(text).copied()
    }

    /// Returns the number of distinct interned strings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.strings.len()
    }

    /// Returns `true` if no strings have been interned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{Interner, Symbol};
    use crate::alloc_prelude::*;

    #[test]
    fn equal_strings_share_symbols() {
        let mut interner = Interner::new();
        let a = interner.intern("foo").unwrap();
        let b = interner.intern("foo").unwrap();
        assert_eq!(a, b);
        assert_eq!(interner.len(), 1);
    }

    #[test]
    fn distinct_strings_differ() {
        let mut interner = Interner::new();
        let a = interner.intern("foo").unwrap();
        let b = interner.intern("bar").unwrap();
        assert_ne!(a, b);
        assert_eq!(interner.len(), 2);
    }

    #[test]
    fn resolve_round_trips() {
        let mut interner = Interner::new();
        let a = interner.intern("hello").unwrap();
        assert_eq!(interner.resolve(a).unwrap(), "hello");
        assert_eq!(interner.try_resolve(a), Some("hello"));
    }

    #[test]
    fn empty_interner_state() {
        let interner = Interner::new();
        assert!(interner.is_empty());
        assert_eq!(interner.len(), 0);
    }

    #[test]
    fn symbol_raw_and_debug_are_stable() {
        let sym = Symbol::default();
        assert_eq!(sym.raw(), 0);
        assert_eq!(format!("{sym:?}"), "Symbol(0)");
    }

    #[test]
    fn unknown_symbol_is_reported() {
        let interner = Interner::new();
        assert!(interner.resolve(Symbol::default()).is_err());
        assert_eq!(interner.try_resolve(Symbol::default()), None);
    }

    #[test]
    fn get_does_not_insert() {
        let mut interner = Interner::new();
        assert_eq!(interner.get("missing"), None);
        let sym = interner.intern("present").unwrap();
        assert_eq!(interner.get("present"), Some(sym));
        assert_eq!(interner.len(), 1);
    }
}
