//! Neutral dynamic-linkage tables: the imports a module needs from other images and the
//! exports it offers in return.
//!
//! These mirror a PE import/export directory or a Mach-O dynamic-symbol/dylib table without
//! committing to either encoding; codecs translate to and from their on-disk form.

use stratum_arena::Symbol;

/// A single symbol imported from another image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Import {
    /// Interned name of the providing library (e.g. `kernel32.dll`, `/usr/lib/libSystem.dylib`).
    pub library: Symbol,
    /// Interned name of the imported symbol. Ignored when imported purely [`by ordinal`].
    ///
    /// [`by ordinal`]: Import::ordinal
    pub name: Symbol,
    /// Import ordinal, when the symbol is imported by ordinal rather than name (PE).
    pub ordinal: Option<u16>,
    /// Export-name-table hint, when present (PE).
    pub hint: Option<u16>,
}

/// A single symbol this module exports for other images to bind against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Export {
    /// Interned name of the exported symbol.
    pub name: Symbol,
    /// Virtual address (or RVA) of the exported entity.
    pub address: u64,
    /// Export ordinal, when assigned (PE).
    pub ordinal: Option<u16>,
}
