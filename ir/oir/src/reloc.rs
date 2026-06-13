//! Neutral relocations: the format-independent description of "patch this offset with the
//! address of that symbol".
//!
//! Each codec maps its own relocation-type zoo (ELF `R_*`, Mach-O `*_RELOC_*`, PE
//! `IMAGE_REL_*`) onto [`RelocKind`], preserving any type it does not model through
//! [`RelocKind::Other`].

use crate::model::{SectionId, SymbolId};

/// The neutral classification of a relocation's arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocKind {
    /// Write the symbol's absolute 64-bit address.
    Absolute64,
    /// Write the symbol's absolute 32-bit address.
    Absolute32,
    /// Write a 32-bit displacement from the end of the fixup to the symbol (PC-relative).
    Relative32,
    /// Write a 64-bit displacement from the end of the fixup to the symbol (PC-relative).
    Relative64,
    /// A Global Offset Table (GOT) relative reference.
    GotRelative,
    /// A Procedure Linkage Table (PLT) relative reference.
    PltRelative,
    /// A relocation Stratum does not model, keyed by its raw format-specific type id.
    Other(u32),
}

/// A request to patch bytes in a section with a value derived from a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    /// Section whose bytes are patched.
    pub section: SectionId,
    /// Byte offset of the fixup within the section.
    pub offset: u64,
    /// Symbol whose address feeds the fixup.
    pub symbol: SymbolId,
    /// The arithmetic to apply.
    pub kind: RelocKind,
    /// A constant added to the symbol's value before the fixup is written.
    pub addend: i64,
}
