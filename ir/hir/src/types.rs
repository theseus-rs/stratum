//! High-level, language-neutral types.

use crate::alloc_prelude::*;
use crate::context::HirTypeId;
use stratum_arena::Symbol;

/// C-style type qualifiers (`const`, `volatile`, `restrict`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "C type qualifiers are independent flags"
)]
pub struct Qualifiers {
    /// The `const` qualifier.
    pub is_const: bool,
    /// The `volatile` qualifier.
    pub is_volatile: bool,
    /// The C99 `restrict` qualifier.
    pub is_restrict: bool,
    /// The C11 `_Atomic` qualifier.
    pub is_atomic: bool,
}

impl Qualifiers {
    /// Returns `true` if no qualifier is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        !self.is_const && !self.is_volatile && !self.is_restrict && !self.is_atomic
    }
}

/// The tag namespace a [`HirType::Tag`] refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TagKind {
    /// `struct`
    Struct,
    /// `union`
    Union,
    /// `enum`
    Enum,
}

impl TagKind {
    /// Returns the C keyword spelling.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            TagKind::Struct => "struct",
            TagKind::Union => "union",
            TagKind::Enum => "enum",
        }
    }
}

/// The bit width of an integer type.
///
/// Widths are explicit so the HIR stays target-neutral; lowering chooses a concrete width
/// for source types such as C's `int` rather than leaving it implementation-defined here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntWidth {
    /// 8-bit integer.
    W8,
    /// 16-bit integer.
    W16,
    /// 32-bit integer.
    W32,
    /// 64-bit integer.
    W64,
}

impl IntWidth {
    /// Returns the width in bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        match self {
            IntWidth::W8 => 8,
            IntWidth::W16 => 16,
            IntWidth::W32 => 32,
            IntWidth::W64 => 64,
        }
    }
}

/// A high-level type in the HIR type arena.
///
/// Types are kept deliberately abstract: they describe shape and signedness but not target
/// layout (that is the job of later stages such as the LIR). Unresolved source type names
/// survive as [`HirType::Named`] until a resolution pass replaces them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HirType {
    /// The absence of a value (e.g. a function returning nothing).
    Void,
    /// A boolean.
    Bool,
    /// An integer of a given signedness and width.
    Int {
        /// Whether the integer is signed.
        signed: bool,
        /// The bit width.
        width: IntWidth,
    },
    /// A floating-point number of the given bit width (32 or 64).
    Float {
        /// The bit width.
        bits: u32,
    },
    /// A pointer to another type.
    Pointer(HirTypeId),
    /// An array of `element`, with an optional known length.
    Array {
        /// The element type.
        element: HirTypeId,
        /// The number of elements, if known at this stage.
        length: Option<u64>,
    },
    /// A function type.
    Function {
        /// Parameter types, in order.
        params: Vec<HirTypeId>,
        /// The return type.
        ret: HirTypeId,
        /// Whether the parameter list ends with `, ...`.
        variadic: bool,
    },
    /// A qualified type (`const`/`volatile`/`restrict` applied to another type).
    Qualified {
        /// The underlying type.
        inner: HirTypeId,
        /// The qualifiers applied.
        qualifiers: Qualifiers,
    },
    /// A reference to a tagged `struct`/`union`/`enum` type (the `struct Foo` in a use).
    Tag {
        /// Which tag namespace the name lives in.
        kind: TagKind,
        /// The tag name, or `None` for a reference to an anonymous aggregate.
        name: Option<Symbol>,
    },
    /// An as-yet-unresolved named type introduced by a `typedef`.
    Named(Symbol),
}

#[cfg(test)]
mod tests {
    use super::{IntWidth, Qualifiers, TagKind};

    #[test]
    fn qualifier_empty_and_spellings_are_stable() {
        assert!(Qualifiers::default().is_empty());
        assert!(
            !Qualifiers {
                is_const: true,
                is_volatile: false,
                is_restrict: false,
                is_atomic: false,
            }
            .is_empty()
        );

        assert_eq!(TagKind::Struct.spelling(), "struct");
        assert_eq!(TagKind::Union.spelling(), "union");
        assert_eq!(TagKind::Enum.spelling(), "enum");
        assert_eq!(IntWidth::W8.bits(), 8);
        assert_eq!(IntWidth::W16.bits(), 16);
        assert_eq!(IntWidth::W32.bits(), 32);
        assert_eq!(IntWidth::W64.bits(), 64);
    }
}
