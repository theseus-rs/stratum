//! Strongly-typed arena indices.

use core::cmp::Ordering;
use core::fmt;
use core::hash::{Hash, Hasher};
use core::marker::PhantomData;

/// A strongly-typed handle into an [`Arena`](crate::Arena) of `T`.
///
/// `Id` is a thin wrapper around a `u32` index. The phantom type parameter prevents an
/// index produced for one element type from being accidentally used with another, while
/// keeping the value itself pointer-free and trivially [`Copy`].
///
/// The use of `fn() -> T` for the phantom marker keeps `Id<T>` [`Send`] and [`Sync`]
/// regardless of `T`, and means the standard derives do not impose any bounds on `T`.
///
/// # Examples
///
/// ```
/// use stratum_arena::{Arena, Id};
///
/// let mut arena = Arena::new();
/// let id: Id<u8> = arena.alloc(7).unwrap();
/// assert_eq!(arena[id], 7);
/// assert_eq!(arena[id], 7);
/// ```
pub struct Id<T> {
    raw: u32,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Id<T> {
    /// Creates an identifier from a raw index.
    ///
    /// This is primarily intended for arena implementations and serialization; prefer
    /// obtaining identifiers from [`Arena::alloc`](crate::Arena::alloc).
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    /// Returns the raw `u32` index backing this identifier.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.raw
    }

    /// Returns the index as a `usize`, suitable for slice indexing.
    #[must_use]
    pub const fn index(self) -> usize {
        self.raw as usize
    }
}

impl<T> fmt::Debug for Id<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id({})", self.raw)
    }
}

impl<T> Clone for Id<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Id<T> {}

impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl<T> Eq for Id<T> {}

impl<T> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw.cmp(&other.raw)
    }
}

impl<T> Hash for Id<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::Id;
    use crate::alloc_prelude::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn raw_round_trips() {
        let id: Id<()> = Id::from_raw(42);
        assert_eq!(id.raw(), 42);
        assert_eq!(id.index(), 42);
    }

    #[test]
    fn copy_and_equality() {
        let a: Id<u8> = Id::from_raw(1);
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, Id::<u8>::from_raw(2));
    }

    #[test]
    fn ordering_follows_raw() {
        let a: Id<u8> = Id::from_raw(1);
        let b: Id<u8> = Id::from_raw(2);
        assert!(a < b);
    }

    #[test]
    fn debug_is_concise() {
        let id: Id<u8> = Id::from_raw(3);
        assert_eq!(format!("{id:?}"), "Id(3)");
    }

    #[test]
    fn hash_follows_raw_value() {
        let mut a = DefaultHasher::new();
        Id::<u8>::from_raw(9).hash(&mut a);

        let mut b = DefaultHasher::new();
        9_u32.hash(&mut b);

        assert_eq!(a.finish(), b.finish());
    }
}
