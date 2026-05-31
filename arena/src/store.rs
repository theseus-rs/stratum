//! A flat, index-addressed arena.

use crate::alloc_prelude::*;
use crate::id::Id;
use core::fmt;
use core::marker::PhantomData;
use core::ops::{Index, IndexMut};

/// A growable, contiguous store of `T` values addressed by [`Id<T>`].
///
/// Values are never moved or freed individually; the whole arena is dropped at once. This
/// makes allocation `O(1)` amortised and deallocation a single `Vec` drop.
///
/// # Examples
///
/// ```
/// use stratum_arena::Arena;
///
/// let mut arena: Arena<String> = Arena::new();
/// let a = arena.alloc("a".to_string()).unwrap();
/// arena[a].push('!');
/// assert_eq!(arena[a], "a!");
/// ```
pub struct Arena<T> {
    items: Vec<T>,
}

impl<T> Arena<T> {
    /// Creates an empty arena.
    #[must_use]
    pub const fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Creates an empty arena with capacity for at least `capacity` elements.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Appends `value` and returns its identifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the arena already holds `u32::MAX` elements, the maximum addressable by
    /// [`Id`].
    pub fn alloc(&mut self, value: T) -> crate::Result<Id<T>> {
        let raw = u32::try_from(self.items.len()).map_err(|_| crate::Error::ArenaFull)?;
        self.items.push(value);
        Ok(Id::from_raw(raw))
    }

    /// Returns a reference to the value for `id`, or `None` if out of bounds.
    #[must_use]
    pub fn get(&self, id: Id<T>) -> Option<&T> {
        self.items.get(id.index())
    }

    /// Returns a mutable reference to the value for `id`, or `None` if out of bounds.
    #[must_use]
    pub fn get_mut(&mut self, id: Id<T>) -> Option<&mut T> {
        self.items.get_mut(id.index())
    }

    /// Returns the number of elements stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns `true` if the arena holds no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns an iterator over `(Id, &T)` pairs in allocation order.
    #[must_use]
    pub fn iter(&self) -> Iter<'_, T> {
        Iter {
            inner: self.items.iter().enumerate(),
            _marker: PhantomData,
        }
    }

    /// Returns an iterator over the stored values in allocation order.
    pub fn values(&self) -> core::slice::Iter<'_, T> {
        self.items.iter()
    }
}

impl<'a, T> IntoIterator for &'a Arena<T> {
    type Item = (Id<T>, &'a T);
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for Arena<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.items.iter()).finish()
    }
}

impl<T> Index<Id<T>> for Arena<T> {
    type Output = T;

    fn index(&self, id: Id<T>) -> &Self::Output {
        self.items.index(id.index())
    }
}

impl<T> IndexMut<Id<T>> for Arena<T> {
    fn index_mut(&mut self, id: Id<T>) -> &mut Self::Output {
        self.items.index_mut(id.index())
    }
}

/// Iterator over `(Id, &T)` pairs yielded by [`Arena::iter`].
#[derive(Debug)]
pub struct Iter<'a, T> {
    inner: core::iter::Enumerate<core::slice::Iter<'a, T>>,
    _marker: PhantomData<fn() -> T>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = (Id<T>, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        let (index, value) = self.inner.next()?;
        let raw = u32::try_from(index).ok()?;
        Some((Id::from_raw(raw), value))
    }
}

#[cfg(test)]
mod tests {
    use super::Arena;
    use crate::alloc_prelude::*;

    #[test]
    fn alloc_assigns_sequential_ids() {
        let mut arena: Arena<u32> = Arena::new();
        let a = arena.alloc(10).unwrap();
        let b = arena.alloc(20).unwrap();
        assert_eq!(a.index(), 0);
        assert_eq!(b.index(), 1);
        assert_eq!(arena.get(a), Some(&10));
        assert_eq!(arena.get(b), Some(&20));
    }

    #[test]
    fn get_handles_bounds() {
        let mut arena: Arena<u32> = Arena::new();
        let a = arena.alloc(1).unwrap();
        assert_eq!(arena.get(a), Some(&1));
        assert_eq!(arena.len(), 1);
        assert!(!arena.is_empty());
    }

    #[test]
    fn index_mut_updates_in_place() {
        let mut arena: Arena<u32> = Arena::new();
        let a = arena.alloc(1).unwrap();
        let updated = arena.get_mut(a).map(|value| *value = 99).is_some();
        assert!(updated);
        *core::ops::IndexMut::index_mut(&mut arena, a) = 100;
        assert_eq!(arena.get(a), Some(&100));
    }

    #[test]
    fn iter_yields_ids_in_order() {
        let mut arena: Arena<u32> = Arena::new();
        let a = arena.alloc(5).unwrap();
        let b = arena.alloc(6).unwrap();
        let collected: Vec<_> = arena.iter().collect();
        assert_eq!(collected, vec![(a, &5), (b, &6)]);
    }

    #[test]
    fn default_is_empty() {
        let arena: Arena<u8> = Arena::default();
        assert!(arena.is_empty());
    }

    #[test]
    fn capacity_values_into_iter_and_debug_are_available() {
        let mut arena = Arena::with_capacity(2);
        let a = arena.alloc("a").unwrap();
        let b = arena.alloc("b").unwrap();

        let values: Vec<_> = arena.values().copied().collect();
        assert_eq!(values, vec!["a", "b"]);
        assert_eq!(format!("{arena:?}"), "[\"a\", \"b\"]");

        let from_ref: Vec<_> = (&arena).into_iter().collect();
        assert_eq!(from_ref, vec![(a, &"a"), (b, &"b")]);

        assert_eq!(arena.len(), 2);
    }
}
