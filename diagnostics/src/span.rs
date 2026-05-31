//! Byte-range source spans.

use crate::source_map::FileId;

/// A half-open byte range `[start, end)` within a single source file.
///
/// Spans are the universal currency of location information in Stratum. They are
/// deliberately tiny (a [`FileId`] plus two `u32` offsets) so they can be stored in
/// parallel arrays beside arena nodes without bloating them.
///
/// A span always refers to a [`FileId`]; for tokens produced by macro expansion the file
/// is the synthetic expansion file recorded in the [`SourceMap`](crate::SourceMap), whose
/// provenance links back to the physical origin.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    file: FileId,
    start: u32,
    end: u32,
}

impl Span {
    /// Creates a span over `[start, end)` in `file`.
    #[must_use]
    pub fn new(file: FileId, start: u32, end: u32) -> Self {
        let end = end.max(start);
        Self { file, start, end }
    }

    /// Creates an empty span at `offset` in `file`.
    #[must_use]
    pub const fn point(file: FileId, offset: u32) -> Self {
        Self {
            file,
            start: offset,
            end: offset,
        }
    }

    /// The file this span belongs to.
    #[must_use]
    pub const fn file(self) -> FileId {
        self.file
    }

    /// The inclusive start offset, in bytes.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    /// The exclusive end offset, in bytes.
    #[must_use]
    pub const fn end(self) -> u32 {
        self.end
    }

    /// The length of the span in bytes.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.end - self.start
    }

    /// Returns `true` if the span covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// Returns the smallest span covering both `self` and `other`.
    #[must_use]
    pub fn to(self, other: Self) -> Self {
        if self.file != other.file {
            return self;
        }
        Self {
            file: self.file,
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

impl core::fmt::Debug for Span {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Span({}, {}..{})", self.file.raw(), self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::Span;
    use crate::alloc_prelude::*;
    use crate::source_map::FileId;

    fn file() -> FileId {
        FileId::from_raw(0)
    }

    #[test]
    fn accessors_report_range() {
        let span = Span::new(file(), 3, 8);
        assert_eq!(span.start(), 3);
        assert_eq!(span.end(), 8);
        assert_eq!(span.len(), 5);
        assert!(!span.is_empty());
    }

    #[test]
    fn point_is_empty() {
        let span = Span::point(file(), 4);
        assert!(span.is_empty());
        assert_eq!(span.len(), 0);
    }

    #[test]
    fn join_covers_both() {
        let a = Span::new(file(), 2, 4);
        let b = Span::new(file(), 6, 9);
        let joined = a.to(b);
        assert_eq!(joined.start(), 2);
        assert_eq!(joined.end(), 9);
    }

    #[test]
    fn test_clamps_reversed_range() {
        let span = Span::new(FileId::from_raw(0), 10, 5);
        assert_eq!(span.start(), 10);
        assert_eq!(span.end(), 10);
    }

    #[test]
    fn join_preserves_left_span_for_different_files_and_debug_is_concise() {
        let left = Span::new(file(), 4, 6);
        let right = Span::new(FileId::from_raw(8), 1, 9);
        assert_eq!(left.to(right), left);
        assert_eq!(format!("{left:?}"), "Span(0, 4..6)");
    }
}
