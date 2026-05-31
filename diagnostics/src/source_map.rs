//! A provenance-aware registry of source files.

use crate::alloc_prelude::*;
use crate::span::Span;
use core::fmt;

/// Identifies a source file (real or synthetic) inside a [`SourceMap`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileId(u32);

impl FileId {
    /// Creates a file id from a raw index.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw index backing this id.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId({})", self.0)
    }
}

/// A 1-based line and column position within a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineCol {
    /// 1-based line number.
    pub line: u32,
    /// 1-based column number, counted in bytes.
    pub column: u32,
}

/// Where a source file came from.
///
/// Tracking origin lets diagnostics explain *why* a file is in play (an `#include`) and
/// where macro-generated tokens really originated.
#[derive(Debug, Clone)]
pub enum Origin {
    /// A file supplied directly to the compiler (e.g. a command-line input).
    Root,
    /// A file pulled in via `#include` from another file.
    Include {
        /// The file containing the `#include` directive.
        parent: FileId,
        /// The span of the directive within `parent`.
        directive: Span,
    },
    /// A synthetic file holding the tokens produced by a macro expansion.
    Expansion {
        /// The span where the macro was invoked.
        call_site: Span,
        /// The span of the macro's definition body.
        definition: Span,
    },
}

/// A single registered source file plus precomputed line-start offsets.
#[derive(Debug, Clone)]
pub struct SourceFile {
    name: String,
    text: String,
    origin: Origin,
    line_starts: Vec<u32>,
}

impl SourceFile {
    fn new(name: String, text: String, origin: Origin) -> Self {
        let mut line_starts = vec![0u32];
        for (index, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                // Saturating guards pathologically large inputs without panicking.
                let next = u32::try_from(index).map_or(u32::MAX, |i| i.saturating_add(1));
                line_starts.push(next);
            }
        }
        Self {
            name,
            text,
            origin,
            line_starts,
        }
    }

    /// The display name of this file.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The full source text of this file.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// How this file entered the compilation.
    #[must_use]
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    fn line_col(&self, offset: u32) -> LineCol {
        let line_index = match self.line_starts.binary_search(&offset) {
            Ok(exact) => exact,
            Err(insertion) => insertion.saturating_sub(1),
        };
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        LineCol {
            line: u32::try_from(line_index).map_or(u32::MAX, |i| i.saturating_add(1)),
            column: offset.saturating_sub(line_start).saturating_add(1),
        }
    }
}

/// A registry of all source files seen during a compilation.
///
/// # Examples
///
/// ```
/// use stratum_diagnostics::{SourceMap, Span};
///
/// let mut map = SourceMap::new();
/// let file = map.add_root("main.c", "int x;\nint y;\n").unwrap();
/// let span = Span::new(file, 7, 10); // start of the second line
/// let pos = map.line_col(span).unwrap();
/// assert_eq!(pos.line, 2);
/// assert_eq!(pos.column, 1);
/// ```
#[derive(Debug, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    /// Creates an empty source map.
    #[must_use]
    pub fn new() -> Self {
        Self { files: Vec::new() }
    }

    fn add(
        &mut self,
        name: impl Into<String>,
        text: impl Into<String>,
        origin: Origin,
    ) -> crate::Result<FileId> {
        let raw = u32::try_from(self.files.len()).map_err(|_| crate::Error::SourceMapFull)?;
        self.files
            .push(SourceFile::new(name.into(), text.into(), origin));
        Ok(FileId::from_raw(raw))
    }

    /// Registers a root input file and returns its id.
    /// # Errors
    ///
    /// Returns an error if the internal file ID allocation fails.
    pub fn add_root(
        &mut self,
        name: impl Into<String>,
        text: impl Into<String>,
    ) -> crate::Result<FileId> {
        self.add(name, text, Origin::Root)
    }

    /// Registers an `#include`d file, recording the directive that pulled it in.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal file ID allocation fails.
    pub fn add_include(
        &mut self,
        name: impl Into<String>,
        text: impl Into<String>,
        parent: FileId,
        directive: Span,
    ) -> crate::Result<FileId> {
        self.add(name, text, Origin::Include { parent, directive })
    }

    /// Registers a synthetic file for a macro expansion's output tokens.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal file ID allocation fails.
    pub fn add_expansion(
        &mut self,
        name: impl Into<String>,
        text: impl Into<String>,
        call_site: Span,
        definition: Span,
    ) -> crate::Result<FileId> {
        self.add(
            name,
            text,
            Origin::Expansion {
                call_site,
                definition,
            },
        )
    }

    /// Returns the file for `id`, or `None` if it is unknown.
    #[must_use]
    pub fn file(&self, id: FileId) -> Option<&SourceFile> {
        self.files.get(id.0 as usize)
    }

    /// Returns the number of registered files.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Returns `true` if no files are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Resolves the start of `span` to a 1-based line and column.
    ///
    /// # Errors
    ///
    /// Returns an error if the span refers to a file not present in this map.
    pub fn line_col(&self, span: Span) -> crate::Result<LineCol> {
        let file = self
            .file(span.file())
            .ok_or_else(|| crate::Error::UnknownFile(span.file()))?;
        Ok(file.line_col(span.start()))
    }

    /// Returns the source text covered by `span`, if both the file and range are valid.
    #[must_use]
    pub fn snippet(&self, span: Span) -> Option<&str> {
        let file = self.file(span.file())?;
        file.text.get(span.start() as usize..span.end() as usize)
    }

    /// Walks the include chain for `id`, from the file itself up to its root.
    #[must_use]
    pub fn include_chain(&self, id: FileId) -> Vec<FileId> {
        let mut chain = vec![id];
        let mut current = id;
        while let Some(file) = self.file(current) {
            match file.origin() {
                Origin::Include { parent, .. } => {
                    chain.push(*parent);
                    current = *parent;
                }
                Origin::Root | Origin::Expansion { .. } => break,
            }
        }
        chain
    }
}

#[cfg(test)]
mod tests {
    use super::{FileId, Origin, SourceFile, SourceMap};
    use crate::alloc_prelude::*;
    use crate::span::Span;

    #[test]
    fn line_col_on_first_line() {
        let mut map = SourceMap::new();
        let file = map.add_root("a.c", "abc\ndef\n").unwrap();
        let pos = map.line_col(Span::new(file, 1, 2)).unwrap();
        assert_eq!(pos.line, 1);
        assert_eq!(pos.column, 2);
    }

    #[test]
    fn line_col_on_later_line() {
        let mut map = SourceMap::new();
        let file = map.add_root("a.c", "abc\ndef\n").unwrap();
        let pos = map.line_col(Span::new(file, 4, 5)).unwrap();
        assert_eq!(pos.line, 2);
        assert_eq!(pos.column, 1);
    }

    #[test]
    fn snippet_extracts_text() {
        let mut map = SourceMap::new();
        let file = map.add_root("a.c", "hello world").unwrap();
        let span = Span::new(file, 6, 11);
        assert_eq!(map.snippet(span), Some("world"));
    }

    #[test]
    fn include_chain_tracks_parents() {
        let mut map = SourceMap::new();
        let root = map.add_root("main.c", "#include \"a.h\"\n").unwrap();
        let directive = Span::new(root, 0, 14);
        let header = map.add_include("a.h", "int x;\n", root, directive).unwrap();
        assert_eq!(map.include_chain(header), vec![header, root]);
    }

    #[test]
    fn origin_records_expansion() {
        let mut map = SourceMap::new();
        let root = map.add_root("main.c", "FOO\n").unwrap();
        let call = Span::new(root, 0, 3);
        let def = Span::new(root, 0, 3);
        let exp = map.add_expansion("<FOO>", "1", call, def).unwrap();
        assert!(matches!(
            map.file(exp).map(SourceFile::origin),
            Some(Origin::Expansion { .. })
        ));
    }

    #[test]
    fn file_id_raw_debug_and_accessors_are_stable() {
        let id = FileId::from_raw(7);
        assert_eq!(id.raw(), 7);
        assert_eq!(format!("{id:?}"), "FileId(7)");

        let mut map = SourceMap::new();
        assert!(map.is_empty());
        let file = map.add_root("root.c", "text").unwrap();
        assert_eq!(map.len(), 1);
        let source = map.file(file).unwrap();
        assert_eq!(source.name(), "root.c");
        assert_eq!(source.text(), "text");
        assert!(matches!(source.origin(), Origin::Root));
    }

    #[test]
    fn empty_source_map_rejects_unknown_spans() {
        let map = SourceMap::new();
        let unknown = FileId::from_raw(42);
        let span = Span::point(unknown, 0);
        assert!(map.line_col(span).is_err());
        assert_eq!(map.snippet(span), None);
        assert_eq!(map.include_chain(unknown), vec![unknown]);
    }
}
