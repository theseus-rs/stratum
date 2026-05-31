//! Compiler diagnostics and a plain-text renderer.

use crate::alloc_prelude::*;
use crate::source_map::SourceMap;
use crate::span::Span;
use core::fmt;

/// How serious a [`Diagnostic`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// An informational note, usually attached to another diagnostic.
    Note,
    /// A potential problem that does not stop compilation.
    Warning,
    /// A problem that prevents successful compilation.
    Error,
}

impl Severity {
    /// Returns the lowercase label used when rendering.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Severity::Note => "note",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A span paired with an explanatory message, pointing at part of the source.
#[derive(Debug, Clone)]
pub struct Label {
    /// The location this label refers to.
    pub span: Span,
    /// The message describing what is notable at `span`.
    pub message: String,
}

impl Label {
    /// Creates a label.
    pub fn new(span: Span, message: impl Into<String>) -> Self {
        Self {
            span,
            message: message.into(),
        }
    }
}

/// A single diagnostic: a severity, a primary message, and zero or more labels.
///
/// # Examples
///
/// ```
/// use stratum_diagnostics::{Diagnostic, Label, Severity, SourceMap, Span};
///
/// let mut map = SourceMap::new();
/// let file = map.add_root("main.c", "int x = ;\n").unwrap();
/// let diag = Diagnostic::error("expected expression")
///     .with_label(Label::new(Span::new(file, 8, 9), "unexpected `;`"));
/// let rendered = diag.render(&map);
/// assert!(rendered.contains("error: expected expression"));
/// assert!(rendered.contains("main.c:1:9"));
/// ```
#[derive(Debug, Clone)]
pub struct Diagnostic {
    severity: Severity,
    message: String,
    labels: Vec<Label>,
}

impl Diagnostic {
    /// Creates a diagnostic with the given severity and message.
    pub fn new(severity: Severity, message: impl Into<String>) -> Self {
        Self {
            severity,
            message: message.into(),
            labels: Vec::new(),
        }
    }

    /// Creates an error-severity diagnostic.
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(Severity::Error, message)
    }

    /// Creates a warning-severity diagnostic.
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, message)
    }

    /// Creates a note-severity diagnostic.
    pub fn note(message: impl Into<String>) -> Self {
        Self::new(Severity::Note, message)
    }

    /// Attaches a label and returns the diagnostic, for builder-style use.
    #[must_use]
    pub fn with_label(mut self, label: Label) -> Self {
        self.labels.push(label);
        self
    }

    /// Adds a label in place.
    pub fn push_label(&mut self, label: Label) {
        self.labels.push(label);
    }

    /// The severity of this diagnostic.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// The primary message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The attached labels.
    #[must_use]
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Renders the diagnostic to a human-readable, multi-line string.
    ///
    /// The format is intentionally simple and deterministic so it can be snapshot-tested:
    ///
    /// ```text
    /// error: <message>
    ///   --> <file>:<line>:<col>: <label message>
    /// ```
    #[must_use]
    pub fn render(&self, sources: &SourceMap) -> String {
        use core::fmt::Write as _;
        let mut out = format!("{}: {}\n", self.severity.label(), self.message);
        for label in &self.labels {
            let name = sources
                .file(label.span.file())
                .map_or("<unknown>", crate::source_map::SourceFile::name);
            let (line, column) = match sources.line_col(label.span) {
                Ok(pos) => (pos.line, pos.column),
                Err(_) => (0, 0),
            };
            let _ = writeln!(out, "  --> {}:{}:{}: {}", name, line, column, label.message);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Label, Severity};
    use crate::alloc_prelude::*;
    use crate::source_map::{FileId, SourceMap};
    use crate::span::Span;

    #[test]
    fn severity_ordering() {
        assert!(Severity::Error > Severity::Warning);
        assert!(Severity::Warning > Severity::Note);
    }

    #[test]
    fn builder_collects_labels() {
        let mut map = SourceMap::new();
        let file = map.add_root("a.c", "abc\n").unwrap();
        let diag =
            Diagnostic::warning("careful").with_label(Label::new(Span::new(file, 0, 1), "here"));
        assert_eq!(diag.severity(), Severity::Warning);
        assert_eq!(diag.labels().len(), 1);
    }

    #[test]
    fn render_includes_location() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "int x = ;\n").unwrap();
        let diag = Diagnostic::error("expected expression")
            .with_label(Label::new(Span::new(file, 8, 9), "unexpected `;`"));
        let rendered = diag.render(&map);
        assert!(rendered.contains("error: expected expression"));
        assert!(rendered.contains("main.c:1:9: unexpected `;`"));
    }

    #[test]
    fn render_without_labels() {
        let map = SourceMap::new();
        let diag = Diagnostic::note("just so you know");
        assert_eq!(diag.render(&map), "note: just so you know\n");
    }

    #[test]
    fn severity_display_and_label_accessors_are_stable() {
        assert_eq!(Severity::Error.label(), "error");
        assert_eq!(Severity::Warning.to_string(), "warning");
        assert_eq!(Severity::Note.to_string(), "note");

        let span = Span::new(FileId::from_raw(0), 1, 3);
        let label = Label::new(span, "label");
        assert_eq!(label.span, span);
        assert_eq!(label.message, "label");

        let mut diagnostic = Diagnostic::warning("warn");
        diagnostic.push_label(label.clone());
        assert_eq!(diagnostic.message(), "warn");
        let stored = diagnostic.labels().first().unwrap();
        assert_eq!(stored.span, label.span);
        assert_eq!(stored.message, label.message);
    }

    #[test]
    fn render_includes_missing_file_fallback() {
        let span = Span::new(FileId::from_raw(99), 2, 4);
        let rendered = Diagnostic::error("missing")
            .with_label(Label::new(span, "there"))
            .render(&SourceMap::new());
        assert!(rendered.contains("<unknown>"));
        assert!(rendered.contains("there"));
    }
}
