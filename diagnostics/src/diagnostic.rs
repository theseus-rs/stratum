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
/// assert!(rendered.contains("--> main.c:1:9"));
/// assert!(rendered.contains("^ unexpected `;`"));
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
    /// The format provides detailed compiler diagnostics while staying deterministic:
    ///
    /// ```text
    /// error: <message>
    ///  --> <file>:<line>:<col>
    ///   |
    /// 1 | <source line>
    ///   |  ^ <label message>
    /// ```
    #[must_use]
    pub fn render(&self, sources: &SourceMap) -> String {
        let mut out = format!("{}: {}\n", self.severity.label(), self.message);
        for label in &self.labels {
            render_label(&mut out, sources, label);
        }
        out
    }
}

struct LineSnippet<'a> {
    number: u32,
    start: usize,
    end: usize,
    text: &'a str,
}

fn render_label(out: &mut String, sources: &SourceMap, label: &Label) {
    use core::fmt::Write as _;

    let Some(file) = sources.file(label.span.file()) else {
        let _ = writeln!(out, " --> <unknown>:0:0");
        let _ = writeln!(out, "  = {}", label.message);
        return;
    };

    let position = sources.line_col(label.span).ok();
    let line = position.map_or(0, |pos| pos.line);
    let column = position.map_or(0, |pos| pos.column);
    let _ = writeln!(out, " --> {}:{line}:{column}", file.name());

    let Some(snippet) = line_snippet(file.text(), label.span.start()) else {
        let _ = writeln!(out, "  = {}", label.message);
        return;
    };

    let width = line_number_width(snippet.number);
    let gutter = " ".repeat(width);
    let _ = writeln!(out, "{gutter} |");
    let _ = writeln!(out, "{:>width$} | {}", snippet.number, snippet.text);

    let underline = underline_for(label.span, &snippet);
    if label.message.is_empty() {
        let _ = writeln!(out, "{gutter} | {underline}");
    } else {
        let _ = writeln!(out, "{gutter} | {underline} {}", label.message);
    }
}

fn line_snippet(text: &str, offset: u32) -> Option<LineSnippet<'_>> {
    let offset = usize::try_from(offset).ok()?.min(text.len());
    let before = text.get(..offset)?;
    let line_start = before
        .rfind('\n')
        .map_or(0, |index| index.saturating_add(1));
    let after = text.get(offset..)?;
    let line_end = offset.saturating_add(after.find('\n').unwrap_or(after.len()));
    let raw_line = text.get(line_start..line_end)?;
    let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
    let end = line_start.saturating_add(line.len());
    let number = u32::try_from(before.bytes().filter(|byte| *byte == b'\n').count())
        .map_or(u32::MAX, |count| count.saturating_add(1));
    Some(LineSnippet {
        number,
        start: line_start,
        end,
        text: line,
    })
}

fn underline_for(span: Span, snippet: &LineSnippet<'_>) -> String {
    let span_start = usize::try_from(span.start()).unwrap_or(usize::MAX);
    let span_end = usize::try_from(span.end()).unwrap_or(usize::MAX);
    let start = span_start
        .saturating_sub(snippet.start)
        .min(snippet.text.len());
    let end = span_end
        .min(snippet.end)
        .saturating_sub(snippet.start)
        .min(snippet.text.len());
    let marked = end.saturating_sub(start).max(1);

    let mut underline = String::new();
    if let Some(prefix) = snippet.text.get(..start) {
        push_visual_padding(&mut underline, prefix);
    } else {
        underline.extend(core::iter::repeat_n(' ', start));
    }

    let marker_count = snippet
        .text
        .get(start..end)
        .map_or(marked, |text| text.chars().count().max(1));
    underline.extend(core::iter::repeat_n('^', marker_count));
    underline
}

fn push_visual_padding(out: &mut String, text: &str) {
    for ch in text.chars() {
        out.push(if ch == '\t' { '\t' } else { ' ' });
    }
}

fn line_number_width(line: u32) -> usize {
    line.to_string().len()
}

#[cfg(test)]
mod tests {
    use super::{Diagnostic, Label, LineSnippet, Severity, underline_for};
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
        assert_eq!(
            rendered,
            "\
error: expected expression
 --> main.c:1:9
  |
1 | int x = ;
  |         ^ unexpected `;`
"
        );
    }

    #[test]
    fn render_without_labels() {
        let map = SourceMap::new();
        let diag = Diagnostic::note("just so you know");
        assert_eq!(
            diag.render(&map),
            "\
note: just so you know
"
        );
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
        assert_eq!(
            rendered,
            "\
error: missing
 --> <unknown>:0:0
  = there
"
        );
    }

    #[test]
    fn render_marks_wider_spans_and_later_lines() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "int x;\nreturn value;\n").unwrap();
        let rendered = Diagnostic::error("bad return")
            .with_label(Label::new(Span::new(file, 14, 19), "this value"))
            .render(&map);
        assert_eq!(
            rendered,
            "\
error: bad return
 --> main.c:2:8
  |
2 | return value;
  |        ^^^^^ this value
"
        );
    }

    #[test]
    fn render_points_at_empty_spans() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "int x\n").unwrap();
        let rendered = Diagnostic::error("expected `;`")
            .with_label(Label::new(Span::point(file, 5), "insert here"))
            .render(&map);
        assert_eq!(
            rendered,
            "\
error: expected `;`
 --> main.c:1:6
  |
1 | int x
  |      ^ insert here
"
        );
    }

    #[test]
    fn render_falls_back_when_snippet_starts_inside_utf8_codepoint() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "é\n").unwrap();
        let rendered = Diagnostic::error("invalid byte boundary")
            .with_label(Label::new(Span::point(file, 1), "inside `é`"))
            .render(&map);
        assert_eq!(
            rendered,
            "\
error: invalid byte boundary
 --> main.c:1:2
  = inside `é`
"
        );
    }

    #[test]
    fn render_omits_empty_label_message() {
        let mut map = SourceMap::new();
        let file = map.add_root("main.c", "abc\n").unwrap();
        let rendered = Diagnostic::error("plain marker")
            .with_label(Label::new(Span::new(file, 1, 2), ""))
            .render(&map);
        assert_eq!(
            rendered,
            "\
error: plain marker
 --> main.c:1:2
  |
1 | abc
  |  ^
"
        );
    }

    #[test]
    fn underline_handles_unaligned_and_tabbed_prefixes() {
        let file = FileId::from_raw(0);
        let unaligned = LineSnippet {
            number: 1,
            start: 0,
            end: 3,
            text: "éx",
        };
        assert_eq!(underline_for(Span::new(file, 1, 2), &unaligned), " ^");

        let tabbed = LineSnippet {
            number: 1,
            start: 0,
            end: 3,
            text: "\tab",
        };
        assert_eq!(underline_for(Span::new(file, 2, 3), &tabbed), "\t ^");
    }
}
