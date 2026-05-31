//! The C AST container: a node arena with parallel spans and an interner.

use crate::alloc_prelude::*;
use crate::node::CNode;
use core::ops::Index;
use stratum_arena::{Arena, Id, Interner, Symbol};
use stratum_diagnostics::Span;

/// Identifies a [`CNode`] within a [`CAst`].
pub type CNodeId = Id<CNode>;

/// Owns every node, span, and interned string for one parsed translation unit.
///
/// Mirrors the data-oriented design of the HIR: nodes live in a flat arena and refer to
/// each other by [`CNodeId`], with source spans kept in a parallel vector.
///
/// # Examples
///
/// ```
/// use stratum_c_ast::{CAst, CNode};
/// use stratum_diagnostics::{SourceMap, Span};
///
/// let mut map = SourceMap::new();
/// let file = map.add_root("t.c", "42").unwrap();
/// let mut ast = CAst::new();
/// let sym = ast.intern("42").unwrap();
/// let lit = ast.alloc(CNode::IntLiteral(sym), Span::new(file, 0, 2)).unwrap();
/// assert_eq!(ast.node(lit), &CNode::IntLiteral(sym));
/// ```
#[derive(Debug)]
pub struct CAst {
    interner: Interner,
    nodes: Arena<CNode>,
    spans: Vec<Span>,
    root: Option<CNodeId>,
}

impl CAst {
    /// Creates an empty AST.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interner: Interner::new(),
            nodes: Arena::new(),
            spans: Vec::new(),
            root: None,
        }
    }

    /// Creates an empty AST that reuses an existing interner.
    ///
    /// This is used by the parser so that [`Symbol`]s carried by the token stream (which were
    /// interned earlier in the pipeline) resolve correctly against the AST's interner.
    #[must_use]
    pub fn with_interner(interner: Interner) -> Self {
        Self {
            interner,
            nodes: Arena::new(),
            spans: Vec::new(),
            root: None,
        }
    }

    /// Interns `text`.
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn intern(&mut self, text: &str) -> crate::Result<Symbol> {
        Ok(self.interner.intern(text)?)
    }

    /// Resolves a [`Symbol`] to its string.
    ///
    /// # Errors
    ///
    /// Returns an error if `symbol` was not produced by this AST.
    pub fn resolve(&self, symbol: Symbol) -> crate::Result<&str> {
        Ok(self.interner.resolve(symbol)?)
    }

    /// Returns the interner backing this AST.
    #[must_use]
    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    /// Allocates a node with its span and returns the id.
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn alloc(&mut self, node: CNode, span: Span) -> crate::Result<CNodeId> {
        let id = self.nodes.alloc(node)?;
        self.spans.push(span);
        Ok(id)
    }

    /// Returns the node for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this AST.
    #[must_use]
    pub fn node(&self, id: CNodeId) -> &CNode {
        self.nodes.index(id)
    }

    /// Returns the span for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this AST.
    #[must_use]
    pub fn span(&self, id: CNodeId) -> Span {
        *self.spans.index(id.index())
    }

    /// Returns the number of nodes allocated.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Sets the root node (typically a [`CNode::TranslationUnit`]).
    pub fn set_root(&mut self, root: CNodeId) {
        self.root = Some(root);
    }

    /// Returns the root node id, if set.
    #[must_use]
    pub fn root(&self) -> Option<CNodeId> {
        self.root
    }
}

impl Default for CAst {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::alloc_prelude::*;
    use crate::node::CNode;
    use crate::tree::CAst;
    use stratum_diagnostics::{SourceMap, Span};

    #[test]
    fn alloc_and_lookup() {
        let mut map = SourceMap::new();
        let file = map.add_root("t.c", "ab").unwrap();
        let s = Span::new(file, 0, 2);
        let mut ast = CAst::new();
        let sym = ast.intern("ab").unwrap();
        let id = ast.alloc(CNode::Ident(sym), s).unwrap();
        assert_eq!(ast.node(id), &CNode::Ident(sym));
        assert_eq!(ast.span(id), s);
        assert_eq!(ast.node_count(), 1);
    }

    #[test]
    fn root_round_trips() {
        let mut map = SourceMap::new();
        let file = map.add_root("t.c", "").unwrap();
        let mut ast = CAst::new();
        assert_eq!(ast.root(), None);
        let tu = ast
            .alloc(CNode::TranslationUnit(Vec::new()), Span::point(file, 0))
            .unwrap();
        ast.set_root(tu);
        assert_eq!(ast.root(), Some(tu));
    }

    #[test]
    fn interner_and_default_are_accessible() {
        let mut ast = CAst::default();
        let sym = ast.intern("name").unwrap();
        assert_eq!(ast.resolve(sym).unwrap(), "name");
        assert_eq!(ast.interner().resolve(sym).unwrap(), "name");
    }
}
