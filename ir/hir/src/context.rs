//! The HIR container: arenas for nodes and types plus parallel spans.

use crate::alloc_prelude::*;
use crate::node::HirNode;
use crate::types::HirType;
use core::ops::Index;
use stratum_arena::{Arena, Id, Interner, Symbol};
use stratum_diagnostics::Span;

/// Identifies an [`HirNode`] within a [`HirContext`].
pub type HirNodeId = Id<HirNode>;

/// Identifies an [`HirType`] within a [`HirContext`].
pub type HirTypeId = Id<HirType>;

/// Owns every node, type, span, and interned string for one HIR program.
///
/// A `HirContext` is the single source of truth a lowering pass writes into and that later
/// stages read from. Nodes are addressed by [`HirNodeId`]; their source locations live in a
/// parallel `spans` vector so the node enum stays compact.
///
/// # Examples
///
/// ```
/// use stratum_hir::{HirContext, HirNode};
/// use stratum_diagnostics::{SourceMap, Span};
///
/// let mut map = SourceMap::new();
/// let file = map.add_root("t.c", "1").unwrap();
/// let mut hir = HirContext::new();
/// let lit = hir.alloc(HirNode::IntLiteral(1), Span::new(file, 0, 1)).unwrap();
/// assert_eq!(hir.node(lit), &HirNode::IntLiteral(1));
/// ```
#[derive(Debug)]
pub struct HirContext {
    interner: Interner,
    types: Arena<HirType>,
    nodes: Arena<HirNode>,
    spans: Vec<Span>,
    root: Option<HirNodeId>,
}

impl HirContext {
    /// Creates an empty HIR context.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interner: Interner::new(),
            types: Arena::new(),
            nodes: Arena::new(),
            spans: Vec::new(),
            root: None,
        }
    }

    /// Interns `text`, returning a reusable [`Symbol`].
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn intern(&mut self, text: &str) -> crate::Result<Symbol> {
        Ok(self.interner.intern(text)?)
    }

    /// Resolves a [`Symbol`] back to its string.
    ///
    /// # Errors
    ///
    /// Returns an error if `symbol` was not produced by this context.
    pub fn resolve(&self, symbol: Symbol) -> crate::Result<&str> {
        Ok(self.interner.resolve(symbol)?)
    }

    /// Returns the shared interner, mainly for dumping and debugging.
    #[must_use]
    pub fn interner(&self) -> &Interner {
        &self.interner
    }

    /// Allocates a type and returns its id.
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn alloc_type(&mut self, ty: HirType) -> crate::Result<HirTypeId> {
        Ok(self.types.alloc(ty)?)
    }

    /// Returns the type for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this context.
    #[must_use]
    pub fn ty(&self, id: HirTypeId) -> &HirType {
        self.types.index(id)
    }

    /// Allocates a node with its source span and returns its id.
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn alloc(&mut self, node: HirNode, span: Span) -> crate::Result<HirNodeId> {
        let id = self.nodes.alloc(node)?;
        self.spans.push(span);
        Ok(id)
    }

    /// Returns the node for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this context.
    #[must_use]
    pub fn node(&self, id: HirNodeId) -> &HirNode {
        self.nodes.index(id)
    }

    /// Returns the source span for `id`.
    ///
    /// # Panics
    ///
    /// Panics if `id` does not belong to this context.
    #[must_use]
    pub fn span(&self, id: HirNodeId) -> Span {
        *self.spans.index(id.index())
    }

    /// Returns the number of nodes allocated.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Sets the root node of the program (typically a [`HirNode::Module`]).
    pub fn set_root(&mut self, root: HirNodeId) {
        self.root = Some(root);
    }

    /// Returns the root node id, if one has been set.
    #[must_use]
    pub fn root(&self) -> Option<HirNodeId> {
        self.root
    }
}

impl Default for HirContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::HirContext;
    use crate::alloc_prelude::*;
    use crate::node::HirNode;
    use crate::types::{HirType, IntWidth};
    use stratum_diagnostics::{SourceMap, Span};

    fn span() -> Span {
        let mut map = SourceMap::new();
        let file = map.add_root("t.c", "int main(void){return 0;}").unwrap();
        Span::new(file, 0, 1)
    }

    #[test]
    fn alloc_tracks_spans() {
        let mut hir = HirContext::new();
        let s = span();
        let a = hir.alloc(HirNode::IntLiteral(1), s).unwrap();
        let b = hir.alloc(HirNode::IntLiteral(2), s).unwrap();
        assert_eq!(hir.node(a), &HirNode::IntLiteral(1));
        assert_eq!(hir.node(b), &HirNode::IntLiteral(2));
        assert_eq!(hir.span(a), s);
        assert_eq!(hir.node_count(), 2);
    }

    #[test]
    fn interning_round_trips() {
        let mut hir = HirContext::new();
        let sym = hir.intern("main").unwrap();
        assert_eq!(hir.resolve(sym).unwrap(), "main");
        assert_eq!(hir.interner().resolve(sym).unwrap(), "main");
    }

    #[test]
    fn types_are_stored() {
        let mut hir = HirContext::new();
        let ty = hir
            .alloc_type(HirType::Int {
                signed: true,
                width: IntWidth::W32,
            })
            .unwrap();
        assert_eq!(
            hir.ty(ty),
            &HirType::Int {
                signed: true,
                width: IntWidth::W32
            }
        );
    }

    #[test]
    fn root_round_trips() {
        let mut hir = HirContext::new();
        assert_eq!(hir.root(), None);
        let m = hir.alloc(HirNode::Module(Vec::new()), span()).unwrap();
        hir.set_root(m);
        assert_eq!(hir.root(), Some(m));
    }

    #[test]
    fn default_constructs_empty_context() {
        let hir = HirContext::default();
        assert_eq!(hir.node_count(), 0);
        assert_eq!(hir.root(), None);
    }
}
