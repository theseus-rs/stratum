//! The bidirectional bridge between a language AST and the shared HIR.

use crate::alloc_prelude::*;
use crate::context::{HirContext, HirNodeId};

/// Implemented by a language frontend to translate, in both directions, between its private
/// AST and the shared HIR.
///
/// Each frontend keeps its own private AST and provides an implementation of this trait (or
/// an internal driver that fulfils the same contract). The implementor is typically a
/// zero-sized *marker* type rather than the AST itself, because the two directions are not
/// symmetric in their inputs:
///
/// - [`lower`](HirBridge::lower) walks a borrowed AST and writes nodes into a [`HirContext`].
///   This is the single seam at which language-specific structure is dissolved: everything
///   downstream sees only HIR.
/// - [`raise`](HirBridge::raise) walks a populated [`HirContext`] and reconstructs equivalent
///   source text, proving the HIR retained enough structure to round-trip.
///
/// Lowering implementations should emit *unresolved* names
/// ([`HirNode::Name`](crate::HirNode::Name)) rather than attempting symbol or type
/// resolution, which is the responsibility of a later pass. [`lower`](HirBridge::lower) is
/// expected to set the context root (via [`HirContext::set_root`]) so that a subsequent
/// [`raise`](HirBridge::raise) can find it.
///
/// # Examples
///
/// ```
/// use stratum_hir::{HirBridge, HirContext, HirNode, HirNodeId};
/// use stratum_diagnostics::{SourceMap, Span};
///
/// // A trivial "AST" that holds a single integer literal.
/// struct LitAst {
///     value: i128,
///     span: Span,
/// }
///
/// // A zero-sized marker that bridges `LitAst` and the HIR in both directions.
/// struct LitBridge;
///
/// impl HirBridge for LitBridge {
///     type Ast = LitAst;
///     type Error = stratum_hir::Error;
///
///     fn lower(&self, ast: &LitAst, cx: &mut HirContext) -> Result<HirNodeId, Self::Error> {
///         let id = cx.alloc(HirNode::IntLiteral(ast.value), ast.span)?;
///         cx.set_root(id);
///         Ok(id)
///     }
///
///     fn raise(&self, cx: &HirContext) -> Result<String, Self::Error> {
///         match cx.root().map(|root| cx.node(root)) {
///             Some(HirNode::IntLiteral(value)) => Ok(value.to_string()),
///             _ => Ok(String::new()),
///         }
///     }
/// }
///
/// let mut map = SourceMap::new();
/// let file = map.add_root("t", "7")?;
/// let ast = LitAst { value: 7, span: Span::new(file, 0, 1) };
/// let bridge = LitBridge;
/// let mut hir = HirContext::new();
/// let id = bridge.lower(&ast, &mut hir)?;
/// assert_eq!(hir.node(id), &HirNode::IntLiteral(7));
/// assert_eq!(bridge.raise(&hir)?, "7");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait HirBridge {
    /// The frontend's private AST type, consumed by [`lower`](HirBridge::lower).
    type Ast;

    /// Error returned by either direction of this bridge.
    type Error;

    /// Lowers `ast` into `cx`, returning the id of the produced root node.
    ///
    /// Implementations should set the context root (via [`HirContext::set_root`]) to the
    /// returned id (or the enclosing module) so that [`raise`](HirBridge::raise) can locate
    /// it afterwards.
    ///
    /// # Errors
    ///
    /// Returns an error if lowering cannot allocate HIR storage or if the source structure is
    /// invalid for the frontend.
    fn lower(
        &self,
        ast: &Self::Ast,
        cx: &mut HirContext,
    ) -> core::result::Result<HirNodeId, Self::Error>;

    /// Raises the HIR held in `cx` back into source text for this frontend's language.
    ///
    /// # Errors
    ///
    /// Returns an error if the HIR is malformed for this language (for example, a node
    /// appearing in a position it cannot occupy) or if a symbol cannot be resolved.
    fn raise(&self, cx: &HirContext) -> core::result::Result<String, Self::Error>;
}
