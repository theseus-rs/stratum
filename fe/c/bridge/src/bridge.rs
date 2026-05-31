//! The C frontend's [`HirBridge`] implementation: the bidirectional seam between the private
//! C AST and the shared HIR.

use crate::alloc_prelude::*;
use crate::raise::raise as raise_source;
use stratum_c_ast::CAst;
use stratum_hir::{HirBridge, HirContext, HirNodeId};

/// A zero-sized marker implementing [`HirBridge`] for the C frontend.
///
/// [`lower`](HirBridge::lower) converges a [`CAst`] into HIR (delegating to the lowering
/// driver), and [`raise`](HirBridge::raise) reconstructs C source from HIR.
///
/// The diagnostic-rich [`lower`](crate::lower::lower) free function remains the production
/// entry point: it returns a [`LowerResult`](crate::lower::LowerResult) carrying both the HIR
/// and any diagnostics. The trait path here returns only the root node id and is intended for
/// uses that drive both directions through the shared [`HirBridge`] contract.
#[derive(Debug, Default, Clone, Copy)]
pub struct CBridge;

impl HirBridge for CBridge {
    type Ast = CAst;
    type Error = crate::error::Error;

    fn lower(&self, ast: &CAst, cx: &mut HirContext) -> crate::error::Result<HirNodeId> {
        let lowering = crate::lower::CLowering::new(ast);
        let (root, _diagnostics) = lowering.run(cx)?;
        cx.set_root(root);
        Ok(root)
    }

    fn raise(&self, cx: &HirContext) -> crate::error::Result<String> {
        raise_source(cx)
    }
}
