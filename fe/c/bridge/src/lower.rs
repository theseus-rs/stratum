//! The lowering driver: walks a [`CAst`] and emits [`HirNode`]s into a [`HirContext`].

use crate::alloc_prelude::*;
use stratum_arena::Symbol as CSymbol;
use stratum_c_ast::{
    CAst, CNode, CNodeId, DeclSpecifiers, Declarator, Derivation, Designator as CDesignator,
    Enumerator, FieldDecl, InitDeclarator, StorageClass, TypeSpecifier,
};
use stratum_diagnostics::{Diagnostic, Label, Span};
use stratum_hir::{
    DeclFlags, EnumVariant, Field, HirContext, HirInit, HirNode, HirNodeId, InitEntry, IntWidth,
    Param, RecordKind, StorageClass as HirStorage,
};

/// The result of lowering a translation unit into HIR.
#[derive(Debug)]
pub struct LowerResult {
    /// The populated HIR context. Its root is the lowered `Module`.
    pub hir: HirContext,
    /// Diagnostics emitted during lowering (invalid literals, etc.).
    pub diagnostics: Vec<Diagnostic>,
}

impl LowerResult {
    /// Returns `true` if any error-severity diagnostics were produced.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity() == stratum_diagnostics::Severity::Error)
    }
}

/// Lowers `ast` into a fresh [`HirContext`], returning it alongside any diagnostics.
///
/// # Errors
///
/// Returns an error if lowering cannot resolve an AST symbol or allocate HIR storage.
pub fn lower(ast: &CAst) -> crate::error::Result<LowerResult> {
    lower_with_data_model(ast, CDataModel::default())
}

/// Lowers `ast` using an explicit C data model for implementation-defined integer layout.
///
/// # Errors
///
/// Returns an error if lowering cannot resolve an AST symbol or allocate HIR storage.
pub fn lower_with_data_model(
    ast: &CAst,
    data_model: CDataModel,
) -> crate::error::Result<LowerResult> {
    let mut hir = HirContext::new();
    let lowering = CLowering::with_data_model(ast, data_model);
    let (root, diagnostics) = lowering.run(&mut hir)?;
    hir.set_root(root);
    Ok(LowerResult { hir, diagnostics })
}

/// C implementation choices needed when lowering source types to concrete HIR widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CDataModel {
    /// Whether plain `char` lowers as signed.
    pub plain_char_signed: bool,
    /// Width of `short`.
    pub short_width: IntWidth,
    /// Width of `int`.
    pub int_width: IntWidth,
    /// Width of `long`.
    pub long_width: IntWidth,
    /// Width of `long long`.
    pub long_long_width: IntWidth,
}

impl CDataModel {
    /// LP64 data model used by most Unix-like 64-bit targets.
    #[must_use]
    pub const fn lp64() -> Self {
        Self {
            plain_char_signed: true,
            short_width: IntWidth::W16,
            int_width: IntWidth::W32,
            long_width: IntWidth::W64,
            long_long_width: IntWidth::W64,
        }
    }

    /// LLP64 data model used by 64-bit Windows targets.
    #[must_use]
    pub const fn llp64() -> Self {
        Self {
            plain_char_signed: true,
            short_width: IntWidth::W16,
            int_width: IntWidth::W32,
            long_width: IntWidth::W32,
            long_long_width: IntWidth::W64,
        }
    }
}

impl Default for CDataModel {
    fn default() -> Self {
        Self::lp64()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CGenericType {
    Void,
    Bool,
    PlainChar,
    SignedInteger(IntegerRank),
    UnsignedInteger(IntegerRank),
    Float(FloatRank),
    Pointer(Box<CGenericType>),
    Array(Box<CGenericType>),
    Function {
        params: Vec<CGenericType>,
        ret: Box<CGenericType>,
        variadic: bool,
    },
    Tag {
        kind: CGenericTag,
        name: Option<CSymbol>,
    },
    Named(CSymbol),
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CGenericTag {
    Struct,
    Union,
    Enum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IntegerRank {
    Char,
    Short,
    Int,
    Long,
    LongLong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloatRank {
    Float,
    Double,
    LongDouble,
    Decimal32,
    Decimal64,
    Decimal128,
}

/// The lowering driver for the C frontend.
///
/// It walks the [`CAst`] and emits HIR nodes into a [`HirContext`], accumulating diagnostics
/// as it goes. The bidirectional seam is [`CBridge`](crate::bridge::CBridge), which delegates
/// its `lower` direction here.
#[derive(Debug)]
pub struct CLowering<'a> {
    pub(crate) ast: &'a CAst,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) data_model: CDataModel,
    scopes: Vec<Vec<(CSymbol, CGenericType)>>,
    type_aliases: Vec<Vec<(CSymbol, CGenericType)>>,
}

impl<'a> CLowering<'a> {
    /// Creates a lowering driver over `ast`.
    #[must_use]
    pub fn new(ast: &'a CAst) -> Self {
        Self::with_data_model(ast, CDataModel::default())
    }

    /// Creates a lowering driver over `ast` using an explicit data model.
    #[must_use]
    pub fn with_data_model(ast: &'a CAst, data_model: CDataModel) -> Self {
        Self {
            ast,
            diagnostics: Vec::new(),
            data_model,
            scopes: vec![Vec::new()],
            type_aliases: vec![Vec::new()],
        }
    }

    /// Lowers the whole translation unit, returning the module node id and diagnostics.
    pub(crate) fn run(
        mut self,
        cx: &mut HirContext,
    ) -> crate::error::Result<(HirNodeId, Vec<Diagnostic>)> {
        let root = self.lower_module(cx)?;
        Ok((root, self.diagnostics))
    }

    pub(crate) fn error(&mut self, span: Span, message: &str) {
        self.diagnostics
            .push(Diagnostic::error(message.to_string()).with_label(Label::new(span, "here")));
    }

    pub(crate) fn generic_expr_type(&self, id: CNodeId) -> Option<CGenericType> {
        match self.ast.node(id) {
            CNode::Binary { op, lhs, rhs } => self.generic_binary_type(*op, *lhs, *rhs),
            CNode::Unary { op, operand } => match op {
                stratum_c_ast::UnaryOp::AddressOf => self
                    .generic_expr_type_unadjusted(*operand)
                    .map(|ty| CGenericType::Pointer(Box::new(ty))),
                stratum_c_ast::UnaryOp::Deref => match self.generic_expr_type(*operand)? {
                    CGenericType::Pointer(inner) => Some(Self::adjust_generic_type(*inner)),
                    _ => None,
                },
                _ => self.generic_expr_type(*operand),
            },
            CNode::Conditional {
                then_expr,
                else_expr,
                ..
            } => {
                let then_ty = self.generic_expr_type(*then_expr)?;
                let else_ty = self.generic_expr_type(*else_expr)?;
                self.generic_types_compatible(&then_ty, &else_ty)
                    .then(|| self.composite_generic_type(&then_ty, &else_ty))
            }
            CNode::Comma { rhs, .. } => self.generic_expr_type(*rhs),
            _ => self
                .generic_expr_type_unadjusted(id)
                .map(Self::adjust_generic_type),
        }
    }

    fn generic_expr_type_unadjusted(&self, id: CNodeId) -> Option<CGenericType> {
        match self.ast.node(id) {
            CNode::Ident(sym) => self.lookup_type(*sym),
            CNode::IntLiteral(sym) => self.integer_literal_type(*sym),
            CNode::CharLiteral(_) => Some(CGenericType::SignedInteger(IntegerRank::Int)),
            CNode::BoolLiteral(_) => Some(CGenericType::Bool),
            CNode::FloatLiteral(sym) => self.float_literal_type(*sym),
            CNode::StringLiteral(_) => Some(CGenericType::Array(Box::new(CGenericType::PlainChar))),
            CNode::Nullptr => Some(CGenericType::Pointer(Box::new(CGenericType::Void))),
            CNode::Cast { type_name, .. } => Some(Self::generic_type_from_declaration(
                &type_name.specifiers,
                &type_name.declarator.derivations,
            )),
            CNode::Binary { .. }
            | CNode::Unary { .. }
            | CNode::Conditional { .. }
            | CNode::Comma { .. } => self.generic_expr_type(id),
            _ => None,
        }
    }

    pub(crate) fn generic_type_from_declaration(
        specifiers: &DeclSpecifiers,
        derivations: &[Derivation],
    ) -> CGenericType {
        let mut ty = Self::generic_base_type(specifiers);
        for derivation in derivations.iter().rev() {
            ty = Self::apply_generic_derivation(ty, derivation);
        }
        ty
    }

    fn apply_generic_derivation(inner: CGenericType, derivation: &Derivation) -> CGenericType {
        match derivation {
            Derivation::Pointer { .. } => CGenericType::Pointer(Box::new(inner)),
            Derivation::Array { .. } => CGenericType::Array(Box::new(inner)),
            Derivation::Function { params, variadic } => CGenericType::Function {
                params: params
                    .iter()
                    .map(|param| {
                        Self::generic_type_from_declaration(
                            &param.specifiers,
                            &param.declarator.derivations,
                        )
                    })
                    .collect(),
                ret: Box::new(inner),
                variadic: *variadic,
            },
        }
    }

    fn adjust_generic_type(ty: CGenericType) -> CGenericType {
        match ty {
            CGenericType::Array(element) => CGenericType::Pointer(element),
            CGenericType::Function {
                params,
                ret,
                variadic,
            } => CGenericType::Pointer(Box::new(CGenericType::Function {
                params,
                ret,
                variadic,
            })),
            other => other,
        }
    }

    pub(crate) fn generic_types_compatible(&self, lhs: &CGenericType, rhs: &CGenericType) -> bool {
        self.canonical_generic_type(lhs, 0) == self.canonical_generic_type(rhs, 0)
    }

    fn composite_generic_type(&self, lhs: &CGenericType, rhs: &CGenericType) -> CGenericType {
        let lhs = self.canonical_generic_type(lhs, 0);
        let rhs = self.canonical_generic_type(rhs, 0);
        if lhs == rhs { lhs } else { CGenericType::Other }
    }

    fn canonical_generic_type(&self, ty: &CGenericType, depth: usize) -> CGenericType {
        if depth > 32 {
            return CGenericType::Other;
        }
        match ty {
            CGenericType::Pointer(inner) => {
                CGenericType::Pointer(Box::new(self.canonical_generic_type(inner, depth + 1)))
            }
            CGenericType::Array(inner) => {
                CGenericType::Array(Box::new(self.canonical_generic_type(inner, depth + 1)))
            }
            CGenericType::Function {
                params,
                ret,
                variadic,
            } => CGenericType::Function {
                params: params
                    .iter()
                    .map(|param| self.canonical_generic_type(param, depth + 1))
                    .collect(),
                ret: Box::new(self.canonical_generic_type(ret, depth + 1)),
                variadic: *variadic,
            },
            CGenericType::Named(sym) => self.lookup_alias(*sym).map_or_else(
                || ty.clone(),
                |aliased| self.canonical_generic_type(&aliased, depth + 1),
            ),
            other => other.clone(),
        }
    }

    fn generic_binary_type(
        &self,
        op: stratum_c_ast::BinaryOp,
        lhs: CNodeId,
        rhs: CNodeId,
    ) -> Option<CGenericType> {
        use stratum_c_ast::BinaryOp;
        let lhs_ty = self.generic_expr_type(lhs)?;
        let rhs_ty = self.generic_expr_type(rhs)?;
        match op {
            BinaryOp::Lt
            | BinaryOp::Gt
            | BinaryOp::Le
            | BinaryOp::Ge
            | BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::LogicalAnd
            | BinaryOp::LogicalOr => Some(CGenericType::SignedInteger(IntegerRank::Int)),
            BinaryOp::Add => match (&lhs_ty, &rhs_ty) {
                (CGenericType::Pointer(_), ty) if Self::is_integer_type(ty) => Some(lhs_ty),
                (ty, CGenericType::Pointer(_)) if Self::is_integer_type(ty) => Some(rhs_ty),
                _ => Self::usual_arithmetic_type(&lhs_ty, &rhs_ty),
            },
            BinaryOp::Sub => match (&lhs_ty, &rhs_ty) {
                (CGenericType::Pointer(_), ty) if Self::is_integer_type(ty) => Some(lhs_ty),
                (CGenericType::Pointer(_), CGenericType::Pointer(_)) => {
                    Some(CGenericType::SignedInteger(IntegerRank::Long))
                }
                _ => Self::usual_arithmetic_type(&lhs_ty, &rhs_ty),
            },
            BinaryOp::Shl | BinaryOp::Shr => Self::integer_promote(&lhs_ty),
            BinaryOp::BitAnd | BinaryOp::BitXor | BinaryOp::BitOr | BinaryOp::Rem => {
                Self::usual_integer_type(&lhs_ty, &rhs_ty)
            }
            BinaryOp::Mul | BinaryOp::Div => Self::usual_arithmetic_type(&lhs_ty, &rhs_ty),
        }
    }

    fn usual_arithmetic_type(lhs: &CGenericType, rhs: &CGenericType) -> Option<CGenericType> {
        match (lhs, rhs) {
            (CGenericType::Float(lhs), CGenericType::Float(rhs)) => {
                Some(CGenericType::Float(Self::max_float_rank(*lhs, *rhs)))
            }
            (CGenericType::Float(rank), ty) | (ty, CGenericType::Float(rank))
                if Self::is_integer_type(ty) =>
            {
                Some(CGenericType::Float(*rank))
            }
            (lhs, rhs) => Self::usual_integer_type(lhs, rhs),
        }
    }

    fn usual_integer_type(lhs: &CGenericType, rhs: &CGenericType) -> Option<CGenericType> {
        let (lhs_signed, lhs_rank) = Self::integer_promote_rank(lhs)?;
        let (rhs_signed, rhs_rank) = Self::integer_promote_rank(rhs)?;
        let rank = Self::max_integer_rank(lhs_rank, rhs_rank);
        if lhs_signed && rhs_signed {
            Some(CGenericType::SignedInteger(rank))
        } else {
            Some(CGenericType::UnsignedInteger(rank))
        }
    }

    fn integer_promote(ty: &CGenericType) -> Option<CGenericType> {
        let (signed, rank) = Self::integer_promote_rank(ty)?;
        if signed {
            Some(CGenericType::SignedInteger(rank))
        } else {
            Some(CGenericType::UnsignedInteger(rank))
        }
    }

    fn integer_promote_rank(ty: &CGenericType) -> Option<(bool, IntegerRank)> {
        match ty {
            CGenericType::Bool
            | CGenericType::PlainChar
            | CGenericType::SignedInteger(IntegerRank::Char | IntegerRank::Short)
            | CGenericType::UnsignedInteger(IntegerRank::Char | IntegerRank::Short) => {
                Some((true, IntegerRank::Int))
            }
            CGenericType::SignedInteger(rank) => Some((true, *rank)),
            CGenericType::UnsignedInteger(rank) => Some((false, *rank)),
            _ => None,
        }
    }

    fn is_integer_type(ty: &CGenericType) -> bool {
        matches!(
            ty,
            CGenericType::Bool
                | CGenericType::PlainChar
                | CGenericType::SignedInteger(_)
                | CGenericType::UnsignedInteger(_)
        )
    }

    fn max_integer_rank(lhs: IntegerRank, rhs: IntegerRank) -> IntegerRank {
        use IntegerRank::{Char, Int, Long, LongLong, Short};
        match (lhs, rhs) {
            (LongLong, _) | (_, LongLong) => LongLong,
            (Long, _) | (_, Long) => Long,
            (Int, _) | (_, Int) => Int,
            (Short, _) | (_, Short) => Short,
            (Char, Char) => Char,
        }
    }

    fn max_float_rank(lhs: FloatRank, rhs: FloatRank) -> FloatRank {
        use FloatRank::{Decimal32, Decimal64, Decimal128, Double, Float, LongDouble};
        match (lhs, rhs) {
            (Decimal128, _) | (_, Decimal128) => Decimal128,
            (Decimal64, _) | (_, Decimal64) => Decimal64,
            (Decimal32, _) | (_, Decimal32) => Decimal32,
            (LongDouble, _) | (_, LongDouble) => LongDouble,
            (Double, _) | (_, Double) => Double,
            (Float, Float) => Float,
        }
    }

    fn generic_base_type(specifiers: &DeclSpecifiers) -> CGenericType {
        let specs = &specifiers.type_specifiers;
        if specs.contains(&TypeSpecifier::Void) {
            return CGenericType::Void;
        }
        if specs.contains(&TypeSpecifier::Bool) {
            return CGenericType::Bool;
        }
        if specs.contains(&TypeSpecifier::Decimal128) {
            return CGenericType::Float(FloatRank::Decimal128);
        }
        if specs.contains(&TypeSpecifier::Decimal64) {
            return CGenericType::Float(FloatRank::Decimal64);
        }
        if specs.contains(&TypeSpecifier::Decimal32) {
            return CGenericType::Float(FloatRank::Decimal32);
        }
        if specs.contains(&TypeSpecifier::Double) {
            return CGenericType::Float(if specs.contains(&TypeSpecifier::Long) {
                FloatRank::LongDouble
            } else {
                FloatRank::Double
            });
        }
        if specs.contains(&TypeSpecifier::Float) {
            return CGenericType::Float(FloatRank::Float);
        }
        if specs.contains(&TypeSpecifier::Char) {
            return if specs.contains(&TypeSpecifier::Signed) {
                CGenericType::SignedInteger(IntegerRank::Char)
            } else if specs.contains(&TypeSpecifier::Unsigned) {
                CGenericType::UnsignedInteger(IntegerRank::Char)
            } else {
                CGenericType::PlainChar
            };
        }
        if let Some(named) = specs.iter().find_map(|spec| match spec {
            TypeSpecifier::TypedefName(sym) => Some(*sym),
            _ => None,
        }) {
            return CGenericType::Named(named);
        }
        if let Some(tag) = specs.iter().find_map(|spec| match spec {
            TypeSpecifier::Struct { tag, .. } => Some(CGenericType::Tag {
                kind: CGenericTag::Struct,
                name: *tag,
            }),
            TypeSpecifier::Union { tag, .. } => Some(CGenericType::Tag {
                kind: CGenericTag::Union,
                name: *tag,
            }),
            TypeSpecifier::Enum { tag, .. } => Some(CGenericType::Tag {
                kind: CGenericTag::Enum,
                name: *tag,
            }),
            TypeSpecifier::Atomic(type_name) => Some(Self::generic_type_from_declaration(
                &type_name.specifiers,
                &type_name.declarator.derivations,
            )),
            _ => None,
        }) {
            return tag;
        }
        if specs.iter().any(|spec| {
            matches!(
                spec,
                TypeSpecifier::Complex
                    | TypeSpecifier::Imaginary
                    | TypeSpecifier::BitInt(_)
                    | TypeSpecifier::Typeof { .. }
            )
        }) {
            return CGenericType::Other;
        }
        let rank = integer_rank(specs);
        if specs.contains(&TypeSpecifier::Unsigned) {
            CGenericType::UnsignedInteger(rank)
        } else {
            CGenericType::SignedInteger(rank)
        }
    }

    pub(crate) fn push_scope(&mut self) {
        self.scopes.push(Vec::new());
        self.type_aliases.push(Vec::new());
    }

    pub(crate) fn pop_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
        if self.type_aliases.len() > 1 {
            self.type_aliases.pop();
        }
    }

    fn define_type(&mut self, name: CSymbol, ty: CGenericType) {
        if self.scopes.is_empty() {
            self.scopes.push(Vec::new());
        }
        let mut scope = self.scopes.pop().unwrap_or_default();
        if let Some((_, existing)) = scope.iter_mut().find(|(symbol, _)| *symbol == name) {
            *existing = ty;
        } else {
            scope.push((name, ty));
        }
        self.scopes.push(scope);
    }

    fn lookup_type(&self, name: CSymbol) -> Option<CGenericType> {
        self.scopes
            .iter()
            .rev()
            .find_map(|scope| scope.iter().rev().find(|(symbol, _)| *symbol == name))
            .map(|(_, ty)| ty.clone())
    }

    fn define_alias(&mut self, name: CSymbol, ty: CGenericType) {
        if self.type_aliases.is_empty() {
            self.type_aliases.push(Vec::new());
        }
        let mut scope = self.type_aliases.pop().unwrap_or_default();
        if let Some((_, existing)) = scope.iter_mut().find(|(symbol, _)| *symbol == name) {
            *existing = ty;
        } else {
            scope.push((name, ty));
        }
        self.type_aliases.push(scope);
    }

    fn lookup_alias(&self, name: CSymbol) -> Option<CGenericType> {
        self.type_aliases
            .iter()
            .rev()
            .find_map(|scope| scope.iter().rev().find(|(symbol, _)| *symbol == name))
            .map(|(_, ty)| ty.clone())
    }

    fn define_declarator_type(&mut self, specifiers: &DeclSpecifiers, declarator: &Declarator) {
        let Some(name) = declarator.name else {
            return;
        };
        let ty = Self::generic_type_from_declaration(specifiers, &declarator.derivations);
        self.define_type(name, ty);
    }

    fn define_function_parameters(&mut self, declarator: &Declarator) {
        for derivation in &declarator.derivations {
            let Derivation::Function { params, .. } = derivation else {
                continue;
            };
            for param in params {
                self.define_declarator_type(&param.specifiers, &param.declarator);
            }
        }
    }

    fn integer_literal_type(&self, sym: CSymbol) -> Option<CGenericType> {
        let raw = self.ast.resolve(sym).ok()?;
        let unsigned = raw.contains('u') || raw.contains('U');
        let rank = integer_suffix_rank(raw);
        Some(if unsigned {
            CGenericType::UnsignedInteger(rank)
        } else {
            CGenericType::SignedInteger(rank)
        })
    }

    fn float_literal_type(&self, sym: CSymbol) -> Option<CGenericType> {
        let raw = self.ast.resolve(sym).ok()?;
        let lower = raw.to_ascii_lowercase();
        let rank = if lower.ends_with('f') {
            FloatRank::Float
        } else if lower.ends_with('l') {
            FloatRank::LongDouble
        } else {
            FloatRank::Double
        };
        Some(CGenericType::Float(rank))
    }

    fn lower_module(&mut self, cx: &mut HirContext) -> crate::error::Result<HirNodeId> {
        let mut items = Vec::new();
        if let Some(root) = self.ast.root()
            && let CNode::TranslationUnit(decls) = self.ast.node(root)
        {
            let decls = decls.clone();
            for decl in decls {
                self.lower_top_level(cx, decl, &mut items)?;
            }
        }
        let span = self.root_span();
        cx.alloc(HirNode::Module(items), span)
            .map_err(crate::error::Error::from)
    }

    fn lower_top_level(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        match self.ast.node(id) {
            CNode::FunctionDef {
                specifiers,
                declarator,
                body,
            } => {
                let specifiers = specifiers.clone();
                let declarator = declarator.clone();
                let body = *body;
                self.lower_aggregate_defs(cx, &specifiers, id, out)?;
                self.define_declarator_type(&specifiers, &declarator);
                let node = self.lower_function(cx, &specifiers, &declarator, Some(body), id)?;
                out.push(node);
            }
            CNode::Declaration {
                specifiers,
                declarators,
            } => {
                let specifiers = specifiers.clone();
                let declarators = declarators.clone();
                self.lower_declaration(cx, &specifiers, &declarators, id, out)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Lowers a declaration (at module or block scope) into HIR items: any inline aggregate
    /// definitions first, then a `typedef`, function, or variable per declarator.
    pub(crate) fn lower_declaration(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        declarators: &[InitDeclarator],
        node: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        self.lower_aggregate_defs(cx, specifiers, node, out)?;
        let is_typedef = specifiers.storage.contains(&StorageClass::Typedef);
        let span = self.ast.span(node);
        for init in declarators {
            if is_typedef {
                self.lower_typedef(cx, specifiers, init, span, out)?;
            } else if is_function_declarator(&init.declarator) {
                self.define_declarator_type(specifiers, &init.declarator);
                let fn_node = self.lower_function(cx, specifiers, &init.declarator, None, node)?;
                out.push(fn_node);
            } else {
                self.lower_variable(cx, specifiers, init, span, out)?;
            }
        }
        Ok(())
    }

    fn lower_typedef(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        init: &InitDeclarator,
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let Some(name) = init.declarator.name else {
            return Ok(());
        };
        let alias_ty =
            Self::generic_type_from_declaration(specifiers, &init.declarator.derivations);
        self.define_alias(name, alias_ty);
        let name = self.lower_symbol(cx, name)?;
        let ty = self.lower_type(cx, specifiers, &init.declarator.derivations)?;
        let alias = cx
            .alloc(HirNode::TypeAlias { name, ty }, span)
            .map_err(crate::error::Error::from)?;
        out.push(alias);
        Ok(())
    }

    fn lower_variable(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        init: &InitDeclarator,
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let Some(name) = init.declarator.name else {
            return Ok(());
        };
        self.define_declarator_type(specifiers, &init.declarator);
        let name = self.lower_symbol(cx, name)?;
        let ty = self.lower_type(cx, specifiers, &init.declarator.derivations)?;
        let flags = Self::decl_flags(specifiers);
        let init = match init.init {
            Some(e) => Some(self.lower_init(cx, e)?),
            None => None,
        };
        let var = cx
            .alloc(
                HirNode::Var {
                    name,
                    ty,
                    flags,
                    init,
                },
                span,
            )
            .map_err(crate::error::Error::from)?;
        out.push(var);
        Ok(())
    }

    /// Emits [`Record`](HirNode::Record)/[`Enumeration`](HirNode::Enumeration) items for any
    /// `struct`/`union`/`enum` *definitions* present in the specifiers.
    fn lower_aggregate_defs(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        node: CNodeId,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let span = self.ast.span(node);
        let specs = specifiers.type_specifiers.clone();
        for spec in &specs {
            match spec {
                TypeSpecifier::Struct {
                    tag,
                    fields: Some(fields),
                } => self.emit_record(cx, RecordKind::Struct, *tag, fields, span, out)?,
                TypeSpecifier::Union {
                    tag,
                    fields: Some(fields),
                } => self.emit_record(cx, RecordKind::Union, *tag, fields, span, out)?,
                TypeSpecifier::Enum {
                    tag,
                    enumerators: Some(enumerators),
                } => self.emit_enum(cx, *tag, enumerators, span, out)?,
                _ => {}
            }
        }
        Ok(())
    }

    fn emit_record(
        &mut self,
        cx: &mut HirContext,
        kind: RecordKind,
        tag: Option<CSymbol>,
        fields: &[FieldDecl],
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let tag = match tag {
            Some(t) => Some(self.lower_symbol(cx, t)?),
            None => None,
        };
        let mut lowered_fields = Vec::with_capacity(fields.len());
        for field in fields {
            let name = match field.declarator.name {
                Some(n) => Some(self.lower_symbol(cx, n)?),
                None => None,
            };
            let ty = self.lower_type(cx, &field.specifiers, &field.declarator.derivations)?;
            let bit_width = match field.bit_width {
                Some(w) => Some(self.lower_expr(cx, w)?),
                None => None,
            };
            lowered_fields.push(Field {
                name,
                ty,
                bit_width,
            });
        }
        let record = cx
            .alloc(
                HirNode::Record {
                    kind,
                    tag,
                    fields: lowered_fields,
                },
                span,
            )
            .map_err(crate::error::Error::from)?;
        out.push(record);
        Ok(())
    }

    fn emit_enum(
        &mut self,
        cx: &mut HirContext,
        tag: Option<CSymbol>,
        enumerators: &[Enumerator],
        span: Span,
        out: &mut Vec<HirNodeId>,
    ) -> crate::error::Result<()> {
        let tag = match tag {
            Some(t) => Some(self.lower_symbol(cx, t)?),
            None => None,
        };
        let mut variants = Vec::with_capacity(enumerators.len());
        for enumerator in enumerators {
            let name = self.lower_symbol(cx, enumerator.name)?;
            let value = match enumerator.value {
                Some(v) => Some(self.lower_expr(cx, v)?),
                None => None,
            };
            variants.push(EnumVariant { name, value });
        }
        let enumeration = cx
            .alloc(HirNode::Enumeration { tag, variants }, span)
            .map_err(crate::error::Error::from)?;
        out.push(enumeration);
        Ok(())
    }

    fn lower_function(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        declarator: &Declarator,
        body: Option<CNodeId>,
        node: CNodeId,
    ) -> crate::error::Result<HirNodeId> {
        let span = self.ast.span(node);
        let name = match declarator.name {
            Some(n) => self.lower_symbol(cx, n)?,
            None => cx.intern("<anonymous>")?,
        };
        let (params, ret, variadic) = self.lower_function_signature(cx, specifiers, declarator)?;
        let flags = Self::decl_flags(specifiers);
        let body = match body {
            Some(b) => {
                self.push_scope();
                self.define_function_parameters(declarator);
                let lowered = self.lower_block(cx, b);
                self.pop_scope();
                Some(lowered?)
            }
            None => None,
        };
        cx.alloc(
            HirNode::Function {
                name,
                params,
                ret,
                variadic,
                flags,
                body,
            },
            span,
        )
        .map_err(crate::error::Error::from)
    }

    fn lower_function_signature(
        &mut self,
        cx: &mut HirContext,
        specifiers: &DeclSpecifiers,
        declarator: &Declarator,
    ) -> crate::error::Result<(Vec<Param>, stratum_hir::HirTypeId, bool)> {
        let fn_index = declarator
            .derivations
            .iter()
            .position(|d| matches!(d, Derivation::Function { .. }));
        let mut params = Vec::new();
        let mut variadic = false;
        if let Some(idx) = fn_index
            && let Some(Derivation::Function {
                params: c_params,
                variadic: is_variadic,
            }) = declarator.derivations.get(idx)
        {
            variadic = *is_variadic;
            let c_params = c_params.clone();
            for p in &c_params {
                let name = match p.declarator.name {
                    Some(n) => Some(self.lower_symbol(cx, n)?),
                    None => None,
                };
                let ty = self.lower_type(cx, &p.specifiers, &p.declarator.derivations)?;
                params.push(Param { name, ty });
            }
        }
        // The return type is the base specifiers wrapped by any derivations that appear
        // *outside* (after) the function derivation, e.g. `int *f(void)`.
        let ret = match fn_index {
            Some(idx) => {
                let derivations = declarator.derivations.get(idx + 1..).unwrap_or_default();
                self.lower_type(cx, specifiers, derivations)?
            }
            None => self.lower_type(cx, specifiers, &[])?,
        };
        Ok((params, ret, variadic))
    }

    /// Lowers a C initialiser (a scalar expression or a braced list) into a [`HirInit`].
    pub(crate) fn lower_init(
        &mut self,
        cx: &mut HirContext,
        id: CNodeId,
    ) -> crate::error::Result<HirInit> {
        if let CNode::InitList(items) = self.ast.node(id) {
            let items = items.clone();
            let mut entries = Vec::with_capacity(items.len());
            for item in items {
                let mut designators = Vec::with_capacity(item.designators.len());
                for designator in item.designators {
                    designators.push(self.lower_designator(cx, designator)?);
                }
                entries.push(InitEntry {
                    designators,
                    value: self.lower_init(cx, item.value)?,
                });
            }
            Ok(HirInit::List(entries))
        } else {
            Ok(HirInit::Expr(self.lower_expr(cx, id)?))
        }
    }

    fn lower_designator(
        &mut self,
        cx: &mut HirContext,
        designator: CDesignator,
    ) -> crate::error::Result<stratum_hir::Designator> {
        match designator {
            CDesignator::Field(name) => {
                Ok(stratum_hir::Designator::Field(self.lower_symbol(cx, name)?))
            }
            CDesignator::Index(expr) => {
                Ok(stratum_hir::Designator::Index(self.lower_expr(cx, expr)?))
            }
        }
    }

    /// Builds the HIR declaration flags (storage class plus `inline`) from C specifiers,
    /// ignoring `typedef`, which is handled by a dedicated lowering path.
    fn decl_flags(specifiers: &DeclSpecifiers) -> DeclFlags {
        let mut storage = None;
        for class in &specifiers.storage {
            storage = match class {
                StorageClass::Extern => Some(HirStorage::Extern),
                StorageClass::Static => Some(HirStorage::Static),
                StorageClass::Auto => Some(HirStorage::Auto),
                StorageClass::Register => Some(HirStorage::Register),
                StorageClass::ThreadLocal => Some(HirStorage::ThreadLocal),
                StorageClass::Constexpr => Some(HirStorage::Constexpr),
                StorageClass::Typedef => continue,
            };
            break;
        }
        DeclFlags {
            storage,
            inline: specifiers.inline,
            noreturn: specifiers.noreturn,
        }
    }

    /// Resolves a C-interner symbol and re-interns it into the HIR context's interner.
    ///
    /// C and HIR each own a separate interner, so symbols are never shared directly.
    pub(crate) fn lower_symbol(
        &self,
        cx: &mut HirContext,
        sym: CSymbol,
    ) -> crate::error::Result<stratum_arena::Symbol> {
        let text = self.ast.resolve(sym)?;
        Ok(cx.intern(text)?)
    }

    pub(crate) fn root_span(&self) -> Span {
        self.ast.root().map_or_else(
            || Span::point(stratum_diagnostics::FileId::from_raw(0), 0),
            |r| self.ast.span(r),
        )
    }
}

/// Returns `true` if the declarator's outermost derivation is a function.
pub(crate) fn is_function_declarator(declarator: &Declarator) -> bool {
    matches!(
        declarator.derivations.first(),
        Some(Derivation::Function { .. })
    )
}

fn integer_rank(specs: &[TypeSpecifier]) -> IntegerRank {
    let longs = specs
        .iter()
        .filter(|spec| matches!(spec, TypeSpecifier::Long))
        .count();
    if longs >= 2 {
        IntegerRank::LongLong
    } else if longs == 1 {
        IntegerRank::Long
    } else if specs.contains(&TypeSpecifier::Short) {
        IntegerRank::Short
    } else {
        IntegerRank::Int
    }
}

fn integer_suffix_rank(raw: &str) -> IntegerRank {
    let lower = raw.to_ascii_lowercase();
    let long_count = lower.chars().filter(|ch| *ch == 'l').count();
    if long_count >= 2 {
        IntegerRank::LongLong
    } else if long_count == 1 {
        IntegerRank::Long
    } else {
        IntegerRank::Int
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CGenericTag, CGenericType, CLowering, FloatRank, IntegerRank, LowerResult,
        integer_suffix_rank, lower,
    };
    use crate::alloc_prelude::*;
    use crate::bridge::CBridge;
    use crate::test_utils::{build, dump};
    use stratum_c_ast::{
        BinaryOp, CAst, CNode, DeclSpecifiers, Declarator, Derivation, InitDeclarator, ParamDecl,
        StorageClass, TypeName, TypeSpecifier, TypeofOperand, UnaryOp,
    };
    use stratum_diagnostics::{Diagnostic, FileId, Span};
    use stratum_hir::{HirBridge, HirContext, StorageClass as HirStorage};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn int_specs() -> DeclSpecifiers {
        DeclSpecifiers {
            type_specifiers: vec![TypeSpecifier::Int],
            ..DeclSpecifiers::default()
        }
    }

    fn specs(type_specifiers: Vec<TypeSpecifier>) -> DeclSpecifiers {
        DeclSpecifiers {
            type_specifiers,
            ..DeclSpecifiers::default()
        }
    }

    fn ptr(ty: CGenericType) -> CGenericType {
        CGenericType::Pointer(Box::new(ty))
    }

    #[test]
    fn empty_unit_lowers_to_empty_module() {
        assert_eq!(dump(""), "module\n");
    }

    #[test]
    fn function_with_return() {
        let out = dump("int main(void) { return 0; }");
        assert!(out.contains("function main"));
        assert!(out.contains("return"));
        assert!(out.contains("int 0"));
    }

    #[test]
    fn function_prototype_has_no_body() {
        let out = dump("int f(int a);");
        assert!(out.contains("function f(a: i32) -> i32"), "got: {out}");
    }

    #[test]
    fn variadic_prototype_is_preserved() {
        let out = dump("int printf(char *fmt, ...);");
        assert!(out.contains("function printf("), "got: {out}");
        assert!(out.contains(", ...) -> i32"), "got: {out}");
    }

    #[test]
    fn unnamed_parameter_lowers_without_a_name() {
        let out = dump("int f(int);");
        assert!(out.contains("function f("), "got: {out}");
        assert!(out.contains("i32) -> i32"), "got: {out}");
    }

    #[test]
    fn storage_class_and_inline_flags_are_preserved() {
        let out = dump(
            "static inline _Noreturn int f(void) { return 0; } \
             thread_local int tls; constexpr int c = 1;",
        );
        assert!(
            out.contains("static inline _Noreturn function f"),
            "got: {out}"
        );
        assert!(out.contains("_Thread_local var tls"), "got: {out}");
        assert!(out.contains("constexpr var c"), "got: {out}");
    }

    #[test]
    fn auto_and_register_storage_flags_are_preserved() {
        let out = dump("void f(void) { auto int a; register int r; }");
        assert!(out.contains("auto var a"), "got: {out}");
        assert!(out.contains("register var r"), "got: {out}");
    }

    #[test]
    fn lower_result_and_decl_flags_cover_all_storage_arms() {
        let result = LowerResult {
            hir: HirContext::new(),
            diagnostics: vec![Diagnostic::error("bad")],
        };
        assert!(result.has_errors());
        let result = LowerResult {
            hir: HirContext::new(),
            diagnostics: Vec::new(),
        };
        assert!(!result.has_errors());

        for (storage, expected) in [
            (StorageClass::Extern, Some(HirStorage::Extern)),
            (StorageClass::Static, Some(HirStorage::Static)),
            (StorageClass::Auto, Some(HirStorage::Auto)),
            (StorageClass::Register, Some(HirStorage::Register)),
            (StorageClass::ThreadLocal, Some(HirStorage::ThreadLocal)),
            (StorageClass::Constexpr, Some(HirStorage::Constexpr)),
            (StorageClass::Typedef, None),
        ] {
            let flags = CLowering::decl_flags(&DeclSpecifiers {
                storage: vec![storage],
                inline: true,
                noreturn: true,
                ..DeclSpecifiers::default()
            });
            assert_eq!(flags.storage, expected);
            assert!(flags.inline);
            assert!(flags.noreturn);
        }
    }

    #[test]
    fn integer_suffix_rank_tracks_long_suffixes() {
        assert_eq!(integer_suffix_rank("1"), IntegerRank::Int);
        assert_eq!(integer_suffix_rank("1L"), IntegerRank::Long);
        assert_eq!(integer_suffix_rank("1ull"), IntegerRank::LongLong);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "exhaustively covers generic C type classification paths"
    )]
    fn generic_type_helpers_cover_expression_and_specifier_paths() {
        let mut ast = CAst::new();
        let alias = ast.intern("Alias").unwrap();
        let declared = ast.intern("declared").unwrap();
        let param = ast.intern("param").unwrap();
        let one = ast.intern("1ull").unwrap();
        let float = ast.intern("1.0f").unwrap();
        let double = ast.intern("1.0").unwrap();
        let long_double = ast.intern("1.0l").unwrap();
        let text = ast.intern("text").unwrap();
        let ident = ast.alloc(CNode::Ident(alias), span()).unwrap();
        let declared_ident = ast.alloc(CNode::Ident(declared), span()).unwrap();
        let param_ident = ast.alloc(CNode::Ident(param), span()).unwrap();
        let int_lit = ast.alloc(CNode::IntLiteral(one), span()).unwrap();
        let char_lit = ast.alloc(CNode::CharLiteral(one), span()).unwrap();
        let binary = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Add,
                    lhs: int_lit,
                    rhs: int_lit,
                },
                span(),
            )
            .unwrap();
        let bool_lit = ast.alloc(CNode::BoolLiteral(true), span()).unwrap();
        let float_lit = ast.alloc(CNode::FloatLiteral(float), span()).unwrap();
        let double_lit = ast.alloc(CNode::FloatLiteral(double), span()).unwrap();
        let long_double_lit = ast.alloc(CNode::FloatLiteral(long_double), span()).unwrap();
        let string_lit = ast.alloc(CNode::StringLiteral(text), span()).unwrap();
        let nullptr = ast.alloc(CNode::Nullptr, span()).unwrap();
        let cast = ast
            .alloc(
                CNode::Cast {
                    type_name: TypeName {
                        specifiers: specs(vec![TypeSpecifier::Decimal32]),
                        declarator: Declarator::default(),
                    },
                    expr: int_lit,
                },
                span(),
            )
            .unwrap();
        let address = ast
            .alloc(
                CNode::Unary {
                    op: UnaryOp::AddressOf,
                    operand: int_lit,
                },
                span(),
            )
            .unwrap();
        let plus = ast
            .alloc(
                CNode::Unary {
                    op: UnaryOp::Plus,
                    operand: int_lit,
                },
                span(),
            )
            .unwrap();
        let same_conditional = ast
            .alloc(
                CNode::Conditional {
                    cond: bool_lit,
                    then_expr: int_lit,
                    else_expr: int_lit,
                },
                span(),
            )
            .unwrap();
        let mismatched_conditional = ast
            .alloc(
                CNode::Conditional {
                    cond: bool_lit,
                    then_expr: int_lit,
                    else_expr: string_lit,
                },
                span(),
            )
            .unwrap();
        let comma = ast
            .alloc(
                CNode::Comma {
                    lhs: int_lit,
                    rhs: string_lit,
                },
                span(),
            )
            .unwrap();
        let unknown = ast
            .alloc(CNode::TranslationUnit(Vec::new()), span())
            .unwrap();

        let mut lowering = CLowering::new(&ast);
        lowering.error(span(), "forced");
        assert_eq!(lowering.diagnostics.len(), 1);
        lowering.define_type(alias, CGenericType::Bool);
        lowering.define_type(alias, ptr(CGenericType::Bool));
        assert_eq!(
            lowering.generic_expr_type(ident),
            Some(ptr(CGenericType::Bool))
        );
        assert_eq!(
            lowering.generic_expr_type(int_lit),
            Some(CGenericType::UnsignedInteger(IntegerRank::LongLong))
        );
        assert_eq!(
            lowering.generic_expr_type(char_lit),
            Some(CGenericType::SignedInteger(IntegerRank::Int))
        );
        assert_eq!(
            lowering.generic_expr_type(binary),
            Some(CGenericType::UnsignedInteger(IntegerRank::LongLong))
        );
        assert_eq!(
            lowering.generic_expr_type(bool_lit),
            Some(CGenericType::Bool)
        );
        assert_eq!(
            lowering.generic_expr_type(float_lit),
            Some(CGenericType::Float(FloatRank::Float))
        );
        assert_eq!(
            lowering.generic_expr_type(double_lit),
            Some(CGenericType::Float(FloatRank::Double))
        );
        assert_eq!(
            lowering.generic_expr_type(long_double_lit),
            Some(CGenericType::Float(FloatRank::LongDouble))
        );
        assert_eq!(
            lowering.generic_expr_type(string_lit),
            Some(ptr(CGenericType::PlainChar))
        );
        assert_eq!(
            lowering.generic_expr_type(nullptr),
            Some(ptr(CGenericType::Void))
        );
        assert_eq!(
            lowering.generic_expr_type(cast),
            Some(CGenericType::Float(FloatRank::Decimal32))
        );
        assert_eq!(
            lowering.generic_expr_type(address),
            Some(ptr(CGenericType::UnsignedInteger(IntegerRank::LongLong)))
        );
        assert_eq!(
            lowering.generic_expr_type(plus),
            Some(CGenericType::UnsignedInteger(IntegerRank::LongLong))
        );
        assert_eq!(
            lowering.generic_expr_type(same_conditional),
            Some(CGenericType::UnsignedInteger(IntegerRank::LongLong))
        );
        assert_eq!(lowering.generic_expr_type(mismatched_conditional), None);
        assert_eq!(
            lowering.generic_expr_type(comma),
            Some(ptr(CGenericType::PlainChar))
        );
        assert_eq!(lowering.generic_expr_type(unknown), None);

        let pointer_decl = [Derivation::Pointer {
            qualifiers: Vec::new(),
        }];
        let array_decl = [Derivation::Array { size: None }];
        let function_decl = [Derivation::Function {
            params: Vec::new(),
            variadic: false,
        }];
        assert_eq!(
            CLowering::generic_type_from_declaration(&int_specs(), &pointer_decl),
            ptr(CGenericType::SignedInteger(IntegerRank::Int))
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&int_specs(), &array_decl),
            CGenericType::Array(Box::new(CGenericType::SignedInteger(IntegerRank::Int)))
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&int_specs(), &function_decl),
            CGenericType::Function {
                params: Vec::new(),
                ret: Box::new(CGenericType::SignedInteger(IntegerRank::Int)),
                variadic: false,
            }
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Void]), &[]),
            CGenericType::Void
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Bool]), &[]),
            CGenericType::Bool
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Decimal128]), &[]),
            CGenericType::Float(FloatRank::Decimal128)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Decimal64]), &[]),
            CGenericType::Float(FloatRank::Decimal64)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::Double, TypeSpecifier::Long]),
                &[],
            ),
            CGenericType::Float(FloatRank::LongDouble)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Double]), &[]),
            CGenericType::Float(FloatRank::Double)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Float]), &[]),
            CGenericType::Float(FloatRank::Float)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::Char, TypeSpecifier::Signed]),
                &[],
            ),
            CGenericType::SignedInteger(IntegerRank::Char)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::Char, TypeSpecifier::Unsigned]),
                &[],
            ),
            CGenericType::UnsignedInteger(IntegerRank::Char)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![TypeSpecifier::Char]), &[]),
            CGenericType::PlainChar
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::TypedefName(alias)]),
                &[],
            ),
            CGenericType::Named(alias)
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::Struct {
                    tag: None,
                    fields: None,
                }]),
                &[],
            ),
            CGenericType::Tag {
                kind: CGenericTag::Struct,
                name: None,
            }
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::Union {
                    tag: None,
                    fields: None,
                }]),
                &[],
            ),
            CGenericType::Tag {
                kind: CGenericTag::Union,
                name: None,
            }
        );
        assert_eq!(
            CLowering::generic_type_from_declaration(
                &specs(vec![TypeSpecifier::Enum {
                    tag: None,
                    enumerators: None,
                }]),
                &[],
            ),
            CGenericType::Tag {
                kind: CGenericTag::Enum,
                name: None,
            }
        );

        lowering.define_declarator_type(&int_specs(), &Declarator::default());
        lowering.define_declarator_type(
            &specs(vec![TypeSpecifier::Unsigned]),
            &Declarator {
                name: Some(declared),
                derivations: Vec::new(),
            },
        );
        assert_eq!(
            lowering.generic_expr_type(declared_ident),
            Some(CGenericType::UnsignedInteger(IntegerRank::Int))
        );
        lowering.define_function_parameters(&Declarator {
            name: None,
            derivations: vec![Derivation::Function {
                params: vec![ParamDecl {
                    specifiers: specs(vec![TypeSpecifier::Float]),
                    declarator: Declarator {
                        name: Some(param),
                        derivations: Vec::new(),
                    },
                }],
                variadic: false,
            }],
        });
        assert_eq!(
            lowering.generic_expr_type(param_ident),
            Some(CGenericType::Float(FloatRank::Float))
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "directly covers the generic type inference conversion table"
    )]
    fn generic_type_inference_covers_remaining_edges() {
        let mut ast = CAst::new();
        let one = ast.intern("1").unwrap();
        let unsigned = ast.intern("1u").unwrap();
        let float = ast.intern("1.0f").unwrap();
        let function_name = ast.intern("function_like").unwrap();
        let alias = ast.intern("Alias").unwrap();
        let recursive = ast.intern("Recursive").unwrap();
        let missing_alias = ast.intern("MissingAlias").unwrap();

        let one_lit = ast.alloc(CNode::IntLiteral(one), span()).unwrap();
        let unsigned_lit = ast.alloc(CNode::IntLiteral(unsigned), span()).unwrap();
        let float_lit = ast.alloc(CNode::FloatLiteral(float), span()).unwrap();
        let function_ident = ast.alloc(CNode::Ident(function_name), span()).unwrap();
        let add_ints = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Add,
                    lhs: one_lit,
                    rhs: one_lit,
                },
                span(),
            )
            .unwrap();
        let address_of_int = ast
            .alloc(
                CNode::Unary {
                    op: UnaryOp::AddressOf,
                    operand: one_lit,
                },
                span(),
            )
            .unwrap();
        let deref_int = ast
            .alloc(
                CNode::Unary {
                    op: UnaryOp::Deref,
                    operand: address_of_int,
                },
                span(),
            )
            .unwrap();
        let deref_non_pointer = ast
            .alloc(
                CNode::Unary {
                    op: UnaryOp::Deref,
                    operand: one_lit,
                },
                span(),
            )
            .unwrap();
        let address_of_binary = ast
            .alloc(
                CNode::Unary {
                    op: UnaryOp::AddressOf,
                    operand: add_ints,
                },
                span(),
            )
            .unwrap();
        let add_ptr_int = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Add,
                    lhs: address_of_int,
                    rhs: one_lit,
                },
                span(),
            )
            .unwrap();
        let add_int_ptr = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Add,
                    lhs: one_lit,
                    rhs: address_of_int,
                },
                span(),
            )
            .unwrap();
        let sub_ptr_int = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Sub,
                    lhs: address_of_int,
                    rhs: one_lit,
                },
                span(),
            )
            .unwrap();
        let sub_ptr_ptr = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Sub,
                    lhs: address_of_int,
                    rhs: address_of_int,
                },
                span(),
            )
            .unwrap();
        let sub_ints = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Sub,
                    lhs: one_lit,
                    rhs: one_lit,
                },
                span(),
            )
            .unwrap();
        let compare = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Lt,
                    lhs: one_lit,
                    rhs: one_lit,
                },
                span(),
            )
            .unwrap();
        let shift = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Shl,
                    lhs: one_lit,
                    rhs: one_lit,
                },
                span(),
            )
            .unwrap();
        let rem = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Rem,
                    lhs: one_lit,
                    rhs: unsigned_lit,
                },
                span(),
            )
            .unwrap();
        let mul_float = ast
            .alloc(
                CNode::Binary {
                    op: BinaryOp::Mul,
                    lhs: one_lit,
                    rhs: float_lit,
                },
                span(),
            )
            .unwrap();

        let mut lowering = CLowering::new(&ast);
        lowering.define_type(
            function_name,
            CGenericType::Function {
                params: vec![CGenericType::SignedInteger(IntegerRank::Int)],
                ret: Box::new(CGenericType::Bool),
                variadic: true,
            },
        );
        assert_eq!(
            lowering.generic_expr_type(function_ident),
            Some(ptr(CGenericType::Function {
                params: vec![CGenericType::SignedInteger(IntegerRank::Int)],
                ret: Box::new(CGenericType::Bool),
                variadic: true,
            }))
        );
        assert_eq!(
            lowering.generic_expr_type(deref_int),
            Some(CGenericType::SignedInteger(IntegerRank::Int))
        );
        assert_eq!(lowering.generic_expr_type(deref_non_pointer), None);
        assert_eq!(
            lowering.generic_expr_type(address_of_binary),
            Some(ptr(CGenericType::SignedInteger(IntegerRank::Int)))
        );
        assert_eq!(
            lowering.generic_expr_type(add_ptr_int),
            Some(ptr(CGenericType::SignedInteger(IntegerRank::Int)))
        );
        assert_eq!(
            lowering.generic_expr_type(add_int_ptr),
            Some(ptr(CGenericType::SignedInteger(IntegerRank::Int)))
        );
        assert_eq!(
            lowering.generic_expr_type(sub_ptr_int),
            Some(ptr(CGenericType::SignedInteger(IntegerRank::Int)))
        );
        assert_eq!(
            lowering.generic_expr_type(sub_ptr_ptr),
            Some(CGenericType::SignedInteger(IntegerRank::Long))
        );
        assert_eq!(
            lowering.generic_expr_type(sub_ints),
            Some(CGenericType::SignedInteger(IntegerRank::Int))
        );
        assert_eq!(
            lowering.generic_expr_type(compare),
            Some(CGenericType::SignedInteger(IntegerRank::Int))
        );
        assert_eq!(
            lowering.generic_expr_type(shift),
            Some(CGenericType::SignedInteger(IntegerRank::Int))
        );
        assert_eq!(
            lowering.generic_expr_type(rem),
            Some(CGenericType::UnsignedInteger(IntegerRank::Int))
        );
        assert_eq!(
            lowering.generic_expr_type(mul_float),
            Some(CGenericType::Float(FloatRank::Float))
        );

        let function_decl = [Derivation::Function {
            params: vec![ParamDecl {
                specifiers: specs(vec![TypeSpecifier::Unsigned, TypeSpecifier::Long]),
                declarator: Declarator::default(),
            }],
            variadic: true,
        }];
        assert_eq!(
            CLowering::generic_type_from_declaration(&int_specs(), &function_decl),
            CGenericType::Function {
                params: vec![CGenericType::UnsignedInteger(IntegerRank::Long)],
                ret: Box::new(CGenericType::SignedInteger(IntegerRank::Int)),
                variadic: true,
            }
        );

        lowering.define_alias(alias, CGenericType::SignedInteger(IntegerRank::Int));
        assert!(lowering.generic_types_compatible(
            &CGenericType::Named(alias),
            &CGenericType::SignedInteger(IntegerRank::Int),
        ));
        lowering.define_alias(alias, CGenericType::SignedInteger(IntegerRank::Long));
        assert!(lowering.generic_types_compatible(
            &CGenericType::Named(alias),
            &CGenericType::SignedInteger(IntegerRank::Long),
        ));
        lowering.define_alias(recursive, CGenericType::Named(recursive));
        assert!(!lowering.generic_types_compatible(
            &CGenericType::Named(recursive),
            &CGenericType::SignedInteger(IntegerRank::Int),
        ));
        assert_eq!(
            lowering.canonical_generic_type(&CGenericType::Named(missing_alias), 0),
            CGenericType::Named(missing_alias)
        );
        assert_eq!(
            lowering.composite_generic_type(&CGenericType::Bool, &CGenericType::PlainChar),
            CGenericType::Other
        );
        assert_eq!(
            lowering.canonical_generic_type(
                &CGenericType::Function {
                    params: vec![CGenericType::Named(alias)],
                    ret: Box::new(CGenericType::Named(alias)),
                    variadic: false,
                },
                0,
            ),
            CGenericType::Function {
                params: vec![CGenericType::SignedInteger(IntegerRank::Long)],
                ret: Box::new(CGenericType::SignedInteger(IntegerRank::Long)),
                variadic: false,
            }
        );

        assert_eq!(
            CLowering::usual_integer_type(
                &CGenericType::SignedInteger(IntegerRank::Short),
                &CGenericType::SignedInteger(IntegerRank::LongLong),
            ),
            Some(CGenericType::SignedInteger(IntegerRank::LongLong))
        );
        assert_eq!(
            CLowering::usual_integer_type(
                &CGenericType::UnsignedInteger(IntegerRank::Short),
                &CGenericType::UnsignedInteger(IntegerRank::Long),
            ),
            Some(CGenericType::UnsignedInteger(IntegerRank::Long))
        );
        assert_eq!(
            CLowering::usual_integer_type(
                &CGenericType::SignedInteger(IntegerRank::Int),
                &CGenericType::UnsignedInteger(IntegerRank::Long),
            ),
            Some(CGenericType::UnsignedInteger(IntegerRank::Long))
        );
        assert_eq!(
            CLowering::usual_integer_type(&CGenericType::Other, &CGenericType::Bool),
            None
        );
        assert_eq!(
            CLowering::usual_arithmetic_type(
                &CGenericType::Bool,
                &CGenericType::Float(FloatRank::Float),
            ),
            Some(CGenericType::Float(FloatRank::Float))
        );

        for ty in [
            CGenericType::Bool,
            CGenericType::PlainChar,
            CGenericType::SignedInteger(IntegerRank::Char),
            CGenericType::UnsignedInteger(IntegerRank::Short),
        ] {
            assert_eq!(
                CLowering::integer_promote(&ty),
                Some(CGenericType::SignedInteger(IntegerRank::Int))
            );
            assert!(CLowering::is_integer_type(&ty));
        }
        assert_eq!(
            CLowering::integer_promote(&CGenericType::SignedInteger(IntegerRank::Long)),
            Some(CGenericType::SignedInteger(IntegerRank::Long))
        );
        assert_eq!(
            CLowering::integer_promote(&CGenericType::UnsignedInteger(IntegerRank::Long)),
            Some(CGenericType::UnsignedInteger(IntegerRank::Long))
        );
        assert_eq!(
            CLowering::integer_promote(&CGenericType::Float(FloatRank::Float)),
            None
        );
        assert!(!CLowering::is_integer_type(&CGenericType::Float(
            FloatRank::Float
        )));

        assert_eq!(
            CLowering::max_integer_rank(IntegerRank::Char, IntegerRank::Char),
            IntegerRank::Char
        );
        assert_eq!(
            CLowering::max_integer_rank(IntegerRank::Short, IntegerRank::Char),
            IntegerRank::Short
        );
        assert_eq!(
            CLowering::max_integer_rank(IntegerRank::Int, IntegerRank::Short),
            IntegerRank::Int
        );
        assert_eq!(
            CLowering::max_float_rank(FloatRank::Float, FloatRank::Float),
            FloatRank::Float
        );
        assert_eq!(
            CLowering::max_float_rank(FloatRank::Double, FloatRank::Float),
            FloatRank::Double
        );
        assert_eq!(
            CLowering::max_float_rank(FloatRank::LongDouble, FloatRank::Double),
            FloatRank::LongDouble
        );
        assert_eq!(
            CLowering::max_float_rank(FloatRank::Decimal32, FloatRank::LongDouble),
            FloatRank::Decimal32
        );
        assert_eq!(
            CLowering::max_float_rank(FloatRank::Decimal64, FloatRank::Decimal32),
            FloatRank::Decimal64
        );
        assert_eq!(
            CLowering::max_float_rank(FloatRank::Decimal128, FloatRank::Decimal64),
            FloatRank::Decimal128
        );

        let atomic = TypeSpecifier::Atomic(Box::new(TypeName {
            specifiers: specs(vec![TypeSpecifier::Unsigned]),
            declarator: Declarator::default(),
        }));
        assert_eq!(
            CLowering::generic_type_from_declaration(&specs(vec![atomic]), &[]),
            CGenericType::UnsignedInteger(IntegerRank::Int)
        );
        for specifier in [
            TypeSpecifier::Complex,
            TypeSpecifier::Imaginary,
            TypeSpecifier::BitInt(one_lit),
            TypeSpecifier::Typeof {
                operand: TypeofOperand::Expr(one_lit),
                unqualified: false,
            },
        ] {
            assert_eq!(
                CLowering::generic_type_from_declaration(&specs(vec![specifier]), &[]),
                CGenericType::Other
            );
        }

        lowering.scopes.clear();
        lowering.define_type(alias, CGenericType::Bool);
        assert_eq!(lowering.lookup_type(alias), Some(CGenericType::Bool));
        lowering.type_aliases.clear();
        lowering.define_alias(alias, CGenericType::PlainChar);
        assert!(
            lowering
                .generic_types_compatible(&CGenericType::Named(alias), &CGenericType::PlainChar,)
        );
    }

    #[test]
    fn typedef_lowers_to_type_alias() {
        let out = dump("typedef int myint; myint x;");
        assert!(out.contains("typedef myint = i32"), "got: {out}");
        assert!(out.contains("var x: myint"), "got: {out}");
    }

    #[test]
    fn struct_definition_lowers_to_record() {
        let out = dump("struct Point { int x; int y; };");
        assert!(out.contains("struct Point"), "got: {out}");
        assert!(out.contains("field x: i32"), "got: {out}");
        assert!(out.contains("field y: i32"), "got: {out}");
    }

    #[test]
    fn union_definition_lowers_to_record() {
        let out = dump("union U { int i; float f; };");
        assert!(out.contains("union U"), "got: {out}");
        assert!(out.contains("field i: i32"), "got: {out}");
        assert!(out.contains("field f: f32"), "got: {out}");
    }

    #[test]
    fn anonymous_aggregates_and_abstract_fields_lower() {
        let out = dump("union { int; } u; enum { A };");
        assert!(out.contains("union <anonymous>"), "got: {out}");
        assert!(out.contains("field <unnamed>: i32"), "got: {out}");
        assert!(out.contains("enum <anonymous>"), "got: {out}");
    }

    #[test]
    fn bitfields_are_preserved() {
        let out = dump("struct Flags { unsigned a : 1; unsigned b : 3; };");
        assert!(out.contains("field a: u32 : "), "got: {out}");
        assert!(out.contains("int 1"), "got: {out}");
    }

    #[test]
    fn enum_definition_lowers_to_enumeration() {
        let out = dump("enum Color { Red, Green = 5, Blue };");
        assert!(out.contains("enum Color"), "got: {out}");
        assert!(out.contains("variant Red"), "got: {out}");
        assert!(out.contains("variant Green"), "got: {out}");
        assert!(out.contains("int 5"), "got: {out}");
    }

    #[test]
    fn struct_with_variable_emits_record_and_var() {
        let out = dump("struct P { int x; } p;");
        assert!(out.contains("struct P"), "got: {out}");
        assert!(out.contains("var p: struct P"), "got: {out}");
    }

    #[test]
    fn aggregate_initializer_lowers_to_init_list() {
        let out = dump("int a[3] = { 1, 2, 3 };");
        assert!(out.contains("init-list"), "got: {out}");
        assert!(out.contains("int 1"), "got: {out}");
        assert!(out.contains("int 3"), "got: {out}");
    }

    #[test]
    fn nested_aggregate_initializer() {
        let out = dump("int m[2][2] = { { 1, 2 }, { 3, 4 } };");
        let lists = out.matches("init-list").count();
        assert!(lists >= 3, "expected nested init lists, got: {out}");
    }

    #[test]
    fn lowering_is_total_no_errors_on_rich_input() {
        let src = "
            typedef unsigned long size_t;
            struct Node { int value; struct Node *next; };
            enum E { A, B = 2, C };
            static int counter = 0;
            int sum(int *xs, int n, ...) {
                int total = 0;
                for (int i = 0; i < n; i++) {
                    switch (xs[i]) {
                        case 0: continue;
                        default: total += xs[i] ? xs[i] : -1;
                    }
                }
                return total;
            }
        ";
        let ast = build(src);
        let result = lower(&ast).unwrap();
        assert!(!result.has_errors(), "got: {:?}", result.diagnostics);
    }

    #[test]
    fn designated_initializers_lower_with_designators() {
        let out = dump("struct P { int x; int y; }; struct P p = { .y = 2, .x = 1 };");
        assert!(out.contains("init-list"), "got: {out}");
        assert!(out.contains("designator .y"), "got: {out}");
        assert!(out.contains("designator .x"), "got: {out}");
    }

    #[test]
    fn array_index_designators_lower() {
        let out = dump("int a[4] = { [2] = 9, [0] = 1 };");
        assert!(out.contains("init-list"), "got: {out}");
        assert!(out.contains("designator []"), "got: {out}");
    }

    #[test]
    fn separate_interners_resolve_names() {
        let out = dump("int g; void f(void) { g = 1; }");
        assert!(out.contains("name `g`"), "got: {out}");
    }

    #[test]
    fn lowering_empty_ast_uses_synthetic_root_span() {
        let ast = CAst::new();
        let lowered = lower(&ast).unwrap();
        assert_eq!(lowered.hir.dump_root(), "module\n");

        let mut hir = HirContext::new();
        let root = CBridge.lower(&ast, &mut hir).unwrap();
        assert_eq!(hir.dump(root), "module\n");
        assert_eq!(hir.root(), Some(root));
    }

    #[test]
    fn hir_bridge_reports_lowering_diagnostics() {
        let mut ast = CAst::new();
        let name = ast.intern("x").unwrap();
        let bad = ast.intern("09").unwrap();
        let expr = ast.alloc(CNode::IntLiteral(bad), span()).unwrap();
        let decl = ast
            .alloc(
                CNode::Declaration {
                    specifiers: int_specs(),
                    declarators: vec![InitDeclarator {
                        declarator: Declarator {
                            name: Some(name),
                            derivations: Vec::new(),
                        },
                        init: Some(expr),
                    }],
                },
                span(),
            )
            .unwrap();
        let root = ast
            .alloc(CNode::TranslationUnit(vec![decl]), span())
            .unwrap();
        ast.set_root(root);
        let mut hir = HirContext::new();

        let error = CBridge
            .lower(&ast, &mut hir)
            .err()
            .map(|err| err.to_string());
        assert_eq!(
            error.as_deref(),
            Some("lowering produced diagnostics that cannot cross HirBridge")
        );
        assert_eq!(hir.root(), None);
    }

    #[test]
    fn non_declaration_top_level_items_are_ignored() {
        let mut ast = CAst::new();
        let sym = ast.intern("1").unwrap();
        let literal = ast.alloc(CNode::IntLiteral(sym), span()).unwrap();
        let root = ast
            .alloc(CNode::TranslationUnit(vec![literal]), span())
            .unwrap();
        ast.set_root(root);

        let lowered = lower(&ast).unwrap();
        assert_eq!(lowered.hir.dump_root(), "module\n");
    }

    #[test]
    fn nameless_declarators_do_not_emit_typedefs_or_variables() {
        let mut ast = CAst::new();
        let node = ast
            .alloc(
                CNode::Declaration {
                    specifiers: int_specs(),
                    declarators: Vec::new(),
                },
                span(),
            )
            .unwrap();
        let init = InitDeclarator {
            declarator: Declarator::default(),
            init: None,
        };
        let mut typedef_specs = int_specs();
        typedef_specs.storage.push(StorageClass::Typedef);
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();
        let mut out = Vec::new();

        lowering
            .lower_declaration(
                &mut hir,
                &typedef_specs,
                std::slice::from_ref(&init),
                node,
                &mut out,
            )
            .unwrap();
        lowering
            .lower_declaration(&mut hir, &int_specs(), &[init], node, &mut out)
            .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn anonymous_function_without_function_derivation_gets_default_signature() {
        let mut ast = CAst::new();
        let node = ast
            .alloc(
                CNode::Declaration {
                    specifiers: int_specs(),
                    declarators: Vec::new(),
                },
                span(),
            )
            .unwrap();
        let mut lowering = CLowering::new(&ast);
        let mut hir = HirContext::new();

        let function = lowering
            .lower_function(&mut hir, &int_specs(), &Declarator::default(), None, node)
            .unwrap();
        assert!(hir.dump(function).contains("function <anonymous>() -> i32"));
    }

    #[test]
    fn typedef_storage_is_ignored_by_decl_flags() {
        let mut specs = int_specs();
        specs.storage.push(StorageClass::Typedef);
        let flags = CLowering::decl_flags(&specs);
        assert_eq!(flags.storage, None);
    }
}
