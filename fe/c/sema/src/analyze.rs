//! The semantic-analysis pass: a scoped walk that collects symbols.

use crate::alloc_prelude::*;
use crate::symbol::{SymbolInfo, SymbolKind, SymbolTable};
use stratum_arena::Symbol;
use stratum_c_ast::{
    CAst, CNode, CNodeId, DeclSpecifiers, Declarator, Derivation, InitDeclarator, StorageClass,
    TypeSpecifier,
};
use stratum_diagnostics::{Diagnostic, FileId, Label, Span};

/// The result of analysing a translation unit.
#[derive(Debug)]
pub struct SemaResult {
    /// The populated symbol table (its global scope holds file-scope declarations).
    pub symbols: SymbolTable,
    /// Diagnostics produced during analysis.
    pub diagnostics: Vec<Diagnostic>,
}

impl SemaResult {
    /// Returns `true` if any diagnostics were produced.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }
}

/// Analyses `ast`, building a symbol table and reporting basic semantic errors.
#[must_use]
pub fn analyze(ast: &CAst) -> SemaResult {
    let mut analyzer = Analyzer {
        ast,
        symbols: SymbolTable::new(),
        diagnostics: Vec::new(),
    };
    if let Some(root) = ast.root() {
        analyzer.walk(root);
    }
    SemaResult {
        symbols: analyzer.symbols,
        diagnostics: analyzer.diagnostics,
    }
}

struct Analyzer<'a> {
    ast: &'a CAst,
    symbols: SymbolTable,
    diagnostics: Vec<Diagnostic>,
}

impl Analyzer<'_> {
    fn walk(&mut self, id: CNodeId) {
        match self.ast.node(id) {
            CNode::TranslationUnit(items) => self.walk_all(items),
            CNode::FunctionDef {
                declarator, body, ..
            } => self.walk_function(declarator, *body),
            CNode::Declaration {
                specifiers,
                declarators,
            } => self.walk_declaration(specifiers, declarators),
            CNode::Compound(items) => {
                self.symbols.enter_scope();
                self.walk_all(items);
                self.symbols.exit_scope();
            }
            CNode::If {
                then_branch,
                else_branch,
                ..
            } => {
                self.walk(*then_branch);
                if let Some(branch) = else_branch {
                    self.walk(*branch);
                }
            }
            CNode::While { body, .. }
            | CNode::DoWhile { body, .. }
            | CNode::Switch { body, .. }
            | CNode::Label { body, .. }
            | CNode::Case { body, .. }
            | CNode::Default { body } => self.walk(*body),
            CNode::For { init, body, .. } => {
                self.symbols.enter_scope();
                if let Some(init) = init {
                    self.walk(*init);
                }
                self.walk(*body);
                self.symbols.exit_scope();
            }
            _ => {}
        }
    }

    fn walk_all(&mut self, items: &[CNodeId]) {
        for &item in items {
            self.walk(item);
        }
    }

    fn walk_function(&mut self, declarator: &Declarator, body: CNodeId) {
        if let Some(name) = declarator.name {
            self.declare(name, SymbolKind::Function, declarator);
        }
        self.symbols.enter_scope();
        self.declare_parameters(declarator);
        // Walk the body's items directly so parameters share the body's scope.
        if let CNode::Compound(items) = self.ast.node(body) {
            let items = items.clone();
            self.walk_all(&items);
        }
        self.symbols.exit_scope();
    }

    fn declare_parameters(&mut self, declarator: &Declarator) {
        for derivation in &declarator.derivations {
            let Derivation::Function { params, .. } = derivation else {
                continue;
            };

            for param in params {
                if let Some(name) = param.declarator.name {
                    self.symbols.define(
                        name,
                        SymbolInfo {
                            kind: SymbolKind::Parameter,
                        },
                    );
                }
            }
        }
    }

    fn walk_declaration(&mut self, specifiers: &DeclSpecifiers, declarators: &[InitDeclarator]) {
        self.collect_enum_constants(specifiers);
        let kind = if specifiers.storage.contains(&StorageClass::Typedef) {
            SymbolKind::Typedef
        } else {
            SymbolKind::Variable
        };
        for init in declarators {
            if let Some(name) = init.declarator.name {
                self.declare(name, kind, &init.declarator);
            }
        }
    }

    /// Records enumeration constants declared by an `enum { ... }` specifier.
    fn collect_enum_constants(&mut self, specifiers: &DeclSpecifiers) {
        for spec in &specifiers.type_specifiers {
            let TypeSpecifier::Enum {
                enumerators: Some(enumerators),
                ..
            } = spec
            else {
                continue;
            };
            let mut next = 0i64;
            for enumerator in enumerators {
                let value = enumerator
                    .value
                    .and_then(|v| self.const_int(v))
                    .unwrap_or(next);
                self.symbols.define(
                    enumerator.name,
                    SymbolInfo {
                        kind: SymbolKind::EnumConstant(value),
                    },
                );
                next = value + 1;
            }
        }
    }

    /// Best-effort evaluation of a constant integer expression (literals only, for now).
    fn const_int(&self, id: CNodeId) -> Option<i64> {
        match self.ast.node(id) {
            CNode::IntLiteral(sym) | CNode::CharLiteral(sym) => {
                self.ast.resolve(*sym).unwrap_or("0").parse::<i64>().ok()
            }
            _ => None,
        }
    }

    /// Determines whether the declarator declares a function (has a function derivation).
    fn is_function_declarator(declarator: &Declarator) -> bool {
        matches!(
            declarator.derivations.first(),
            Some(Derivation::Function { .. })
        )
    }

    fn declare(&mut self, name: Symbol, mut kind: SymbolKind, declarator: &Declarator) {
        if kind == SymbolKind::Variable && Self::is_function_declarator(declarator) {
            kind = SymbolKind::Function;
        }
        let previous = self.symbols.define(name, SymbolInfo { kind });
        if let Some(previous) = previous {
            // Re-declaring a function or variable is allowed; conflicting kinds (e.g. typedef
            // vs variable) are not.
            if previous.kind != kind && !mergeable(previous.kind, kind) {
                let span = self.root_span();
                self.diagnostics.push(
                    Diagnostic::error(format!(
                        "`{}` redeclared as a different kind of symbol",
                        self.ast.resolve(name).unwrap_or("<invalid>")
                    ))
                    .with_label(Label::new(span, "redeclared here")),
                );
            }
        }
    }

    fn root_span(&self) -> Span {
        self.ast.root().map_or_else(
            || Span::point(FileId::from_raw(0), 0),
            |root| self.ast.span(root),
        )
    }
}

/// Returns `true` if two symbol kinds can co-exist for the same name (compatible redecls).
fn mergeable(a: SymbolKind, b: SymbolKind) -> bool {
    matches!(
        (a, b),
        (SymbolKind::Function, SymbolKind::Function) | (SymbolKind::Variable, SymbolKind::Variable)
    )
}

#[cfg(test)]
mod tests {
    use super::{Analyzer, mergeable};
    use crate::alloc_prelude::*;
    use crate::symbol::SymbolTable;
    use stratum_c_ast::CAst;
    use stratum_diagnostics::FileId;

    #[test]
    fn root_span_falls_back_when_ast_has_no_root() {
        let ast = CAst::new();
        let analyzer = Analyzer {
            ast: &ast,
            symbols: SymbolTable::new(),
            diagnostics: Vec::new(),
        };
        assert_eq!(analyzer.root_span().file(), FileId::from_raw(0));
    }

    #[test]
    fn only_same_kind_functions_and_variables_are_mergeable() {
        use crate::symbol::SymbolKind;

        assert!(mergeable(SymbolKind::Function, SymbolKind::Function));
        assert!(mergeable(SymbolKind::Variable, SymbolKind::Variable));
        assert!(!mergeable(SymbolKind::Typedef, SymbolKind::Variable));
    }

    #[test]
    fn declarator_without_function_derivation_has_no_parameters() {
        let ast = CAst::new();
        let mut analyzer = Analyzer {
            ast: &ast,
            symbols: SymbolTable::new(),
            diagnostics: Vec::new(),
        };
        analyzer.declare_parameters(&stratum_c_ast::Declarator::default());
        analyzer.declare_parameters(&stratum_c_ast::Declarator {
            name: None,
            derivations: vec![stratum_c_ast::Derivation::Pointer {
                qualifiers: Vec::new(),
            }],
        });
        assert!(analyzer.symbols.globals().is_empty());
    }
}
