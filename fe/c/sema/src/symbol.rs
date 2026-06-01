//! Symbol kinds and scoped symbol tables.

use crate::alloc_prelude::*;
use core::ops::Index;
use stratum_arena::Symbol;
use stratum_utils::HashMap;

/// What a name denotes in C's ordinary identifier namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// A name introduced by `typedef`.
    Typedef,
    /// A variable (object) with the given storage having external/internal/automatic linkage.
    Variable,
    /// A function (declaration or definition).
    Function,
    /// A function parameter.
    Parameter,
    /// An enumeration constant with its computed value.
    EnumConstant(i64),
}

/// Information recorded for a declared name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolInfo {
    /// What the name denotes.
    pub kind: SymbolKind,
}

/// A lexically scoped symbol table for C's ordinary identifiers.
///
/// Tags (`struct`/`union`/`enum` names) live in a separate namespace in C; this skeletal
/// table tracks the ordinary-identifier namespace only, which is what later stages currently
/// need.
#[derive(Debug)]
pub struct SymbolTable {
    scopes: Vec<HashMap<Symbol, SymbolInfo>>,
}

impl SymbolTable {
    /// Creates a table with a single (global) scope.
    #[must_use]
    pub fn new() -> Self {
        Self {
            scopes: vec![HashMap::default()],
        }
    }

    /// Pushes a new innermost scope.
    pub fn enter_scope(&mut self) {
        self.scopes.push(HashMap::default());
    }

    /// Pops the innermost scope.
    ///
    /// The global scope is never popped.
    pub fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Returns `true` if currently at global scope.
    #[must_use]
    pub fn at_global_scope(&self) -> bool {
        self.scopes.len() == 1
    }

    /// Defines `name` in the innermost scope.
    ///
    /// Returns the previous definition in that same scope, if any (a redefinition).
    pub fn define(&mut self, name: Symbol, info: SymbolInfo) -> Option<SymbolInfo> {
        match self.scopes.last_mut() {
            Some(scope) => scope.insert(name, info),
            None => None,
        }
    }

    /// Looks up `name`, searching from the innermost scope outward.
    #[must_use]
    pub fn lookup(&self, name: Symbol) -> Option<SymbolInfo> {
        self.scopes.iter().rev().find_map(|s| s.get(&name).copied())
    }

    /// Returns the global scope's bindings.
    #[must_use]
    pub fn globals(&self) -> &HashMap<Symbol, SymbolInfo> {
        self.scopes.first().unwrap_or_else(|| self.scopes.index(0))
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{SymbolInfo, SymbolKind, SymbolTable};
    use crate::alloc_prelude::*;
    use stratum_arena::Interner;

    #[test]
    fn scope_helpers_and_globals_are_stable() {
        let mut interner = Interner::new();
        let name = interner.intern("x").unwrap();
        let mut table = SymbolTable::default();

        assert!(table.at_global_scope());
        assert_eq!(
            table.define(
                name,
                SymbolInfo {
                    kind: SymbolKind::Variable
                }
            ),
            None
        );
        assert_eq!(table.globals().len(), 1);

        table.enter_scope();
        assert!(!table.at_global_scope());
        assert_eq!(
            table.define(
                name,
                SymbolInfo {
                    kind: SymbolKind::Parameter
                }
            ),
            None
        );
        assert_eq!(
            table.lookup(name).map(|info| info.kind),
            Some(SymbolKind::Parameter)
        );
        table.exit_scope();
        table.exit_scope();
        assert!(table.at_global_scope());
        assert_eq!(
            table.lookup(name).map(|info| info.kind),
            Some(SymbolKind::Variable)
        );
    }

    #[test]
    fn define_handles_empty_scope_stack() {
        let mut interner = Interner::new();
        let name = interner.intern("x").unwrap();
        let mut table = SymbolTable { scopes: Vec::new() };
        assert_eq!(
            table.define(
                name,
                SymbolInfo {
                    kind: SymbolKind::Variable
                }
            ),
            None
        );
        assert!(std::panic::catch_unwind(|| table.globals()).is_err());
    }
}
