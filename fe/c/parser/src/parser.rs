//! The recursive-descent parser: cursor, scopes, and the top-level grammar.

use crate::alloc_prelude::*;
use stratum_utils::HashSet;

use stratum_arena::{Interner, Symbol};
use stratum_c_ast::{
    CAst, CNode, CNodeId, DeclSpecifiers, Declarator, Designator, InitDeclarator, InitItem,
    StorageClass,
};
use stratum_c_lexer::{Dialect, Keyword, Punctuator, Token, TokenKind};
use stratum_diagnostics::{Diagnostic, FileId, Label, Span};

/// The result of parsing a translation unit.
#[derive(Debug)]
pub struct ParseResult {
    /// The parsed AST (its root is the translation unit, if parsing produced one).
    pub ast: CAst,
    /// Diagnostics produced during parsing.
    pub diagnostics: Vec<Diagnostic>,
}

impl ParseResult {
    /// Returns `true` if any error-severity diagnostics were produced.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        !self.diagnostics.is_empty()
    }
}

/// A marker indicating a diagnostic has been recorded and the caller should recover.
pub(crate) struct ParseError;

impl From<stratum_c_ast::Error> for ParseError {
    fn from(_: stratum_c_ast::Error) -> Self {
        ParseError
    }
}

pub(crate) type PResult<T> = Result<T, ParseError>;

/// Parses a finalized token stream into a [`CAst`].
///
/// `interner` must be the interner that produced the token symbols; it is moved into the
/// resulting AST so symbols resolve consistently.
///
/// # Errors
///
/// Returns an error if the parser cannot allocate the translation-unit root in the AST.
pub fn parse(tokens: &[Token], interner: Interner) -> crate::Result<ParseResult> {
    parse_with_dialect(tokens, interner, Dialect::DEFAULT)
}

/// Parses a finalized token stream under a specific ISO C dialect.
///
/// # Errors
///
/// Returns an error if the parser cannot allocate the translation-unit root in the AST.
pub fn parse_with_dialect(
    tokens: &[Token],
    interner: Interner,
    dialect: Dialect,
) -> crate::Result<ParseResult> {
    let mut parser = Parser::new_with_dialect(tokens, interner, dialect);
    parser.parse_translation_unit()?;
    Ok(ParseResult {
        ast: parser.ast,
        diagnostics: parser.diagnostics,
    })
}

pub(crate) struct Parser<'a> {
    pub(crate) tokens: &'a [Token],
    pub(crate) pos: usize,
    pub(crate) ast: CAst,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) typedefs: Vec<HashSet<Symbol>>,
    pub(crate) dialect: Dialect,
}

impl<'a> Parser<'a> {
    #[cfg(test)]
    fn new(tokens: &'a [Token], interner: Interner) -> Self {
        Self::new_with_dialect(tokens, interner, Dialect::DEFAULT)
    }

    fn new_with_dialect(tokens: &'a [Token], interner: Interner, dialect: Dialect) -> Self {
        Self {
            tokens,
            pos: 0,
            ast: CAst::with_interner(interner),
            diagnostics: Vec::new(),
            typedefs: vec![HashSet::default()],
            dialect,
        }
    }

    // --- Token cursor ----------------------------------------------------------------------

    pub(crate) fn peek(&self) -> Token {
        self.token_at_or_eof(self.pos)
    }

    pub(crate) fn peek_kind(&self) -> TokenKind {
        self.peek().kind
    }

    pub(crate) fn peek2_kind(&self) -> TokenKind {
        self.token_at_or_eof(self.pos.saturating_add(1)).kind
    }

    fn token_at_or_eof(&self, pos: usize) -> Token {
        self.tokens
            .get(pos)
            .or_else(|| self.tokens.last())
            .copied()
            .unwrap_or(Token {
                kind: TokenKind::Eof,
                span: Span::point(FileId::from_raw(0), 0),
            })
    }

    pub(crate) fn at_eof(&self) -> bool {
        matches!(self.peek_kind(), TokenKind::Eof)
    }

    pub(crate) fn bump(&mut self) -> Token {
        let token = self.peek();
        if self.pos.saturating_add(1) < self.tokens.len() {
            self.pos += 1;
        }
        token
    }

    pub(crate) fn is_punct(&self, punct: Punctuator) -> bool {
        self.peek_kind() == TokenKind::Punct(punct)
    }

    pub(crate) fn is_keyword(&self, keyword: Keyword) -> bool {
        self.peek_kind() == TokenKind::Keyword(keyword)
    }

    pub(crate) fn eat_punct(&mut self, punct: Punctuator) -> bool {
        if self.is_punct(punct) {
            self.bump();
            true
        } else {
            false
        }
    }

    pub(crate) fn eat_keyword(&mut self, keyword: Keyword) -> bool {
        if self.is_keyword(keyword) {
            self.bump();
            true
        } else {
            false
        }
    }

    pub(crate) fn expect_punct(&mut self, punct: Punctuator) -> PResult<Span> {
        if self.is_punct(punct) {
            Ok(self.bump().span)
        } else {
            Err(self.error(&format!("expected `{}`", punct.spelling())))
        }
    }

    pub(crate) fn is_attribute_start(&self) -> bool {
        self.is_punct(Punctuator::LBracket)
            && self.peek2_kind() == TokenKind::Punct(Punctuator::LBracket)
    }

    pub(crate) fn skip_attribute_specifiers(&mut self) -> PResult<()> {
        while self.is_attribute_start() {
            self.require(Dialect::C23, "attribute specifier")?;
            self.bump(); // `[`
            self.bump(); // `[`
            let mut depth = 1usize;
            while depth != 0 {
                if self.at_eof() {
                    return Err(self.error("unterminated attribute specifier"));
                }
                if self.is_attribute_start() {
                    self.bump();
                    self.bump();
                    depth = depth.saturating_add(1);
                } else if self.is_punct(Punctuator::RBracket)
                    && self.peek2_kind() == TokenKind::Punct(Punctuator::RBracket)
                {
                    self.bump();
                    self.bump();
                    depth = depth.saturating_sub(1);
                } else {
                    self.bump();
                }
            }
        }
        Ok(())
    }

    // --- Diagnostics & recovery ------------------------------------------------------------

    pub(crate) fn error(&mut self, message: &str) -> ParseError {
        let span = self.peek().span;
        self.error_at(span, message)
    }

    pub(crate) fn error_at(&mut self, span: Span, message: &str) -> ParseError {
        self.diagnostics
            .push(Diagnostic::error(message.to_string()).with_label(Label::new(span, "here")));
        ParseError
    }

    pub(crate) fn supports(&self, dialect: Dialect) -> bool {
        self.dialect.supports(dialect)
    }

    pub(crate) fn require(&mut self, dialect: Dialect, feature: &str) -> PResult<()> {
        if self.supports(dialect) {
            Ok(())
        } else {
            Err(self.error(&format!(
                "{feature} requires {} or later",
                dialect.spelling()
            )))
        }
    }

    /// Skips tokens until just past the next `;` or balanced `}`, for panic-mode recovery.
    pub(crate) fn synchronize(&mut self) {
        while !self.at_eof() {
            if self.eat_punct(Punctuator::Semicolon) {
                return;
            }
            if self.is_punct(Punctuator::RBrace) {
                return;
            }
            self.bump();
        }
    }

    // --- Scopes & typedef table ------------------------------------------------------------

    pub(crate) fn enter_scope(&mut self) {
        self.typedefs.push(HashSet::default());
    }

    pub(crate) fn exit_scope(&mut self) {
        self.typedefs.pop();
    }

    pub(crate) fn add_typedef(&mut self, name: Symbol) {
        if let Some(scope) = self.typedefs.last_mut() {
            scope.insert(name);
        }
    }

    pub(crate) fn is_typedef_name(&self, name: Symbol) -> bool {
        self.typedefs.iter().rev().any(|s| s.contains(&name))
    }

    // --- Top level -------------------------------------------------------------------------

    fn parse_translation_unit(&mut self) -> crate::Result<()> {
        let start = self.peek().span;
        let mut items = Vec::new();
        while !self.at_eof() {
            let before = self.pos;
            match self.parse_external_declaration() {
                Ok(id) => items.push(id),
                Err(ParseError) => self.synchronize(),
            }
            if self.pos == before {
                self.bump();
            }
        }
        let span = items
            .first()
            .map_or(start, |&id| start.to(self.ast.span(id)));
        let tu = self.ast.alloc(CNode::TranslationUnit(items), span)?;
        self.ast.set_root(tu);
        Ok(())
    }

    /// Parses one external declaration (a function definition or a declaration).
    fn parse_external_declaration(&mut self) -> PResult<CNodeId> {
        self.skip_attribute_specifiers()?;
        if let TokenKind::Keyword(kw) = self.peek_kind()
            && crate::decl::is_static_assert_keyword(kw)
        {
            return self.parse_static_assert();
        }
        let start = self.peek().span;
        let specifiers = self.parse_decl_specifiers()?;

        if self.eat_punct(Punctuator::Semicolon) {
            let node = CNode::Declaration {
                specifiers,
                declarators: Vec::new(),
            };
            return Ok(self.ast.alloc(node, start)?);
        }

        let declarator = self.parse_declarator(false)?;

        if self.is_punct(Punctuator::LBrace) {
            return self.finish_function_def(specifiers, declarator, start);
        }
        self.finish_declaration(specifiers, declarator, start)
    }

    fn finish_function_def(
        &mut self,
        specifiers: DeclSpecifiers,
        declarator: Declarator,
        start: Span,
    ) -> PResult<CNodeId> {
        let body = self.parse_compound_statement()?;
        let span = start.to(self.ast.span(body));
        let node = CNode::FunctionDef {
            specifiers,
            declarator,
            body,
        };
        Ok(self.ast.alloc(node, span)?)
    }

    pub(crate) fn parse_static_assert(&mut self) -> PResult<CNodeId> {
        let kw = match self.peek_kind() {
            TokenKind::Keyword(kw) if crate::decl::is_static_assert_keyword(kw) => kw,
            _ => return Err(self.error("expected static assertion")),
        };
        let minimum = if kw == Keyword::C23StaticAssert {
            Dialect::C23
        } else {
            Dialect::C11
        };
        self.require(minimum, "static assertion")?;
        let start = self.bump().span;
        self.expect_punct(Punctuator::LParen)?;
        let cond = self.parse_conditional()?;
        let message = if self.eat_punct(Punctuator::Comma) {
            match self.bump().kind {
                TokenKind::String(sym) => Some(sym),
                _ => return Err(self.error("expected a string literal in static assertion")),
            }
        } else {
            if !self.supports(Dialect::C23) {
                return Err(self.error("message-less static assertion requires c23 or later"));
            }
            None
        };
        self.expect_punct(Punctuator::RParen)?;
        let end = self.expect_punct(Punctuator::Semicolon)?;
        Ok(self
            .ast
            .alloc(CNode::StaticAssert { cond, message }, start.to(end))?)
    }

    pub(crate) fn finish_declaration(
        &mut self,
        specifiers: DeclSpecifiers,
        first: Declarator,
        start: Span,
    ) -> PResult<CNodeId> {
        let is_typedef = specifiers.storage.contains(&StorageClass::Typedef);
        let mut declarators = Vec::new();
        self.push_init_declarator(first, is_typedef, &mut declarators)?;
        while self.eat_punct(Punctuator::Comma) {
            let declarator = self.parse_declarator(false)?;
            self.push_init_declarator(declarator, is_typedef, &mut declarators)?;
        }
        let end = self.expect_punct(Punctuator::Semicolon)?;
        let node = CNode::Declaration {
            specifiers,
            declarators,
        };
        Ok(self.ast.alloc(node, start.to(end))?)
    }

    fn push_init_declarator(
        &mut self,
        declarator: Declarator,
        is_typedef: bool,
        out: &mut Vec<InitDeclarator>,
    ) -> PResult<()> {
        if is_typedef && let Some(name) = declarator.name {
            self.add_typedef(name);
        }
        let init = if self.eat_punct(Punctuator::Assign) {
            Some(self.parse_initializer()?)
        } else {
            None
        };
        out.push(InitDeclarator { declarator, init });
        Ok(())
    }

    /// Parses an initialiser: an assignment expression or a braced initialiser list.
    fn parse_initializer(&mut self) -> PResult<CNodeId> {
        if self.is_punct(Punctuator::LBrace) {
            self.parse_brace_initializer()
        } else {
            self.parse_assignment()
        }
    }

    pub(crate) fn parse_brace_initializer(&mut self) -> PResult<CNodeId> {
        let start = self.expect_punct(Punctuator::LBrace)?;
        let mut items = Vec::new();
        if self.is_punct(Punctuator::RBrace) && !self.supports(Dialect::C23) {
            return Err(self.error("empty initializer requires c23 or later"));
        }
        while !self.is_punct(Punctuator::RBrace) && !self.at_eof() {
            items.push(self.parse_init_item()?);
            if !self.eat_punct(Punctuator::Comma) {
                break;
            }
        }
        let end = self.expect_punct(Punctuator::RBrace)?;
        Ok(self.ast.alloc(CNode::InitList(items), start.to(end))?)
    }

    /// Parses one initialiser-list entry: an optional designator list (terminated by `=`)
    /// followed by an initialiser value.
    fn parse_init_item(&mut self) -> PResult<InitItem> {
        let designators = self.parse_designators()?;
        let value = self.parse_initializer()?;
        Ok(InitItem { designators, value })
    }

    /// Parses a (possibly empty) C99 designator list such as `.x[0].y =`.
    fn parse_designators(&mut self) -> PResult<Vec<Designator>> {
        let mut designators = Vec::new();
        loop {
            if self.eat_punct(Punctuator::Dot) {
                let Some(name) = self.eat_identifier() else {
                    return Err(self.error("expected a field name after `.` in designator"));
                };
                designators.push(Designator::Field(name));
            } else if self.is_punct(Punctuator::LBracket) {
                self.bump();
                let index = self.parse_conditional()?;
                self.expect_punct(Punctuator::RBracket)?;
                designators.push(Designator::Index(index));
            } else {
                break;
            }
        }
        if !designators.is_empty() {
            self.require(Dialect::C99, "designated initializer")?;
            self.expect_punct(Punctuator::Assign)?;
        }
        Ok(designators)
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseError, Parser};
    use stratum_arena::Interner;
    use stratum_c_lexer::{Punctuator, Token, TokenKind};
    use stratum_diagnostics::{FileId, Span};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn parse_error_converts_from_ast_error() {
        let _err: ParseError = stratum_c_ast::Error::InconsistentNodeStorage.into();
    }

    #[test]
    fn field_designator_requires_a_name() {
        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::Dot),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Assign),
                span: span(),
            },
        ];
        let mut parser = Parser::new(&tokens, Interner::new());
        assert!(parser.parse_designators().is_err());
        assert!(!parser.diagnostics.is_empty());
    }

    #[test]
    fn static_assert_entry_rejects_wrong_token_when_called_directly() {
        let tokens = [Token {
            kind: TokenKind::Punct(Punctuator::Semicolon),
            span: span(),
        }];
        let mut parser = Parser::new(&tokens, Interner::new());
        assert!(parser.parse_static_assert().is_err());
    }
}
