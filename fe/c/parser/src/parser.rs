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
        if let Some(token) = self.tokens.get(pos).copied() {
            return token;
        }
        if let Some(token) = self.tokens.last().copied() {
            return token;
        }
        Token {
            kind: TokenKind::Eof,
            span: Span::point(FileId::from_raw(0), 0),
        }
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

    pub(crate) fn alloc_node(&mut self, node: CNode, span: Span) -> PResult<CNodeId> {
        self.ast.alloc(node, span).map_or(Err(ParseError), Ok)
    }

    pub(crate) fn intern_ast(&mut self, text: &str) -> PResult<Symbol> {
        self.ast.intern(text).map_or(Err(ParseError), Ok)
    }

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
            return self.alloc_node(node, start);
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
        self.alloc_node(node, span)
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
        self.alloc_node(CNode::StaticAssert { cond, message }, start.to(end))
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
        loop {
            if !self.eat_punct(Punctuator::Comma) {
                break;
            }
            let declarator = self.parse_declarator(false)?;
            self.push_init_declarator(declarator, is_typedef, &mut declarators)?;
        }
        let end = self.expect_punct(Punctuator::Semicolon)?;
        let node = CNode::Declaration {
            specifiers,
            declarators,
        };
        self.alloc_node(node, start.to(end))
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
        self.alloc_node(CNode::InitList(items), start.to(end))
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
    use super::Parser;
    use stratum_arena::{Interner, Symbol};
    use stratum_c_lexer::{Dialect, Keyword, Punctuator, Token, TokenKind};
    use stratum_diagnostics::{FileId, Span};

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    #[test]
    fn public_parse_accepts_empty_token_stream() {
        let result = crate::parse(&[], Interner::new()).unwrap();
        assert!(!result.has_errors());
        assert!(result.ast.root().is_some());
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

    #[test]
    fn add_typedef_is_noop_without_active_scope() {
        let mut parser = Parser::new(&[], Interner::new());
        parser.exit_scope();

        parser.add_typedef(Symbol::default());

        assert!(!parser.is_typedef_name(Symbol::default()));
    }

    #[test]
    fn token_lookup_past_non_empty_stream_returns_last_token() {
        let eof = Token {
            kind: TokenKind::Eof,
            span: Span::point(FileId::from_raw(0), 7),
        };
        let tokens = [eof];
        let parser = Parser::new(&tokens, Interner::new());

        assert_eq!(parser.token_at_or_eof(1).span, eof.span);
    }

    #[test]
    fn token_lookup_on_empty_stream_returns_synthetic_eof() {
        let parser = Parser::new(&[], Interner::new());
        let token = parser.token_at_or_eof(0);

        assert_eq!(token.kind, TokenKind::Eof);
        assert_eq!(token.span, Span::point(FileId::from_raw(0), 0));
    }

    #[test]
    fn recovery_edges_are_covered_directly() {
        let nested_attributes = [
            Token {
                kind: TokenKind::Punct(Punctuator::LBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Eof,
                span: span(),
            },
        ];
        let mut parser = Parser::new(&nested_attributes, Interner::new());
        parser.dialect = Dialect::C23;
        parser.skip_attribute_specifiers().ok().unwrap();

        let mut parser = Parser::new(&[], Interner::new());
        parser.dialect = Dialect::C89;
        assert!(parser.require(Dialect::C99, "future feature").is_err());

        let tokens = [Token {
            kind: TokenKind::Punct(Punctuator::Semicolon),
            span: span(),
        }];
        let mut parser = Parser::new(&tokens, Interner::new());
        parser.synchronize();
        assert_eq!(parser.pos, 0);

        let tokens = [Token {
            kind: TokenKind::Punct(Punctuator::RBrace),
            span: span(),
        }];
        let mut parser = Parser::new(&tokens, Interner::new());
        parser.synchronize();
        assert_eq!(parser.pos, 0);

        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::RBrace),
                span: span(),
            },
            Token {
                kind: TokenKind::Eof,
                span: span(),
            },
        ];
        let result = crate::parse(&tokens, Interner::new()).unwrap();
        assert!(result.has_errors());
    }

    #[test]
    fn dialect_error_edges_are_covered_directly() {
        let mut parser = Parser::new(&[], Interner::new());
        parser.dialect = Dialect::C89;
        assert!(parser.require(Dialect::C99, "future feature").is_err());

        let empty_initializer = [
            Token {
                kind: TokenKind::Punct(Punctuator::LBrace),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RBrace),
                span: span(),
            },
        ];
        let mut parser = Parser::new(&empty_initializer, Interner::new());
        parser.dialect = Dialect::C17;
        assert!(parser.parse_brace_initializer().is_err());
    }

    #[test]
    fn static_assert_error_edges_are_covered_directly() {
        let static_assert_without_message = [
            Token {
                kind: TokenKind::Keyword(Keyword::StaticAssert),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Integer {
                    value: 1,
                    unsigned: false,
                },
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
        ];
        let mut parser = Parser::new(&static_assert_without_message, Interner::new());
        parser.dialect = Dialect::C11;
        assert!(parser.parse_static_assert().is_err());

        let static_assert_with_bad_message = [
            Token {
                kind: TokenKind::Keyword(Keyword::StaticAssert),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Integer {
                    value: 1,
                    unsigned: false,
                },
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Comma),
                span: span(),
            },
            Token {
                kind: TokenKind::Keyword(Keyword::Int),
                span: span(),
            },
        ];
        let mut parser = Parser::new(&static_assert_with_bad_message, Interner::new());
        parser.dialect = Dialect::C11;
        assert!(parser.parse_static_assert().is_err());
    }
}
