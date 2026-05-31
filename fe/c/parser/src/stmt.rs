//! Parsing of statements.

use crate::alloc_prelude::*;
use crate::parser::{PResult, Parser};
use stratum_c_ast::{CNode, CNodeId};
use stratum_c_lexer::{Dialect, Keyword, Punctuator, TokenKind};

impl Parser<'_> {
    /// Parses a `{ ... }` compound statement, introducing a new scope.
    pub(crate) fn parse_compound_statement(&mut self) -> PResult<CNodeId> {
        let start = self.expect_punct(Punctuator::LBrace)?;
        self.enter_scope();
        let mut items = Vec::new();
        let mut seen_statement = false;
        while !self.is_punct(Punctuator::RBrace) && !self.at_eof() {
            let is_decl = self.at_declaration_start();
            if is_decl && seen_statement && !self.supports(Dialect::C99) {
                self.error("declarations after statements require c99 or later");
                self.synchronize();
                continue;
            }
            match self.parse_block_item() {
                Ok(id) => items.push(id),
                Err(_) => self.synchronize(),
            }
            if !is_decl {
                seen_statement = true;
            }
        }
        self.exit_scope();
        let end = self.expect_punct(Punctuator::RBrace)?;
        Ok(self.ast.alloc(CNode::Compound(items), start.to(end))?)
    }

    fn parse_block_item(&mut self) -> PResult<CNodeId> {
        self.skip_attribute_specifiers()?;
        if let TokenKind::Keyword(kw) = self.peek_kind()
            && crate::decl::is_static_assert_keyword(kw)
        {
            return self.parse_static_assert();
        }
        if self.at_declaration_start() {
            self.parse_declaration()
        } else {
            self.parse_statement()
        }
    }

    /// Parses a local declaration (reusing the external-declaration declarator machinery).
    fn parse_declaration(&mut self) -> PResult<CNodeId> {
        self.skip_attribute_specifiers()?;
        if let TokenKind::Keyword(kw) = self.peek_kind()
            && crate::decl::is_static_assert_keyword(kw)
        {
            return self.parse_static_assert();
        }
        let start = self.peek().span;
        let specifiers = self.parse_decl_specifiers()?;
        if self.eat_punct(Punctuator::Semicolon) {
            return self
                .ast
                .alloc(
                    CNode::Declaration {
                        specifiers,
                        declarators: Vec::new(),
                    },
                    start,
                )
                .map_err(Into::into);
        }
        let first = self.parse_declarator(false)?;
        self.finish_declaration(specifiers, first, start)
    }

    /// Parses a statement.
    pub(crate) fn parse_statement(&mut self) -> PResult<CNodeId> {
        self.skip_attribute_specifiers()?;
        match self.peek_kind() {
            TokenKind::Punct(Punctuator::LBrace) => self.parse_compound_statement(),
            TokenKind::Keyword(Keyword::If) => self.parse_if(),
            TokenKind::Keyword(Keyword::While) => self.parse_while(),
            TokenKind::Keyword(Keyword::Do) => self.parse_do_while(),
            TokenKind::Keyword(Keyword::For) => self.parse_for(),
            TokenKind::Keyword(Keyword::Return) => self.parse_return(),
            TokenKind::Keyword(Keyword::Break) => self.parse_simple(CNode::Break),
            TokenKind::Keyword(Keyword::Continue) => self.parse_simple(CNode::Continue),
            TokenKind::Keyword(Keyword::Goto) => self.parse_goto(),
            TokenKind::Keyword(Keyword::Switch) => self.parse_switch(),
            TokenKind::Keyword(Keyword::Case) => self.parse_case(),
            TokenKind::Keyword(Keyword::Default) => self.parse_default(),
            TokenKind::Identifier(_)
                if self.peek2_kind() == TokenKind::Punct(Punctuator::Colon) =>
            {
                self.parse_label()
            }
            _ => self.parse_expr_statement(),
        }
    }

    fn parse_if(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `if`
        self.expect_punct(Punctuator::LParen)?;
        let cond = self.parse_expr()?;
        self.expect_punct(Punctuator::RParen)?;
        let then_branch = self.parse_statement()?;
        let else_branch = if self.eat_keyword(Keyword::Else) {
            Some(self.parse_statement()?)
        } else {
            None
        };
        let end = else_branch.unwrap_or(then_branch);
        let node = CNode::If {
            cond,
            then_branch,
            else_branch,
        };
        Ok(self.ast.alloc(node, start.to(self.ast.span(end)))?)
    }

    fn parse_while(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `while`
        self.expect_punct(Punctuator::LParen)?;
        let cond = self.parse_expr()?;
        self.expect_punct(Punctuator::RParen)?;
        let body = self.parse_statement()?;
        let span = start.to(self.ast.span(body));
        Ok(self.ast.alloc(CNode::While { cond, body }, span)?)
    }

    fn parse_do_while(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `do`
        let body = self.parse_statement()?;
        if !self.eat_keyword(Keyword::While) {
            return Err(self.error("expected `while` after `do` body"));
        }
        self.expect_punct(Punctuator::LParen)?;
        let cond = self.parse_expr()?;
        self.expect_punct(Punctuator::RParen)?;
        let end = self.expect_punct(Punctuator::Semicolon)?;
        Ok(self
            .ast
            .alloc(CNode::DoWhile { body, cond }, start.to(end))?)
    }

    fn parse_for(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `for`
        self.expect_punct(Punctuator::LParen)?;
        self.enter_scope();
        let init = self.parse_for_init()?;
        let cond = self.parse_optional_expr(Punctuator::Semicolon)?;
        self.expect_punct(Punctuator::Semicolon)?;
        let step = self.parse_optional_expr(Punctuator::RParen)?;
        self.expect_punct(Punctuator::RParen)?;
        let body = self.parse_statement()?;
        self.exit_scope();
        let span = start.to(self.ast.span(body));
        let node = CNode::For {
            init,
            cond,
            step,
            body,
        };
        Ok(self.ast.alloc(node, span)?)
    }

    fn parse_for_init(&mut self) -> PResult<Option<CNodeId>> {
        if self.eat_punct(Punctuator::Semicolon) {
            return Ok(None);
        }
        if self.at_declaration_start() {
            self.require(Dialect::C99, "declaration in `for` initializer")?;
            let start = self.peek().span;
            let specifiers = self.parse_decl_specifiers()?;
            let first = self.parse_declarator(false)?;
            return Ok(Some(self.finish_declaration(specifiers, first, start)?));
        }
        let expr = self.parse_expr()?;
        self.expect_punct(Punctuator::Semicolon)?;
        Ok(Some(expr))
    }

    fn parse_optional_expr(&mut self, terminator: Punctuator) -> PResult<Option<CNodeId>> {
        if self.is_punct(terminator) {
            Ok(None)
        } else {
            Ok(Some(self.parse_expr()?))
        }
    }

    fn parse_return(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `return`
        let value = if self.is_punct(Punctuator::Semicolon) {
            None
        } else {
            Some(self.parse_expr()?)
        };
        let end = self.expect_punct(Punctuator::Semicolon)?;
        Ok(self.ast.alloc(CNode::Return(value), start.to(end))?)
    }

    fn parse_simple(&mut self, node: CNode) -> PResult<CNodeId> {
        let start = self.bump().span; // `break` / `continue`
        let end = self.expect_punct(Punctuator::Semicolon)?;
        Ok(self.ast.alloc(node, start.to(end))?)
    }

    fn parse_goto(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `goto`
        let Some(label) = self.eat_identifier() else {
            return Err(self.error("expected a label after `goto`"));
        };
        let end = self.expect_punct(Punctuator::Semicolon)?;
        Ok(self.ast.alloc(CNode::Goto(label), start.to(end))?)
    }

    fn parse_label(&mut self) -> PResult<CNodeId> {
        let start = self.peek().span;
        let Some(name) = self.eat_identifier() else {
            return Err(self.error("expected a label name"));
        };
        self.expect_punct(Punctuator::Colon)?;
        let body = if self.supports(Dialect::C23) && self.at_declaration_start() {
            self.parse_declaration()?
        } else if self.supports(Dialect::C23) && self.is_punct(Punctuator::RBrace) {
            self.ast.alloc(CNode::ExprStmt(None), start)?
        } else {
            self.parse_statement()?
        };
        let span = start.to(self.ast.span(body));
        Ok(self.ast.alloc(CNode::Label { name, body }, span)?)
    }

    fn parse_switch(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `switch`
        self.expect_punct(Punctuator::LParen)?;
        let cond = self.parse_expr()?;
        self.expect_punct(Punctuator::RParen)?;
        let body = self.parse_statement()?;
        let span = start.to(self.ast.span(body));
        Ok(self.ast.alloc(CNode::Switch { cond, body }, span)?)
    }

    fn parse_case(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `case`
        let value = self.parse_conditional()?;
        self.expect_punct(Punctuator::Colon)?;
        let body = self.parse_statement()?;
        let span = start.to(self.ast.span(body));
        Ok(self.ast.alloc(CNode::Case { value, body }, span)?)
    }

    fn parse_default(&mut self) -> PResult<CNodeId> {
        let start = self.bump().span; // `default`
        self.expect_punct(Punctuator::Colon)?;
        let body = self.parse_statement()?;
        let span = start.to(self.ast.span(body));
        Ok(self.ast.alloc(CNode::Default { body }, span)?)
    }

    fn parse_expr_statement(&mut self) -> PResult<CNodeId> {
        let start = self.peek().span;
        if self.is_punct(Punctuator::Semicolon) {
            let end = self.bump().span;
            return Ok(self.ast.alloc(CNode::ExprStmt(None), start.to(end))?);
        }
        let expr = self.parse_expr()?;
        let end = self.expect_punct(Punctuator::Semicolon)?;
        Ok(self.ast.alloc(CNode::ExprStmt(Some(expr)), start.to(end))?)
    }
}

#[cfg(test)]
mod tests {
    use crate::alloc_prelude::*;
    use crate::parser::Parser;
    use stratum_arena::Interner;
    use stratum_c_ast::{CAst, CNode};
    use stratum_c_lexer::{Dialect, Keyword, Punctuator, Token, TokenKind};
    use stratum_diagnostics::{FileId, Span};
    use stratum_utils::HashSet;

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn parser_with(tokens: &[Token]) -> Parser<'_> {
        Parser {
            tokens,
            pos: 0,
            ast: CAst::with_interner(Interner::new()),
            diagnostics: Vec::new(),
            typedefs: vec![HashSet::default()],
            dialect: Dialect::DEFAULT,
        }
    }

    #[test]
    fn local_empty_declaration_is_preserved() {
        let tokens = [
            Token {
                kind: TokenKind::Keyword(Keyword::Int),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens);
        let id = parser.parse_declaration().ok().unwrap();
        assert!(
            matches!(parser.ast.node(id), CNode::Declaration { declarators, .. } if declarators.is_empty())
        );
    }

    #[test]
    fn malformed_do_goto_and_label_paths_report_errors() {
        let tokens = [
            Token {
                kind: TokenKind::Keyword(Keyword::Do),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens);
        assert!(parser.parse_statement().is_err());

        let tokens = [
            Token {
                kind: TokenKind::Keyword(Keyword::Goto),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens);
        assert!(parser.parse_statement().is_err());

        let tokens = [Token {
            kind: TokenKind::Punct(Punctuator::Semicolon),
            span: span(),
        }];
        let mut parser = parser_with(&tokens);
        assert!(parser.parse_label().is_err());
    }

    #[test]
    fn declaration_entry_handles_static_assert_directly() {
        let tokens = [
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
                kind: TokenKind::String(stratum_arena::Symbol::default()),
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
        let mut parser = parser_with(&tokens);
        parser.dialect = Dialect::C11;
        let id = parser.parse_declaration().ok().unwrap();
        assert!(matches!(parser.ast.node(id), CNode::StaticAssert { .. }));
    }
}
