//! Parsing of declaration specifiers, declarators, type names, and aggregates.

use crate::alloc_prelude::*;
use crate::parser::{PResult, Parser};
use stratum_c_ast::{
    DeclSpecifiers, Declarator, Derivation, Enumerator, FieldDecl, ParamDecl, StorageClass,
    TypeName, TypeQualifier, TypeSpecifier,
};
use stratum_c_lexer::{Keyword, Punctuator, TokenKind};

impl Parser<'_> {
    /// Returns `true` if the current token begins a declaration.
    pub(crate) fn at_declaration_start(&self) -> bool {
        match self.peek_kind() {
            TokenKind::Keyword(kw) => is_specifier_keyword(kw),
            TokenKind::Identifier(sym) => self.is_typedef_name(sym),
            _ => false,
        }
    }

    /// Parses a (possibly empty) sequence of declaration specifiers.
    pub(crate) fn parse_decl_specifiers(&mut self) -> PResult<DeclSpecifiers> {
        let mut specs = DeclSpecifiers::default();
        let mut has_type = false;
        loop {
            match self.peek_kind() {
                TokenKind::Keyword(kw) if self.absorb_keyword(kw, &mut specs, &mut has_type)? => {}
                TokenKind::Identifier(sym) if !has_type && self.is_typedef_name(sym) => {
                    self.bump();
                    specs.type_specifiers.push(TypeSpecifier::TypedefName(sym));
                    has_type = true;
                }
                _ => break,
            }
        }
        Ok(specs)
    }

    /// Absorbs one specifier keyword; returns `false` if the keyword is not a specifier.
    fn absorb_keyword(
        &mut self,
        kw: Keyword,
        specs: &mut DeclSpecifiers,
        has_type: &mut bool,
    ) -> PResult<bool> {
        if let Some(storage) = storage_class(kw) {
            self.bump();
            specs.storage.push(storage);
        } else if let Some(qual) = type_qualifier(kw) {
            self.bump();
            specs.qualifiers.push(qual);
        } else if kw == Keyword::Inline {
            self.bump();
            specs.inline = true;
        } else if let Some(spec) = simple_type_specifier(kw) {
            self.bump();
            specs.type_specifiers.push(spec);
            *has_type = true;
        } else if matches!(kw, Keyword::Struct | Keyword::Union) {
            let spec = self.parse_struct_or_union(kw)?;
            specs.type_specifiers.push(spec);
            *has_type = true;
        } else if kw == Keyword::Enum {
            let spec = self.parse_enum()?;
            specs.type_specifiers.push(spec);
            *has_type = true;
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    fn parse_struct_or_union(&mut self, kw: Keyword) -> PResult<TypeSpecifier> {
        self.bump(); // `struct` / `union`
        let tag = self.eat_identifier();
        let fields = if self.is_punct(Punctuator::LBrace) {
            Some(self.parse_field_list()?)
        } else {
            None
        };
        Ok(if kw == Keyword::Struct {
            TypeSpecifier::Struct { tag, fields }
        } else {
            TypeSpecifier::Union { tag, fields }
        })
    }

    fn parse_field_list(&mut self) -> PResult<Vec<FieldDecl>> {
        self.expect_punct(Punctuator::LBrace)?;
        let mut fields = Vec::new();
        while !self.is_punct(Punctuator::RBrace) && !self.at_eof() {
            let specifiers = self.parse_decl_specifiers()?;
            loop {
                let declarator = self.parse_declarator(true)?;
                let bit_width = if self.eat_punct(Punctuator::Colon) {
                    Some(self.parse_conditional()?)
                } else {
                    None
                };
                fields.push(FieldDecl {
                    specifiers: specifiers.clone(),
                    declarator,
                    bit_width,
                });
                if !self.eat_punct(Punctuator::Comma) {
                    break;
                }
            }
            self.expect_punct(Punctuator::Semicolon)?;
        }
        self.expect_punct(Punctuator::RBrace)?;
        Ok(fields)
    }

    fn parse_enum(&mut self) -> PResult<TypeSpecifier> {
        self.bump(); // `enum`
        let tag = self.eat_identifier();
        let enumerators = if self.is_punct(Punctuator::LBrace) {
            Some(self.parse_enumerators()?)
        } else {
            None
        };
        Ok(TypeSpecifier::Enum { tag, enumerators })
    }

    fn parse_enumerators(&mut self) -> PResult<Vec<Enumerator>> {
        self.expect_punct(Punctuator::LBrace)?;
        let mut enumerators = Vec::new();
        while !self.is_punct(Punctuator::RBrace) && !self.at_eof() {
            let Some(name) = self.eat_identifier() else {
                return Err(self.error("expected an enumerator name"));
            };
            let value = if self.eat_punct(Punctuator::Assign) {
                Some(self.parse_conditional()?)
            } else {
                None
            };
            enumerators.push(Enumerator { name, value });
            if !self.eat_punct(Punctuator::Comma) {
                break;
            }
        }
        self.expect_punct(Punctuator::RBrace)?;
        Ok(enumerators)
    }

    // --- Declarators -----------------------------------------------------------------------

    /// Parses a declarator. When `abstract_allowed`, the name may be omitted.
    pub(crate) fn parse_declarator(&mut self, abstract_allowed: bool) -> PResult<Declarator> {
        let mut pointers = self.parse_pointers();
        pointers.reverse();
        let mut declarator = self.parse_direct_declarator(abstract_allowed)?;
        declarator.derivations.extend(pointers);
        Ok(declarator)
    }

    /// Parses zero or more `*` pointer derivations with their qualifiers, in source order.
    fn parse_pointers(&mut self) -> Vec<Derivation> {
        let mut pointers = Vec::new();
        while self.eat_punct(Punctuator::Star) {
            let mut qualifiers = Vec::new();
            while let TokenKind::Keyword(kw) = self.peek_kind() {
                let Some(qual) = type_qualifier(kw) else {
                    break;
                };
                self.bump();
                qualifiers.push(qual);
            }
            pointers.push(Derivation::Pointer { qualifiers });
        }
        pointers
    }

    fn parse_direct_declarator(&mut self, abstract_allowed: bool) -> PResult<Declarator> {
        let mut declarator = Declarator::default();
        let mut inner = Vec::new();

        if self.is_punct(Punctuator::LParen) && self.paren_starts_declarator(abstract_allowed) {
            self.bump();
            let nested = self.parse_declarator(abstract_allowed)?;
            self.expect_punct(Punctuator::RParen)?;
            declarator.name = nested.name;
            inner = nested.derivations;
        } else if let Some(name) = self.eat_identifier() {
            declarator.name = Some(name);
        } else if !abstract_allowed {
            return Err(self.error("expected a declarator"));
        }

        let suffixes = self.parse_declarator_suffixes()?;
        let mut derivations = inner;
        derivations.extend(suffixes);
        declarator.derivations = derivations;
        Ok(declarator)
    }

    /// Decides whether a `(` after a declarator begins a nested declarator or a parameter list.
    fn paren_starts_declarator(&self, abstract_allowed: bool) -> bool {
        match self.peek2_kind() {
            TokenKind::Punct(Punctuator::Star | Punctuator::LParen) => true,
            TokenKind::Identifier(sym) => !self.is_typedef_name(sym),
            TokenKind::Punct(Punctuator::RParen) => !abstract_allowed,
            _ => false,
        }
    }

    fn parse_declarator_suffixes(&mut self) -> PResult<Vec<Derivation>> {
        let mut derivations = Vec::new();
        loop {
            if self.is_punct(Punctuator::LBracket) {
                derivations.push(self.parse_array_suffix()?);
            } else if self.is_punct(Punctuator::LParen) {
                derivations.push(self.parse_function_suffix()?);
            } else {
                break;
            }
        }
        Ok(derivations)
    }

    fn parse_array_suffix(&mut self) -> PResult<Derivation> {
        self.expect_punct(Punctuator::LBracket)?;
        let size = if self.is_punct(Punctuator::RBracket) {
            None
        } else {
            Some(self.parse_assignment()?)
        };
        self.expect_punct(Punctuator::RBracket)?;
        Ok(Derivation::Array { size })
    }

    fn parse_function_suffix(&mut self) -> PResult<Derivation> {
        self.expect_punct(Punctuator::LParen)?;
        let (params, variadic) = self.parse_parameter_list()?;
        self.expect_punct(Punctuator::RParen)?;
        Ok(Derivation::Function { params, variadic })
    }

    fn parse_parameter_list(&mut self) -> PResult<(Vec<ParamDecl>, bool)> {
        if self.is_punct(Punctuator::RParen) {
            return Ok((Vec::new(), false));
        }
        // `(void)` denotes an explicitly empty parameter list.
        if self.is_keyword(Keyword::Void)
            && self.peek2_kind() == TokenKind::Punct(Punctuator::RParen)
        {
            self.bump();
            return Ok((Vec::new(), false));
        }
        let mut params = Vec::new();
        let mut variadic = false;
        loop {
            if self.eat_punct(Punctuator::Ellipsis) {
                variadic = true;
                break;
            }
            let specifiers = self.parse_decl_specifiers()?;
            let declarator = self.parse_declarator(true)?;
            params.push(ParamDecl {
                specifiers,
                declarator,
            });
            if !self.eat_punct(Punctuator::Comma) {
                break;
            }
        }
        Ok((params, variadic))
    }

    /// Parses a type name (an abstract declaration), used by casts and `sizeof`.
    pub(crate) fn parse_type_name(&mut self) -> PResult<TypeName> {
        let specifiers = self.parse_decl_specifiers()?;
        let declarator = self.parse_declarator(true)?;
        Ok(TypeName {
            specifiers,
            declarator,
        })
    }

    pub(crate) fn eat_identifier(&mut self) -> Option<stratum_arena::Symbol> {
        if let TokenKind::Identifier(sym) = self.peek_kind() {
            self.bump();
            Some(sym)
        } else {
            None
        }
    }
}

fn storage_class(kw: Keyword) -> Option<StorageClass> {
    Some(match kw {
        Keyword::Typedef => StorageClass::Typedef,
        Keyword::Extern => StorageClass::Extern,
        Keyword::Static => StorageClass::Static,
        Keyword::Auto => StorageClass::Auto,
        Keyword::Register => StorageClass::Register,
        _ => return None,
    })
}

fn type_qualifier(kw: Keyword) -> Option<TypeQualifier> {
    Some(match kw {
        Keyword::Const => TypeQualifier::Const,
        Keyword::Volatile => TypeQualifier::Volatile,
        Keyword::Restrict => TypeQualifier::Restrict,
        _ => return None,
    })
}

fn simple_type_specifier(kw: Keyword) -> Option<TypeSpecifier> {
    Some(match kw {
        Keyword::Void => TypeSpecifier::Void,
        Keyword::Char => TypeSpecifier::Char,
        Keyword::Short => TypeSpecifier::Short,
        Keyword::Int => TypeSpecifier::Int,
        Keyword::Long => TypeSpecifier::Long,
        Keyword::Float => TypeSpecifier::Float,
        Keyword::Double => TypeSpecifier::Double,
        Keyword::Signed => TypeSpecifier::Signed,
        Keyword::Unsigned => TypeSpecifier::Unsigned,
        Keyword::Bool => TypeSpecifier::Bool,
        Keyword::Complex => TypeSpecifier::Complex,
        _ => return None,
    })
}

/// Returns `true` if `kw` can begin a declaration specifier.
fn is_specifier_keyword(kw: Keyword) -> bool {
    storage_class(kw).is_some()
        || type_qualifier(kw).is_some()
        || simple_type_specifier(kw).is_some()
        || matches!(
            kw,
            Keyword::Struct | Keyword::Union | Keyword::Enum | Keyword::Inline
        )
}

#[cfg(test)]
mod tests {
    use super::simple_type_specifier;
    use crate::alloc_prelude::*;
    use crate::parser::Parser;
    use stratum_arena::Interner;
    use stratum_c_ast::{CAst, DeclSpecifiers, Derivation, TypeSpecifier};
    use stratum_c_lexer::{Keyword, Punctuator, Token, TokenKind};
    use stratum_diagnostics::{FileId, Span};
    use stratum_utils::HashSet;

    fn span() -> Span {
        Span::point(FileId::from_raw(0), 0)
    }

    fn parser_with(tokens: &[Token], interner: Interner) -> Parser<'_> {
        Parser {
            tokens,
            pos: 0,
            ast: CAst::with_interner(interner),
            diagnostics: Vec::new(),
            typedefs: vec![HashSet::default()],
        }
    }

    #[test]
    fn keyword_absorption_covers_inline_and_non_specifier() {
        let interner = Interner::new();
        let tokens = [Token {
            kind: TokenKind::Eof,
            span: span(),
        }];
        let mut parser = parser_with(&tokens, interner);
        let mut specs = DeclSpecifiers::default();
        let mut has_type = false;

        assert!(
            parser
                .absorb_keyword(Keyword::Inline, &mut specs, &mut has_type)
                .ok()
                .unwrap()
        );
        assert!(specs.inline);
        assert!(
            !parser
                .absorb_keyword(Keyword::Return, &mut specs, &mut has_type)
                .ok()
                .unwrap()
        );
    }

    #[test]
    fn enum_without_body_and_malformed_enumerator_paths_are_covered() {
        let mut interner = Interner::new();
        let tag = interner.intern("E").unwrap();
        let tokens = [
            Token {
                kind: TokenKind::Keyword(Keyword::Enum),
                span: span(),
            },
            Token {
                kind: TokenKind::Identifier(tag),
                span: span(),
            },
            Token {
                kind: TokenKind::Eof,
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens, interner);
        assert!(matches!(
            parser.parse_enum().ok().unwrap(),
            TypeSpecifier::Enum {
                enumerators: None,
                ..
            }
        ));

        let interner = Interner::new();
        let tokens = [
            Token {
                kind: TokenKind::Keyword(Keyword::Enum),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LBrace),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens, interner);
        assert!(parser.parse_enum().is_err());
    }

    #[test]
    fn pointer_and_paren_disambiguation_edges_are_covered() {
        let interner = Interner::new();
        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::Star),
                span: span(),
            },
            Token {
                kind: TokenKind::Keyword(Keyword::Inline),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens, interner);
        assert_eq!(parser.parse_pointers().len(), 1);

        let mut interner = Interner::new();
        let name = interner.intern("T").unwrap();
        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::LParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Identifier(name),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens, interner);
        assert!(parser.paren_starts_declarator(false));
        parser.add_typedef(name);
        assert!(!parser.paren_starts_declarator(false));

        let interner = Interner::new();
        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::LParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RParen),
                span: span(),
            },
        ];
        let parser = parser_with(&tokens, interner);
        assert!(parser.paren_starts_declarator(false));
        assert!(!parser.paren_starts_declarator(true));

        let interner = Interner::new();
        let tokens = [
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
        ];
        let parser = parser_with(&tokens, interner);
        assert!(!parser.paren_starts_declarator(false));
    }

    #[test]
    fn complex_is_a_simple_type_specifier() {
        assert_eq!(
            simple_type_specifier(Keyword::Complex),
            Some(TypeSpecifier::Complex)
        );
    }

    #[test]
    fn nested_declarator_derivations_are_innermost_first() {
        let mut interner = Interner::new();
        let name = interner.intern("x").unwrap();
        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::LParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Star),
                span: span(),
            },
            Token {
                kind: TokenKind::Identifier(name),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RParen),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::LBracket),
                span: span(),
            },
            Token {
                kind: TokenKind::Integer {
                    value: 5,
                    unsigned: false,
                },
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
        let mut parser = parser_with(&tokens, interner);
        let declarator = parser.parse_declarator(false).ok().unwrap();
        assert_eq!(declarator.name, Some(name));
        assert!(
            matches!(
                declarator.derivations.as_slice(),
                [Derivation::Pointer { .. }, Derivation::Array { .. }]
            ),
            "expected [Pointer, Array], got {:?}",
            declarator.derivations
        );
    }

    #[test]
    fn field_list_accepts_multiple_declarators() {
        let mut interner = Interner::new();
        let a = interner.intern("a").unwrap();
        let b = interner.intern("b").unwrap();
        let tokens = [
            Token {
                kind: TokenKind::Punct(Punctuator::LBrace),
                span: span(),
            },
            Token {
                kind: TokenKind::Keyword(Keyword::Int),
                span: span(),
            },
            Token {
                kind: TokenKind::Identifier(a),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Comma),
                span: span(),
            },
            Token {
                kind: TokenKind::Identifier(b),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::Semicolon),
                span: span(),
            },
            Token {
                kind: TokenKind::Punct(Punctuator::RBrace),
                span: span(),
            },
        ];
        let mut parser = parser_with(&tokens, interner);
        let fields = parser.parse_field_list().ok().unwrap();
        assert_eq!(fields.len(), 2);
    }
}
