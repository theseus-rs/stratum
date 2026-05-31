//! Unit tests for the C lexer.

use crate::alloc_prelude::*;
use crate::{Dialect, Keyword, PpTokenKind, Punctuator, lex};
use stratum_arena::Interner;
use stratum_diagnostics::{FileId, SourceMap};

fn lex_kinds(source: &str) -> Vec<PpTokenKind> {
    let mut interner = Interner::new();
    let file = FileId::from_raw(0);
    lex(source, file, &mut interner)
        .unwrap()
        .tokens
        .into_iter()
        .map(|t| t.kind)
        .collect()
}

fn kind(kinds: &[PpTokenKind], index: usize) -> Option<PpTokenKind> {
    kinds.get(index).copied()
}

fn resolve_first_ident(source: &str) -> String {
    let mut interner = Interner::new();
    let file = FileId::from_raw(0);
    let result = lex(source, file, &mut interner).unwrap();
    match result.tokens.first().map(|token| token.kind) {
        Some(PpTokenKind::Identifier(sym) | PpTokenKind::Number(sym)) => {
            interner.resolve(sym).unwrap().to_string()
        }
        _ => String::new(),
    }
}

#[test]
fn lexes_simple_declaration() {
    let kinds = lex_kinds("int x;");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::Identifier(_))));
    assert!(matches!(kind(&kinds, 1), Some(PpTokenKind::Identifier(_))));
    assert_eq!(
        kind(&kinds, 2),
        Some(PpTokenKind::Punct(Punctuator::Semicolon))
    );
}

#[test]
fn keeps_newlines() {
    let kinds = lex_kinds("a\nb\n");
    assert_eq!(kind(&kinds, 1), Some(PpTokenKind::Newline));
    assert_eq!(kind(&kinds, 3), Some(PpTokenKind::Newline));
}

#[test]
fn block_comment_is_whitespace() {
    let mut interner = Interner::new();
    let result = lex("a /* comment */ b", FileId::from_raw(0), &mut interner).unwrap();
    let non_ws: Vec<_> = result.tokens.iter().map(|t| t.kind).collect();
    assert_eq!(non_ws.len(), 2);
    assert!(
        result
            .tokens
            .get(1)
            .is_some_and(|token| token.leading_whitespace)
    );
}

#[test]
fn line_comment_is_whitespace() {
    let kinds = lex_kinds("a // ignored\nb");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::Identifier(_))));
    assert_eq!(kind(&kinds, 1), Some(PpTokenKind::Newline));
    assert!(matches!(kind(&kinds, 2), Some(PpTokenKind::Identifier(_))));
}

#[test]
fn line_splicing_joins_tokens() {
    assert_eq!(resolve_first_ident("ab\\\ncd"), "abcd");
}

#[test]
fn maximal_munch_operators() {
    let kinds = lex_kinds("a>>=b");
    assert_eq!(
        kind(&kinds, 1),
        Some(PpTokenKind::Punct(Punctuator::ShrAssign))
    );
}

#[test]
fn ellipsis_is_one_token() {
    let kinds = lex_kinds("(...)");
    assert_eq!(
        kind(&kinds, 1),
        Some(PpTokenKind::Punct(Punctuator::Ellipsis))
    );
}

#[test]
fn digraphs_normalise() {
    let kinds = lex_kinds("<::>");
    assert_eq!(
        kind(&kinds, 0),
        Some(PpTokenKind::Punct(Punctuator::LBracket))
    );
    assert_eq!(
        kind(&kinds, 1),
        Some(PpTokenKind::Punct(Punctuator::RBracket))
    );
}

#[test]
fn pp_number_includes_exponent_sign() {
    assert_eq!(resolve_first_ident("1.5e+10"), "1.5e+10");
}

#[test]
fn string_literal_is_one_token() {
    let kinds = lex_kinds("\"hello world\"");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::StringLit(_))));
    assert_eq!(kinds.len(), 1);
}

#[test]
fn string_with_escaped_quote() {
    let kinds = lex_kinds("\"a\\\"b\" x");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::StringLit(_))));
    assert!(matches!(kind(&kinds, 1), Some(PpTokenKind::Identifier(_))));
}

#[test]
fn wide_string_prefix() {
    let kinds = lex_kinds("L\"wide\"");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::StringLit(_))));
    assert_eq!(kinds.len(), 1);
}

#[test]
fn char_constant() {
    let kinds = lex_kinds("'a'");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::CharConst(_))));
}

#[test]
fn unterminated_string_reports_error() {
    let mut interner = Interner::new();
    let result = lex("\"oops", FileId::from_raw(0), &mut interner).unwrap();
    assert!(result.has_errors());
}

#[test]
fn unterminated_block_comment_reports_error() {
    let mut interner = Interner::new();
    let result = lex("/* never ends", FileId::from_raw(0), &mut interner).unwrap();
    assert!(result.has_errors());
}

#[test]
fn at_bol_flag_tracks_line_starts() {
    let mut interner = Interner::new();
    let result = lex("  first\nsecond", FileId::from_raw(0), &mut interner).unwrap();
    assert!(result.tokens.first().is_some_and(|token| token.at_bol));
    assert!(
        result
            .tokens
            .first()
            .is_some_and(|token| token.leading_whitespace)
    );
    // The second token is the newline; the third token is `second`.
    assert!(result.tokens.get(2).is_some_and(|token| token.at_bol));
}

#[test]
fn spans_refer_to_original_offsets() {
    let mut interner = Interner::new();
    let mut map = SourceMap::new();
    let file = map.add_root("t.c", "a+\\\nb");
    let result = lex("a+\\\nb", file.unwrap(), &mut interner).unwrap();
    // `b` appears at original offset 4 despite the splice removing `\` and the newline.
    let b = result.tokens.iter().find(
        |t| matches!(t.kind, PpTokenKind::Identifier(s) if interner.resolve(s).unwrap() == "b"),
    );
    assert_eq!(b.map(|t| t.span.start()), Some(4));
}

#[test]
fn crlf_line_splicing_joins_tokens() {
    assert_eq!(resolve_first_ident("ab\\\r\ncd"), "abcd");
}

#[test]
fn all_punctuator_spellings_are_stable() {
    let cases = [
        (Punctuator::LBracket, "["),
        (Punctuator::RBracket, "]"),
        (Punctuator::LParen, "("),
        (Punctuator::RParen, ")"),
        (Punctuator::LBrace, "{"),
        (Punctuator::RBrace, "}"),
        (Punctuator::Dot, "."),
        (Punctuator::Arrow, "->"),
        (Punctuator::PlusPlus, "++"),
        (Punctuator::MinusMinus, "--"),
        (Punctuator::Amp, "&"),
        (Punctuator::Star, "*"),
        (Punctuator::Plus, "+"),
        (Punctuator::Minus, "-"),
        (Punctuator::Tilde, "~"),
        (Punctuator::Bang, "!"),
        (Punctuator::Slash, "/"),
        (Punctuator::Percent, "%"),
        (Punctuator::Shl, "<<"),
        (Punctuator::Shr, ">>"),
        (Punctuator::Lt, "<"),
        (Punctuator::Gt, ">"),
        (Punctuator::Le, "<="),
        (Punctuator::Ge, ">="),
        (Punctuator::EqEq, "=="),
        (Punctuator::Ne, "!="),
        (Punctuator::Caret, "^"),
        (Punctuator::Pipe, "|"),
        (Punctuator::AmpAmp, "&&"),
        (Punctuator::PipePipe, "||"),
        (Punctuator::Question, "?"),
        (Punctuator::Colon, ":"),
        (Punctuator::Semicolon, ";"),
        (Punctuator::Ellipsis, "..."),
        (Punctuator::Assign, "="),
        (Punctuator::StarAssign, "*="),
        (Punctuator::SlashAssign, "/="),
        (Punctuator::PercentAssign, "%="),
        (Punctuator::PlusAssign, "+="),
        (Punctuator::MinusAssign, "-="),
        (Punctuator::ShlAssign, "<<="),
        (Punctuator::ShrAssign, ">>="),
        (Punctuator::AmpAssign, "&="),
        (Punctuator::CaretAssign, "^="),
        (Punctuator::PipeAssign, "|="),
        (Punctuator::Comma, ","),
        (Punctuator::Hash, "#"),
        (Punctuator::HashHash, "##"),
    ];
    for (punct, spelling) in cases {
        assert_eq!(punct.spelling(), spelling);
    }
}

#[test]
fn all_keywords_round_trip_from_identifier() {
    let cases = [
        (Keyword::Auto, "auto"),
        (Keyword::Break, "break"),
        (Keyword::Case, "case"),
        (Keyword::Char, "char"),
        (Keyword::Const, "const"),
        (Keyword::Continue, "continue"),
        (Keyword::Default, "default"),
        (Keyword::Do, "do"),
        (Keyword::Double, "double"),
        (Keyword::Else, "else"),
        (Keyword::Enum, "enum"),
        (Keyword::Extern, "extern"),
        (Keyword::Float, "float"),
        (Keyword::For, "for"),
        (Keyword::Goto, "goto"),
        (Keyword::If, "if"),
        (Keyword::Inline, "inline"),
        (Keyword::Int, "int"),
        (Keyword::Long, "long"),
        (Keyword::Register, "register"),
        (Keyword::Restrict, "restrict"),
        (Keyword::Return, "return"),
        (Keyword::Short, "short"),
        (Keyword::Signed, "signed"),
        (Keyword::Sizeof, "sizeof"),
        (Keyword::Static, "static"),
        (Keyword::Struct, "struct"),
        (Keyword::Switch, "switch"),
        (Keyword::Typedef, "typedef"),
        (Keyword::Union, "union"),
        (Keyword::Unsigned, "unsigned"),
        (Keyword::Void, "void"),
        (Keyword::Volatile, "volatile"),
        (Keyword::While, "while"),
        (Keyword::Bool, "_Bool"),
        (Keyword::Complex, "_Complex"),
        (Keyword::Imaginary, "_Imaginary"),
        (Keyword::Alignas, "_Alignas"),
        (Keyword::Alignof, "_Alignof"),
        (Keyword::Atomic, "_Atomic"),
        (Keyword::Generic, "_Generic"),
        (Keyword::Noreturn, "_Noreturn"),
        (Keyword::StaticAssert, "_Static_assert"),
        (Keyword::ThreadLocal, "_Thread_local"),
        (Keyword::BitInt, "_BitInt"),
        (Keyword::Decimal32, "_Decimal32"),
        (Keyword::Decimal64, "_Decimal64"),
        (Keyword::Decimal128, "_Decimal128"),
        (Keyword::C23Alignas, "alignas"),
        (Keyword::C23Alignof, "alignof"),
        (Keyword::C23Bool, "bool"),
        (Keyword::Constexpr, "constexpr"),
        (Keyword::False, "false"),
        (Keyword::Nullptr, "nullptr"),
        (Keyword::C23StaticAssert, "static_assert"),
        (Keyword::C23ThreadLocal, "thread_local"),
        (Keyword::True, "true"),
        (Keyword::Typeof, "typeof"),
        (Keyword::TypeofUnqual, "typeof_unqual"),
    ];
    for (keyword, spelling) in cases {
        assert_eq!(keyword.spelling(), spelling);
        assert_eq!(Keyword::from_identifier(spelling), Some(keyword));
    }
    assert_eq!(Keyword::from_identifier("not_a_keyword"), None);
}

#[test]
fn dialect_keyword_gate_keeps_future_keywords_as_identifiers() {
    assert_eq!("c90".parse::<Dialect>(), Ok(Dialect::C89));
    assert_eq!("c18".parse::<Dialect>(), Ok(Dialect::C17));
    assert_eq!("c2x".parse::<Dialect>(), Ok(Dialect::C23));
    assert_eq!("gnu11".parse::<Dialect>(), Err(()));
    assert_eq!(Dialect::default(), Dialect::C23);
    assert_eq!(Dialect::C89.spelling(), "c89");
    assert_eq!(Dialect::C99.spelling(), "c99");
    assert_eq!(Dialect::C11.spelling(), "c11");
    assert_eq!(Dialect::C17.spelling(), "c17");
    assert_eq!(Dialect::C23.spelling(), "c23");
    assert!(Dialect::C23.supports(Dialect::C11));
    assert!(!Dialect::C99.supports(Dialect::C11));

    assert_eq!(Keyword::from_identifier_in("inline", Dialect::C89), None);
    assert_eq!(
        Keyword::from_identifier_in("inline", Dialect::C99),
        Some(Keyword::Inline)
    );
    assert_eq!(Keyword::from_identifier_in("_Generic", Dialect::C99), None);
    assert_eq!(
        Keyword::from_identifier_in("_Generic", Dialect::C11),
        Some(Keyword::Generic)
    );
    assert_eq!(Keyword::from_identifier_in("true", Dialect::C17), None);
    assert_eq!(
        Keyword::from_identifier_in("true", Dialect::C23),
        Some(Keyword::True)
    );
}

#[test]
fn prefixed_char_literals_are_recognized() {
    let kinds = lex_kinds("u'a' U'b' L'c' u8'd'");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::CharConst(_))));
    assert!(matches!(kind(&kinds, 1), Some(PpTokenKind::CharConst(_))));
    assert!(matches!(kind(&kinds, 2), Some(PpTokenKind::CharConst(_))));
    assert!(matches!(kind(&kinds, 3), Some(PpTokenKind::CharConst(_))));
}

#[test]
fn literal_prefixes_without_quotes_are_identifiers() {
    let kinds = lex_kinds("u8 u8name");
    assert!(matches!(kind(&kinds, 0), Some(PpTokenKind::Identifier(_))));
    assert!(matches!(kind(&kinds, 1), Some(PpTokenKind::Identifier(_))));
    assert_eq!(resolve_first_ident("u8"), "u8");
}

#[test]
fn unterminated_char_reports_error() {
    let mut interner = Interner::new();
    let result = lex("'oops", FileId::from_raw(0), &mut interner).unwrap();
    assert!(result.has_errors());
}

#[test]
fn unterminated_string_stops_at_newline() {
    let mut interner = Interner::new();
    let result = lex("\"oops\nnext", FileId::from_raw(0), &mut interner).unwrap();
    assert!(result.has_errors());
    assert_eq!(
        kind(&lex_kinds("\"oops\nnext"), 1),
        Some(PpTokenKind::Newline)
    );
}

#[test]
fn unknown_character_is_other_token() {
    let kinds = lex_kinds("@");
    assert_eq!(kind(&kinds, 0), Some(PpTokenKind::Other('@')));
}

#[test]
fn remaining_digraphs_normalise() {
    let kinds = lex_kinds("<% %> %: %:%:");
    assert_eq!(
        kind(&kinds, 0),
        Some(PpTokenKind::Punct(Punctuator::LBrace))
    );
    assert_eq!(
        kind(&kinds, 1),
        Some(PpTokenKind::Punct(Punctuator::RBrace))
    );
    assert_eq!(kind(&kinds, 2), Some(PpTokenKind::Punct(Punctuator::Hash)));
    assert_eq!(
        kind(&kinds, 3),
        Some(PpTokenKind::Punct(Punctuator::HashHash))
    );
}
