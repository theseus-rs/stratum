//! Token and punctuator definitions shared by the C lexer, preprocessor, and parser.

use stratum_arena::Symbol;
use stratum_diagnostics::Span;

/// A C punctuator (operator or separator).
///
/// Digraphs (`<:`, `:>`, `<%`, `%>`, `%:`, `%:%:`) are normalised to their canonical
/// punctuator during lexing, so consumers never need to special-case them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Punctuator {
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `.`
    Dot,
    /// `->`
    Arrow,
    /// `++`
    PlusPlus,
    /// `--`
    MinusMinus,
    /// `&`
    Amp,
    /// `*`
    Star,
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `~`
    Tilde,
    /// `!`
    Bang,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `<<`
    Shl,
    /// `>>`
    Shr,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `>=`
    Ge,
    /// `==`
    EqEq,
    /// `!=`
    Ne,
    /// `^`
    Caret,
    /// `|`
    Pipe,
    /// `&&`
    AmpAmp,
    /// `||`
    PipePipe,
    /// `?`
    Question,
    /// `:`
    Colon,
    /// `;`
    Semicolon,
    /// `...`
    Ellipsis,
    /// `=`
    Assign,
    /// `*=`
    StarAssign,
    /// `/=`
    SlashAssign,
    /// `%=`
    PercentAssign,
    /// `+=`
    PlusAssign,
    /// `-=`
    MinusAssign,
    /// `<<=`
    ShlAssign,
    /// `>>=`
    ShrAssign,
    /// `&=`
    AmpAssign,
    /// `^=`
    CaretAssign,
    /// `|=`
    PipeAssign,
    /// `,`
    Comma,
    /// `#`
    Hash,
    /// `##`
    HashHash,
}

impl Punctuator {
    /// Returns the canonical spelling of this punctuator.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Punctuator::LBracket => "[",
            Punctuator::RBracket => "]",
            Punctuator::LParen => "(",
            Punctuator::RParen => ")",
            Punctuator::LBrace => "{",
            Punctuator::RBrace => "}",
            Punctuator::Dot => ".",
            Punctuator::Arrow => "->",
            Punctuator::PlusPlus => "++",
            Punctuator::MinusMinus => "--",
            Punctuator::Amp => "&",
            Punctuator::Star => "*",
            Punctuator::Plus => "+",
            Punctuator::Minus => "-",
            Punctuator::Tilde => "~",
            Punctuator::Bang => "!",
            Punctuator::Slash => "/",
            Punctuator::Percent => "%",
            Punctuator::Shl => "<<",
            Punctuator::Shr => ">>",
            Punctuator::Lt => "<",
            Punctuator::Gt => ">",
            Punctuator::Le => "<=",
            Punctuator::Ge => ">=",
            Punctuator::EqEq => "==",
            Punctuator::Ne => "!=",
            Punctuator::Caret => "^",
            Punctuator::Pipe => "|",
            Punctuator::AmpAmp => "&&",
            Punctuator::PipePipe => "||",
            Punctuator::Question => "?",
            Punctuator::Colon => ":",
            Punctuator::Semicolon => ";",
            Punctuator::Ellipsis => "...",
            Punctuator::Assign => "=",
            Punctuator::StarAssign => "*=",
            Punctuator::SlashAssign => "/=",
            Punctuator::PercentAssign => "%=",
            Punctuator::PlusAssign => "+=",
            Punctuator::MinusAssign => "-=",
            Punctuator::ShlAssign => "<<=",
            Punctuator::ShrAssign => ">>=",
            Punctuator::AmpAssign => "&=",
            Punctuator::CaretAssign => "^=",
            Punctuator::PipeAssign => "|=",
            Punctuator::Comma => ",",
            Punctuator::Hash => "#",
            Punctuator::HashHash => "##",
        }
    }
}

/// A C keyword, recognised when preprocessing tokens are converted to final tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Keyword {
    Auto,
    Break,
    Case,
    Char,
    Const,
    Continue,
    Default,
    Do,
    Double,
    Else,
    Enum,
    Extern,
    Float,
    For,
    Goto,
    If,
    Inline,
    Int,
    Long,
    Register,
    Restrict,
    Return,
    Short,
    Signed,
    Sizeof,
    Static,
    Struct,
    Switch,
    Typedef,
    Union,
    Unsigned,
    Void,
    Volatile,
    While,
    /// C99 `_Bool`.
    Bool,
    /// C99 `_Complex`.
    Complex,
    /// C99 `_Imaginary`.
    Imaginary,
}

impl Keyword {
    /// Returns the keyword matching `text`, if any.
    #[must_use]
    pub fn from_identifier(text: &str) -> Option<Self> {
        let keyword = match text {
            "auto" => Keyword::Auto,
            "break" => Keyword::Break,
            "case" => Keyword::Case,
            "char" => Keyword::Char,
            "const" => Keyword::Const,
            "continue" => Keyword::Continue,
            "default" => Keyword::Default,
            "do" => Keyword::Do,
            "double" => Keyword::Double,
            "else" => Keyword::Else,
            "enum" => Keyword::Enum,
            "extern" => Keyword::Extern,
            "float" => Keyword::Float,
            "for" => Keyword::For,
            "goto" => Keyword::Goto,
            "if" => Keyword::If,
            "inline" => Keyword::Inline,
            "int" => Keyword::Int,
            "long" => Keyword::Long,
            "register" => Keyword::Register,
            "restrict" => Keyword::Restrict,
            "return" => Keyword::Return,
            "short" => Keyword::Short,
            "signed" => Keyword::Signed,
            "sizeof" => Keyword::Sizeof,
            "static" => Keyword::Static,
            "struct" => Keyword::Struct,
            "switch" => Keyword::Switch,
            "typedef" => Keyword::Typedef,
            "union" => Keyword::Union,
            "unsigned" => Keyword::Unsigned,
            "void" => Keyword::Void,
            "volatile" => Keyword::Volatile,
            "while" => Keyword::While,
            "_Bool" => Keyword::Bool,
            "_Complex" => Keyword::Complex,
            "_Imaginary" => Keyword::Imaginary,
            _ => return None,
        };
        Some(keyword)
    }

    /// Returns the canonical spelling of this keyword.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            Keyword::Auto => "auto",
            Keyword::Break => "break",
            Keyword::Case => "case",
            Keyword::Char => "char",
            Keyword::Const => "const",
            Keyword::Continue => "continue",
            Keyword::Default => "default",
            Keyword::Do => "do",
            Keyword::Double => "double",
            Keyword::Else => "else",
            Keyword::Enum => "enum",
            Keyword::Extern => "extern",
            Keyword::Float => "float",
            Keyword::For => "for",
            Keyword::Goto => "goto",
            Keyword::If => "if",
            Keyword::Inline => "inline",
            Keyword::Int => "int",
            Keyword::Long => "long",
            Keyword::Register => "register",
            Keyword::Restrict => "restrict",
            Keyword::Return => "return",
            Keyword::Short => "short",
            Keyword::Signed => "signed",
            Keyword::Sizeof => "sizeof",
            Keyword::Static => "static",
            Keyword::Struct => "struct",
            Keyword::Switch => "switch",
            Keyword::Typedef => "typedef",
            Keyword::Union => "union",
            Keyword::Unsigned => "unsigned",
            Keyword::Void => "void",
            Keyword::Volatile => "volatile",
            Keyword::While => "while",
            Keyword::Bool => "_Bool",
            Keyword::Complex => "_Complex",
            Keyword::Imaginary => "_Imaginary",
        }
    }
}

/// The kind of a preprocessing token.
///
/// Preprocessing tokens are the output of [phase 3][crate] of translation: the source has
/// been split into the coarse categories the preprocessor operates on, but keywords are not
/// yet distinguished from identifiers and numbers are not yet parsed into values. That
/// refinement happens later, during token finalisation in the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PpTokenKind {
    /// An identifier (or, before finalisation, a keyword).
    Identifier(Symbol),
    /// A preprocessing number: its raw spelling is interned for later parsing.
    Number(Symbol),
    /// A character constant, stored as its raw spelling including quotes and any prefix.
    CharConst(Symbol),
    /// A string literal, stored as its raw spelling including quotes and any prefix.
    StringLit(Symbol),
    /// A punctuator.
    Punct(Punctuator),
    /// A newline. Retained because the preprocessor is line-oriented.
    Newline,
    /// Any single character that does not form a valid preprocessing token.
    Other(char),
}

/// A single preprocessing token with its source span and whitespace context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PpToken {
    /// What kind of token this is.
    pub kind: PpTokenKind,
    /// The source location of the token.
    pub span: Span,
    /// Whether whitespace (or a comment) immediately preceded this token.
    pub leading_whitespace: bool,
    /// Whether this token is the first token on its logical source line.
    pub at_bol: bool,
}

/// The kind of a *finalized* token.
///
/// finalized tokens are produced after preprocessing, during token finalisation in the
/// parser: keywords are distinguished from identifiers, numeric spellings are parsed into
/// values, and adjacent string literals are concatenated. This vocabulary is defined here,
/// alongside [`PpTokenKind`], so the lexer remains the single owner of the token model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// A keyword.
    Keyword(Keyword),
    /// An identifier.
    Identifier(Symbol),
    /// An integer constant and whether it carried an unsigned suffix.
    Integer {
        /// The parsed value.
        value: i128,
        /// Whether an unsigned suffix (`u`/`U`) was present.
        unsigned: bool,
    },
    /// A floating constant, kept as its interned spelling for now.
    Float(Symbol),
    /// A character constant's value.
    Char(u32),
    /// A string literal's interned contents (after concatenation).
    String(Symbol),
    /// A punctuator.
    Punct(Punctuator),
    /// The end of the token stream.
    Eof,
}

/// A finalized token with its source span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Token {
    /// What kind of token this is.
    pub kind: TokenKind,
    /// The source location of the token.
    pub span: Span,
}
