//! HIR node definitions.
//!
//! The HIR is rich enough to represent every C89/C99 construct faithfully: control flow
//! keeps its original `while`/`do`/`for`/`switch` shapes, expressions retain casts,
//! `sizeof`, member access, subscripting, the conditional and comma operators, compound
//! assignment, and pre/post increment, and declarations carry storage classes, qualifiers,
//! aggregates, enumerations, and `typedef`s. Nothing the parser produces is dropped.

use crate::alloc_prelude::*;
use crate::context::{HirNodeId, HirTypeId};
use crate::types::Qualifiers;
use stratum_arena::Symbol;

/// A binary operator, normalised across source languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// `a + b`
    Add,
    /// `a - b`
    Sub,
    /// `a * b`
    Mul,
    /// `a / b`
    Div,
    /// `a % b`
    Rem,
    /// `a == b`
    Eq,
    /// `a != b`
    Ne,
    /// `a < b`
    Lt,
    /// `a <= b`
    Le,
    /// `a > b`
    Gt,
    /// `a >= b`
    Ge,
    /// `a && b`
    LogicalAnd,
    /// `a || b`
    LogicalOr,
    /// `a & b`
    BitAnd,
    /// `a | b`
    BitOr,
    /// `a ^ b`
    BitXor,
    /// `a << b`
    Shl,
    /// `a >> b`
    Shr,
}

impl BinaryOp {
    /// Returns a stable textual symbol for the operator, used by the HIR dumper.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            BinaryOp::Add => "+",
            BinaryOp::Sub => "-",
            BinaryOp::Mul => "*",
            BinaryOp::Div => "/",
            BinaryOp::Rem => "%",
            BinaryOp::Eq => "==",
            BinaryOp::Ne => "!=",
            BinaryOp::Lt => "<",
            BinaryOp::Le => "<=",
            BinaryOp::Gt => ">",
            BinaryOp::Ge => ">=",
            BinaryOp::LogicalAnd => "&&",
            BinaryOp::LogicalOr => "||",
            BinaryOp::BitAnd => "&",
            BinaryOp::BitOr => "|",
            BinaryOp::BitXor => "^",
            BinaryOp::Shl => "<<",
            BinaryOp::Shr => ">>",
        }
    }
}

/// A prefix unary operator, normalised across source languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    /// Unary plus `+a` (an identity kept for faithful round-tripping).
    Plus,
    /// Arithmetic negation `-a`.
    Neg,
    /// Logical negation `!a`.
    Not,
    /// Bitwise complement `~a`.
    BitNot,
    /// Address-of `&a`.
    AddressOf,
    /// Pointer dereference `*a`.
    Deref,
    /// Pre-increment `++a`.
    PreInc,
    /// Pre-decrement `--a`.
    PreDec,
}

impl UnaryOp {
    /// Returns a stable textual symbol for the operator, used by the HIR dumper.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            UnaryOp::Plus => "+",
            UnaryOp::Neg => "-",
            UnaryOp::Not => "!",
            UnaryOp::BitNot => "~",
            UnaryOp::AddressOf => "&",
            UnaryOp::Deref => "*",
            UnaryOp::PreInc => "++",
            UnaryOp::PreDec => "--",
        }
    }
}

/// A postfix `++`/`--` operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostfixOp {
    /// Post-increment `a++`.
    Inc,
    /// Post-decrement `a--`.
    Dec,
}

impl PostfixOp {
    /// Returns a stable textual symbol for the operator, used by the HIR dumper.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            PostfixOp::Inc => "++",
            PostfixOp::Dec => "--",
        }
    }
}

/// A storage-class specifier carried on a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageClass {
    /// `extern`
    Extern,
    /// `static`
    Static,
    /// `auto`
    Auto,
    /// `register`
    Register,
}

impl StorageClass {
    /// Returns the C keyword spelling.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            StorageClass::Extern => "extern",
            StorageClass::Static => "static",
            StorageClass::Auto => "auto",
            StorageClass::Register => "register",
        }
    }
}

/// Declaration-level flags preserved from the source: storage class and `inline`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DeclFlags {
    /// The storage-class specifier, if any.
    pub storage: Option<StorageClass>,
    /// Whether the `inline` function specifier was present.
    pub inline: bool,
}

impl DeclFlags {
    /// Returns `true` if no flags are set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.storage.is_none() && !self.inline
    }
}

/// Whether an aggregate is a `struct` or a `union`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// `struct`
    Struct,
    /// `union`
    Union,
}

impl RecordKind {
    /// Returns the C keyword spelling.
    #[must_use]
    pub const fn spelling(self) -> &'static str {
        match self {
            RecordKind::Struct => "struct",
            RecordKind::Union => "union",
        }
    }
}

/// A named, typed function parameter. The name is absent for unnamed prototype parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// The parameter name, if given.
    pub name: Option<Symbol>,
    /// The parameter type.
    pub ty: HirTypeId,
}

/// A field (member) of a `struct` or `union`, possibly an unnamed bit-field.
#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    /// The member name, or `None` for an unnamed (e.g. padding) bit-field.
    pub name: Option<Symbol>,
    /// The member type.
    pub ty: HirTypeId,
    /// The bit-field width expression, if this member is a bit-field.
    pub bit_width: Option<HirNodeId>,
}

/// A single enumeration constant with an optional explicit value.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    /// The constant's name.
    pub name: Symbol,
    /// The explicit value expression, if specified.
    pub value: Option<HirNodeId>,
}

/// A C initialiser: either a scalar expression or a (possibly designated) braced list.
///
/// initializers form their own small tree rather than living in the expression node space,
/// mirroring the C grammar where an initialiser is not an ordinary expression.
#[derive(Debug, Clone, PartialEq)]
pub enum HirInit {
    /// A scalar initialiser: a single assignment-expression.
    Expr(HirNodeId),
    /// A braced initialiser list, each entry with zero or more designators.
    List(Vec<InitEntry>),
}

/// One entry in a braced initialiser list.
#[derive(Debug, Clone, PartialEq)]
pub struct InitEntry {
    /// The designators selecting where this value goes (empty for positional entries).
    pub designators: Vec<Designator>,
    /// The initialiser value.
    pub value: HirInit,
}

/// A C99 designator selecting a sub-object within an aggregate initialiser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Designator {
    /// `.field`
    Field(Symbol),
    /// `[index]`
    Index(HirNodeId),
}

/// A node in the HIR.
///
/// Items, statements, and expressions share one node space so they can all be addressed by
/// [`HirNodeId`] and stored in a single arena. Unlike a fully normalised IR, control flow
/// keeps its original C shapes (`while`/`do`/`for`/`switch`) so that lowering preserves the
/// source structure exactly.
#[derive(Debug, Clone, PartialEq)]
pub enum HirNode {
    /// A translation unit: an ordered list of top-level items.
    Module(Vec<HirNodeId>),
    /// A function definition or prototype.
    Function {
        /// The function name.
        name: Symbol,
        /// The parameters, in order.
        params: Vec<Param>,
        /// The return type.
        ret: HirTypeId,
        /// Whether the parameter list ends with `, ...`.
        variadic: bool,
        /// Storage class and `inline` flags.
        flags: DeclFlags,
        /// The function body block, if the function is defined (not just declared).
        body: Option<HirNodeId>,
    },
    /// A variable declaration, at module or block scope.
    Var {
        /// The variable name.
        name: Symbol,
        /// The declared type.
        ty: HirTypeId,
        /// Storage class and `inline` flags.
        flags: DeclFlags,
        /// The initialiser, if any.
        init: Option<HirInit>,
    },
    /// A `typedef`: a name introduced as an alias for a type.
    TypeAlias {
        /// The alias name.
        name: Symbol,
        /// The aliased type.
        ty: HirTypeId,
    },
    /// A `struct` or `union` definition.
    Record {
        /// Whether this is a `struct` or a `union`.
        kind: RecordKind,
        /// The tag name, if present.
        tag: Option<Symbol>,
        /// The fields, in order.
        fields: Vec<Field>,
    },
    /// An `enum` definition.
    Enumeration {
        /// The tag name, if present.
        tag: Option<Symbol>,
        /// The enumerators, in order.
        variants: Vec<EnumVariant>,
    },
    /// A lexically scoped sequence of statements.
    Block(Vec<HirNodeId>),
    /// A two-way (or one-way) conditional statement.
    Conditional {
        /// The condition expression.
        cond: HirNodeId,
        /// The block taken when the condition is true.
        then_block: HirNodeId,
        /// The block taken otherwise, if present.
        else_block: Option<HirNodeId>,
    },
    /// A `while` loop.
    While {
        /// The controlling condition.
        cond: HirNodeId,
        /// The loop body.
        body: HirNodeId,
    },
    /// A `do`/`while` loop.
    DoWhile {
        /// The loop body.
        body: HirNodeId,
        /// The controlling condition.
        cond: HirNodeId,
    },
    /// A `for` loop. Each clause is optional, mirroring C.
    For {
        /// The initialisation clause (an expression statement, declaration, or block).
        init: Option<HirNodeId>,
        /// The controlling condition.
        cond: Option<HirNodeId>,
        /// The iteration (step) expression.
        step: Option<HirNodeId>,
        /// The loop body.
        body: HirNodeId,
    },
    /// A `switch` statement. The body is a block whose [`Case`](HirNode::Case) and
    /// [`Default`](HirNode::Default) labels mark positions in a fall-through stream.
    Switch {
        /// The controlling expression.
        scrutinee: HirNodeId,
        /// The switch body.
        body: HirNodeId,
    },
    /// A `case` label attached to the following statement.
    Case {
        /// The case constant expression.
        value: HirNodeId,
        /// The labelled statement.
        body: HirNodeId,
    },
    /// A `default` label attached to the following statement.
    Default {
        /// The labelled statement.
        body: HirNodeId,
    },
    /// A labelled statement (the target of a `goto`).
    Label {
        /// The label name.
        name: Symbol,
        /// The labelled statement.
        body: HirNodeId,
    },
    /// A `goto` to a label.
    Goto(Symbol),
    /// Exit the nearest enclosing loop or `switch`.
    Break,
    /// Continue the nearest enclosing loop.
    Continue,
    /// Return from the current function, optionally with a value.
    Return(Option<HirNodeId>),
    /// An expression evaluated for its side effects (or an empty statement when `None`).
    ExprStmt(Option<HirNodeId>),
    /// A simple or compound assignment `target op= value`.
    Assign {
        /// The compound operator, or `None` for a plain `=`.
        op: Option<BinaryOp>,
        /// The assignment target (an lvalue expression).
        target: HirNodeId,
        /// The value to assign.
        value: HirNodeId,
    },
    /// A binary operation.
    Binary {
        /// The operator.
        op: BinaryOp,
        /// The left operand.
        lhs: HirNodeId,
        /// The right operand.
        rhs: HirNodeId,
    },
    /// A prefix unary operation.
    Unary {
        /// The operator.
        op: UnaryOp,
        /// The operand.
        operand: HirNodeId,
    },
    /// A postfix `++`/`--` operation.
    Postfix {
        /// The operator.
        op: PostfixOp,
        /// The operand.
        operand: HirNodeId,
    },
    /// A conditional `cond ? then : else` expression.
    Ternary {
        /// The condition.
        cond: HirNodeId,
        /// The value when the condition holds.
        then_expr: HirNodeId,
        /// The value otherwise.
        else_expr: HirNodeId,
    },
    /// A function call.
    Call {
        /// The callee expression.
        callee: HirNodeId,
        /// The argument expressions, in order.
        args: Vec<HirNodeId>,
    },
    /// A member access `base.field` or `base->field`.
    Member {
        /// The aggregate expression.
        base: HirNodeId,
        /// The member name.
        field: Symbol,
        /// Whether the access used `->` (true) or `.` (false).
        arrow: bool,
    },
    /// An array subscript `base[index]`.
    Index {
        /// The array (or pointer) expression.
        base: HirNodeId,
        /// The index expression.
        index: HirNodeId,
    },
    /// A cast `(ty)operand`.
    Cast {
        /// The target type.
        ty: HirTypeId,
        /// The operand.
        operand: HirNodeId,
    },
    /// A comma expression `lhs, rhs`.
    Comma {
        /// The left operand, evaluated for its side effects.
        lhs: HirNodeId,
        /// The right operand, whose value is the result.
        rhs: HirNodeId,
    },
    /// `sizeof expr`.
    SizeofExpr(HirNodeId),
    /// `sizeof(type)`.
    SizeofType(HirTypeId),
    /// A compound literal `(ty){ init }`.
    CompoundLiteral {
        /// The literal's type.
        ty: HirTypeId,
        /// The initialiser.
        init: HirInit,
    },
    /// An unresolved reference to a name. Resolution happens in a later stage.
    Name(Symbol),
    /// An integer literal.
    IntLiteral(i128),
    /// A floating-point literal, stored as its interned textual form for determinism.
    FloatLiteral(Symbol),
    /// A string literal, interned.
    StringLiteral(Symbol),
    /// A character literal, stored as its code point.
    CharLiteral(u32),
}

/// A qualified type reference used where a node needs both a type and its qualifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QualifiedType {
    /// The underlying type.
    pub ty: HirTypeId,
    /// The qualifiers applied to it.
    pub qualifiers: Qualifiers,
}

#[cfg(test)]
mod tests {
    use super::{BinaryOp, DeclFlags, PostfixOp, RecordKind, StorageClass, UnaryOp};

    #[test]
    fn operator_symbols_cover_all_variants() {
        assert_eq!(BinaryOp::Add.symbol(), "+");
        assert_eq!(BinaryOp::Sub.symbol(), "-");
        assert_eq!(BinaryOp::Mul.symbol(), "*");
        assert_eq!(BinaryOp::Div.symbol(), "/");
        assert_eq!(BinaryOp::Rem.symbol(), "%");
        assert_eq!(BinaryOp::Eq.symbol(), "==");
        assert_eq!(BinaryOp::Ne.symbol(), "!=");
        assert_eq!(BinaryOp::Lt.symbol(), "<");
        assert_eq!(BinaryOp::Le.symbol(), "<=");
        assert_eq!(BinaryOp::Gt.symbol(), ">");
        assert_eq!(BinaryOp::Ge.symbol(), ">=");
        assert_eq!(BinaryOp::LogicalAnd.symbol(), "&&");
        assert_eq!(BinaryOp::LogicalOr.symbol(), "||");
        assert_eq!(BinaryOp::BitAnd.symbol(), "&");
        assert_eq!(BinaryOp::BitOr.symbol(), "|");
        assert_eq!(BinaryOp::BitXor.symbol(), "^");
        assert_eq!(BinaryOp::Shl.symbol(), "<<");
        assert_eq!(BinaryOp::Shr.symbol(), ">>");

        assert_eq!(UnaryOp::Plus.symbol(), "+");
        assert_eq!(UnaryOp::Neg.symbol(), "-");
        assert_eq!(UnaryOp::Not.symbol(), "!");
        assert_eq!(UnaryOp::BitNot.symbol(), "~");
        assert_eq!(UnaryOp::AddressOf.symbol(), "&");
        assert_eq!(UnaryOp::Deref.symbol(), "*");
        assert_eq!(UnaryOp::PreInc.symbol(), "++");
        assert_eq!(UnaryOp::PreDec.symbol(), "--");

        assert_eq!(PostfixOp::Inc.symbol(), "++");
        assert_eq!(PostfixOp::Dec.symbol(), "--");
    }

    #[test]
    fn flags_and_kind_spellings_are_stable() {
        assert_eq!(StorageClass::Extern.spelling(), "extern");
        assert_eq!(StorageClass::Static.spelling(), "static");
        assert_eq!(StorageClass::Auto.spelling(), "auto");
        assert_eq!(StorageClass::Register.spelling(), "register");
        assert_eq!(RecordKind::Struct.spelling(), "struct");
        assert_eq!(RecordKind::Union.spelling(), "union");
        assert!(DeclFlags::default().is_empty());
        assert!(
            !DeclFlags {
                storage: Some(StorageClass::Static),
                inline: false,
            }
            .is_empty()
        );
    }
}
