//! C abstract syntax tree node definitions.
//!
//! Nodes live in a [`CAst`](crate::CAst) arena and reference one another by
//! [`CNodeId`]. Small, non-shared structures (declaration specifiers,
//! declarators) are stored inline rather than in the arena.

use crate::alloc_prelude::*;
use crate::ops::{AssignOp, BinaryOp, PostfixOp, UnaryOp};
use crate::tree::CNodeId;
use stratum_arena::Symbol;

/// A storage-class specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageClass {
    /// `typedef`
    Typedef,
    /// `extern`
    Extern,
    /// `static`
    Static,
    /// `auto`
    Auto,
    /// `register`
    Register,
    /// C11 `_Thread_local` / C23 `thread_local`.
    ThreadLocal,
    /// C23 `constexpr`.
    Constexpr,
}

/// A type qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeQualifier {
    /// `const`
    Const,
    /// `volatile`
    Volatile,
    /// `restrict`
    Restrict,
    /// C11 `_Atomic` used as a qualifier.
    Atomic,
}

/// A C11/C23 alignment specifier attached to declaration specifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlignmentSpecifier {
    /// `_Alignas(type-name)` / `alignas(type-name)`.
    Type(TypeName),
    /// `_Alignas(constant-expression)` / `alignas(constant-expression)`.
    Expr(CNodeId),
}

/// A single type specifier, including aggregate and `typedef`-name specifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSpecifier {
    /// `void`
    Void,
    /// `char`
    Char,
    /// `short`
    Short,
    /// `int`
    Int,
    /// `long`
    Long,
    /// `float`
    Float,
    /// `double`
    Double,
    /// `signed`
    Signed,
    /// `unsigned`
    Unsigned,
    /// `_Bool`
    Bool,
    /// `_Complex`
    Complex,
    /// C99 `_Imaginary`.
    Imaginary,
    /// C11 `_Atomic(type-name)`.
    Atomic(Box<TypeName>),
    /// C23 `_BitInt(width)`.
    BitInt(CNodeId),
    /// C23 `_Decimal32`.
    Decimal32,
    /// C23 `_Decimal64`.
    Decimal64,
    /// C23 `_Decimal128`.
    Decimal128,
    /// C23 `typeof(...)` / `typeof_unqual(...)`.
    Typeof {
        /// The operand form used by the typeof specifier.
        operand: TypeofOperand,
        /// Whether the spelling was `typeof_unqual`.
        unqualified: bool,
    },
    /// A `struct` type, with an optional tag and optional field list.
    Struct {
        /// The tag name, if present.
        tag: Option<Symbol>,
        /// The fields, if the struct is defined here.
        fields: Option<Vec<FieldDecl>>,
    },
    /// A `union` type, with an optional tag and optional field list.
    Union {
        /// The tag name, if present.
        tag: Option<Symbol>,
        /// The fields, if the union is defined here.
        fields: Option<Vec<FieldDecl>>,
    },
    /// An `enum` type, with an optional tag and optional enumerator list.
    Enum {
        /// The tag name, if present.
        tag: Option<Symbol>,
        /// The enumerators, if the enum is defined here.
        enumerators: Option<Vec<Enumerator>>,
    },
    /// A name introduced by an earlier `typedef`.
    TypedefName(Symbol),
}

/// A member declaration inside a `struct` or `union`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldDecl {
    /// The member's specifiers and qualifiers.
    pub specifiers: DeclSpecifiers,
    /// The member's declarator.
    pub declarator: Declarator,
    /// The bit-field width expression, if this is a bit-field.
    pub bit_width: Option<CNodeId>,
}

/// A single `enum` constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enumerator {
    /// The constant's name.
    pub name: Symbol,
    /// The explicit value expression, if given.
    pub value: Option<CNodeId>,
}

/// The leading specifiers of a declaration: storage class, qualifiers, type, and `inline`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeclSpecifiers {
    /// Storage-class specifiers, in source order.
    pub storage: Vec<StorageClass>,
    /// Type qualifiers, in source order.
    pub qualifiers: Vec<TypeQualifier>,
    /// Type specifiers, in source order.
    pub type_specifiers: Vec<TypeSpecifier>,
    /// Alignment specifiers, in source order.
    pub alignments: Vec<AlignmentSpecifier>,
    /// Whether the `inline` function specifier was present.
    pub inline: bool,
    /// Whether the C11 `_Noreturn` function specifier was present.
    pub noreturn: bool,
}

/// The operand accepted by a C23 `typeof` type specifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeofOperand {
    /// `typeof(type-name)`.
    Type(Box<TypeName>),
    /// `typeof(expression)`.
    Expr(CNodeId),
}

/// A type derivation applied around a declared name, innermost first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Derivation {
    /// A pointer, with its own qualifiers (e.g. `int * const p`).
    Pointer {
        /// Qualifiers applied to the pointer itself.
        qualifiers: Vec<TypeQualifier>,
    },
    /// An array, with an optional size expression.
    Array {
        /// The element-count expression, if specified.
        size: Option<CNodeId>,
    },
    /// A function, with its parameters.
    Function {
        /// The parameter declarations.
        params: Vec<ParamDecl>,
        /// Whether the parameter list ends with `, ...`.
        variadic: bool,
    },
}

/// A declarator: an optional name plus the derivations wrapping it.
///
/// An *abstract* declarator (used in casts, `sizeof`, and parameter type lists) has `name`
/// set to `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Declarator {
    /// The declared name, or `None` for an abstract declarator.
    pub name: Option<Symbol>,
    /// Derivations applied to the name, innermost first.
    pub derivations: Vec<Derivation>,
}

/// A single parameter declaration in a function declarator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamDecl {
    /// The parameter's specifiers.
    pub specifiers: DeclSpecifiers,
    /// The parameter's declarator (possibly abstract).
    pub declarator: Declarator,
}

/// A type name (abstract declaration) used by casts and `sizeof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeName {
    /// The specifiers and qualifiers.
    pub specifiers: DeclSpecifiers,
    /// The abstract declarator.
    pub declarator: Declarator,
}

/// A declarator paired with an optional initialiser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitDeclarator {
    /// The declarator.
    pub declarator: Declarator,
    /// The initialiser expression, if present.
    pub init: Option<CNodeId>,
}

/// A C99 designator selecting a sub-object within an aggregate initialiser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Designator {
    /// `.field`
    Field(Symbol),
    /// `[constant-expression]`
    Index(CNodeId),
}

/// One entry of a braced initialiser list: zero or more designators and a value.
#[derive(Debug, Clone, PartialEq)]
pub struct InitItem {
    /// The designators selecting where the value goes (empty for positional entries).
    pub designators: Vec<Designator>,
    /// The initialiser value (an expression or a nested [`CNode::InitList`]).
    pub value: CNodeId,
}

/// A node in the C AST: an external declaration, statement, or expression.
#[derive(Debug, Clone, PartialEq)]
pub enum CNode {
    /// The whole translation unit: a list of external declarations.
    TranslationUnit(Vec<CNodeId>),
    /// A function definition.
    FunctionDef {
        /// The declaration specifiers.
        specifiers: DeclSpecifiers,
        /// The function declarator (its name and parameters).
        declarator: Declarator,
        /// The function body (a compound statement).
        body: CNodeId,
    },
    /// A declaration of one or more entities.
    Declaration {
        /// The shared declaration specifiers.
        specifiers: DeclSpecifiers,
        /// The declarators with optional initializers.
        declarators: Vec<InitDeclarator>,
    },
    /// A C11/C23 static assertion declaration.
    StaticAssert {
        /// The constant expression being asserted.
        cond: CNodeId,
        /// The optional diagnostic message.
        message: Option<Symbol>,
    },

    /// A `{ ... }` block.
    Compound(Vec<CNodeId>),
    /// An expression statement, possibly empty (`;`).
    ExprStmt(Option<CNodeId>),
    /// An `if` statement.
    If {
        /// The controlling condition.
        cond: CNodeId,
        /// The statement run when the condition holds.
        then_branch: CNodeId,
        /// The `else` statement, if present.
        else_branch: Option<CNodeId>,
    },
    /// A `while` loop.
    While {
        /// The controlling condition.
        cond: CNodeId,
        /// The loop body.
        body: CNodeId,
    },
    /// A `do`/`while` loop.
    DoWhile {
        /// The loop body.
        body: CNodeId,
        /// The controlling condition.
        cond: CNodeId,
    },
    /// A `for` loop.
    For {
        /// The initialisation clause (expression or declaration).
        init: Option<CNodeId>,
        /// The controlling condition.
        cond: Option<CNodeId>,
        /// The iteration expression.
        step: Option<CNodeId>,
        /// The loop body.
        body: CNodeId,
    },
    /// A `return` statement.
    Return(Option<CNodeId>),
    /// A `break` statement.
    Break,
    /// A `continue` statement.
    Continue,
    /// A `goto` statement.
    Goto(Symbol),
    /// A labelled statement.
    Label {
        /// The label name.
        name: Symbol,
        /// The labelled statement.
        body: CNodeId,
    },
    /// A `switch` statement.
    Switch {
        /// The controlling expression.
        cond: CNodeId,
        /// The switch body.
        body: CNodeId,
    },
    /// A `case` label.
    Case {
        /// The case value expression.
        value: CNodeId,
        /// The statement following the label.
        body: CNodeId,
    },
    /// A `default` label.
    Default {
        /// The statement following the label.
        body: CNodeId,
    },

    /// An identifier reference.
    Ident(Symbol),
    /// An integer literal, kept as its raw spelling.
    IntLiteral(Symbol),
    /// A floating literal, kept as its raw spelling.
    FloatLiteral(Symbol),
    /// A character literal, kept as its raw spelling.
    CharLiteral(Symbol),
    /// A C23 boolean constant.
    BoolLiteral(bool),
    /// A C23 `nullptr` constant.
    Nullptr,
    /// A string literal, kept as its raw spelling.
    StringLiteral(Symbol),
    /// A prefix unary operation.
    Unary {
        /// The operator.
        op: UnaryOp,
        /// The operand.
        operand: CNodeId,
    },
    /// A postfix `++`/`--` operation.
    Postfix {
        /// The operator.
        op: PostfixOp,
        /// The operand.
        operand: CNodeId,
    },
    /// A binary operation.
    Binary {
        /// The operator.
        op: BinaryOp,
        /// The left operand.
        lhs: CNodeId,
        /// The right operand.
        rhs: CNodeId,
    },
    /// An assignment.
    Assign {
        /// The assignment operator.
        op: AssignOp,
        /// The target lvalue.
        target: CNodeId,
        /// The assigned value.
        value: CNodeId,
    },
    /// A conditional `a ? b : c` expression.
    Conditional {
        /// The condition.
        cond: CNodeId,
        /// The value when the condition holds.
        then_expr: CNodeId,
        /// The value otherwise.
        else_expr: CNodeId,
    },
    /// A comma expression `a, b`.
    Comma {
        /// The left, discarded operand.
        lhs: CNodeId,
        /// The right operand whose value is the result.
        rhs: CNodeId,
    },
    /// A function call.
    Call {
        /// The callee expression.
        callee: CNodeId,
        /// The argument expressions.
        args: Vec<CNodeId>,
    },
    /// A member access `a.b` or `a->b`.
    Member {
        /// The aggregate expression.
        base: CNodeId,
        /// The member name.
        field: Symbol,
        /// Whether the access used `->` (true) or `.` (false).
        arrow: bool,
    },
    /// An array subscript `a[i]`.
    Index {
        /// The array expression.
        base: CNodeId,
        /// The index expression.
        index: CNodeId,
    },
    /// A cast `(T)e`.
    Cast {
        /// The target type.
        type_name: TypeName,
        /// The operand.
        expr: CNodeId,
    },
    /// `sizeof e`.
    SizeofExpr(CNodeId),
    /// `sizeof(T)`.
    SizeofType(TypeName),
    /// C11 `_Alignof(type)` / C23 `alignof(type)`.
    AlignofType(TypeName),
    /// C23 `alignof expr`.
    AlignofExpr(CNodeId),
    /// A C11 generic selection.
    GenericSelection {
        /// The controlling assignment-expression.
        controlling: CNodeId,
        /// The generic associations.
        associations: Vec<GenericAssociation>,
    },
    /// A braced initialiser list `{ ... }`, possibly with C99 designators.
    InitList(Vec<InitItem>),
    /// A C99 compound literal `(T){ ... }`.
    CompoundLiteral {
        /// The literal's type.
        type_name: TypeName,
        /// The braced initialiser (a [`CNode::InitList`]).
        init: CNodeId,
    },
}

/// A single association in a C11 generic selection.
#[derive(Debug, Clone, PartialEq)]
pub struct GenericAssociation {
    /// `None` for the `default` association.
    pub type_name: Option<TypeName>,
    /// The selected expression for this association.
    pub expr: CNodeId,
}
