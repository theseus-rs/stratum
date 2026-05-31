//! Operators used by the C abstract syntax tree.

/// A C binary operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryOp {
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `%`
    Rem,
    /// `+`
    Add,
    /// `-`
    Sub,
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
    Eq,
    /// `!=`
    Ne,
    /// `&`
    BitAnd,
    /// `^`
    BitXor,
    /// `|`
    BitOr,
    /// `&&`
    LogicalAnd,
    /// `||`
    LogicalOr,
}

/// A C unary (prefix) operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnaryOp {
    /// `+a`
    Plus,
    /// `-a`
    Neg,
    /// `!a`
    Not,
    /// `~a`
    BitNot,
    /// `&a`
    AddressOf,
    /// `*a`
    Deref,
    /// `++a`
    PreInc,
    /// `--a`
    PreDec,
}

/// A C postfix operator that takes no further operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostfixOp {
    /// `a++`
    PostInc,
    /// `a--`
    PostDec,
}

/// A C assignment operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssignOp {
    /// `=`
    Assign,
    /// `*=`
    Mul,
    /// `/=`
    Div,
    /// `%=`
    Rem,
    /// `+=`
    Add,
    /// `-=`
    Sub,
    /// `<<=`
    Shl,
    /// `>>=`
    Shr,
    /// `&=`
    And,
    /// `^=`
    Xor,
    /// `|=`
    Or,
}
