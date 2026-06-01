use core::fmt;
use stratum_c_ast::{
    AssignOp, BinaryOp, CAst, CNode, DeclSpecifiers, Declarator, Designator, GenericAssociation,
    InitItem, TypeName, UnaryOp,
};
use stratum_diagnostics::{FileId, Span};

#[derive(Debug)]
enum DumpTestError {
    Ast(stratum_c_ast::Error),
    Mismatch { actual: String, expected: String },
    EmptyDump,
}

impl fmt::Display for DumpTestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ast(err) => write!(f, "{err}"),
            Self::Mismatch { actual, expected } => {
                write!(f, "expected {expected:?}, got {actual:?}")
            }
            Self::EmptyDump => write!(f, "expected non-empty dump output"),
        }
    }
}

impl std::error::Error for DumpTestError {}

impl From<stratum_c_ast::Error> for DumpTestError {
    fn from(err: stratum_c_ast::Error) -> Self {
        Self::Ast(err)
    }
}

type TestResult<T = ()> = Result<T, DumpTestError>;

fn span() -> Span {
    Span::point(FileId::from_raw(0), 0)
}

fn ensure_eq(actual: String, expected: &str) -> TestResult {
    if actual == expected {
        Ok(())
    } else {
        Err(DumpTestError::Mismatch {
            actual,
            expected: expected.to_string(),
        })
    }
}

fn ensure_non_empty(value: &str) -> TestResult {
    if value.is_empty() {
        Err(DumpTestError::EmptyDump)
    } else {
        Ok(())
    }
}

fn int(ast: &mut CAst, value: &str) -> TestResult<stratum_c_ast::CNodeId> {
    let symbol = ast.intern(value)?;
    Ok(ast.alloc(CNode::IntLiteral(symbol), span())?)
}

fn type_name() -> TypeName {
    TypeName {
        specifiers: DeclSpecifiers::default(),
        declarator: Declarator::default(),
    }
}

#[test]
fn public_dump_covers_normal_library_instantiation() -> TestResult {
    let mut ast = CAst::new();
    ensure_eq(ast.dump_root(), "<empty>")?;

    let one = int(&mut ast, "1")?;
    let two = int(&mut ast, "2")?;
    let name = ast.intern("field")?;
    let ident = ast.alloc(CNode::Ident(name), span())?;
    let string = ast.intern("\"s\"")?;
    let string = ast.alloc(CNode::StringLiteral(string), span())?;
    let float = ast.intern("1.0")?;
    let float = ast.alloc(CNode::FloatLiteral(float), span())?;
    let ch = ast.intern("'a'")?;
    let ch = ast.alloc(CNode::CharLiteral(ch), span())?;
    let unary = ast.alloc(
        CNode::Unary {
            op: UnaryOp::Not,
            operand: one,
        },
        span(),
    )?;
    let binary = ast.alloc(
        CNode::Binary {
            op: BinaryOp::Add,
            lhs: one,
            rhs: two,
        },
        span(),
    )?;
    let assign = ast.alloc(
        CNode::Assign {
            op: AssignOp::Assign,
            target: ident,
            value: two,
        },
        span(),
    )?;
    let generic = ast.alloc(
        CNode::GenericSelection {
            controlling: one,
            associations: vec![
                GenericAssociation {
                    type_name: Some(type_name()),
                    expr: two,
                },
                GenericAssociation {
                    type_name: None,
                    expr: one,
                },
            ],
        },
        span(),
    )?;
    let init = ast.alloc(
        CNode::InitList(vec![InitItem {
            designators: vec![Designator::Field(name), Designator::Index(one)],
            value: two,
        }]),
        span(),
    )?;

    for id in [string, float, ch, unary, binary, assign, generic, init] {
        ensure_non_empty(&ast.dump(id))?;
    }
    let stmt_as_expr = ast.alloc(CNode::Break, span())?;
    ensure_eq(ast.dump_expr(stmt_as_expr), "<stmt>")?;
    let nullptr = ast.alloc(CNode::Nullptr, span())?;
    ensure_eq(ast.dump(nullptr), "nullptr")?;
    let boolean = ast.alloc(CNode::BoolLiteral(true), span())?;
    ensure_eq(ast.dump(boolean), "true")?;
    let function_name = ast.intern("f")?;
    let body = ast.alloc(CNode::Compound(Vec::new()), span())?;
    let function = ast.alloc(
        CNode::FunctionDef {
            specifiers: DeclSpecifiers::default(),
            declarator: Declarator {
                name: Some(function_name),
                derivations: Vec::new(),
            },
            body,
        },
        span(),
    )?;
    ensure_eq(ast.dump(function), "(fn f (block ))")
}
