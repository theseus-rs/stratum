//! Parser tests for statements: selection, iteration, jumps, labels, switch, blocks,
//! and how statement bodies nest.

mod common;
use common::{assert_dump, assert_ok};

/// Wraps `body` inside `f` and asserts the dumped block contents.
fn stmt(body: &str, expected_inner: &str) {
    let src = format!("int f() {{ {body} }}");
    let expected = format!("(tu (fn f (block {expected_inner})))");
    assert_dump(&src, &expected);
}

#[test]
fn return_with_value() {
    stmt("return 0;", "(return 0)");
}

#[test]
fn return_without_value() {
    stmt("return;", "(return _)");
}

#[test]
fn expression_statement() {
    stmt("a + b;", "(expr (Add a b))");
}

#[test]
fn empty_statement() {
    stmt(";", "(expr)");
}

#[test]
fn local_declaration() {
    stmt("int x;", "(decl x)");
}

#[test]
fn local_declaration_with_init() {
    stmt("int x = 5;", "(decl x=5)");
}

#[test]
fn if_without_else() {
    stmt("if (a) b;", "(if a (expr b))");
}

#[test]
fn if_with_else() {
    stmt("if (a) b; else c;", "(if a (expr b) (expr c))");
}

#[test]
fn dangling_else_binds_to_nearest_if() {
    stmt(
        "if (a) if (b) c; else d;",
        "(if a (if b (expr c) (expr d)))",
    );
}

#[test]
fn else_if_chain() {
    stmt(
        "if (a) x; else if (b) y; else z;",
        "(if a (expr x) (if b (expr y) (expr z)))",
    );
}

#[test]
fn while_loop() {
    stmt("while (a) b;", "(while a (expr b))");
}

#[test]
fn do_while_loop() {
    stmt("do b; while (a);", "(do (expr b) a)");
}

#[test]
fn for_loop_full() {
    stmt(
        "for (i = 0; i < n; i++) b;",
        "(for (Assign i 0) (Lt i n) (PostInc i) (expr b))",
    );
}

#[test]
fn for_loop_empty_clauses() {
    stmt("for (;;) b;", "(for _ _ _ (expr b))");
}

#[test]
fn for_loop_with_declaration() {
    assert_ok("int f() { for (int i = 0; i < n; i++) g(i); }");
}

#[test]
fn break_statement() {
    stmt("break;", "(break)");
}

#[test]
fn continue_statement() {
    stmt("continue;", "(continue)");
}

#[test]
fn goto_and_label() {
    stmt("goto end; end: ;", "(goto end) (label end (expr))");
}

#[test]
fn switch_with_cases() {
    stmt(
        "switch (x) { case 1: break; default: break; }",
        "(switch x (block (case 1 (break)) (default (break))))",
    );
}

#[test]
fn nested_block_scope() {
    stmt("{ int x; }", "(block (decl x))");
}

#[test]
fn deeply_nested_blocks() {
    stmt("{ { { ; } } }", "(block (block (block (expr))))");
}

#[test]
fn multiple_statements_in_order() {
    stmt(
        "int x; x = 1; return x;",
        "(decl x) (expr (Assign x 1)) (return x)",
    );
}

#[test]
fn loop_with_compound_body() {
    stmt("while (a) { b; c; }", "(while a (block (expr b) (expr c)))");
}

#[test]
fn nested_loops() {
    assert_ok("int f() { for (i=0;i<n;i++) for (j=0;j<m;j++) g(); }");
}
