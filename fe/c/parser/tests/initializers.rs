//! Parser tests for initializers: braced lists, nesting, C99 designators, trailing commas,
//! and compound literals. These exercise coverage beyond the common subset that mainstream
//! compilers exercise in their happy-path smoke tests, focusing on the structural shapes the
//! parser must preserve for faithful lowering.

mod common;
use common::{assert_dump, assert_ok};

#[test]
fn scalar_initializer() {
    assert_dump("int x = 5;", "(tu (decl x=5))");
}

#[test]
fn flat_array_initializer() {
    assert_dump("int a[3] = { 1, 2, 3 };", "(tu (decl a=(init 1 2 3)))");
}

#[test]
fn trailing_comma_is_accepted() {
    assert_dump("int a[3] = { 1, 2, 3, };", "(tu (decl a=(init 1 2 3)))");
}

#[test]
fn empty_brace_initializer() {
    assert_dump("int x = { 0 };", "(tu (decl x=(init 0)))");
}

#[test]
fn nested_array_initializer() {
    assert_dump(
        "int m[2][2] = { { 1, 2 }, { 3, 4 } };",
        "(tu (decl m=(init (init 1 2) (init 3 4))))",
    );
}

#[test]
fn deeply_nested_initializer() {
    assert_dump(
        "int t[2][2][1] = { { { 1 }, { 2 } }, { { 3 }, { 4 } } };",
        "(tu (decl t=(init (init (init 1) (init 2)) (init (init 3) (init 4)))))",
    );
}

#[test]
fn field_designators() {
    assert_dump(
        "struct P { int x; int y; }; struct P p = { .y = 2, .x = 1 };",
        "(tu (decl ) (decl p=(init .y=2 .x=1)))",
    );
}

#[test]
fn array_index_designators() {
    assert_dump(
        "int a[4] = { [2] = 9, [0] = 1 };",
        "(tu (decl a=(init [2]=9 [0]=1)))",
    );
}

#[test]
fn nested_field_designators() {
    assert_dump("struct P p = { .a.b = 1 };", "(tu (decl p=(init .a.b=1)))");
}

#[test]
fn mixed_index_and_field_designator() {
    assert_dump(
        "struct P a[2] = { [1].x = 7 };",
        "(tu (decl a=(init [1].x=7)))",
    );
}

#[test]
fn designator_with_trailing_comma() {
    assert_dump(
        "int arr[] = { [0] = 1, [2] = 3, };",
        "(tu (decl arr=(init [0]=1 [2]=3)))",
    );
}

#[test]
fn compound_literal_in_assignment() {
    assert_dump(
        "void f(void) { q = (struct P){ 7 }; }",
        "(tu (fn f (block (expr (Assign q (compound-lit (init 7)))))))",
    );
}

#[test]
fn compound_literal_with_designators() {
    assert_ok("void f(void) { p = (struct P){ .x = 1, .y = 2 }; }");
}

#[test]
fn compound_literal_of_array_type() {
    assert_ok("void f(void) { int *p = (int[]){ 1, 2, 3 }; }");
}

#[test]
fn compound_literal_followed_by_subscript() {
    assert_ok("void f(void) { int n = (int[]){ 1, 2, 3 }[1]; }");
}

#[test]
fn string_initializer_for_char_array() {
    assert_dump("char s[] = \"hi\";", "(tu (decl s=\"hi\"))");
}

#[test]
fn initializer_with_expressions() {
    assert_dump(
        "int a[2] = { 1 + 2, 3 * 4 };",
        "(tu (decl a=(init (Add 1 2) (Mul 3 4))))",
    );
}
