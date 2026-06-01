//! Parser tests for declarations: variables, multiple declarators, initializers,
//! storage classes, qualifiers, typedefs, and aggregate type declarations.

mod common;
use common::{assert_dump, assert_ok};

#[test]
fn single_variable() {
    assert_dump("int x;", "(tu (decl x))");
}

#[test]
fn multiple_declarators() {
    assert_dump("int x, y, z;", "(tu (decl x y z))");
}

#[test]
fn scalar_initialiser() {
    assert_dump("int x = 5;", "(tu (decl x=5))");
}

#[test]
fn multiple_with_initializers() {
    assert_dump("int a = 1, b = 2;", "(tu (decl a=1 b=2))");
}

#[test]
fn pointer_declarator() {
    assert_dump("int *p;", "(tu (decl p))");
}

#[test]
fn double_pointer_declarator() {
    assert_dump("int **pp;", "(tu (decl pp))");
}

#[test]
fn array_declarator() {
    assert_dump("int a[10];", "(tu (decl a))");
}

#[test]
fn multidimensional_array() {
    assert_ok("int grid[3][4];");
}

#[test]
fn char_initialiser_is_code_point() {
    assert_dump("char c = 'a';", "(tu (decl c=97))");
}

#[test]
fn floating_initialiser() {
    assert_dump("double d = 3.14;", "(tu (decl d=3.14))");
}

#[test]
fn unsigned_specifier() {
    assert_dump("unsigned int u;", "(tu (decl u))");
}

#[test]
fn storage_class_static() {
    assert_dump("static int s;", "(tu (decl s))");
}

#[test]
fn storage_class_extern() {
    assert_dump("extern int e;", "(tu (decl e))");
}

#[test]
fn const_qualifier() {
    assert_dump("const int ci = 1;", "(tu (decl ci=1))");
}

#[test]
fn volatile_qualifier() {
    assert_ok("volatile int v;");
}

#[test]
fn typedef_is_a_declaration() {
    assert_dump("typedef int myint;", "(tu (decl myint))");
}

#[test]
fn typedef_then_use() {
    assert_ok("typedef int myint; myint x;");
}

#[test]
fn typedef_pointer() {
    assert_ok("typedef int *intptr; intptr p;");
}

#[test]
fn struct_definition() {
    assert_dump("struct Point { int x; int y; };", "(tu (decl ))");
}

#[test]
fn struct_variable() {
    assert_ok("struct Point { int x; int y; } origin;");
}

#[test]
fn union_definition() {
    assert_ok("union U { int i; float f; };");
}

#[test]
fn enum_definition() {
    assert_dump("enum Color { RED, GREEN, BLUE };", "(tu (decl ))");
}

#[test]
fn enum_with_explicit_values() {
    assert_ok("enum E { A = 1, B = 2, C = 4 };");
}

#[test]
fn forward_struct_declaration() {
    assert_ok("struct Node;");
}

#[test]
fn nested_struct() {
    assert_ok("struct Outer { struct Inner { int x; } inner; };");
}

#[test]
fn function_prototype_void() {
    assert_dump("int f(void);", "(tu (decl f))");
}

#[test]
fn function_prototype_params() {
    assert_dump("int g(int a, int b);", "(tu (decl g))");
}

#[test]
fn multiple_top_level_declarations() {
    assert_dump("int a; int b; int c;", "(tu (decl a) (decl b) (decl c))");
}

#[test]
fn pointer_to_pointer_to_const() {
    assert_ok("const int *const *p;");
}

#[test]
fn optional_declaration_arms_parse_integration_path() {
    assert_ok(
        r#"
        alignas(16) int aligned_expr;
        alignas(int) int aligned_type;
        typeof(1 + 2) expr_type;
        typeof(int *) ptr_type;
        typeof_unqual(int) plain_type;
        struct Forward;
        enum Implicit { A, B = 2 };
        struct Fields { int a, b : 3; _Static_assert(1, "ok"); };
        int * const ptr;
        int unsized[];
        "#,
    );
}
