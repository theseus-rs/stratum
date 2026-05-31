//! Parser tests for the type grammar: storage classes, qualifiers, pointers, arrays,
//! function declarators, aggregates (`struct`/`union`/`enum`), `typedef`, and the more
//! tangled declarator forms (function pointers, arrays of pointers, qualified pointers).
//!
//! The shared S-expression dump intentionally elides type detail, so most of these assert
//! that the parser *accepts* the construct (a strong signal on its own, given the declarator
//! grammar is the trickiest part of C), with structural assertions where names are visible.

mod common;
use common::{assert_dump, assert_ok};

#[test]
fn pointer_declarator() {
    assert_dump("int *p;", "(tu (decl p))");
}

#[test]
fn multi_level_pointer() {
    assert_ok("int ***p;");
}

#[test]
fn const_and_volatile_qualifiers() {
    assert_ok("const int a; volatile int b; const volatile int c;");
}

#[test]
fn qualified_pointer_forms() {
    assert_ok("const int *p; int *const q; const int *const r;");
}

#[test]
fn restrict_qualifier() {
    assert_ok("int *restrict p;");
}

#[test]
fn array_declarators() {
    assert_ok("int a[10]; int b[2][3]; int c[1][2][3];");
}

#[test]
fn array_of_pointers_and_pointer_to_array() {
    assert_ok("int *a[3]; int (*b)[3];");
}

#[test]
fn function_pointer() {
    assert_dump("int (*fp)(int, int);", "(tu (decl fp))");
}

#[test]
fn function_returning_pointer() {
    assert_ok("int *f(void);");
}

#[test]
fn pointer_to_function_returning_pointer() {
    assert_ok("char *(*fp)(int);");
}

#[test]
fn all_storage_classes() {
    assert_ok("extern int a; static int b; register int c; auto int local_unused;");
}

#[test]
fn storage_class_with_qualifiers() {
    assert_dump("static const unsigned long x = 5;", "(tu (decl x=5))");
}

#[test]
fn integer_type_combinations() {
    assert_ok(
        "signed char a; unsigned char b; short c; unsigned short d; \
         int e; unsigned int f; long g; unsigned long h; \
         long long i; unsigned long long j;",
    );
}

#[test]
fn floating_and_bool_types() {
    assert_ok("float a; double b; long double c; _Bool d;");
}

#[test]
fn struct_definition() {
    assert_dump("struct Point { int x; int y; };", "(tu (decl ))");
}

#[test]
fn struct_with_variable() {
    assert_dump("struct Point { int x; } p;", "(tu (decl p))");
}

#[test]
fn anonymous_struct() {
    assert_ok("struct { int x; int y; } origin;");
}

#[test]
fn union_definition() {
    assert_ok("union U { int i; float f; char bytes[4]; };");
}

#[test]
fn enum_definition() {
    assert_ok("enum Color { Red, Green, Blue };");
}

#[test]
fn enum_with_explicit_values() {
    assert_ok("enum E { A = 1, B = 2, C = 4, D };");
}

#[test]
fn bitfields() {
    assert_ok("struct Flags { unsigned a : 1; unsigned b : 3; int : 0; signed c : 4; };");
}

#[test]
fn nested_aggregates() {
    assert_ok("struct Outer { struct Inner { int x; } inner; int y; };");
}

#[test]
fn typedef_simple() {
    assert_dump("typedef int myint; myint v;", "(tu (decl myint) (decl v))");
}

#[test]
fn typedef_pointer_and_struct() {
    assert_ok("typedef char *string; typedef struct Node { int v; } Node;");
}

#[test]
fn typedef_function_pointer() {
    assert_ok("typedef int (*binop)(int, int); binop add;");
}

#[test]
fn forward_struct_declaration() {
    assert_ok("struct Node; struct Node { struct Node *next; int value; };");
}

#[test]
fn prototype_with_unnamed_parameters() {
    assert_ok("int f(int, char *, double);");
}

#[test]
fn variadic_prototype() {
    assert_ok("int printf(const char *fmt, ...);");
}

#[test]
fn void_parameter_list() {
    assert_ok("int f(void);");
}
