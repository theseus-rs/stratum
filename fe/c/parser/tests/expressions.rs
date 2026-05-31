//! Parser tests for expressions: precedence, associativity, unary/postfix operators,
//! calls, subscripting, member access, casts, and the ternary/comma operators.

mod common;
use common::{assert_dump, assert_ok};

/// Wraps an expression in a `return` inside `f` and asserts the dumped form.
fn expr(src_expr: &str, expected_inner: &str) {
    let src = format!("int f() {{ return {src_expr}; }}");
    let expected = format!("(tu (fn f (block (return {expected_inner}))))");
    assert_dump(&src, &expected);
}

#[test]
fn additive_then_multiplicative_precedence() {
    expr("1 + 2 * 3", "(Add 1 (Mul 2 3))");
}

#[test]
fn parentheses_override_precedence() {
    expr("(1 + 2) * 3", "(Mul (Add 1 2) 3)");
}

#[test]
fn subtraction_is_left_associative() {
    expr("a - b - c", "(Sub (Sub a b) c)");
}

#[test]
fn division_and_remainder() {
    expr("a / b % c", "(Rem (Div a b) c)");
}

#[test]
fn shift_below_bitor() {
    expr("a << 2 | b", "(BitOr (Shl a 2) b)");
}

#[test]
fn bitwise_precedence_chain() {
    expr("a | b & c ^ d", "(BitOr a (BitXor (BitAnd b c) d))");
}

#[test]
fn equality_lower_than_relational() {
    expr("a < b == c", "(Eq (Lt a b) c)");
}

#[test]
fn logical_and_below_or() {
    expr("a && b || c", "(LogicalOr (LogicalAnd a b) c)");
}

#[test]
fn equality_operator() {
    expr("a == b", "(Eq a b)");
}

#[test]
fn not_equal_operator() {
    expr("a != b", "(Ne a b)");
}

#[test]
fn relational_operators() {
    expr("a <= b", "(Le a b)");
    expr("a >= b", "(Ge a b)");
    expr("a > b", "(Gt a b)");
}

#[test]
fn assignment_is_right_associative() {
    assert_dump(
        "int f() { a = b = c; }",
        "(tu (fn f (block (expr (Assign a (Assign b c))))))",
    );
}

#[test]
fn compound_assignment_add() {
    expr("a += 5", "(Add a 5)");
}

#[test]
fn ternary_operator() {
    expr("a < b ? a : b", "(?: (Lt a b) a b)");
}

#[test]
fn nested_ternary_is_right_associative() {
    expr("a ? b : c ? d : e", "(?: a b (?: c d e))");
}

#[test]
fn unary_negation() {
    expr("-a", "(Neg a)");
}

#[test]
fn unary_plus() {
    expr("+a", "(Plus a)");
}

#[test]
fn logical_not() {
    expr("!a", "(Not a)");
}

#[test]
fn bitwise_complement() {
    expr("~a", "(BitNot a)");
}

#[test]
fn dereference() {
    expr("*p", "(Deref p)");
}

#[test]
fn address_of() {
    expr("&x", "(AddressOf x)");
}

#[test]
fn prefix_increment() {
    expr("++a", "(PreInc a)");
}

#[test]
fn prefix_decrement() {
    expr("--a", "(PreDec a)");
}

#[test]
fn postfix_increment() {
    expr("a++", "(PostInc a)");
}

#[test]
fn postfix_decrement() {
    expr("a--", "(PostDec a)");
}

#[test]
fn nested_unary() {
    expr("!!a", "(Not (Not a))");
}

#[test]
fn deref_of_address() {
    expr("*&x", "(Deref (AddressOf x))");
}

#[test]
fn call_no_args() {
    expr("f()", "(call f )");
}

#[test]
fn call_with_args() {
    expr("f(1, 2, 3)", "(call f 1 2 3)");
}

#[test]
fn call_with_expression_args() {
    expr("f(a + b, c * d)", "(call f (Add a b) (Mul c d))");
}

#[test]
fn nested_calls() {
    expr("f(g(x))", "(call f (call g x))");
}

#[test]
fn array_subscript() {
    expr("arr[i]", "(idx arr i)");
}

#[test]
fn chained_subscript() {
    expr("m[i][j]", "(idx (idx m i) j)");
}

#[test]
fn member_access_dot() {
    expr("s.field", "(mem. s field)");
}

#[test]
fn member_access_arrow() {
    expr("p->field", "(mem-> p field)");
}

#[test]
fn chained_member_access() {
    expr("a.b.c", "(mem. (mem. a b) c)");
}

#[test]
fn mixed_postfix_chain() {
    expr("obj.items[0]", "(idx (mem. obj items) 0)");
}

#[test]
fn cast_expression() {
    expr("(int)x", "(cast x)");
}

#[test]
fn sizeof_expression() {
    expr("sizeof x", "(sizeof x)");
}

#[test]
fn comma_operator() {
    expr("a, b", "(comma a b)");
}

#[test]
fn string_literal_expression() {
    expr("\"hello\"", "\"hello\"");
}

#[test]
fn adjacent_string_literals_concatenate() {
    assert_ok("int f() { return \"foo\" \"bar\"; }");
}

#[test]
fn complex_real_world_expression() {
    expr(
        "a * b + c / d - e % f",
        "(Sub (Add (Mul a b) (Div c d)) (Rem e f))",
    );
}
