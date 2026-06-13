use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn fixture_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("stratum-driver-{name}-{}", std::process::id()));
    path
}

#[test]
fn binary_compiles_input_file() {
    let input = fixture_path("ok.c");
    fs::write(&input, "int main(void) { return 0; }\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--emit=ast")
        .arg(&input)
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("(tu"));

    fs::remove_file(input).unwrap();
}

#[test]
fn binary_emits_each_stage_and_uses_include_dirs() {
    let dir = fixture_path("include-dir");
    let input = dir.join("stages.c");
    let header = dir.join("hdr.h");
    fs::create_dir(&dir).unwrap();
    fs::write(&header, "#define VALUE 7\nint from_header;\n").unwrap();
    fs::write(
        &input,
        r#"#include "hdr.h"
#define X 1
#define ADD(a, b) a + b
#define STR(x) #x
#define HASH_TAIL(x) #
#define HASH_PLUS(x) # + x
#define CAT(a, b) a ## b
#define VA(a, ...) a + __VA_ARGS__
#if defined X
int sum = ADD(1, 2);
#elif 1
int skipped;
#else
int skipped_else;
#endif
#undef X
#ifndef X
const char *s = STR(hello   world);
int CAT(ma, in) = VA(1, 2);
#endif
#if 0
#error skipped
#else
int live;
#endif
int x = VALUE;
"#,
    )
    .unwrap();

    let pp_tokens = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("-I")
        .arg(&dir)
        .arg("--emit")
        .arg("pptokens")
        .arg(&input)
        .output()
        .unwrap();
    assert!(pp_tokens.status.success());
    let pp_output = String::from_utf8_lossy(&pp_tokens.stdout);
    assert!(pp_output.contains("number 7"));
    assert!(pp_output.contains("string \"hello world\""));
    assert!(pp_output.contains("ident main"));

    let tokens = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("-I")
        .arg(&dir)
        .arg("--emit=tokens")
        .arg(&input)
        .output()
        .unwrap();
    assert!(tokens.status.success());
    let token_output = String::from_utf8_lossy(&tokens.stdout);
    assert!(token_output.contains("keyword int"));
    assert!(token_output.contains("int 7"));

    let hir = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg(format!("-I{}", dir.display()))
        .arg("--emit")
        .arg("hir")
        .arg(&input)
        .output()
        .unwrap();
    assert!(hir.status.success());
    assert!(String::from_utf8_lossy(&hir.stdout).contains("var x"));

    let hash_input = dir.join("hash.c");
    fs::write(
        &hash_input,
        "#define HASH_TAIL(x) #\n#define HASH_PLUS(x) # + x\nHASH_TAIL(a)\nHASH_PLUS(a)\n",
    )
    .unwrap();
    let hash = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--emit=pptokens")
        .arg(&hash_input)
        .output()
        .unwrap();
    assert!(hash.status.success());
    assert!(String::from_utf8_lossy(&hash.stdout).contains("punct #"));

    let error_input = dir.join("error.c");
    fs::write(&error_input, "#error forced\nint after;\n").unwrap();
    let error = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--emit=pptokens")
        .arg(&error_input)
        .output()
        .unwrap();
    assert_eq!(error.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&error.stderr).contains("#error forced"));

    fs::remove_file(error_input).unwrap();
    fs::remove_file(hash_input).unwrap();
    fs::remove_file(input).unwrap();
    fs::remove_file(header).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[test]
fn binary_enforces_requested_std() {
    let input = fixture_path("std.c");
    fs::write(
        &input,
        "int f(void) { int x = 0; x = 1; int y = x; return y; }\n",
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--std=c89")
        .arg("--emit=ast")
        .arg(&input)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stdout).contains("(tu"));

    fs::remove_file(input).unwrap();
}

#[test]
fn binary_reports_help_as_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--help")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: stratum-c"));
}

#[test]
fn binary_reports_malformed_arguments_and_missing_files() {
    let bad_emit = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--emit=bad")
        .arg("input.c")
        .output()
        .unwrap();
    assert_eq!(bad_emit.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_emit.stderr).contains("unknown --emit"));

    let bad_std = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--std")
        .arg("bad")
        .arg("input.c")
        .output()
        .unwrap();
    assert_eq!(bad_std.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_std.stderr).contains("unknown --std"));

    let missing = fixture_path("missing.c");
    let missing_file = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg(&missing)
        .output()
        .unwrap();
    assert_eq!(missing_file.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_file.stderr).contains("cannot read"));
}
