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
fn binary_reports_help_as_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_stratum-c"))
        .arg("--help")
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("usage: stratum-c"));
}
