//! Host-aware "Hello, world!" integration test for the WebAssembly codec.
//!
//! When a WASI runtime (`wasmtime`) is detected on the host the produced module is executed
//! and its stdout is checked. Otherwise the bytes are validated structurally only, so the
//! suite passes everywhere without a runtime installed.

use stratum_wasm::{samples, write};

fn build_bytes() -> stratum_oir::Result<Vec<u8>> {
    let module = samples::hello_world_wasm32_wasi()?;
    write(&module)
}

fn find_tool(name: &str) -> Option<std::path::PathBuf> {
    if name == "wasmtime"
        && let Ok(home) = std::env::var("HOME")
    {
        let candidate = std::path::Path::new(&home).join(".wasmtime/bin/wasmtime");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let path = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn test_output_path(name: &str) -> std::io::Result<std::path::PathBuf> {
    let dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/stratum-wasm-tests");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{name}_{}.wasm", std::process::id())))
}

#[test]
fn wasm_is_structurally_valid() {
    let bytes = build_bytes().unwrap();
    assert_eq!(
        bytes.get(..4),
        Some([0x00, 0x61, 0x73, 0x6D].as_slice()),
        "Wasm magic"
    );
    assert_eq!(
        bytes.get(4..8),
        Some([0x01, 0x00, 0x00, 0x00].as_slice()),
        "Wasm version 1"
    );
}

#[test]
fn wasm_tools_validates_self_emitted_samples_when_available() {
    let Some(wasm_tools) = find_tool("wasm-tools") else {
        return;
    };
    for (name, bytes) in [
        ("hello", samples::hello_bytes().unwrap()),
        ("full", samples::full_featured_bytes().unwrap()),
    ] {
        let path = test_output_path(name).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        let output = std::process::Command::new(&wasm_tools)
            .arg("validate")
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            output.status.success(),
            "wasm-tools failed for {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn wasmtime_compiles_self_emitted_samples_when_available() {
    let Some(wasmtime) = find_tool("wasmtime") else {
        return;
    };
    for (name, bytes) in [
        ("hello-compile", samples::hello_bytes().unwrap()),
        ("full-compile", samples::full_featured_bytes().unwrap()),
    ] {
        let wasm_path = test_output_path(name).unwrap();
        let cwasm_path = wasm_path.with_extension("cwasm");
        std::fs::write(&wasm_path, &bytes).unwrap();
        let output = std::process::Command::new(&wasmtime)
            .arg("compile")
            .arg("--output")
            .arg(&cwasm_path)
            .arg(&wasm_path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&wasm_path);
        let _ = std::fs::remove_file(&cwasm_path);
        assert!(
            output.status.success(),
            "wasmtime compile failed for {name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn wasm_runs_and_prints_hello() {
    let Some(wasmtime) = find_tool("wasmtime") else {
        return;
    };
    let bytes = build_bytes().unwrap();
    let path = test_output_path("hello-run").unwrap();
    std::fs::write(&path, &bytes).unwrap();

    let output = std::process::Command::new(&wasmtime)
        .arg("run")
        .arg(&path)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "wasmtime exited with failure: {:?}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        samples::HELLO_MESSAGE
    );
}
