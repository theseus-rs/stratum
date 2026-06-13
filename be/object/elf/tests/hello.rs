//! Host-aware "Hello, world!" integration tests for emitted ELF executables.

mod support;

use std::path::PathBuf;
use stratum_elf::{samples, write};

#[test]
fn public_api_surface_is_covered() {
    support::exercise_public_api_surface();
}

fn x86_64_bytes() -> stratum_oir::Result<Vec<u8>> {
    let module = samples::hello_world_x86_64_linux()?;
    write(&module)
}

fn aarch64_bytes() -> stratum_oir::Result<Vec<u8>> {
    let module = samples::hello_world_aarch64_linux()?;
    write(&module)
}

fn artifact_path(name: &str) -> std::io::Result<PathBuf> {
    let mut path = std::env::current_dir()?;
    path.push("target");
    std::fs::create_dir_all(&path)?;
    path.push(format!("stratum_{name}_{}.elf", std::process::id()));
    Ok(path)
}

#[test]
fn x86_64_elf_is_structurally_valid() {
    let bytes = x86_64_bytes().unwrap();
    assert!(bytes.starts_with(b"\x7fELF"), "ELF magic");
    assert_eq!(bytes.get(4).copied(), Some(2), "ELFCLASS64");
    assert_eq!(bytes.get(5).copied(), Some(1), "little endian");
    let e_type = u16::from_le_bytes(bytes.get(16..18).and_then(|s| s.try_into().ok()).unwrap());
    let e_machine = u16::from_le_bytes(bytes.get(18..20).and_then(|s| s.try_into().ok()).unwrap());
    assert_eq!(e_type, 2);
    assert_eq!(e_machine, 62);
}

#[test]
fn aarch64_elf_is_structurally_valid() {
    let bytes = aarch64_bytes().unwrap();
    assert!(bytes.starts_with(b"\x7fELF"), "ELF magic");
    assert_eq!(bytes.get(4).copied(), Some(2), "ELFCLASS64");
    assert_eq!(bytes.get(5).copied(), Some(1), "little endian");
    let e_machine = u16::from_le_bytes(bytes.get(18..20).and_then(|s| s.try_into().ok()).unwrap());
    assert_eq!(e_machine, 183);
}

#[test]
fn llvm_readobj_accepts_hello_fixtures_when_available() {
    let tool = std::path::Path::new("/opt/homebrew/opt/llvm/bin/llvm-readobj");
    if !tool.exists() {
        return;
    }
    for (name, bytes) in [
        ("x86_64", x86_64_bytes().unwrap()),
        ("aarch64", aarch64_bytes().unwrap()),
    ] {
        let path = artifact_path(name).unwrap();
        std::fs::write(&path, bytes).unwrap();
        let output = std::process::Command::new(tool)
            .arg("--file-headers")
            .arg("--program-headers")
            .arg("--section-headers")
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(output.status.success(), "llvm-readobj rejected {name}");
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn x86_64_elf_runs_and_prints_hello() {
    use std::os::unix::fs::PermissionsExt;

    let path = artifact_path("run_x86_64").unwrap();
    std::fs::write(&path, x86_64_bytes().unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "process failed: {:?}",
        output.status
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        samples::HELLO_MESSAGE
    );
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[test]
fn aarch64_elf_runs_and_prints_hello() {
    use std::os::unix::fs::PermissionsExt;

    let path = artifact_path("run_aarch64").unwrap();
    std::fs::write(&path, aarch64_bytes().unwrap()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = std::process::Command::new(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "process failed: {:?}",
        output.status
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        samples::HELLO_MESSAGE
    );
}
