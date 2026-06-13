//! Host-aware "Hello, world!" integration tests for the Mach-O codec.

use stratum_macho::{read, samples, write};

fn build_arm64_bytes() -> stratum_oir::Result<Vec<u8>> {
    let module = samples::hello_world_aarch64_macos()?;
    write(&module)
}

fn build_x86_64_bytes() -> stratum_oir::Result<Vec<u8>> {
    let module = samples::hello_world_x86_64_macos()?;
    write(&module)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    Some(u32::from_le_bytes(
        bytes.get(offset..end).and_then(|s| s.try_into().ok())?,
    ))
}

fn executable_path(name: &str) -> std::io::Result<std::path::PathBuf> {
    let mut dir = std::env::current_dir()?;
    dir.push("target");
    dir.push("stratum-macho-tests");
    std::fs::create_dir_all(&dir)?;
    dir.push(format!("{name}_{}", std::process::id()));
    Ok(dir)
}

fn write_executable(name: &str, bytes: &[u8]) -> std::io::Result<std::path::PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let path = executable_path(name)?;
    {
        let mut file = std::fs::File::create(&path)?;
        file.write_all(bytes)?;
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

#[test]
fn arm64_macho_is_structurally_valid() {
    let bytes = build_arm64_bytes().unwrap();
    assert_eq!(
        bytes.get(..4),
        Some([0xCF, 0xFA, 0xED, 0xFE].as_slice()),
        "Mach-O magic"
    );
    assert_eq!(read_u32(&bytes, 4).unwrap(), 0x0100_000C);
    assert_eq!(read_u32(&bytes, 12).unwrap(), 2);
}

#[test]
fn x86_64_macho_is_structurally_valid() {
    let bytes = build_x86_64_bytes().unwrap();
    assert_eq!(
        bytes.get(..4),
        Some([0xCF, 0xFA, 0xED, 0xFE].as_slice()),
        "Mach-O magic"
    );
    assert_eq!(read_u32(&bytes, 4).unwrap(), 0x0100_0007);
    assert_eq!(read_u32(&bytes, 12).unwrap(), 2);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Option<()> {
    bytes
        .get_mut(offset..offset.checked_add(4)?)
        .map(|slot| slot.copy_from_slice(&value.to_le_bytes()))
}

#[test]
fn malformed_headers_are_rejected_through_public_api() {
    let bytes = build_arm64_bytes().unwrap();
    assert!(read(bytes.get(..40).unwrap()).is_err());

    let mut bytes = build_arm64_bytes().unwrap();
    put_u32(&mut bytes, 36, 0).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = build_arm64_bytes().unwrap();
    put_u32(&mut bytes, 4, 0).unwrap();
    assert!(read(&bytes).is_err());

    let mut bytes = Vec::new();
    for value in [0xFEED_FACF_u32, 0x0100_0007, 3, 2, 1, 0, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    assert!(read(&bytes).is_err());

    let mut bytes = Vec::new();
    for value in [0xFEED_FACF_u32, 0x0100_0007, 3, 2, 1, 8, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&0x2_u32.to_le_bytes());
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.resize(48, 0);
    assert!(read(&bytes).is_err());

    let mut bytes = Vec::new();
    for value in [0xFEED_FACF_u32, 0x0100_0007, 3, 2, 1, 56, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&0x1_u32.to_le_bytes());
    bytes.extend_from_slice(&56_u32.to_le_bytes());
    bytes.resize(88, 0);
    assert!(read(&bytes).is_err());

    let mut bytes = Vec::new();
    for value in [0xFEED_FACF_u32, 0x0100_0007, 3, 2, 1, 8, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&0x1234_u32.to_le_bytes());
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    assert!(read(&bytes).is_ok());

    let mut bytes = Vec::new();
    for value in [0xFEED_FACF_u32, 0x0100_0007, 3, 2, 0, 8, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.resize(40, 0);
    assert!(read(&bytes).is_err());

    let mut bytes = Vec::new();
    for value in [
        0xFEED_FACF_u32,
        0x0100_0007,
        3,
        2,
        1,
        24,
        0,
        0,
        0x2,
        24,
        56,
        1,
        72,
        2,
        0,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    bytes.push(0);
    assert!(read(&bytes).is_err());
}

#[test]
fn minimal_image_without_symbol_table_reads() {
    let mut bytes = Vec::new();
    for value in [0xFEED_FACF_u32, 0x0100_0007, 3, 2, 0, 0, 0, 0] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    let parsed = read(&bytes).unwrap();
    assert_eq!(parsed.symbol_count(), 0);
}

#[test]
fn rejects_segment_with_inconsistent_section_count() {
    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0xFEED_FACF);
    push_u32(&mut bytes, 0x0100_0007);
    push_u32(&mut bytes, 3);
    push_u32(&mut bytes, 2);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 72);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0x19);
    push_u32(&mut bytes, 72);
    let mut segname = [0u8; 16];
    segname.get_mut(..6).unwrap().copy_from_slice(b"__TEXT");
    bytes.extend_from_slice(&segname);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, 0);
    push_u64(&mut bytes, 0);
    push_u32(&mut bytes, 5);
    push_u32(&mut bytes, 5);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 0);

    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_symbol_string_index_at_string_table_end() {
    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let mut bytes = Vec::new();
    push_u32(&mut bytes, 0xFEED_FACF);
    push_u32(&mut bytes, 0x0100_0007);
    push_u32(&mut bytes, 3);
    push_u32(&mut bytes, 2);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0);
    push_u32(&mut bytes, 0x2);
    push_u32(&mut bytes, 24);
    push_u32(&mut bytes, 56);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 72);
    push_u32(&mut bytes, 1);
    push_u32(&mut bytes, 1);
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    push_u64(&mut bytes, 0);
    bytes.push(0);

    assert!(read(&bytes).is_err());
}

#[test]
fn host_tools_accept_arm64_sample_when_available() {
    let bytes = build_arm64_bytes().unwrap();
    let path = write_executable("stratum_arm64_hello", &bytes).unwrap();
    if std::path::Path::new("/usr/bin/otool").exists() {
        let output = std::process::Command::new("/usr/bin/otool")
            .args(["-l"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(output.status.success(), "otool failed: {:?}", output.status);
    }
    if std::path::Path::new("/usr/bin/codesign").exists() {
        let output = std::process::Command::new("/usr/bin/codesign")
            .args(["--verify"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "codesign failed: {:?}",
            output.status
        );
    }
    let _ = std::fs::remove_file(&path);
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[test]
fn arm64_macho_runs_and_prints_hello() {
    let bytes = build_arm64_bytes().unwrap();
    let path = write_executable("stratum_arm64_run", &bytes).unwrap();
    let output = std::process::Command::new(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "process exited with failure: {:?}",
        output.status
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        samples::HELLO_MESSAGE
    );
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
#[test]
fn x86_64_macho_runs_and_prints_hello() {
    let bytes = build_x86_64_bytes().unwrap();
    let path = write_executable("stratum_x86_64_run", &bytes).unwrap();
    let output = std::process::Command::new(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);

    assert!(
        output.status.success(),
        "process exited with failure: {:?}",
        output.status
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        samples::HELLO_MESSAGE
    );
}
