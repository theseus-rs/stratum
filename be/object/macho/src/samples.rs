//! Freestanding "Hello, world!" Mach-O samples for macOS.

use crate::consts::{PAGE_SIZE, TEXT_VMADDR};
use crate::convert::{u32_from_usize, u64_from_usize};
use crate::write::CODE_OFFSET;
use stratum_oir::{
    Architecture, BinaryFormat, Error, ObjectModule, PtrWidth, Result, Section, SectionFlags,
    SectionKind, TargetSpec,
};

extern crate alloc;
use alloc::vec::Vec;

/// The exact bytes the samples write to standard output.
pub const HELLO_MESSAGE: &str = "Hello, world!\n";

const SYS_WRITE: u32 = 4;
const SYS_EXIT: u32 = 1;

fn movz(rd: u32, imm16: u32) -> u32 {
    0xD280_0000 | (imm16 << 5) | rd
}

fn adr(rd: u32, imm: u32) -> u32 {
    let immlo = imm & 0x3;
    let immhi = (imm >> 2) & 0x7_FFFF;
    0x1000_0000 | (immlo << 29) | (immhi << 5) | rd
}

fn push32(code: &mut Vec<u8>, insn: u32) {
    code.extend_from_slice(&insn.to_le_bytes());
}

fn push8(code: &mut Vec<u8>, byte: u8) {
    code.push(byte);
}

fn push_x86_imm32(code: &mut Vec<u8>, value: u32) {
    code.extend_from_slice(&value.to_le_bytes());
}

fn text_module(target: TargetSpec, code: Vec<u8>) -> Result<ObjectModule> {
    let size = u64_from_usize(code.len());
    let addr = TEXT_VMADDR + u64::from(CODE_OFFSET);
    if u64::from(CODE_OFFSET).saturating_add(size) > PAGE_SIZE {
        return Err(Error::ValueOutOfRange("sample exceeds first page"));
    }
    let mut module = ObjectModule::new(BinaryFormat::MachO, target);
    let name = module.intern("__text")?;
    module.add_section(Section {
        name,
        kind: SectionKind::Text,
        address: addr,
        align: 4,
        flags: SectionFlags::code(),
        data: code,
        size,
    })?;
    module.set_entry(addr);
    Ok(module)
}

/// Builds a freestanding arm64 macOS executable that prints [`HELLO_MESSAGE`].
///
/// # Errors
///
/// Returns an error if an arena fills.
pub fn hello_world_aarch64_macos() -> Result<ObjectModule> {
    let message = HELLO_MESSAGE.as_bytes();
    let len = u32_from_usize(message.len());

    let mut code: Vec<u8> = Vec::new();
    push32(&mut code, movz(0, 1));
    push32(&mut code, adr(1, 28));
    push32(&mut code, movz(2, len));
    push32(&mut code, movz(16, SYS_WRITE));
    push32(&mut code, 0xD400_1001);
    push32(&mut code, movz(0, 0));
    push32(&mut code, movz(16, SYS_EXIT));
    push32(&mut code, 0xD400_1001);
    debug_assert_eq!(code.len(), 32);
    code.extend_from_slice(message);
    text_module(TargetSpec::aarch64(), code)
}

/// Builds a freestanding `x86_64` macOS executable that prints [`HELLO_MESSAGE`].
///
/// # Errors
///
/// Returns an error if the message length does not fit the syscall immediate or an arena fills.
pub fn hello_world_x86_64_macos() -> Result<ObjectModule> {
    let message = HELLO_MESSAGE.as_bytes();
    let len = u32_from_usize(message.len());
    let mut code = Vec::new();
    push8(&mut code, 0xB8);
    push_x86_imm32(&mut code, 0x0200_0004);
    push8(&mut code, 0xBF);
    push_x86_imm32(&mut code, 1);
    code.extend_from_slice(&[0x48, 0x8D, 0x35]);
    push_x86_imm32(&mut code, 16);
    push8(&mut code, 0xBA);
    push_x86_imm32(&mut code, len);
    code.extend_from_slice(&[0x0F, 0x05]);
    push8(&mut code, 0xB8);
    push_x86_imm32(&mut code, 0x0200_0001);
    code.extend_from_slice(&[0x31, 0xFF, 0x0F, 0x05]);
    debug_assert_eq!(code.len(), 33);
    code.extend_from_slice(message);
    text_module(TargetSpec::x86_64(), code)
}

/// Empty structural i386 sample used to exercise 32-bit Mach-O encoding.
///
/// # Errors
///
/// Returns an error if an arena fills.
pub fn empty_i386_macos() -> Result<ObjectModule> {
    Ok(ObjectModule::new(BinaryFormat::MachO, TargetSpec::x86()))
}

/// Empty structural armv7 sample used to exercise 32-bit Mach-O encoding.
///
/// # Errors
///
/// Returns an error if an arena fills.
pub fn empty_arm_macos() -> Result<ObjectModule> {
    Ok(ObjectModule::new(
        BinaryFormat::MachO,
        TargetSpec::new(
            Architecture::Arm,
            stratum_oir::Endianness::Little,
            PtrWidth::W32,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[test]
    fn all_samples_build_modules() {
        let arm64 = hello_world_aarch64_macos().unwrap();
        assert_eq!(arm64.section_count(), 1);
        let x86_64 = hello_world_x86_64_macos().unwrap();
        assert_eq!(x86_64.section_count(), 1);
        assert_eq!(
            empty_i386_macos().unwrap().target().ptr_width,
            PtrWidth::W32
        );
        assert_eq!(empty_arm_macos().unwrap().target().arch, Architecture::Arm);
    }

    #[test]
    fn text_module_rejects_first_page_overflow() {
        let big_len = usize::try_from(PAGE_SIZE).unwrap();
        let code: Vec<u8> = vec![0; big_len];
        assert!(text_module(TargetSpec::aarch64(), code).is_err());
    }
}
