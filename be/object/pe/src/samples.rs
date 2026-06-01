//! Self-emitted PE fixtures used by tests and examples.

use crate::consts::{IMAGE_BASE64, SECTION_ALIGNMENT};
use stratum_oir::{
    Architecture, BinaryFormat, ByteWriter, Endianness, Error, Export, Import, ObjectModule,
    Result, Section, SectionFlags, SectionKind, SymbolBinding, SymbolEntry, SymbolFlags,
    SymbolKind, TargetSpec,
};

extern crate alloc;
use alloc::vec::Vec;

/// The exact bytes the runnable samples write to standard output.
pub const HELLO_MESSAGE: &str = "Hello, world!\n";

const TEXT_RVA: u32 = SECTION_ALIGNMENT;
const IDATA_RVA: u32 = SECTION_ALIGNMENT * 2;
const EDATA_RVA: u32 = SECTION_ALIGNMENT * 3;
const RELOC_RVA: u32 = SECTION_ALIGNMENT * 4;
const X64_CODE_LEN: u32 = 60;
const IMPORTS: [&str; 3] = ["GetStdHandle", "WriteFile", "ExitProcess"];
const DLL_NAME: &str = "kernel32.dll";

struct Imports {
    bytes: Vec<u8>,
    iat: [u32; 3],
}

fn build_imports64() -> Result<Imports> {
    build_imports(8)
}

fn build_imports32() -> Result<Imports> {
    build_imports(4)
}

fn build_imports(thunk_width: u32) -> Result<Imports> {
    let n = IMPORTS.len();
    let lookup_off = 40u32;
    let entries = u32::try_from(n.checked_add(1).ok_or(Error::ValueOutOfRange("imports"))?)
        .map_err(|_| Error::ValueOutOfRange("imports"))?
        .saturating_mul(thunk_width);
    let addr_off = lookup_off + entries;
    let names_off = addr_off + entries;
    let mut hint_name_offsets = [0u32; 3];
    let mut cursor = names_off;
    for (slot, import) in hint_name_offsets.iter_mut().zip(IMPORTS) {
        *slot = cursor;
        let len = u32::try_from(import.len()).map_err(|_| Error::ValueOutOfRange("name"))?;
        let entry_len = align_even(2 + len + 1);
        cursor = cursor.saturating_add(entry_len);
    }
    let dll_off = cursor;
    let mut w = ByteWriter::new(Endianness::Little);
    w.write_u32(IDATA_RVA + lookup_off);
    w.write_u32(0);
    w.write_u32(0);
    w.write_u32(IDATA_RVA + dll_off);
    w.write_u32(IDATA_RVA + addr_off);
    w.write_zeros(20);
    for _ in 0..2 {
        for slot in hint_name_offsets {
            if thunk_width == 8 {
                w.write_u64(u64::from(IDATA_RVA + slot));
            } else {
                w.write_u32(IDATA_RVA + slot);
            }
        }
        if thunk_width == 8 {
            w.write_u64(0);
        } else {
            w.write_u32(0);
        }
    }
    for import in IMPORTS {
        w.write_u16(0);
        w.write_bytes(import.as_bytes());
        w.write_u8(0);
        if align_even(
            2 + u32::try_from(import.len()).map_err(|_| Error::ValueOutOfRange("name"))? + 1,
        ) != 2 + u32::try_from(import.len()).map_err(|_| Error::ValueOutOfRange("name"))? + 1
        {
            w.write_u8(0);
        }
    }
    w.write_bytes(DLL_NAME.as_bytes());
    w.write_u8(0);
    Ok(Imports {
        bytes: w.finish()?,
        iat: [
            IDATA_RVA + addr_off,
            IDATA_RVA + addr_off + thunk_width,
            IDATA_RVA + addr_off + thunk_width.saturating_mul(2),
        ],
    })
}

const fn align_even(value: u32) -> u32 {
    value + (value & 1)
}

fn push_u32(code: &mut Vec<u8>, value: u32) {
    code.extend_from_slice(&value.to_le_bytes());
}

fn rip_call(code: &mut Vec<u8>, target: u32) -> Result<()> {
    let next = TEXT_RVA
        .checked_add(u32::try_from(code.len()).map_err(|_| Error::ValueOutOfRange("code"))?)
        .and_then(|v| v.checked_add(6))
        .ok_or(Error::ValueOutOfRange("code"))?;
    let disp = target.wrapping_sub(next);
    code.extend_from_slice(&[0xFF, 0x15]);
    push_u32(code, disp);
    Ok(())
}

fn rip_lea_rdx(code: &mut Vec<u8>, target: u32) -> Result<()> {
    let next = TEXT_RVA
        .checked_add(u32::try_from(code.len()).map_err(|_| Error::ValueOutOfRange("code"))?)
        .and_then(|v| v.checked_add(7))
        .ok_or(Error::ValueOutOfRange("code"))?;
    let disp = target.wrapping_sub(next);
    code.extend_from_slice(&[0x48, 0x8D, 0x15]);
    push_u32(code, disp);
    Ok(())
}

fn build_x64_code(imports: &Imports, msg_rva: u32, len: u32) -> Result<Vec<u8>> {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0x83, 0xEC, 0x38]);
    code.extend_from_slice(&[0xB9, 0xF5, 0xFF, 0xFF, 0xFF]);
    rip_call(&mut code, first_iat(imports)?)?;
    code.extend_from_slice(&[0x48, 0x89, 0xC1]);
    rip_lea_rdx(&mut code, msg_rva)?;
    code.extend_from_slice(&[0x41, 0xB8]);
    push_u32(&mut code, len);
    code.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x28]);
    code.extend_from_slice(&[0x48, 0xC7, 0x44, 0x24, 0x20, 0, 0, 0, 0]);
    rip_call(&mut code, second_iat(imports)?)?;
    code.extend_from_slice(&[0x31, 0xC9]);
    rip_call(&mut code, third_iat(imports)?)?;
    code.push(0xCC);
    Ok(code)
}

fn first_iat(imports: &Imports) -> Result<u32> {
    imports.iat.first().copied().ok_or(Error::Malformed("IAT"))
}

fn second_iat(imports: &Imports) -> Result<u32> {
    imports.iat.get(1).copied().ok_or(Error::Malformed("IAT"))
}

fn third_iat(imports: &Imports) -> Result<u32> {
    imports.iat.get(2).copied().ok_or(Error::Malformed("IAT"))
}

fn add_common_sections(module: &mut ObjectModule, text: Vec<u8>, imports: Vec<u8>) -> Result<()> {
    let text_size = u64::try_from(text.len()).map_err(|_| Error::ValueOutOfRange("text"))?;
    let idata_size = u64::try_from(imports.len()).map_err(|_| Error::ValueOutOfRange("idata"))?;
    let text_name = module.intern(".text")?;
    let text_id = module.add_section(Section {
        name: text_name,
        kind: SectionKind::Text,
        address: u64::from(TEXT_RVA),
        align: u64::from(SECTION_ALIGNMENT),
        flags: SectionFlags::code(),
        data: text,
        size: text_size,
    })?;
    let sym_name = module.intern("main")?;
    module.add_symbol(SymbolEntry {
        name: sym_name,
        value: u64::from(TEXT_RVA),
        size: 0,
        section: Some(text_id),
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::none(),
    })?;
    let idata_name = module.intern(".idata")?;
    module.add_section(Section {
        name: idata_name,
        kind: SectionKind::Data,
        address: u64::from(IDATA_RVA),
        align: u64::from(SECTION_ALIGNMENT),
        flags: SectionFlags::data(),
        data: imports,
        size: idata_size,
    })?;
    let library = module.intern(DLL_NAME)?;
    for import in IMPORTS {
        let name = module.intern(import)?;
        module.add_import(Import {
            library,
            name,
            ordinal: None,
            hint: Some(0),
        });
    }
    Ok(())
}

/// Builds a runnable `x86_64` Windows console executable.
///
/// # Errors
///
/// Returns an error if any RVA, code length, or model table exceeds representable bounds.
pub fn hello_world_x86_64_windows() -> Result<ObjectModule> {
    let message = HELLO_MESSAGE.as_bytes();
    let len = u32::try_from(message.len()).map_err(|_| Error::ValueOutOfRange("message"))?;
    let imports = build_imports64()?;
    let msg_rva = TEXT_RVA + X64_CODE_LEN;
    let mut code = build_x64_code(&imports, msg_rva, len)?;
    let code_len = u32::try_from(code.len()).map_err(|_| Error::ValueOutOfRange("code"))?;
    debug_assert_eq!(code_len, X64_CODE_LEN, "unexpected x64 sample code length");
    code.extend_from_slice(message);
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86_64());
    add_common_sections(&mut module, code, imports.bytes)?;
    module.set_entry(u64::from(TEXT_RVA));
    Ok(module)
}

/// Builds an `aarch64` Windows console executable fixture with the same imports.
///
/// # Errors
///
/// Returns an error if any RVA, code length, or model table exceeds representable bounds.
pub fn hello_world_aarch64_windows() -> Result<ObjectModule> {
    let imports = build_imports64()?;
    let mut code = Vec::new();
    for instruction in [
        0xA9BB_7BFD_u32,
        0x9100_03FD,
        0xD280_0000,
        0xD63F_0200,
        0xD420_0000,
    ] {
        code.extend_from_slice(&instruction.to_le_bytes());
    }
    code.extend_from_slice(HELLO_MESSAGE.as_bytes());
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::aarch64());
    add_common_sections(&mut module, code, imports.bytes)?;
    module.set_entry(u64::from(TEXT_RVA));
    Ok(module)
}

/// Builds a tiny fixture for one PE machine family.
///
/// # Errors
///
/// Returns an error if the target architecture is unsupported by the PE writer.
pub fn machine_fixture(arch: Architecture) -> Result<ObjectModule> {
    let target = match arch {
        Architecture::X86 => TargetSpec::x86(),
        Architecture::Arm => TargetSpec::arm(),
        Architecture::X86_64 => TargetSpec::x86_64(),
        Architecture::Aarch64 => TargetSpec::aarch64(),
        _ => return Err(Error::Unsupported("PE fixture architecture")),
    };
    let mut module = ObjectModule::new(BinaryFormat::Pe, target);
    let code = alloc::vec![0xC3];
    let name = module.intern(".text")?;
    module.add_section(Section {
        name,
        kind: SectionKind::Text,
        address: u64::from(TEXT_RVA),
        align: u64::from(SECTION_ALIGNMENT),
        flags: SectionFlags::code(),
        size: 1,
        data: code,
    })?;
    module.set_entry(u64::from(TEXT_RVA));
    Ok(module)
}

/// Builds a PE32 fixture that carries a 32-bit import table.
///
/// # Errors
///
/// Returns an error if model table allocation fails.
pub fn pe32_import_fixture() -> Result<ObjectModule> {
    let imports = build_imports32()?;
    let mut module = ObjectModule::new(BinaryFormat::Pe, TargetSpec::x86());
    add_common_sections(&mut module, alloc::vec![0xC3], imports.bytes)?;
    module.set_entry(u64::from(TEXT_RVA));
    Ok(module)
}

/// Builds a fixture carrying export and base-relocation directory bytes.
///
/// # Errors
///
/// Returns an error if model table allocation fails.
pub fn directory_fixture() -> Result<ObjectModule> {
    let mut module = hello_world_x86_64_windows()?;
    let export = build_export_section()?;
    let export_name = module.intern(".edata")?;
    let export_section = Section {
        name: export_name,
        kind: SectionKind::ReadOnlyData,
        address: u64::from(EDATA_RVA),
        align: u64::from(SECTION_ALIGNMENT),
        flags: SectionFlags::read_only(),
        size: u64::try_from(export.len()).map_err(|_| Error::ValueOutOfRange("edata"))?,
        data: export,
    };
    module.add_section(export_section)?;
    let main_export = module.intern("main")?;
    module.add_export(Export {
        name: main_export,
        address: u64::from(TEXT_RVA),
        ordinal: Some(1),
    });
    let reloc = build_reloc_section();
    let reloc_name = module.intern(".reloc")?;
    let reloc_section = Section {
        name: reloc_name,
        kind: SectionKind::Other,
        address: u64::from(RELOC_RVA),
        align: u64::from(SECTION_ALIGNMENT),
        flags: SectionFlags::read_only(),
        size: u64::try_from(reloc.len()).map_err(|_| Error::ValueOutOfRange("reloc"))?,
        data: reloc,
    };
    module.add_section(reloc_section)?;
    Ok(module)
}

fn build_export_section() -> Result<Vec<u8>> {
    let mut w = ByteWriter::new(Endianness::Little);
    let dll_name_rva = EDATA_RVA + 40;
    let function_table_rva = EDATA_RVA + 52;
    let name_pointer_table_rva = EDATA_RVA + 56;
    let ordinal_table_rva = EDATA_RVA + 60;
    let exported_symbol_name_rva = EDATA_RVA + 62;
    w.write_u32(0);
    w.write_u32(0);
    w.write_u16(0);
    w.write_u16(0);
    w.write_u32(dll_name_rva);
    w.write_u32(1);
    w.write_u32(1);
    w.write_u32(1);
    w.write_u32(function_table_rva);
    w.write_u32(name_pointer_table_rva);
    w.write_u32(ordinal_table_rva);
    w.write_bytes(b"stratum.exe\0");
    w.write_u32(TEXT_RVA);
    w.write_u32(exported_symbol_name_rva);
    w.write_u16(0);
    w.write_bytes(b"main\0");
    w.finish()
}

fn build_reloc_section() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TEXT_RVA.to_le_bytes());
    bytes.extend_from_slice(&12u32.to_le_bytes());
    bytes.extend_from_slice(&0xA000u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

/// Preferred image base used by fixtures.
#[must_use]
pub const fn image_base64() -> u64 {
    IMAGE_BASE64
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn aarch64_fixture_and_constants_are_used() {
        let module = hello_world_aarch64_windows().unwrap();
        assert_eq!(module.target().arch, Architecture::Aarch64);
        assert_eq!(module.imports().len(), IMPORTS.len());
        assert_eq!(image_base64(), IMAGE_BASE64);
    }

    #[test]
    fn unsupported_machine_fixture_is_rejected() {
        assert!(machine_fixture(Architecture::Wasm32).is_err());
    }
}
