use std::cmp::Ordering;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use stratum_elf::{
    Elf, ElfDynamicTag, ElfFile, ElfMachine, ElfNoteType, ElfOsAbi, ElfRelocationType,
    ElfSectionFlags, ElfSectionType, ElfSegmentFlags, ElfSegmentType, ElfSymbolBind, ElfSymbolType,
    ElfSymbolVisibility, ElfType, read, samples, write,
};
use stratum_oir::{
    BinaryFormat, ObjectModule, OirBridge, RelocKind, Relocation, Section, SectionFlags, SectionId,
    SectionKind, Symbol, SymbolBinding, SymbolEntry, SymbolFlags, SymbolKind, TargetSpec,
};

pub fn exercise_public_api_surface() {
    raw_wrappers_round_trip();
    native_and_bridge_round_trip();
    public_error_paths();
}

fn raw_wrappers_round_trip() {
    macro_rules! assert_enum {
        ($ty:ty, default $default:expr, values [$($value:expr),+ $(,)?]) => {{
            assert_eq!(<$ty>::default().raw(), $default);
            $(
                let wrapped = <$ty>::from($value);
                assert_eq!(wrapped.raw(), $value);
                assert_eq!(<$ty>::from(wrapped.raw()).raw(), $value);
                assert_eq!(wrapped, <$ty>::from($value));
                assert_eq!(wrapped.partial_cmp(&<$ty>::from($value)), Some(Ordering::Equal));
                assert_eq!(wrapped.cmp(&<$ty>::from($value)), Ordering::Equal);
                assert_eq!(hash_value(wrapped), hash_value(<$ty>::from($value)));
            )+
        }};
    }

    assert_enum!(ElfType, default 0, values [0_u16, 1, 2, 3, 4, 0xfeff]);
    assert_enum!(
        ElfMachine,
        default 0,
        values [0_u16, 3, 8, 20, 21, 40, 62, 183, 243, 258, 390, 999]
    );
    assert_enum!(
        ElfOsAbi,
        default 0,
        values [0_u8, 1, 2, 3, 6, 7, 8, 9, 12, 64, 255]
    );
    assert_enum!(ElfSegmentType, default 0, values [0_u32, 1, 2, 4, 0x7000_0000]);
    assert_enum!(ElfSegmentFlags, default 0, values [0_u32, 7]);
    assert_enum!(
        ElfSectionType,
        default 0,
        values [0_u32, 1, 2, 3, 4, 6, 7, 8, 9, 11, 0x7000_0000]
    );
    assert_enum!(ElfSectionFlags, default 0, values [0_u64, 6]);
    assert_enum!(ElfSymbolBind, default 0, values [0_u8, 1, 2, 13]);
    assert_enum!(ElfSymbolType, default 0, values [0_u8, 1, 2, 3, 4, 5, 6, 15]);
    assert_enum!(ElfSymbolVisibility, default 0, values [0_u8, 1, 2, 3, 7]);
    assert_enum!(ElfRelocationType, default 0, values [0_u32, 42]);
    assert_enum!(
        ElfDynamicTag,
        default 0,
        values [
            0_i64, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28, 29, 30, -1
        ]
    );
    assert_enum!(ElfNoteType, default 0, values [0_u32, 1]);
    assert!(ElfType::from(1) < ElfType::from(2));
}

fn hash_value<T: Hash>(value: T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn native_and_bridge_round_trip() {
    let bridge = Elf;

    for module in [
        samples::hello_world_x86_64_linux().unwrap(),
        samples::hello_world_aarch64_linux().unwrap(),
        automatic_program_header_module(TargetSpec::x86_64(), 0x40_1000).unwrap(),
        automatic_program_header_module(TargetSpec::x86(), 0x1000).unwrap(),
    ] {
        let bytes = bridge.write(&module).unwrap();
        let native = ElfFile::parse(&bytes).unwrap();
        assert_eq!(native.to_bytes().unwrap(), bytes);
        let projected = native.to_oir().unwrap();
        assert_eq!(projected.format(), BinaryFormat::Elf);
        assert_eq!(read(&bytes).unwrap().target(), module.target());
        assert_eq!(
            ElfFile::from_oir(&module).unwrap().to_bytes().unwrap(),
            bytes
        );
    }

    let samples = samples::structural_samples().unwrap();
    assert_eq!(samples.len(), 16);
    for (_, module) in samples {
        let bytes = write(&module).unwrap();
        let native = ElfFile::parse(&bytes).unwrap();
        assert!(!native.section_headers.is_empty());
        assert!(native.symbols.len() >= 3);
        assert_eq!(native.relocations.len(), 1);
        let projected = bridge.read(&bytes).unwrap();
        assert_eq!(projected.target(), module.target());
        assert_eq!(write(&projected).unwrap(), bytes);
    }
}

#[test]
fn public_error_paths() {
    let base = write(&samples::hello_world_x86_64_linux().unwrap()).unwrap();
    assert!(read(&[]).is_err());
    assert!(read(base.get(..8).unwrap()).is_err());
    assert_all_truncated_prefixes_fail(&base);

    let mut bad_magic = base.clone();
    *bad_magic.get_mut(0).unwrap() = 0;
    assert!(read(&bad_magic).is_err());

    let mut bad_class = base.clone();
    *bad_class.get_mut(4).unwrap() = 9;
    assert!(read(&bad_class).is_err());

    let mut bad_data = base.clone();
    *bad_data.get_mut(5).unwrap() = 9;
    assert!(read(&bad_data).is_err());

    let mut bad_ident_version = base.clone();
    *bad_ident_version.get_mut(6).unwrap() = 0;
    assert!(read(&bad_ident_version).is_err());

    let mut bad_header_version = base.clone();
    patch(&mut bad_header_version, 20, &0_u32.to_le_bytes()).unwrap();
    assert!(read(&bad_header_version).is_err());

    let mut small_header = base.clone();
    patch(&mut small_header, 52, &1_u16.to_le_bytes()).unwrap();
    assert!(read(&small_header).is_err());

    let mut small_program_header = base.clone();
    patch(&mut small_program_header, 54, &1_u16.to_le_bytes()).unwrap();
    assert!(read(&small_program_header).is_err());

    let mut small_section_header = base.clone();
    patch(&mut small_section_header, 58, &1_u16.to_le_bytes()).unwrap();
    assert!(read(&small_section_header).is_err());

    let mut bad_section_names = base.clone();
    patch(&mut bad_section_names, 62, &u16::MAX.to_le_bytes()).unwrap();
    assert!(read(&bad_section_names).is_err());

    let mut bad_program_offset = base.clone();
    patch(&mut bad_program_offset, 32, &u64::MAX.to_le_bytes()).unwrap();
    assert!(read(&bad_program_offset).is_err());

    let mut bad_section_offset = base.clone();
    patch(&mut bad_section_offset, 40, &u64::MAX.to_le_bytes()).unwrap();
    assert!(read(&bad_section_offset).is_err());

    let mut unsupported = ObjectModule::new(BinaryFormat::Elf, TargetSpec::wasm32());
    assert!(write(&unsupported).is_err());
    unsupported.set_entry(u64::from(u32::MAX) + 1);

    let mut invalid_section_name = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
    invalid_section_name
        .add_section(Section {
            name: Symbol::default(),
            kind: SectionKind::Other,
            address: 0,
            align: 1,
            flags: SectionFlags {
                read: false,
                write: false,
                execute: false,
            },
            data: Vec::new(),
            size: 0,
        })
        .unwrap();
    assert!(write(&invalid_section_name).is_err());

    assert!(write(&incongruent_allocated_module().unwrap()).is_err());
    assert!(write(&oversized_32_bit_module().unwrap()).is_err());
    assert!(write(&bad_relocation_section_module().unwrap()).is_err());

    let samples = samples::structural_samples().unwrap();
    for (name, module) in samples {
        if matches!(name.as_str(), "x86_64" | "aarch64_be" | "i386" | "powerpc") {
            let bytes = write(&module).unwrap();
            assert_all_truncated_prefixes_fail(&bytes);
        }
    }
}

fn automatic_program_header_module(
    target: TargetSpec,
    base: u64,
) -> stratum_oir::Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Elf, target);
    module.set_entry(base);
    let text_name = module.intern(".text")?;
    let text = module.add_section(Section {
        name: text_name,
        kind: SectionKind::Text,
        address: base,
        align: 0x1000,
        flags: SectionFlags::code(),
        data: vec![0x90, 0xc3],
        size: 2,
    })?;
    let bss_name = module.intern(".bss")?;
    module.add_section(Section {
        name: bss_name,
        kind: SectionKind::Bss,
        address: base + 0x1000,
        align: 0x1000,
        flags: SectionFlags::data(),
        data: Vec::new(),
        size: 8,
    })?;
    let start_name = module.intern("_start")?;
    module.add_symbol(SymbolEntry {
        name: start_name,
        value: base,
        size: 2,
        section: Some(text),
        kind: SymbolKind::Function,
        binding: SymbolBinding::Global,
        flags: SymbolFlags::exported(),
    })?;
    Ok(module)
}

fn incongruent_allocated_module() -> stratum_oir::Result<ObjectModule> {
    let mut module = ObjectModule::new(BinaryFormat::Elf, TargetSpec::x86_64());
    let name = module.intern(".text")?;
    module.add_section(Section {
        name,
        kind: SectionKind::Text,
        address: 0x40_1001,
        align: 0x1000,
        flags: SectionFlags::code(),
        data: vec![0xc3],
        size: 1,
    })?;
    Ok(module)
}

fn oversized_32_bit_module() -> stratum_oir::Result<ObjectModule> {
    let mut module = automatic_program_header_module(TargetSpec::x86(), 0x1000)?;
    module.set_entry(u64::from(u32::MAX) + 1);
    Ok(module)
}

fn bad_relocation_section_module() -> stratum_oir::Result<ObjectModule> {
    let mut module = automatic_program_header_module(TargetSpec::x86_64(), 0x40_1000)?;
    let symbol = module
        .symbols()
        .next()
        .map(|(id, _)| id)
        .ok_or(stratum_oir::Error::Malformed("missing symbol"))?;
    module.add_relocation(Relocation {
        section: SectionId::from_raw(99),
        offset: 0,
        symbol,
        kind: RelocKind::Absolute64,
        addend: 0,
    })?;
    Ok(module)
}

fn patch(bytes: &mut [u8], offset: usize, replacement: &[u8]) -> Option<()> {
    let end = offset.checked_add(replacement.len())?;
    bytes
        .get_mut(offset..end)
        .map(|slot| slot.copy_from_slice(replacement))
}

fn assert_all_truncated_prefixes_fail(bytes: &[u8]) {
    for len in 0..bytes.len() {
        if let Some(prefix) = bytes.get(..len) {
            assert!(read(prefix).is_err(), "prefix length {len}");
        }
    }
}
