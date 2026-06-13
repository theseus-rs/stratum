//! Round-trip fidelity tests for the WebAssembly codec.

use stratum_oir::{
    BinaryFormat, ObjectModule, OirBridge, Section, SectionFlags, SectionKind, TargetSpec,
};
use stratum_wasm::{Wasm, read, samples, write};

fn self_emitted_samples() -> stratum_oir::Result<[ObjectModule; 2]> {
    Ok([
        samples::hello_world_wasm32_wasi()?,
        samples::full_featured_module()?,
    ])
}

fn add_section(
    module: &mut ObjectModule,
    name: &str,
    kind: SectionKind,
    data: Vec<u8>,
) -> stratum_oir::Result<()> {
    let name = module.intern(name)?;
    let flags = match kind {
        SectionKind::Text => SectionFlags::code(),
        SectionKind::Data => SectionFlags::data(),
        _ => SectionFlags::read_only(),
    };
    let section = Section {
        name,
        kind,
        address: 0,
        align: 1,
        flags,
        size: u64::try_from(data.len())
            .map_err(|_| stratum_oir::Error::ValueOutOfRange("section size"))?,
        data,
    };
    module.add_section(section).map(|_| ())
}

#[test]
fn write_read_write_is_byte_idempotent_for_all_samples() {
    for module in self_emitted_samples().unwrap() {
        let first = write(&module).unwrap();
        let reparsed = read(&first).unwrap();
        let second = write(&reparsed).unwrap();
        assert_eq!(first, second, "round-tripped bytes must be identical");
    }
}

#[test]
fn semantic_dump_survives_round_trip_for_all_samples() {
    for module in self_emitted_samples().unwrap() {
        let bytes = Wasm.write(&module).unwrap();
        let reparsed = Wasm.read(&bytes).unwrap();
        assert_eq!(module.dump(), reparsed.dump());
    }
}

#[test]
fn legacy_kind_based_writer_round_trips() {
    let mut module = ObjectModule::new(BinaryFormat::Wasm, TargetSpec::wasm32());
    add_section(&mut module, ".text", SectionKind::Text, std::vec![0, 0x0B]).unwrap();
    add_section(&mut module, ".data", SectionKind::Data, std::vec![1, 2, 3]).unwrap();
    let bytes = write(&module).unwrap();
    assert!(read(&bytes).is_ok());
}

#[test]
fn rejects_truncated_header() {
    let module = samples::hello_world_wasm32_wasi().unwrap();
    let bytes = write(&module).unwrap();
    let head = bytes.get(..4).unwrap();
    assert!(read(head).is_err());
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = write(&samples::hello_world_wasm32_wasi().unwrap()).unwrap();
    *bytes.first_mut().unwrap() = 0xFF;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_bad_version() {
    let mut bytes = write(&samples::hello_world_wasm32_wasi().unwrap()).unwrap();
    let version = bytes.get_mut(4).unwrap();
    *version = 0x02;
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_empty_input() {
    assert!(read(&[]).is_err());
}

#[test]
fn rejects_truncated_body() {
    let bytes = write(&samples::hello_world_wasm32_wasi().unwrap()).unwrap();
    let half = bytes.len() / 2;
    let partial = bytes.get(..half).unwrap();
    assert!(read(partial).is_err());
}

#[test]
fn rejects_truncated_leb128_section_size() {
    let mut bytes = std::vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    bytes.push(1);
    bytes.push(0x80);
    assert!(read(&bytes).is_err());
}

#[test]
fn rejects_bad_section_id() {
    let mut bytes = std::vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
    bytes.push(13);
    bytes.push(0);
    assert!(read(&bytes).is_err());
}
