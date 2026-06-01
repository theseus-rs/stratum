//! PDB stream encoder/decoder.

use crate::consts::{
    FEATURE_MINIMAL_DEBUG_INFO, FEATURE_VC140, STRATUM_DBI_MAGIC, STRATUM_MODULE_MAGIC,
    STRATUM_SYMBOL_MAGIC, STREAM_DBI, STREAM_IPI, STREAM_PDB, STREAM_TPI, TPI_VERSION_80,
    TYPE_INDEX_BEGIN,
};
use crate::model::{
    NamedStream, PdbFieldRecord, PdbFile, PdbInfo, PdbLineRecord, PdbModule, PdbRawStream,
    PdbScopeRecord, PdbSourceRecord, PdbSymbolKind, PdbSymbolRecord, PdbTypeKind, PdbTypeRecord,
    PdbVariableRecord,
};
use crate::msf::MsfFile;
use stratum_oir::{ByteReader, ByteWriter, Endianness, Error, Result};

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

const GLOBAL_STREAM_NAME: &str = "/globals";
const NAMES_STREAM_NAME: &str = "/names";
const PUBLIC_STREAM_NAME: &str = "/publics";
const STRATUM_DBI_STREAM_NAME: &str = "/stratum/dbi";
const DBI_VERSION_V70: u32 = 19_990_903;

fn writer() -> ByteWriter {
    ByteWriter::new(Endianness::Little)
}

fn u32_len(value: usize, what: &'static str) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

#[cfg(any(target_pointer_width = "32", target_pointer_width = "64"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "helper keeps a fallible signature across target widths"
)]
fn usize_from_u32(value: u32, _what: &'static str) -> Result<usize> {
    Ok(value as usize)
}

#[cfg(target_pointer_width = "16")]
fn usize_from_u32(value: u32, what: &'static str) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::ValueOutOfRange(what))
}

fn get_stream(streams: &[Vec<u8>], index: u32) -> Result<&[u8]> {
    streams
        .get(usize_from_u32(index, "PDB stream index")?)
        .map(Vec::as_slice)
        .ok_or(Error::Malformed("missing PDB stream"))
}

fn maybe_stream(streams: &[Vec<u8>], index: u32) -> Option<&[u8]> {
    streams.get(usize::try_from(index).ok()?).map(Vec::as_slice)
}

fn write_len_string(w: &mut ByteWriter, text: &str) -> Result<()> {
    w.write_u32(u32_len(text.len(), "string length")?);
    w.write_bytes(text.as_bytes());
    Ok(())
}

fn read_len_string(r: &mut ByteReader<'_>) -> Result<String> {
    let len = usize_from_u32(r.read_u32()?, "string length")?;
    let bytes = r.read_bytes(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::Malformed("utf8 string"))
}

fn read_c_string(bytes: &[u8], offset: u32) -> Result<String> {
    let start = usize_from_u32(offset, "string offset")?;
    let tail = bytes.get(start..).ok_or(Error::UnexpectedEof {
        offset: start,
        needed: 1,
        len: bytes.len(),
    })?;
    let len = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Error::Malformed("unterminated string"))?;
    let raw = tail.get(0..len).ok_or(Error::Malformed("string slice"))?;
    String::from_utf8(raw.to_vec()).map_err(|_| Error::Malformed("utf8 string"))
}

/// Reads native PDB/MSF bytes into a [`PdbFile`].
///
/// # Errors
///
/// Returns an error if the MSF container or one of the required modern PDB streams is malformed.
pub fn read(bytes: &[u8]) -> Result<PdbFile> {
    let msf = MsfFile::read(bytes)?;
    let info = read_pdb_stream(get_stream(&msf.streams, STREAM_PDB)?)?;
    if info.features.contains(&FEATURE_MINIMAL_DEBUG_INFO) {
        return Err(Error::Unsupported("PDB minimal debug info"));
    }
    let types = read_type_stream(get_stream(&msf.streams, STREAM_TPI)?)?;
    let ids = read_type_stream(get_stream(&msf.streams, STREAM_IPI)?)?;
    let (modules, global_index, public_index) =
        read_dbi_stream(get_stream(&msf.streams, STREAM_DBI)?, &msf.streams, &info)?;
    let globals = maybe_stream(&msf.streams, global_index)
        .map(read_symbol_stream)
        .transpose()?
        .unwrap_or_default();
    let publics = maybe_stream(&msf.streams, public_index)
        .map(read_symbol_stream)
        .transpose()?
        .unwrap_or_default();
    let raw_streams = raw_streams(&msf.streams, &info, &modules);
    Ok(PdbFile {
        info,
        types,
        ids,
        modules,
        globals,
        publics,
        raw_streams,
    })
}

/// Writes a [`PdbFile`] into deterministic MSF/PDB bytes.
///
/// # Errors
///
/// Returns an error if any stream exceeds PDB/MSF field widths.
pub fn write(file: &PdbFile) -> Result<Vec<u8>> {
    let mut streams = alloc::vec![Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()];
    let reserved = reserved_raw_streams(file);
    let names_bytes = build_names_stream(file)?;
    let names_stream = add_stream(&mut streams, &reserved, names_bytes, "names stream index")?;
    let globals_bytes = build_symbol_stream(&file.globals)?;
    let globals_stream = add_stream(&mut streams, &reserved, globals_bytes, "globals")?;
    let publics_bytes = build_symbol_stream(&file.publics)?;
    let publics_stream = add_stream(&mut streams, &reserved, publics_bytes, "publics")?;

    let mut modules = file.modules.clone();
    let mut generated_streams = alloc::vec![names_stream, globals_stream, publics_stream];
    for module in &mut modules {
        let module_bytes = build_module_stream(module)?;
        module.stream = add_stream(&mut streams, &reserved, module_bytes, "module stream index")?;
        generated_streams.push(module.stream);
    }
    let dbi_bytes = build_stratum_dbi_stream(&modules, globals_stream, publics_stream)?;
    let dbi_stream = add_stream(&mut streams, &reserved, dbi_bytes, "DBI")?;
    generated_streams.push(dbi_stream);

    let mut info = file.info.clone();
    info.named_streams = canonical_named_streams(
        &info.named_streams,
        names_stream,
        globals_stream,
        publics_stream,
        dbi_stream,
    );
    if !info.features.contains(&FEATURE_VC140) {
        info.features.push(FEATURE_VC140);
    }
    set_stream(&mut streams, STREAM_PDB, build_pdb_stream(&info)?)?;
    set_stream(&mut streams, STREAM_TPI, build_type_stream(&file.types)?)?;
    let dbi_stream = build_dbi_stream(globals_stream, publics_stream)?;
    set_stream(&mut streams, STREAM_DBI, dbi_stream)?;
    set_stream(&mut streams, STREAM_IPI, build_type_stream(&file.ids)?)?;

    for raw in &file.raw_streams {
        if is_fixed_stream(raw.index) || generated_streams.contains(&raw.index) {
            continue;
        }
        ensure_stream_len(&mut streams, raw.index)?;
        set_stream(&mut streams, raw.index, raw.data.clone())?;
    }
    MsfFile::write(&streams)
}

fn reserved_raw_streams(file: &PdbFile) -> Vec<u32> {
    file.raw_streams
        .iter()
        .filter_map(|raw| (!is_fixed_stream(raw.index)).then_some(raw.index))
        .collect()
}

fn add_stream(
    streams: &mut Vec<Vec<u8>>,
    reserved: &[u32],
    bytes: Vec<u8>,
    what: &'static str,
) -> Result<u32> {
    allocate_generated_stream(streams, reserved, bytes, what)
}

fn allocate_generated_stream(
    streams: &mut Vec<Vec<u8>>,
    reserved: &[u32],
    bytes: Vec<u8>,
    what: &'static str,
) -> Result<u32> {
    let mut index = u32_len(streams.len(), what)?;
    while reserved.contains(&index) {
        ensure_stream_len(streams, index)?;
        index = index.checked_add(1).ok_or(Error::ValueOutOfRange(what))?;
    }
    set_stream(streams, index, bytes)?;
    Ok(index)
}

fn set_stream(streams: &mut Vec<Vec<u8>>, index: u32, bytes: Vec<u8>) -> Result<()> {
    ensure_stream_len(streams, index)?;
    let slot = streams
        .get_mut(usize_from_u32(index, "stream index")?)
        .ok_or(Error::Malformed("missing stream slot"))?;
    *slot = bytes;
    Ok(())
}

fn ensure_stream_len(streams: &mut Vec<Vec<u8>>, index: u32) -> Result<()> {
    let len = usize_from_u32(index, "stream index")?
        .checked_add(1)
        .ok_or(Error::ValueOutOfRange("stream index"))?;
    if streams.len() < len {
        streams.resize_with(len, Vec::new);
    }
    Ok(())
}

fn is_fixed_stream(index: u32) -> bool {
    matches!(index, 0 | STREAM_PDB | STREAM_TPI | STREAM_DBI | STREAM_IPI)
}

fn canonical_named_streams(
    existing: &[NamedStream],
    names: u32,
    globals: u32,
    publics: u32,
    stratum_dbi: u32,
) -> Vec<NamedStream> {
    let mut out = Vec::new();
    push_named(&mut out, NAMES_STREAM_NAME, names);
    push_named(&mut out, GLOBAL_STREAM_NAME, globals);
    push_named(&mut out, PUBLIC_STREAM_NAME, publics);
    push_named(&mut out, STRATUM_DBI_STREAM_NAME, stratum_dbi);
    for stream in existing {
        if out
            .iter()
            .all(|item: &NamedStream| item.name != stream.name)
        {
            out.push(stream.clone());
        }
    }
    out
}

fn push_named(out: &mut Vec<NamedStream>, name: &str, stream: u32) {
    out.push(NamedStream {
        name: name.to_string(),
        stream,
    });
}

fn build_pdb_stream(info: &PdbInfo) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_u32(info.version);
    w.write_u32(info.signature);
    w.write_u32(info.age);
    w.write_bytes(&info.guid);
    write_named_stream_map(&mut w, &info.named_streams)?;
    write_len_string(&mut w, &info.path)?;
    w.write_u32(u32_len(info.features.len(), "PDB feature count")?);
    for feature in &info.features {
        w.write_u32(*feature);
    }
    w.finish()
}

fn read_pdb_stream(bytes: &[u8]) -> Result<PdbInfo> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    let version = r.read_u32()?;
    let signature = r.read_u32()?;
    let age = r.read_u32()?;
    let mut guid = [0u8; 16];
    guid.copy_from_slice(r.read_bytes(16)?);
    let string_len = usize_from_u32(r.read_u32()?, "named stream strings")?;
    let strings = r.read_bytes(string_len)?.to_vec();
    let named_streams = read_serialized_hash_table(&mut r, &strings)?;
    let path = if r.is_empty() {
        "stratum.pdb".to_string()
    } else {
        read_len_string(&mut r)?
    };
    let feature_count = if r.is_empty() {
        0
    } else {
        usize_from_u32(r.read_u32()?, "PDB feature count")?
    };
    let mut features = Vec::new();
    for _ in 0..feature_count {
        features.push(r.read_u32()?);
    }
    while !r.is_empty() {
        features.push(r.read_u32()?);
    }
    Ok(PdbInfo {
        version,
        signature,
        age,
        guid,
        named_streams,
        features,
        path,
    })
}

fn write_named_stream_map(w: &mut ByteWriter, streams: &[NamedStream]) -> Result<()> {
    let mut strings = writer();
    let mut offsets = Vec::with_capacity(streams.len());
    for stream in streams {
        offsets.push(u32_len(strings.position(), "named stream string offset")?);
        strings.write_bytes(stream.name.as_bytes());
        strings.write_u8(0);
    }
    let strings = strings.finish()?;
    w.write_u32(u32_len(strings.len(), "named stream strings")?);
    w.write_bytes(&strings);
    write_serialized_hash_table(w, streams, &offsets)
}

fn write_serialized_hash_table(
    w: &mut ByteWriter,
    streams: &[NamedStream],
    offsets: &[u32],
) -> Result<()> {
    let capacity = streams.len().saturating_mul(2).saturating_add(1).max(1);
    let words = capacity.div_ceil(32);
    w.write_u32(u32_len(streams.len(), "hash size")?);
    w.write_u32(u32_len(capacity, "hash capacity")?);
    write_bit_vector(w, words, streams.len())?;
    write_bit_vector(w, words, 0)?;
    for bucket in 0..capacity {
        if let Some(stream) = streams.get(bucket) {
            w.write_u32(*offsets.get(bucket).ok_or(Error::Malformed("hash offset"))?);
            w.write_u32(stream.stream);
        } else {
            w.write_u32(0);
            w.write_u32(0);
        }
    }
    Ok(())
}

fn write_bit_vector(w: &mut ByteWriter, words: usize, set_bits: usize) -> Result<()> {
    w.write_u32(u32_len(words, "bit vector words")?);
    for word_index in 0..words {
        let mut word = 0u32;
        for bit in 0..32usize {
            let index = word_index
                .checked_mul(32)
                .and_then(|value| value.checked_add(bit))
                .ok_or(Error::ValueOutOfRange("bit vector"))?;
            if index < set_bits {
                word |= 1u32 << bit;
            }
        }
        w.write_u32(word);
    }
    Ok(())
}

fn read_serialized_hash_table(r: &mut ByteReader<'_>, strings: &[u8]) -> Result<Vec<NamedStream>> {
    let _size = r.read_u32()?;
    let capacity = usize_from_u32(r.read_u32()?, "hash capacity")?;
    let present = read_bit_vector(r)?;
    let deleted = read_bit_vector(r)?;
    let mut out = Vec::new();
    for bucket in 0..capacity {
        let key = r.read_u32()?;
        let value = r.read_u32()?;
        if bit_is_set(&present, bucket) && !bit_is_set(&deleted, bucket) {
            out.push(NamedStream {
                name: read_c_string(strings, key)?,
                stream: value,
            });
        }
    }
    Ok(out)
}

fn read_bit_vector(r: &mut ByteReader<'_>) -> Result<Vec<u32>> {
    let words = usize_from_u32(r.read_u32()?, "bit vector words")?;
    let mut out = Vec::with_capacity(words);
    for _ in 0..words {
        out.push(r.read_u32()?);
    }
    Ok(out)
}

fn bit_is_set(words: &[u32], bit: usize) -> bool {
    let Some(word) = words.get(bit / 32) else {
        return false;
    };
    word & (1u32 << (bit % 32)) != 0
}

fn build_names_stream(file: &PdbFile) -> Result<Vec<u8>> {
    let mut names = Vec::new();
    for module in &file.modules {
        push_unique_string(&mut names, &module.name);
        push_unique_string(&mut names, &module.object);
        for source in &module.sources {
            push_unique_string(&mut names, &source.path);
        }
    }
    for symbol in file.globals.iter().chain(&file.publics) {
        push_unique_string(&mut names, &symbol.name);
    }
    let mut w = writer();
    w.write_u32(u32_len(names.len(), "names count")?);
    for name in names {
        write_len_string(&mut w, &name)?;
    }
    w.finish()
}

fn push_unique_string(out: &mut Vec<String>, value: &str) {
    if out.iter().all(|existing| existing != value) {
        out.push(value.to_string());
    }
}

fn build_type_stream(records: &[PdbTypeRecord]) -> Result<Vec<u8>> {
    let mut body = writer();
    for record in records {
        let mut payload = writer();
        payload.write_u32(kind_to_raw(record.kind));
        payload.write_u64(record.size);
        payload.write_u32(u32_len(record.references.len(), "type references")?);
        for reference in &record.references {
            payload.write_u32(*reference);
        }
        write_len_string(&mut payload, &record.name)?;
        payload.write_u32(u32_len(record.fields.len(), "type fields")?);
        for field in &record.fields {
            payload.write_u32(field.type_index);
            payload.write_u64(field.offset);
            write_len_string(&mut payload, &field.name)?;
        }
        payload.write_u32(u32_len(record.raw.len(), "type raw")?);
        payload.write_bytes(&record.raw);
        let payload = payload.finish()?;
        let record_len = payload
            .len()
            .checked_add(2)
            .ok_or(Error::ValueOutOfRange("type record length"))?;
        body.write_u16(
            u16::try_from(record_len).map_err(|_| Error::ValueOutOfRange("type record length"))?,
        );
        body.write_u16(record.raw_kind);
        body.write_bytes(&payload);
    }
    let body = body.finish()?;
    let mut w = writer();
    w.write_u32(TPI_VERSION_80);
    w.write_u32(56);
    w.write_u32(TYPE_INDEX_BEGIN);
    w.write_u32(TYPE_INDEX_BEGIN.saturating_add(u32_len(records.len(), "type count")?));
    w.write_u32(u32_len(body.len(), "type bytes")?);
    w.write_u16(u16::MAX);
    w.write_u16(u16::MAX);
    w.write_u32(4);
    w.write_u32(0x40000);
    for _ in 0..6 {
        w.write_u32(0);
    }
    w.write_bytes(&body);
    w.finish()
}

fn read_type_stream(bytes: &[u8]) -> Result<Vec<PdbTypeRecord>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let mut r = ByteReader::new(bytes, Endianness::Little);
    let _version = r.read_u32()?;
    let header_size = usize_from_u32(r.read_u32()?, "TPI header")?;
    let begin = r.read_u32()?;
    let _end = r.read_u32()?;
    let bytes_len = usize_from_u32(r.read_u32()?, "TPI record bytes")?;
    r.seek(header_size)?;
    let record_bytes = r.read_bytes(bytes_len)?;
    let mut records = Vec::new();
    let mut body = ByteReader::new(record_bytes, Endianness::Little);
    let mut index = begin;
    while !body.is_empty() {
        let len = usize::from(body.read_u16()?);
        if len < 2 {
            return Err(Error::Malformed("type record length"));
        }
        let raw_kind = body.read_u16()?;
        let payload = body.read_bytes(len - 2)?.to_vec();
        records.push(decode_type_record(index, raw_kind, &payload)?);
        index = index.saturating_add(1);
    }
    Ok(records)
}

fn decode_type_record(index: u32, raw_kind: u16, payload: &[u8]) -> Result<PdbTypeRecord> {
    let mut r = ByteReader::new(payload, Endianness::Little);
    if r.remaining() < 20 {
        return Ok(PdbTypeRecord {
            index,
            raw_kind,
            kind: PdbTypeKind::Other(u32::from(raw_kind)),
            name: String::new(),
            size: 0,
            references: Vec::new(),
            fields: Vec::new(),
            raw: payload.to_vec(),
        });
    }
    let kind = raw_to_kind(r.read_u32()?);
    let size = r.read_u64()?;
    let ref_count = usize_from_u32(r.read_u32()?, "type reference count")?;
    let mut references = Vec::with_capacity(ref_count);
    for _ in 0..ref_count {
        references.push(r.read_u32()?);
    }
    let name = read_len_string(&mut r)?;
    let field_count = usize_from_u32(r.read_u32()?, "type field count")?;
    let mut fields = Vec::with_capacity(field_count);
    for _ in 0..field_count {
        fields.push(PdbFieldRecord {
            type_index: r.read_u32()?,
            offset: r.read_u64()?,
            name: read_len_string(&mut r)?,
        });
    }
    let raw_len = usize_from_u32(r.read_u32()?, "type raw length")?;
    let raw = r.read_bytes(raw_len)?.to_vec();
    Ok(PdbTypeRecord {
        index,
        raw_kind,
        kind,
        name,
        size,
        references,
        fields,
        raw,
    })
}

fn raw_to_kind(raw: u32) -> PdbTypeKind {
    match raw {
        0 => PdbTypeKind::Primitive,
        1 => PdbTypeKind::Pointer,
        2 => PdbTypeKind::Function,
        3 => PdbTypeKind::Aggregate,
        4 => PdbTypeKind::Enum,
        5 => PdbTypeKind::Array,
        6 => PdbTypeKind::Alias,
        other => PdbTypeKind::Other(other),
    }
}

fn kind_to_raw(kind: PdbTypeKind) -> u32 {
    match kind {
        PdbTypeKind::Primitive => 0,
        PdbTypeKind::Pointer => 1,
        PdbTypeKind::Function => 2,
        PdbTypeKind::Aggregate => 3,
        PdbTypeKind::Enum => 4,
        PdbTypeKind::Array => 5,
        PdbTypeKind::Alias => 6,
        PdbTypeKind::Other(raw) => raw,
    }
}

fn build_dbi_stream(globals: u32, publics: u32) -> Result<Vec<u8>> {
    let globals = u16::try_from(globals).map_err(|_| Error::ValueOutOfRange("global stream"))?;
    let publics = u16::try_from(publics).map_err(|_| Error::ValueOutOfRange("public stream"))?;
    let mut w = writer();
    w.write_u32(u32::MAX);
    w.write_u32(DBI_VERSION_V70);
    w.write_u32(1);
    w.write_u16(globals);
    w.write_u16(0);
    w.write_u16(publics);
    w.write_u16(0);
    w.write_u16(u16::MAX);
    w.write_u16(0);
    for _ in 0..8 {
        w.write_u32(0);
    }
    w.write_u16(0);
    w.write_u16(0x8664);
    w.write_u32(0);
    w.finish()
}

fn build_stratum_dbi_stream(modules: &[PdbModule], globals: u32, publics: u32) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_bytes(STRATUM_DBI_MAGIC);
    w.write_u32(globals);
    w.write_u32(publics);
    w.write_u32(u32_len(modules.len(), "module count")?);
    for module in modules {
        w.write_u32(module.stream);
        write_len_string(&mut w, &module.name)?;
        write_len_string(&mut w, &module.object)?;
        w.write_u32(u32_len(module.sources.len(), "source count")?);
        for source in &module.sources {
            w.write_u32(source.file);
            w.write_u8(source.checksum_kind);
            w.write_u32(u32_len(source.checksum.len(), "source checksum")?);
            w.write_bytes(&source.checksum);
            write_len_string(&mut w, &source.path)?;
        }
    }
    w.finish()
}

fn read_dbi_stream(
    bytes: &[u8],
    streams: &[Vec<u8>],
    info: &PdbInfo,
) -> Result<(Vec<PdbModule>, u32, u32)> {
    if bytes.starts_with(STRATUM_DBI_MAGIC) {
        return read_stratum_dbi_stream(bytes, streams);
    }
    let (globals, publics) = read_native_dbi_header(bytes)?;
    let modules = info
        .named_streams
        .iter()
        .find(|entry| entry.name == STRATUM_DBI_STREAM_NAME)
        .and_then(|entry| maybe_stream(streams, entry.stream))
        .filter(|stream| stream.starts_with(STRATUM_DBI_MAGIC))
        .map(|stream| read_stratum_dbi_stream(stream, streams).map(|(modules, _, _)| modules))
        .transpose()?
        .unwrap_or_default();
    Ok((modules, globals, publics))
}

fn read_native_dbi_header(bytes: &[u8]) -> Result<(u32, u32)> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    let signature = r.read_u32()?;
    if signature != u32::MAX {
        return Err(Error::Unsupported("PDB DBI stream"));
    }
    let _version = r.read_u32()?;
    let _age = r.read_u32()?;
    let globals = u32::from(r.read_u16()?);
    r.skip(2)?;
    let publics = u32::from(r.read_u16()?);
    Ok((globals, publics))
}

fn read_stratum_dbi_stream(
    bytes: &[u8],
    streams: &[Vec<u8>],
) -> Result<(Vec<PdbModule>, u32, u32)> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    if r.read_bytes(4)? != STRATUM_DBI_MAGIC {
        return Err(Error::Unsupported("non-Stratum DBI stream"));
    }
    let globals = r.read_u32()?;
    let publics = r.read_u32()?;
    let count = usize_from_u32(r.read_u32()?, "module count")?;
    let mut modules = Vec::with_capacity(count);
    for _ in 0..count {
        let stream = r.read_u32()?;
        let name = read_len_string(&mut r)?;
        let object = read_len_string(&mut r)?;
        let source_count = usize_from_u32(r.read_u32()?, "source count")?;
        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            let file = r.read_u32()?;
            let checksum_kind = r.read_u8()?;
            let checksum_len = usize_from_u32(r.read_u32()?, "source checksum")?;
            let checksum = r.read_bytes(checksum_len)?.to_vec();
            let path = read_len_string(&mut r)?;
            sources.push(PdbSourceRecord {
                file,
                path,
                checksum_kind,
                checksum,
            });
        }
        let (lines, symbols, scopes) = read_module_stream(get_stream(streams, stream)?)?;
        modules.push(PdbModule {
            name,
            object,
            sources,
            lines,
            symbols,
            scopes,
            stream,
        });
    }
    Ok((modules, globals, publics))
}

fn build_module_stream(module: &PdbModule) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_bytes(STRATUM_MODULE_MAGIC);
    w.write_u32(u32_len(module.lines.len(), "line count")?);
    for line in &module.lines {
        w.write_u64(line.address);
        w.write_u64(line.length);
        w.write_u32(line.file);
        w.write_u32(line.start);
        w.write_u32(line.end);
    }
    let symbols = build_symbol_stream(&module.symbols)?;
    w.write_u32(u32_len(symbols.len(), "module symbols")?);
    w.write_bytes(&symbols);
    w.write_u32(u32_len(module.scopes.len(), "scope count")?);
    for scope in &module.scopes {
        w.write_u32(scope.id);
        w.write_u32(scope.parent.unwrap_or(u32::MAX));
        w.write_u64(scope.address);
        w.write_u64(scope.length);
        w.write_u32(u32_len(scope.variables.len(), "variable count")?);
        for variable in &scope.variables {
            write_len_string(&mut w, &variable.name)?;
            w.write_u32(variable.type_index.unwrap_or(u32::MAX));
            w.write_u64(u64::from_ne_bytes(variable.location.to_ne_bytes()));
            w.write_u32(u32_len(variable.raw_location.len(), "raw location")?);
            w.write_bytes(&variable.raw_location);
        }
    }
    w.finish()
}

fn read_module_stream(
    bytes: &[u8],
) -> Result<(
    Vec<PdbLineRecord>,
    Vec<PdbSymbolRecord>,
    Vec<PdbScopeRecord>,
)> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    if r.read_bytes(4)? != STRATUM_MODULE_MAGIC {
        return Err(Error::Unsupported("non-Stratum module stream"));
    }
    let count = usize_from_u32(r.read_u32()?, "line count")?;
    let mut lines = Vec::with_capacity(count);
    for _ in 0..count {
        lines.push(PdbLineRecord {
            address: r.read_u64()?,
            length: r.read_u64()?,
            file: r.read_u32()?,
            start: r.read_u32()?,
            end: r.read_u32()?,
        });
    }
    let symbol_len = usize_from_u32(r.read_u32()?, "module symbols")?;
    let symbols = read_symbol_stream(r.read_bytes(symbol_len)?)?;
    let mut scopes = Vec::new();
    if r.is_empty() {
        return Ok((lines, symbols, scopes));
    }
    let scope_count = usize_from_u32(r.read_u32()?, "scope count")?;
    scopes = Vec::with_capacity(scope_count);
    for _ in 0..scope_count {
        let id = r.read_u32()?;
        let parent = match r.read_u32()? {
            u32::MAX => None,
            value => Some(value),
        };
        let address = r.read_u64()?;
        let length = r.read_u64()?;
        let variable_count = usize_from_u32(r.read_u32()?, "variable count")?;
        let mut variables = Vec::with_capacity(variable_count);
        for _ in 0..variable_count {
            let name = read_len_string(&mut r)?;
            let type_index = match r.read_u32()? {
                u32::MAX => None,
                value => Some(value),
            };
            let location = i64::from_ne_bytes(r.read_u64()?.to_ne_bytes());
            let raw_len = usize_from_u32(r.read_u32()?, "raw location")?;
            let raw_location = r.read_bytes(raw_len)?.to_vec();
            variables.push(PdbVariableRecord {
                name,
                type_index,
                location,
                raw_location,
            });
        }
        scopes.push(PdbScopeRecord {
            id,
            parent,
            address,
            length,
            variables,
        });
    }
    Ok((lines, symbols, scopes))
}

fn build_symbol_stream(symbols: &[PdbSymbolRecord]) -> Result<Vec<u8>> {
    let mut w = writer();
    w.write_bytes(STRATUM_SYMBOL_MAGIC);
    w.write_u32(u32_len(symbols.len(), "symbol count")?);
    for symbol in symbols {
        w.write_u16(symbol.raw_kind);
        w.write_u32(symbol_kind_to_raw(symbol.kind));
        w.write_u64(symbol.address);
        w.write_u64(symbol.length);
        w.write_u32(symbol.type_index.unwrap_or(u32::MAX));
        write_len_string(&mut w, &symbol.name)?;
        w.write_u32(u32_len(symbol.raw.len(), "symbol raw")?);
        w.write_bytes(&symbol.raw);
    }
    w.finish()
}

fn read_symbol_stream(bytes: &[u8]) -> Result<Vec<PdbSymbolRecord>> {
    let mut r = ByteReader::new(bytes, Endianness::Little);
    if r.read_bytes(4)? != STRATUM_SYMBOL_MAGIC {
        return Err(Error::Unsupported("non-Stratum symbol stream"));
    }
    let count = usize_from_u32(r.read_u32()?, "symbol count")?;
    let mut symbols = Vec::with_capacity(count);
    for _ in 0..count {
        let raw_kind = r.read_u16()?;
        let kind = raw_to_symbol_kind(r.read_u32()?);
        let address = r.read_u64()?;
        let length = r.read_u64()?;
        let type_index = match r.read_u32()? {
            u32::MAX => None,
            value => Some(value),
        };
        let name = read_len_string(&mut r)?;
        let raw_len = usize_from_u32(r.read_u32()?, "symbol raw")?;
        let raw = r.read_bytes(raw_len)?.to_vec();
        symbols.push(PdbSymbolRecord {
            raw_kind,
            kind,
            name,
            address,
            length,
            type_index,
            raw,
        });
    }
    Ok(symbols)
}

fn raw_to_symbol_kind(raw: u32) -> PdbSymbolKind {
    match raw {
        0 => PdbSymbolKind::Public,
        1 => PdbSymbolKind::Global,
        2 => PdbSymbolKind::Local,
        3 => PdbSymbolKind::Function,
        4 => PdbSymbolKind::Data,
        other => PdbSymbolKind::Other(other),
    }
}

fn symbol_kind_to_raw(kind: PdbSymbolKind) -> u32 {
    match kind {
        PdbSymbolKind::Public => 0,
        PdbSymbolKind::Global => 1,
        PdbSymbolKind::Local => 2,
        PdbSymbolKind::Function => 3,
        PdbSymbolKind::Data => 4,
        PdbSymbolKind::Other(raw) => raw,
    }
}

fn raw_streams(streams: &[Vec<u8>], info: &PdbInfo, modules: &[PdbModule]) -> Vec<PdbRawStream> {
    let mut out = Vec::new();
    for (index_u32, data) in (0u32..).zip(streams) {
        if is_known_stream(index_u32, info, modules) {
            continue;
        }
        out.push(PdbRawStream {
            index: index_u32,
            name: info
                .named_streams
                .iter()
                .find_map(|entry| (entry.stream == index_u32).then_some(entry.name.clone())),
            data: data.clone(),
        });
    }
    out
}

fn is_known_stream(index: u32, info: &PdbInfo, modules: &[PdbModule]) -> bool {
    is_fixed_stream(index)
        || info.named_streams.iter().any(|entry| {
            entry.stream == index
                && matches!(
                    entry.name.as_str(),
                    NAMES_STREAM_NAME
                        | GLOBAL_STREAM_NAME
                        | PUBLIC_STREAM_NAME
                        | STRATUM_DBI_STREAM_NAME
                )
        })
        || modules.iter().any(|module| module.stream == index)
}

#[cfg(test)]
mod tests {
    use super::{
        STRATUM_DBI_STREAM_NAME, bit_is_set, build_dbi_stream, build_module_stream,
        build_stratum_dbi_stream, build_symbol_stream, build_type_stream, decode_type_record,
        read_dbi_stream, read_module_stream, read_pdb_stream, read_stratum_dbi_stream,
        read_symbol_stream, read_type_stream, u32_len, write, write_len_string,
    };
    use crate::consts::{FEATURE_MINIMAL_DEBUG_INFO, STRATUM_DBI_MAGIC, STREAM_DBI};
    use crate::model::{
        NamedStream, PdbFieldRecord, PdbFile, PdbInfo, PdbLineRecord, PdbModule, PdbRawStream,
        PdbScopeRecord, PdbSourceRecord, PdbSymbolKind, PdbSymbolRecord, PdbTypeKind,
        PdbTypeRecord, PdbVariableRecord,
    };
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use stratum_oir::{ByteWriter, Endianness};

    fn symbol(kind: PdbSymbolKind, raw_kind: u16) -> PdbSymbolRecord {
        PdbSymbolRecord {
            raw_kind,
            kind,
            name: "sym".to_string(),
            address: u64::from(raw_kind) * 0x10,
            length: 3,
            type_index: raw_kind.is_multiple_of(2).then_some(0x1000),
            raw: vec![u8::try_from(raw_kind).unwrap()],
        }
    }

    fn ty(kind: PdbTypeKind, index: u32) -> PdbTypeRecord {
        PdbTypeRecord {
            index,
            raw_kind: u16::try_from(index & 0xffff).unwrap(),
            kind,
            name: "type".to_string(),
            size: 8,
            references: vec![0x74],
            fields: vec![PdbFieldRecord {
                name: "field".to_string(),
                type_index: 0x74,
                offset: 4,
            }],
            raw: vec![u8::try_from(index & 0xff).unwrap()],
        }
    }

    fn rich_file() -> PdbFile {
        PdbFile {
            info: PdbInfo {
                version: 20_000_404,
                signature: 12,
                age: 7,
                guid: [3; 16],
                named_streams: vec![
                    NamedStream {
                        name: "/globals".to_string(),
                        stream: 99,
                    },
                    NamedStream {
                        name: "/custom".to_string(),
                        stream: 9,
                    },
                ],
                features: Vec::new(),
                path: "rich.pdb".to_string(),
            },
            types: vec![
                ty(PdbTypeKind::Primitive, 0x1000),
                ty(PdbTypeKind::Pointer, 0x1001),
                ty(PdbTypeKind::Function, 0x1002),
                ty(PdbTypeKind::Aggregate, 0x1003),
                ty(PdbTypeKind::Enum, 0x1004),
                ty(PdbTypeKind::Array, 0x1005),
                ty(PdbTypeKind::Alias, 0x1006),
                ty(PdbTypeKind::Other(0x88), 0x1007),
            ],
            ids: vec![ty(PdbTypeKind::Other(0x99), 0x2000)],
            modules: vec![PdbModule {
                name: "module".to_string(),
                object: "module.obj".to_string(),
                sources: vec![PdbSourceRecord {
                    file: 2,
                    path: "module.c".to_string(),
                    checksum_kind: 1,
                    checksum: vec![1, 2, 3],
                }],
                lines: vec![PdbLineRecord {
                    address: 0x1000,
                    length: 4,
                    file: 2,
                    start: 10,
                    end: 11,
                }],
                symbols: vec![symbol(PdbSymbolKind::Local, 2)],
                scopes: vec![
                    PdbScopeRecord {
                        id: 1,
                        parent: Some(0),
                        address: 0x1000,
                        length: 4,
                        variables: vec![PdbVariableRecord {
                            name: "local".to_string(),
                            type_index: Some(0x1000),
                            location: -16,
                            raw_location: vec![0xaa],
                        }],
                    },
                    PdbScopeRecord {
                        id: 2,
                        parent: None,
                        address: 0x2000,
                        length: 4,
                        variables: vec![PdbVariableRecord {
                            name: "untyped".to_string(),
                            type_index: None,
                            location: 8,
                            raw_location: Vec::new(),
                        }],
                    },
                ],
                stream: 0,
            }],
            globals: vec![
                symbol(PdbSymbolKind::Public, 0),
                symbol(PdbSymbolKind::Global, 1),
                symbol(PdbSymbolKind::Function, 3),
                symbol(PdbSymbolKind::Data, 4),
                symbol(PdbSymbolKind::Other(0x44), 5),
            ],
            publics: vec![symbol(PdbSymbolKind::Public, 6)],
            raw_streams: vec![
                PdbRawStream {
                    index: 1,
                    name: None,
                    data: vec![0],
                },
                PdbRawStream {
                    index: 9,
                    name: Some("/custom".to_string()),
                    data: vec![9, 9],
                },
            ],
        }
    }

    #[test]
    fn rich_file_round_trips_all_stream_shapes() {
        let file = rich_file();
        let bytes = write(&file).unwrap();
        let parsed = super::read(&bytes).unwrap();

        assert!(parsed.info.features.contains(&20_140_508));
        assert_eq!(parsed.info.path, "rich.pdb");
        assert_eq!(parsed.types.len(), file.types.len());
        assert_eq!(parsed.ids.len(), file.ids.len());
        let parsed_module = parsed.modules.first().unwrap();
        assert_eq!(
            parsed_module.sources.first().unwrap().checksum,
            vec![1, 2, 3]
        );
        assert_eq!(
            parsed_module
                .scopes
                .first()
                .and_then(|scope| scope.variables.first())
                .unwrap()
                .location,
            -16
        );
        assert!(
            parsed
                .raw_streams
                .iter()
                .any(|stream| stream.index == 9 && stream.data == vec![9, 9])
        );
    }

    #[test]
    fn rejects_minimal_debug_info_feature() {
        let mut file = rich_file();
        file.info.features.push(FEATURE_MINIMAL_DEBUG_INFO);
        assert!(super::read(&write(&file).unwrap()).is_err());
    }

    #[test]
    fn rejects_oversized_u32_lengths() {
        assert!(u32_len(usize::MAX, "oversized length").is_err());
    }

    #[test]
    fn private_decoders_cover_legacy_and_malformed_paths() {
        fn write_legacy_header(w: &mut ByteWriter) {
            w.write_u32(20_000_404);
            w.write_u32(0);
            w.write_u32(1);
            w.write_bytes(&[0; 16]);
            w.write_u32(0);
            w.write_u32(0);
            w.write_u32(1);
            w.write_u32(1);
            w.write_u32(0);
            w.write_u32(1);
            w.write_u32(0);
            w.write_u32(0);
            w.write_u32(0);
        }

        let mut legacy_stream = ByteWriter::new(Endianness::Little);
        write_legacy_header(&mut legacy_stream);
        let legacy = read_pdb_stream(&legacy_stream.finish().unwrap()).unwrap();
        assert_eq!(legacy.path, "stratum.pdb");

        let mut stream = ByteWriter::new(Endianness::Little);
        write_legacy_header(&mut stream);
        write_len_string(&mut stream, "tail.pdb").unwrap();
        stream.write_u32(0);
        stream.write_u32(99);
        let trailing = read_pdb_stream(&stream.finish().unwrap()).unwrap();
        assert_eq!(trailing.features, vec![99]);

        assert!(!bit_is_set(&[], 0));

        let mut w = ByteWriter::new(Endianness::Little);
        w.write_u32(20_040_203);
        w.write_u32(56);
        w.write_u32(0x1000);
        w.write_u32(0x1001);
        w.write_u32(2);
        w.write_zeros(36);
        w.write_u16(1);
        assert!(read_type_stream(&w.finish().unwrap()).is_err());

        let short = decode_type_record(0x1000, 0x1234, &[1, 2, 3]).unwrap();
        assert_eq!(short.kind, PdbTypeKind::Other(0x1234));

        assert!(read_dbi_stream(b"BAD!", &[], &PdbInfo::default()).is_err());
        assert!(read_stratum_dbi_stream(b"BAD!", &[]).is_err());
        assert!(read_module_stream(b"BAD!").is_err());
        assert!(read_symbol_stream(b"BAD!").is_err());
    }

    #[test]
    fn direct_stream_builders_cover_empty_and_module_paths() {
        assert!(read_type_stream(&[]).unwrap().is_empty());
        assert!(!build_type_stream(&rich_file().types).unwrap().is_empty());
        assert!(
            !build_symbol_stream(&rich_file().globals)
                .unwrap()
                .is_empty()
        );

        let mut module = rich_file().modules.remove(0);
        module.stream = 7;
        let module_bytes = build_module_stream(&module).unwrap();
        let (lines, symbols, scopes) = read_module_stream(&module_bytes).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(symbols.len(), 1);
        assert_eq!(scopes.len(), 2);

        let mut legacy_module = ByteWriter::new(Endianness::Little);
        legacy_module.write_bytes(b"SMOD");
        legacy_module.write_u32(0);
        let empty_symbols = build_symbol_stream(&[]).unwrap();
        legacy_module.write_u32(u32::try_from(empty_symbols.len()).unwrap());
        legacy_module.write_bytes(&empty_symbols);
        let (_, _, legacy_scopes) = read_module_stream(&legacy_module.finish().unwrap()).unwrap();
        assert!(legacy_scopes.is_empty());

        let dbi = build_dbi_stream(5, 6).unwrap();
        assert!(!dbi.starts_with(STRATUM_DBI_MAGIC));

        let stratum_dbi = build_stratum_dbi_stream(core::slice::from_ref(&module), 5, 6).unwrap();
        let mut streams = vec![Vec::new(); 9];
        *streams.get_mut(7).unwrap() = module_bytes;
        *streams.get_mut(8).unwrap() = stratum_dbi;
        let mut info = PdbInfo::default();
        info.named_streams.push(NamedStream {
            name: STRATUM_DBI_STREAM_NAME.to_string(),
            stream: 8,
        });
        let (modules, globals, publics) = read_dbi_stream(&dbi, &streams, &info).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(globals, 5);
        assert_eq!(publics, 6);

        let legacy_dbi = build_stratum_dbi_stream(core::slice::from_ref(&module), 5, 6).unwrap();
        let (legacy_modules, legacy_globals, legacy_publics) =
            read_dbi_stream(&legacy_dbi, &streams, &PdbInfo::default()).unwrap();
        assert_eq!(legacy_modules.len(), 1);
        assert_eq!(legacy_globals, 5);
        assert_eq!(legacy_publics, 6);
    }

    #[test]
    fn writer_keeps_fixed_dbi_native_and_stratum_dbi_named() {
        let bytes = write(&rich_file()).unwrap();
        let msf = super::MsfFile::read(&bytes).unwrap();
        let dbi = msf
            .streams
            .get(usize::try_from(STREAM_DBI).unwrap())
            .unwrap();
        assert!(!dbi.starts_with(STRATUM_DBI_MAGIC));

        let info = read_pdb_stream(msf.streams.get(1).unwrap()).unwrap();
        let stratum_entry = info
            .named_streams
            .iter()
            .find(|entry| entry.name == STRATUM_DBI_STREAM_NAME)
            .unwrap();
        let stratum_dbi = msf
            .streams
            .get(usize::try_from(stratum_entry.stream).unwrap())
            .unwrap();
        assert!(stratum_dbi.starts_with(STRATUM_DBI_MAGIC));
    }
}
