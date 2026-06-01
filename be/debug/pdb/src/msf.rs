//! MSF container reader/writer.

use crate::consts::{DEFAULT_BLOCK_SIZE, MSF_MAGIC};
use stratum_oir::{ByteReader, ByteWriter, Endianness, Error, Result};

extern crate alloc;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MsfFile {
    pub(crate) block_size: u32,
    pub(crate) streams: Vec<Vec<u8>>,
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

fn block_count(size: usize, block_size: usize) -> usize {
    if size == 0 {
        0
    } else {
        size.div_ceil(block_size)
    }
}

fn checked_offset(block: u32, block_size: u32) -> Result<usize> {
    let raw = block
        .checked_mul(block_size)
        .ok_or(Error::ValueOutOfRange("MSF block offset"))?;
    usize_from_u32(raw, "MSF block offset")
}

fn write_at(image: &mut Vec<u8>, offset: usize, data: &[u8]) -> Result<()> {
    let end = offset
        .checked_add(data.len())
        .ok_or(Error::ValueOutOfRange("MSF write"))?;
    if image.len() < end {
        image.resize(end, 0);
    }
    let dst = image
        .get_mut(offset..end)
        .ok_or(Error::Malformed("MSF write range"))?;
    dst.copy_from_slice(data);
    Ok(())
}

fn read_blocks(bytes: &[u8], blocks: &[u32], size: usize, block_size: u32) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size);
    let block_size_usize = usize_from_u32(block_size, "MSF block size")?;
    for block in blocks {
        let offset = checked_offset(*block, block_size)?;
        let chunk = bytes
            .get(offset..offset.saturating_add(block_size_usize))
            .ok_or(Error::UnexpectedEof {
                offset,
                needed: block_size_usize,
                len: bytes.len(),
            })?;
        let remaining = size.saturating_sub(out.len());
        let take = remaining.min(block_size_usize);
        out.extend_from_slice(
            chunk
                .get(0..take)
                .ok_or(Error::Malformed("MSF block slice"))?,
        );
        if out.len() == size {
            break;
        }
    }
    if out.len() != size {
        return Err(Error::UnexpectedEof {
            offset: bytes.len(),
            needed: size.saturating_sub(out.len()),
            len: bytes.len(),
        });
    }
    Ok(out)
}

impl MsfFile {
    pub(crate) fn read(bytes: &[u8]) -> Result<Self> {
        let mut r = ByteReader::new(bytes, Endianness::Little);
        if r.read_bytes(MSF_MAGIC.len())? != MSF_MAGIC {
            return Err(Error::BadMagic);
        }
        let block_size = r.read_u32()?;
        if !matches!(block_size, 512 | 1024 | 2048 | 4096) {
            return Err(Error::Unsupported("MSF block size"));
        }
        let _free_block_map = r.read_u32()?;
        let block_count_total = r.read_u32()?;
        let directory_bytes = r.read_u32()?;
        r.skip(4)?;
        let block_map_addr = r.read_u32()?;
        let expected_file_size = block_count_total
            .checked_mul(block_size)
            .ok_or(Error::ValueOutOfRange("MSF file size"))?;
        let expected_len = usize_from_u32(expected_file_size, "MSF file size")?;
        if bytes.len() < expected_len {
            return Err(Error::UnexpectedEof {
                offset: bytes.len(),
                needed: expected_len.saturating_sub(bytes.len()),
                len: bytes.len(),
            });
        }

        let dir_size = usize_from_u32(directory_bytes, "MSF directory size")?;
        let dir_block_count = block_count(dir_size, usize_from_u32(block_size, "MSF block size")?);
        let map_offset = checked_offset(block_map_addr, block_size)?;
        let mut map_reader = ByteReader::new(
            bytes.get(map_offset..).ok_or(Error::UnexpectedEof {
                offset: map_offset,
                needed: 4,
                len: bytes.len(),
            })?,
            Endianness::Little,
        );
        let mut dir_blocks = Vec::with_capacity(dir_block_count);
        for _ in 0..dir_block_count {
            dir_blocks.push(map_reader.read_u32()?);
        }
        let directory = read_blocks(bytes, &dir_blocks, dir_size, block_size)?;
        let mut d = ByteReader::new(&directory, Endianness::Little);
        let stream_count = usize_from_u32(d.read_u32()?, "MSF stream count")?;
        let mut sizes = Vec::with_capacity(stream_count);
        for _ in 0..stream_count {
            sizes.push(d.read_u32()?);
        }
        let mut streams = Vec::with_capacity(stream_count);
        let block_size_usize = usize_from_u32(block_size, "MSF block size")?;
        for size in sizes {
            if size == u32::MAX {
                streams.push(Vec::new());
                continue;
            }
            let size_usize = usize_from_u32(size, "MSF stream size")?;
            let count = block_count(size_usize, block_size_usize);
            let mut blocks = Vec::with_capacity(count);
            for _ in 0..count {
                blocks.push(d.read_u32()?);
            }
            streams.push(read_blocks(bytes, &blocks, size_usize, block_size)?);
        }
        Ok(Self {
            block_size,
            streams,
        })
    }

    pub(crate) fn write(streams: &[Vec<u8>]) -> Result<Vec<u8>> {
        let block_size = DEFAULT_BLOCK_SIZE;
        let block_size_usize = usize_from_u32(block_size, "MSF block size")?;
        let mut image = alloc::vec![0; block_size_usize * 3];
        let mut next_block = 3u32;
        let mut stream_blocks: Vec<Vec<u32>> = Vec::with_capacity(streams.len());
        for stream in streams {
            let count = block_count(stream.len(), block_size_usize);
            let mut blocks = Vec::with_capacity(count);
            let mut cursor = 0usize;
            for _ in 0..count {
                let block = next_block;
                next_block = next_block
                    .checked_add(1)
                    .ok_or(Error::ValueOutOfRange("MSF block"))?;
                blocks.push(block);
                let take = stream.len().saturating_sub(cursor).min(block_size_usize);
                let offset = checked_offset(block, block_size)?;
                let stream_end = cursor.saturating_add(take);
                let chunk = stream
                    .get(cursor..stream_end)
                    .ok_or(Error::Malformed("MSF stream slice"))?;
                write_at(&mut image, offset, chunk)?;
                cursor = cursor.saturating_add(take);
            }
            stream_blocks.push(blocks);
        }

        let directory = build_directory(streams, &stream_blocks)?;
        let dir_block_count = block_count(directory.len(), block_size_usize);
        let mut dir_blocks = Vec::with_capacity(dir_block_count);
        let mut cursor = 0usize;
        for _ in 0..dir_block_count {
            let block = next_block;
            next_block = next_block
                .checked_add(1)
                .ok_or(Error::ValueOutOfRange("MSF directory block"))?;
            dir_blocks.push(block);
            let take = directory.len().saturating_sub(cursor).min(block_size_usize);
            let offset = checked_offset(block, block_size)?;
            let directory_end = cursor.saturating_add(take);
            let chunk = directory
                .get(cursor..directory_end)
                .ok_or(Error::Malformed("MSF directory slice"))?;
            write_at(&mut image, offset, chunk)?;
            cursor = cursor.saturating_add(take);
        }

        let block_map_addr = next_block;
        next_block = next_block
            .checked_add(1)
            .ok_or(Error::ValueOutOfRange("MSF block map"))?;
        let mut map = ByteWriter::new(Endianness::Little);
        for block in &dir_blocks {
            map.write_u32(*block);
        }
        let map_offset = checked_offset(block_map_addr, block_size)?;
        let map = map.finish()?;
        write_at(&mut image, map_offset, &map)?;

        let final_size = next_block
            .checked_mul(block_size)
            .ok_or(Error::ValueOutOfRange("MSF final size"))?;
        let final_len = usize_from_u32(final_size, "MSF final size")?;
        image.resize(final_len, 0);
        let directory_len = u32_len(directory.len(), "MSF directory")?;
        let superblock = write_superblock(
            &mut image,
            block_size,
            next_block,
            directory_len,
            block_map_addr,
        );
        superblock?;
        Ok(image)
    }
}

fn build_directory(streams: &[Vec<u8>], blocks: &[Vec<u32>]) -> Result<Vec<u8>> {
    let mut w = ByteWriter::new(Endianness::Little);
    w.write_u32(u32_len(streams.len(), "MSF stream count")?);
    for stream in streams {
        w.write_u32(u32_len(stream.len(), "MSF stream size")?);
    }
    for stream_blocks in blocks {
        for block in stream_blocks {
            w.write_u32(*block);
        }
    }
    w.finish()
}

fn write_superblock(
    image: &mut Vec<u8>,
    block_size: u32,
    blocks: u32,
    directory_bytes: u32,
    block_map_addr: u32,
) -> Result<()> {
    let mut w = ByteWriter::new(Endianness::Little);
    w.write_bytes(MSF_MAGIC);
    w.write_u32(block_size);
    w.write_u32(1);
    w.write_u32(blocks);
    w.write_u32(directory_bytes);
    w.write_u32(0);
    w.write_u32(block_map_addr);
    write_at(image, 0, &w.finish()?)
}

#[cfg(test)]
mod tests {
    use super::{MsfFile, build_directory, read_blocks, u32_len, write_superblock};
    use crate::consts::{DEFAULT_BLOCK_SIZE, MSF_MAGIC};
    use alloc::vec::Vec;
    use stratum_oir::{ByteWriter, Endianness};

    #[test]
    fn msf_round_trips_streams() {
        let streams = alloc::vec![
            Vec::new(),
            b"one".to_vec(),
            alloc::vec![7; 5000],
            b"three".to_vec(),
        ];
        let bytes = MsfFile::write(&streams).unwrap();
        let parsed = MsfFile::read(&bytes).unwrap();
        assert_eq!(parsed.streams, streams);
        assert_eq!(MsfFile::write(&parsed.streams).unwrap(), bytes);
    }

    #[test]
    fn rejects_malformed_msf_headers_and_blocks() {
        assert!(MsfFile::read(b"not an msf").is_err());

        let mut unsupported = alloc::vec![0u8; 512];
        unsupported
            .get_mut(..MSF_MAGIC.len())
            .unwrap()
            .copy_from_slice(MSF_MAGIC);
        unsupported
            .get_mut(MSF_MAGIC.len()..MSF_MAGIC.len() + 4)
            .unwrap()
            .copy_from_slice(&123u32.to_le_bytes());
        assert!(MsfFile::read(&unsupported).is_err());

        let mut truncated = alloc::vec![0u8; usize::try_from(DEFAULT_BLOCK_SIZE).unwrap()];
        write_superblock(&mut truncated, DEFAULT_BLOCK_SIZE, 2, 0, 1).unwrap();
        truncated.truncate(64);
        assert!(MsfFile::read(&truncated).is_err());

        assert!(read_blocks(&truncated, &[1], 1, DEFAULT_BLOCK_SIZE).is_err());
        assert!(read_blocks(&truncated, &[], 1, DEFAULT_BLOCK_SIZE).is_err());
    }

    #[test]
    fn reads_deleted_stream_slots_from_directory() {
        let mut directory = ByteWriter::new(Endianness::Little);
        directory.write_u32(1);
        directory.write_u32(u32::MAX);
        let directory = directory.finish().unwrap();
        let mut image = alloc::vec![0u8; usize::try_from(DEFAULT_BLOCK_SIZE * 4).unwrap()];
        image
            .get_mut(
                usize::try_from(DEFAULT_BLOCK_SIZE).unwrap()
                    ..usize::try_from(DEFAULT_BLOCK_SIZE).unwrap() + directory.len(),
            )
            .unwrap()
            .copy_from_slice(&directory);
        let mut map = ByteWriter::new(Endianness::Little);
        map.write_u32(1);
        let map = map.finish().unwrap();
        image
            .get_mut(
                usize::try_from(DEFAULT_BLOCK_SIZE * 2).unwrap()
                    ..usize::try_from(DEFAULT_BLOCK_SIZE * 2).unwrap() + map.len(),
            )
            .unwrap()
            .copy_from_slice(&map);
        write_superblock(
            &mut image,
            DEFAULT_BLOCK_SIZE,
            4,
            u32::try_from(directory.len()).unwrap(),
            2,
        )
        .unwrap();

        let parsed = MsfFile::read(&image).unwrap();
        assert_eq!(parsed.streams, alloc::vec![Vec::new()]);
    }

    #[test]
    fn rejects_oversized_u32_lengths() {
        assert!(u32_len(usize::MAX, "oversized length").is_err());
    }

    #[test]
    fn directory_builder_rejects_large_counts() {
        let blocks = alloc::vec![Vec::new()];
        let streams = alloc::vec![alloc::vec![0u8; 4]];
        assert!(build_directory(&streams, &blocks).is_ok());
    }
}
