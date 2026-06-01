//! On-disk constants for the Portable Executable / COFF container.

/// `MZ` DOS header signature.
pub const DOS_MAGIC: u16 = 0x5A4D;
/// Offset within the DOS header holding the file offset of the PE signature.
pub const E_LFANEW_OFFSET: usize = 0x3C;
/// `PE\0\0` signature introducing the COFF header.
pub const PE_SIGNATURE: u32 = 0x0000_4550;

/// `IMAGE_FILE_MACHINE_I386`.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
/// `IMAGE_FILE_MACHINE_ARMNT`.
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;
/// `IMAGE_FILE_MACHINE_AMD64`.
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`.
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

/// `IMAGE_FILE_EXECUTABLE_IMAGE`.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
/// `IMAGE_FILE_32BIT_MACHINE`.
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;
/// `IMAGE_FILE_LARGE_ADDRESS_AWARE`.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

/// `IMAGE_NT_OPTIONAL_HDR32_MAGIC` (PE32).
pub const OPTIONAL_MAGIC_PE32: u16 = 0x010B;
/// `IMAGE_NT_OPTIONAL_HDR64_MAGIC` (PE32+).
pub const OPTIONAL_MAGIC_PE32PLUS: u16 = 0x020B;
/// `IMAGE_SUBSYSTEM_WINDOWS_CUI` (console).
pub const SUBSYSTEM_WINDOWS_CUI: u16 = 3;
/// Number of data directory entries in the optional header.
pub const NUMBER_OF_DIRECTORIES: u32 = 16;
/// Index of the export table data directory.
pub const DIRECTORY_EXPORT: usize = 0;
/// Index of the import table data directory.
pub const DIRECTORY_IMPORT: usize = 1;
/// Index of the base relocation table data directory.
pub const DIRECTORY_BASERELOC: usize = 5;

/// Section contains executable code.
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
/// Section contains initialised data.
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
/// Section contains uninitialised data.
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
/// Section is executable.
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
/// Section is readable.
pub const SCN_MEM_READ: u32 = 0x4000_0000;
/// Section is writable.
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// COFF external symbol storage class.
pub const SYM_CLASS_EXTERNAL: u8 = 2;
/// COFF static symbol storage class.
pub const SYM_CLASS_STATIC: u8 = 3;
/// COFF function derived type.
pub const SYM_DTYPE_FUNCTION: u16 = 0x20;

/// COFF header size in bytes.
pub const COFF_HEADER_SIZE: u32 = 20;
/// PE32 optional header size in bytes (including the 16 data directories).
pub const OPTIONAL_HEADER_SIZE_PE32: u16 = 224;
/// PE32+ optional header size in bytes (including the 16 data directories).
pub const OPTIONAL_HEADER_SIZE_PE32PLUS: u16 = 240;
/// Section table entry size in bytes.
pub const SECTION_HEADER_SIZE: u32 = 40;
/// COFF symbol-table entry size in bytes.
pub const SYMBOL_TABLE_ENTRY_SIZE: u32 = 18;

/// In-file alignment of section bodies.
pub const FILE_ALIGNMENT: u32 = 0x200;
/// In-memory alignment of sections.
pub const SECTION_ALIGNMENT: u32 = 0x1000;
/// Preferred load address for PE32+ images.
pub const IMAGE_BASE64: u64 = 0x1_4000_0000;
/// Preferred load address for PE32 images.
pub const IMAGE_BASE32: u32 = 0x0040_0000;
