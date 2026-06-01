//! On-disk constants for the WebAssembly binary format.

/// WebAssembly module magic (`\0asm`).
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];
/// WebAssembly binary format version 1.
pub const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Custom section id.
pub const SECTION_CUSTOM: u8 = 0;
/// Type section id.
pub const SECTION_TYPE: u8 = 1;
/// Import section id.
pub const SECTION_IMPORT: u8 = 2;
/// Function section id.
pub const SECTION_FUNCTION: u8 = 3;
/// Table section id.
pub const SECTION_TABLE: u8 = 4;
/// Memory section id.
pub const SECTION_MEMORY: u8 = 5;
/// Global section id.
pub const SECTION_GLOBAL: u8 = 6;
/// Export section id.
pub const SECTION_EXPORT: u8 = 7;
/// Start section id.
pub const SECTION_START: u8 = 8;
/// Element section id.
pub const SECTION_ELEMENT: u8 = 9;
/// Code section id.
pub const SECTION_CODE: u8 = 10;
/// Data section id.
pub const SECTION_DATA: u8 = 11;
/// Data-count section id.
pub const SECTION_DATA_COUNT: u8 = 12;
/// Highest standard section id in WebAssembly 1.x.
pub const SECTION_MAX_STANDARD: u8 = SECTION_DATA_COUNT;

/// `func` type constructor.
pub const TYPE_FUNC: u8 = 0x60;
/// `funcref` reference type.
pub const REF_FUNC: u8 = 0x70;
/// `i32` value type.
pub const VAL_I32: u8 = 0x7F;

/// Import/export descriptor: function.
pub const DESC_FUNC: u8 = 0x00;
/// Import/export descriptor: table.
pub const DESC_TABLE: u8 = 0x01;
/// Import/export descriptor: memory.
pub const DESC_MEMORY: u8 = 0x02;
/// Import/export descriptor: global.
pub const DESC_GLOBAL: u8 = 0x03;

/// `i32.const` opcode.
pub const OP_I32_CONST: u8 = 0x41;
/// `call` opcode.
pub const OP_CALL: u8 = 0x10;
/// `drop` opcode.
pub const OP_DROP: u8 = 0x1A;
/// `end` opcode.
pub const OP_END: u8 = 0x0B;

/// WASI module name for imports.
pub const WASI_MODULE: &str = "wasi_snapshot_preview1";
/// WASI `fd_write` import name.
pub const WASI_FD_WRITE: &str = "fd_write";
/// Exported memory name.
pub const EXPORT_MEMORY: &str = "memory";
/// Exported entry-point name.
pub const EXPORT_START: &str = "_start";
