//! DWARF constants used by the debug-info and line-program codec.

/// `DW_TAG_compile_unit`.
pub const DW_TAG_COMPILE_UNIT: u64 = 0x11;
/// `DW_TAG_base_type`.
pub const DW_TAG_BASE_TYPE: u64 = 0x24;
/// `DW_TAG_subprogram`.
pub const DW_TAG_SUBPROGRAM: u64 = 0x2e;
/// `DW_TAG_variable`.
pub const DW_TAG_VARIABLE: u64 = 0x34;

/// `DW_CHILDREN_no`.
pub const DW_CHILDREN_NO: u8 = 0x00;
/// `DW_CHILDREN_yes`.
pub const DW_CHILDREN_YES: u8 = 0x01;

/// `DW_AT_name`.
pub const DW_AT_NAME: u64 = 0x03;
/// `DW_AT_stmt_list`.
pub const DW_AT_STMT_LIST: u64 = 0x10;
/// `DW_AT_low_pc`.
pub const DW_AT_LOW_PC: u64 = 0x11;
/// `DW_AT_high_pc`.
pub const DW_AT_HIGH_PC: u64 = 0x12;
/// `DW_AT_type`.
pub const DW_AT_TYPE: u64 = 0x49;
/// `DW_AT_encoding`.
pub const DW_AT_ENCODING: u64 = 0x3e;
/// `DW_AT_byte_size`.
pub const DW_AT_BYTE_SIZE: u64 = 0x0b;

/// `DW_FORM_addr`.
pub const DW_FORM_ADDR: u64 = 0x01;
/// `DW_FORM_data1`.
pub const DW_FORM_DATA1: u64 = 0x0b;
/// `DW_FORM_data8`.
pub const DW_FORM_DATA8: u64 = 0x07;
/// `DW_FORM_ref4`.
pub const DW_FORM_REF4: u64 = 0x13;
/// `DW_FORM_sec_offset`.
pub const DW_FORM_SEC_OFFSET: u64 = 0x17;
/// `DW_FORM_strp`.
pub const DW_FORM_STRP: u64 = 0x0e;

/// `DW_ATE_unsigned`.
pub const DW_ATE_UNSIGNED: u8 = 0x07;

/// `DW_UT_compile`.
pub const DW_UT_COMPILE: u8 = 0x01;

/// `DW_LNS_copy`.
pub const DW_LNS_COPY: u8 = 0x01;
/// `DW_LNS_advance_pc`.
pub const DW_LNS_ADVANCE_PC: u8 = 0x02;
/// `DW_LNS_advance_line`.
pub const DW_LNS_ADVANCE_LINE: u8 = 0x03;
/// `DW_LNS_set_file`.
pub const DW_LNS_SET_FILE: u8 = 0x04;
/// `DW_LNS_set_column`.
pub const DW_LNS_SET_COLUMN: u8 = 0x05;

/// Extended-opcode escape (`0x00`).
pub const DW_LNS_EXTENDED: u8 = 0x00;
/// `DW_LNE_end_sequence`.
pub const DW_LNE_END_SEQUENCE: u8 = 0x01;
/// `DW_LNE_set_address`.
pub const DW_LNE_SET_ADDRESS: u8 = 0x02;

/// `DW_LNCT_path`.
pub const DW_LNCT_PATH: u8 = 0x1;
/// `DW_FORM_string` (inline NUL-terminated string).
pub const DW_FORM_STRING: u8 = 0x08;

/// DWARF version implemented by this codec.
pub const DWARF_VERSION: u16 = 5;
/// 64-bit address size.
pub const ADDRESS_SIZE: u8 = 8;
/// First special opcode (we emit none, so all rows use standard opcodes).
pub const OPCODE_BASE: u8 = 13;
/// Standard opcode operand counts for opcodes `1..=12`.
pub const STANDARD_OPCODE_LENGTHS: [u8; 12] = [0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1];
