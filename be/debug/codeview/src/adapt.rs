//! Bridges between the neutral [`DebugInfo`](stratum_oir::DebugInfo) attached to an object module
//! and the codec's self-contained [`DebugTable`].

use crate::table::{DebugTable, FuncEntry, LineEntry};
use stratum_diagnostics::{FileId, Span};
use stratum_oir::{FunctionRecord, LineRecord, ObjectModule, Result};

extern crate alloc;
use alloc::string::ToString;

/// Builds a [`DebugTable`] from the debug info attached to `module`.
///
/// # Errors
///
/// Returns an error if a function symbol cannot be resolved.
pub fn from_object(module: &ObjectModule) -> Result<DebugTable> {
    let debug = module.debug();
    let mut table = DebugTable::new();
    for line in debug.lines() {
        table.lines.push(LineEntry {
            address: line.address,
            length: line.length,
            file: line.span.file().raw(),
            start: line.span.start(),
            end: line.span.end(),
        });
    }
    for func in debug.functions() {
        table.funcs.push(FuncEntry {
            address: func.address,
            length: func.length,
            name: module.resolve(func.name)?.to_string(),
        });
    }
    Ok(table)
}

/// Populates `module`'s debug info from `table`, interning function names into the module.
///
/// # Errors
///
/// Returns an error if interning a function name fails.
pub fn apply_to_object(module: &mut ObjectModule, table: &DebugTable) -> Result<()> {
    for line in &table.lines {
        module.debug_mut().add_line(LineRecord {
            address: line.address,
            length: line.length,
            span: Span::new(FileId::from_raw(line.file), line.start, line.end),
        });
    }
    for func in &table.funcs {
        let name = module.intern(&func.name)?;
        module.debug_mut().add_function(FunctionRecord {
            name,
            address: func.address,
            length: func.length,
        });
    }
    Ok(())
}
