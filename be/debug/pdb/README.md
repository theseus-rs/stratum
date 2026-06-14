# `stratum_pdb`

An MSF7/PDB codec for Stratum debug metadata.

The crate reads and writes modern PDB files as an MSF container with fixed PDB, TPI, DBI, and
IPI streams plus named streams such as `/names`, `/globals`, `/publics`, and `/stratum/dbi`.
The fixed DBI stream uses a native-shaped DBI header with global and public stream references;
Stratum-specific module metadata lives in `/stratum/dbi` so stream 3 is not a private marker
payload. The codec preserves unknown streams while adapting modeled source, line, function,
type, symbol, scope, and PE/PDB identity records to and from [`stratum_oir::DebugInfo`].

The writer emits deterministic MSF 7 files using 4096-byte blocks. The reader accepts the
standard MSF block sizes and reconstructs discontiguous streams through the stream directory.
FASTLINK/minimal and obsolete pre-MSF7 PDB variants are detected as unsupported rather than
silently misparsed.
