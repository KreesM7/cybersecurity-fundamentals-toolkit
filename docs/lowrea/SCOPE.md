# Implementation coverage

Implemented: regular-file byte identity, content-addressed evidence, minimal PE/ELF
file-backed mappings, selected-window Capstone decoding (x86/x86-64/ARM64), ASCII
prefixes and limited selected RIP-relative data references. GUI, CLI and official
MCP stdio share the producer; workspace jobs, cancellation and explicit export
reuse host ownership. This slice does not execute or attach to artifacts.

Full format validation, symbols, functions, CFG, all xrefs, decompilation,
external provider integration, emulation, snapshots, comparison and reconstruction
remain unimplemented. See OPERATIONS.md for physical byte-window and capture limits.

Planned capabilities are described in DESIGN.md. Inventory rows remain missing until their engine/provider and producer tests are implemented and verified.
