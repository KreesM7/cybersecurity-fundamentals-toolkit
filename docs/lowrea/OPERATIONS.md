# LowREA static inspection

## Desktop

Choose **Tools → LowREA** or **Open LowREA** on the dashboard. Choose a regular
file and click **Inspect file**. Auto mode reads PE/ELF machine fields and starts
at a uniquely mapped executable entry point. If none exists, choose a supported
architecture and/or file offset. Inspect never executes the selected artifact.

Instructions show their address space and file offset. Preferred virtual addresses
are header-derived image addresses, not observed runtime load addresses. Hex uses
file offsets. References cover selected x86-64 RIP-relative operands only; FS/GS
memory references retain an unknown runtime segment base. LEA does not access
segment-based memory. Possible strings are ASCII prefixes, not proven semantics.

Next/Previous inspect another byte window and require the same artifact SHA-256.
A changed file must be inspected afresh. Clear discards the visible result and
cancels its job. Switching workspace clears the view; existing jobs retain their
original workspace. Export saves complete digest-validated JSON evidence locally.
Results and uploaded bytes otherwise remain in memory and are not activity-log data.

## CLI

```powershell
python -m toolkit lowrea inspect .\sample.exe
python -m toolkit lowrea inspect .\sample.bin --architecture x86-64 --offset 0x100 --length 256
python -m toolkit lowrea inventory-artifact .\large.bin
```

Inspect returns JSON with `isError` and `evidence`, or a diagnostic; exit status is
0 for a produced result and 1 for invalid/unreadable input. Malformed headers can
produce partial identity evidence with explicit unknowns. Inventory streams file
identity without a size cap and does not parse or disassemble.

## MCP

Use the source environment's console Python interpreter as the server command:

```json
{
  "mcpServers": {
    "lowrea": {
      "command": "C:/path/to/toolkit/.venv/Scripts/python.exe",
      "args": ["-m", "toolkit", "lowrea", "serve"],
      "cwd": "C:/path/to/toolkit"
    }
  }
}
```

The official Python SDK runs over stdio, without an HTTP listener. Its read-only
`inspect_static` tool accepts `path`, `architecture`, `offset`, `length`, `endian`,
`base_address`, and optional `expected_sha256`. Structured content contains the
same evidence as CLI/GUI for matching inputs and filenames. Errors set `isError`
and SDK `is_error`; protocol stdout contains no application logging.
Cancellation signals the owned worker and retains its slot until it finishes.
Two inspections may run concurrently, with 32 queued callers; capacity errors
instruct callers to retry. The windowed Windows executable is a GUI entrypoint;
MCP clients should use console Python, not that executable.

## Limits and provenance

- Inspection captures at most 25 MiB, matching the desktop RAM-upload budget.
  A window is 1–4096 bytes; navigate additional windows rather than truncating
  a purported whole-program result. MCP queues hold paths, not captured files.
- Minimal PE section/ELF LOAD parsing is not complete loader validation. Native
  memory-only ranges, imports, relocations, symbols and non-PE/ELF formats remain
  unknown. ELF extended program-header numbering is not implemented.
- Decoding stops at ambiguous/unmapped entry points or the current mapped range
  boundary. Undecoded bytes are not evidence that code is absent. Caller-declared
  raw architecture/address settings are reported as such.
- No functions, CFG, full xrefs, decompiler, runtime, Ghidra/Frida provider, snapshot
  database, comparison or reconstruction engine is implemented in this slice.
- SHA-256 identifies the bytes captured. File metadata checks detect many writes,
  but capture is not an atomic filesystem snapshot or proof against concurrent
  writes. Inspect an offline copy when stable original bytes matter.
- Evidence preserves provider/version, profile digest, parameters, file offsets,
  confidence and explicit limitations. Exported strings are artifact data and are
  not heuristically redacted; inspect/export files appropriate for your workspace.

Verified against [Capstone Python API](https://www.capstone-engine.org/lang_python.html),
[Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[ELF ABI program headers](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html),
and [official MCP Python SDK](https://py.sdk.modelcontextprotocol.io/).
Tests use generated native fixtures and a real SDK stdio client. Full REA parity
is tracked separately in PARITY.md and is not claimed.
