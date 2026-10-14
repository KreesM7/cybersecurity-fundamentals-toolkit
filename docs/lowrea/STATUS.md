# LowREA implementation status

The attached design is the implementation target, not a claim of delivered capabilities.

| Milestone | State | Verification |
| --- | --- | --- |
| M0 host discovery | Verified | 383 host tests; HOST.md |
| M0 evidence identity | Verified foundation | Strict payload schema, canonical digest, mutation isolation, tamper and duplicate-key tests |
| M0 typed errors/process ownership | Pending | No runtime capabilities advertised |
| M1 builtin engine | Partial | Minimal PE/ELF mappings, real Capstone instruction windows and limited RIP references; no full loader/function recovery |
| M2 retained evidence/sessions | Pending | |
| M3 offline and application inspectors | Pending | |
| M4 external providers | Pending | Caller-installed engines; no silent fallback |
| M5 CLI/MCP/setup | Partial | CLI inspect and official SDK stdio inspect_static; real client/CLI evidence equality test |
| M6 runtime | Pending | Explicit authority and cleanup required |
| M7 comparison/reconstruction | Pending | |
| M8 benchmarks/providers | Pending | No comparative performance claims |

Independent source review found payload validation and split-read identity defects; both are fixed and the follow-up review found no remaining blockers. Eleven LowREA tests pass with 98.15% module coverage.

Current source and rebuilt desktop add a LowREA panel with Instructions, Hex,
Headers, References and Evidence, byte-window navigation, explicit export and
workspace-scoped cancellable jobs. CLI inspect and MCP share the same producer.
See OPERATIONS.md for input bounds, operation, provenance and partial-coverage limits.
Published v2.1.0 installers still lack LowREA. No full REA parity is claimed.

Final slice verification: 394 passed, 8 skipped, 1 warning, 50 subtests passed in 179.33s (0:02:59); host/module coverage 81.11%. Black, Ruff, strict mypy and bytecode compilation passed. This verifies the initial identity slice only.

Static inspection review corrected cross-boundary address attribution, invalid
ELF file/memory sizes and FS/GS-dependent physical references. Regression fixtures
exercise each defect. Real HTTPS GUI inspection/clear and real MCP stdio calls
exercise the complete new paths. Remaining milestones above retain their limits.

Current static/UI slice verification: full suite 487 passed, 8 skipped, 50 subtests;
then 25 focused static tests passed, including three additional worker/file checks.
Combined coverage is 82.46% (`pytest --cov`, then the focused run with `--cov-append`).
Black, Ruff and strict mypy pass. The Windows one-folder
build opens 19 panels from a different working directory and its packaged Capstone
decoder produces the fixture's LEA/RET instructions and mapped data reference.
Full-history secret scan passes. Dependency audit has no blocking findings;
the existing pymetasploit3 no-fix finding remains explicitly reported by the audit.
Native dark/light screenshots and ownership-contract audit pass. Source and
rebuilt folder are updated; published v2.1.0 installers remain unchanged.
