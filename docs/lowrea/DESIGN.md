# LowREA master prompt (final, merged)

> How to use: open your EXISTING app repo in a coding agent (Codex, Claude Code, Cursor). Copy `rea-tool-inventory.md` into `docs/lowrea/` first. Paste everything below the line.
> Basis: the morluto/rea README and full v6.4.0 source dump. Items marked **[REA]** mirror REA. Items marked **[NEW]** are proposed improvements, not REA features.

---

# ROLE

You are a senior reverse-engineering and systems engineer. Add **LowREA** to the existing application in this repo: a local-only tool that exposes one set of workflows through both an **MCP stdio server** and a **CLI**, so AI agents can investigate any shipped software (native binaries, desktop and Electron apps, websites, Android apps, managed code, firmware, runtime behavior) and return findings backed by evidence.

Goal: an agent sees a feature or behavior in a program, understands how it works down to the instruction level, shows its evidence, and helps rebuild it. LowREA must (1) match REA's public capability, then (2) be easier to use, and (3) go deeper on low-level work.

Work in small verified steps. Never claim a capability works until a test in this repo proves it. List everything you did not verify.

# 0. HOST INTEGRATION (this is NOT a new project)

## Phase 0: discover the host before any code (write findings to `docs/lowrea/HOST.md`)
1. Identify the host's language, framework, package/build tool, test runner, linter, type-checker, CI config, directory conventions, logging, config/env handling, error style, release process.
2. Identify attach points: existing CLI entrypoints, plugin/command registries, services, routes, workers.
3. Identify overlapping code (binary parsing, disassembly, sessions, result/evidence types, process spawning). Reuse where sound, never duplicate.
4. If a `lowrev` package exists, treat it as the seed of the builtin provider (LIEF + Capstone core, PLT resolution, limits notes, fixture-compiling tests).
5. Record the host's baseline test result before touching anything.

## Integration rules
1. **Isolation:** all code in one namespaced module (`<host_src>/lowrea/` or `packages/lowrea/`, per host convention). Edit host files only at minimal wiring points (entrypoint registration, dependency manifest, CI step, docs link). List every touched host file and the reason in HOST.md.
2. **Host conventions win** for formatting, naming, layout, tests, lint/type rules, commit style, logging, config. The layering in section 5 lives INSIDE the module.
3. **Stack:** if the host is Python 3.11+, use section 4 as written. Otherwise do NOT rewrite the host: ship LowREA as a Python sidecar package in the module directory, called through its CLI/MCP stdio boundary, with its own pinned manifest. Heavy deps (lief, capstone, unicorn, angr) are optional extras, never host core dependencies. Record the decision and reason in HOST.md.
4. **No behavior change:** existing host tests pass unchanged before and after. If the host has no tests, add none to host code.
5. **Reuse, don't fork:** reuse host config/logging/process/error types only if they meet section 2; otherwise wrap behind a LowREA interface. Never modify them.
6. **Wiring:** expose as a `<host> lowrea ...` subcommand namespace plus an MCP stdio entry, not a competing root CLI.
7. **Docs:** under `docs/lowrea/` (DESIGN, HOST, PARITY, SCOPE, DISCLAIMER, AGENTS, capability matrix, benchmarks). Never overwrite the host README or AGENTS.md; append a short "LowREA" section with a link.
8. **CI:** a separate job running only LowREA checks plus the readiness verifier. Never slow or gate host jobs.
9. **Rollback:** the integration must be removable by deleting the module directory and reverting the listed wiring edits. Verify once and record it.
10. Prefer the smallest diff to host files.

# 1. PARITY WITH REA **[REA]**

REA (github.com/morluto/rea, MIT) is "one MCP for reverse engineering across binaries, applications, and runtime behavior". One shared application layer serves a CLI and an MCP stdio server with the same facts, Evidence and session semantics. Native deep analysis uses bring-your-own engines (Hopper, Ghidra, IDA).

## Parity rules
1. `docs/lowrea/rea-tool-inventory.md` is the seed list (about 180 tool names extracted from REA's contracts by pattern match; treat as a seed, verify against REA's generated catalog). Create `docs/lowrea/PARITY.md`: one row per name -> LowREA tool -> status (done/partial/missing/out-of-scope) -> proving test.
2. **Keep REA's public tool names identical** so existing REA skills, prompts and agent habits transfer.
3. Parity means a test shows the same class of facts with equal or better Evidence and limitations. Never claim parity from docs alone.
4. Do not copy REA source. Reimplement from public behavior and contracts. Third-party engines stay bring-your-own.
5. Anything in the inventory that crosses section 3 goes to `docs/lowrea/SCOPE.md` as an unknown; ask, do not build.

## Target coverage matrix (each row: provider/inspector, Evidence-producing tool, CLI command, MCP registration, test)
- **Native** ELF/PE/Mach-O/raw/16-bit DOS: builtin engine + Ghidra + IDA + Hopper + rizin adapters.
- **Offline inspectors:** ELF layout and mitigation candidates, Go build info, WASM (sections, imports/exports, WAT), EVM bytecode (selectors, offsets, inferred args/mutability), recorded Linux crashes (all threads, registers, signals, mappings), PE resources and signatures, Mach-O.
- **JavaScript / Electron / ASAR:** modules, imports, source maps, routes, IPC, preload-to-main bridges, native add-ons; source recovery and bundle-to-source comparison; export shape comparison. Static, no execution.
- **Websites:** page structure, scripts, event listeners, module imports, source-location tracing, screenshots and comparisons, WebMCP discovery, execution/session observation via a caller-installed Chrome-family browser. **Saved captures:** HAR and mitmproxy dumps.
- **.NET/managed:** metadata, members, CIL, native boundaries, build comparison, project graph, reconstruction import. Static only.
- **Android:** APK manifest/classes/methods/references (JADX, caller-supplied), resources (Apktool), JEB via caller-started MCP, Flutter/Dart AOT identification, Harmony and Apple application graphs.
- **Devices (adb, caller-supplied):** devices, packages, processes, services, logcat, settings, dumps, screen capture, bugreport, file/APK transfer, app start/stop. All with declared effects.
- **Apple:** bundle anatomy, plists, keyed archives, asset catalogs, Interface Builder, Swift/ObjC metadata, dylib resolution, native UI observation/tracing.
- **Firmware:** regions, extraction (binwalk/unblob, caller-supplied), handoff to native analysis. **Packages/archives:** inventory, digests, extraction, comparison.
- **Process behavior:** PTY capture of output, interactions, exit and filesystem observations, run-to-run comparison.
- **Frida** (optional extra): devices, processes, sessions, script load/unload, instrumentation.
- **Evidence/workflow:** bundles (get/export/import/compare), unknown registry (record/update/list/verify resolution), reconstruction (obligation ledger, coverage, `verify_reconstruction`), `find_changed_behavior`, `correlate_static_and_runtime`, `trace_feature`, `trace_application_feature`.

Each row reports supported host OS/arch. An unsupported host returns a typed `unavailable` result with remediation, never a silent skip.

# 2. NON-NEGOTIABLE PRINCIPLES **[REA]**

Put these in `docs/lowrea/AGENTS.md`.

1. **Observed, derived, inferred, unknown are four different things.** Never upgrade one into another. Decompiler output is an analysis observation, not original source. Missing coverage is unknown, never "absent". An empty call list with partial coverage is not proof of no calls.
2. **Preserve provenance end to end:** artifact SHA-256, provider and version, analysis-profile digest, parameters, addresses or file offsets, limitations.
3. **Static by default. Runtime only with explicit declared authority.** Launching, attaching, injecting, emulating, driving a browser, adb actions, writing memory or registers are effects. Tools declare effects truthfully; runtime tools require the caller to name the exact target and action.
4. **One owner per interpretation and per resource.** Parse once at the owning boundary with format-aware parsers. Never infer behavior from filenames or strings alone.
5. **Fail closed.** Unresolved scope, authority, side effects or verification disables the capability and records an unknown.
6. **Resource ownership and cleanup are first-class.** Every process, debugger, emulator, browser, temp dir and database has an owner, deadline, cancellation and retryable cleanup. If cleanup fails, keep ownership and report it. PID plus path does not prove ownership after exit or reuse.
7. **Token-efficient by design:** agent tokens/context first, then analysis time, then CPU/memory. Smallest sufficient answer with provenance and limits; page; summarize; retain full Evidence retrievably. No arbitrary result caps; limits come from real format/protocol/resource constraints and are reported when hit.
8. **Config changes are additive, idempotent and backed up.** Never install or upgrade unrelated software. External engines are bring-your-own.
9. **Redact only what is explicitly marked sensitive.** Never guess secrecy from names or patterns.
10. **Model expected failures as typed errors** (tagged union plus `Result`), preserving partial facts and a meaningful reason.

# 3. SCOPE BOUNDARIES **[REA]**

In scope: format inspection, disassembly, decompilation, xrefs, CFG/call-graph recovery, general static deobfuscation, archive extraction, vulnerability analysis, crash triage, diffing, evidence reporting, bounded declared runtime observation, interoperability, preservation and analysis of software the user owns or is authorized to examine.

Out of scope. Do not build, stub or document workflows for:
- defeating commercial packers or code-virtualization protections or recovering protected code (static detection is fine);
- anti-debugging/anti-instrumentation evasion, DRM, license-check, anti-cheat or access-control bypass;
- exploit or attack-payload generation, credential theft, persistence, unauthorized access, bulk attack tooling.

Commercial engines (IDA, Hopper, JEB) must be legally obtained by the user; LowREA grants no license, key or activation. Put a `DISCLAIMER.md` in `docs/lowrea/`: the user must be authorized to analyze the target; "authorized use only" text does not itself contain misuse. Website, device and network analysis requires authorization for the target.

# 4. TECH STACK

Python 3.11+ (subject to integration rule 3).
- Contracts: `pydantic` v2, frozen, strict.
- MCP: official `mcp` Python SDK (verify the current API, pin a compatible version; v2 renamed `FastMCP`).
- CLI: `typer` or `argparse`; JSON by default, `--text` for humans.
- Parsing: `lief`. Disassembly: `capstone`. Assemble: `keystone-engine` (optional). Emulation: `unicorn`. Symbolic: `angr` (optional extra).
- Engines: Ghidra headless (`pyghidra` or `analyzeHeadless` + packaged bridge), `rzpipe` for rizin, IDA via `ida-pro-mcp`, Hopper last.
- Debugging: GDB/MI and LLDB via owned subprocesses. Browser: CDP. Optional Frida.
- Quality: `pytest` + `hypothesis`, `ruff`, `mypy --strict` or `pyright`. No binaries committed; fixtures compiled or generated at test time.

# 5. ARCHITECTURE (inside the module; dependencies flow inward) **[REA]**

```
cli/ , mcp_server/        adapters: translate only, no analysis logic
composition/              builds providers, sessions, registries
application/              shared workflows for CLI and MCP (sessions, investigation ledger)
providers/                engine adapters; protocols never leak upward
  builtin/  ghidra/  rizin/  ida/  hopper/  runtime/(process,debugger,emulator,browser,adb,frida)
  artifacts/ (go, macho, pe, elf, wasm, evm, managed, android, js, firmware, crash)
process/                  supervised children, deadlines, private temp roots, cleanup
contracts/                caller-visible schemas and error schemas
domain/                   pure: Evidence, locations, digests, comparisons
config/                   validated env parsing
```
Domain imports nothing above it. Providers never import application. Adapters never import providers directly.

# 6. EVIDENCE MODEL **[REA]**

```
Evidence {
  evidence_id        "ev:" + digest of canonical JSON (stable, content-addressed)
  subject            { name, digest.sha256, format, architecture|null, local_path } | null
  provider           { id, name, version|null }
  analysis_profile   object | null   # participates in identity
  predicate_type, operation, parameters
  raw_result         json | null
  normalized_result  json
  confidence         "observed" | "derived" | "inferred"
  authority          "shipped-artifact" | "controlled-replay" | "historical-reference" | "external-service" | "analyst-inference"
  environment        { id, platform, architecture, isolation: none|process|container|virtual-machine } | null
  limitations        string[]
  relationship_coverage  "complete" | "partial" | "unknown" | null
  locations          [ address | address-range | artifact-path | file-offset | file-offset-range ]
  evidence_links     ev:...[]
}
```
- Canonical JSON digest (sorted keys, stable numbers); records immutable.
- Success returns full Evidence in text and structured content. Failure returns `isError` with typed diagnostic (code, target, partial observations, remediation).
- Unknown registry: `record_unknown`, `update_unknown` (revision-checked), `list_unknowns`, `verify_unknown_resolution`; resolved only by qualifying observed evidence.
- Bundles: `get_evidence_bundle`, `export_evidence_bundle`, `import_evidence_bundle`, `compare_bundles`; round-trip and tamper detection.
- `inspect_analysis_view` reads a view (summary, one section/function, stable page with `offset/limit/next_offset`) of retained Evidence so agents never re-run analysis to read one fact.

# 7. SESSIONS AND PROVIDERS **[REA]**

- `open_binary(path, provider_id?, options)` hashes the artifact, selects exactly one deep provider deterministically, binds it. `binary_session` reports target, provider, alignment, catalog identity and a **tool-availability inventory** with reason and remediation for every unavailable tool. **No silent fallback to another provider.**
- If the file changes after binding, report `artifact_changed` with both digests; do not silently re-analyze.
- Capabilities reported per provider with exact coverage. Tool names are provider-neutral; never claim two engines' pseudocode is equivalent.
- Analysis databases are ephemeral and read-only by default; only annotation edits on the ephemeral DB are allowed, never on the executable. Re-opening a target reuses the live database.
- Cancellation is real: terminate the in-flight request, discard state, report cleanup status.
- Target-free inspectors work on an explicit path with no session.

# 8. EASE OF USE **[NEW]** (the "easier than REA" requirements; each needs a test)

1. **Zero-config start.** `lowrea analyze PATH` auto-routes by target type (native file, `.app`, directory/ASAR -> JS/Electron, `.apk`, managed `.dll`, `.wasm`, `.har`, firmware blob, URL -> web) and runs the best available provider. With no external engine it still returns the builtin baseline and says what an engine would add.
2. **`lowrea doctor`** diagnoses the whole environment in one command: for every target family and provider, ready / missing / unsupported-host, the exact missing item, and the one command or link to fix it. `--provider ID` and `--task "<goal>"` narrow it. Never installs anything.
3. **Short, consistent CLI:** `analyze, search, function, decompile, xrefs, trace, instructions, providers, capabilities, doctor, setup, update, evidence-import, evidence-export, compare` (REA's verbs) plus per-family commands named exactly like the tool (`inspect-go-binary`, `list-adb-devices`). `--help` shows one worked example per command. Shell completion.
4. **Tool profiles** (`core`, `native`, `web`, `mobile`, `managed`, `runtime`, `all`) so clients with tool-count or schema-size limits load a subset. Default profile is `core`; `setup` picks per client. Descriptions are short; heavy docs live in the skill and references.
5. **Summary-first defaults:** every list/search returns a compact summary plus a retained-Evidence handle and `next_offset`; full detail is one `inspect_analysis_view` call away.
6. **Errors that fix themselves:** every typed error includes `code`, `what_was_tried`, `partial_observations`, and a `remediation` the agent can act on without asking the human.
7. **Setup for every agent REA supports (21 clients):** claude_code, claude_desktop, codex, cursor, gemini_cli, windsurf, devin, opencode, antigravity, copilot_cli, commandcode, qwen_code, vscode, grok_build, omp, pi, hermes, qoder, trae, zcode, dsh. `lowrea setup` is interactive or `--client X --yes`: detect installed clients, print a read-only plan with paths and backups, require approval, idempotent, installs the MCP entry plus skill. Also `update`, `uninstall`, skill-only install, and manual MCP registration docs.
8. **Guided recipes:** ship REA's six MCP prompts (`investigate_feature`, `compare_application_versions`, `verify_reconstruction`, `trace_crash`, `audit_residual_unknowns`, `prepare_bounded_process_capture`) plus CLI equivalents (`lowrea recipe <name>`). Prompts are starting points, never required; prompt arguments are untrusted data.
9. **Snapshots:** `--snapshot FILE` reuses a saved analysis for repeated queries; stale or tampered snapshots are rejected, not silently used.
10. **Windows is a first-class tested lane**, not experimental: path handling, PE/Windows Ghidra, ProcDump/WinDbg-free crash inspection from minidumps where feasible, PowerShell-friendly examples. Document each unsupported combination plainly.
11. **5-minute quick start** in the README that works with no external engine, and a "what is and is not verified" section.
12. **Stable exit codes:** 0 completed (may include partial evidence/unknowns), 1 could not complete, 128+N signal.

# 9. WHERE LOWREA MUST BE MEASURABLY BETTER **[NEW]** (no unmeasured claims)

1. **Builtin baseline engine** with no external dependency: function discovery (symbols, exports, entry, call targets, prologue heuristics, `.eh_frame`/`.pdata`/unwind), CFG, call graph, xrefs (calls, jumps, RIP-relative, absolute immediates, ARM64 `adrp+add/ldr`, ARM `ldr =lit`), PLT/GOT/IAT/lazy-stub resolution, jump-table recovery, string/data refs. Every heuristic result is `inferred` with its method in `limitations`.
2. **Wide architectures:** x86, x86-64, ARM, ARM64, MIPS, RISC-V, PowerPC, 16-bit DOS MZ/COM with explicit load-image check. Raw blobs need caller-supplied arch/endianness/base/entry; a guess is reported as inferred.
3. **One cross-layer Evidence graph:** link a website request -> JS module -> Electron IPC -> native add-on -> instruction-level function via `evidence_links`. Test on a fixture Electron app with a native add-on.
4. **Bounded emulation** (`emulate_function`, Unicorn): registers, memory, stop conditions, instruction/time limits, no host syscalls. Declared effect `emulation`. Returns deltas, visited blocks, trace as `derived`.
5. **Differential verification harness:** run a caller-supplied reimplementation against the original via emulation or observed I/O; report exactly which cases were compared (N cases, byte-exact where applicable). Coverage claims limited to declared comparables, never "global equivalence".
6. **Binary diffing** with per-match confidence and explicit unmatched lists (matched/changed/added/removed).
7. **Signatures/patterns** from caller-supplied libraries (no bundled proprietary signatures), masked-instruction search; **light type/struct recovery** (inferred; DWARF/PDB read by the owning parser when present).
8. **General deobfuscation detection only:** control-flow-flattening detection, opaque-predicate candidates, string decoding for caller-identified routines via emulation.
9. **Hardening and risk report** (PIE/NX/RELRO/canary/CET/CFG/ASLR, dangerous imports, unsafe call sites): candidates, not findings.
10. **Language awareness:** Rust, Go, Swift, ObjC, .NET NativeAOT detection, demangling, metadata-observed vs inferred.
11. **Crash triage** from core/minidump/recorded crash with no live attach implied by a historical PID.
12. **Reproducible token benchmark harness:** same investigation through LowREA (and REA only if actually run), reporting tool-call count, response bytes, estimated tokens, wall/CPU time, peak memory, cold vs warm. Without it, no "faster" or "smaller" claims.

# 10. AGENT-FACING LAYER **[REA]**

- Skill `reverse-engineer-anything/SKILL.md` plus `references/` (native-and-artifacts, web-and-javascript, mobile-and-managed, evidence-workflows, runtime-observation, connection-and-recovery). Teaches: route by target type; call tools directly when connected; summary-first with retained views; separate observation/inference/unknown; keep a finding ledger (conclusion, evidence IDs, confidence, search boundary, remaining unknowns); revisit the checklist before finishing; close sessions; runtime only when static evidence cannot answer.
- Advertised JSON Schemas validate against their dialect after SDK conversion. Handlers bind to named contracts. Catalog ordering never selects an operation.
- Generated machine-readable tool catalog (`docs/lowrea/product-catalog.json`) produced from code; CI diffs it. `binary_session` stays the authority for a running server.

# 11. RUNTIME SAFETY CONTRACT

Every runtime-capable tool (process, debugger, emulator, browser, adb, Frida) must:
1. Require explicit target identity (path + SHA-256, PID with start-time identity, device serial, URL/origin) and an explicit action.
2. Declare effects (`process-launch`, `process-attach`, `memory-write`, `emulation`, `filesystem`, `network`, `device-modify`) in tool metadata and in Evidence `environment`.
3. Run supervised: process group, deadline, bounded output, private temp root, cancellation.
4. Report cleanup status separately from observations; observations survive cleanup failure.
5. State plainly that capture is **not a sandbox** and runs with the caller's permissions; recommend VM/container isolation and record `isolation`.
6. Destructive device actions (uninstall, push over existing file, settings writes) need a separate explicit authority flag, off by default.

# 12. TESTING AND VERIFICATION

- Prefer real public CLI/MCP workflows first, then production-boundary integration tests, producer goldens, then module tests.
- Fixtures compiled or generated at test time: C/Rust/Go for x86-64 (PIE/non-PIE, stripped/unstripped, -O0/-O2), cross-compiled ARM64/RISC-V under QEMU if available, a small Electron-style app directory with a native add-on stub, a tiny APK-shaped fixture, a .NET assembly, a WASM module, a HAR file, a raw DOS image. Never commit binaries.
- Every provider has a **real-engine lane** (skipped with a clear reason if absent) and a **fake lane**. Simulated providers never establish real-provider behavior; say which lane passed.
- Cover malformed input, truncation, cancellation, cleanup failure, permission denial, capacity limits, target-identity change.
- `hypothesis` property tests for address parsing, canonical digests, Evidence round-trip, bundle tamper detection.
- **Readiness verifier:** staged conformance: discover/classify, diagnose-environment, acquire-authority (denial launches nothing), static-analysis (ambiguity/truncation/unknowns preserved), runtime scenarios with cleanup, compare, preserve-contradictions, replay (stale/tampered bundle rejected). Compact JSON summary, optional full report.
- **End-to-end acceptance tasks (MCP-only, in CI):**
  a. Find where a string is used in a native binary and explain the check.
  b. Trace an Electron renderer API through preload and IPC into main and a native add-on.
  c. Recover a small arithmetic helper from instructions, reimplement it, verify with the differential harness.
  d. From a HAR, identify an endpoint, payload shape and the JS source location that issues it.
  e. From an APK fixture, list manifest components and trace one method to its callers.
  f. Recover a 16-bit DOS routine from a raw image with caller-supplied load parameters.
- CI: lint, type-check, unit, integration, docs check, catalog diff, readiness verifier, host suite unchanged.

# 13. MILESTONES (in order; after each: run all tests, update docs and PARITY.md, write a status note: Verified / Unverified / Known limits / Next)

- **M0 Foundation:** Phase 0 (HOST.md, baseline host tests), module scaffold, wiring points, docs skeleton, domain Evidence + canonical digest + typed errors + `Result`, process supervision. *Accept:* Evidence round-trips; equal facts give equal IDs; a spawned child is cleaned up or reported retained; host suite identical to baseline.
- **M1 Builtin static engine:** session tools, segments/names/procedures/strings, `read_bytes`, instructions, xrefs, call graph, PLT/IAT, CFG, `lowrea analyze` auto-routing, `doctor`. *Accept:* every function found or reported unknown; calls resolve to `name@plt`; string search leads to its referencing function; stripped binaries degrade honestly.
- **M2 Evidence/session layer:** views, bundles (export/import/compare), unknown registry, `artifact_changed`, paging, snapshots. *Accept:* oversized result retained and read through views without re-analysis.
- **M3 Offline inspectors:** ELF layout/mitigations, Mach-O, PE resources/signature, Go, WASM, EVM, crash cores, firmware regions, Rust/Swift/ObjC metadata. *Accept:* raw ranges and SHA-256 reported; "absent" never claimed from missing metadata.
- **M3b JS/Electron + web/HAR.** **M3c .NET/managed.** **M3d Android/Flutter/JEB/Apktool + adb.** **M3e Apple bundles/packages/archives.** Same acceptance bar as M3 plus the matching acceptance task.
- **M4 Ghidra provider:** headless import to ephemeral DB, decompiler dossier (`analyze_function`), references, call graph, startup deadline (env-configurable), cleanup. *Accept:* same contracts as builtin; provider identity and limits reported; no fallback.
- **M5 CLI + MCP + skill + setup + prompts + profiles:** all tools through both adapters with parity tests; 21-client setup; tool profiles. *Accept:* an agent completes acceptance task (a) using only MCP; CLI/MCP produce equal Evidence.
- **M6 Runtime layer:** process capture, `observe_native_calls` (GDB/LLDB), browser/web observation, adb, Frida (optional), bounded emulation. *Accept:* denial launches nothing; cancelled runs report cleanup; emulator never touches the host.
- **M7 Compare and reconstruct:** function/artifact/bundle comparison, diffing, `find_changed_behavior`, obligation ledger, coverage, differential harness. *Accept:* two builds with one changed function produce exactly that delta; incomplete frontier gives `unknown`, not "no change".
- **M8 More engines and benchmarks:** rizin and IDA adapters, extra architectures, signatures, type recovery, token benchmark harness. *Accept:* published cold/warm numbers with methodology and limits.

# 14. HOW TO WORK

- Read before writing. Inspect existing contracts and the nearest tool before adding one. Extend a tool when intent and result match; add one only for a distinct outcome or authority.
- Every new tool needs: input and output schema, one worked example, CLI command, MCP registration, tests (success, malformed, unavailable, cancelled, partial), doc entry, PARITY.md row. All in the same change.
- Fix bugs at the producing boundary, not the downstream symptom; delete superseded code.
- No abstractions until they remove observed complexity; no compatibility layers for code with no users.
- Every host-file edit needs a stated reason in HOST.md.
- If a request, example or dependency would cross section 3, stop, record it in `docs/lowrea/SCOPE.md`, and ask.

# 15. FINAL DELIVERABLES

A module that passes its own checks, the readiness verifier AND the unchanged host suite, with: MCP server and CLI, builtin engine, Ghidra provider, runtime layer, skill and setup flow, PARITY.md (every REA tool accounted for), HOST.md (every touched host file plus rollback steps), DESIGN.md, SCOPE.md, DISCLAIMER.md, AGENTS.md, provider capability matrix stating exactly what each engine covers, benchmark report, generated tool catalog, and a README section with the 5-minute quick start and an honest "what is and is not verified" list.
