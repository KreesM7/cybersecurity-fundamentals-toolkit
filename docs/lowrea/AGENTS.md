# LowREA implementation rules

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
