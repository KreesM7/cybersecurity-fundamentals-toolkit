# Credential vault

Each workspace has an independent vault. Initialize it with a master passphrase of at least 12 characters. The master passphrase is never saved. Fernet encrypts the complete credential record. New vaults use Argon2id v19 with 19,456 KiB (19 MiB) memory, two iterations, one lane, a random 32-byte salt and a 32-byte derived key. KDF parameters and the encrypted verification marker are stored beside ciphertext.

Unlocking creates a random 256-bit opaque session token. Only its SHA-256 digest is held in the workspace-bound server session and comparisons are constant-time. Its maximum lifetime is 15 minutes; five minutes without a protected vault operation locks the vault sooner. Status polling does not count as activity. Lock, workspace switch, password change and application shutdown revoke access and discard keys and temporary candidates. Python does not guarantee physical zeroization of all previously allocated immutable memory.

**Add temporary candidate** holds the credential in memory. Only **Accept candidate** writes ciphertext to the workspace database. Reveal requires the master passphrase again and clears the displayed secret after 30 seconds or when locked. Password changes re-encrypt all saved records and the check marker in a single database transaction; failures roll back and preserve the old password.

**Export plaintext** is a separate, confirmed action requiring reauthentication and a user-selected filename. It does not create a plaintext artifact inside the profile. Protect that intentionally unencrypted export yourself. Reports never include vault contents. RPC passwords use the OS keyring only when explicitly requested in Settings.

Vault APIs require the normal instance Bearer token. Protected operations additionally require `X-Vault-Token`; neither token belongs in a URL. Shared contracts are in `shared/vault.py`. Reveal and export are read operations with uncached plaintext responses. Candidate replay records are memory-only. Unlock replay records retain only completion status, never the issued token. A duplicate completed unlock request returns HTTP 409 and asks for a new request ID; it never silently repeats the unlock. Accepted credential mutations persist only identifiers and status, never plaintext values. Locked or revoked access returns HTTP 423.

Failed unlock attempts impose an in-memory, per-workspace retry cooldown of 1, 2, 4, 8, 16, 32, then 60 seconds. Success resets it. Cancelling a waiting request does not clear its cooldown. Password derivation runs outside the shared vault lock; a workspace-specific gate serializes password operations. Lock or workspace switch invalidates pending unlocks before they can grant access. Error responses do not disclose attempt counts or distinguish unknown workspaces from wrong passwords.

## KDF migration and benchmark

The fixed Argon2id parameters follow the [OWASP minimum configuration](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html). At most two native derivations run concurrently; cancellation retains its slot until the native call finishes. Stored parameters are validated before derivation to reject unsupported or excessive costs.

Existing PBKDF2-HMAC-SHA256 vaults with 600,000 iterations remain readable. Successful unlock first creates an owner-only SQLite backup named workspace.pre-argon2-<random>.db (including committed WAL contents), then re-encrypts every credential and the check marker with a fresh Argon2id salt in one transaction. Backup, encryption or commit failure leaves the old vault intact. Wrong passwords never migrate. The encrypted backup retains its old password; keep it protected and remove it only after independently verifying the migrated vault. No user vault was used in migration tests: tests build legacy fixtures and open separate copies, preserving the originals.

Run python scripts/benchmark_vault.py to measure one warmup followed by 20 derivations. CI records median, p95 and maximum on Windows/Ubuntu and Python 3.11/3.12; p95 must remain below 300 ms. Local Windows 11 / Python 3.12.14 measured median 17.516 ms, p95 18.344 ms and maximum 21.918 ms. These are measurements, not a latency guarantee for every computer.

Measured on GitHub-hosted CI hardware in [run 38079453337](https://github.com/KreesM7/cybersecurity-fundamentals-toolkit/actions/runs/38079453337), 2026-10-10, commit `776148a`, using the chosen 19 MiB / t=2 / p=1 configuration:

| Runner | Python | Median (ms) | p95 (ms) | Maximum (ms) |
| --- | --- | ---: | ---: | ---: |
| Windows latest, AMD64 Family 25 Model 1 | 3.11.9 | 27.368 | 30.570 | 37.090 |
| Windows Server 2025, AMD64 Family 25 Model 1 | 3.12.10 | 27.750 | 28.493 | 32.049 |
| Ubuntu 24.04, Linux 6.17 Azure x86_64 | 3.11.17 | 14.782 | 15.692 | 15.711 |
| Ubuntu 24.04, Linux 6.17 Azure x86_64 | 3.12.15 | 19.407 | 20.326 | 20.720 |

All four jobs passed the benchmark and their complete regression suites. CI archives the machine-readable `vault-benchmark.json` alongside coverage results.

## Key lifetime and audit trail

Unlocked sessions retain a mutable 32-byte key buffer, not a long-lived Fernet object. Discard, replacement, password change, expiry, lock and shutdown overwrite that buffer before dropping the session. Operation-local immutable Python and native-library copies may survive until reclaimed; best-effort wiping does not guarantee physical erasure, as described in SECURITY.md.

Unlock success/failure and session expiry emit redacted vault-audit entries into the existing bounded local activity feed and the standard local logger. Entries contain action, outcome and workspace identity only, never passwords, tokens, key material or attempt counts. The activity feed is memory-only and bounded; durable audit retention requires a locally configured logging handler.
