# Credential vault

Each workspace has an independent vault. Initialize it with a master passphrase of at least 12 characters. The master passphrase is never saved. Fernet encrypts the complete credential record; PBKDF2-HMAC-SHA256 uses 600,000 iterations, a random 32-byte salt and a 32-byte derived key. KDF parameters and the encrypted verification marker are stored beside ciphertext.

Unlocking creates a random 256-bit opaque session token. Only its SHA-256 digest is held in the workspace-bound server session and comparisons are constant-time. Its maximum lifetime is 15 minutes; five minutes without a protected vault operation locks the vault sooner. Status polling does not count as activity. Lock, workspace switch, password change and application shutdown revoke access and discard keys and temporary candidates. Python does not guarantee physical zeroization of all previously allocated immutable memory.

**Add temporary candidate** holds the credential in memory. Only **Accept candidate** writes ciphertext to the workspace database. Reveal requires the master passphrase again and clears the displayed secret after 30 seconds or when locked. Password changes re-encrypt all saved records and the check marker in a single database transaction; failures roll back and preserve the old password.

**Export plaintext** is a separate, confirmed action requiring reauthentication and a user-selected filename. It does not create a plaintext artifact inside the profile. Protect that intentionally unencrypted export yourself. Reports never include vault contents. RPC passwords use the OS keyring only when explicitly requested in Settings.

Vault APIs require the normal instance Bearer token. Protected operations additionally require `X-Vault-Token`; neither token belongs in a URL. Shared contracts are in `shared/vault.py`. Reveal and export are read operations with uncached plaintext responses. Candidate and unlock replay records are memory-only. Accepted credential mutations persist only identifiers and status, never plaintext values. Locked or revoked access returns HTTP 423.

Failed unlock attempts impose an in-memory, per-workspace retry cooldown of 1, 2, 4, 8, 16, 32, then 60 seconds. Success resets it. Cancelling a waiting request does not clear its cooldown. Password derivation runs outside the shared vault lock; a workspace-specific gate serializes password operations. Lock or workspace switch invalidates pending unlocks before they can grant access. Error responses do not disclose attempt counts or distinguish unknown workspaces from wrong passwords.

