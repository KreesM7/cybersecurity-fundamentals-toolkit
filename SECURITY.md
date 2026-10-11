# Security policy

Use this application only on systems you own or have explicit authorization to test.
The local API is not a multi-user or remote-host service. Keep the profile readable
only by its owner and keep the OS account secure. Local administrators or malware
running as that user are outside the credential-vault isolation boundary.

Do not post passwords, tokens, TLS private keys, private captures, payload contents
or unredacted framework output in public issues. Use GitHub's private vulnerability
reporting feature when available on this repository. If it is unavailable, open a
minimal issue requesting a private contact channel without including exploit details
or sensitive data. No response-time guarantee is currently provided.

Supported release line: 2.x. Optional update checks are initially off and can be
enabled in Settings; they show new stable releases without installing anything.
Maintain separately installed Metasploit, Scapy, Nmap and libmagic through their
own update mechanisms. A clean tool result is not proof that a target or file is safe.

Vault passwords cannot be recovered. Reports exclude credentials by default;
optional notes and explicit exports still require review before sharing. Pattern-based
redaction cannot identify every possible secret. Same-user memory access and physical
erasure of Python/Qt memory are not guaranteed.

Release security review and its scope are recorded in docs/SECURITY_REVIEW.md.
Installers are unsigned. Verify SHA256SUMS against the GitHub release assets and
review the corresponding source. Releases processed by the Release integrity
workflow also include keyless Sigstore bundles for artifacts and SHA256SUMS;
verify the exact workflow identity and OIDC issuer as documented in
docs/RELEASE_VERIFICATION.md. These detached signatures do not replace native
Authenticode/notarization or remove operating-system warnings. Never disable
TLS validation as a workaround.
