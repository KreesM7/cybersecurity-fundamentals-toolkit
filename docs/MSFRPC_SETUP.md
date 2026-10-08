# Dedicated Metasploit setup

The desktop can open without Metasploit. Connecting requires your own dedicated installation. `OpenClawGateway` is an unrelated existing WSL distribution: the toolkit never provisions, inspects or stops it. Windows setup uses only `Toolkit-MSF`; Linux setup uses a dedicated Ubuntu24.04 host.

## Windows

Enable WSL2 first. Obtain the Ubuntu24.04 rootfs archive and its verified SHA256 from Ubuntu's official signed release manifest. In PowerShell at the project root:

```powershell
.\scripts\Setup-ToolkitMSF.ps1 -Rootfs C:\Downloads\ubuntu-24.04-rootfs.tar.gz -InstallDirectory C:\Toolkit-MSF -Sha256 YOUR_VERIFIED_64_DIGIT_HASH
```

The script verifies the supplied archive before importing the fixed distribution, reuses an existing Toolkit-MSF, and never deletes/reimports it. Provisioning installs signed Metasploit packages, Nmap, libmagic and a separate Scapy worker environment. It does not start a daemon. Run:

```powershell
wsl --distribution Toolkit-MSF --exec python3 /opt/toolkit-msf/start-msfrpc.py
```

Enter a new RPC password at the hidden prompt. Leave that terminal running while connected. Ctrl+C stops only that owned server and its child process group. Do not put the password in shell arguments, environment variables, scripts or configuration files.

The certificate is `~/.toolkit-msf/rpc-cert.pem` inside Toolkit-MSF. Copy only that public certificate to the desktop when setting up trust. Never copy `rpc-key.pem` or `rpc.pem`. WSL localhost forwarding must be enabled; the RPC listener binds only127.0.0.1. Do not expose it through a public firewall rule.

## Native Ubuntu24.04

```sh
sudo bash scripts/provision-linux.sh
python3 /opt/toolkit-msf/start-msfrpc.py
```

Run the server as your ordinary user. `--prepare` generates/renews the certificate without starting a server. The launcher renews missing, expired or near-expiry certificates before binding. After renewal, update the trusted public certificate in the desktop. Private files use0700 directories and0600 files.

The provisioner downloads a pinned Rapid7 installer template solely to extract its reviewed public signing key; it verifies both the file SHA256 and key fingerprint, and never executes that template. Unexpected key rotation fails closed and requires review. System packages follow their signed upstream repository; Scapy is pinned in the independent worker manifest.

## Desktop connection and API

Use HTTPS, host127.0.0.1, port55553 and user `msf`, with the public RPC certificate. The connection API is `POST /api/v1/connection/connect`: `host`, `port`, `username`, `password`, `ca_pem` and `remember_password`. It requires the normal private-instance Bearer token and a fresh `X-Request-ID`. `GET /api/v1/connection` reports readiness; `POST /api/v1/connection/disconnect` revokes the temporary token and leaves an externally managed server running. The Settings panel is delivered in the desktop-completion slice.

Passwords remain in memory unless Remember is selected; remembered passwords are written only to the OS keyring. Linux needs an unlocked supported system keyring for that option. No fallback writes passwords to a file. The server issues temporary tokens with a five-minute idle timeout; the client never requests permanent tokens.

The startup bridge adds an authenticated instance UUID. Reconnection backoff is1/2/4 seconds, capped30; reconnecting to a different framework UUID stops automatically and asks for reconciliation. Stock daemons without the identity bridge are rejected rather than guessing that numeric session IDs belong to the previous instance. RPC calls are serialized, limited to32 pending calls, a15-second total deadline and four MiB responses. Redirects and environment proxies are disabled; certificate and hostname verification stay enabled.

External state-changing operations use durable request IDs and a keyed payload fingerprint. Raw options and passwords are never stored in mutation records. A repeated ID with different input conflicts; a pending/unknown outcome, including after restart, is never executed again automatically. Inspect the recorded framework UUID and its jobs/sessions to determine the outcome before deliberately submitting a new ID. Back up `mutation.key` with the private profile: losing it makes old duplicates conflict rather than allowing a replay.

## Verification

```sh
python -m pytest -q tests/integration/test_native_rpc.py
```

On a prepared native host this test starts a temporary owned loopback server, rejects an untrusted certificate, authenticates using the pinned certificate, lists module metadata, reconnects to the same instance and proves the listener is gone after shutdown. It does not execute modules. A prerequisite skip is not a passing native-lab result.
