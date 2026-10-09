# Structured terminal fallback

Provisioning installs a separate terminal host in `/opt/toolkit-msf`, including pinned pexpect4.9.0 and ptyprocess0.7.0. Windows always invokes it through the fixed `Toolkit-MSF` distribution. It starts its own `msfconsole`; it never attaches to, kills or relabels a user's existing console or external daemon.

`POST /api/v1/connection/fallback` requires the private instance token, stable request ID and `{"confirmed":true}`. Disconnect the current connection first. The owned console has a fresh framework UUID; the backend does not silently substitute a new framework after an uncertain outcome. It supports Metasploit6; other major versions fail compatibility checks.

The shipped Ruby resource exposes the same installed Metasploit handlers used by RPC: module catalogs, info/options, execution, sessions, shell/Meterpreter I/O, jobs and console operations. Commands are structured data, not text interpolated into Ruby or shell commands. Console output and replies are separated using a random per-process frame prefix. The host converts them to UTF-8 LF-delimited JSONL:

```json
{"v":1,"type":"ready","id":"framework-uuid","version":"6.5.3"}
{"v":1,"id":"request-uuid","method":"module.options","args":["auxiliary","scanner/http/title"]}
{"v":1,"type":"output","text":"bounded console output"}
{"v":1,"type":"result","id":"request-uuid","data":{}}
{"v":1,"type":"error","id":"request-uuid","message":"Framework operation failed"}
```

Only the request record travels to the host; other records travel back. Replies must match the active request. The backend serializes calls, caps pending calls at32, input at one MiB, replies/console output per request at four MiB, diagnostics at64KiB and startup at60 seconds. Each Ruby operation is bounded to15 seconds; the desktop deadline is20 seconds. Malformed, missing, mismatched or timed-out replies mark execution uncertain; commands are never automatically repeated. Inspect activity before deliberately submitting another request ID.

The host owns its PTY child and terminates/reaps it on input closure, cancellation or failure. A random capability addresses one current-user-only Unix control socket. Windows cancellation addresses that socket inside Toolkit-MSF and waits for the owned host to exit; it never terminates the whole distribution. A failure to confirm shutdown is reported rather than silently claimed successful.

`GET /api/v1/connection/shutdown-check` reports whether owned activity requires confirmation. `POST /api/v1/connection/disconnect` accepts `{"confirmed":true}` to terminate active or uncertain owned activity. Without confirmation it rejects that operation. External RPC disconnect only revokes the client token and leaves the external server running. Desktop close confirmation is wired in the desktop-completion slice.

The native integration test exercises metadata, console I/O, module execution, a real framework shell session with a Python loopback peer, session termination and job termination. The Python peer returns fixture text and never executes OS commands. On a prepared Windows host run it with `TOOLKIT_MSF_INTEGRATION=1`; otherwise missing native prerequisites are explicitly skipped.
