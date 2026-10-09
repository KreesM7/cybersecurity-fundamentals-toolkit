# Workspaces, targets and activity

Use **Workspaces** to create, switch or delete inactive workspaces and save notes. Switching preserves the original workspace on running jobs, launched modules, sessions and generated artifacts. Deletion is explicit and refuses the active workspace or storage still leased by an in-flight operation; deleting saved records does not terminate an externally managed framework.

**Targets** provides create/edit/delete, status and notes, a validated port list, bounded CIDR expansion, Nmap XML import, JSON/CSV/Nmap export and transfer to RHOSTS. Imports reject external entities and malformed documents. Exports are managed artifacts and use the same authenticated Save As path as generated files.

**Sessions / Jobs / Console** polls live snapshots once per second while visible. Local jobs remain available when Metasploit is offline. Unassigned remote jobs and sessions must be explicitly imported into a workspace before control is allowed. Sessions created by known launches are associated through their framework execution identifier. Existing associations never move on a workspace switch; another framework's numeric IDs cannot be used with stale controls.

Select a session and open its shell/Meterpreter terminal, or open a workspace-specific framework console. Commands are explicit, carry stable request IDs and are never retried after an unknown outcome. Stop actions require confirmation. Closing a terminal view does not terminate a remote session; closing an API console destroys only that owned console. Closing the app prompts before terminating activity in its owned fallback process.

Terminal output is bounded to 10,000 lines per stream, with at most 32 retained streams and 16 open consoles. Terminal reads use a sequence cursor; older discarded output is labeled. Live output remains in memory and is returned only through authenticated REST. Events contain status metadata, not terminal output. Persisted history contains a safe command name and an explicit argument-redaction marker; arbitrary commands and arguments are never saved. Known secret patterns are also redacted from live output. This deliberately makes history unsuitable for replaying commands with credentials.

WebSocket disconnection or queue overflow triggers bounded reconnect backoff and REST reload; mutations are never replayed as part of reconnection. Manual Refresh is always available. The **Artifacts** screen lists saved files and downloads them through Save As without opening or executing their contents.

API contracts: `shared/activity.py`; `/api/v1/activity` snapshots; `/claim`, `/stop`, `/console`, `/console/close`, `/command`, `/output`, and `/history`. Every state-changing request requires `X-Request-ID`, and terminal actions also require their captured workspace and framework IDs.
