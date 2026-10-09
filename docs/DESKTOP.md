# Desktop controls

Dashboard shows the selected workspace, target and historical session counts, active local
jobs, saved reports, tool readiness, framework connection and vault status. The workspace
selector locks the vault when switching; running jobs retain their original workspace.

Settings → General offers dark, light and system appearance. Changes save after a short
pause, through the authenticated API. Failed saves show an inline retry instruction.
Settings → Metasploit contains connection setup. The first-launch guide can be dismissed.

Shortcuts: **Ctrl+K** opens a searchable page palette; **Ctrl+T** opens Modules;
**Ctrl+L** opens Sessions / Jobs / Console; **Ctrl+S** saves the active workspace's notes;
**F5** refreshes session/job lists. Terminal commands are never silently retried.

Update checks are optional and initially disabled. When enabled, startup performs one
background request to the public GitHub latest-release endpoint, using verified TLS,
no proxies or redirects, a five-second total deadline, a 64 KiB response cap and ETags.
Only newer stable versions produce a dismissible banner. Offline, missing releases and
rate limits stay quiet. Viewing a release opens the fixed repository page; nothing is
automatically downloaded or installed. Disabling checks cancels an in-flight check.
