# Module browser

Connect through **Settings** using the dedicated RPC certificate and credentials, or start the owned Toolkit-MSF fallback. See [setup](MSFRPC_SETUP.md). The UI sends the password only through authenticated HTTPS and clears the input immediately; saving it uses the OS keyring.

**Modules** searches the installed framework by text, type, rank and platform. Search responses are cached for 60 seconds per framework identity (32 searches); metadata caches hold 128 entries. Results show at most 2,000 matches, with an explicit truncation message. Narrow the query for larger catalogs.

Select a module for its description and editable options. Required fields have an asterisk; boolean and enumerated fields have appropriate editors, descriptions appear as tooltips, and password/token fields are masked. Exploits offer compatible payloads and their options. Favorites and the most recent 50 launches belong to the selected workspace.

Select a saved target and choose **Use as RHOSTS**. Direct target inputs accept a literal IPv4 host or CIDR with at most 256 addresses; framework file lists and implicit range expansion are rejected. Click Run to submit the module. Auxiliary, exploit, post and evasion modules launch here; payloads, encoders and NOPs can be browsed but require generation rather than a module launch.

Launches capture the workspace and framework identity. A stable request ID prevents duplicate execution; conflicting duplicates are rejected and unknown outcomes are never repeated automatically. Refresh/reconcile framework jobs before a new launch after a connection failure. Output displays launch events without recording option values. Persistent launch associations retain only identifiers and status. Active or uncertain owned-console activity requires confirmation before closing; externally managed RPC servers remain running.

API: authenticated `/api/v1/modules/search`, `/info?path=…`, `/library`, `POST /favorites`, `POST /run`; mutation requests require `X-Request-ID`. Shared request/response definitions are in `shared/modules.py`. `/ws/events` streams launch status; REST remains authoritative.
