# Payload generation

Provision Toolkit-MSF, connect in Settings, and open **Payloads**. Search for a payload, choose its output format and optional encoder, enter LHOST/LPORT and 1–10 encoding iterations, and select **Generate**. Metadata comes from the connected framework; generation uses the dedicated locally installed msfvenom. Keep their versions aligned.

The panel displays bounded progress output, allows cancellation and offers **Save As** when generation succeeds. Save As downloads a workspace-owned artifact over the authenticated API, writes a temporary file beside your chosen destination, then atomically replaces the destination. Nothing generated is executed by the toolkit.

Generation uses a fixed executable and argument list, never a shell command. The independently installed `payload-host.py` accepts one JSON line containing `payload,format,encoder,iterations,lhost,lport`; its stdout emits LF-delimited JSON `progress` messages, base64 `data` chunks and one `end` record with boolean `ok`. It bounds artifacts to 8 MiB, diagnostic output to 64 KiB, and child runtime to 90 seconds. Closing its stdin cancels the operation and kills/reaps only its own process group, including when invoked from Windows through WSL. Failed or incomplete output is not stored.

The backend validates advertised formats, encoders and required payload options before starting. Payloads requiring extra values beyond their defaults and the supplied LHOST/LPORT are rejected by this form. The existing two-worker/32-waiting-job limits apply. Workspace and artifact IDs remain stable when you switch workspaces. Cancellation retains the workspace lease until the generator exits.

API: `GET /api/v1/payloads/catalog`, `POST /api/v1/payloads/generate` (requires stable `X-Request-ID`), ordinary job status/cancel endpoints, `GET /api/v1/artifacts?workspace_id=…`, and `GET /api/v1/artifacts/{id}/download?workspace_id=…`. Artifact names are display data, never user-controlled server paths. Generated artifacts are an explicit saved output and remain in the chosen workspace.
