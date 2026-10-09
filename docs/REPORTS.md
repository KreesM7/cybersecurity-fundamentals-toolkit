# Workspace reports

Reports → Generate creates an escaped HTML summary as a managed workspace artifact.
PDF uses the optional `pip install -e .[pdf]` renderer and its native prerequisites;
if unavailable, the job explicitly reports that it saved HTML instead. Save As exports
the artifact. Reports retain their original workspace even if you switch while rendering.

Each section contains at most 500 targets, recorded framework launches, recorded sessions,
or current in-memory analysis job statuses. These are historical summaries, not raw
findings or a fresh live assessment. Further rows are explicitly described as omitted.
Credentials, command arguments, raw analysis results and terminal output are excluded.
Notes are excluded by default. Including notes is explicit; registered secrets and common
secret labels are redacted, but review free-form text before sharing.

Templates and styles are fixed application code with Jinja autoescaping. No user HTML,
templates, file paths, attachments or external resource URLs are accepted. WeasyPrint
70's URLFetcher rejects every protocol, including file, data, HTTP and redirects.
See the [official renderer API](https://doc.courtbouillon.org/weasyprint/stable/api_reference.html).
