# SecDesk development resource ownership

Before any source edit, dependency change or rebuild, close the running dev instance. This includes an instance Krees is using. Close it normally so owned terminals, packet-capture handles, serial connections and backend listeners finish cleanup. Do not kill unrelated native tools, production instances or services. Confirm the dev process exited before writing files. Keep it closed through the edit; restart after the edit to verify the result.

For automated checks, use `python -m toolkit --self-test` with its disposable profile. For visible development use `python -m toolkit --profile work/secdesk-dev`. Stop that dev instance before further changes. Existing installed releases and user profiles remain separate.

SecDesk owns explicitly launched native processes and PTYs until cleanup completes. Its doctor only observes local metadata; serial detection never opens a port. Firmware actions remain disabled. GUI fixtures use temporary profiles; the visible dev instance uses an isolated profile so schema changes cannot affect the installed release or the only copy of a vault. Back up before promoting source changes to a production profile.
