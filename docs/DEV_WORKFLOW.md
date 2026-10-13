# SecDesk development resource ownership

Before any source edit, dependency change or rebuild, close the running dev instance. This includes an instance Krees is using. Close it normally so owned terminals, packet-capture handles, serial connections and backend listeners finish cleanup. Do not kill unrelated native tools, production instances or services. Confirm the dev process exited before writing files. Keep it closed through the edit; restart after the edit to verify the result.

For automated checks, use `python -m toolkit --self-test` with its disposable profile. For visible development use `python -m toolkit --profile work/secdesk-dev`. Stop that dev instance before further changes. Existing installed releases and user profiles remain separate.

The initial SecDesk slice opens no capture devices, serial ports or native tool processes. Its doctor only locates executables. The existing authenticated backend owns its request threads and shutdown. Native launch/PTY lifecycle and hardware protocol work remain unverified and are not offered as actions yet.
