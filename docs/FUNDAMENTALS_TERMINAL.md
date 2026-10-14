# Fundamentals tool terminals

Open any of the seven fundamentals pages, then select **Open in Terminal** below
the description. **Return to GUI** restores the form. Both views share the same
background jobs, results, cancellation, and Clear behavior. These are in-app tool
command consoles; native shells for external tools remain on the SecDesk page.

Press Enter or **Execute command**. Available commands:

| Command | Behavior |
|---|---|
| `help` | Show an example for the current tool |
| `run` | Run using the current GUI settings and selected file |
| `run {JSON}` | Run using explicit options for the current tool |
| `cancel` | Cancel the current tool job |
| `clear` | Clear the command and session results; passwords are also cleared |

Examples:

```text
run {"text":"Hello", "shift":3, "decrypt":false}
run {"password":"example-only"}
run {"target":"127.0.0.1/32"}
run {"url":"http://127.0.0.1:8000/", "operation":"discover"}
run {"file":"C:/captures/requests.csv", "threshold":100}
run {"file":"C:/captures/traffic.csv", "baseline_bins":30, "threshold":3}
run {"file":"C:/captures/sample.pcap"}
```

Use each example in its matching tool. File paths can contain spaces; use forward
slashes on Windows or escape backslashes inside JSON. If `file` is omitted, file tools
use the GUI selection. Choose `help` before sending a command for a network tool.
Opening Terminal itself never starts analysis or network traffic.

SQL discovery returns a `discovery_id`, `generation`, and form details. To test, send
`operation: "test"`, the same URL and discovery identifiers, `form_index`, and the
edited `fields` list. POST uses the existing `allow_post` setting. The GUI form editor
can also build the test request.

Commands are cleared after submission, never echoed, and have no saved history.
Password commands are masked. Validation errors display no submitted values.
Optional native dependencies remain necessary for their underlying tools.
