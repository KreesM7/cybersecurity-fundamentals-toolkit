"""All input assistance, examples and tool guides. No secret values enter help copy."""

from dataclasses import dataclass

from shared.modules import OptionSpec


@dataclass(frozen=True)
class FieldHelp:
    title: str
    what: str
    example: str
    wrong: str = "Check the value and try again; invalid input is rejected."

    def tooltip(self) -> str:
        return f"{self.what} Example: {self.example}. {self.wrong}"


# Attribute keys are stable across view extraction and dynamic form creation.
FIELDS = {
    "page_search": FieldHelp(
        "Find page", "Type a page name and press Enter to open it.", "Password Strength"
    ),
    "workspace_name": FieldHelp(
        "Workspace name",
        "Name this separate set of targets, notes and reports.",
        "Training lab",
        "Use 1 to 100 characters.",
    ),
    "subnet": FieldHelp(
        "IPv4 subnet",
        "Enter an authorized CIDR with at most 256 addresses.",
        "192.168.1.0/24",
        "Invalid or oversized subnets are rejected.",
    ),
    "query": FieldHelp(
        "Find modules", "Enter part of a framework module name, then search.", "scanner/http/title"
    ),
    "search": FieldHelp(
        "Find payloads", "Filter the installed framework catalog by name.", "linux/x64"
    ),
    "source": FieldHelp("Input text", "Enter practice text to transform.", "Hello, World!"),
    "shift": FieldHelp("Shift", "Choose how many ASCII letters to move, from 1 to 25.", "3"),
    "decrypt": FieldHelp(
        "Decrypt", "Reverse the chosen shift instead of encrypting.", "Enabled for Khoor"
    ),
    "password": FieldHelp(
        "Password",
        "Enter a practice password; do not reuse a real account password.",
        "correct horse battery staple",
    ),
    "passphrase": FieldHelp(
        "Vault passphrase",
        "Enter the master passphrase used to encrypt this workspace vault.",
        "A unique multi-word passphrase",
        "A wrong passphrase leaves the vault locked; wait before retrying.",
    ),
    "address": FieldHelp("IPv4 address", "Enter one authorized IPv4 target.", "192.168.1.10"),
    "target": FieldHelp(
        "Target",
        "Choose or enter a target you have permission to assess.",
        "192.168.1.10 or 192.168.1.0/24",
    ),
    "hostname": FieldHelp(
        "Hostname", "Optional descriptive host name for the saved target.", "lab-web"
    ),
    "ports": FieldHelp(
        "Ports",
        "Optional JSON list describing known ports.",
        '[{"port":80,"protocol":"tcp","service":"http"}]',
    ),
    "host": FieldHelp(
        "Host address", "Enter the reachable address for this local lab connection.", "127.0.0.1"
    ),
    "port": FieldHelp("Port", "Enter a TCP port between 1 and 65535.", "4444"),
    "url": FieldHelp(
        "Target URL",
        "Enter the URL of a web application you are authorized to test.",
        "http://127.0.0.1:8000/",
    ),
    "file_path": FieldHelp(
        "Input file", "Choose a saved file; the upload limit is 25 MiB.", "traffic.csv"
    ),
    "interfaces": FieldHelp(
        "Target routing",
        "Choose a detected interface or system routing for the entered target.",
        "Ethernet: 192.168.1.10",
    ),
    "threshold": FieldHelp(
        "Threshold", "Choose the cutoff above which a result is flagged.", "100 requests per second"
    ),
    "interval": FieldHelp("Bin duration", "Group events into bins of this many seconds.", "1"),
    "baseline": FieldHelp(
        "Baseline bins",
        "Compare each bin with this many preceding bins.",
        "30",
        "Too few bins produce an insufficient-baseline result.",
    ),
    "notes": FieldHelp(
        "Notes",
        "Enter observations for this workspace or target; review before sharing.",
        "Lab web server; assessment approved",
    ),
    "title": FieldHelp(
        "Report title", "Enter a descriptive heading for the generated report.", "Lab assessment"
    ),
    "format": FieldHelp(
        "Output format", "Choose a format supported by the installed tool.", "html for a report"
    ),
    "encoder": FieldHelp(
        "Encoder", "Choose an installed encoder or None; encoding does not imply evasion.", "None"
    ),
    "iterations": FieldHelp(
        "Encoding iterations", "Choose the number of encoder passes, from 1 to 10.", "1"
    ),
    "payload": FieldHelp(
        "Payload",
        "Choose from the installed or compatible payload catalog.",
        "linux/x64/shell_reverse_tcp",
    ),
    "kind": FieldHelp("Module type", "Limit search to a framework module category.", "auxiliary"),
    "rank": FieldHelp(
        "Module rank", "Filter by the framework reliability classification.", "normal"
    ),
    "platform": FieldHelp("Platform", "Filter the installed catalog by target platform.", "linux"),
    "saved": FieldHelp(
        "Saved modules",
        "Choose a favorite or recently used module.",
        "auxiliary/scanner/http/title",
    ),
    "workspaces": FieldHelp(
        "Workspace", "Choose a workspace to activate or manage.", "Training lab"
    ),
    "workspace": FieldHelp(
        "Workspace", "Choose the workspace whose data you want to view.", "Training lab"
    ),
    "service": FieldHelp(
        "Service",
        "Name the service associated with this temporary credential candidate.",
        "lab-web",
    ),
    "username": FieldHelp("Username", "Enter the credential account name.", "lab-user"),
    "user": FieldHelp(
        "RPC username", "Enter the username configured in your MSF RPC service.", "msf"
    ),
    "secret": FieldHelp(
        "Credential secret",
        "Enter a candidate secret; it is saved only after explicit acceptance.",
        "A lab-only credential",
    ),
    "revealed": FieldHelp(
        "Revealed credential",
        "Temporarily displayed credential; it clears automatically.",
        "A stored lab credential",
    ),
    "command": FieldHelp(
        "Advanced command",
        "Send a command to the explicitly opened terminal. Maximum 65,536 characters.",
        "help",
        "Commands can change remote state. Check uncertain outcomes before retrying.",
    ),
    "forms": FieldHelp(
        "Selected form", "Choose one discovered form to inspect and test.", "GET /search"
    ),
    "fields": FieldHelp(
        "Form values", "Edit ordinary field values used for baseline requests.", "q = sample"
    ),
    "theme": FieldHelp(
        "Appearance", "Choose dark, light, or the operating system preference.", "dark"
    ),
    "owned": FieldHelp(
        "Ownership confirmation",
        "Confirm that you own the target or have explicit permission before testing.",
        "Checked only for an approved lab",
    ),
    "post": FieldHelp(
        "Enable POST",
        "Explicitly allow POST for the selected form; it may change application data.",
        "Off for initial GET testing",
    ),
    "show_password": FieldHelp(
        "Show password",
        "Temporarily reveal the practice password on screen.",
        "Off in shared environments",
    ),
    "advanced": FieldHelp(
        "Advanced options",
        "Reveal optional configuration or raw terminal controls.",
        "Off for guided use",
    ),
    "status": FieldHelp("Status", "Choose the observed state of this saved target.", "unknown"),
}

COPY = {
    "collapse": "Collapse or expand navigation; page names remain available as tooltips.",
    "settings": "Open appearance and Metasploit connection settings.",
    "hint": "Tab to a field for guidance. Ctrl+K opens every page.",
    ("empty_console"): (
        "No output yet. Choose a session or module. Open an authorized session, or "
        "review a module before running."
    ),
    ("advanced_warning"): (
        "Advanced console sends commands directly to the opened terminal. Verify "
        "scope and outcomes before retrying."
    ),
    ("artifact"): (
        "Save the redacted display as a local text artifact. This does not add it to "
        "the backend artifact catalog."
    ),
    "required": "Required: enter a value.",
    "number": "Enter a valid number.",
    "review": "Review target and options. Secrets remain hidden. Confirm ownership before Run.",
    "example": "Fill a safe example only. No request runs and ownership remains unchecked.",
    "unknown_option": "The installed framework did not provide an option description.",
    "empty_table": "No rows yet. Refresh or select an item to get started.",
    "output": "Results appear here after an action. Review messages before retrying failures.",
}


def field_help(identifier: str, label: str = "") -> FieldHelp:
    if identifier == "anomaly-detector.threshold":
        return FieldHelp(
            "Z-score threshold", "Flag absolute z-scores strictly above this value.", "3"
        )
    key = identifier.rsplit(".", 1)[-1]
    return FIELDS.get(
        key,
        FieldHelp(
            label or key.replace("_", " ").title(),
            f'Use {label or key.replace("_", " ")} for the current page.',
            "Choose an available value",
        ),
    )


def option_help(option: OptionSpec) -> FieldHelp:
    default = (
        "[hidden]"
        if option.secret
        else str(option.default) if option.default is not None else "none"
    )
    badge = "Required" if option.required else "Optional"
    example = (
        default
        if option.default is not None and not option.secret
        else (
            "127.0.0.1"
            if option.name in {"RHOST", "RHOSTS", "LHOST"}
            else (
                "4444"
                if option.name.endswith("PORT")
                else option.choices[0] if option.choices else "Value described by this module"
            )
        )
    )
    return FieldHelp(
        option.name,
        f'{option.description or COPY["unknown_option"]} ({badge}; default: {default})',
        example,
    )


# Five fixed sections, each guide comfortably below 120 words.
GUIDES = {
    "caesar": (
        "Shift ASCII letters while preserving case and punctuation.",
        "Learn substitution ciphers; never protect secrets.",
        (
            "Enter practice text.",
            "Choose shift and direction.",
            "Run; compare all decryption candidates.",
        ),
        "Hello, World! + shift 3 → Khoor, Zruog!",
        "Only ASCII letters change. This cipher is not secure.",
    ),
    "password-strength": (
        "Estimate guessing effort with zxcvbn and a common-password list.",
        "Compare practice passwords.",
        (
            "Enter a practice password.",
            "Run the estimate.",
            "Review bits and illustrative guessing times.",
            "Clear the field.",
        ),
        "password → common, weak estimate.",
        "72-character maximum. Estimates are not guarantees. Values stay in memory.",
    ),
    "network-scanner": (
        "Check a fixed common TCP port preset with Nmap.",
        "Inventory an authorized lab subnet.",
        (
            "Choose routing.",
            "Enter an IPv4 address or CIDR.",
            "Confirm permission.",
            "Run and review responding versus inconclusive hosts.",
        ),
        "127.0.0.1/32 → open local ports or an inconclusive result.",
        "256-address limit; external Nmap required. No example automatically starts a scan.",
    ),
    "dos-detector": (
        "Count events per source IP per second.",
        "Inspect request bursts in saved logs or packet captures.",
        (
            "Choose requests.csv, access.log, or sample.pcap.",
            "Set the threshold.",
            "Run and inspect flagged sources.",
        ),
        "Bundled requests.csv + threshold 100 → counts above 100 flagged.",
        "Logs count requests; PCAP counts packets. Malformed records mark incomplete analysis.",
    ),
    "sql-checker": (
        "Compare baselines with three quote probes for possible SQL issues.",
        "Check an explicitly authorized web form.",
        (
            "Enter a local lab URL.",
            "Confirm permission and load forms.",
            "Review one form and its values.",
            "Test; inspect evidence.",
        ),
        "http://127.0.0.1:8000/ → forms if your lab is running.",
        (
            "POST is opt-in. Anomalies are not proof. Redirects, size, time and request "
            "limits remain enforced."
        ),
    ),
    "anomaly-detector": (
        "Compare volume and protocol proportions with preceding bins.",
        "Find unusual changes in saved traffic.",
        (
            "Choose traffic.csv or a saved capture.",
            "Set bin size, baseline and threshold.",
            "Run and review z-scores and completeness.",
        ),
        "Bundled traffic.csv → baseline comparisons and possible outliers.",
        (
            "Default: 30 prior one-second bins, threshold 3. Too little data reports "
            "insufficient baseline. Captures require the worker."
        ),
    ),
    "file-type": (
        "Identify MIME type and signature using libmagic.",
        "Check a file whose extension may be misleading.",
        ("Choose a readable file.", "Run identification.", "Compare signature with extension."),
        "Bundled access.log → text MIME type and description.",
        "Native libmagic is required. Identification is not a malware scan.",
    ),
    "modules": (
        "Find and configure installed Metasploit modules.",
        "Assess targets within a written authorization scope.",
        (
            "Find a module.",
            "Complete required options; expand advanced options if needed.",
            "Review the target and options.",
            "Confirm ownership, then Run.",
        ),
        "Search scanner/http/title → matching installed modules.",
        (
            "Framework required. Metadata comes from the installed module. Check Jobs "
            "after uncertain launches; never blindly retry."
        ),
    ),
    "payloads": (
        "Generate an artifact using your installed msfvenom.",
        "Prepare authorized lab exercises.",
        (
            "Find and select a payload.",
            "Choose format and callback address/port.",
            "Review encoder settings.",
            "Confirm permission, generate, and save.",
        ),
        "LHOST 127.0.0.1, LPORT 4444 → lab callback configuration; generation stays manual.",
        (
            "Generated payloads can be dangerous. Do not deploy outside approved scope. "
            "Encoding is not a safety guarantee."
        ),
    ),
}

GUIDE_HEADINGS = (
    "What it does",
    "When to use it",
    "How to use it",
    "Example input + expected output",
    "Limits & safety notes",
)


TOOL_DESCRIPTIONS = {
    ("anomaly-detector"): (
        "Upload UTF-8 logs or CSV with timestamp, source_ip, bytes and protocol. By "
        "default one-second bins compare against the preceding 30 bins; absolute "
        "z-scores above 3 are flagged. At least 31 bins are needed by default. Saved "
        "captures require the separate PCAP worker."
    ),
    ("caesar"): (
        "Shift ASCII letters; preserve case and punctuation. Up to 100,000 "
        "characters. This exercise cipher does not protect sensitive information."
    ),
    ("dos-detector"): (
        "Upload UTF-8 access logs or request CSV. Counts strictly above the threshold "
        "in UTC one-second bins are flagged. A spike alone does not establish an "
        "attack. Saved captures require the separate PCAP worker."
    ),
    ("file-type"): (
        "Identify MIME type and signature from at most the first 1 MiB; compare the "
        "original filename extension. Extension checks are advisory. A file signature "
        "does not establish safety."
    ),
    ("network-scanner"): (
        "TCP connect scans of authorized IPv4 addresses or CIDRs (up to 256 whole "
        "addresses). Selected interfaces require an RFC1918 contained subnet; entered "
        "targets use system routing. Filtered ports leave host presence inconclusive."
    ),
    ("password-strength"): (
        "Local estimator (maximum 72 characters, never truncated). Strength bits are "
        "log2(guesses). Crack times at 10/s, 10,000/s and 10 billion/s are "
        "illustrative. Passwords are sent only to your authenticated local backend "
        "and never saved or logged."
    ),
    ("sql-checker"): (
        "Test only applications you own or have permission to assess. Even benign "
        "POST inputs can change application data. This sends only single, double and "
        "doubled quote probes after two stable baselines; findings are possible "
        "issues, not proof of exploitability."
    ),
}
