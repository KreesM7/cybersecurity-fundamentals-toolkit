"""One redaction policy for framework output, event/history fields and reports."""

from __future__ import annotations

import re
from collections import Counter

from pydantic import JsonValue

REDACTED = "[REDACTED]"
_KEY = re.compile(
    r"(?:password|passwd|passphrase|secret|authorization|private_key|ntlm|smbpass|"
    r"(?:^|_)token(?:$|_)|api_key|access_key|credential_value)",
    re.IGNORECASE,
)
_ASSIGNMENT = re.compile(
    r"(?im)(\b(?:password|passwd|passphrase|smbpass|sshpass|dbpass|secret|"
    r"access_token|api_key|authorization)[ \t]*[:=][ \t]*)([^\r\n]*)"
)
_SET = re.compile(r"(?im)(\bsetg?[ \t]+\S*(?:pass|password|token|secret|key)[ \t]+)([^\r\n]*)")
_BEARER = re.compile(r"(?i)(\bBearer[ \t]+)[A-Za-z0-9._~+/=-]+")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)
_NTLM_PAIR = re.compile(r"\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b")


class Redactor:
    """Registered secrets stay memory-only and can be removed when their owner closes."""

    def __init__(self) -> None:
        self._secrets: Counter[str] = Counter()

    def register(self, secret: str) -> None:
        if not secret:
            return
        if len(secret) > 65536 or (secret not in self._secrets and len(self._secrets) >= 1000):
            raise ValueError("Secret redaction registry capacity exceeded.")
        self._secrets[secret] += 1

    def unregister(self, secret: str) -> None:
        if self._secrets[secret] <= 1:
            self._secrets.pop(secret, None)
        else:
            self._secrets[secret] -= 1

    def text(self, value: str) -> str:
        bounded = value[:10000]
        for secret in sorted(self._secrets, key=len, reverse=True):
            bounded = bounded.replace(secret, REDACTED)
        bounded = _PRIVATE_KEY.sub(REDACTED, bounded)
        bounded = _NTLM_PAIR.sub(REDACTED, bounded)
        for pattern in (_SET, _ASSIGNMENT, _BEARER):
            bounded = pattern.sub(lambda match: match.group(1) + REDACTED, bounded)
        return bounded

    def clean(self, value: JsonValue) -> JsonValue:
        if isinstance(value, dict):
            return {
                key: REDACTED if _KEY.search(key) else self.clean(item)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self.clean(item) for item in value]
        if isinstance(value, str):
            return self.text(value)
        return value

    def clear(self) -> None:
        self._secrets.clear()
