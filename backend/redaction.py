"""One redaction policy for framework output, event/history fields and reports."""

from __future__ import annotations

import logging
import re
import traceback
from collections import Counter
from typing import Any

from pydantic import JsonValue

REDACTED = "[REDACTED]"
_NAME = (
    r"[A-Za-z0-9_]*(?:password|passwd|passphrase|secret|authorization|private_key|"
    r"ntlm|smbpass|sshpass|dbpass|pass|token|api[_-]key|access_key|credential_value)"
    r"[A-Za-z0-9_]*"
)
_KEY = re.compile(r"(?<![A-Za-z0-9])" + _NAME + r"(?![A-Za-z0-9_])", re.IGNORECASE)
_ASSIGNMENT = re.compile(r"(?im)((?<![A-Za-z0-9])" + _NAME + r"[ \t]*[:=][ \t]*)([^\r\n]*)")
_SET = re.compile(r"(?im)((?<![A-Za-z0-9])setg?[ \t]+" + _NAME + r"[ \t]+)([^\r\n]*)")
_JSON = re.compile(r'(?i)("' + _NAME + r'"\s*:\s*)"(?:\\.|[^"\\])*"')
_USERINFO = re.compile(r"://[^/@\s]+:[^/@\s]+@")
_HEADERS = re.compile(
    r"(?im)((?<![A-Za-z0-9_-])(?:Cookie|Set-Cookie|X-Vault-Token|X-Api-Key)"
    r"[ \t]*:[ \t]*)[^\r\n]*"
)
_JWT = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
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
        bounded = value
        for secret in sorted(self._secrets, key=len, reverse=True):
            bounded = bounded.replace(secret, REDACTED)
        bounded = _PRIVATE_KEY.sub(REDACTED, bounded)
        bounded = _NTLM_PAIR.sub(REDACTED, bounded)
        bounded = _JWT.sub(REDACTED, bounded)
        bounded = _USERINFO.sub("://" + REDACTED + "@", bounded)
        bounded = _JSON.sub(lambda match: match.group(1) + '"' + REDACTED + '"', bounded)
        for pattern in (_HEADERS, _SET, _ASSIGNMENT, _BEARER):
            bounded = pattern.sub(lambda match: match.group(1) + REDACTED, bounded)
        return bounded[:10000]

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


def install_logging_redaction() -> None:
    """Sanitize records before any handler formats messages or exception tracebacks."""
    previous = logging.getLogRecordFactory()
    if getattr(previous, "toolkit_redaction", False):
        return
    redactor = Redactor()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = previous(*args, **kwargs)
        record.msg = redactor.text(record.getMessage())
        record.args = ()
        if record.exc_info:
            record.exc_text = redactor.text("".join(traceback.format_exception(*record.exc_info)))
            record.exc_info = None
        elif record.exc_text:
            record.exc_text = redactor.text(record.exc_text)
        if record.stack_info:
            record.stack_info = redactor.text(record.stack_info)
        return record

    setattr(factory, "toolkit_redaction", True)
    logging.setLogRecordFactory(factory)
