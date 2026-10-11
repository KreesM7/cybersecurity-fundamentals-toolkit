"""One redaction policy for framework output, event/history fields and reports."""

from __future__ import annotations

import json
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
# Consume identifiers once, then classify them. Searching the prefixed secret-name
# expression at every underscore creates quadratic work on untrusted log output.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_]+(?:-key)?", re.IGNORECASE)
_ASSIGNMENT = re.compile(r"(?im)(?<![A-Za-z0-9])(?<![_-])(?P<key>[A-Za-z0-9_-]+)[ \t]*[:=][ \t]*")
_SET = re.compile(r"(?im)(?<![A-Za-z0-9])(?<![_-])setg?[ \t]+(?P<key>[A-Za-z0-9_-]+)[ \t]+")
_JSON_STRING = re.compile(r'"(?:\\.|[^"\\])*"')
_SPACE = re.compile(r"\s*")
_JSON_DECODER = json.JSONDecoder()
_LINE_END = re.compile(r"[\r\n]")
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


def _sensitive_key(value: str) -> bool:
    return any(_KEY.fullmatch(match.group()) for match in _IDENTIFIER.finditer(value))


def _redact_json(value: str) -> str:
    pieces: list[str] = []
    cursor = scan = 0
    while (start := value.find('"', scan)) >= 0:
        # Anchor at the next quote and consume the entire token, even when it is
        # not a key. Restarting at every escaped quote makes malformed text quadratic.
        match = _JSON_STRING.match(value, start)
        if match is None:
            break
        scan = match.end()
        space = _SPACE.match(value, scan)
        assert space is not None
        colon = space.end()
        if colon >= len(value) or value[colon] != ":":
            continue
        try:
            key = json.loads(match.group())
        except ValueError:
            continue
        if not _sensitive_key(key):
            continue
        space = _SPACE.match(value, colon + 1)
        assert space is not None
        end = space.end()
        pieces.append(value[cursor:end])
        try:
            _, cursor = _JSON_DECODER.raw_decode(value, end)
        except (ValueError, RecursionError):
            # A malformed/truncated secret value cannot safely be displayed.
            cursor = len(value)
        pieces.append('"' + REDACTED + '"')
        scan = cursor
    pieces.append(value[cursor:])
    return "".join(pieces)


def _redact_fields(value: str, pattern: re.Pattern[str]) -> str:
    pieces: list[str] = []
    cursor = 0
    for match in pattern.finditer(value):
        if match.start() < cursor:
            continue
        if not _sensitive_key(match.group("key")):
            continue
        pieces.append(value[cursor : match.end()])
        end = _LINE_END.search(value, match.end())
        cursor = end.start() if end else len(value)
        pieces.append(REDACTED)
    pieces.append(value[cursor:])
    return "".join(pieces)


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
        bounded = _redact_json(bounded)
        for pattern in (_SET, _ASSIGNMENT):
            bounded = _redact_fields(bounded, pattern)
        for pattern in (_HEADERS, _BEARER):
            bounded = pattern.sub(lambda match: match.group(1) + REDACTED, bounded)
        return bounded[:10000]

    def clean(self, value: JsonValue) -> JsonValue:
        if isinstance(value, dict):
            return {
                key: REDACTED if _sensitive_key(key) else self.clean(item)
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
