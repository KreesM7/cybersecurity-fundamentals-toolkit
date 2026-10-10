import io
import logging
import traceback

import pytest

from backend.events import EventHub
from backend.redaction import REDACTED, Redactor

SECRETS = [
    ("client_secret=x", "x"),
    ("db_password: x", "x"),
    ("PGPASSWORD=x", "x"),
    ("aws_secret_access_key=x", "x"),
    ("admin_pass=x", "x"),
    ('"password": "x"', '"x"'),
    ("https://user:pw@host", "user:pw"),
    ("Cookie: session=private-cookie", "private-cookie"),
    ("Set-Cookie: session=private-cookie; HttpOnly", "private-cookie"),
    ("X-Vault-Token: private-vault", "private-vault"),
    ("x-api-key: private-api", "private-api"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature", "eyJhbGci"),
    ("set DB_PASSWORD hidden-value", "hidden-value"),
    ("setg ADMIN_PASS hidden-value", "hidden-value"),
    ('{"client_secret": "hidden\\"value", "ok": true}', "hidden"),
]


@pytest.mark.parametrize("text,secret", SECRETS)
def test_confirmed_secret_formats(text, secret):
    result = Redactor().text(text)
    assert REDACTED in result
    assert secret not in result


@pytest.mark.parametrize(
    "text",
    [
        "Password strength is estimated.",
        "Token expiry occurs after fifteen minutes.",
        "The secret garden is open.",
        "https://example.com/path?q=value",
        "user@example.com",
        "Set target 192.168.1.1",
        "Cookie settings are disabled.",
        '{"status": "ready", "count": 3}',
        "Scan completed: 12 hosts.",
        "Database connection failed without credentials.",
    ],
)
def test_plain_text_unchanged(text):
    assert Redactor().text(text) == text


def test_prefixed_dictionary_keys():
    assert Redactor().clean({"PGPASSWORD": "hidden", "admin_pass": "hidden"}) == {
        "PGPASSWORD": REDACTED,
        "admin_pass": REDACTED,
    }


@pytest.mark.asyncio
async def test_activity_traceback_redacted():
    hub = EventHub()
    try:
        raise RuntimeError("client_secret=hidden-secret")
    except RuntimeError:
        await hub.publish("activity", {"traceback": traceback.format_exc()})
    assert "hidden-secret" not in hub.recent[-1].model_dump_json()


def test_exception_logging_redacts_message_and_traceback():
    from backend.redaction import install_logging_redaction

    previous = logging.getLogRecordFactory()
    output = io.StringIO()
    logger = logging.getLogger("toolkit.redaction-test")
    handler = logging.StreamHandler(output)
    logger.addHandler(handler)
    try:
        install_logging_redaction()
        try:
            raise RuntimeError("db_password: hidden-error")
        except RuntimeError:
            logger.exception("client_secret=%s", "hidden-message")
        assert "hidden-error" not in output.getvalue()
        assert "hidden-message" not in output.getvalue()
        assert "RuntimeError" in output.getvalue()
    finally:
        logger.removeHandler(handler)
        logging.setLogRecordFactory(previous)
