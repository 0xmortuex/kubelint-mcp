"""Deciding whether a name or a value looks like a secret, and describing it without revealing it.

Nothing here ever returns a value. `redacted()` gives the name and the length only.
"""

from __future__ import annotations

import re

_SECRET_WORDS = {"PASSWORD", "PASSWD", "PWD", "SECRET", "TOKEN", "APIKEY", "CREDENTIAL", "CREDENTIALS", "PASSPHRASE"}
_SECRET_PAIRS = {("API", "KEY"), ("PRIVATE", "KEY"), ("ACCESS", "KEY"), ("SECRET", "KEY"), ("AUTH", "TOKEN")}
# A name ending in one of these is a pointer to a secret (a file, a key name), not the secret.
_NOT_SECRET_LAST = {
    "FILE", "PATH", "NAME", "REF", "ENABLED", "ID", "DIR", "KEYNAME", "SECRETNAME", "URL", "ARN",
    "LENGTH", "TTL", "EXPIRY", "TYPE", "MOUNT", "KEYS", "FROM", "NS", "NAMESPACE", "ANNOTATION",
}

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")

_URL_CREDS = re.compile(r"[a-z][a-z0-9+.\-]{0,20}://[^/\s:@]{1,100}:[^/\s@]{1,200}@")
_VALUE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
)
_MAX_SCAN = 4096


def words(name: str) -> list[str]:
    return [w for w in _SPLIT.split(_CAMEL.sub("_", name)) if w]


def is_secret_name(name: str) -> bool:
    ws = [w.upper() for w in words(name)]
    if not ws:
        return False
    if ws[-1] in _NOT_SECRET_LAST:
        return False
    if any(w in _SECRET_WORDS for w in ws):
        return True
    return any((a, b) in _SECRET_PAIRS for a, b in zip(ws, ws[1:]))


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return v == "" or v.startswith(("$(", "${", "{{", "<"))


def secret_value_kind(value: str) -> str | None:
    """Name of the kind of credential `value` looks like, or None. Scans a bounded prefix only."""
    head = value[:_MAX_SCAN]
    for label, pat in _VALUE_PATTERNS:
        if pat.search(head):
            return label
    if _URL_CREDS.search(head):
        return "URL with embedded credentials"
    return None


def redacted(name: str, value: object) -> str:
    n = len(value) if isinstance(value, str) else 0
    return f"{name} ({n} characters, value redacted)"
