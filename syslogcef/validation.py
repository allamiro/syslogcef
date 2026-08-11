"""Validation of CEF extension keys and values against the ArcSight dictionary.

Key metadata — data type, maximum string length, and producer/consumer
scope per key — is loaded from the shared ``dictionary.json`` data file
(see :mod:`syslogcef.dictionary`). Custom keys are permitted by the CEF
standard, so unknown keys produce advisory findings only; type and
length violations are the errors that ``strict`` mode raises on, and
consumer-scope keys in producer output warn without failing.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .dictionary import cef_keys, consumer_keys

# type tags: str (with max length), int, long, float, port, ip (v4/v6),
# ipv6, mac, ts (MMM dd yyyy HH:mm:ss or epoch milliseconds)
_S = "str"

# Loaded from dictionary.json — the single source of truth shared with
# normalization (aliases) and documented in docs/cef_fields.md.
CEF_KEYS: Dict[str, Tuple[str, int]] = cef_keys()
CONSUMER_KEYS = consumer_keys()

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")


class CEFValidationError(ValueError):
    """Raised in strict mode when an extension value violates the dictionary."""


@dataclass
class Finding:
    key: str
    problem: str
    fatal: bool

    def __str__(self) -> str:
        return f"{self.key}: {self.problem}"


def _is_ip(value: str, version: int | None = None) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return version is None or addr.version == version


def _check(key: str, value: str) -> str | None:
    kind, maxlen = CEF_KEYS[key]
    if kind == _S:
        if maxlen and len(value) > maxlen:
            return f"string exceeds maximum length {maxlen} ({len(value)} characters)"
        return None
    if kind in ("int", "long"):
        try:
            int(value)
        except ValueError:
            return f"expected an integer, got {value!r}"
        return None
    if kind == "float":
        try:
            float(value)
        except ValueError:
            return f"expected a number, got {value!r}"
        return None
    if kind == "port":
        try:
            port = int(value)
        except ValueError:
            return f"expected a port number, got {value!r}"
        if not 0 <= port <= 65535:
            return f"port {port} outside 0-65535"
        return None
    if kind == "ip":
        if not _is_ip(value):
            return f"expected an IP address, got {value!r}"
        return None
    if kind == "ipv4":
        if not _is_ip(value, 4):
            return f"expected an IPv4 address (use c6a1-c6a4 for IPv6), got {value!r}"
        return None
    if kind == "ipv6":
        if not _is_ip(value, 6):
            return f"expected an IPv6 address, got {value!r}"
        return None
    if kind == "mac":
        if not MAC_RE.match(value):
            return f"expected a MAC address (aa:bb:cc:dd:ee:ff), got {value!r}"
        return None
    if kind == "ts":
        if value.isdigit():
            if 10 <= len(value) <= 19:
                return None  # epoch seconds through nanoseconds
            return f"epoch timestamp has implausible magnitude: {value!r}"
        try:
            datetime.strptime(value, "%b %d %Y %H:%M:%S")
        except ValueError:
            return f"expected 'MMM dd yyyy HH:mm:ss' or epoch milliseconds, got {value!r}"
        return None
    return None


def validate_extensions(extensions: Dict[str, str]) -> List[Finding]:
    """Validate raw (pre-escaping) extension values against the dictionary.

    Returns findings; type/length violations are fatal, unknown keys are
    advisory (the CEF standard allows custom keys).
    """

    findings: List[Finding] = []
    for key, value in extensions.items():
        if key not in CEF_KEYS:
            findings.append(
                Finding(key, "not in the ArcSight dictionary (custom keys are allowed)", fatal=False)
            )
            continue
        if key in CONSUMER_KEYS:
            findings.append(
                Finding(
                    key,
                    "consumer-side key; producers should carry this via a labeled custom field (cs1/cs1Label)",
                    fatal=False,
                )
            )
        problem = _check(key, str(value))
        if problem:
            findings.append(Finding(key, problem, fatal=True))
    return findings


__all__ = ["CEF_KEYS", "CONSUMER_KEYS", "CEFValidationError", "Finding", "validate_extensions"]
