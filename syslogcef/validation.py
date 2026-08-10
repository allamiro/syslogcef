"""Validation of CEF extension keys and values against the ArcSight dictionary.

The key metadata below is derived from the ArcSight Extension Dictionary
(CEF key names for event producers): data type and maximum string length
per key. Custom keys are permitted by the CEF standard, so unknown keys
produce advisory findings only; type and length violations are the
errors that ``strict`` mode raises on.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Dict, List, Tuple

# type tags: str (with max length), int, long, float, port, ip (v4/v6),
# ipv6, mac, ts (MMM dd yyyy HH:mm:ss or epoch milliseconds)
_S = "str"

CEF_KEYS: Dict[str, Tuple[str, int]] = {
    "act": (_S, 63), "app": (_S, 31), "cat": (_S, 1023), "cnt": ("int", 0),
    "cn1": ("long", 0), "cn2": ("long", 0), "cn3": ("long", 0),
    "cn1Label": (_S, 1023), "cn2Label": (_S, 1023), "cn3Label": (_S, 1023),
    "cfp1": ("float", 0), "cfp2": ("float", 0), "cfp3": ("float", 0), "cfp4": ("float", 0),
    "cfp1Label": (_S, 1023), "cfp2Label": (_S, 1023), "cfp3Label": (_S, 1023), "cfp4Label": (_S, 1023),
    "cs1": (_S, 4000), "cs2": (_S, 4000), "cs3": (_S, 4000),
    "cs4": (_S, 4000), "cs5": (_S, 4000), "cs6": (_S, 4000),
    "cs1Label": (_S, 1023), "cs2Label": (_S, 1023), "cs3Label": (_S, 1023),
    "cs4Label": (_S, 1023), "cs5Label": (_S, 1023), "cs6Label": (_S, 1023),
    "c6a1": ("ipv6", 0), "c6a2": ("ipv6", 0), "c6a3": ("ipv6", 0), "c6a4": ("ipv6", 0),
    "c6a1Label": (_S, 1023), "c6a2Label": (_S, 1023), "c6a3Label": (_S, 1023), "c6a4Label": (_S, 1023),
    "destinationDnsDomain": (_S, 255), "destinationServiceName": (_S, 1023),
    "destinationTranslatedAddress": ("ip", 0), "destinationTranslatedPort": ("port", 0),
    "deviceDirection": ("int", 0), "deviceDnsDomain": (_S, 255),
    "deviceExternalId": (_S, 255), "deviceFacility": (_S, 1023),
    "deviceInboundInterface": (_S, 128), "deviceOutboundInterface": (_S, 128),
    "deviceNtDomain": (_S, 255), "devicePayloadId": (_S, 128),
    "deviceProcessName": (_S, 1023), "deviceTranslatedAddress": ("ip", 0),
    "deviceCustomDate1": ("ts", 0), "deviceCustomDate2": ("ts", 0),
    "deviceCustomDate1Label": (_S, 1023), "deviceCustomDate2Label": (_S, 1023),
    "dhost": (_S, 1023), "dmac": ("mac", 0), "dntdom": (_S, 255),
    "dpid": ("int", 0), "dpriv": (_S, 1023), "dproc": (_S, 1023),
    "dpt": ("port", 0), "dst": ("ip", 0), "dtz": (_S, 255),
    "duid": (_S, 1023), "duser": (_S, 1023),
    "dvc": ("ip", 0), "dvchost": (_S, 100), "dvcpid": ("int", 0),
    "end": ("ts", 0), "externalId": (_S, 40),
    "fileCreateTime": ("ts", 0), "fileHash": (_S, 255), "fileId": (_S, 1023),
    "fileModificationTime": ("ts", 0), "filePath": (_S, 1023),
    "filePermission": (_S, 1023), "fileType": (_S, 1023),
    "flexDate1": ("ts", 0), "flexDate1Label": (_S, 128),
    "flexString1": (_S, 1023), "flexString1Label": (_S, 128),
    "flexString2": (_S, 1023), "flexString2Label": (_S, 128),
    "fname": (_S, 1023), "fsize": ("int", 0),
    "in": ("long", 0), "out": ("long", 0),
    "msg": (_S, 1023), "outcome": (_S, 63), "proto": (_S, 31),
    "reason": (_S, 1023), "request": (_S, 1023),
    "requestClientApplication": (_S, 1023), "requestContext": (_S, 2048),
    "requestCookies": (_S, 1023), "requestMethod": (_S, 1023),
    "rt": ("ts", 0), "start": ("ts", 0),
    "shost": (_S, 1023), "smac": ("mac", 0), "sntdom": (_S, 255),
    "sourceDnsDomain": (_S, 255), "sourceServiceName": (_S, 1023),
    "sourceTranslatedAddress": ("ip", 0), "sourceTranslatedPort": ("port", 0),
    "spid": ("int", 0), "spriv": (_S, 1023), "sproc": (_S, 1023),
    "spt": ("port", 0), "src": ("ip", 0),
    "suid": (_S, 1023), "suser": (_S, 1023),
    "type": ("int", 0),
    "rawEvent": (_S, 4000),
}

MAC_RE = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
TS_RE = re.compile(r"^[A-Z][a-z]{2} \d{2} \d{4} \d{2}:\d{2}:\d{2}$")


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
            return None  # epoch milliseconds
        if TS_RE.match(value):
            return None
        return f"expected 'MMM dd yyyy HH:mm:ss' or epoch milliseconds, got {value!r}"
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
        problem = _check(key, str(value))
        if problem:
            findings.append(Finding(key, problem, fatal=True))
    return findings


__all__ = ["CEF_KEYS", "CEFValidationError", "Finding", "validate_extensions"]
