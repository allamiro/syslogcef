from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

logger = logging.getLogger(__name__)

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

KEY_VALUE_RE = re.compile(r"(?P<key>[A-Za-z0-9_.-]+)=(?P<value>\S+)")
UTF8_REPLACEMENT_CHAR = "\uFFFD"


def month_abbr_to_int(abbr: str) -> int:
    try:
        return MONTHS[abbr]
    except KeyError as exc:
        raise ValueError(f"Unknown month abbreviation: {abbr!r}") from exc


def convert_pri(pri: Optional[int]) -> tuple[Optional[int], Optional[int]]:
    if pri is None:
        return None, None
    facility = pri // 8
    severity = pri % 8
    return facility, severity


def parse_iso8601(value: str) -> datetime:
    if value is None:
        raise ValueError("Timestamp value is required")
    value = str(value)
    if value.isdigit():
        micros = int(value)
        if len(value) > 10:
            seconds, micros = divmod(micros, 1_000_000)
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=micros)
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"Invalid ISO8601 timestamp: {value!r}") from exc


def ensure_tzaware(ts: Optional[datetime]) -> Optional[datetime]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts


def sanitize_message(msg: str) -> str:
    return msg.encode("utf-8", "replace").decode("utf-8").replace("\u0000", UTF8_REPLACEMENT_CHAR)


def parse_key_value_pairs(msg: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for match in KEY_VALUE_RE.finditer(msg):
        key = match.group("key")
        value = match.group("value")
        if value.startswith(('"', "'")) and value.endswith(('"', "'")):
            value = value[1:-1]
        pairs[key] = value
    return pairs


def guess_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class JournalJSONMapping:
    data: Mapping[str, Any]

    def to_structured_data(self) -> Dict[str, Any]:
        sd: Dict[str, Any] = {}
        for key, value in self.data.items():
            if key.startswith("_") or key.startswith("__"):
                continue
            if isinstance(value, (str, int, float)):
                sd[f"journald.{key}"] = str(value)
        return sd


def flatten_dict(prefix: str, data: Mapping[str, Any]) -> Dict[str, Any]:
    flat: Dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, Mapping):
            flat.update(flatten_dict(f"{prefix}{key}.", value))
        else:
            flat[f"{prefix}{key}"] = value
    return flat


def cef_escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\n", "\\n")
    )
