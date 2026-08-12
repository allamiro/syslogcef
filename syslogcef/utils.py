from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

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

KEY_VALUE_RE = re.compile(
    r"(?P<key>[A-Za-z0-9_.-]+)="
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|"
    r"\S+?(?=,\s*[A-Za-z0-9_.-]+=|\s|$))"
)

SEVERITY_WORDS = {
    "emergency": 0, "emerg": 0, "panic": 0,
    "alert": 1,
    "critical": 2, "crit": 2,
    "error": 3, "err": 3,
    "warning": 4, "warn": 4,
    "notice": 5,
    "information": 6, "informational": 6, "info": 6,
    "debug": 7,
}
UTF8_REPLACEMENT_CHAR = "\uFFFD"
_NUL = "\x00"

# A trailing "+HH", "+HHMM", or "+HH:MM" offset, required to follow a
# time-of-day component so a bare "2026-07" is never treated as offset.
_TZ_OFFSET_RE = re.compile(r"^(.*\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?)([+-]\d{2}):?(\d{2})?$")


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
        # Interpret integer epochs by their conventional precision (#87):
        # 10 digits = seconds, 13 = milliseconds, 16 = microseconds,
        # 19 = nanoseconds (truncated to Python's microseconds). Other
        # lengths are ambiguous and rejected rather than silently
        # producing a date decades off (a 13-digit millisecond value
        # previously parsed as microseconds, ~1000x too early).
        digits = len(value)
        number = int(value)
        if digits <= 10:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        if digits == 13:
            seconds, millis = divmod(number, 1_000)
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=millis * 1000)
        if digits == 16:
            seconds, micros = divmod(number, 1_000_000)
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=micros)
        if digits == 19:
            seconds, nanos = divmod(number, 1_000_000_000)
            return datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=nanos // 1000)
        raise ValueError(f"ambiguous epoch precision ({digits} digits): {value!r}")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    # Normalize compact UTC offsets ("+02", "+0200") to "+02:00": macOS
    # install.log stamps hour-only offsets, and Python < 3.11
    # fromisoformat only accepts the colon form.
    offset_match = _TZ_OFFSET_RE.match(value)
    if offset_match:
        head, hours, minutes = offset_match.groups()
        value = f"{head}{hours}:{minutes or '00'}"
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
        if len(value) >= 2 and value[0] in "\"'" and value[-1] == value[0]:
            quote = value[0]
            value = value[1:-1]
            # Decode only escapes meaningful to the surrounding quote.
            # Sequences such as \n and Windows path separators remain
            # literal instead of being unexpectedly transformed.
            value = re.sub(rf"\\([{re.escape(quote)}\\])", r"\1", value)
        pairs[key] = value
    return pairs


def severity_from_word(word: str) -> Optional[int]:
    return SEVERITY_WORDS.get(word.strip().lower())


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
    # Strip NUL here, not only in msg: the raw event reaches cs1
    # unsanitized, and an embedded NUL truncates or confuses downstream
    # CEF consumers that treat records as C strings.
    return (
        value.replace(_NUL, UTF8_REPLACEMENT_CHAR)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("=", "\\=")
        .replace("\r", "\\r")
        .replace("\n", "\\n")
    )


def cef_escape_header(value: str) -> str:
    return (
        value.replace(_NUL, UTF8_REPLACEMENT_CHAR)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )
