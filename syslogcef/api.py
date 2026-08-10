from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional

from .parsers import ParsedEvent, autodetect_and_parse
from .normalizer import NormalizedEvent, normalize
from .mappings import CISCO_ASA, CISCO_IOS, F5, LINUX, VMWARE
from .cef import CEFEvent, build_cef

logger = logging.getLogger(__name__)


@dataclass
class ParseResult:
    """Container returned by :func:`parse_syslog`.

    The ``raw`` attribute always contains the original syslog line.
    """

    event: NormalizedEvent
    raw: str


def parse_syslog(
    line: str,
    *,
    mode: Optional[str] = None,
    now: Optional[datetime] = None,
) -> ParsedEvent:
    """Parse a raw syslog line.

    Parameters
    ----------
    line:
        Raw syslog string.
    mode:
        Optional parser mode. When ``None`` the parser auto-detects RFC3164,
        RFC5424, rsyslog formats and journalctl exports.
    now:
        Optional datetime used when inferring missing year information.
    """

    parsed = autodetect_and_parse(line, mode=mode, now=now)
    return parsed


def normalize_event(event: ParsedEvent | NormalizedEvent) -> NormalizedEvent:
    """Normalize parsed syslog data.

    The normalizer enriches the event with structured fields, sanitised
    messages and derived metadata that the CEF renderer relies on.
    """

    if isinstance(event, NormalizedEvent):
        return event
    return normalize(event)


def _load_mapping(mapping: Mapping[str, Any] | Path | str | None) -> Mapping[str, Any]:
    if mapping is None:
        return {}
    if isinstance(mapping, Mapping):
        return mapping
    path = Path(mapping)
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def to_cef(
    event: NormalizedEvent,
    mapping: Mapping[str, Any] | Path | str | None = None,
) -> str:
    """Convert a normalized event into a CEF string."""

    if mapping is None:
        mapping_data = _guess_mapping(event)
    else:
        mapping_data = _load_mapping(mapping)
    cef_event = build_cef(event, mapping_data)
    return cef_event.render()


def convert_line(
    line: str,
    *,
    mode: Optional[str] = None,
    mapping: Mapping[str, Any] | Path | str | None = None,
    now: Optional[datetime] = None,
) -> str:
    """Full pipeline that parses, normalizes and converts a syslog line."""

    parsed = parse_syslog(line, mode=mode, now=now)
    normalized = normalize_event(parsed)

    return to_cef(normalized, mapping)


def _guess_mapping(event: NormalizedEvent) -> Mapping[str, Any]:
    msg_upper = event.msg.upper()
    app_upper = (event.app or "").upper()
    event_code = event.kv.get("event_code", "")

    if "%ASA-" in msg_upper or "ASA" in app_upper or event_code.startswith(("ASA-", "FTD-")):
        return CISCO_ASA
    if "IOS" in app_upper or "%IOS-" in msg_upper:
        return CISCO_IOS
    if "BIG-IP" in msg_upper or "F5" in app_upper:
        return F5
    if "VMWARE" in msg_upper or "ESXI" in msg_upper or "VMWARE" in app_upper:
        return VMWARE
    if event_code:
        # Other %FAC-SEV-MNEMONIC codes are Cisco IOS style.
        return CISCO_IOS
    return LINUX


__all__ = [
    "CEFEvent",
    "ParsedEvent",
    "NormalizedEvent",
    "ParseResult",
    "convert_line",
    "normalize_event",
    "parse_syslog",
    "to_cef",
]
