from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .parsers import ParsedEvent
from .utils import ensure_tzaware, parse_key_value_pairs, sanitize_message, severity_from_word

logger = logging.getLogger(__name__)


@dataclass
class NormalizedEvent(ParsedEvent):
    kv: Dict[str, str] = None
    extras: Dict[str, Any] = None

    def __post_init__(self) -> None:
        if self.kv is None:
            self.kv = {}
        if self.extras is None:
            self.extras = {}

    def as_field_dict(self) -> Dict[str, Any]:
        base = {
            "pri": self.pri,
            "facility": self.facility,
            "severity": self.severity,
            "timestamp": self.ts.isoformat() if self.ts else None,
            "ts": self.ts.isoformat() if self.ts else None,
            "ts_orig": self.ts_orig,
            "host": self.host,
            "app": self.app,
            "pid": self.pid,
            "msgid": self.msgid,
            "source_hint": self.source_hint,
            "msg": self.msg,
        }
        fields: Dict[str, Any] = {}
        fields.update(self.sd)
        fields.update(self.kv)
        fields.update(self.extras)

        # Parsed envelope metadata is more trustworthy than same-named
        # key=value text inside the message. Reapply it last when present,
        # while still allowing a kv field to fill metadata absent from the
        # envelope. ``msg`` intentionally retains the established kv
        # behavior for formats that carry an inner msg="..." value.
        authoritative = {
            "pri", "facility", "severity", "timestamp", "ts", "ts_orig",
            "host", "app", "pid", "msgid", "source_hint",
        }
        for key in authoritative:
            if base[key] is not None:
                fields[key] = base[key]
        fields.setdefault("msg", base["msg"])
        return {k: v for k, v in fields.items() if v is not None}


def normalize(event: ParsedEvent) -> NormalizedEvent:
    ts = ensure_tzaware(event.ts) or datetime.now(timezone.utc)
    msg = sanitize_message(event.msg)
    kv = parse_key_value_pairs(msg)

    extras = {
        "message_length": len(msg),
        "message_short": msg[:120],
        "raw": event.raw,
        "raw_kv": " ".join(f"{k}={v}" for k, v in kv.items()),
        # Event time as epoch milliseconds for the CEF rt field.
        "rt": str(int(ts.timestamp() * 1000)),
    }

    # dvcpid is an integer field in the CEF dictionary, but RFC 5424
    # PROCID (and kv pids) may be arbitrary strings ("worker-A"); expose
    # a numeric-only alias so mappings can emit dvcpid without tripping
    # strict validation. ASCII check: isdigit() alone accepts Unicode
    # digits that int() consumers reject.
    pid = str(event.pid) if event.pid is not None else ""
    if pid.isascii() and pid.isdigit():
        extras["dvcpid"] = pid

    if event.source_hint in {"rfc3164", "rsyslog", "journald"} and event.host is None:
        extras["host"] = "localhost"

    normalized = NormalizedEvent(
        pri=event.pri,
        facility=event.facility,
        severity=event.severity,
        ts=ts,
        ts_orig=event.ts_orig,
        host=event.host,
        app=event.app,
        pid=event.pid,
        msgid=event.msgid,
        sd=dict(event.sd),
        msg=msg,
        raw=event.raw,
        source_hint=event.source_hint,
        kv=kv,
        extras=extras,
    )

    _derive_common_fields(normalized)
    return normalized


def _derive_common_fields(event: NormalizedEvent) -> None:
    # Canonicalize field names via the shared dictionary (srcip -> src,
    # dstport -> dpt, user -> suser, ...). This runs for every event —
    # including kv pairs extracted from adaptive-parsed lines — so
    # mappings and validation always see canonical CEF keys. Original
    # keys are kept; an existing canonical key is never overwritten.
    from .dictionary import cef_keys, field_aliases

    # Source formats frequently vary only in field-name casing (SRCIP,
    # SrcIp, srcip). Preserve every original key, add a lowercase spelling,
    # and prefer an explicitly lowercase value when both forms are present.
    original_items = list(event.kv.items())
    for key, value in original_items:
        lower = key.lower()
        if lower not in event.kv:
            event.kv[lower] = value

    # Restore the dictionary's exact spelling for canonical camelCase CEF
    # keys (DeviceExternalId -> deviceExternalId), again without overwrite.
    canonical_by_lower = {key.lower(): key for key in cef_keys()}
    for key in list(event.kv):
        lower = key.lower()
        canonical = canonical_by_lower.get(lower)
        if canonical is not None and canonical not in event.kv:
            # Take the folded lowercase value rather than this spelling.
            # The loop above already applied lowercase-wins precedence, so
            # an explicit deviceexternalid= beats DEVICEEXTERNALID=
            # regardless of which appeared first in the message.
            event.kv[canonical] = event.kv.get(lower, event.kv[key])

    for alias, canonical in field_aliases().items():
        if canonical not in event.kv and alias in event.kv:
            event.kv[canonical] = event.kv[alias]

    if "event_code" not in event.kv:
        code = _extract_event_code(event.msg)
        if code:
            event.kv["event_code"] = code

    # Cisco codes embed the severity digit (%SEC-6-IPACCESSLOGRP -> 6);
    # use it when the line carried no PRI.
    if event.severity is None:
        code = event.kv.get("event_code", "")
        sev_match = re.search(r"-(\d)-", code)
        if sev_match:
            event.severity = int(sev_match.group(1))

    # Key=value formats often carry a textual level (level="notice",
    # priority=Information); use it when no PRI was present.
    if event.severity is None:
        for key in ("level", "priority", "severity"):
            word = event.kv.get(key)
            if word:
                sev = severity_from_word(word)
                if sev is not None:
                    event.severity = sev
                    break


CISCO_CODE_RE = re.compile(r"%([A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)*-\d-[A-Z0-9_]+)")


def _extract_event_code(msg: str) -> Optional[str]:
    # Cisco style codes (%ASA-6-106100, %SEC-6-IPACCESSLOGRP, %LINK-3-UPDOWN)
    # may appear at the start of the message or after an inline timestamp.
    match = CISCO_CODE_RE.search(msg)
    if match:
        return match.group(1)
    return None


__all__ = [
    "NormalizedEvent",
    "normalize",
]
