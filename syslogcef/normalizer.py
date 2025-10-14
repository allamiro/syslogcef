from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, Optional

from .parsers import ParsedEvent
from .utils import ensure_tzaware, parse_key_value_pairs, sanitize_message

logger = logging.getLogger(__name__)


@dataclass(slots=True)
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
        base.update(self.sd)
        base.update(self.kv)
        base.update(self.extras)
        return {k: v for k, v in base.items() if v is not None}


def normalize(event: ParsedEvent) -> NormalizedEvent:
    ts = ensure_tzaware(event.ts)
    msg = sanitize_message(event.msg)
    kv = parse_key_value_pairs(msg)

    extras = {
        "message_length": len(msg),
        "message_short": msg[:120],
        "raw": event.raw,
        "raw_kv": " ".join(f"{k}={v}" for k, v in kv.items()),
    }

    if event.source_hint in {"rfc3164", "rsyslog", "journald"} and event.host is None:
        extras["host"] = "localhost"

    normalized = NormalizedEvent(
        pri=event.pri,
        facility=event.facility,
        severity=event.severity,
        ts=ts or datetime.now(timezone.utc),
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
    if "src" not in event.kv and "src_ip" in event.kv:
        event.kv.setdefault("src", event.kv["src_ip"])
    if "dst" not in event.kv and "dst_ip" in event.kv:
        event.kv.setdefault("dst", event.kv["dst_ip"])

    if "event_code" not in event.kv:
        code = _extract_event_code(event.msg)
        if code:
            event.kv["event_code"] = code


def _extract_event_code(msg: str) -> Optional[str]:
    # Cisco ASA style: %ASA-6-106100: message
    if msg.startswith("%") and ":" in msg:
        head = msg.split(":", 1)[0]
        return head.strip("%")
    return None


__all__ = [
    "NormalizedEvent",
    "normalize",
]
