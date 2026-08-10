from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple

from .utils import (
    KEY_VALUE_RE,
    JournalJSONMapping,
    convert_pri,
    guess_hostname,
    month_abbr_to_int,
    parse_iso8601,
    parse_key_value_pairs,
    sanitize_message,
)

logger = logging.getLogger(__name__)


@dataclass
class ParsedEvent:
    pri: Optional[int]
    facility: Optional[int]
    severity: Optional[int]
    ts: Optional[datetime]
    ts_orig: str
    host: Optional[str]
    app: Optional[str]
    pid: Optional[str]
    msgid: Optional[str]
    sd: Dict[str, Any] = field(default_factory=dict)
    msg: str = ""
    raw: str = ""
    source_hint: str = "unknown"


RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?:(?P<year>\d{4})\s+)?"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>[^\s]+?):?\s+"
    r"(?::\s+)?"
    r"(?:(?P<tag>[\w\-/\.]+)(?:\[(?P<pid>[^\]]+)\])?:\s?)?"
    r"(?P<msg>.*)$"
)

RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s"
    r"(?P<timestamp>[^\s]+)\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<app>[^\s]+)\s"
    r"(?P<procid>[^\s]+)\s"
    r"(?P<msgid>[^\s]+)\s"
    r"(?P<sd>(?:-|\[.*\]))\s?"
    r"(?P<msg>.*)$"
)

RSYSLOG_FILE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<tag>[\w\-/\.]+)(?:\[(?P<pid>[^\]]+)\])?:\s?"
    r"(?P<msg>.*)$"
)

JOURNALCTL_SHORT_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<tag>[^:]+):\s?"
    r"(?P<msg>.*)$"
)

JOURNALCTL_ISO_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:Z|[+-]\d{2}:?\d{2})?)\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<tag>[^:]+):\s?"
    r"(?P<msg>.*)$"
)

KV_SPLIT_RE = re.compile(r"\s+|,|")

# Native Cisco console/buffer format: optional sequence number, optional
# clock-state marker (* = unsynced, . = drifting), timestamp with optional
# year/milliseconds/timezone, then the %CODE message.
CISCO_SEQ_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?:(?P<seq>\d+):\s+)?"
    r"[*.]?"
    r"(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?:(?P<year>\d{4})\s+)?"
    r"(?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?"
    r"(?:\s+[A-Z]{3,4})?:\s+"
    r"(?P<msg>%[A-Z].*)$"
)

# ISO timestamp syslog without RFC5424 framing: <PRI>ISO host [tag[pid]:] msg
ISO_SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>[^\s]+?):?\s+"
    r"(?:(?P<tag>[\w\-/\.]+)(?:\[(?P<pid>[^\]]+)\])?:\s?)?"
    r"(?P<msg>.*)$"
)

# Key=value stream format (Fortinet FortiGate, Sophos XG, ...): the whole
# line is key=value pairs, optionally preceded by a PRI. Detection is done
# in _looks_like_kv_line (linear scan) rather than a repeated-group regex,
# which backtracks catastrophically on long non-matching lines.
PRI_PREFIX_RE = re.compile(r"^<(?P<pri>\d{1,3})>")


def _looks_like_kv_line(body: str) -> bool:
    matches = list(KEY_VALUE_RE.finditer(body))
    if len(matches) < 3:
        return False
    covered = sum(m.end() - m.start() for m in matches)
    return covered >= 0.7 * len(body.strip())


def _infer_timestamp(month: int, day: int, time_str: str, *, now: Optional[datetime]) -> datetime:
    if now is None:
        now = datetime.now(timezone.utc)
    hour, minute, second = map(int, time_str.split(":"))
    candidate = now.replace(month=month, day=day, hour=hour, minute=minute, second=second, microsecond=0)
    # Handle rollover into previous year.
    if candidate - now > timedelta(days=180):
        candidate = candidate.replace(year=now.year - 1)
    elif now - candidate > timedelta(days=180):
        candidate = candidate.replace(year=now.year + 1)
    return candidate


STRUCTURED_DATA_RE = re.compile(
    r"\[(?P<id>[^\s\]]+)"  # identifier
    r"(?P<body>(?:\s+[^=]+=\"[^\"]*\"|\s+[^=]+=[^\s\]]+)*)"  # key="value" or key=value
    r"\]"
)
STRUCTURED_DATA_VALUE_RE = re.compile(r"\s+([^=]+)=(?:\"([^\"]*)\"|([^\s\]]+))")


class ParserError(RuntimeError):
    pass


def parse_structured_data(sd_raw: str) -> Dict[str, Any]:
    if sd_raw == "-":
        return {}
    data: Dict[str, Any] = {}
    for match in STRUCTURED_DATA_RE.finditer(sd_raw):
        sd_id = match.group("id")
        body = match.group("body")
        for key, quoted, bare in STRUCTURED_DATA_VALUE_RE.findall(body):
            value = quoted or bare
            data[f"{sd_id}.{key}"] = value
    return data


def parse_rfc3164(line: str, *, now: Optional[datetime]) -> ParsedEvent | None:
    match = RFC3164_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    pri = int(gd["pri"]) if gd.get("pri") else None
    facility, severity = convert_pri(pri)
    month = month_abbr_to_int(gd["month"])
    hour, minute, second = map(int, gd["time"].split(":"))
    if gd.get("year"):
        ts = datetime(int(gd["year"]), month, int(gd["day"]), hour, minute, second, tzinfo=timezone.utc)
        ts_orig = f"{gd['month']} {gd['day']} {gd['year']} {gd['time']}"
    else:
        ts = _infer_timestamp(month, int(gd["day"]), gd["time"], now=now)
        ts_orig = f"{gd['month']} {gd['day']} {gd['time']}"
    app = gd.get("tag")
    msg = gd.get("msg", "")
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=ts_orig,
        host=gd.get("host"),
        app=app,
        pid=gd.get("pid"),
        msgid=None,
        sd={},
        msg=msg,
        raw=line,
        source_hint="rfc3164",
    )


def parse_rfc5424(line: str) -> ParsedEvent | None:
    match = RFC5424_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    pri = int(gd["pri"]) if gd.get("pri") else None
    facility, severity = convert_pri(pri)
    ts = parse_iso8601(gd["timestamp"])
    sd = parse_structured_data(gd.get("sd") or "-")
    msg = gd.get("msg", "")
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=gd["timestamp"],
        host=None if gd["host"] == "-" else gd["host"],
        app=None if gd["app"] == "-" else gd["app"],
        pid=None if gd["procid"] == "-" else gd["procid"],
        msgid=None if gd["msgid"] == "-" else gd["msgid"],
        sd=sd,
        msg=msg,
        raw=line,
        source_hint="rfc5424",
    )


def parse_rsyslog_json(line: str) -> ParsedEvent | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    pri = data.get("pri") or data.get("syslogpriority")
    pri = int(pri) if pri is not None else None
    facility, severity = convert_pri(pri)
    timestamp = data.get("timestamp") or data.get("timegenerated")
    ts = parse_iso8601(timestamp) if timestamp else None
    host = data.get("hostname") or data.get("host")
    app = data.get("app-name") or data.get("programname")
    pid = data.get("procid") or data.get("pid")
    msg = data.get("msg") or data.get("message") or ""
    sd = {k: v for k, v in data.items() if isinstance(k, str) and k.startswith("structured-data")}
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=timestamp or "",
        host=host,
        app=app,
        pid=str(pid) if pid is not None else None,
        msgid=data.get("msgid"),
        sd=sd,
        msg=msg,
        raw=line,
        source_hint="rsyslog",
    )


def parse_rsyslog_file(line: str) -> ParsedEvent | None:
    match = RSYSLOG_FILE_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    ts = parse_iso8601(gd["timestamp"])
    pri = None
    facility, severity = convert_pri(pri)
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=gd["timestamp"],
        host=gd.get("host"),
        app=gd.get("tag"),
        pid=gd.get("pid"),
        msgid=None,
        sd={},
        msg=gd.get("msg", ""),
        raw=line,
        source_hint="rsyslog",
    )


def parse_journalctl_json(line: str) -> ParsedEvent | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    pri_raw = data.get("PRIORITY") or data.get("priority")
    pri = int(pri_raw) if pri_raw is not None else None
    facility, severity = convert_pri(pri)
    timestamp = data.get("__REALTIME_TIMESTAMP") or data.get("timestamp")
    ts = parse_iso8601(timestamp) if timestamp else None
    host = data.get("_HOSTNAME") or data.get("hostname")
    app = data.get("SYSLOG_IDENTIFIER") or data.get("app-name")
    pid = data.get("_PID") or data.get("pid")
    msg = data.get("MESSAGE") or data.get("msg") or ""
    sd = JournalJSONMapping(data).to_structured_data()
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=str(timestamp or ""),
        host=host,
        app=app,
        pid=str(pid) if pid is not None else None,
        msgid=None,
        sd=sd,
        msg=msg,
        raw=line,
        source_hint="journald",
    )


def parse_journalctl_short(line: str, *, now: Optional[datetime]) -> ParsedEvent | None:
    match = JOURNALCTL_SHORT_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    month = month_abbr_to_int(gd["month"])
    ts = _infer_timestamp(month, int(gd["day"]), gd["time"], now=now)
    return ParsedEvent(
        pri=None,
        facility=None,
        severity=None,
        ts=ts,
        ts_orig=f"{gd['month']} {gd['day']} {gd['time']}",
        host=gd.get("host"),
        app=gd.get("tag"),
        pid=None,
        msgid=None,
        sd={},
        msg=gd.get("msg", ""),
        raw=line,
        source_hint="journald",
    )


def parse_journalctl_iso(line: str) -> ParsedEvent | None:
    match = JOURNALCTL_ISO_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    ts = parse_iso8601(gd["timestamp"])
    return ParsedEvent(
        pri=None,
        facility=None,
        severity=None,
        ts=ts,
        ts_orig=gd["timestamp"],
        host=gd.get("host"),
        app=gd.get("tag"),
        pid=None,
        msgid=None,
        sd={},
        msg=gd.get("msg", ""),
        raw=line,
        source_hint="journald",
    )


def parse_cisco_seq(line: str, *, now: Optional[datetime]) -> ParsedEvent | None:
    match = CISCO_SEQ_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    pri = int(gd["pri"]) if gd.get("pri") else None
    facility, severity = convert_pri(pri)
    month = month_abbr_to_int(gd["month"])
    hour, minute, second = map(int, gd["time"].split(":"))
    microsecond = int(float(gd["frac"]) * 1_000_000) if gd.get("frac") else 0
    if gd.get("year"):
        ts = datetime(int(gd["year"]), month, int(gd["day"]), hour, minute, second, microsecond, tzinfo=timezone.utc)
    else:
        ts = _infer_timestamp(month, int(gd["day"]), gd["time"], now=now).replace(microsecond=microsecond)
    sd = {"cisco.sequence": gd["seq"]} if gd.get("seq") else {}
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=f"{gd['month']} {gd['day']} {gd['time']}",
        host=None,
        app=None,
        pid=None,
        msgid=None,
        sd=sd,
        msg=gd.get("msg", ""),
        raw=line,
        source_hint="cisco",
    )


def parse_iso_syslog(line: str) -> ParsedEvent | None:
    match = ISO_SYSLOG_RE.match(line)
    if not match:
        return None
    gd = match.groupdict()
    pri = int(gd["pri"]) if gd.get("pri") else None
    facility, severity = convert_pri(pri)
    try:
        ts = parse_iso8601(gd["timestamp"])
    except ValueError:
        return None
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=gd["timestamp"],
        host=gd.get("host"),
        app=gd.get("tag"),
        pid=gd.get("pid"),
        msgid=None,
        sd={},
        msg=gd.get("msg", ""),
        raw=line,
        source_hint="iso_syslog",
    )


def parse_kv_stream(line: str) -> ParsedEvent | None:
    pri = None
    body = line
    pri_match = PRI_PREFIX_RE.match(line)
    if pri_match:
        pri = int(pri_match.group("pri"))
        body = line[pri_match.end():]
    if not _looks_like_kv_line(body):
        return None
    facility, severity = convert_pri(pri)
    pairs = parse_key_value_pairs(body)
    if len(pairs) < 3:
        return None

    ts = None
    if pairs.get("date") and pairs.get("time"):
        try:
            ts = parse_iso8601(f"{pairs['date']}T{pairs['time']}")
        except ValueError:
            ts = None
    elif pairs.get("eventtime", "").isdigit():
        try:
            ts = parse_iso8601(pairs["eventtime"][:16])
        except ValueError:
            ts = None
    if ts is not None and ts.tzinfo is None:
        # Apply a numeric offset supplied in the record (tz="-0500");
        # named zones (timezone="CEST") cannot be resolved portably.
        offset_match = re.fullmatch(
            r"([+-])(\d{2}):?(\d{2})", pairs.get("tz") or pairs.get("timezone") or ""
        )
        if offset_match:
            sign = 1 if offset_match.group(1) == "+" else -1
            delta = timedelta(
                hours=int(offset_match.group(2)), minutes=int(offset_match.group(3))
            )
            ts = ts.replace(tzinfo=timezone(sign * delta))

    host = (
        pairs.get("devname")
        or pairs.get("device_name")
        or pairs.get("dvchost")
        or pairs.get("devid")
        or pairs.get("device_id")
    )
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=f"{pairs.get('date', '')} {pairs.get('time', '')}".strip(),
        host=host,
        app=pairs.get("type") or pairs.get("log_type"),
        pid=None,
        msgid=pairs.get("logid") or pairs.get("log_id"),
        sd={},
        msg=body.strip(),
        raw=line,
        source_hint="kv",
    )


PARSERS = {
    "rfc3164": parse_rfc3164,
    "rfc5424": parse_rfc5424,
    "rsyslog_json": parse_rsyslog_json,
    "rsyslog_file": parse_rsyslog_file,
    "journald_json": parse_journalctl_json,
    "journald_short": parse_journalctl_short,
    "journald_iso": parse_journalctl_iso,
    "cisco_seq": parse_cisco_seq,
    "iso_syslog": parse_iso_syslog,
    "kv": parse_kv_stream,
}


def autodetect_and_parse(line: str, *, mode: Optional[str] = None, now: Optional[datetime] = None) -> ParsedEvent:
    detectors = [
        ("journald_json", lambda s: s.lstrip().startswith("{")),
        ("rsyslog_json", lambda s: s.lstrip().startswith("{")),
        ("rfc5424", lambda s: s.startswith("<") and ">" in s[:10]),
        ("rsyslog_file", lambda s: bool(RSYSLOG_FILE_RE.match(s))),
        ("journald_iso", lambda s: bool(JOURNALCTL_ISO_RE.match(s))),
        ("iso_syslog", lambda s: bool(ISO_SYSLOG_RE.match(s))),
        ("kv", lambda s: "=" in s[:80]),
        ("cisco_seq", lambda s: bool(CISCO_SEQ_RE.match(s))),
        ("journald_short", lambda s: bool(JOURNALCTL_SHORT_RE.match(s))),
        ("rfc3164", lambda s: bool(RFC3164_RE.match(s))),
    ]

    if mode:
        parser = PARSERS.get(mode)
        if parser is None:
            raise ParserError(f"Unknown parser mode: {mode}")
        result = parser(line, now=now) if "now" in parser.__code__.co_varnames else parser(line)
        if result is None:
            raise ParserError(f"Parser '{mode}' could not parse line")
        return result

    for key, detector in detectors:
        try:
            if detector(line):
                parser = PARSERS[key]
                result = parser(line, now=now) if "now" in parser.__code__.co_varnames else parser(line)
                if result is not None:
                    return result
        except Exception:
            logger.exception("Parser %s failed for line", key)
            continue

    # Nothing known matched: let the adaptive detector analyze the line and
    # synthesize a reusable pattern before giving up.
    from .adaptive import adaptive_parse

    try:
        adaptive_event = adaptive_parse(line, now=now)
    except Exception:
        logger.exception("Adaptive parser failed for line")
        adaptive_event = None
    if adaptive_event is not None:
        return adaptive_event

    # Fallback to raw message if nothing matches. A leading <PRI> is still
    # honored so facility/severity survive for non-standard formats.
    logger.debug("Falling back to raw parser for line: %s", line)
    pri = None
    body = line
    pri_match = re.match(r"^<(\d{1,3})>", line)
    if pri_match:
        pri = int(pri_match.group(1))
        body = line[pri_match.end():]
    facility, severity = convert_pri(pri)
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=None,
        ts_orig="",
        host=guess_hostname(),
        app=None,
        pid=None,
        msgid=None,
        sd={},
        msg=sanitize_message(body),
        raw=line,
        source_hint="unknown",
    )


__all__ = [
    "ParsedEvent",
    "ParserError",
    "autodetect_and_parse",
]
