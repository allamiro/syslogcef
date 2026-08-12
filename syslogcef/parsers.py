from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional

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

# SD and MSG are separated by scanning, not regex: a greedy [.*] cannot
# distinguish an escaped \] inside a param value from the element
# terminator, and would swallow a ']' in the free-form message.
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s"
    r"(?P<timestamp>[^\s]+)\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<app>[^\s]+)\s"
    r"(?P<procid>[^\s]+)\s"
    r"(?P<msgid>[^\s]+)\s"
    r"(?P<rest>.*)$"
)

RSYSLOG_FILE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?))\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<tag>[\w\-/\.]+)(?:\[(?P<pid>[^\]]+)\])?:\s?"
    r"(?P<msg>.*)$"
)

JOURNALCTL_SHORT_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<tag>[^:\[]+)(?:\[(?P<pid>[^\]]+)\])?:\s?"
    r"(?P<msg>.*)$"
)

JOURNALCTL_ISO_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?:Z|[+-]\d{2}(?::?\d{2})?)?)\s"
    r"(?P<host>[^\s]+)\s"
    r"(?P<tag>[^:\[]+)(?:\[(?P<pid>[^\]]+)\])?:\s?"
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
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?)\s+"
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
    # KEY_VALUE_RE excludes a trailing comma from a value, where it used to
    # be captured as part of it. Credit exactly those commas back so a
    # comma-delimited stream of short values ("a=1, b=2, c=3, d=4") scores
    # as it always did. Only commas are credited, and only in a gap that is
    # nothing but separators: crediting whitespace too would newly qualify
    # lines of prose that merely contain a few pairs.
    for current, following in zip(matches, matches[1:]):
        gap = body[current.end():following.start()]
        if gap and not gap.strip(", \t"):
            covered += gap.count(",")
    return covered >= 0.7 * len(body.strip())


def _infer_timestamp(month: int, day: int, time_str: str, *, now: Optional[datetime]) -> datetime:
    if now is None:
        now = datetime.now(timezone.utc)
    hour, minute, second = map(int, time_str.split(":"))

    def build(year: int) -> Optional[datetime]:
        try:
            return now.replace(
                year=year, month=month, day=day,
                hour=hour, minute=minute, second=second, microsecond=0,
            )
        except ValueError:  # Feb 29 in a non-leap year
            return None

    candidate = build(now.year)
    if candidate is None:
        # A yearless Feb 29 line in a non-leap runtime year must not
        # crash the parser: pick the occurrence closest in time (not
        # merely the first leap year found in either direction).
        candidates = [c for off in range(-4, 5) if off and (c := build(now.year + off))]
        if not candidates:
            raise ValueError(f"impossible calendar date: month={month} day={day}")
        return min(candidates, key=lambda c: abs(c - now))
    # Handle rollover into previous year.
    if candidate - now > timedelta(days=180):
        candidate = build(now.year - 1) or candidate
    elif now - candidate > timedelta(days=180):
        candidate = build(now.year + 1) or candidate
    return candidate


class ParserError(RuntimeError):
    pass


def _scan_structured_data(text: str) -> tuple[Dict[str, Any], int]:
    """Linear scan of RFC 5424 STRUCTURED-DATA at the start of ``text``.

    Returns ``(sd_dict, end_index)``. Honors the RFC's PARAM-VALUE
    escapes (``\\"``, ``\\\\``, ``\\]``), so an escaped quote or bracket
    inside a value is data, not a terminator. Malformed input never
    raises: scanning stops at the first invalid character and whatever
    follows is left for the caller (typically as the message).
    """
    data: Dict[str, Any] = {}
    i, n = 0, len(text)
    while i < n and text[i] == "[":
        j = i + 1
        id_start = j
        while j < n and text[j] not in " ]":
            j += 1
        sd_id = text[id_start:j]
        if not sd_id:
            break
        # Accumulate this element's params locally and only merge them
        # into the result once its closing ']' is confirmed, so a
        # truncated element (e.g. `[e@1 role="admin"` with no ']') does
        # not leak partial params into the output.
        element: Dict[str, Any] = {}
        params_ok = True
        while j < n and text[j] == " ":
            j += 1
            # A space before the closing bracket ("[id a=\"1\" ]") is
            # not a new parameter — stop scanning params.
            if j < n and text[j] == "]":
                break
            name_start = j
            while j < n and text[j] not in "= ]":
                j += 1
            if j >= n or text[j] != "=" or j == name_start:
                params_ok = False
                break
            name = text[name_start:j]
            j += 1
            if j < n and text[j] == '"':
                j += 1
                buf: list = []
                closed = False
                while j < n:
                    ch = text[j]
                    if ch == "\\" and j + 1 < n and text[j + 1] in '"\\]':
                        buf.append(text[j + 1])
                        j += 2
                        continue
                    if ch == '"':
                        closed = True
                        j += 1
                        break
                    buf.append(ch)
                    j += 1
                if not closed:
                    params_ok = False
                    break
                element[f"{sd_id}.{name}"] = "".join(buf)
            else:
                # Tolerate real-world unquoted values (iut=3): the RFC
                # requires quoting, but the wild does not always comply.
                bare_start = j
                while j < n and text[j] not in " ]":
                    j += 1
                element[f"{sd_id}.{name}"] = text[bare_start:j]
        if not params_ok or j >= n or text[j] != "]":
            break
        data.update(element)  # element closed cleanly — commit it
        i = j + 1
    return data, i


def parse_structured_data(sd_raw: str) -> Dict[str, Any]:
    if sd_raw == "-":
        return {}
    data, _end = _scan_structured_data(sd_raw)
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
    # NILVALUE ("-") is a valid RFC 5424 timestamp meaning "unknown". A
    # malformed or ambiguous value keeps ts=None rather than aborting the
    # event (the never-drop-a-line contract, including forced mode).
    ts = None
    if gd["timestamp"] != "-":
        try:
            ts = parse_iso8601(gd["timestamp"])
        except (ValueError, OverflowError, OSError):
            ts = None
    rest = gd.get("rest") or ""
    if rest.startswith("["):
        sd, end = _scan_structured_data(rest)
        msg = rest[end:]
        if msg.startswith(" "):
            msg = msg[1:]
    elif rest == "-" or rest.startswith("- "):
        sd, msg = {}, rest[2:]
    else:
        sd, msg = {}, rest
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
    # Each alias is tried independently: an invalid value in an earlier
    # key must not mask a valid one in a later key.
    ts = None
    timestamp = ""
    for ts_key in ("timestamp", "timegenerated", "@timestamp", "timereported"):
        raw_ts = data.get(ts_key)
        if not raw_ts:
            continue
        if not timestamp:
            timestamp = str(raw_ts)  # first present value, for ts_orig
        try:
            ts = parse_iso8601(raw_ts)
            timestamp = str(raw_ts)
            break
        except (ValueError, OverflowError, OSError):
            continue
    # JSON values may be any scalar (e.g. "message": 123); coerce to str
    # so downstream sanitization/slicing never sees a non-string.
    host = data.get("hostname") or data.get("host")
    host = str(host) if host is not None else None
    app = data.get("app-name") or data.get("programname")
    app = str(app) if app is not None else None
    if app is None and isinstance(data.get("syslogtag"), str):
        # "nginx:" or "app[123]:" -> "nginx" / "app"
        app = data["syslogtag"].rstrip(":").split("[")[0] or None
    pid = data.get("procid") or data.get("pid")
    msg = str(data.get("msg") or data.get("message") or "")
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


# A JSON object must carry at least one journald-style key to be claimed
# by this parser; otherwise generic JSON (e.g. rsyslog's @timestamp/host
# shape) would be swallowed into an all-empty event instead of falling
# through to the rsyslog parser.
_JOURNALD_NATIVE_KEYS = (
    "MESSAGE",
    "__REALTIME_TIMESTAMP",
    "_HOSTNAME",
    "SYSLOG_IDENTIFIER",
    "_PID",
    "PRIORITY",
)
# Every lowercase alias the parser body reads must also gate, or explicit
# --mode journald_json rejects records it can parse.
_JOURNALD_ALIAS_KEYS = ("timestamp", "hostname", "app-name", "priority", "pid", "msg")
# Keys only rsyslog emits: a record matched purely via the lowercase
# aliases but carrying one of these belongs to parse_rsyslog_json, which
# reads fields (message, programname, ...) journald would drop.
_RSYSLOG_MARKER_KEYS = (
    "@timestamp",
    "message",
    "programname",
    "syslogtag",
    "timegenerated",
    "timereported",
    "syslogpriority",
)


def parse_journalctl_json(line: str) -> ParsedEvent | None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    if not any(key in data for key in _JOURNALD_NATIVE_KEYS):
        if not any(key in data for key in _JOURNALD_ALIAS_KEYS):
            return None
        if any(key in data for key in _RSYSLOG_MARKER_KEYS):
            return None
    pri_raw = data.get("PRIORITY") or data.get("priority")
    pri = int(pri_raw) if pri_raw is not None else None
    facility, severity = convert_pri(pri)
    ts = None
    ts_orig = str(data.get("__REALTIME_TIMESTAMP") or data.get("timestamp") or "")
    realtime = data.get("__REALTIME_TIMESTAMP")
    if realtime is not None and str(realtime).isdigit():
        # journald's __REALTIME_TIMESTAMP is always microseconds since
        # the epoch, regardless of digit count — a pre-2001 value has
        # fewer than 16 digits, which parse_iso8601's precision dispatch
        # would reject as ambiguous. Scale it explicitly.
        try:
            micros = int(realtime)
            ts = datetime.fromtimestamp(micros // 1_000_000, tz=timezone.utc).replace(
                microsecond=micros % 1_000_000
            )
        except (ValueError, OverflowError, OSError):
            ts = None
    else:
        raw_ts = data.get("timestamp")
        if raw_ts:
            try:
                ts = parse_iso8601(raw_ts)
            except (ValueError, OverflowError, OSError):
                ts = None
    # Coerce JSON scalars to str, as in parse_rsyslog_json.
    host = data.get("_HOSTNAME") or data.get("hostname")
    host = str(host) if host is not None else None
    app = data.get("SYSLOG_IDENTIFIER") or data.get("app-name")
    app = str(app) if app is not None else None
    pid = data.get("_PID") or data.get("pid")
    msg = str(data.get("MESSAGE") or data.get("msg") or "")
    sd = JournalJSONMapping(data).to_structured_data()
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=ts_orig,
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
        pid=gd.get("pid"),
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
        pid=gd.get("pid"),
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

    # Device key names are commonly emitted in uppercase. Use a folded
    # metadata view for parsing while preserving the exact originals in the
    # message/normalizer. An explicitly lowercase spelling wins collisions.
    pairs_ci: Dict[str, str] = {}
    for key, value in pairs.items():
        pairs_ci.setdefault(key.lower(), value)
    for key, value in pairs.items():
        if key == key.lower():
            pairs_ci[key] = value

    # Timestamp candidates in preference order, each falling through to
    # the next when absent or unparseable (an invalid ts= must not mask
    # a valid eventtime=). Overflow/OSError cover out-of-range epoch
    # values, which must never abort explicit kv-mode processing.
    # ts_orig records the candidate that actually parsed.
    ts = None
    ts_orig = ""
    if pairs_ci.get("date") and pairs_ci.get("time"):
        try:
            ts = parse_iso8601(f"{pairs_ci['date']}T{pairs_ci['time']}")
            ts_orig = f"{pairs_ci['date']} {pairs_ci['time']}"
        except (ValueError, OverflowError, OSError):
            ts = None
    if ts is None:
        # Each ISO alias tried independently: an invalid ts= must not
        # mask a valid timestamp= or datetime=.
        for iso_key in ("ts", "timestamp", "datetime"):
            raw_iso = pairs_ci.get(iso_key)
            if not raw_iso:
                continue
            try:
                ts = parse_iso8601(raw_iso)
                ts_orig = raw_iso
                break
            except (ValueError, OverflowError, OSError):
                continue
    if ts is None and pairs_ci.get("eventtime", "").isdigit():
        try:
            # Full value: parse_iso8601 dispatches on digit count
            # (10/13/16/19), so Fortinet's 19-digit nanoseconds no
            # longer need lossy [:16] truncation.
            ts = parse_iso8601(pairs_ci["eventtime"])
            ts_orig = pairs_ci["eventtime"]
        except (ValueError, OverflowError, OSError):
            ts = None
    if not ts_orig:
        ts_orig = (
            f"{pairs_ci.get('date', '')} {pairs_ci.get('time', '')}".strip()
            or pairs_ci.get("ts")
            or pairs_ci.get("timestamp")
            or pairs_ci.get("datetime")
            or ""
        )
    if ts is not None and ts.tzinfo is None:
        # Apply a numeric offset supplied in the record (tz="-0500");
        # named zones (timezone="CEST") cannot be resolved portably.
        offset_match = re.fullmatch(
            r"([+-])(\d{2}):?(\d{2})",
            pairs_ci.get("tz") or pairs_ci.get("timezone") or "",
        )
        if offset_match:
            sign = 1 if offset_match.group(1) == "+" else -1
            delta = timedelta(
                hours=int(offset_match.group(2)), minutes=int(offset_match.group(3))
            )
            try:
                ts = ts.replace(tzinfo=timezone(sign * delta))
            except ValueError:
                # tz=+24:00 and other out-of-range offsets: keep the
                # naive timestamp rather than dropping the event.
                pass

    host = (
        pairs_ci.get("devname")
        or pairs_ci.get("device_name")
        or pairs_ci.get("dvchost")
        or pairs_ci.get("devid")
        or pairs_ci.get("device_id")
    )
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig=ts_orig,
        host=host,
        app=pairs_ci.get("type") or pairs_ci.get("log_type"),
        pid=None,
        msgid=pairs_ci.get("logid") or pairs_ci.get("log_id"),
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


def _call_parser(parser, line: str, *, now: Optional[datetime] = None):
    try:
        code = parser.__code__
        # Only real parameter names — co_varnames also lists locals, and a
        # registered fn(line) with a local called "now" must keep working.
        arg_names = code.co_varnames[: code.co_argcount + code.co_kwonlyargcount]
        takes_now = "now" in arg_names
    except AttributeError:
        takes_now = False
    return parser(line, now=now) if takes_now else parser(line)


def autodetect_and_parse(line: str, *, mode: Optional[str] = None, now: Optional[datetime] = None) -> ParsedEvent:
    detectors = [
        ("journald_json", lambda s: s.lstrip().startswith("{")),
        ("rsyslog_json", lambda s: s.lstrip().startswith("{")),
        ("rfc5424", lambda s: s.startswith("<") and ">" in s[:10]),
        ("rsyslog_file", lambda s: bool(RSYSLOG_FILE_RE.match(s))),
        ("journald_iso", lambda s: bool(JOURNALCTL_ISO_RE.match(s))),
        ("iso_syslog", lambda s: bool(ISO_SYSLOG_RE.match(s))),
        # Header-based parsers run BEFORE kv: a normal RFC3164/journald
        # line whose *message* carries key=value pairs (containerd,
        # dockerd, NetworkManager, ...) must be claimed by its syslog
        # parser, not the kv format. Genuine kv streams (Fortinet, Sophos)
        # start with date=/device= and match none of these headers, so
        # they still fall through to kv.
        ("cisco_seq", lambda s: bool(CISCO_SEQ_RE.match(s))),
        ("journald_short", lambda s: bool(JOURNALCTL_SHORT_RE.match(s))),
        ("rfc3164", lambda s: bool(RFC3164_RE.match(s))),
        ("kv", lambda s: "=" in s[:80]),
    ]

    from . import custom

    if mode:
        parser = PARSERS.get(mode) or custom.get_registered(mode)
        if parser is None:
            raise ParserError(f"Unknown parser mode: {mode}")
        result = _call_parser(parser, line, now=now)
        if result is None:
            raise ParserError(f"Parser '{mode}' could not parse line")
        return result

    result = custom.custom_parse(line, "before", now=now)
    if result is not None:
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

    result = custom.custom_parse(line, "after", now=now)
    if result is not None:
        return result

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
