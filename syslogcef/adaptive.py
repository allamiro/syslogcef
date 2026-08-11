"""Adaptive pattern detection for lines no known parser matches.

When every dedicated parser fails, this module analyzes the line: it
locates a timestamp using a library of datetime shapes, identifies a
plausible host token, and synthesizes a compiled regex for that line
layout. The synthesized pattern is cached by the line's shape signature,
so subsequent lines with the same layout parse with a single regex match
instead of a fresh analysis. Events parsed this way report
``source_hint="adaptive"``.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Pattern, Tuple

from .utils import convert_pri, month_abbr_to_int, parse_iso8601, sanitize_message

PRI_RE = re.compile(r"^<(\d{1,3})>")

# Each entry: (name, regex source, converter(match, now) -> datetime)
def _iso(match: "re.Match[str]", now: Optional[datetime]) -> datetime:
    return parse_iso8601(match.group(0).replace(" ", "T", 1) if "T" not in match.group(0) else match.group(0))


def _epoch(match: "re.Match[str]", now: Optional[datetime]) -> datetime:
    return parse_iso8601(match.group(0))


def _mon_day(match: "re.Match[str]", now: Optional[datetime]) -> datetime:
    month = month_abbr_to_int(match.group("month"))
    day = int(match.group("day"))
    if match.groupdict().get("year"):
        hour, minute, second = map(int, match.group("hms").split(":"))
        return datetime(int(match.group("year")), month, day, hour, minute, second, tzinfo=timezone.utc)
    # No year: use the same rollover inference as the dedicated parsers so a
    # December event parsed in January lands in the previous year.
    from .parsers import _infer_timestamp

    return _infer_timestamp(month, day, match.group("hms"), now=now)


def _ymd_slash(match: "re.Match[str]", now: Optional[datetime]) -> datetime:
    y, m, d = int(match.group("y")), int(match.group("m")), int(match.group("d"))
    hour, minute, second = map(int, match.group("hms").split(":"))
    return datetime(y, m, d, hour, minute, second, tzinfo=timezone.utc)


def _dmy_dash(match: "re.Match[str]", now: Optional[datetime]) -> datetime:
    d = int(match.group("d"))
    month = month_abbr_to_int(match.group("month").title())
    y = int(match.group("y"))
    hour, minute, second = map(int, match.group("hms").split(":"))
    return datetime(y, month, d, hour, minute, second, tzinfo=timezone.utc)


TIMESTAMP_LIB: Tuple[Tuple[str, str, Callable], ...] = (
    ("iso", r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}(?::?\d{2})?)?", _iso),
    ("mon_day_year", r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<year>\d{4})\s+(?P<hms>\d{2}:\d{2}:\d{2})(?:\.\d+)?", _mon_day),
    ("mon_day", r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})(?:\.\d+)?", _mon_day),
    ("ymd_slash", r"(?P<y>\d{4})/(?P<m>\d{2})/(?P<d>\d{2})[ T](?P<hms>\d{2}:\d{2}:\d{2})", _ymd_slash),
    ("dmy_dash", r"(?P<d>\d{1,2})-(?P<month>[A-Za-z]{3})-(?P<y>\d{4})\s+(?P<hms>\d{2}:\d{2}:\d{2})", _dmy_dash),
    # 10/13/16/19 digits = seconds/ms/us/ns, matching parse_iso8601's
    # precision dispatch (a bare 10-digit run only, then the optional
    # ms/us/ns extensions), so adaptively-parsed epochs get the same
    # correct scaling as the built-in parsers.
    ("epoch", r"\b1\d{9}(?:\d{3}|\d{6}|\d{9})?\b", _epoch),
)

HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SKIP_HOST_TOKENS = {"error", "warning", "info", "debug", "notice", "kernel"}

# Syslog-style program tag following the host: "app:", "app[pid]:".
TAG_RE = re.compile(r"^(?P<app>[\w\-/\.]+)(?:\[(?P<pid>[^\]]+)\])?:$")
# The same shape as a regex fragment for synthesized patterns.
_TAG_SRC = r"(?:(?P<adaptive_app>[\w\-/\.]+)(?:\[(?P<adaptive_pid>[^\]]+)\])?:\s+)?"


def _valid_host(candidate: Optional[str]) -> bool:
    return bool(
        candidate
        and "=" not in candidate
        and HOST_RE.match(candidate)
        and candidate.lower() not in _SKIP_HOST_TOKENS
        and not candidate.isdigit()
    )

_CACHE: Dict[str, Tuple[Pattern[str], str, Callable]] = {}
_CACHE_MAX = 256


def _signature(line: str) -> str:
    """Reduce a line to a layout signature: token classes of the prefix.

    Only the first few tokens participate — the layout (timestamp + host)
    lives there, while later tokens are free-form message words that must
    not fragment the cache.
    """
    tokens = line[:96].split()[:4]
    classes = []
    for token in tokens:
        cls = re.sub(r"[A-Za-z]+", "A", token)
        cls = re.sub(r"\d+", "9", cls)
        classes.append(cls)
    return " ".join(classes)


def clear_cache() -> None:
    _CACHE.clear()


def cache_size() -> int:
    return len(_CACHE)


def _build_event(line, pri, ts, host, msg, app=None, pid=None):
    from .parsers import ParsedEvent

    facility, severity = convert_pri(pri)
    return ParsedEvent(
        pri=pri,
        facility=facility,
        severity=severity,
        ts=ts,
        ts_orig="",
        host=host,
        app=app,
        pid=pid,
        msgid=None,
        sd={},
        msg=sanitize_message(msg),
        raw=line,
        source_hint="adaptive",
    )


def adaptive_parse(line: str, *, now: Optional[datetime] = None):
    """Parse an unknown-format line, learning its layout on first sight."""

    raw = line
    pri = None
    pri_match = PRI_RE.match(line)
    if pri_match:
        pri = int(pri_match.group(1))
        line = line[pri_match.end():]

    sig = _signature(line)
    cached = _CACHE.get(sig)
    if cached is not None:
        pattern, _name, conv = cached
        match = pattern.match(line)
        if match is not None:
            try:
                ts = conv(pattern_ts_match(pattern, match), now)
            except (ValueError, KeyError):
                ts = None
            gd = match.groupdict()
            host = gd.get("adaptive_host")
            app = gd.get("adaptive_app")
            pid = gd.get("adaptive_pid")
            msg = gd.get("adaptive_msg")
            msg = line if msg is None else msg
            # The shape signature reduces all words to the same class, so a
            # cached host slot may capture a non-host token; revalidate.
            if host is not None and not _valid_host(host.rstrip(":,")):
                tag = f"{app}[{pid}]: " if app and pid else (f"{app}: " if app else "")
                msg = f"{host} {tag}{msg}".strip()
                host = app = pid = None
            return _build_event(raw, pri, ts, host, msg, app=app, pid=pid)

    # Analysis pass: find the earliest timestamp in the line head.
    best = None
    for name, src, conv in TIMESTAMP_LIB:
        match = re.compile(src).search(line[:96])
        if match and (best is None or match.start() < best[0].start()):
            best = (match, name, src, conv)
    if best is None:
        return None
    ts_match, name, src, conv = best
    try:
        ts = conv(ts_match, now)
    except (ValueError, KeyError):
        return None

    # Host candidate: the first plausible token after the timestamp that is
    # not a key=value pair or severity word. A leading timezone remnant the
    # timestamp library could not consume (a lone "+02"/"CEST") must not be
    # mistaken for the host — such tokens fail _valid_host and stay in msg.
    rest = line[ts_match.end():].lstrip(" :,\t")
    host = None
    app = None
    pid = None
    msg = rest
    tokens = rest.split(None, 1)
    if tokens:
        candidate = tokens[0].rstrip(":,")
        if _valid_host(candidate):
            host = candidate
            msg = tokens[1] if len(tokens) > 1 else ""
            # Program tag after the host ("app:" / "app[pid]:"): split it
            # off so it maps to the CEF process field instead of polluting
            # the message.
            tag_tokens = msg.split(None, 1)
            if tag_tokens:
                tag_match = TAG_RE.match(tag_tokens[0])
                if tag_match:
                    app = tag_match.group("app")
                    pid = tag_match.group("pid")
                    msg = tag_tokens[1] if len(tag_tokens) > 1 else ""

    # Synthesize and cache a pattern for this layout.
    prefix = line[: ts_match.start()]
    parts = [re.escape(prefix), f"(?P<adaptive_ts>{src})", r"[\s:,]*"]
    if host is not None:
        parts.append(r"(?P<adaptive_host>\S+?):?(?:\s+|$)")
        parts.append(_TAG_SRC)
    parts.append(r"(?P<adaptive_msg>.*)$")
    try:
        pattern = re.compile("".join(parts))
    except re.error:
        pattern = None
    if pattern is not None and pattern.match(line):
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[sig] = (pattern, name, conv)

    return _build_event(raw, pri, ts, host, msg, app=app, pid=pid)


def pattern_ts_match(pattern: Pattern[str], match: "re.Match[str]"):
    """Re-match the timestamp portion so converters see their own groups."""
    ts_text = match.group("adaptive_ts")
    for _name, src, _conv in TIMESTAMP_LIB:
        m = re.compile(src).fullmatch(ts_text)
        if m:
            return m
    raise ValueError(f"cached timestamp no longer matches: {ts_text!r}")


__all__ = ["adaptive_parse", "cache_size", "clear_cache"]
