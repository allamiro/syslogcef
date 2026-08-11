"""User-defined parsers: declarative pattern files and a registration API.

Two ways to teach syslogcef a format it does not know (issue #67):

1. **Pattern files** — ``--patterns file.json`` (or ``load_patterns()``
   from Python) loads named regexes whose named groups map to event
   fields, the same way ``--mapping`` supplies CEF mappings::

       {
         "patterns": [
           {
             "name": "acme_fw",
             "regex": "^(?P<ts>\\\\d{4}-\\\\d{2}-\\\\d{2} \\\\d{2}:\\\\d{2}:\\\\d{2}) (?P<host>\\\\S+) (?P<app>\\\\w+): (?P<msg>.*)$",
             "timestamp_format": "%Y-%m-%d %H:%M:%S",
             "priority": "after"
           }
         ]
       }

   Recognized groups: ``pri``, ``host``, ``app``, ``pid``, ``msgid``,
   ``msg``, and ``ts`` (which requires ``timestamp_format``: a strptime
   format, ``iso8601``, or ``epoch``). ``priority`` decides whether the
   pattern is tried ``"before"`` the built-in parsers or ``"after"``
   them (the default — still ahead of the adaptive fallback). Pattern
   names are also accepted by ``--mode``.

2. **``register_parser(name, fn)``** — register a full parser function
   ``fn(line) -> ParsedEvent | None`` programmatically; the name becomes
   a valid ``--mode`` value.

Files are validated eagerly at load time — regex syntax, group names,
timestamp formats, duplicate names — so a typo fails at startup with a
clear message instead of mid-stream. User regexes run against untrusted
log content: keep them anchored and free of nested quantifiers (ReDoS),
as they enjoy the same time budget as everything else, i.e. none.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from .parsers import PARSERS, ParsedEvent
from .utils import convert_pri, parse_iso8601

_EVENT_GROUPS = {"pri", "host", "app", "pid", "msgid", "msg"}
_TS_SPECIAL_FORMATS = {"iso8601", "epoch"}
_PRIORITIES = {"before", "after"}


class PatternFileError(ValueError):
    """A pattern file failed validation; the message names the pattern."""


@dataclass
class CustomPattern:
    name: str
    regex: "re.Pattern[str]"
    timestamp_format: Optional[str]
    priority: str

    def parse(self, line: str, *, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
        match = self.regex.match(line)
        if match is None:
            return None
        groups = {k: v for k, v in match.groupdict().items() if v is not None}

        pri = int(groups["pri"]) if groups.get("pri", "").isdigit() else None
        facility, severity = convert_pri(pri)

        ts = None
        ts_orig = groups.get("ts", "")
        if ts_orig and self.timestamp_format:
            try:
                ts = _parse_timestamp(ts_orig, self.timestamp_format, now=now)
            except (ValueError, OverflowError, OSError):
                # OverflowError/OSError: out-of-range epoch values. A bad
                # timestamp never drops the line, in any mode.
                ts = None

        return ParsedEvent(
            pri=pri,
            facility=facility,
            severity=severity,
            ts=ts,
            ts_orig=ts_orig,
            host=groups.get("host"),
            app=groups.get("app"),
            pid=groups.get("pid"),
            msgid=groups.get("msgid"),
            msg=groups.get("msg", line),
            raw=line,
            source_hint=f"custom:{self.name}",
        )


# Directives datetime.strptime accepts on every platform. Validated at
# load time so a typo like %Q fails at startup, not silently mid-stream.
_STRPTIME_DIRECTIVES = frozenset("aAbBcdfGHIjmMpSuUVwWxXyYzZ%")


def _validate_strptime_format(fmt: str) -> bool:
    """Return True if *fmt* contains a year directive; raise on invalid."""
    has_year, has_directive, i = False, False, 0
    while i < len(fmt):
        if fmt[i] == "%":
            if i + 1 >= len(fmt):
                raise ValueError("trailing '%' in timestamp_format")
            nxt = fmt[i + 1]
            if nxt not in _STRPTIME_DIRECTIVES:
                raise ValueError(f"unsupported strptime directive '%{nxt}'")
            if nxt != "%":
                has_directive = True
            if nxt in "YyG":
                has_year = True
            i += 2
        else:
            i += 1
    if not has_directive:
        raise ValueError("timestamp_format contains no strptime directives")
    return has_year


def _year_with_rollover(parsed: datetime, ref: datetime) -> datetime:
    """Assign the most plausible year to a yearless timestamp.

    Keeps every parsed component (tz offset, microseconds); handles
    Feb 29 by picking the nearest leap year when needed.
    """

    def with_year(year: int) -> Optional[datetime]:
        try:
            return parsed.replace(year=year)
        except ValueError:  # Feb 29 in a non-leap year
            return None

    candidate = with_year(ref.year)
    if candidate is None:
        # Feb 29: pick the occurrence closest in time, not the first
        # leap year found in either direction.
        candidates = [c for off in range(-4, 5) if off and (c := with_year(ref.year + off))]
        if not candidates:
            return parsed
        return min(candidates, key=lambda c: abs(c - ref))
    if candidate - ref > timedelta(days=180):
        return with_year(ref.year - 1) or candidate
    if ref - candidate > timedelta(days=180):
        return with_year(ref.year + 1) or candidate
    return candidate


def _parse_timestamp(text: str, fmt: str, *, now: Optional[datetime] = None) -> datetime:
    if fmt == "iso8601":
        return parse_iso8601(text)
    if fmt == "epoch":
        return datetime.fromtimestamp(float(text), tz=timezone.utc)
    has_year = "%Y" in fmt or "%y" in fmt or "%G" in fmt
    if has_year:
        parsed = datetime.strptime(text, fmt)
    else:
        # Parse against leap year 2000 so Feb 29 survives strptime (the
        # implicit 1900 default is not a leap year), then infer the real
        # year with the same rollover logic as the built-in parsers.
        parsed = datetime.strptime(f"2000 {text}", f"%Y {fmt}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    if not has_year:
        ref = now or datetime.now(timezone.utc)
        if ref.tzinfo is None:
            ref = ref.replace(tzinfo=timezone.utc)
        parsed = _year_with_rollover(parsed, ref)
    return parsed


_registered: Dict[str, Callable] = {}
_before: List[CustomPattern] = []
_after: List[CustomPattern] = []


def register_parser(name: str, parser: Callable, *, replace: bool = False) -> None:
    """Register ``parser(line) -> ParsedEvent | None`` under ``name``.

    The name becomes a valid ``--mode`` value. Built-in parser names are
    reserved; re-registering an existing custom name requires
    ``replace=True``.
    """
    if name in PARSERS:
        raise ValueError(f"'{name}' is a built-in parser name")
    if name in _registered and not replace:
        raise ValueError(f"parser '{name}' is already registered")
    _registered[name] = parser


def get_registered(name: str) -> Optional[Callable]:
    return _registered.get(name)


def custom_parse(line: str, stage: str, *, now: Optional[datetime] = None) -> Optional[ParsedEvent]:
    """Try every loaded pattern of the given stage ("before"/"after")."""
    for pattern in _before if stage == "before" else _after:
        try:
            result = pattern.parse(line, now=now)
        except Exception:  # a broken user regex must never abort a stream
            continue
        if result is not None:
            return result
    return None


def clear_registry() -> None:
    """Forget all registered parsers and loaded patterns (for tests)."""
    _registered.clear()
    del _before[:]
    del _after[:]


def load_patterns(path: Union[str, Path]) -> int:
    """Load and validate a pattern file; returns the number of patterns.

    Raises :class:`PatternFileError` naming the offending pattern on any
    validation problem, so services fail at startup rather than
    mid-stream.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise PatternFileError(f"cannot read pattern file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise PatternFileError(f"invalid JSON in pattern file {path}: {exc}") from exc

    entries = data.get("patterns") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise PatternFileError(
            f"{path}: expected an object with a non-empty 'patterns' list"
        )

    loaded: List[CustomPattern] = []
    for index, entry in enumerate(entries):
        where = f"{path}: patterns[{index}]"
        if not isinstance(entry, dict):
            raise PatternFileError(f"{where}: entry must be an object")
        name = entry.get("name")
        if not name or not isinstance(name, str):
            raise PatternFileError(f"{where}: missing 'name'")
        where = f"{path}: pattern '{name}'"
        if name in PARSERS:
            raise PatternFileError(f"{where}: shadows a built-in parser name")
        if name in _registered or any(p.name == name for p in loaded):
            raise PatternFileError(f"{where}: duplicate name")

        regex_src = entry.get("regex")
        if not regex_src or not isinstance(regex_src, str):
            raise PatternFileError(f"{where}: missing 'regex'")
        try:
            regex = re.compile(regex_src)
        except re.error as exc:
            raise PatternFileError(f"{where}: invalid regex: {exc}") from exc

        unknown = set(regex.groupindex) - _EVENT_GROUPS - {"ts"}
        if unknown:
            raise PatternFileError(
                f"{where}: unknown capture group(s) {sorted(unknown)}; "
                f"allowed: {sorted(_EVENT_GROUPS | {'ts'})}"
            )

        ts_format = entry.get("timestamp_format")
        if ts_format is not None and not isinstance(ts_format, str):
            raise PatternFileError(f"{where}: 'timestamp_format' must be a string")
        if "ts" in regex.groupindex:
            if not ts_format:
                raise PatternFileError(
                    f"{where}: a 'ts' group requires 'timestamp_format' "
                    f"(a strptime format, 'iso8601', or 'epoch')"
                )
            if ts_format not in _TS_SPECIAL_FORMATS:
                try:
                    _validate_strptime_format(ts_format)
                except ValueError as exc:
                    raise PatternFileError(
                        f"{where}: 'timestamp_format' must be a strptime format, "
                        f"'iso8601', or 'epoch': {exc}"
                    ) from exc
        elif ts_format:
            raise PatternFileError(
                f"{where}: 'timestamp_format' given but the regex has no 'ts' group"
            )

        priority = entry.get("priority", "after")
        if not isinstance(priority, str) or priority not in _PRIORITIES:
            raise PatternFileError(
                f"{where}: 'priority' must be 'before' or 'after' (got {priority!r})"
            )

        loaded.append(
            CustomPattern(name=name, regex=regex, timestamp_format=ts_format, priority=priority)
        )

    for pattern in loaded:
        (_before if pattern.priority == "before" else _after).append(pattern)
        _registered[pattern.name] = pattern.parse
    return len(loaded)
