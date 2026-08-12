from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Optional

from .parsers import ParsedEvent, ParserError, autodetect_and_parse
from .normalizer import NormalizedEvent, normalize
from .utils import sanitize_message
from .mappings import CISCO_ASA, CISCO_IOS, F5, FORTINET, LINUX, SOPHOS, VMWARE
from .cef import CEFEvent, build_cef

logger = logging.getLogger(__name__)

_MAPPING_HEADER_KEYS = (
    "deviceVendor", "deviceProduct", "deviceVersion", "eventClassId", "name"
)
_EXTENSION_KEY_RE = re.compile(r"^[A-Za-z0-9_.]+$")

# One printf-style conversion as templates are rendered (``template % fields``):
# either a literal "%%" or a mapping key followed by optional flags, width,
# precision and length modifier. A width/precision of "*" is deliberately
# excluded because it consumes positional arguments a mapping cannot supply.
_FORMAT_SPEC_RE = re.compile(
    r"%(?:%|\((?P<key>[^)]*)\)[#0\- +]*\d*(?:\.\d+)?[hlL]?[diouxXeEfFgGcrsa])"
)


def _validate_template(template: str, where: str, what: str) -> None:
    """Reject a template that cannot render, before any record is produced.

    ``MappingResolver._format`` swallows a rendering failure and returns "",
    which silently falls a header back to its default or drops an extension.
    A malformed template is a configuration error, so surface it eagerly.
    """
    position = 0
    while True:
        start = template.find("%", position)
        if start == -1:
            return
        match = _FORMAT_SPEC_RE.match(template, start)
        if match is None:
            raise ValueError(
                f"{where}: {what} template {template!r} has an invalid format "
                f"specifier at index {start} (use '%%' for a literal percent)"
            )
        if match.group("key") is not None and not match.group("key"):
            raise ValueError(
                f"{where}: {what} template {template!r} has an empty format key"
            )
        position = match.end()


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
        data = mapping
        where = "mapping"
    else:
        path = Path(mapping)
        with path.open("r", encoding="utf-8") as fp:
            data = json.load(fp)
        where = str(path)
    # Structural validation with clear messages: a top-level array would
    # otherwise TypeError deep inside the renderer, and a wrong-shaped
    # extensions/severity_map would fail per event instead of up front.
    if not isinstance(data, Mapping):
        raise ValueError(f"{where}: mapping must be a JSON object")
    for key in ("extensions", "severity_map"):
        if key in data and not isinstance(data[key], Mapping):
            raise ValueError(f"{where}: '{key}' must be an object")
    for key in _MAPPING_HEADER_KEYS:
        if key in data:
            if not isinstance(data[key], str):
                raise ValueError(f"{where}: '{key}' must be a string")
            _validate_template(data[key], where, f"header {key!r}")
    for key, template in data.get("extensions", {}).items():
        if not isinstance(key, str) or not _EXTENSION_KEY_RE.fullmatch(key):
            raise ValueError(f"{where}: invalid extension key {key!r}")
        if not isinstance(template, str):
            raise ValueError(
                f"{where}: extension template for {key!r} must be a string"
            )
        _validate_template(template, where, f"extension {key!r}")
    for source, target in data.get("severity_map", {}).items():
        source_text, target_text = str(source), str(target)
        if not (
            source_text.isascii() and source_text.isdigit()
            and len(source_text) == 1
            and 0 <= int(source_text) <= 7
        ):
            raise ValueError(
                f"{where}: severity_map key {source!r} must be an integer from 0 to 7"
            )
        if not (
            target_text.isascii() and target_text.isdigit()
            and len(target_text) <= 2
            and 0 <= int(target_text) <= 10
        ):
            raise ValueError(
                f"{where}: severity_map value {target!r} must be an integer from 0 to 10"
            )
    return data


def to_cef(
    event: NormalizedEvent,
    mapping: Mapping[str, Any] | Path | str | None = None,
    *,
    validate: bool = False,
    strict: bool = False,
) -> str:
    """Convert a normalized event into a CEF string.

    With ``validate=True``, extension values are checked against the
    ArcSight dictionary and violations logged as warnings; ``strict=True``
    additionally raises :class:`syslogcef.validation.CEFValidationError`
    on type or length violations.
    """

    if mapping is None:
        mapping_data = _guess_mapping(event)
    else:
        mapping_data = _load_mapping(mapping)
    cef_event = build_cef(event, mapping_data, validate=validate, strict=strict)
    return cef_event.render()


def convert_line(
    line: str,
    *,
    mode: Optional[str] = None,
    mapping: Mapping[str, Any] | Path | str | None = None,
    now: Optional[datetime] = None,
    validate: bool = False,
    strict: bool = False,
) -> str:
    """Full pipeline that parses, normalizes and converts a syslog line."""

    parsed = parse_syslog(line, mode=mode, now=now)
    normalized = normalize_event(parsed)

    return to_cef(normalized, mapping, validate=validate, strict=strict)


class StreamConverter:
    """Stateful converter for an ordered stream of syslog lines.

    Multi-line records (macOS install.log, wrapped plist/JSON payloads in
    Apple system logs, Java stack traces) continue onto lines that begin
    with whitespace and carry no syslog header of their own. Converted in
    isolation such a line gets no timestamp and the local machine's
    hostname — inside a container that is the container ID, not the host
    that produced the log. Here a whitespace-indented line instead
    inherits host, app, pid, PRI, and timestamp from the most recent
    fully-parsed event and is tagged ``source_hint="continuation"``. One
    CEF record is still emitted per input line.

    Context is tracked per ``source`` (e.g. one entry per input file), so
    interleaved streams — several files tailed at once — never inherit
    another file's host or timestamp. Callers with a single stream can
    ignore the parameter.
    """

    def __init__(
        self,
        *,
        mode: Optional[str] = None,
        mapping: Mapping[str, Any] | Path | str | None = None,
        validate: bool = False,
        strict: bool = False,
    ) -> None:
        self.mode = mode
        self.mapping = mapping
        self.validate = validate
        self.strict = strict
        self._contexts: dict[str, ParsedEvent] = {}

    def convert(self, line: str, *, now: Optional[datetime] = None, source: str = "") -> str:
        ctx = self._contexts.get(source)
        is_continuation = line[:1] in ("\t", " ") and ctx is not None
        try:
            parsed = parse_syslog(line, mode=self.mode, now=now)
        except ParserError:
            if not is_continuation:
                raise
            # A forced --mode rejects headerless continuation lines; a
            # continuation with context must inherit, not abort the run.
            parsed = ParsedEvent(
                pri=None,
                facility=None,
                severity=None,
                ts=None,
                ts_orig="",
                host=None,
                app=None,
                pid=None,
                msgid=None,
                sd={},
                msg=sanitize_message(line),
                raw=line,
                source_hint="unknown",
            )
        if is_continuation:
            parsed.host = ctx.host
            parsed.app = parsed.app or ctx.app
            parsed.pid = parsed.pid or ctx.pid
            if parsed.ts is None:
                parsed.ts = ctx.ts
            if parsed.pri is None:
                parsed.pri = ctx.pri
                parsed.facility = ctx.facility
                parsed.severity = ctx.severity
            parsed.msg = parsed.msg.lstrip()
            parsed.source_hint = "continuation"
        elif parsed.host is not None and parsed.source_hint != "unknown":
            # Only a line whose host was actually parsed (not the
            # guessed fallback) may become continuation context.
            self._contexts[source] = parsed
        normalized = normalize_event(parsed)
        return to_cef(normalized, self.mapping, validate=self.validate, strict=self.strict)


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
    if "logid" in event.kv:
        return FORTINET
    if "log_id" in event.kv:
        return SOPHOS
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
    "StreamConverter",
    "convert_line",
    "normalize_event",
    "parse_syslog",
    "to_cef",
]
