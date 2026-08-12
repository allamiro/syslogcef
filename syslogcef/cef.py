from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Mapping

from .normalizer import NormalizedEvent
from .utils import cef_escape, cef_escape_header

logger = logging.getLogger(__name__)


DEFAULT_MAPPING = {
    "deviceVendor": "Generic",
    "deviceProduct": "Syslog",
    "deviceVersion": "1.0",
    "eventClassId": "syslog",
    "name": "%(message_short)s",
    "severity_map": {
        "0": "10",
        "1": "8",
        "2": "7",
        "3": "6",
        "4": "5",
        "5": "3",
        "6": "2",
        "7": "1",
    },
    "extensions": {
        "msg": "%(msg)s",
        # The syslog HOSTNAME identifies the device that GENERATED the
        # event, so it is the source host (shost) — never the destination
        # (dhost), which is reserved for network-specific logs whose
        # payload names an actual destination. shost (max 1023) rather
        # than dvchost (max 100): RFC 5424 hostnames may reach 255 chars,
        # which would fail --strict against dvchost's dictionary limit.
        # Empty values are dropped, so this is a no-op for a hostless line.
        "shost": "%(host)s",
        # Event time (epoch milliseconds) parsed from the line, or the
        # processing time when the line carried no usable timestamp.
        "rt": "%(rt)s",
        # The raw line travels in a labeled custom string: rawEvent is a
        # consumer-side key producers must not set (see docs/cef_fields.md),
        # and every bundled mapping already uses this shape.
        "cs1Label": "rawEvent",
        "cs1": "%(raw)s",
    },
}


@dataclass
class CEFEvent:
    header: Dict[str, str]
    extensions: Dict[str, str]

    def render(self) -> str:
        extension_str = " ".join(f"{k}={v}" for k, v in self.extensions.items())
        return "CEF:0|{deviceVendor}|{deviceProduct}|{deviceVersion}|{eventClassId}|{name}|{severity}|{extension}".format(
            extension=extension_str,
            **self.header,
        )


class MappingResolver:
    def __init__(self, mapping: Mapping[str, Any]) -> None:
        merged = DEFAULT_MAPPING | mapping
        self.mapping = merged

    def resolve_header(self, fields: Mapping[str, Any]) -> Dict[str, str]:
        header = {}
        for key in ["deviceVendor", "deviceProduct", "deviceVersion", "eventClassId", "name"]:
            template = self.mapping.get(key, DEFAULT_MAPPING[key])
            value = self._format(template, fields)
            if not value:
                # A template referencing missing fields must not leave an
                # empty CEF header slot; fall back to the default template.
                value = self._format(DEFAULT_MAPPING[key], fields)
            header[key] = cef_escape_header(value)
        severity = self._resolve_severity(fields)
        header["severity"] = severity
        return header

    def _resolve_severity(self, fields: Mapping[str, Any]) -> str:
        severity_map = {**DEFAULT_MAPPING["severity_map"], **self.mapping.get("severity_map", {})}
        value = fields.get("severity")
        if value is None and "pri" in fields:
            # "pri" may come from an untrusted kv pair (pri=zzz), not just
            # a parsed <PRI> header; garbage must not abort the pipeline.
            try:
                _, value = divmod(int(fields.get("pri", 0)), 8)
            except (TypeError, ValueError):
                value = None
        if value is None:
            return "3"
        mapped = str(severity_map.get(str(value), value))
        # The CEF:0 header severity slot must be numeric 0-10; anything
        # else (non-numeric kv severity, bad severity_map value) falls
        # back to the default rather than corrupting the header. ASCII
        # check required: str.isdigit() accepts Unicode digits like "²"
        # that int() rejects.
        # Length guard first: int() on a multi-thousand-digit string hits
        # Python 3.11+'s integer-conversion limit and raises. Valid CEF
        # severities are at most two characters ("10").
        if not (mapped.isascii() and mapped.isdigit() and len(mapped) <= 2) or int(mapped) > 10:
            return "3"
        return mapped

    def resolve_raw_extensions(self, fields: Mapping[str, Any]) -> Dict[str, str]:
        raw = {}
        merged = DEFAULT_MAPPING["extensions"].copy()
        user_extensions = self.mapping.get("extensions", {})
        # The default cs1/cs1Label pair is atomic: if a custom mapping
        # touches either member, drop both defaults so a custom cs1 is
        # not silently labeled "rawEvent" (nor a custom label attached
        # to the default raw line).
        if "cs1" in user_extensions or "cs1Label" in user_extensions:
            merged.pop("cs1", None)
            merged.pop("cs1Label", None)
        merged.update(user_extensions)
        for key, template in merged.items():
            value = self._format(template, fields)
            if value:
                raw[key] = str(value)
        return raw

    def resolve_extensions(self, fields: Mapping[str, Any]) -> Dict[str, str]:
        return {k: cef_escape(v) for k, v in self.resolve_raw_extensions(fields).items()}

    def _format(self, template: str, fields: Mapping[str, Any]) -> str:
        try:
            return template % fields
        except KeyError as exc:
            logger.debug("Missing key %s for template %s", exc, template)
            return ""
        except (ValueError, TypeError) as exc:
            logger.warning("Invalid template %r: %s", template, exc)
            return ""


def build_cef(
    event: NormalizedEvent,
    mapping: Mapping[str, Any],
    *,
    validate: bool = False,
    strict: bool = False,
) -> CEFEvent:
    resolver = MappingResolver(mapping)
    fields = event.as_field_dict()
    header = resolver.resolve_header(fields)
    raw = resolver.resolve_raw_extensions(fields)
    if validate or strict:
        from .validation import CEFValidationError, validate_extensions

        findings = validate_extensions(raw)
        for finding in findings:
            logger.warning("CEF validation: %s", finding)
        fatal = [f for f in findings if f.fatal]
        if strict and fatal:
            raise CEFValidationError("; ".join(str(f) for f in fatal))
    extensions = {k: cef_escape(v) for k, v in raw.items()}
    return CEFEvent(header=header, extensions=extensions)


__all__ = ["CEFEvent", "build_cef"]
