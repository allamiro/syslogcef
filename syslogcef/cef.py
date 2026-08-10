from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Mapping, Optional

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
        "rawEvent": "%(raw)s",
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
            header[key] = cef_escape_header(self._format(template, fields))
        severity = self._resolve_severity(fields)
        header["severity"] = severity
        return header

    def _resolve_severity(self, fields: Mapping[str, Any]) -> str:
        severity_map = {**DEFAULT_MAPPING["severity_map"], **self.mapping.get("severity_map", {})}
        value = fields.get("severity")
        if value is None and "pri" in fields:
            _, severity_value = divmod(int(fields.get("pri", 0)), 8)
            value = severity_value
        if value is None:
            return "3"
        return severity_map.get(str(value), str(value))

    def resolve_extensions(self, fields: Mapping[str, Any]) -> Dict[str, str]:
        extensions = {}
        merged = DEFAULT_MAPPING["extensions"].copy()
        merged.update(self.mapping.get("extensions", {}))
        for key, template in merged.items():
            value = self._format(template, fields)
            if value:
                extensions[key] = cef_escape(str(value))
        return extensions

    def _format(self, template: str, fields: Mapping[str, Any]) -> str:
        try:
            return template % fields
        except KeyError as exc:
            logger.debug("Missing key %s for template %s", exc, template)
            return ""
        except (ValueError, TypeError) as exc:
            logger.warning("Invalid template %r: %s", template, exc)
            return ""


def build_cef(event: NormalizedEvent, mapping: Mapping[str, Any]) -> CEFEvent:
    resolver = MappingResolver(mapping)
    fields = event.as_field_dict()
    header = resolver.resolve_header(fields)
    extensions = resolver.resolve_extensions(fields)
    return CEFEvent(header=header, extensions=extensions)


__all__ = ["CEFEvent", "build_cef"]
