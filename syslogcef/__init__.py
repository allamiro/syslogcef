"""Core API for converting syslog lines into ArcSight CEF.

This package exposes a high level pipeline composed of four functions:

``parse_syslog`` -> ``normalize_event`` -> ``to_cef`` -> ``convert_line``

Each function can be used independently or as part of the complete
conversion workflow.
"""
from __future__ import annotations

from .api import StreamConverter, convert_line, normalize_event, parse_syslog, to_cef
from .custom import PatternFileError, load_patterns, register_parser

__all__ = [
    "StreamConverter",
    "convert_line",
    "normalize_event",
    "parse_syslog",
    "to_cef",
    "load_patterns",
    "register_parser",
    "PatternFileError",
]
