from __future__ import annotations

import warnings
from pathlib import Path

from syslogcef import convert_line

warnings.warn(
    "ciscoasacef.py is deprecated; use the 'syslogcef' package and CLI instead",
    DeprecationWarning,
    stacklevel=2,
)

_DEFAULT_MAPPING = Path(__file__).resolve().parent / "syslogcef" / "mappings" / "cisco_asa.json"


def convert(log_line: str) -> str:
    """Convert a Cisco ASA syslog line to CEF using the new library."""

    return convert_line(log_line, mapping=_DEFAULT_MAPPING)


__all__ = ["convert"]
