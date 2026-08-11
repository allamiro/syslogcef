from __future__ import annotations

import json
from importlib import resources
from typing import Any, Mapping

__all__ = [
    "load_mapping",
    "CISCO_ASA",
    "CISCO_IOS",
    "F5",
    "FORTINET",
    "LINUX",
    "SOPHOS",
    "VMWARE",
]


def _load(name: str) -> Mapping[str, Any]:
    with resources.files("syslogcef.mappings").joinpath(f"{name}.json").open("r", encoding="utf-8") as fp:
        return json.load(fp)


CISCO_ASA = _load("cisco_asa")
CISCO_IOS = _load("cisco_ios")
F5 = _load("f5")
FORTINET = _load("fortinet")
LINUX = _load("linux")
SOPHOS = _load("sophos")
VMWARE = _load("vmware")


def load_mapping(name: str) -> Mapping[str, Any]:
    mapping = {
        "cisco_asa": CISCO_ASA,
        "cisco_ios": CISCO_IOS,
        "f5": F5,
        "fortinet": FORTINET,
        "linux": LINUX,
        "sophos": SOPHOS,
        "vmware": VMWARE,
    }
    try:
        return mapping[name]
    except KeyError as exc:
        raise KeyError(f"Unknown mapping {name!r}") from exc
