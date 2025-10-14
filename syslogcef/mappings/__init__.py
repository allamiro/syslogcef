from __future__ import annotations

import json
from importlib import resources
from typing import Any, Mapping

__all__ = [
    "load_mapping",
    "CISCO_ASA",
    "CISCO_IOS",
    "F5",
    "LINUX",
    "VMWARE",
]


def _load(name: str) -> Mapping[str, Any]:
    with resources.files(__package__).joinpath(f"{name}.json").open("r", encoding="utf-8") as fp:
        return json.load(fp)


CISCO_ASA = _load("cisco_asa")
CISCO_IOS = _load("cisco_ios")
F5 = _load("f5")
LINUX = _load("linux")
VMWARE = _load("vmware")


def load_mapping(name: str) -> Mapping[str, Any]:
    mapping = {
        "cisco_asa": CISCO_ASA,
        "cisco_ios": CISCO_IOS,
        "f5": F5,
        "linux": LINUX,
        "vmware": VMWARE,
    }
    try:
        return mapping[name]
    except KeyError as exc:
        raise KeyError(f"Unknown mapping {name!r}") from exc
