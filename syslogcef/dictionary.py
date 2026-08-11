"""The CEF field dictionary: one data file the whole pipeline consults.

``dictionary.json`` (shipped as package data) is the single source of
truth for CEF extension knowledge, derived from the ArcSight Extension
Dictionary (see ``docs/cef_fields.md``):

- ``keys``: every CEF key with its data type, maximum length, and scope
  (``producer`` or ``consumer``). Validation checks types/lengths from
  here and warns when producer output sets a consumer-side key.
- ``aliases``: common source-log field names mapped to canonical CEF
  keys (``srcip`` -> ``src``, ``dstport`` -> ``dpt``, ``user`` ->
  ``suser``, ...). Normalization applies these to the key=value pairs
  extracted from any event — including adaptive-parsed lines — so
  mappings and validation always see canonical names.

Loaded once and cached; a broken data file fails loudly at first use
rather than silently disabling validation.
"""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Dict, FrozenSet, Tuple


@lru_cache(maxsize=1)
def _load() -> dict:
    # importlib.resources, not a filesystem path: the package also runs
    # from the standalone zipapp, where package files are inside the
    # archive and Path(__file__)-style access fails (mappings/__init__.py
    # uses the same mechanism for the same reason).
    with resources.files("syslogcef").joinpath("dictionary.json").open(
        "r", encoding="utf-8"
    ) as fp:
        data = json.load(fp)
    if not isinstance(data.get("keys"), dict) or not isinstance(data.get("aliases"), dict):
        raise ValueError("dictionary.json: expected 'keys' and 'aliases' objects")
    return data


@lru_cache(maxsize=1)
def cef_keys() -> Dict[str, Tuple[str, int]]:
    """CEF key -> (type, max length) for every known key, any scope."""
    return {
        key: (spec["type"], spec["len"]) for key, spec in _load()["keys"].items()
    }


@lru_cache(maxsize=1)
def consumer_keys() -> FrozenSet[str]:
    """Keys the ArcSight side sets; producers should not emit these."""
    return frozenset(
        key for key, spec in _load()["keys"].items() if spec["scope"] == "consumer"
    )


@lru_cache(maxsize=1)
def field_aliases() -> Dict[str, str]:
    """Source-log field name -> canonical CEF key."""
    return dict(_load()["aliases"])


__all__ = ["cef_keys", "consumer_keys", "field_aliases"]
