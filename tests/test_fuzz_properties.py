"""Property-based fuzz tests for the parse -> normalize -> CEF pipeline.

These verify the project's core promises against arbitrary and mutated
input (issue #66):

1. ``convert_line`` never raises — malformed lines fall back to a
   raw-message event instead of aborting a stream.
2. Output is structurally valid CEF: a ``CEF:0`` prefix, exactly seven
   header fields when split on unescaped pipes, and no CR/LF in the
   header so crafted content cannot forge or split records.
3. No pathological slowdowns: each line converts within a generous
   wall-clock budget, guarding against catastrophic regex backtracking
   in synthesized adaptive patterns.
4. The adaptive pattern cache stays bounded for streams of
   ever-changing line shapes.
5. ``--validate`` / ``--strict`` never crash with anything but the
   documented validation error.

Requires ``hypothesis`` (``pip install syslog2cef[fuzz]``); the module
is skipped where it is not installed, e.g. during RPM %check. Set
SYSLOGCEF_HYPOTHESIS_PROFILE=deep for the scheduled long run.
"""

from __future__ import annotations

import os
import re
import time

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given, settings, strategies as st  # noqa: E402

from syslogcef import convert_line  # noqa: E402
from syslogcef import adaptive  # noqa: E402
from syslogcef.validation import CEFValidationError  # noqa: E402

# Profiles are registered centrally in conftest.py (a 2s deadline so a
# slow-but-passing regression fails fast in the deep run instead of
# draining the job budget); here we only load.
settings.load_profile(os.environ.get("SYSLOGCEF_HYPOTHESIS_PROFILE", "ci"))

# Real-world seed lines covering every parser family; mutations of these
# reach much deeper into the parsers than raw random text does.
SEEDS = [
    "<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2",
    "<134>1 2026-08-11T07:00:00.123Z host01 app 1234 MSGID [exampleSDID@32473 iut=\"3\"] An application event",
    '{"@timestamp":"2026-08-11T07:00:00.000000+00:00","host":"web1","severity":"info","facility":"daemon","syslogtag":"nginx:","message":"GET / 200"}',
    "Aug 11 07:00:00 fw01 kernel: [12345.678] iptables: IN=eth0 OUT= SRC=10.0.0.1 DST=10.0.0.2",
    "000123: Aug 11 07:00:00.123: %SYS-5-CONFIG_I: Configured from console by admin",
    "ts=2026-08-11T07:00:00Z level=info msg=\"hello world\" src=10.0.0.1",
]

# Text without CR/LF: the API contract is one event per line (the CLI
# strips newlines before calling convert_line).
line_text = st.text(
    alphabet=st.characters(blacklist_characters="\r\n", blacklist_categories=("Cs",)),
    max_size=2048,
)


def split_unescaped_pipes(record: str) -> list:
    """Split a CEF record on pipes, honouring backslash escapes."""
    parts, cur, i = [], [], 0
    while i < len(record):
        ch = record[i]
        if ch == "\\" and i + 1 < len(record):
            cur.append(ch)
            cur.append(record[i + 1])
            i += 2
            continue
        if ch == "|":
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def assert_valid_cef(cef: str) -> None:
    parts = split_unescaped_pipes(cef)
    # 7 header fields + at least one extension chunk (pipes are legal
    # unescaped inside the extension part, so more chunks may follow).
    assert len(parts) >= 8, f"only {len(parts)} pipe-separated parts"
    # Positional checks so an unescaped pipe inside a header value cannot
    # shift fields undetected: the version slot must be exactly CEF:0 and
    # the severity slot must be numeric — a shifted header puts free text
    # there and fails.
    assert parts[0] == "CEF:0", f"bad version field: {parts[0]!r}"
    assert re.fullmatch(r"\d{1,2}", parts[6]), f"non-numeric severity: {parts[6]!r}"
    for field in parts[:7]:
        assert "\r" not in field and "\n" not in field, "CR/LF in CEF header"


@given(line=line_text)
def test_arbitrary_text_never_raises_and_renders_valid_cef(line):
    start = time.perf_counter()
    cef = convert_line(line)
    elapsed = time.perf_counter() - start
    assert_valid_cef(cef)
    assert elapsed < 1.0, f"conversion took {elapsed:.2f}s (possible ReDoS)"


@given(seed=st.sampled_from(SEEDS), pos=st.integers(0, 200), junk=line_text)
def test_mutated_real_lines_never_raise(seed, pos, junk):
    line = seed[: min(pos, len(seed))] + junk + seed[min(pos, len(seed)):]
    assert_valid_cef(convert_line(line))


@given(line=st.text(max_size=512))
def test_embedded_newlines_cannot_split_records(line):
    # Even if raw CR/LF reaches the API, the rendered header must stay
    # single-line so a crafted message cannot forge a second record.
    cef = convert_line(line)
    header = "|".join(split_unescaped_pipes(cef)[:7])
    assert "\r" not in header and "\n" not in header


@given(line=line_text)
def test_validate_and_strict_never_crash(line):
    convert_line(line, validate=True)
    try:
        convert_line(line, validate=True, strict=True)
    except CEFValidationError:
        pass


def test_adaptive_cache_stays_bounded():
    adaptive.clear_cache()
    # Lines with a recognizable timestamp behind a prefix no built-in
    # parser accepts, in rotating shapes: these actually exercise the
    # adaptive engine's pattern synthesis and cache.
    prefixes = ["#", "@", "::", "--", "~", ";;", "!", "**", "..", "^"]
    for i in range(2000):
        prefix = prefixes[i % len(prefixes)] * (i % 4 + 1)
        convert_line(f"{prefix} Aug 11 07:00:{i % 60:02d} host{i} payload number {i}")
    # Guard against vacuity: the loop must have populated the cache ...
    assert adaptive.cache_size() > 0, "test lines never reached the adaptive engine"
    # ... and the cache must stay at or below its documented cap.
    assert adaptive.cache_size() <= adaptive._CACHE_MAX
