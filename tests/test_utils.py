from __future__ import annotations

from datetime import datetime, timezone

import pytest

from syslogcef.utils import (
    cef_escape,
    convert_pri,
    ensure_tzaware,
    month_abbr_to_int,
    parse_iso8601,
    parse_key_value_pairs,
    sanitize_message,
)


def test_cef_escape_special_characters():
    assert cef_escape("a|b") == "a\\|b"
    assert cef_escape("a=b") == "a\\=b"
    assert cef_escape("a\\b") == "a\\\\b"
    assert cef_escape("a\nb") == "a\\nb"


def test_convert_pri():
    assert convert_pri(166) == (20, 6)
    assert convert_pri(0) == (0, 0)
    assert convert_pri(None) == (None, None)


def test_month_abbr_to_int():
    assert month_abbr_to_int("Jan") == 1
    assert month_abbr_to_int("Dec") == 12
    with pytest.raises(ValueError):
        month_abbr_to_int("Foo")


def test_parse_iso8601_variants():
    assert parse_iso8601("2023-07-01T12:00:00Z") == datetime(
        2023, 7, 1, 12, 0, 0, tzinfo=timezone.utc
    )
    assert parse_iso8601("2023-07-01T12:00:00+02:00").utcoffset().total_seconds() == 7200
    # Epoch seconds and journald-style epoch microseconds
    assert parse_iso8601("1688212800") == datetime(2023, 7, 1, 12, 0, 0, tzinfo=timezone.utc)
    micros = parse_iso8601("1688212800123456")
    assert micros.microsecond == 123456
    with pytest.raises(ValueError):
        parse_iso8601("not-a-date")


def test_ensure_tzaware():
    naive = datetime(2023, 1, 1, 12, 0, 0)
    aware = ensure_tzaware(naive)
    assert aware.tzinfo is timezone.utc
    assert ensure_tzaware(None) is None


def test_sanitize_message_replaces_null_bytes():
    cleaned = sanitize_message("abc" + chr(0) + "def")
    assert chr(0) not in cleaned
    assert cleaned.startswith("abc")
    assert cleaned.endswith("def")


def test_parse_key_value_pairs():
    pairs = parse_key_value_pairs('src=10.0.0.1 dst=10.0.0.2 user="bob" action=allow')
    assert pairs["src"] == "10.0.0.1"
    assert pairs["dst"] == "10.0.0.2"
    assert pairs["user"] == "bob"
    assert pairs["action"] == "allow"


def test_parse_key_value_pairs_handles_escaped_quotes_and_commas():
    pairs = parse_key_value_pairs(
        r'reason="user said \"hello\"" src=10.0.0.1,dst=10.0.0.2 note=one,two'
    )

    assert pairs["reason"] == 'user said "hello"'
    assert pairs["src"] == "10.0.0.1"
    assert pairs["dst"] == "10.0.0.2"
    assert pairs["note"] == "one,two"


def test_comma_delimited_kv_stream_is_still_detected():
    # KEY_VALUE_RE excludes the trailing separator from a value, so the
    # coverage heuristic must count inter-pair delimiters or a stream of
    # short comma-separated values falls below the threshold.
    from syslogcef.parsers import _looks_like_kv_line

    assert _looks_like_kv_line("a=1, b=2, c=3, d=4")
    assert _looks_like_kv_line("src=1.1.1.1, dst=2.2.2.2, act=allow")
    # Prose with a few embedded pairs must still be rejected.
    assert not _looks_like_kv_line(
        "the quick brown fox jumped over a=1 lazy dog b=2 and c=3 more padding"
    )
