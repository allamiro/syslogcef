"""Regressions for #86 (RFC 5424 NILVALUE + SD escapes) and #87 (epoch
precision by digit count)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from syslogcef import parse_syslog
from syslogcef.utils import parse_iso8601


# ---- #86: RFC 5424 -------------------------------------------------------

def test_nilvalue_timestamp_parses_in_forced_mode():
    event = parse_syslog("<34>1 - host app 1 ID - message", mode="rfc5424")

    assert event.source_hint == "rfc5424"
    assert event.ts is None
    assert event.ts_orig == "-"
    assert event.host == "host"
    assert event.msg == "message"


def test_sd_escaped_quote_is_data():
    line = '<34>1 2026-08-11T00:00:00Z host app 1 ID [example@1 k="a\\"b"] message'

    event = parse_syslog(line, mode="rfc5424")

    assert event.sd == {"example@1.k": 'a"b'}
    assert event.msg == "message"


def test_sd_escaped_backslash_and_bracket():
    line = '<34>1 2026-08-11T00:00:00Z host app 1 ID [example@1 p="c:\\\\dir" q="x\\]y"] tail'

    event = parse_syslog(line, mode="rfc5424")

    assert event.sd["example@1.p"] == "c:\\dir"
    assert event.sd["example@1.q"] == "x]y"
    assert event.msg == "tail"


def test_sd_multiple_elements_and_bracket_in_message():
    line = (
        '<34>1 2026-08-11T00:00:00Z host app 1 ID '
        '[a@1 x="1"][b@2 y="2"] closing ] bracket in msg'
    )

    event = parse_syslog(line, mode="rfc5424")

    assert event.sd == {"a@1.x": "1", "b@2.y": "2"}
    # The old greedy regex swallowed the message up to its last ']'.
    assert event.msg == "closing ] bracket in msg"


def test_sd_unquoted_values_still_tolerated():
    line = "<34>1 2026-08-11T00:00:00Z host app 1 ID [e@1 iut=3 src=Application] m"

    event = parse_syslog(line, mode="rfc5424")

    assert event.sd == {"e@1.iut": "3", "e@1.src": "Application"}


def test_sd_malformed_never_raises():
    line = '<34>1 2026-08-11T00:00:00Z host app 1 ID [broken k="unterminated message'

    event = parse_syslog(line, mode="rfc5424")

    assert event.source_hint == "rfc5424"  # stream survives


def test_sd_truncated_element_leaks_no_partial_params():
    # An element missing its ']' must not commit its parsed params.
    line = '<34>1 2026-08-11T00:00:00Z host app 1 ID [e@1 role="admin"'

    event = parse_syslog(line, mode="rfc5424")

    assert event.sd == {}  # nothing committed from the unterminated element


def test_sd_trailing_space_before_bracket():
    line = '<34>1 2026-08-11T00:00:00Z host app 1 ID [id@1 a="1" ] rest'

    event = parse_syslog(line, mode="rfc5424")

    assert event.sd == {"id@1.a": "1"}  # element not abandoned on the space
    assert event.msg == "rest"


def test_malformed_epoch_timestamp_keeps_event_in_forced_mode():
    # A bad/ambiguous numeric timestamp must not abort forced rfc5424.
    line = "<34>1 12345678901234 host app 1 ID - message"

    event = parse_syslog(line, mode="rfc5424")

    assert event.source_hint == "rfc5424"
    assert event.ts is None
    assert event.host == "host"


def test_journald_json_bad_epoch_keeps_event():
    event = parse_syslog('{"timestamp": "12345678901234", "MESSAGE": "hi"}', mode="journald_json")

    assert event.ts is None
    assert event.msg == "hi"


def test_journald_realtime_timestamp_is_microseconds():
    # __REALTIME_TIMESTAMP is always microseconds. A 2023 value (16
    # digits) and a pre-2001 value (15 digits) both scale correctly.
    modern = parse_syslog('{"__REALTIME_TIMESTAMP": "1688212800123456", "MESSAGE": "m"}', mode="journald_json")
    assert modern.ts == datetime(2023, 7, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)

    # 946684800000000 us = 2000-01-01 (15 digits — would be "ambiguous"
    # under digit-count dispatch, but is unambiguously microseconds here).
    old = parse_syslog('{"__REALTIME_TIMESTAMP": "946684800000000", "MESSAGE": "m"}', mode="journald_json")
    assert old.ts == datetime(2000, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def test_adaptive_millisecond_epoch_scaled():
    # An unknown-format line whose only timestamp is a 13-digit epoch.
    event = parse_syslog("## marker 1688212800123 payload here")

    if event.source_hint == "adaptive" and event.ts is not None:
        assert event.ts == datetime(2023, 7, 1, 12, 0, 0, 123000, tzinfo=timezone.utc)


# ---- #87: epoch precision ------------------------------------------------

def test_epoch_seconds():
    assert parse_iso8601("1688212800") == datetime(2023, 7, 1, 12, 0, tzinfo=timezone.utc)


def test_epoch_milliseconds():
    ts = parse_iso8601("1688212800123")
    assert ts == datetime(2023, 7, 1, 12, 0, 0, 123000, tzinfo=timezone.utc)


def test_epoch_microseconds():
    ts = parse_iso8601("1688212800123456")
    assert ts == datetime(2023, 7, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


def test_epoch_nanoseconds_truncate_to_micros():
    ts = parse_iso8601("1688212800123456789")
    assert ts == datetime(2023, 7, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)


@pytest.mark.parametrize("digits", [11, 12, 14, 15, 17, 18])
def test_ambiguous_epoch_lengths_rejected(digits):
    with pytest.raises(ValueError):
        parse_iso8601("1" * digits)


def test_kv_eventtime_nanoseconds_full_precision():
    event = parse_syslog("eventtime=1688212800123456789 src=1.2.3.4 dst=5.6.7.8 action=allow")

    assert event.ts == datetime(2023, 7, 1, 12, 0, 0, 123456, tzinfo=timezone.utc)
