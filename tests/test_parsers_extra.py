from __future__ import annotations

from datetime import datetime, timezone

import pytest

from syslogcef.parsers import ParserError, autodetect_and_parse


NOW = datetime(2023, 7, 2, tzinfo=timezone.utc)


def test_parse_rsyslog_json():
    line = '{"timestamp": "2023-07-01T12:00:00Z", "hostname": "web01", "programname": "nginx", "pid": 42, "msg": "GET /index.html", "pri": "14"}'
    result = autodetect_and_parse(line)
    assert result.source_hint in {"rsyslog", "journald"}
    assert result.host == "web01"
    assert result.msg == "GET /index.html"


def test_parse_rsyslog_file_format():
    line = "2023-07-01T12:00:00.123+00:00 web01 sshd[999]: Accepted publickey for root"
    result = autodetect_and_parse(line)
    assert result.host == "web01"
    assert result.app == "sshd"
    assert result.pid == "999"
    assert result.msg.startswith("Accepted publickey")


def test_parse_journald_iso():
    line = "2023-07-01 12:00:00 host1 systemd: Started Session 1 of user root."
    result = autodetect_and_parse(line)
    assert result.host == "host1"
    assert result.msg.startswith("Started Session")


def test_parse_journald_short():
    line = "Jul  1 12:00:00 host1 mytag with spaces: unit entered running state"
    result = autodetect_and_parse(line, now=NOW)
    assert result.host == "host1"
    assert result.msg == "unit entered running state"


def test_rfc5424_dash_fields_become_none():
    line = "<34>1 2023-07-01T12:00:00Z - - - - - message only"
    result = autodetect_and_parse(line)
    assert result.host is None
    assert result.app is None
    assert result.pid is None
    assert result.msgid is None


def test_unknown_format_falls_back_to_raw():
    line = "completely unstructured garbage without any format"
    result = autodetect_and_parse(line)
    assert result.source_hint == "unknown"
    assert result.msg == line
    assert result.host is not None


def test_explicit_mode_unknown_raises():
    with pytest.raises(ParserError):
        autodetect_and_parse("anything", mode="no_such_mode")


def test_explicit_mode_parse_failure_raises():
    with pytest.raises(ParserError):
        autodetect_and_parse("not valid rfc5424", mode="rfc5424")


def test_rfc3164_year_rollover_previous_year():
    # A December timestamp seen in January belongs to the previous year.
    line = "<14>Dec 31 23:59:59 host1 app: year rollover"
    result = autodetect_and_parse(line, now=datetime(2024, 1, 2, tzinfo=timezone.utc))
    assert result.ts.year == 2023
