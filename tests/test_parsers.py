from __future__ import annotations

from datetime import datetime, timezone

from syslogcef.parsers import autodetect_and_parse


def test_parse_rfc3164():
    line = "<166>Jan  1 12:34:56 router1 sshd[123]: Accepted password for user"
    result = autodetect_and_parse(line, now=datetime(2023, 1, 2, tzinfo=timezone.utc))
    assert result.pri == 166
    assert result.severity == 6
    assert result.app == "sshd"
    assert result.pid == "123"
    assert result.source_hint == "rfc3164"


def test_parse_rfc5424():
    line = "<34>1 2023-07-01T12:00:00Z host app 1234 ID47 [exampleSDID@32473 iut=3 eventSource=Application] An application event"
    result = autodetect_and_parse(line)
    assert result.pri == 34
    assert result.severity == 2
    assert result.sd["exampleSDID@32473.iut"] == "3"
    assert result.msg.startswith("An application event")
    assert result.source_hint == "rfc5424"


def test_parse_rfc3164_untagged_cisco_asa():
    line = "<166>Jan  1 12:34:56 fw1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
    result = autodetect_and_parse(line, now=datetime(2023, 1, 2, tzinfo=timezone.utc))
    assert result.source_hint == "rfc3164"
    assert result.pri == 166
    assert result.severity == 6
    assert result.host == "fw1"
    assert result.app is None
    assert result.msg.startswith("%ASA-6-302013:")


def test_untagged_asa_line_produces_event_code_and_severity():
    from syslogcef import convert_line
    from syslogcef.mappings import CISCO_ASA

    line = "<166>Jan  1 12:34:56 fw1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
    cef = convert_line(line, mapping=CISCO_ASA)
    fields = cef.split("|")
    assert fields[4] == "asa.ASA-6-302013"
    assert fields[6] == "2"


def test_parse_journald_json():
    line = '{"PRIORITY": "4", "_HOSTNAME": "host", "SYSLOG_IDENTIFIER": "kernel", "_PID": "1", "MESSAGE": "Boot complete"}'
    result = autodetect_and_parse(line)
    assert result.severity == 4
    assert result.app == "kernel"
    assert result.msg == "Boot complete"
    assert result.source_hint == "journald"
