from __future__ import annotations

from syslogcef import convert_line, normalize_event, parse_syslog, to_cef
from syslogcef.mappings import CISCO_ASA


def test_full_pipeline_to_cef():
    line = "<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
    parsed = parse_syslog(line)
    normalized = normalize_event(parsed)
    cef = to_cef(normalized, CISCO_ASA)

    assert cef.startswith("CEF:0|Cisco|ASA|")
    assert "src=10.0.0.1" in cef
    assert "dst=10.0.0.2" in cef


def test_convert_line_helper():
    line = "<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2"
    cef = convert_line(line, mapping=CISCO_ASA)
    assert "CEF:0|Cisco|ASA" in cef
