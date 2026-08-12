from __future__ import annotations

import pytest

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


def test_header_pipe_injection_is_escaped():
    line = "<14>Jan  1 12:34:56 host1 app: evil|Fake|Vendor|9|spoofed message"
    cef = convert_line(line, mapping={})
    # The message lands in the CEF "name" header slot; pipes inside it must be
    # escaped so they cannot forge extra header fields.
    assert "evil\\|Fake\\|Vendor" in cef
    assert cef.count("|") - cef.count("\\|") == 7


def test_header_newlines_are_stripped():
    line = "<14>Jan  1 12:34:56 host1 app: first\nsecond"
    cef = convert_line(line, mapping={})
    assert "\n" not in cef


def test_default_linux_mapping_does_not_crash():
    # Regression test: the auto-guessed Linux mapping used to contain an
    # invalid %-format template that raised ValueError for every event.
    line = "<13>Jan  2 10:00:00 web01 sshd[123]: Failed password for root from 10.1.1.1 port 22"
    cef = convert_line(line)
    assert cef.startswith("CEF:0|Linux|Syslog|")
    assert "linux.syslog" in cef


def test_invalid_mapping_template_is_rejected_before_processing():
    # Originally (#2) a malformed template crashed the pipeline once per
    # event, so _format was made to degrade gracefully. Structural
    # validation now rejects the mapping at load time instead, which serves
    # the same intent — no mid-stream failure — while telling the operator
    # what is wrong rather than silently emitting a defaulted header.
    line = "<13>Jan  2 10:00:00 web01 sshd[123]: Failed password for root"
    mapping = {"eventClassId": "broken.%{msgid}"}
    with pytest.raises(ValueError, match="invalid format specifier"):
        convert_line(line, mapping=mapping)


def test_unsatisfiable_conversion_still_degrades_gracefully():
    # The runtime safety net in _format remains for data-dependent failures
    # that eager validation cannot detect: the syntax is valid, but a string
    # kv value cannot satisfy %d. The event must still render.
    line = "<13>Jan  2 10:00:00 web01 sshd[123]: dstport=notaport"
    cef = convert_line(line, mapping={"extensions": {"dpt": "%(dpt)d"}})
    assert cef.startswith("CEF:0|")
    assert "dpt=" not in cef
