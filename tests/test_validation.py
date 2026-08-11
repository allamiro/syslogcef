from __future__ import annotations

import pytest

from syslogcef import convert_line, normalize_event, parse_syslog, to_cef
from syslogcef.validation import CEFValidationError, validate_extensions


def test_valid_extensions_produce_no_fatal_findings():
    findings = validate_extensions(
        {"src": "10.0.0.1", "dst": "10.0.0.2", "c6a1": "2001:db8::1", "spt": "443", "msg": "hello", "smac": "00:0d:60:af:1b:61"}
    )
    assert [f for f in findings if f.fatal] == []


def test_type_violations_are_fatal():
    findings = validate_extensions({"src": "not-an-ip", "spt": "99999", "fsize": "big"})
    assert sorted(f.key for f in findings if f.fatal) == ["fsize", "spt", "src"]


def test_unknown_keys_are_advisory_only():
    findings = validate_extensions({"myCustomKey": "anything"})
    assert len(findings) == 1
    assert not findings[0].fatal


def test_length_violation_detected():
    findings = validate_extensions({"outcome": "x" * 100})  # max 63
    assert findings and findings[0].fatal


def test_timestamp_formats():
    ok = validate_extensions({"rt": "Jan 17 2020 08:52:10", "start": "1587231168000"})
    assert [f for f in ok if f.fatal] == []
    bad = validate_extensions({"rt": "yesterday at noon"})
    assert bad and bad[0].fatal


def test_strict_mode_raises_through_pipeline():
    # The ASA mapping maps src= from the message; a bogus IP violates the
    # dictionary in strict mode.
    line = "<166>Jan  1 12:34:56 fw1 asa[1]: %ASA-6-302013: Built inbound src=notanip dst=10.0.0.2"
    with pytest.raises(CEFValidationError):
        convert_line(line, validate=True, strict=True)
    # Non-strict validation still renders the record.
    assert convert_line(line, validate=True).startswith("CEF:0|")


def test_strict_mode_passes_clean_lines():
    line = "<166>Jan  1 12:34:56 fw1 asa[1]: %ASA-6-302013: Built inbound src=10.0.0.1 dst=10.0.0.2"
    cef = convert_line(line, validate=True, strict=True)
    assert "src=10.0.0.1" in cef


def test_cli_strict_exits_nonzero(tmp_path):
    import subprocess
    import sys

    bad = tmp_path / "bad.log"
    bad.write_text("<166>Jan  1 12:34:56 fw1 asa[1]: %ASA-6-302013: x src=notanip\n")
    result = subprocess.run(
        [sys.executable, "-m", "syslogcef", str(bad), "--strict"],
        capture_output=True,
    )
    assert result.returncode == 1
    assert b"strict validation failed" in result.stderr


# --- round-2 review findings --------------------------------------------------

def test_ipv4_only_fields_reject_ipv6():
    findings = validate_extensions({"src": "2001:db8::1", "c6a1": "2001:db8::1"})
    fatal = [f.key for f in findings if f.fatal]
    assert fatal == ["src"]


def test_old_file_keys_validated():
    findings = validate_extensions({"oldFileSize": "not-a-number", "oldFileHash": "abc"})
    fatal = [f.key for f in findings if f.fatal]
    assert fatal == ["oldFileSize"]


def test_timestamp_values_actually_parsed():
    bad = validate_extensions({"rt": "Foo 99 2020 99:99:99"})
    assert bad and bad[0].fatal
    bad2 = validate_extensions({"rt": "123"})  # implausible epoch
    assert bad2 and bad2[0].fatal
    ok = validate_extensions({"rt": "Feb 29 2020 12:00:00"})
    assert [f for f in ok if f.fatal] == []
