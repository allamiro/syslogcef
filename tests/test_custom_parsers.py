from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from syslogcef import PatternFileError, convert_line, load_patterns, parse_syslog, register_parser
from syslogcef import custom


@pytest.fixture(autouse=True)
def _clean_registry():
    custom.clear_registry()
    yield
    custom.clear_registry()


def write_patterns(tmp_path: Path, *entries) -> Path:
    path = tmp_path / "patterns.json"
    path.write_text(json.dumps({"patterns": list(entries)}), encoding="utf-8")
    return path


ACME = {
    "name": "acme_fw",
    "regex": r"^ACME (?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<app>\w+)\[(?P<pid>\d+)\]: (?P<msg>.*)$",
    "timestamp_format": "%Y-%m-%d %H:%M:%S",
}


def test_pattern_file_parses_unknown_format(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    event = parse_syslog("ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp 10.0.0.1 -> 10.0.0.2")

    assert event.source_hint == "custom:acme_fw"
    assert event.host == "fw01"
    assert event.app == "nat"
    assert event.pid == "42"
    assert event.msg.startswith("allowed tcp")
    assert event.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)


def test_pattern_used_as_explicit_mode(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    cef = convert_line("ACME 2026-08-11 07:00:00 fw01 nat[42]: hello", mode="acme_fw")

    assert cef.startswith("CEF:0|")


def test_priority_before_beats_builtin_parsers(tmp_path: Path):
    # This line parses fine as RFC3164; priority=before must win anyway.
    entry = {
        "name": "grabby",
        "regex": r"^<\d+>(?P<msg>.*)$",
        "priority": "before",
    }
    load_patterns(write_patterns(tmp_path, entry))

    event = parse_syslog("<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection")

    assert event.source_hint == "custom:grabby"


def test_priority_after_runs_after_builtins(tmp_path: Path):
    entry = {
        "name": "fallback",
        "regex": r"^(?P<msg>.*)$",
    }
    load_patterns(write_patterns(tmp_path, entry))

    rfc3164 = parse_syslog("<166>Jan  1 12:34:56 router1 app: hello")
    assert rfc3164.source_hint != "custom:fallback"

    weird = parse_syslog("no known parser matches this ~~ shape ~~ at all")
    assert weird.source_hint == "custom:fallback"


def test_iso8601_and_epoch_timestamp_formats(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "iso", "regex": r"^I (?P<ts>\S+) (?P<msg>.*)$", "timestamp_format": "iso8601"},
            {"name": "epoch", "regex": r"^E (?P<ts>[\d.]+) (?P<msg>.*)$", "timestamp_format": "epoch"},
        )
    )

    iso = parse_syslog("I 2026-08-11T07:00:00Z hello", mode="iso")
    assert iso.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)

    epoch = parse_syslog("E 1770000000 hello", mode="epoch")
    assert epoch.ts == datetime.fromtimestamp(1770000000, tz=timezone.utc)


def test_yearless_timestamp_gets_inferred_year(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "noyear", "regex": r"^N (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S"},
        )
    )

    event = parse_syslog("N Aug 11 07:00:00 hello", mode="noyear")

    assert event.ts is not None and event.ts.year != 1900


def test_bad_timestamp_never_drops_the_event(tmp_path: Path):
    load_patterns(write_patterns(tmp_path, ACME))

    event = parse_syslog("ACME 2026-99-99 99:99:99 fw01 nat[1]: bad ts", mode="acme_fw")

    assert event.ts is None
    assert event.msg == "bad ts"


def test_register_parser_programmatic():
    from syslogcef.parsers import ParsedEvent

    def parse_marker(line):
        if not line.startswith("MARK "):
            return None
        return ParsedEvent(
            pri=None, facility=None, severity=None, ts=None, ts_orig="",
            host="marker", app=None, pid=None, msgid=None,
            msg=line[5:], raw=line, source_hint="custom:marker",
        )

    register_parser("marker", parse_marker)

    event = parse_syslog("MARK hello", mode="marker")
    assert event.host == "marker" and event.msg == "hello"

    with pytest.raises(ValueError):
        register_parser("marker", parse_marker)
    with pytest.raises(ValueError):
        register_parser("rfc3164", parse_marker)


@pytest.mark.parametrize(
    "entry, message_part",
    [
        ({"regex": r"^x$"}, "missing 'name'"),
        ({"name": "x"}, "missing 'regex'"),
        ({"name": "x", "regex": "("}, "invalid regex"),
        ({"name": "x", "regex": r"(?P<bogus>\d+)"}, "unknown capture group"),
        ({"name": "x", "regex": r"(?P<ts>\d+)"}, "requires 'timestamp_format'"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "timestamp_format": "%Y"}, "no 'ts' group"),
        ({"name": "x", "regex": r"(?P<ts>\d+)", "timestamp_format": "bogus"}, "must be a strptime format"),
        ({"name": "x", "regex": r"(?P<msg>.*)", "priority": "middle"}, "'priority' must be"),
        ({"name": "rfc3164", "regex": r"(?P<msg>.*)"}, "shadows a built-in"),
    ],
)
def test_pattern_file_validation_errors(tmp_path: Path, entry, message_part):
    with pytest.raises(PatternFileError, match=message_part):
        load_patterns(write_patterns(tmp_path, entry))


def test_duplicate_names_rejected(tmp_path: Path):
    entry = {"name": "dup", "regex": r"^(?P<msg>.*)$"}
    with pytest.raises(PatternFileError, match="duplicate name"):
        load_patterns(write_patterns(tmp_path, entry, entry))


def test_out_of_range_epoch_keeps_event(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "epoch2", "regex": r"^E (?P<ts>[\d.]+) (?P<msg>.*)$", "timestamp_format": "epoch"},
        )
    )

    event = parse_syslog("E 99999999999999999999 still here", mode="epoch2")

    assert event.ts is None
    assert event.msg == "still here"


def test_leap_day_yearless_timestamp(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "leap", "regex": r"^L (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S"},
        )
    )

    ref = datetime(2024, 3, 1, tzinfo=timezone.utc)
    event = custom.get_registered("leap")("L Feb 29 12:00:00 leap day", now=ref)

    assert event.ts is not None
    assert (event.ts.month, event.ts.day) == (2, 29)
    assert event.ts.year == 2024


def test_yearless_timestamp_preserves_offset_and_microseconds(tmp_path: Path):
    load_patterns(
        write_patterns(
            tmp_path,
            {"name": "tzoff", "regex": r"^T (?P<ts>\w{3} \d{2} \d{2}:\d{2}:\d{2}\.\d+ [+-]\d{4}) (?P<msg>.*)$", "timestamp_format": "%b %d %H:%M:%S.%f %z"},
        )
    )

    event = parse_syslog("T Aug 11 07:00:00.123456 +0530 hello", mode="tzoff")

    assert event.ts is not None
    assert event.ts.microsecond == 123456
    assert event.ts.utcoffset() == timedelta(hours=5, minutes=30)


def test_invalid_strptime_directive_rejected_at_load(tmp_path: Path):
    entry = {"name": "x", "regex": r"(?P<ts>\d+)", "timestamp_format": "%Q"}
    with pytest.raises(PatternFileError, match="unsupported strptime directive"):
        load_patterns(write_patterns(tmp_path, entry))


@pytest.mark.parametrize(
    "entry",
    [
        {"name": "x", "regex": r"(?P<ts>\d+)", "timestamp_format": ["%Y"]},
        {"name": "x", "regex": r"(?P<msg>.*)", "priority": ["before"]},
        {"name": "x", "regex": r"(?P<msg>.*)", "priority": {"value": "before"}},
    ],
)
def test_non_string_fields_rejected_not_typeerror(tmp_path: Path, entry):
    with pytest.raises(PatternFileError):
        load_patterns(write_patterns(tmp_path, entry))


def test_registered_fn_with_local_named_now():
    from syslogcef.parsers import ParsedEvent

    def parse_with_local(line):
        now = "just a local, not a parameter"  # noqa: F841
        if not line.startswith("LOCAL "):
            return None
        return ParsedEvent(
            pri=None, facility=None, severity=None, ts=None, ts_orig="",
            host=None, app=None, pid=None, msgid=None,
            msg=line[6:], raw=line, source_hint="custom:local",
        )

    register_parser("localnow", parse_with_local)

    event = parse_syslog("LOCAL hello", mode="localnow")
    assert event.msg == "hello"


def test_mp_load_patterns_clears_inherited_registry(tmp_path: Path):
    from syslogcef.cli import _mp_load_patterns

    pattern_file = write_patterns(tmp_path, ACME)
    load_patterns(pattern_file)  # parent process load
    # Simulates a fork-start worker inheriting the populated registry:
    # without the internal clear this raises duplicate-name errors.
    _mp_load_patterns([str(pattern_file)])

    event = parse_syslog("ACME 2026-08-11 07:00:00 fw01 nat[42]: ok", mode="acme_fw")
    assert event.source_hint == "custom:acme_fw"


def test_cli_patterns_end_to_end(tmp_path: Path):
    from syslogcef.cli import main

    pattern_file = write_patterns(tmp_path, ACME)
    log = tmp_path / "in.log"
    log.write_text("ACME 2026-08-11 07:00:00 fw01 nat[42]: allowed tcp\n", encoding="utf-8")
    out = tmp_path / "out.cef"

    assert main([str(log), "--patterns", str(pattern_file), "-o", str(out)]) == 0
    assert "CEF:0|" in out.read_text(encoding="utf-8")


def test_cli_rejects_broken_pattern_file(tmp_path: Path):
    from syslogcef.cli import main

    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    with pytest.raises(SystemExit):
        main(["--patterns", str(bad)])


def test_cli_rejects_unknown_mode(tmp_path: Path):
    from syslogcef.cli import main

    with pytest.raises(SystemExit):
        main(["--mode", "nonexistent"])