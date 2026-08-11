"""Grammar-based property tests: generated syslog with planted values.

Where test_fuzz_properties.py asserts the pipeline survives arbitrary
bytes, these tests *generate* structurally valid syslog in the dialects
seen in the wild — RFC3164, RFC5424, rsyslog JSON, kv streams, and
adaptive-only shapes — across payload lengths from empty to multi-KB,
with known hosts, apps, IPs, and timestamps planted in each line. They
then assert the pipeline actually detects the format and maps the
planted fields: host to host, IP to src/dst, time to the parsed
timestamp — the adaptivity guarantees, not just crash-freedom.

Requires hypothesis (skipped where absent, e.g. RPM %check).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given, settings, strategies as st  # noqa: E402

from syslogcef import convert_line, normalize_event, parse_syslog  # noqa: E402

# Profiles are registered centrally in conftest.py; here we only load.
settings.load_profile(os.environ.get("SYSLOGCEF_HYPOTHESIS_PROFILE", "ci"))

hostnames = st.from_regex(r"[a-z][a-z0-9\-]{0,14}[a-z0-9]", fullmatch=True)
appnames = st.from_regex(r"[A-Za-z][A-Za-z0-9_]{0,11}", fullmatch=True)
ips = st.ip_addresses(v=4).map(str)
pids = st.integers(min_value=1, max_value=99999)
timestamps = st.datetimes(
    min_value=datetime(2021, 1, 10),
    max_value=datetime(2029, 12, 28),
    timezones=st.just(timezone.utc),
).map(lambda d: d.replace(microsecond=0))

# Payloads from empty to ~3KB. '=' is excluded because an early '=' makes
# the kv detector claim the line (by design); pipes/backslashes stay in —
# the escaper must handle them.
payloads = st.text(
    alphabet=st.characters(
        blacklist_characters="\r\n=\"[]{}", blacklist_categories=("Cs",)
    ),
    max_size=3000,
).map(lambda s: " ".join(s.split()))


@given(host=hostnames, app=appnames, pid=pids, ts=timestamps, payload=payloads)
def test_rfc3164_fields_detected(host, app, pid, ts, payload):
    line = f"<134>{ts.strftime('%b %d %H:%M:%S')} {host} {app}[{pid}]: {payload}"

    # Anchor year inference to the generated timestamp so a generated
    # Feb 29 resolves against its own (leap) year, not the wall clock.
    event = parse_syslog(line, now=ts)

    assert event.host == host
    assert event.app == app
    assert event.pid == str(pid)
    assert event.ts is not None
    assert (event.ts.month, event.ts.day, event.ts.hour, event.ts.minute, event.ts.second) == (
        ts.month, ts.day, ts.hour, ts.minute, ts.second,
    )


@given(host=hostnames, app=appnames, pid=pids, ts=timestamps, payload=payloads)
def test_rfc5424_fields_detected(host, app, pid, ts, payload):
    line = f"<134>1 {ts.strftime('%Y-%m-%dT%H:%M:%S')}Z {host} {app} {pid} MSGID - {payload}"

    event = parse_syslog(line)

    assert event.host == host
    assert event.app == app
    assert event.pid == str(pid)
    assert event.ts == ts


@given(host=hostnames, app=appnames, ts=timestamps, payload=payloads)
def test_rsyslog_json_fields_detected(host, app, ts, payload):
    line = json.dumps(
        {
            "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S+00:00"),
            "host": host,
            "severity": "info",
            "facility": "daemon",
            "syslogtag": f"{app}:",
            "message": payload,
        }
    )

    event = parse_syslog(line)

    assert event.host == host
    assert event.msg == payload
    assert event.app == app  # from syslogtag, colon stripped
    assert event.ts == ts  # from @timestamp


@given(src=ips, dst=ips, ts=timestamps, user=appnames, payload=payloads)
def test_kv_stream_ips_and_time_mapped(src, dst, ts, user, payload):
    line = (
        f"ts={ts.strftime('%Y-%m-%dT%H:%M:%S')}Z level=info "
        f'src={src} dst={dst} user={user} msg="{payload[:200]}"'
    )

    event = parse_syslog(line)
    normalized = normalize_event(event)

    # Planted IPs must surface as the kv fields mappings consume
    # (ip -> src/dst), and the planted time must be the parsed timestamp.
    assert normalized.kv.get("src") == src
    assert normalized.kv.get("dst") == dst
    assert normalized.kv.get("user") == user
    assert event.ts == ts


@given(src=ips, dst=ips, ts=timestamps)
def test_asa_ips_reach_cef_extensions(src, dst, ts):
    line = (
        f"<166>{ts.strftime('%b %d %H:%M:%S')} fw01 "
        f"%ASA-6-302013: Built inbound TCP connection src={src} dst={dst}"
    )

    cef = convert_line(line)

    # Device lines must map planted IPs into the CEF extension fields.
    assert f"src={src}" in cef
    assert f"dst={dst}" in cef
    assert "|Cisco|ASA|" in cef


def test_journald_lowercase_only_record_parses_in_explicit_mode():
    # The journald-key gate must include every lowercase alias the parser
    # body reads, or --mode journald_json rejects records it can parse.
    event = parse_syslog('{"priority": "4", "pid": "1", "msg": "hello"}', mode="journald_json")

    assert event.msg == "hello"
    assert event.pid == "1"


def test_kv_invalid_iso_falls_back_to_eventtime():
    line = "eventtime=1770000000 ts=not-a-date src=1.2.3.4 dst=5.6.7.8 action=allow"

    event = parse_syslog(line)

    assert event.source_hint == "kv"
    assert event.ts is not None  # an invalid ts= must not mask eventtime=
    assert event.ts_orig == "1770000000"  # records the candidate that parsed


def test_kv_out_of_range_epoch_keeps_event_in_explicit_mode():
    line = "ts=99999999999999999999 src=1.2.3.4 dst=5.6.7.8 action=allow"

    event = parse_syslog(line, mode="kv")

    assert event.ts is None  # OverflowError contained, event preserved


def test_rsyslog_invalid_timestamp_alias_falls_through():
    line = '{"timestamp": "bad", "@timestamp": "2026-08-11T07:00:00Z", "message": "m", "host": "h1"}'

    event = parse_syslog(line)

    assert event.source_hint == "rsyslog"
    assert event.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)


def test_kv_invalid_ts_alias_falls_through_to_timestamp():
    line = "ts=bad timestamp=2026-08-11T07:00:00Z src=1.2.3.4 dst=5.6.7.8 action=allow"

    event = parse_syslog(line)

    assert event.ts == datetime(2026, 8, 11, 7, 0, 0, tzinfo=timezone.utc)
    assert event.ts_orig == "2026-08-11T07:00:00Z"


def test_yearless_feb29_rfc3164_survives_non_leap_wall_clock():
    # A real device can emit "Feb 29" while the converting host's clock
    # is in a non-leap year; the parser must not crash.
    ref = datetime(2026, 3, 1, tzinfo=timezone.utc)  # 2026 is not a leap year

    event = parse_syslog("<134>Feb 29 12:00:00 fw01 app[1]: leap traffic", now=ref)

    assert event.source_hint == "rfc3164"
    assert event.ts is not None
    assert (event.ts.month, event.ts.day) == (2, 29)


def test_non_string_json_message_scalar_survives():
    # JSON allows any scalar for message-ish keys; a non-string must be
    # coerced, not crash sanitization downstream.
    cef = convert_line('{"timestamp": "2026-08-11T07:00:00Z", "message": 123, "host": "h1"}')

    assert cef.startswith("CEF:0|")
    assert "msg=123" in cef


def test_huge_digit_severity_cannot_crash_resolution():
    # 5000 digits pass isascii/isdigit but int() hits Python 3.11+'s
    # conversion limit; the length guard must trigger the fallback.
    cef = convert_line("severity=" + "9" * 5000 + " src=1.2.3.4 dst=2.2.2.2 action=x")

    severity = cef.split("|")[6]
    assert severity.isdigit() and 0 <= int(severity) <= 10


def test_unicode_digit_severity_cannot_crash_resolution():
    # str.isdigit() is True for "²" but int("²") raises; the severity
    # resolver must fall back, not propagate.
    cef = convert_line("severity=² src=1.2.3.4 dst=2.2.2.2 action=x")

    severity = cef.split("|")[6]
    assert severity.isascii() and severity.isdigit() and 0 <= int(severity) <= 10


def test_feb29_resolves_to_nearest_leap_occurrence():
    from syslogcef.parsers import _infer_timestamp

    # 2026-01-01: 2024-02-29 (~22 months back) is nearer than 2028-02-29
    # (~26 months ahead); a direction-biased search would pick 2028.
    ref = datetime(2026, 1, 1, tzinfo=timezone.utc)

    ts = _infer_timestamp(2, 29, "12:00:00", now=ref)

    assert ts.year == 2024


def test_kv_out_of_range_tz_offset_keeps_event():
    # tz=+24:00 is not a valid UTC offset; it must be ignored, not raise
    # (reachable in explicit kv mode where no detector guard applies).
    event = parse_syslog(
        "ts=2026-08-11T07:00:00 tz=+24:00 src=1.2.3.4 dst=2.2.2.2 action=x", mode="kv"
    )

    assert event.ts is not None  # timestamp kept, bogus offset dropped


def test_non_numeric_pri_kv_pair_cannot_crash_severity_resolution():
    # Found by ClusterFuzzLite (fuzz_structured): a kv line supplying
    # pri=<garbage> reached int() in _resolve_severity and escaped
    # convert_line, violating the never-raise contract.
    cef = convert_line("pri=zzz src=1.2.3.4 dst=2.2.2.2 action=x")

    severity = cef.split("|")[6]
    assert severity.isdigit() and 0 <= int(severity) <= 10


def test_rsyslog_lowercase_aliases_with_rsyslog_markers_route_to_rsyslog():
    line = (
        '{"timestamp": "2026-08-11T07:00:00Z", "hostname": "web7",'
        ' "programname": "nginx", "message": "GET / 200"}'
    )

    event = parse_syslog(line)

    assert event.source_hint == "rsyslog"
    assert event.host == "web7"
    assert event.app == "nginx"
    assert event.msg == "GET / 200"


# Lowercase words only: no digits or colons that could read as a second
# timestamp, so the planted one is unambiguous and the adaptive
# assertions below can be unconditional.
adaptive_payloads = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz ", max_size=200
).map(lambda s: " ".join(s.split()))


@given(
    punct=st.sampled_from(["#", "@", "~", "^", "!", ";"]),
    reps=st.integers(min_value=1, max_value=4),
    host=hostnames,
    ts=timestamps,
    payload=adaptive_payloads,
)
def test_adaptive_engine_finds_time_in_unknown_shapes(punct, reps, host, ts, payload):
    # A prefix no built-in parser accepts: only the adaptive engine can
    # take this, and it MUST locate the unambiguous planted timestamp —
    # falling back to raw would be exactly the regression this guards.
    line = f"{punct * reps} {ts.strftime('%b %d %H:%M:%S')} {host} {payload}"

    event = parse_syslog(line, now=ts)

    assert event.source_hint == "adaptive"
    assert event.ts is not None
    assert (event.ts.month, event.ts.day, event.ts.hour, event.ts.minute, event.ts.second) == (
        ts.month, ts.day, ts.hour, ts.minute, ts.second,
    )
