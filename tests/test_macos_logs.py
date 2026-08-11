"""macOS log formats: install.log compact offsets, tag/pid splitting,
continuation-line inheritance, and event time in the CEF output."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from syslogcef.adaptive import adaptive_parse, clear_cache
from syslogcef.api import StreamConverter
from syslogcef.parsers import autodetect_and_parse
from syslogcef.utils import parse_iso8601


class TestCompactUtcOffset:
    """macOS install.log stamps hour-only offsets: 2026-07-20 03:23:05+02."""

    def test_parse_iso8601_hour_only_offset(self):
        ts = parse_iso8601("2026-07-20 03:23:05+02")
        assert ts.utcoffset() == timedelta(hours=2)
        assert ts.replace(tzinfo=None) == datetime(2026, 7, 20, 3, 23, 5)

    def test_parse_iso8601_colonless_offset(self):
        ts = parse_iso8601("2026-07-20T03:23:05+0230")
        assert ts.utcoffset() == timedelta(hours=2, minutes=30)

    def test_parse_iso8601_negative_compact_offset(self):
        ts = parse_iso8601("2026-07-20 03:23:05-05")
        assert ts.utcoffset() == timedelta(hours=-5)

    def test_parse_iso8601_colon_offset_unchanged(self):
        ts = parse_iso8601("2026-07-20T03:23:05+02:00")
        assert ts.utcoffset() == timedelta(hours=2)

    def test_year_month_not_mistaken_for_offset(self):
        with pytest.raises(ValueError):
            parse_iso8601("2026-07")

    def test_install_log_line_fully_parsed(self):
        line = "2026-07-20 03:23:05+02 Tamirs-MBP system_installd[27234]: installd: Starting"
        event = autodetect_and_parse(line)
        assert event.host == "Tamirs-MBP"
        assert event.app == "system_installd"
        assert event.pid == "27234"
        assert event.ts is not None
        assert event.ts.utcoffset() == timedelta(hours=2)
        assert event.msg == "installd: Starting"


class TestTagPidSplit:
    def test_journald_short_splits_pid_from_tag(self):
        line = "May 28 16:04:52 MacBookPro opendirectoryd[69]: [session] node assigned UUID"
        event = autodetect_and_parse(line)
        assert event.host == "MacBookPro"
        assert event.app == "opendirectoryd"
        assert event.pid == "69"

    def test_journald_short_tag_without_pid(self):
        line = "May 28 16:04:52 MacBookPro kernel: something happened"
        event = autodetect_and_parse(line)
        assert event.app == "kernel"
        assert event.pid is None


class TestAdaptiveTagExtraction:
    """The adaptive learner recognizes timestamp, host, and app[pid]: tag."""

    def setup_method(self):
        clear_cache()

    def test_fresh_analysis_extracts_tag(self):
        event = adaptive_parse("2026/07/20 03:23:05 myhost myapp[123]: hello world")
        assert event.host == "myhost"
        assert event.app == "myapp"
        assert event.pid == "123"
        assert event.msg == "hello world"

    def test_cached_pattern_extracts_tag(self):
        adaptive_parse("2026/07/20 03:23:05 myhost myapp[123]: hello world")
        event = adaptive_parse("2026/07/20 03:23:06 myhost myapp[123]: second event")
        assert event.app == "myapp"
        assert event.pid == "123"
        assert event.msg == "second event"

    def test_timezone_remnant_not_taken_as_host(self):
        # If a stray non-hostname token follows the timestamp it must stay
        # in the message rather than become the host.
        event = adaptive_parse("2026/07/20 03:23:05 +bogus stays in message")
        assert event.host is None
        assert "+bogus" in event.msg


class TestContinuationLines:
    """Whitespace-indented lines inherit context from the previous event
    instead of getting the local (container) hostname and no timestamp."""

    def test_continuation_inherits_host_app_time(self):
        conv = StreamConverter()
        first = conv.convert(
            "May 28 16:04:52 MacBookPro opendirectoryd[69]: ODNodeCopyDetails request, Keys: ("
        )
        cont = conv.convert('\t    "dsAttrTypeStandard:OperatingSystemVersion"')
        closing = conv.convert("\t)")
        assert "dhost=MacBookPro" in first
        for cef in (cont, closing):
            assert "dhost=MacBookPro" in cef
            assert "sproc=opendirectoryd" in cef
            assert "dvcpid=69" in cef
        # Continuation lines carry the parent's event time.
        rt_first = first.split("rt=")[1].split()[0]
        rt_cont = cont.split("rt=")[1].split()[0]
        assert rt_first == rt_cont

    def test_continuation_without_context_keeps_fallback(self):
        conv = StreamConverter()
        cef = conv.convert("\tstray indented line with no parent")
        assert cef.startswith("CEF:0|")

    def test_non_indented_unknown_line_does_not_become_context(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent event")
        conv.convert("completely freeform line no structure !!")
        cont = conv.convert("\tindented continuation")
        # Context still comes from the last *parsed* event, not the
        # freeform fallback line.
        assert "dhost=MacBookPro" in cont

    def test_indented_message_preserved(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent event")
        cef = conv.convert("\t    AllowBootstrapTokenOnFullSecurity = true;")
        assert "AllowBootstrapTokenOnFullSecurity" in cef


class TestEventTimeInOutput:
    def test_rt_matches_parsed_timestamp(self):
        conv = StreamConverter()
        cef = conv.convert("2026-07-20T03:23:05+02:00 host1 app[1]: hello")
        expected_ms = int(
            datetime(2026, 7, 20, 3, 23, 5, tzinfo=timezone(timedelta(hours=2))).timestamp() * 1000
        )
        assert f"rt={expected_ms}" in cef


class TestPerSourceContext:
    """Continuation context must not leak across input sources (files)."""

    def test_continuation_does_not_inherit_across_sources(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent", source="a.log")
        cef = conv.convert("\tindented start of another file", source="b.log")
        assert "dhost=MacBookPro" not in cef

    def test_each_source_keeps_its_own_context(self):
        conv = StreamConverter()
        conv.convert("May 28 16:04:52 host-a appa[1]: parent A", source="a.log")
        conv.convert("May 28 16:04:53 host-b appb[2]: parent B", source="b.log")
        # Interleaved continuations inherit from their own file.
        cef_a = conv.convert("\tcontinuation for A", source="a.log")
        cef_b = conv.convert("\tcontinuation for B", source="b.log")
        assert "dhost=host-a" in cef_a and "sproc=appa" in cef_a
        assert "dhost=host-b" in cef_b and "sproc=appb" in cef_b

    def test_process_lines_tags_sources(self):
        from syslogcef.cli import process_lines

        items = [
            ("a.log", "May 28 16:04:52 host-a appa[1]: parent A"),
            ("b.log", "\tindented first line of file B"),
        ]
        out = list(
            process_lines(items, mode=None, mapping=None, use_multiprocessing=False, pool_size=None)
        )
        assert "dhost=host-a" in out[0]
        assert "dhost=host-a" not in out[1]


class TestForcedModeContinuation:
    """A forced --mode must inherit continuation lines, not abort on them."""

    def test_forced_mode_continuation_inherits(self):
        conv = StreamConverter(mode="journald_short")
        parent = conv.convert("May 28 16:04:52 MacBookPro opendirectoryd[69]: parent event")
        cont = conv.convert("\t    wrapped payload line")
        assert "dhost=MacBookPro" in parent
        assert "dhost=MacBookPro" in cont
        assert "sproc=opendirectoryd" in cont

    def test_forced_mode_still_rejects_non_continuations(self):
        from syslogcef.parsers import ParserError

        conv = StreamConverter(mode="journald_short")
        with pytest.raises(ParserError):
            conv.convert("not a journald line at all")

    def test_forced_mode_indented_without_context_still_raises(self):
        from syslogcef.parsers import ParserError

        conv = StreamConverter(mode="journald_short")
        with pytest.raises(ParserError):
            conv.convert("\tindented but no preceding event")


class TestDvcpidNumericOnly:
    """dvcpid is an integer CEF field; non-numeric PROCIDs must not land there."""

    def test_numeric_pid_emits_dvcpid(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp 4711 ID47 - message", mapping=LINUX
        )
        assert "dvcpid=4711" in cef

    def test_nonnumeric_procid_omits_dvcpid(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp worker-A ID47 - message", mapping=LINUX
        )
        assert "dvcpid=" not in cef

    def test_nonnumeric_procid_passes_strict_validation(self):
        from syslogcef import convert_line
        from syslogcef.mappings import LINUX

        cef = convert_line(
            "<34>1 2026-07-20T03:23:05Z host1 myapp worker-A ID47 - message",
            mapping=LINUX,
            strict=True,
        )
        assert cef.startswith("CEF:0|")
