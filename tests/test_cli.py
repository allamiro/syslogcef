from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_cli_stdout(tmp_path: Path):
    sample = "<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection src=10.0.0.1 dst=10.0.0.2\n"
    script = Path(sys.executable)
    result = subprocess.run(
        [script, "-m", "syslogcef", "--mapping", str(Path(__file__).resolve().parent.parent / "syslogcef" / "mappings" / "cisco_asa.json")],
        input=sample.encode(),
        capture_output=True,
        check=True,
    )
    assert b"CEF:0" in result.stdout


def test_follow_files_reads_all_files(tmp_path: Path):
    from syslogcef.cli import follow_files

    first = tmp_path / "first.log"
    second = tmp_path / "second.log"
    first.write_text("f1-line1\nf1-line2\n", encoding="utf-8")
    second.write_text("f2-line1\nf2-line2\n", encoding="utf-8")

    lines = list(follow_files([first, second], poll_interval=0, max_idle_polls=1))

    assert set(lines) == {"f1-line1", "f1-line2", "f2-line1", "f2-line2"}


def test_follow_files_picks_up_appended_lines(tmp_path: Path):
    from syslogcef.cli import follow_files

    log = tmp_path / "grow.log"
    log.write_text("old\n", encoding="utf-8")

    gen = follow_files([log], poll_interval=0, max_idle_polls=5)
    assert next(gen) == "old"

    with log.open("a", encoding="utf-8") as fp:
        fp.write("new\n")

    assert "new" in list(gen)


def test_write_lines_plain_truncates(tmp_path: Path):
    from syslogcef.cli import write_lines

    out = tmp_path / "out.cef"
    out.write_text("old\n", encoding="utf-8")

    write_lines(["a", "b"], out, append=False, stream_flush=False)

    assert out.read_text(encoding="utf-8") == "a\nb\n"


def test_write_lines_plain_appends(tmp_path: Path):
    from syslogcef.cli import write_lines

    out = tmp_path / "out.cef"
    out.write_text("old\n", encoding="utf-8")

    write_lines(["a"], out, append=True, stream_flush=False)

    assert out.read_text(encoding="utf-8") == "old\na\n"


def test_write_lines_strftime_rotates_on_hour_change(tmp_path: Path, monkeypatch):
    from datetime import datetime

    import syslogcef.cli as cli

    stamps = [
        datetime(2026, 8, 11, 10, 0),
        datetime(2026, 8, 11, 10, 30),
        datetime(2026, 8, 11, 11, 0),
    ]

    class FakeDateTime:
        calls = 0

        @classmethod
        def now(cls):
            stamp = stamps[min(cls.calls, len(stamps) - 1)]
            cls.calls += 1
            return stamp

    monkeypatch.setattr(cli, "datetime", FakeDateTime)

    template = tmp_path / "%Y-%m-%d" / "events-%H.cef"
    cli.write_lines(["one", "two", "three"], template, append=False, stream_flush=False)

    day_dir = tmp_path / "2026-08-11"
    assert (day_dir / "events-10.cef").read_text(encoding="utf-8") == "one\ntwo\n"
    assert (day_dir / "events-11.cef").read_text(encoding="utf-8") == "three\n"


def test_write_lines_strftime_appends_across_runs(tmp_path: Path):
    from syslogcef.cli import write_lines

    template = tmp_path / "events-%Y.cef"
    write_lines(["first"], template, append=False, stream_flush=False)
    write_lines(["second"], template, append=False, stream_flush=False)

    files = list(tmp_path.glob("events-*.cef"))
    assert len(files) == 1
    assert files[0].read_text(encoding="utf-8") == "first\nsecond\n"


def test_write_lines_literal_percent_keeps_truncation(tmp_path: Path):
    from syslogcef.cli import write_lines

    template = tmp_path / "success-100%%.cef"
    write_lines(["old"], template, append=False, stream_flush=False)
    write_lines(["new"], template, append=False, stream_flush=False)

    rendered = tmp_path / "success-100%.cef"
    assert rendered.read_text(encoding="utf-8") == "new\n"


def test_write_lines_literal_percent_creates_parent_dirs(tmp_path: Path):
    from syslogcef.cli import write_lines

    template = tmp_path / "new" / "archive" / "success-100%%.cef"
    write_lines(["a"], template, append=False, stream_flush=False)

    assert (tmp_path / "new" / "archive" / "success-100%.cef").read_text(encoding="utf-8") == "a\n"


def test_write_lines_timezone_code_renders_offset(tmp_path: Path):
    from syslogcef.cli import write_lines

    template = tmp_path / "events-%z.cef"
    write_lines(["a"], template, append=False, stream_flush=False)

    files = list(tmp_path.glob("events-*.cef"))
    assert len(files) == 1
    # A naive datetime would render %z as "" and produce "events-.cef".
    assert files[0].name != "events-.cef"


def test_main_rejects_unsupported_strftime_code(tmp_path: Path):
    import pytest

    from syslogcef.cli import main

    with pytest.raises(SystemExit):
        main(["-o", str(tmp_path / "events-%Q.cef")])

    with pytest.raises(SystemExit):
        main(["-o", str(tmp_path / "events%")])


def test_main_empty_output_means_stdout(tmp_path: Path, capsys):
    from syslogcef.cli import main

    log = tmp_path / "in.log"
    log.write_text("<166>Jan  1 12:34:56 router1 hello\n", encoding="utf-8")

    assert main([str(log), "-o", ""]) == 0

    assert "CEF:0" in capsys.readouterr().out


def test_cli_output_template_end_to_end(tmp_path: Path):
    from syslogcef.cli import main

    log = tmp_path / "in.log"
    log.write_text("<166>Jan  1 12:34:56 router1 %ASA-6-302013: Built inbound TCP connection\n", encoding="utf-8")
    template = tmp_path / "cef" / "%Y-%m-%d" / "events.cef"

    assert main([str(log), "-o", str(template)]) == 0

    files = list((tmp_path / "cef").rglob("events.cef"))
    assert len(files) == 1
    assert "CEF:0" in files[0].read_text(encoding="utf-8")


def test_cli_reports_the_command_name_not_the_module_file():
    # "python -m syslogcef --help" used to report "usage: __main__.py".
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-m", "syslogcef", "--help"],
        capture_output=True, text=True, check=True,
    ).stdout
    assert out.startswith("usage: syslogcef ")
    assert "__main__.py" not in out


def test_man_page_source_field_names_the_project():
    # The third .TH field is the source package, which is syslog2cef; the
    # page name stays SYSLOGCEF because that is the command.
    from pathlib import Path

    first = Path(__file__).resolve().parent.parent.joinpath(
        "packaging/rpm/syslogcef.1"
    ).read_text().splitlines()[0]
    assert first.startswith(".TH SYSLOGCEF 1 ")
    assert '"syslog2cef ' in first
