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
