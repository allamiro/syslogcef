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
