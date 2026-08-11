"""The package must work when imported from inside a zip archive.

The release workflow ships a standalone zipapp (.pyz). Any package data
read via a filesystem path (Path(__file__)...) works from a normal
install but raises NotADirectoryError inside the archive — exactly the
failure that broke the v0.2.0 zipapp build when dictionary.json was
first added. This test zips the package and converts a line through it,
so every package-data access path is exercised under zipimport.
"""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "syslogcef"


def test_convert_line_works_under_zipimport(tmp_path: Path):
    archive = tmp_path / "app.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for path in sorted(PACKAGE_DIR.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, Path("syslogcef") / path.relative_to(PACKAGE_DIR))

    # A fresh interpreter with ONLY the zip on sys.path: dictionary,
    # mappings, and every other package-data file must load from inside
    # the archive. Exercise kv aliasing + validation so both data files
    # are actually read.
    code = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from syslogcef import convert_line; "
        "cef = convert_line('srcip=10.0.0.1 dstip=10.0.0.2 action=x', validate=True); "
        "assert cef.startswith('CEF:0|'), cef; "
        "print('ZIPAPP_OK')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code, str(archive)],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, f"stderr: {result.stderr[-800:]}"
    assert "ZIPAPP_OK" in result.stdout
