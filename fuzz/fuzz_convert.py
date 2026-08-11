#!/usr/bin/env python3
"""Atheris harness for coverage-guided fuzzing of convert_line.

Usage (local, from a repo checkout; needs clang):

    pip install atheris .
    python fuzz/fuzz_convert.py corpus/ -max_len=4096

Any crash or hang found here is by definition a bug: convert_line must
never raise, and must return structurally valid CEF for every input.
Seed the corpus from tests/ sample lines for much better coverage.
"""

import sys

import atheris

with atheris.instrument_imports():
    from syslogcef import convert_line


def _split_unescaped_pipes(record):
    parts, cur, i = [], [], 0
    while i < len(record):
        ch = record[i]
        if ch == "\\" and i + 1 < len(record):
            cur.append(ch)
            cur.append(record[i + 1])
            i += 2
            continue
        if ch == "|":
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    parts.append("".join(cur))
    return parts


def one_input(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    line = fdp.ConsumeUnicodeNoSurrogates(4096)
    cef = convert_line(line)
    parts = _split_unescaped_pipes(cef)
    if len(parts) < 8 or parts[0] != "CEF:0":
        raise AssertionError(f"structurally invalid CEF for input {line[:80]!r}")
    if not parts[6].isdigit():
        raise AssertionError(f"non-numeric severity field for input {line[:80]!r}")
    for field in parts[:7]:
        if "\r" in field or "\n" in field:
            raise AssertionError(f"CR/LF in CEF header for input {line[:80]!r}")


def main() -> None:
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
