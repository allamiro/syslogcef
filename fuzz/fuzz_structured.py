#!/usr/bin/env python3
"""Structure-aware Atheris harness: generated syslog in many dialects.

Where fuzz_convert.py throws raw bytes at the pipeline, this harness
*builds* syslog-shaped lines — RFC3164, RFC5424, rsyslog JSON, kv
streams, Cisco sequence lines, and adaptive-only shapes — with
fuzzer-chosen hosts, apps, IPs, timestamps, payload lengths (empty to
multi-kilobyte), and trailing junk. Coverage guidance then explores the
parser/normalizer/mapping space far deeper than free-form text does.

Usage (local, from a repo checkout; needs clang):

    pip install atheris .
    python fuzz/fuzz_structured.py corpus/ -max_len=512

Any crash or structurally invalid CEF is a bug.
"""

import json
import re
import sys

import atheris

with atheris.instrument_imports():
    from syslogcef import convert_line

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
PREFIX_PUNCT = ["#", "@", "~", "^", "!", ";", ":", "*", ".", "-"]


def _token(fdp, max_len=16):
    raw = fdp.ConsumeUnicodeNoSurrogates(max_len)
    cleaned = re.sub(r"[\s|\\=\"\[\]{}]", "", raw)
    return cleaned or "tok"


def _ip(fdp):
    return ".".join(str(fdp.ConsumeIntInRange(0, 255)) for _ in range(4))


def _clock(fdp):
    return (
        MONTHS[fdp.ConsumeIntInRange(0, 11)],
        fdp.ConsumeIntInRange(10, 28),
        fdp.ConsumeIntInRange(0, 23),
        fdp.ConsumeIntInRange(0, 59),
        fdp.ConsumeIntInRange(0, 59),
    )


def _payload(fdp):
    # Anything from empty to multi-kilobyte, with fuzzer-chosen content.
    size = (0, 8, 64, 512, 4096)[fdp.ConsumeIntInRange(0, 4)]
    return fdp.ConsumeUnicodeNoSurrogates(size).replace("\n", " ").replace("\r", " ")


def build_line(fdp) -> str:
    family = fdp.ConsumeIntInRange(0, 5)
    host, app = _token(fdp), _token(fdp)
    pri = fdp.ConsumeIntInRange(0, 191)
    mon, day, hh, mm, ss = _clock(fdp)
    payload = _payload(fdp)

    if family == 0:  # RFC3164
        return f"<{pri}>{mon} {day:02d} {hh:02d}:{mm:02d}:{ss:02d} {host} {app}[{fdp.ConsumeIntInRange(1, 99999)}]: {payload}"
    if family == 1:  # RFC5424
        return (
            f"<{pri}>1 2026-{fdp.ConsumeIntInRange(1, 12):02d}-{day:02d}"
            f"T{hh:02d}:{mm:02d}:{ss:02d}Z {host} {app} {fdp.ConsumeIntInRange(1, 99999)} MSGID - {payload}"
        )
    if family == 2:  # rsyslog JSON
        return json.dumps(
            {
                "@timestamp": f"2026-08-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}+00:00",
                "host": host,
                "severity": "info",
                "facility": "daemon",
                "syslogtag": f"{app}:",
                "message": payload,
            }
        )
    if family == 3:  # kv stream
        return (
            f"ts=2026-08-{day:02d}T{hh:02d}:{mm:02d}:{ss:02d}Z level=info "
            f"src={_ip(fdp)} dst={_ip(fdp)} spt={fdp.ConsumeIntInRange(1, 65535)} "
            f'user={_token(fdp)} msg="{payload[:256]}"'
        )
    if family == 4:  # Cisco sequence / ASA
        return (
            f"{fdp.ConsumeIntInRange(0, 999999):06d}: {mon} {day:02d} {hh:02d}:{mm:02d}:{ss:02d}.123: "
            f"%ASA-{fdp.ConsumeIntInRange(0, 7)}-{fdp.ConsumeIntInRange(100000, 799999)}: "
            f"Built conn src={_ip(fdp)} dst={_ip(fdp)} {payload[:128]}"
        )
    # family == 5: adaptive-only shape (punctuation prefix, no builtin match)
    p = PREFIX_PUNCT[fdp.ConsumeIntInRange(0, len(PREFIX_PUNCT) - 1)] * fdp.ConsumeIntInRange(1, 4)
    return f"{p} {mon} {day:02d} {hh:02d}:{mm:02d}:{ss:02d} {host} {payload}"


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
    line = build_line(fdp)
    cef = convert_line(line)
    parts = _split_unescaped_pipes(cef)
    # The renderer escapes pipes in header AND extension values, so a
    # correct record has exactly 8 parts; any extra unescaped pipe is a
    # forgery or an escaping regression.
    if len(parts) != 8 or parts[0] != "CEF:0":
        raise AssertionError(f"structurally invalid CEF for line {line[:80]!r}")
    if not parts[6].isdigit():
        raise AssertionError(f"non-numeric severity for line {line[:80]!r}")
    if parts[7] and not re.match(r"[A-Za-z0-9_.]+=", parts[7]):
        raise AssertionError(f"bad extension boundary for line {line[:80]!r}")
    for field in parts[:7]:
        if "\r" in field or "\n" in field:
            raise AssertionError(f"CR/LF in CEF header for line {line[:80]!r}")


def main() -> None:
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
