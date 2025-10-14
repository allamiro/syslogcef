from __future__ import annotations

import argparse
import logging
import sys
import time
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Iterable, Iterator, Optional

from .api import convert_line

logger = logging.getLogger(__name__)


def iter_lines_from_sources(paths: Iterable[Path] | None) -> Iterator[str]:
    if not paths:
        for line in sys.stdin:
            yield line.rstrip("\n")
        return

    for path in paths:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                yield line.rstrip("\n")


def tail_file(path: Path, *, follow: bool = False) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        while True:
            line = handle.readline()
            if not line:
                if not follow:
                    break
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


def _convert_line_mp(line: str, mode: Optional[str], mapping: Optional[str]) -> str:
    return convert_line(line, mode=mode, mapping=mapping)


def process_lines(
    lines: Iterable[str],
    *,
    mode: Optional[str],
    mapping: Optional[str],
    use_multiprocessing: bool,
    pool_size: Optional[int],
) -> Iterator[str]:
    if use_multiprocessing:
        size = pool_size or max(1, cpu_count() - 1)
        with Pool(size) as pool:
            worker = partial(_convert_line_mp, mode=mode, mapping=mapping)
            for cef in pool.imap(worker, lines):
                yield cef
    else:
        for line in lines:
            yield convert_line(line, mode=mode, mapping=mapping)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert syslog lines to ArcSight CEF")
    parser.add_argument("paths", nargs="*", type=Path, help="Input files (defaults to stdin)")
    parser.add_argument("-o", "--output", type=Path, help="Output file")
    parser.add_argument("--mode", choices=["rfc3164", "rfc5424", "rsyslog_json", "rsyslog_file", "journald_json", "journald_short", "journald_iso"], help="Parser mode override")
    parser.add_argument("--mapping", type=str, help="Mapping JSON file")
    parser.add_argument("--tail", action="store_true", help="Follow file like tail -f")
    parser.add_argument("--multiprocess", action="store_true", help="Process lines using a process pool")
    parser.add_argument("--pool-size", type=int, help="Number of worker processes for --multiprocess")
    parser.add_argument("--log-level", default="WARNING", help="Logging level")

    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.WARNING))

    mapping = args.mapping

    outputs: Iterator[str]
    if args.tail and args.paths:
        def tail_stream() -> Iterator[str]:
            for path in args.paths:
                yield from tail_file(path, follow=True)

        outputs = process_lines(tail_stream(), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size)
    else:
        outputs = process_lines(iter_lines_from_sources(args.paths), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size)

    if args.output:
        with args.output.open("w", encoding="utf-8") as fp:
            for cef in outputs:
                fp.write(cef + "\n")
    else:
        for cef in outputs:
            print(cef)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
