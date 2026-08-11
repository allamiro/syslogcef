from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import datetime
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

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


def follow_files(
    paths: Iterable[Path],
    *,
    poll_interval: float = 0.5,
    max_idle_polls: Optional[int] = None,
) -> Iterator[str]:
    """Tail several files at once, round-robin, yielding lines as they appear.

    ``max_idle_polls`` bounds how many consecutive empty polls are allowed
    before the generator stops; ``None`` follows forever.
    """

    handles = [path.open("r", encoding="utf-8", errors="replace") for path in paths]
    idle_polls = 0
    try:
        while True:
            got_line = False
            for handle in handles:
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    got_line = True
                    yield line.rstrip("\n")
            if got_line:
                idle_polls = 0
                continue
            idle_polls += 1
            if max_idle_polls is not None and idle_polls >= max_idle_polls:
                return
            time.sleep(poll_interval)
    finally:
        for handle in handles:
            handle.close()


# Portable strftime codes with at-coarsest one-second granularity.
# %f (microseconds) is excluded so a rendered path can only change once
# per second; platform extensions (%e, %s, %-d, ...) are excluded so
# templates behave identically on glibc and musl.
_STRFTIME_CODES = frozenset("aAbBcdGHIjmMpSuUVwWxXyYzZ")


def template_has_codes(text: str) -> bool:
    """Return True if *text* contains supported strftime codes.

    ``%%`` is a literal percent. Any other ``%`` sequence, including a
    trailing ``%``, raises ValueError so typos like ``%Q`` fail at
    startup instead of silently producing a literal filename (glibc
    passes unknown codes through rather than raising).
    """
    templated = False
    i = 0
    while i < len(text):
        if text[i] == "%":
            if i + 1 >= len(text):
                raise ValueError("trailing '%' (use '%%' for a literal percent)")
            nxt = text[i + 1]
            if nxt in _STRFTIME_CODES:
                templated = True
            elif nxt != "%":
                raise ValueError(f"unsupported strftime code '%{nxt}' (use '%%' for a literal percent)")
            i += 2
        else:
            i += 1
    return templated


def write_lines(
    outputs: Iterable[str],
    template: Path,
    *,
    append: bool,
    stream_flush: bool,
    sender=None,
) -> None:
    """Write CEF lines to ``template``.

    A path containing strftime codes is re-rendered as time passes and
    the file is reopened whenever the rendered path changes, e.g.
    ``/var/log/syslogcef/%Y-%m-%d/events-%H.cef`` starts a new file each
    hour. Templated paths are always opened in append mode and their
    parent directories are created; paths without codes (``%%`` renders
    as a literal percent) keep the truncate/append behaviour selected by
    ``append``.
    """
    text = str(template)
    if not template_has_codes(text):
        if "%" in text:
            # Rendered (%%-escaped) paths get the same parent-creation
            # guarantee as templated ones; untouched paths keep the old
            # fail-if-missing behaviour.
            path = Path(datetime.now().astimezone().strftime(text))
            path.parent.mkdir(parents=True, exist_ok=True)
        else:
            path = template
        with path.open("a" if append else "w", encoding="utf-8") as fp:
            for cef in outputs:
                fp.write(cef + "\n")
                if stream_flush:
                    fp.flush()
                if sender:
                    sender.send(cef)
        return

    fp = None
    current = None
    last_tick = None
    try:
        for cef in outputs:
            # Aware local datetime so %z/%Z render the real offset/name
            # instead of the empty string a naive datetime produces.
            now = datetime.now().astimezone()
            tick = now.replace(microsecond=0)
            if tick != last_tick:
                last_tick = tick
                rendered = now.strftime(text)
                if rendered != current:
                    if fp:
                        fp.close()
                    path = Path(rendered)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    fp = path.open("a", encoding="utf-8")
                    current = rendered
            fp.write(cef + "\n")
            if stream_flush:
                fp.flush()
            if sender:
                sender.send(cef)
    finally:
        if fp:
            fp.close()


def _convert_line_mp(line: str, mode: Optional[str], mapping: Any, validate: bool = False, strict: bool = False) -> str:
    return convert_line(line, mode=mode, mapping=mapping, validate=validate, strict=strict)


def _mp_load_patterns(pattern_files: list) -> None:
    # Reload pattern files in each pool worker so --patterns works with
    # --multiprocess. Clear first: under the fork start method workers
    # inherit the parent's already-populated registry, and reloading into
    # it would fail every worker with duplicate-name errors.
    from .custom import clear_registry, load_patterns

    clear_registry()
    for path in pattern_files:
        load_patterns(path)


def process_lines(
    lines: Iterable[str],
    *,
    mode: Optional[str],
    mapping: Any,
    use_multiprocessing: bool,
    pool_size: Optional[int],
    validate: bool = False,
    strict: bool = False,
    pattern_files: Optional[list] = None,
) -> Iterator[str]:
    if use_multiprocessing:
        size = pool_size or max(1, cpu_count() - 1)
        with Pool(size, initializer=_mp_load_patterns, initargs=(pattern_files or [],)) as pool:
            worker = partial(_convert_line_mp, mode=mode, mapping=mapping, validate=validate, strict=strict)
            for cef in pool.imap(worker, lines):
                yield cef
    else:
        for line in lines:
            yield convert_line(line, mode=mode, mapping=mapping, validate=validate, strict=strict)


def _optional_path(value: str) -> Optional[Path]:
    # An empty --output (e.g. OUTPUT_FILE= left blank in the service
    # environment file) means stdout, not a file named "".
    return Path(value) if value else None


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert syslog lines to ArcSight CEF")
    parser.add_argument("paths", nargs="*", type=Path, help="Input files (defaults to stdin)")
    parser.add_argument("-o", "--output", type=_optional_path, help="Output file; strftime codes such as %%Y-%%m-%%d or %%H start a new file when the rendered path changes (templated paths always append and parent directories are created). Use %%%% for a literal percent; unsupported codes are rejected. An empty value means stdout.")
    parser.add_argument("-a", "--append", action="store_true", help="Append to --output instead of truncating it (implied for templated paths)")
    parser.add_argument("--mode", help="Parser mode override: rfc3164, rfc5424, rsyslog_json, rsyslog_file, journald_json, journald_short, journald_iso, cisco_seq, iso_syslog, kv, or a name from --patterns")
    parser.add_argument("--mapping", type=str, help="Mapping JSON file")
    parser.add_argument("--patterns", action="append", metavar="FILE", help="JSON file of custom parser patterns (named regexes); may be given multiple times. See the man page for the format.")
    parser.add_argument("--tail", action="store_true", help="Follow file like tail -f")
    parser.add_argument("--listen", metavar="PROTO:PORT", help="Receive syslog over the network instead of reading files/stdin, e.g. udp:514, tcp:5514, or udp:10.0.0.5:514")
    parser.add_argument("--send", metavar="URL", help="Forward CEF records to udp://HOST:PORT, tcp://HOST:PORT (newline-delimited, with reconnect), or kafka://BROKER:PORT/TOPIC (requires the kafka extra)")
    parser.add_argument("--eps", type=float, help="Rate-limit --send to at most this many events per second")
    parser.add_argument("--multiprocess", action="store_true", help="Process lines using a process pool")
    parser.add_argument("--pool-size", type=int, help="Number of worker processes for --multiprocess")
    parser.add_argument("--validate", action="store_true", help="Validate CEF extensions against the ArcSight dictionary; violations are logged as warnings")
    parser.add_argument("--strict", action="store_true", help="Like --validate, but exit with an error on type/length violations")
    parser.add_argument("--log-level", default="WARNING", help="Logging level")

    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.WARNING))

    # Reject invalid option combinations before any file, socket, or
    # pool side effects (#89): mistakes in service environment files
    # must fail with a clear message, not a traceback or silence.
    if args.pool_size is not None and not args.multiprocess:
        parser.error("--pool-size requires --multiprocess")
    if args.multiprocess and args.pool_size is not None and args.pool_size < 1:
        parser.error(f"--pool-size must be a positive integer (got {args.pool_size})")
    if args.eps is not None and not args.send:
        parser.error("--eps requires --send")
    if args.listen and args.paths:
        parser.error("--listen replaces file input; remove the positional paths")
    if args.tail and not args.paths:
        parser.error("--tail requires input file paths")

    if args.output:
        try:
            template_has_codes(str(args.output))
        except ValueError as exc:
            parser.error(f"invalid --output template: {exc}")

    if args.patterns:
        from .custom import PatternFileError, load_patterns

        for pattern_file in args.patterns:
            try:
                load_patterns(pattern_file)
            except PatternFileError as exc:
                parser.error(str(exc))

    if args.mode:
        from .custom import get_registered
        from .parsers import PARSERS

        if args.mode not in PARSERS and get_registered(args.mode) is None:
            parser.error(f"unknown --mode '{args.mode}' (not a built-in parser or a loaded pattern name)")

    # Load and validate the mapping eagerly (#84): a missing or malformed
    # file must fail before the output is opened — a truncate-mode open
    # would destroy an existing archive before the lazy first-event load
    # ever ran. Loading once here also avoids re-reading the JSON file
    # for every converted line.
    mapping = None
    if args.mapping is not None:
        # An explicitly empty --mapping (e.g. MAPPING= blank in a service
        # environment file) is a misconfiguration, not "use the default":
        # silently proceeding would truncate an existing --output with an
        # unintended mapping. Fail before any file is opened.
        if not args.mapping.strip():
            parser.error("--mapping was given an empty value")
        from .api import _load_mapping

        try:
            mapping = _load_mapping(args.mapping)
        except (OSError, ValueError) as exc:
            parser.error(f"invalid --mapping: {exc}")

    outputs: Iterator[str]
    if args.listen:
        from .net import listen_lines, parse_endpoint

        try:
            proto, host, port = parse_endpoint(args.listen)
        except ValueError as exc:
            parser.error(str(exc))
        lines = listen_lines(proto, host, port)
        outputs = process_lines(lines, mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns)
    elif args.tail and args.paths:
        outputs = process_lines(follow_files(args.paths), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns)
    else:
        outputs = process_lines(iter_lines_from_sources(args.paths), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns)

    sender = None
    if args.send:
        from .net import create_sender

        try:
            sender = create_sender(args.send, eps=args.eps)
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))

    from .validation import CEFValidationError

    try:
        if args.output:
            write_lines(
                outputs,
                args.output,
                append=args.append,
                stream_flush=bool(args.tail or args.listen),
                sender=sender,
            )
        elif sender:
            for cef in outputs:
                sender.send(cef)
        else:
            stream_flush = bool(args.tail or args.listen)
            for cef in outputs:
                print(cef, flush=stream_flush)
    except CEFValidationError as exc:
        print(f"syslogcef: strict validation failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if sender:
            sender.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
