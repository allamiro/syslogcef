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

from .api import StreamConverter, convert_line

logger = logging.getLogger(__name__)


def iter_lines_from_sources(paths: Iterable[Path] | None, *, tag_sources: bool = False) -> Iterator[Any]:
    """Yield lines from stdin or the given files.

    With ``tag_sources`` each item is ``(source, line)`` so downstream
    continuation handling can keep per-file context instead of letting
    an indented line at the top of one file inherit the previous file's
    host and timestamp.
    """
    if not paths:
        for line in sys.stdin:
            line = line.rstrip("\n")
            yield ("stdin", line) if tag_sources else line
        return

    for path in paths:
        source = str(path)
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                yield (source, line) if tag_sources else line


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


class _Follower:
    """One tailed path, surviving rotation (rename, replace, truncate)."""

    _FINGERPRINT_LEN = 256

    def __init__(self, path: Path):
        from collections import deque

        self.path = path
        self.handle = path.open("r", encoding="utf-8", errors="replace")
        self.signature = self._fsignature()
        # Fingerprint of the *already-consumed* head of the file. Those
        # bytes are stable across appends (which only add data past our
        # offset) but change when a copy-truncate rewrites the file in
        # place, so comparing them detects rewrites the size/inode check
        # misses. Length is bounded by both _FINGERPRINT_LEN and our read
        # offset, so a plain append to a short file is never mistaken for
        # a rewrite.
        self.fp_len = 0
        self.fingerprint = b""
        self.pending = deque()

    def _fsignature(self):
        import os

        st = os.fstat(self.handle.fileno())
        return (st.st_dev, st.st_ino)

    def _read_head(self, length: int) -> bytes:
        # Positional read so the follow position is untouched.
        import os

        if self.handle is None or length <= 0:
            return b""
        try:
            return os.pread(self.handle.fileno(), length, 0)
        except (OSError, AttributeError):
            return b""

    def _capture_fingerprint(self) -> None:
        if self.handle is None:
            self.fp_len, self.fingerprint = 0, b""
            return
        self.fp_len = min(self._FINGERPRINT_LEN, self.handle.tell())
        self.fingerprint = self._read_head(self.fp_len)

    def read_lines(self) -> Iterator[str]:
        while self.pending:
            yield self.pending.popleft()
        if self.handle is None:
            return
        while True:
            line = self.handle.readline()
            if not line:
                # At EOF: record the consumed-head fingerprint so the next
                # rotation check can tell an append from an in-place rewrite.
                self._capture_fingerprint()
                return
            yield line.rstrip("\n")

    def check_rotation(self) -> bool:
        """Reattach after rotation events. Returns True if a replacement
        file was (re)opened, so the caller can read it before treating
        the poll as idle.

        Runs every pass, not only when idle: a file that is renamed away
        while still being written keeps this follower producing from the
        stale descriptor forever, so a replacement at the original path
        would never be picked up if rotation were checked only on idle
        polls.

        - rename-and-recreate: the path's dev/inode changes; drain any
          remaining lines from the old descriptor, then open the new
          file from the start.
        - copy-truncate: same inode but size below our offset; rewind.
        - temporary disappearance mid-rotation: keep the old descriptor
          (it stays readable) and retry until a replacement appears.
        """
        if self.handle is None:
            try:
                self.handle = self.path.open("r", encoding="utf-8", errors="replace")
                self.signature = self._fsignature()
                self.fp_len, self.fingerprint = 0, b""
                return True
            except OSError:
                return False
        try:
            st = self.path.stat()
        except OSError:
            return False
        if (st.st_dev, st.st_ino) != self.signature:
            for line in self.handle:
                self.pending.append(line.rstrip("\n"))
            self.handle.close()
            self.handle = None
            return self.check_rotation()  # open the replacement immediately
        # Copy-truncate: same inode, but either the file shrank below our
        # offset, or the already-consumed head changed (an in-place rewrite
        # that regrew past our offset). Comparing only the consumed prefix
        # means a plain append — which never touches those bytes — is not
        # mistaken for a rewrite, even for a file shorter than the cap.
        offset = self.handle.tell()
        rewound = False
        if offset > 0:
            if st.st_size < offset:
                rewound = True
            elif self.fp_len and self._read_head(self.fp_len) != self.fingerprint:
                rewound = True
        if rewound:
            self.handle.seek(0)
            self.fp_len, self.fingerprint = 0, b""
        # A rewind exposes fresh content that must be read before the idle
        # limit applies, so report it as activity like a reopen.
        return rewound

    def close(self) -> None:
        if self.handle is not None:
            self.handle.close()
            self.handle = None


def follow_files(
    paths: Iterable[Path],
    *,
    poll_interval: float = 0.5,
    max_idle_polls: Optional[int] = None,
    tag_sources: bool = False,
) -> Iterator[Any]:
    """Tail several files at once, round-robin, yielding lines as they appear.

    Survives log rotation on every path independently: renamed-and-
    recreated files are reopened from the start (after draining the old
    descriptor), copy-truncated files are rewound, and paths that
    disappear mid-rotation are retried until a replacement appears.

    ``max_idle_polls`` bounds how many consecutive empty polls are allowed
    before the generator stops; ``None`` follows forever.

    With ``tag_sources`` each item is ``(path, line)``: the round-robin
    interleaves files, so continuation context downstream must be keyed
    per file rather than shared across them.
    """

    followers = [_Follower(path) for path in paths]
    idle_polls = 0
    try:
        while True:
            any_line = False
            for follower in followers:
                source = str(follower.path)
                for line in follower.read_lines():
                    any_line = True
                    yield (source, line) if tag_sources else line
            # Rotation is checked for every follower on every pass —
            # including busy ones — so a file renamed away while still
            # being written cannot pin this follower to the stale
            # descriptor and starve the replacement at the origin path.
            reopened = False
            for follower in followers:
                if follower.check_rotation():
                    reopened = True
            # A reopened replacement must be read before the idle limit
            # applies, so treat a reopen as activity: loop again to read
            # it rather than counting this pass as idle.
            if any_line or reopened:
                idle_polls = 0
                continue
            idle_polls += 1
            if max_idle_polls is not None and idle_polls >= max_idle_polls:
                return
            time.sleep(poll_interval)
    finally:
        for follower in followers:
            follower.close()


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


def _split_item(item: Any) -> tuple:
    # Line iterators may tag items as (source, line); untagged plain
    # strings share the "" source.
    if isinstance(item, tuple):
        return item
    return ("", item)


def process_lines(
    lines: Iterable[Any],
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
            for cef in pool.imap(worker, (_split_item(item)[1] for item in lines)):
                yield cef
    else:
        # Stateful conversion so whitespace-indented continuation lines
        # inherit host/app/timestamp from the preceding event, keyed by
        # source so interleaved files never cross-inherit. Unavailable
        # under --multiprocess, where workers cannot share line order.
        converter = StreamConverter(mode=mode, mapping=mapping, validate=validate, strict=strict)
        for item in lines:
            source, line = _split_item(item)
            yield converter.convert(line, source=source)


def _optional_path(value: str) -> Optional[Path]:
    # An empty --output (e.g. OUTPUT_FILE= left blank in the service
    # environment file) means stdout, not a file named "".
    return Path(value) if value else None


def main(argv: Optional[list[str]] = None) -> int:
    # prog is explicit so "python -m syslogcef --help" reports the command
    # name rather than "__main__.py".
    parser = argparse.ArgumentParser(
        prog="syslogcef", description="Convert syslog lines to ArcSight CEF"
    )
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
        outputs = process_lines(follow_files(args.paths, tag_sources=True), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns)
    else:
        outputs = process_lines(iter_lines_from_sources(args.paths, tag_sources=True), mode=args.mode, mapping=mapping, use_multiprocessing=args.multiprocess, pool_size=args.pool_size, validate=args.validate or args.strict, strict=args.strict, pattern_files=args.patterns)

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
