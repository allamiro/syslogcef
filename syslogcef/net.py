"""Network input for syslogcef: receive syslog over UDP or TCP.

The listener yields raw lines exactly as the rest of the pipeline expects
them, so ``--listen`` composes with every existing option (mappings, mode
overrides, outputs).
"""

from __future__ import annotations

import logging
import selectors
import socket
from typing import Callable, Iterator, Optional, Tuple

logger = logging.getLogger(__name__)

MAX_DATAGRAM = 65535


def parse_endpoint(spec: str) -> Tuple[str, str, int]:
    """Parse ``udp:514``, ``tcp:5514``, or ``udp:10.0.0.5:514``."""

    parts = spec.split(":")
    proto = parts[0].lower()
    if proto not in ("udp", "tcp") or len(parts) not in (2, 3):
        raise ValueError(
            f"Invalid endpoint {spec!r}; expected udp:PORT, tcp:PORT, or udp:HOST:PORT"
        )
    host = parts[1] if len(parts) == 3 else "0.0.0.0"
    try:
        port = int(parts[-1])
    except ValueError as exc:
        raise ValueError(f"Invalid port in endpoint {spec!r}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"Port out of range in endpoint {spec!r}")
    return proto, host, port


def listen_lines(
    proto: str,
    host: str,
    port: int,
    *,
    max_messages: Optional[int] = None,
    ready_callback: Optional[Callable[[int], None]] = None,
) -> Iterator[str]:
    """Yield syslog lines received on the given endpoint.

    ``max_messages`` bounds the number of yielded lines (used by tests);
    ``None`` listens forever. ``ready_callback`` receives the bound port
    once the socket is listening (useful with port 0).
    """

    if proto == "udp":
        yield from _listen_udp(host, port, max_messages, ready_callback)
    else:
        yield from _listen_tcp(host, port, max_messages, ready_callback)


def _listen_udp(host, port, max_messages, ready_callback) -> Iterator[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    if ready_callback:
        ready_callback(sock.getsockname()[1])
    logger.info("Listening on udp:%s:%s", *sock.getsockname())
    count = 0
    try:
        while max_messages is None or count < max_messages:
            data, _addr = sock.recvfrom(MAX_DATAGRAM)
            for raw in data.decode("utf-8", "replace").splitlines():
                if raw.strip():
                    yield raw
                    count += 1
                    if max_messages is not None and count >= max_messages:
                        return
    finally:
        sock.close()


def _listen_tcp(host, port, max_messages, ready_callback) -> Iterator[str]:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(16)
    server.setblocking(False)
    if ready_callback:
        ready_callback(server.getsockname()[1])
    logger.info("Listening on tcp:%s:%s", *server.getsockname())

    sel = selectors.DefaultSelector()
    sel.register(server, selectors.EVENT_READ)
    buffers: dict[socket.socket, bytes] = {}
    count = 0
    try:
        while max_messages is None or count < max_messages:
            for key, _events in sel.select(timeout=1):
                sock = key.fileobj
                if sock is server:
                    conn, addr = server.accept()
                    conn.setblocking(False)
                    sel.register(conn, selectors.EVENT_READ)
                    buffers[conn] = b""
                    logger.debug("Connection from %s", addr)
                    continue
                try:
                    data = sock.recv(65536)
                except (BlockingIOError, InterruptedError):
                    continue
                except ConnectionError:
                    data = b""
                if not data:
                    sel.unregister(sock)
                    sock.close()
                    remainder = buffers.pop(sock, b"")
                    line = remainder.decode("utf-8", "replace").strip()
                    if line:
                        yield line
                        count += 1
                    continue
                buffers[sock] += data
                while b"\n" in buffers[sock]:
                    raw, buffers[sock] = buffers[sock].split(b"\n", 1)
                    line = raw.decode("utf-8", "replace").rstrip("\r")
                    if line.strip():
                        yield line
                        count += 1
                        if max_messages is not None and count >= max_messages:
                            return
    finally:
        for sock in list(buffers):
            sock.close()
        sel.close()
        server.close()


__all__ = ["listen_lines", "parse_endpoint"]
