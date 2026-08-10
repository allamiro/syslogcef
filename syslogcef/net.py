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


# --------------------------------------------------------------------------
# Network output: forward CEF records to a SIEM or pipeline.

import time as _time
from urllib.parse import urlparse


class RateLimiter:
    """Simple events-per-second pacer."""

    def __init__(self, eps: float, clock=_time.monotonic, sleep=_time.sleep):
        if eps <= 0:
            raise ValueError("eps must be positive")
        self.interval = 1.0 / eps
        self._clock = clock
        self._sleep = sleep
        self._next = self._clock()

    def wait(self) -> None:
        now = self._clock()
        if now < self._next:
            self._sleep(self._next - now)
        self._next = max(self._next + self.interval, self._clock())


class SyslogSender:
    """Send CEF records to a syslog destination over UDP or TCP.

    TCP sends are newline-delimited and reconnect with backoff on failure.
    """

    RETRY_DELAYS = (0.5, 1.0, 2.0)

    def __init__(self, proto: str, host: str, port: int, *, limiter: Optional[RateLimiter] = None):
        self.proto = proto
        self.host = host
        self.port = port
        self.limiter = limiter
        self._sock: Optional[socket.socket] = None
        if proto == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _connect(self) -> socket.socket:
        sock = socket.create_connection((self.host, self.port), timeout=10)
        return sock

    def send(self, record: str) -> None:
        if self.limiter:
            self.limiter.wait()
        payload = record.encode("utf-8")
        if self.proto == "udp":
            self._sock.sendto(payload, (self.host, self.port))
            return
        data = payload + b"\n"
        last_error: Optional[Exception] = None
        for attempt, delay in enumerate((0.0,) + self.RETRY_DELAYS):
            if delay:
                _time.sleep(delay)
            try:
                if self._sock is None:
                    self._sock = self._connect()
                self._sock.sendall(data)
                return
            except OSError as exc:
                last_error = exc
                logger.warning("send to %s:%s failed (%s); reconnecting", self.host, self.port, exc)
                if self._sock is not None:
                    try:
                        self._sock.close()
                    except OSError:
                        pass
                    self._sock = None
        raise ConnectionError(f"Could not deliver record to {self.host}:{self.port}") from last_error

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


class KafkaSender:
    """Send CEF records to a Kafka topic (requires the 'kafka' extra)."""

    def __init__(self, broker: str, topic: str, *, limiter: Optional[RateLimiter] = None, producer=None):
        self.topic = topic
        self.limiter = limiter
        if producer is None:
            try:
                from kafka import KafkaProducer
            except ImportError as exc:
                raise RuntimeError(
                    "Kafka output requires the kafka extra: pip install syslog2cef[kafka]"
                ) from exc
            producer = KafkaProducer(bootstrap_servers=broker)
        self.producer = producer

    def send(self, record: str) -> None:
        if self.limiter:
            self.limiter.wait()
        self.producer.send(self.topic, record.encode("utf-8"))

    def close(self) -> None:
        try:
            self.producer.flush()
        finally:
            close = getattr(self.producer, "close", None)
            if close:
                close()


def create_sender(url: str, *, eps: Optional[float] = None):
    """Create a sender from udp://host:port, tcp://host:port, or kafka://broker/topic."""

    parsed = urlparse(url)
    limiter = RateLimiter(eps) if eps else None
    if parsed.scheme in ("udp", "tcp"):
        if not parsed.hostname or not parsed.port:
            raise ValueError(f"Invalid send target {url!r}; expected {parsed.scheme}://HOST:PORT")
        return SyslogSender(parsed.scheme, parsed.hostname, parsed.port, limiter=limiter)
    if parsed.scheme == "kafka":
        topic = parsed.path.lstrip("/")
        if not parsed.hostname or not topic:
            raise ValueError(f"Invalid send target {url!r}; expected kafka://BROKER:PORT/TOPIC")
        broker = f"{parsed.hostname}:{parsed.port or 9092}"
        return KafkaSender(broker, topic, limiter=limiter)
    raise ValueError(f"Unsupported send scheme {parsed.scheme!r}; use udp://, tcp://, or kafka://")


__all__ += ["RateLimiter", "SyslogSender", "KafkaSender", "create_sender"]
