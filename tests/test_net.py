from __future__ import annotations

import socket
import threading

import pytest

from syslogcef.net import listen_lines, parse_endpoint


def test_parse_endpoint_forms():
    assert parse_endpoint("udp:514") == ("udp", "0.0.0.0", 514)
    assert parse_endpoint("tcp:5514") == ("tcp", "0.0.0.0", 5514)
    assert parse_endpoint("udp:10.0.0.5:514") == ("udp", "10.0.0.5", 514)
    for bad in ("http:80", "udp:notaport", "udp:99999", "514"):
        with pytest.raises(ValueError):
            parse_endpoint(bad)


def _run_when_ready(send_fn):
    """Return (ready_callback, thread) that fires send_fn(port) once bound."""
    started = threading.Event()
    bound = {}

    def ready(port):
        bound["port"] = port
        started.set()

    def runner():
        started.wait(5)
        send_fn(bound["port"])

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()
    return ready, thread


def test_udp_listener_receives_lines():
    def send(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"<166>Jan  1 12:34:56 fw1 app: one", ("127.0.0.1", port))
        sock.sendto(b"line two\nline three\n", ("127.0.0.1", port))
        sock.close()

    ready, thread = _run_when_ready(send)
    lines = list(
        listen_lines("udp", "127.0.0.1", 0, max_messages=3, ready_callback=ready)
    )
    thread.join(5)
    assert lines == ["<166>Jan  1 12:34:56 fw1 app: one", "line two", "line three"]


def test_tcp_listener_receives_lines_across_connections():
    def send(port):
        c1 = socket.create_connection(("127.0.0.1", port), timeout=5)
        c1.sendall(b"alpha\nbeta\n")
        c1.close()
        c2 = socket.create_connection(("127.0.0.1", port), timeout=5)
        c2.sendall(b"gamma without newline")
        c2.close()

    ready, thread = _run_when_ready(send)
    lines = list(
        listen_lines("tcp", "127.0.0.1", 0, max_messages=3, ready_callback=ready)
    )
    thread.join(5)
    assert sorted(lines) == ["alpha", "beta", "gamma without newline"]


def test_listener_lines_convert_end_to_end():
    from syslogcef import convert_line

    def send(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(
            b"<166>Jan  1 12:34:56 fw1 %ASA-6-302013: Built inbound src=1.2.3.4",
            ("127.0.0.1", port),
        )
        sock.close()

    ready, thread = _run_when_ready(send)
    lines = list(
        listen_lines("udp", "127.0.0.1", 0, max_messages=1, ready_callback=ready)
    )
    thread.join(5)
    cef = convert_line(lines[0])
    assert cef.startswith("CEF:0|Cisco|ASA|")


# --- forwarding ---------------------------------------------------------------

def test_create_sender_parses_targets():
    from syslogcef.net import SyslogSender, create_sender

    s = create_sender("udp://siem.example.com:514")
    assert isinstance(s, SyslogSender) and s.proto == "udp" and s.port == 514
    s.close()
    for bad in ("udp://nohost", "ftp://x:1", "kafka://broker:9092"):
        with pytest.raises(ValueError):
            create_sender(bad)


def test_udp_sender_delivers_to_listener():
    from syslogcef.net import create_sender

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(5)
    port = rx.getsockname()[1]
    sender = create_sender(f"udp://127.0.0.1:{port}")
    sender.send("CEF:0|Cisco|ASA|auto|x|y|2|src=1.2.3.4")
    data, _ = rx.recvfrom(65535)
    sender.close()
    rx.close()
    assert data.decode() == "CEF:0|Cisco|ASA|auto|x|y|2|src=1.2.3.4"


def test_tcp_sender_delivers_newline_delimited():
    from syslogcef.net import create_sender

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5)
    port = srv.getsockname()[1]

    sender = create_sender(f"tcp://127.0.0.1:{port}")
    sender.send("record one")
    conn, _ = srv.accept()
    conn.settimeout(5)
    sender.send("record two")
    sender.close()
    received = b""
    while b"two\n" not in received:
        received += conn.recv(1024)
    conn.close()
    srv.close()
    assert received == b"record one\nrecord two\n"


def test_rate_limiter_paces_sends():
    from syslogcef.net import RateLimiter

    sleeps = []
    clock_value = [0.0]

    def clock():
        return clock_value[0]

    def sleep(seconds):
        sleeps.append(seconds)
        clock_value[0] += seconds

    limiter = RateLimiter(10, clock=clock, sleep=sleep)  # 0.1s interval
    for _ in range(3):
        limiter.wait()
    assert sum(sleeps) == pytest.approx(0.2, abs=0.01)


def test_kafka_sender_uses_injected_producer():
    from syslogcef.net import KafkaSender

    class FakeProducer:
        def __init__(self):
            self.sent = []
            self.flushed = False

        def send(self, topic, payload):
            self.sent.append((topic, payload))

        def flush(self):
            self.flushed = True

    producer = FakeProducer()
    sender = KafkaSender("broker:9092", "cef-events", producer=producer)
    sender.send("CEF:0|a|b|1|c|d|5|")
    sender.close()
    assert producer.sent == [("cef-events", b"CEF:0|a|b|1|c|d|5|")]
    assert producer.flushed
