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
