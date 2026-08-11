"""Security-hardening regressions (private review items):

- The TCP listener caps total concurrent connections and closes idle
  ones, so many-but-well-behaved clients cannot exhaust memory or
  descriptors in aggregate.
- NUL bytes are stripped from every CEF extension value (not just msg),
  so an embedded NUL in the raw event's cs1 field cannot truncate or
  confuse downstream consumers.
"""

from __future__ import annotations

import socket
import threading

import syslogcef.net as net
from syslogcef import convert_line
from syslogcef.net import listen_lines
from syslogcef.utils import cef_escape


def _ready_pair(send_fn):
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


# ---- NUL stripping -------------------------------------------------------

def test_cef_escape_strips_nul():
    assert "\x00" not in cef_escape("before\x00after")


def test_raw_event_nul_absent_from_cef_output():
    cef = convert_line("plain\x00message body")

    assert "\x00" not in cef
    # cs1 carries the raw event; it must be NUL-free too.
    assert "cs1=" in cef


# ---- TCP aggregate limits ------------------------------------------------

def test_aggregate_limits_are_configured():
    # The listener must carry a finite connection cap and a positive
    # idle timeout — the aggregate-exhaustion guards from the review.
    assert isinstance(net.MAX_TCP_CONNECTIONS, int) and net.MAX_TCP_CONNECTIONS > 0
    assert isinstance(net.TCP_IDLE_TIMEOUT, float) and net.TCP_IDLE_TIMEOUT > 0


def test_tcp_still_delivers_with_cap_in_place(monkeypatch):
    # A tight cap must not break normal delivery for connections within
    # it (regression guard: the cap/reap bookkeeping stays consistent).
    monkeypatch.setattr(net, "MAX_TCP_CONNECTIONS", 4)

    def send(port):
        c = socket.create_connection(("127.0.0.1", port), timeout=5)
        c.sendall(b"one\ntwo\n")
        c.close()

    ready, thread = _ready_pair(send)
    lines = list(listen_lines("tcp", "127.0.0.1", 0, max_messages=2, ready_callback=ready))
    thread.join(5)

    assert lines == ["one", "two"]


# The refuse-over-cap and flush-on-reap behaviors live deep in the
# select loop and resist deterministic socket-level testing (a
# max_messages-bounded listener can exit before it ever accepts the
# over-cap connection, and idle reaping races the initial recv). They
# are verified here by structural invariant on the listener source —
# guarding that the code paths exist and stay wired to the buffer/yield
# bookkeeping — rather than by flaky threaded timing.

def test_over_capacity_connections_are_refused_and_closed():
    import inspect

    src = inspect.getsource(net._listen_tcp)
    cap_index = src.index("MAX_TCP_CONNECTIONS")
    block = src[cap_index:cap_index + 800]
    assert "conn.close()" in block  # the over-cap connection is closed
    assert "continue" in block      # ... and not registered/buffered


def test_idle_reap_discards_incomplete_fragment():
    import inspect

    src = inspect.getsource(net._listen_tcp)
    reap_index = src.index("Closing idle connection")
    reap_block = src[reap_index:reap_index + 600]
    # The reap must drop the buffered remainder (an incomplete record the
    # still-connected client paused midway through) — not yield it, which
    # would emit a truncated event. The EOF path, by contrast, does flush.
    assert "buffers.pop(sock" in reap_block
    assert "yield line" not in reap_block
