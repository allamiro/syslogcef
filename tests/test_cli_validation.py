"""Startup validation: bad configurations must fail before side effects.

Covers #84 (a broken --mapping must not truncate an existing --output)
and #89 (invalid option combinations exit with a clear parser error,
status 2, no traceback, no side effects).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from syslogcef.cli import main


def _run_expect_usage_error(argv):
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == 2


# ---- #84: mapping validated before the output is opened -------------------

PRECIOUS = "precious archived events\n"


def _existing_output(tmp_path: Path) -> Path:
    out = tmp_path / "existing.cef"
    out.write_text(PRECIOUS, encoding="utf-8")
    return out


def test_missing_mapping_file_preserves_output(tmp_path: Path):
    out = _existing_output(tmp_path)
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")

    _run_expect_usage_error([str(log), "--mapping", str(tmp_path / "nope.json"), "-o", str(out)])

    assert out.read_text(encoding="utf-8") == PRECIOUS


def test_malformed_json_mapping_preserves_output(tmp_path: Path):
    out = _existing_output(tmp_path)
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("# not json at all\n", encoding="utf-8")

    _run_expect_usage_error([str(log), "--mapping", str(bad), "-o", str(out)])

    assert out.read_text(encoding="utf-8") == PRECIOUS


def test_top_level_array_mapping_rejected(tmp_path: Path):
    out = _existing_output(tmp_path)
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")
    bad = tmp_path / "array.json"
    bad.write_text('["not", "an", "object"]', encoding="utf-8")

    _run_expect_usage_error([str(log), "--mapping", str(bad), "-o", str(out)])

    assert out.read_text(encoding="utf-8") == PRECIOUS


def test_wrong_shape_extensions_rejected(tmp_path: Path):
    bad = tmp_path / "shape.json"
    bad.write_text('{"extensions": ["src"]}', encoding="utf-8")
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")

    _run_expect_usage_error([str(log), "--mapping", str(bad)])


def test_valid_mapping_still_converts(tmp_path: Path):
    log = tmp_path / "in.log"
    log.write_text("<166>Jan  1 12:34:56 h a: m\n", encoding="utf-8")
    mapping = tmp_path / "ok.json"
    mapping.write_text('{"deviceVendor": "T", "extensions": {"msg": "%(msg)s"}}', encoding="utf-8")
    out = tmp_path / "out.cef"

    assert main([str(log), "--mapping", str(mapping), "-o", str(out)]) == 0
    assert "CEF:0|T|" in out.read_text(encoding="utf-8")


# ---- #89: invalid option combinations ------------------------------------

def test_empty_mapping_preserves_output(tmp_path: Path):
    out = _existing_output(tmp_path)
    log = tmp_path / "in.log"
    log.write_text("hello\n", encoding="utf-8")

    _run_expect_usage_error([str(log), "--mapping", "", "-o", str(out)])

    assert out.read_text(encoding="utf-8") == PRECIOUS


def test_pool_size_requires_multiprocess():
    _run_expect_usage_error(["--pool-size", "4"])


def test_pool_size_must_be_positive():
    _run_expect_usage_error(["--multiprocess", "--pool-size", "0"])
    _run_expect_usage_error(["--multiprocess", "--pool-size", "-2"])


def test_eps_requires_send():
    _run_expect_usage_error(["--eps", "100"])


def test_listen_excludes_positional_paths(tmp_path: Path):
    log = tmp_path / "in.log"
    log.write_text("x\n", encoding="utf-8")
    _run_expect_usage_error(["--listen", "udp:5514", str(log)])


def test_tail_requires_paths():
    _run_expect_usage_error(["--tail"])
