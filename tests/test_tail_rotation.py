"""--tail must survive log rotation (#85): rename-and-create,
copy-truncate, temporary disappearance, and per-file independence."""

from __future__ import annotations

import os
from pathlib import Path

from syslogcef.cli import follow_files


def drain(gen):
    return list(gen)


def test_rename_and_recreate_is_followed(tmp_path: Path):
    log = tmp_path / "app.log"
    log.write_text("old1\n", encoding="utf-8")

    gen = follow_files([log], poll_interval=0, max_idle_polls=6)
    assert next(gen) == "old1"

    # logrotate move-and-create: rename the active file, write a final
    # line to the rotated file, then create a fresh file at the path.
    rotated = tmp_path / "app.log.1"
    os.rename(log, rotated)
    with rotated.open("a", encoding="utf-8") as fp:
        fp.write("old2-after-rename\n")
    log.write_text("new1\n", encoding="utf-8")

    lines = drain(gen)
    assert "old2-after-rename" in lines  # old descriptor drained, not dropped
    assert "new1" in lines  # replacement picked up from the start


def test_copy_truncate_is_followed(tmp_path: Path):
    log = tmp_path / "app.log"
    log.write_text("aaaa\nbbbb\n", encoding="utf-8")

    gen = follow_files([log], poll_interval=0, max_idle_polls=6)
    assert next(gen) == "aaaa"
    assert next(gen) == "bbbb"

    # copytruncate: same inode, size drops below our offset.
    log.write_text("fresh\n", encoding="utf-8")

    assert "fresh" in drain(gen)


def test_temporary_disappearance_then_replacement(tmp_path: Path):
    # Driven at the _Follower level so the "path absent" window is
    # genuinely exercised across check_rotation calls, not skipped by a
    # synchronous recreate before any poll.
    from syslogcef.cli import _Follower

    log = tmp_path / "app.log"
    log.write_text("one\n", encoding="utf-8")

    follower = _Follower(log)
    assert list(follower.read_lines()) == ["one"]

    # The path vanishes for a rotation window: check_rotation must not
    # crash or drop the old descriptor while there is no replacement.
    os.rename(log, tmp_path / "gone.log")
    follower.check_rotation()
    follower.check_rotation()
    assert list(follower.read_lines()) == []  # still alive, nothing new

    # Replacement appears at the original path.
    log.write_text("back\n", encoding="utf-8")
    follower.check_rotation()
    assert list(follower.read_lines()) == ["back"]
    follower.close()


def test_one_file_rotates_while_others_continue(tmp_path: Path):
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text("a1\n", encoding="utf-8")
    b.write_text("b1\n", encoding="utf-8")

    gen = follow_files([a, b], poll_interval=0, max_idle_polls=6)
    first_two = [next(gen), next(gen)]
    assert set(first_two) == {"a1", "b1"}

    os.rename(a, tmp_path / "a.log.1")
    a.write_text("a2-new\n", encoding="utf-8")
    with b.open("a", encoding="utf-8") as fp:
        fp.write("b2\n")

    lines = drain(gen)
    assert "a2-new" in lines
    assert "b2" in lines


def test_busy_sibling_does_not_pin_a_rotated_file(tmp_path: Path):
    # Regression for the "active file suppresses all rotation checks"
    # bug: `busy` produces data on the poll where `rot` is rotated, so a
    # global "got data -> skip checks" would strand `rot` on its old
    # inode. Drive at the _Follower level for determinism.
    from syslogcef.cli import _Follower

    busy = tmp_path / "busy.log"
    rot = tmp_path / "rot.log"
    busy.write_text("b1\n", encoding="utf-8")
    rot.write_text("r1\n", encoding="utf-8")

    f_busy = _Follower(busy)
    f_rot = _Follower(rot)
    assert list(f_busy.read_lines()) == ["b1"]
    assert list(f_rot.read_lines()) == ["r1"]

    # rot is rename-rotated; busy keeps producing.
    os.rename(rot, tmp_path / "rot.log.1")
    rot.write_text("r2-new\n", encoding="utf-8")
    with busy.open("a", encoding="utf-8") as fp:
        fp.write("b2\n")

    # busy yields data (so it is not rotation-checked, correctly); rot
    # yields nothing and MUST be rotation-checked so it reattaches.
    assert list(f_busy.read_lines()) == ["b2"]
    f_rot.check_rotation()
    assert list(f_rot.read_lines()) == ["r2-new"]
    f_busy.close()
    f_rot.close()


def test_renamed_but_still_written_file_switches_to_replacement(tmp_path: Path):
    # A file renamed away while still receiving writes keeps the follower
    # producing from the stale descriptor. Rotation must still be detected
    # (checked every pass, not only when idle) so the replacement at the
    # origin path is adopted.
    from syslogcef.cli import _Follower

    log = tmp_path / "app.log"
    log.write_text("v1\n", encoding="utf-8")

    follower = _Follower(log)
    assert list(follower.read_lines()) == ["v1"]

    # Rename away, keep writing to the renamed file, and create a fresh
    # file at the origin path.
    rotated = tmp_path / "app.log.1"
    os.rename(log, rotated)
    with rotated.open("a", encoding="utf-8") as fp:
        fp.write("v2-old-fd\n")
    log.write_text("v3-new\n", encoding="utf-8")

    # check_rotation must report a reopen and adopt the replacement,
    # after draining the still-written old descriptor. The drained old
    # line goes to the pending queue; the new file's line follows.
    reopened = follower.check_rotation()
    assert reopened is True
    assert list(follower.read_lines()) == ["v2-old-fd", "v3-new"]
    follower.close()


def test_reopen_returns_true_for_idle_limit_accounting(tmp_path: Path):
    # After rename-and-recreate, check_rotation opening the replacement
    # must return True so follow_files does not count that pass as idle
    # and bail before reading the new file (the max_idle_polls=1 case).
    from syslogcef.cli import _Follower

    log = tmp_path / "app.log"
    log.write_text("a\n", encoding="utf-8")
    follower = _Follower(log)
    list(follower.read_lines())

    os.rename(log, tmp_path / "app.log.1")
    log.write_text("b\n", encoding="utf-8")

    assert follower.check_rotation() is True  # reopen signalled
    assert list(follower.read_lines()) == ["b"]
    follower.close()


def test_copy_truncate_regrown_past_offset_is_detected(tmp_path: Path):
    # The hard copy-truncate case: the file is rewritten to at least the
    # previous length before the next poll, so the inode is unchanged and
    # st_size is NOT below the offset. Content-fingerprint detection must
    # still catch it and rewind.
    from syslogcef.cli import _Follower

    log = tmp_path / "app.log"
    log.write_text("first line is long enough xxxxxxxxxxxxxxxxxxxxxxxx\n", encoding="utf-8")

    follower = _Follower(log)
    assert list(follower.read_lines()) == ["first line is long enough xxxxxxxxxxxxxxxxxxxxxxxx"]

    # copytruncate then immediate rewrite to >= the old length, all before
    # the next check: different head bytes, same-or-larger size.
    log.write_text("REWRITTEN content after copytruncate yyyyyyyyyyyyyyyyyy\n", encoding="utf-8")

    assert follower.check_rotation() is True  # detected via fingerprint
    assert list(follower.read_lines()) == ["REWRITTEN content after copytruncate yyyyyyyyyyyyyyyyyy"]
    follower.close()


def test_append_to_short_file_is_not_mistaken_for_truncation(tmp_path: Path):
    # A short file (< the 256-byte fingerprint) that is simply appended
    # to must NOT be misread as a copy-truncate: the fingerprint covers
    # only the already-consumed prefix, which an append never changes.
    from syslogcef.cli import _Follower

    log = tmp_path / "app.log"
    log.write_text("short1\n", encoding="utf-8")

    follower = _Follower(log)
    assert list(follower.read_lines()) == ["short1"]

    with log.open("a", encoding="utf-8") as fp:
        fp.write("short2\n")

    # No rewind reported, and only the *new* line is yielded — not a
    # re-emission of short1 from a bogus seek(0).
    assert follower.check_rotation() is False
    assert list(follower.read_lines()) == ["short2"]
    follower.close()


def test_copy_truncate_rewind_counts_as_activity(tmp_path: Path):
    # A copy-truncate rewind must report activity so follow_files does not
    # exit on the final allowed idle poll before reading the fresh content.
    from syslogcef.cli import _Follower

    log = tmp_path / "app.log"
    log.write_text("aaaa\nbbbb\n", encoding="utf-8")
    follower = _Follower(log)
    list(follower.read_lines())

    log.write_text("cc\n", encoding="utf-8")  # smaller: size < offset

    assert follower.check_rotation() is True  # rewind signalled as activity
    assert list(follower.read_lines()) == ["cc"]
    follower.close()


def test_plain_append_still_works(tmp_path: Path):
    log = tmp_path / "app.log"
    log.write_text("x\n", encoding="utf-8")

    gen = follow_files([log], poll_interval=0, max_idle_polls=5)
    assert next(gen) == "x"
    with log.open("a", encoding="utf-8") as fp:
        fp.write("y\n")
    assert "y" in drain(gen)
