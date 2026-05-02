"""Tests for mission_nfc_mfkey32 (host-side Crypto-1 key recovery).

Test strategy:
  - parser tests use real-shape Flipper log lines (no hardware needed)
  - solver tests use a fake binary on PATH that emits a canned key — this
    exercises subprocess wiring + output parsing without depending on
    mfkey32v2 being installed in the test environment
  - mission tests use the storage fixture pattern from test_unknown_identify

The "fake binary" approach: we write a tiny shell/batch script to a temp
dir, prepend that dir to PATH, and let find_solver_binary() pick it up.
This is the cleanest way to test the subprocess path hermetically.
"""

import asyncio
import os
import stat
import sys
from pathlib import Path

import pytest

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.missions import mission_nfc_mfkey32
from llmdr_redteam.missions.mfkey32_solver import (
    Mfkey32ParseError,
    NoncePair,
    SolverBinaryMissing,
    find_solver_binary,
    group_pairs,
    parse_mfkey32_log,
    solve,
)


# ---------- log-parsing tests (no subprocess) ---------------------------

class TestParser:
    """parse_mfkey32_log: shape, tolerance, edge cases."""

    def test_single_line(self):
        text = "Sec 1 key A cuid 1234abcd nt 89abcdef nr fedcba98 ar 76543210 at 0fedcba9"
        pairs = parse_mfkey32_log(text)
        assert len(pairs) == 1
        p = pairs[0]
        assert p.sector == 1
        assert p.key_type == "A"
        assert p.cuid == "1234abcd"
        assert p.nt == "89abcdef"
        assert p.nr == "fedcba98"
        assert p.ar == "76543210"
        assert p.at == "0fedcba9"

    def test_uppercase_hex_normalized(self):
        text = "Sec 0 key B cuid 1234ABCD nt 89ABCDEF nr FEDCBA98 ar 76543210 at 0FEDCBA9"
        pairs = parse_mfkey32_log(text)
        assert pairs[0].cuid == "1234abcd"
        assert pairs[0].nt == "89abcdef"

    def test_multi_line(self):
        text = (
            "Sec 1 key A cuid 11111111 nt 22222222 nr 33333333 ar 44444444 at 55555555\n"
            "Sec 1 key A cuid 11111111 nt 66666666 nr 77777777 ar 88888888 at 99999999\n"
            "Sec 2 key B cuid 11111111 nt aaaaaaaa nr bbbbbbbb ar cccccccc at dddddddd\n"
        )
        pairs = parse_mfkey32_log(text)
        assert len(pairs) == 3
        assert {p.sector for p in pairs} == {1, 2}
        assert {p.key_type for p in pairs} == {"A", "B"}

    def test_blank_lines_and_comments_ignored(self):
        text = (
            "# this is a comment\n"
            "\n"
            "Sec 1 key A cuid 11111111 nt 22222222 nr 33333333 ar 44444444 at 55555555\n"
            "  \n"
            "# another comment\n"
        )
        pairs = parse_mfkey32_log(text)
        assert len(pairs) == 1

    def test_empty_input(self):
        assert parse_mfkey32_log("") == []
        assert parse_mfkey32_log("\n\n\n") == []
        assert parse_mfkey32_log("# only comments\n") == []

    def test_malformed_line_raises(self):
        text = (
            "Sec 1 key A cuid 11111111 nt 22222222 nr 33333333 ar 44444444 at 55555555\n"
            "this is not a nonce line at all\n"
        )
        with pytest.raises(Mfkey32ParseError) as exc_info:
            parse_mfkey32_log(text)
        assert "line 2" in str(exc_info.value)

    def test_truncated_hex_rejected(self):
        # 7 hex chars instead of 8 — must fail loud, not parse half
        text = "Sec 1 key A cuid 1234567 nt 22222222 nr 33333333 ar 44444444 at 55555555"
        with pytest.raises(Mfkey32ParseError):
            parse_mfkey32_log(text)

    def test_extra_whitespace_tolerated(self):
        text = "Sec   1   key  A   cuid 11111111 nt 22222222 nr 33333333 ar 44444444 at 55555555"
        pairs = parse_mfkey32_log(text)
        assert len(pairs) == 1


class TestGrouping:
    """group_pairs: same (sector, key_type) bucket, different ones split."""

    def _make(self, sector, key_type, cuid="11111111"):
        return NoncePair(
            sector=sector, key_type=key_type, cuid=cuid,
            nt="22222222", nr="33333333", ar="44444444", at="55555555",
        )

    def test_groups_by_sector_and_key_type(self):
        pairs = [
            self._make(1, "A"),
            self._make(1, "A"),
            self._make(1, "B"),
            self._make(2, "A"),
        ]
        groups = group_pairs(pairs)
        assert (1, "A") in groups
        assert len(groups[(1, "A")]) == 2
        assert len(groups[(1, "B")]) == 1
        assert len(groups[(2, "A")]) == 1
        assert len(groups) == 3


# ---------- fake binary fixtures ----------------------------------------
# We synthesize a tiny "mfkey32" binary that prints a canned key. This
# lets us exercise the subprocess + output-parsing path without depending
# on the real C tool being installed. Real-tool integration is a manual
# operator step, documented in mfkey32.md.

@pytest.fixture
def fake_solver(tmp_path, monkeypatch):
    """Write a fake mfkey32v2 to tmp_path, prepend to PATH.

    The fake echoes a known key on stdout. This is enough to validate:
      - find_solver_binary() picks it up
      - subprocess invocation works
      - output regex picks the hex out of the noise
    """
    canned_key = "a0a1a2a3a4a5"

    if sys.platform == "win32":
        # Windows: a .bat file is the simplest invocable thing.
        fake = tmp_path / "mfkey32v2.bat"
        fake.write_text(f"@echo off\necho Found Key: [{canned_key}]\n")
    else:
        # Unix: a sh script with execute bit.
        fake = tmp_path / "mfkey32v2"
        fake.write_text(f"#!/bin/sh\necho 'Found Key: [{canned_key}]'\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    return canned_key, str(fake)


@pytest.fixture
def fake_solver_failing(tmp_path, monkeypatch):
    """A fake binary that exits 0 but emits no key — simulates a weak-nonce capture."""
    if sys.platform == "win32":
        fake = tmp_path / "mfkey32v2.bat"
        fake.write_text("@echo off\necho No key found, try more nonces\n")
    else:
        fake = tmp_path / "mfkey32v2"
        fake.write_text("#!/bin/sh\necho 'No key found, try more nonces'\n")
        fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))


# ---------- solver tests (with fake binary) ------------------------------

class TestSolver:
    """solve(): autodiscovery, subprocess wiring, output parsing."""

    def _two_pairs(self, sector=1, key_type="A"):
        return [
            NoncePair(sector=sector, key_type=key_type, cuid="11111111",
                      nt="22222222", nr="33333333", ar="44444444", at="55555555"),
            NoncePair(sector=sector, key_type=key_type, cuid="11111111",
                      nt="66666666", nr="77777777", ar="88888888", at="99999999"),
        ]

    def test_finds_fake_binary(self, fake_solver):
        canned, fake_path = fake_solver
        found = find_solver_binary()
        assert found is not None
        assert "mfkey32" in Path(found).name.lower()

    def test_solve_recovers_key(self, fake_solver):
        canned, _ = fake_solver
        result = solve(self._two_pairs())
        assert result.success
        assert len(result.recovered) == 1
        assert result.recovered[0].key_hex == canned
        assert result.recovered[0].sector == 1
        assert result.recovered[0].key_type == "A"

    def test_one_pair_marked_failed_not_recovered(self, fake_solver):
        result = solve([self._two_pairs()[0]])
        assert not result.success
        assert len(result.failed) == 1
        assert "need >= 2" in result.failed[0].reason

    def test_solver_runs_but_emits_no_key(self, fake_solver_failing):
        result = solve(self._two_pairs())
        assert not result.success
        assert len(result.failed) == 1
        assert "did not output" in result.failed[0].reason

    def test_missing_binary_raises(self, monkeypatch):
        # Empty PATH — no solver binary anywhere
        monkeypatch.setenv("PATH", "")
        with pytest.raises(SolverBinaryMissing):
            solve(self._two_pairs())

    def test_explicit_solver_path_overrides_path_lookup(self, fake_solver, monkeypatch):
        canned, fake_path = fake_solver
        # Even if PATH is empty, explicit solver_path should work
        monkeypatch.setenv("PATH", "")
        result = solve(self._two_pairs(), solver_path=fake_path)
        assert result.success
        assert result.recovered[0].key_hex == canned


# ---------- mission integration tests -----------------------------------

@pytest.fixture
def storage():
    s = InMemoryStorage()
    set_storage(s)
    reset_session_id("mfkey32-test-session")
    yield s
    set_storage(None)


class TestMission:
    """End-to-end mission tests: log_text path, log_path path, audit log."""

    _LOG_TWO_PAIRS = (
        "# captured 2026-04-30 against test reader\n"
        "Sec 1 key A cuid deadbeef nt 22222222 nr 33333333 ar 44444444 at 55555555\n"
        "Sec 1 key A cuid deadbeef nt 66666666 nr 77777777 ar 88888888 at 99999999\n"
    )

    def test_inline_log_text(self, storage, fake_solver):
        canned, _ = fake_solver
        result = asyncio.run(mission_nfc_mfkey32(log_text=self._LOG_TWO_PAIRS))
        # Mission returns the wrapped {"outputs": ..., "cross_link": ...} dict
        outputs = result["outputs"]
        assert outputs["nonces_parsed"] == 2
        assert outputs["cuid"] == "deadbeef"
        assert len(outputs["recovered"]) == 1
        assert outputs["recovered"][0]["key_hex"] == canned

    def test_log_path(self, storage, fake_solver, tmp_path):
        log_file = tmp_path / "test.mfkey32.log"
        log_file.write_text(self._LOG_TWO_PAIRS)
        result = asyncio.run(mission_nfc_mfkey32(log_path=str(log_file)))
        assert result["outputs"]["nonces_parsed"] == 2
        assert result["outputs"]["recovered"][0]["sector"] == 1

    def test_cross_link_set_on_success(self, storage, fake_solver):
        result = asyncio.run(mission_nfc_mfkey32(log_text=self._LOG_TWO_PAIRS))
        assert result.get("cross_link") == ("nfc_uid", "deadbeef")

    def test_no_cross_link_on_failure(self, storage, fake_solver_failing):
        result = asyncio.run(mission_nfc_mfkey32(log_text=self._LOG_TWO_PAIRS))
        assert "cross_link" not in result
        assert len(result["outputs"]["failed"]) == 1

    def test_empty_log_returns_empty_result(self, storage, fake_solver):
        result = asyncio.run(mission_nfc_mfkey32(log_text="# empty\n\n"))
        assert result["outputs"]["nonces_parsed"] == 0
        assert result["outputs"]["recovered"] == []
        assert "cross_link" not in result

    def test_neither_text_nor_path_raises(self, storage):
        with pytest.raises(ValueError, match="must provide either"):
            asyncio.run(mission_nfc_mfkey32())

    def test_both_text_and_path_raises(self, storage, tmp_path):
        log_file = tmp_path / "log.txt"
        log_file.write_text("# nothing\n")
        with pytest.raises(ValueError, match="only one of"):
            asyncio.run(mission_nfc_mfkey32(
                log_text="# inline", log_path=str(log_file),
            ))

    def test_audit_event_written_on_success(self, storage, fake_solver):
        asyncio.run(mission_nfc_mfkey32(log_text=self._LOG_TWO_PAIRS))
        events = list(storage.iter_events())
        assert len(events) == 1
        ev = events[0]
        assert ev["mission_name"] == "nfc_mfkey32"
        assert ev["success"] is True
        assert ev["cross_link"] is not None
        assert ev["cross_link"]["type"] == "nfc_uid"

    def test_audit_event_records_failure_when_solver_missing(self, storage, monkeypatch):
        monkeypatch.setenv("PATH", "")
        with pytest.raises(SolverBinaryMissing):
            asyncio.run(mission_nfc_mfkey32(log_text=self._LOG_TWO_PAIRS))
        events = list(storage.iter_events())
        assert len(events) == 1
        assert events[0]["success"] is False
        assert "mfkey32" in (events[0]["error"]["message"] or "").lower()

    def test_multiple_cuids_warning_path(self, storage, fake_solver):
        log = (
            "Sec 1 key A cuid aaaaaaaa nt 22222222 nr 33333333 ar 44444444 at 55555555\n"
            "Sec 1 key A cuid aaaaaaaa nt 66666666 nr 77777777 ar 88888888 at 99999999\n"
            "Sec 2 key A cuid bbbbbbbb nt 22222222 nr 33333333 ar 44444444 at 55555555\n"
            "Sec 2 key A cuid bbbbbbbb nt 66666666 nr 77777777 ar 88888888 at 99999999\n"
        )
        result = asyncio.run(mission_nfc_mfkey32(log_text=log))
        # First CUID alphabetically sorted is 'aaaaaaaa'
        assert result["outputs"]["cuid"] == "aaaaaaaa"
        assert result["outputs"]["all_cuids"] == ["aaaaaaaa", "bbbbbbbb"]
