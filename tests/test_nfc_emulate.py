"""Tests for mission_nfc_emulate (Kiisu pretends to be a captured card).

Test strategy:
  - StubNFCEmulateBackend with canned logs validates parser branches.
  - A FakeFlipper class exercises the RealNFCEmulateBackend's I/O hooks
    without any real hardware.
  - Mission-level integration tests verify the audit log writes correctly.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.missions import mission_nfc_emulate
from llmdr_redteam.missions.nfc_emulate_backend import (
    CANNED_LOG_EMPTY,
    CANNED_LOG_PARSE_FAIL,
    CANNED_LOG_STOPPED_EARLY,
    CANNED_LOG_SUCCESS,
    EmulateRequest,
    RealNFCEmulateBackend,
    StubNFCEmulateBackend,
)


# ---------- storage fixture ---------------------------------------------

@pytest.fixture
def storage():
    s = InMemoryStorage()
    set_storage(s)
    reset_session_id("emulate-test-session")
    yield s
    set_storage(None)


# ---------- StubNFCEmulateBackend tests ---------------------------------

class TestStubBackendParser:
    """The stub uses RealNFCEmulateBackend's parser internally — these
    tests cover both stub usage and the parser branches simultaneously."""

    def _run(self, canned_log: str, source_path: str = "/ext/nfc/test.nfc",
             duration: float = 30.0):
        stub = StubNFCEmulateBackend(canned_log=canned_log)
        return asyncio.run(stub.emulate(EmulateRequest(
            source_path=source_path, duration_s=duration,
        )))

    def test_clean_success(self):
        det = self._run(CANNED_LOG_SUCCESS)
        assert det.detected is True
        assert det.confidence == "high"
        assert det.tentative_id == "emulation_completed"
        assert det.cross_link == ("nfc_uid", "04abcdef120000")
        assert det.raw["completion"] == "done"
        assert det.raw["emulated_uid"] == "04abcdef120000"

    def test_stopped_early_still_success(self):
        det = self._run(CANNED_LOG_STOPPED_EARLY)
        assert det.detected is True
        assert det.raw["completion"] == "stopped"
        assert "Stopped early" in det.notes

    def test_parse_fail_in_js(self):
        det = self._run(CANNED_LOG_PARSE_FAIL)
        assert det.detected is False
        assert det.confidence == "medium"
        # The error path may or may not extract a UID — we don't promise
        # one when [parsed] never fired.
        assert "[error]" in det.notes or "error" in det.notes.lower()

    def test_empty_log_signals_firmware_problem(self):
        det = self._run(CANNED_LOG_EMPTY)
        assert det.detected is False
        assert det.confidence == "low"
        assert "firmware" in det.notes.lower() or "module" in det.notes.lower()

    def test_started_but_never_finished(self):
        # [start] but no [parsed] or [done] — partial run, mid-script
        # firmware crash, etc.
        log = "[start] source=x duration_ms=30000\n[exit]\n"
        det = self._run(log)
        assert det.detected is False
        assert det.confidence == "low"

    def test_request_recorded_for_assertion(self):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        asyncio.run(stub.emulate(EmulateRequest(
            source_path="/ext/nfc/foo.nfc", duration_s=15.0,
        )))
        assert len(stub.received_requests) == 1
        assert stub.received_requests[0].source_path == "/ext/nfc/foo.nfc"
        assert stub.received_requests[0].duration_s == 15.0


# ---------- RealNFCEmulateBackend with FakeFlipper -----------------------
# We don't import flipper-mcp here — the backend duck-types its handle.

@dataclass
class _FakeJS:
    pushed: list[tuple[str, str]] = field(default_factory=list)
    runs:   list[str] = field(default_factory=list)
    push_returns: bool = True
    # When run() is called, the JS would write to this log. We simulate
    # that by storing the canned content here and having a callback
    # populate the storage. _FakeFlipper wires it up.
    canned_log: str = ""
    storage_ref: Any = None  # set by _FakeFlipper.__post_init__
    log_path: str = "/ext/apps_data/mcp_logs/mcp_nfc_emulate.log"

    async def push(self, name: str, content: str) -> bool:
        self.pushed.append((name, content))
        return self.push_returns

    async def run(self, name: str) -> None:
        self.runs.append(name)
        # Simulate the JS mission writing its log file
        if self.storage_ref is not None and self.canned_log:
            self.storage_ref.files[self.log_path] = self.canned_log


@dataclass
class _FakeStorage:
    files: dict[str, str] = field(default_factory=dict)
    deletes: list[str] = field(default_factory=list)

    async def read(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]

    async def delete(self, path: str) -> None:
        self.deletes.append(path)
        self.files.pop(path, None)


@dataclass
class _FakeFlipper:
    js: _FakeJS = field(default_factory=_FakeJS)
    storage: _FakeStorage = field(default_factory=_FakeStorage)

    def __post_init__(self):
        self.js.storage_ref = self.storage


class TestRealBackendIO:
    """Exercise the push → run → readback orchestration without hardware."""

    def _make_backend(self, log_text: str):
        flipper = _FakeFlipper()
        # Tell the fake JS what to write when run() is called
        flipper.js.canned_log = log_text
        # Tiny grace so tests run fast
        backend = RealNFCEmulateBackend(flipper=flipper, startup_grace_s=0.0)
        return backend, flipper

    def test_push_run_read_full_cycle(self):
        backend, flipper = self._make_backend(CANNED_LOG_SUCCESS)
        det = asyncio.run(backend.emulate(EmulateRequest(
            source_path="/ext/nfc/keycard.nfc", duration_s=0.0,
        )))
        # JS pushed exactly once
        assert len(flipper.js.pushed) == 1
        name, content = flipper.js.pushed[0]
        assert name == "mcp_nfc_emulate"
        # Substitutions applied to the JS body
        assert "/ext/nfc/keycard.nfc" in content
        assert "duration_ms=0" in content or "DURATION_MS = 0" in content
        # JS launched once with the same name
        assert flipper.js.runs == ["mcp_nfc_emulate"]
        # Detection reflects log
        assert det.detected is True
        assert det.cross_link == ("nfc_uid", "04abcdef120000")

    def test_log_cleared_before_run(self):
        backend, flipper = self._make_backend(CANNED_LOG_SUCCESS)
        # Pre-existing log should get deleted before mission run
        # (already exists from _make_backend setup, then read after run)
        asyncio.run(backend.emulate(EmulateRequest(
            source_path="/ext/nfc/x.nfc", duration_s=0.0,
        )))
        assert "/ext/apps_data/mcp_logs/mcp_nfc_emulate.log" in flipper.storage.deletes

    def test_push_failure_returns_low_confidence_detection(self):
        backend, flipper = self._make_backend(CANNED_LOG_SUCCESS)
        flipper.js.push_returns = False  # simulate push refusal
        det = asyncio.run(backend.emulate(EmulateRequest(
            source_path="/ext/nfc/x.nfc", duration_s=0.0,
        )))
        assert det.detected is False
        assert det.confidence == "low"
        assert "push" in det.notes.lower()
        # JS never launched if push failed
        assert flipper.js.runs == []

    def test_no_flipper_handle_returns_low_confidence(self):
        backend = RealNFCEmulateBackend(flipper=None)
        det = asyncio.run(backend.emulate(EmulateRequest(
            source_path="/ext/nfc/x.nfc", duration_s=0.0,
        )))
        assert det.detected is False
        assert "no rpc" in det.notes.lower() or "not connected" in det.notes.lower()

    def test_empty_log_after_run_signals_firmware(self):
        backend, flipper = self._make_backend(CANNED_LOG_EMPTY)
        det = asyncio.run(backend.emulate(EmulateRequest(
            source_path="/ext/nfc/x.nfc", duration_s=0.0,
        )))
        assert det.detected is False
        assert "firmware" in det.notes.lower() or "module" in det.notes.lower()

    def test_duration_clamped_at_render_time(self):
        # The backend itself doesn't clamp — the mission does. So the JS
        # should reflect whatever the request held.
        backend, flipper = self._make_backend(CANNED_LOG_SUCCESS)
        asyncio.run(backend.emulate(EmulateRequest(
            source_path="/ext/nfc/x.nfc", duration_s=2.5,
        )))
        _, content = flipper.js.pushed[0]
        # 2.5s = 2500ms
        assert "2500" in content


# ---------- Mission integration tests -----------------------------------

class TestMissionIntegration:
    """End-to-end via the @audit_logged decorator path."""

    def test_success_writes_audit_event_with_cross_link(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        result = asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/sandman_room205.nfc",
            duration_s=5.0,
            backend=stub,
        ))
        assert result["outputs"]["detected"] is True
        assert result["outputs"]["emulated_uid"] == "04abcdef120000"
        assert result["outputs"]["completion"] == "done"
        assert result.get("cross_link") == ("nfc_uid", "04abcdef120000")

        events = list(storage.iter_events())
        assert len(events) == 1
        ev = events[0]
        assert ev["mission_name"] == "nfc_emulate"
        assert ev["success"] is True
        assert ev["cross_link"]["type"] == "nfc_uid"
        assert ev["cross_link"]["value"] == "04abcdef120000"

    def test_failure_no_cross_link(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_PARSE_FAIL)
        result = asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/missing.nfc",
            duration_s=5.0,
            backend=stub,
        ))
        assert result["outputs"]["detected"] is False
        assert "cross_link" not in result

        events = list(storage.iter_events())
        assert len(events) == 1
        # Mission completed without raising — success=True from the
        # decorator's POV. The Detection.detected=False is the signal.
        assert events[0]["success"] is True

    def test_missing_source_path_raises(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        with pytest.raises(ValueError, match="source_path"):
            asyncio.run(mission_nfc_emulate(
                source_path="", duration_s=5.0, backend=stub,
            ))

    def test_missing_backend_raises(self, storage):
        with pytest.raises(ValueError, match="backend"):
            asyncio.run(mission_nfc_emulate(
                source_path="/ext/nfc/x.nfc", duration_s=5.0,
            ))

    def test_duration_clamped_to_one_second_minimum(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        result = asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/x.nfc",
            duration_s=0.001,  # under minimum
            backend=stub,
        ))
        assert result["outputs"]["duration_s"] == 1.0

    def test_duration_clamped_to_three_hundred_max(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        result = asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/x.nfc",
            duration_s=999.0,  # over maximum
            backend=stub,
        ))
        assert result["outputs"]["duration_s"] == 300.0

    def test_inputs_captured_in_audit_event(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/keycard.nfc",
            duration_s=10.0,
            backend=stub,
        ))
        ev = list(storage.iter_events())[0]
        assert ev["inputs"]["source_path"] == "/ext/nfc/keycard.nfc"
        assert ev["inputs"]["duration_s"] == 10.0
        # Backend is a runtime object; decorator should NOT serialize it
        # blindly — but if it does, it should be skipped or stringified.
        # We don't enforce a specific behavior, just that the test runs.

    def test_log_tail_in_outputs(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_SUCCESS)
        result = asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/x.nfc",
            duration_s=5.0,
            backend=stub,
        ))
        tail = result["outputs"]["log_tail"]
        assert isinstance(tail, list)
        assert any("[done]" in ln or "[parsed]" in ln for ln in tail)

    def test_stopped_early_still_marks_detected(self, storage):
        stub = StubNFCEmulateBackend(canned_log=CANNED_LOG_STOPPED_EARLY)
        result = asyncio.run(mission_nfc_emulate(
            source_path="/ext/nfc/x.nfc",
            duration_s=5.0,
            backend=stub,
        ))
        assert result["outputs"]["detected"] is True
        assert result["outputs"]["completion"] == "stopped"
        assert result.get("cross_link") == ("nfc_uid", "04abcdef120000")
