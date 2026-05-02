"""Tests for rfid_backend (parser + RealRFIDBackend) and mission_rfid_capture.

NO LIVE HARDWARE. The RealRFIDBackend code path is exercised through a
_FakeFlipper that mimics storage.list / storage.read / rpc.app_start.

Marker: TODO_HARDWARE_VALIDATE_RFID — when test tags arrive, run
mission_rfid_capture against an actual EM4100 and confirm Detection
shape matches what these tests assert.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import pytest

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.missions import mission_rfid_capture
from llmdr_redteam.missions.rfid_backend import (
    RFIDParseError,
    RealRFIDBackend,
    StubRFIDBackend,
    parse_rfid_file,
    stub_rfid_em4100_canned,
    stub_rfid_hid_prox_canned,
)
from llmdr_redteam.missions.sensor_backends import Detection


# ---------- parser tests ------------------------------------------------

class TestRFIDParser:
    """parse_rfid_file: shape, key_type recognition, security score lookup."""

    def test_em4100_typical(self):
        text = (
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: EM4100\n"
            "Data: 12 34 56 78 9A\n"
        )
        card = parse_rfid_file(text)
        assert card.key_type == "EM4100"
        assert card.data_hex == "12 34 56 78 9A"
        assert card.tentative_id == "em4100"
        assert card.security_score == 1
        assert card.normalized_id == "123456789a"
        assert card.file_format_version == "1"

    def test_hid_prox_h10301(self):
        text = (
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: H10301\n"
            "Data: 02 00 12 34 56\n"
        )
        card = parse_rfid_file(text)
        assert card.tentative_id == "hid_prox"
        assert card.security_score == 1
        assert card.normalized_id == "0200123456"

    def test_indala(self):
        text = (
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: Indala26\n"
            "Data: AB CD EF\n"
        )
        card = parse_rfid_file(text)
        assert card.tentative_id == "indala"
        assert card.security_score == 2

    def test_t5577_raw(self):
        text = (
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: T5577\n"
            "Data: DE AD BE EF\n"
        )
        card = parse_rfid_file(text)
        assert card.tentative_id == "t5577_raw"

    def test_unknown_key_type_passes_through(self):
        """Unrecognized families parse but get tentative_id=None — interpreter
        flags as unfamiliar."""
        text = (
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: WeirdNewProtocol\n"
            "Data: 11 22 33\n"
        )
        card = parse_rfid_file(text)
        assert card.key_type == "WeirdNewProtocol"
        assert card.tentative_id is None
        assert card.security_score is None
        # data_hex still populated so cross-link can still fire
        assert card.normalized_id == "112233"

    def test_extras_captured(self):
        text = (
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: EM4100\n"
            "Data: 01 02 03 04 05\n"
            "Custom Field: arbitrary value\n"
        )
        card = parse_rfid_file(text)
        assert card.extras.get("custom field") == "arbitrary value"

    def test_missing_filetype_raises(self):
        with pytest.raises(RFIDParseError, match="Filetype"):
            parse_rfid_file("Key type: EM4100\nData: 11 22 33\n")

    def test_missing_key_type_raises(self):
        with pytest.raises(RFIDParseError, match="Key type"):
            parse_rfid_file(
                "Filetype: Flipper RFID key\nVersion: 1\nData: 11 22 33\n"
            )

    def test_missing_data_raises(self):
        with pytest.raises(RFIDParseError, match="Data"):
            parse_rfid_file(
                "Filetype: Flipper RFID key\nVersion: 1\nKey type: EM4100\n"
            )

    def test_wrong_filetype_raises(self):
        with pytest.raises(RFIDParseError, match="doesn't look like"):
            parse_rfid_file(
                "Filetype: Flipper SubGHz Raw File\nVersion: 1\n"
                "Key type: EM4100\nData: 11 22 33\n"
            )

    def test_comments_and_blanks_skipped(self):
        text = (
            "# captured at parking lot\n"
            "\n"
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "  \n"
            "Key type: EM4100\n"
            "Data: AA BB CC DD EE\n"
        )
        card = parse_rfid_file(text)
        assert card.tentative_id == "em4100"


# ---------- RealRFIDBackend with FakeFlipper ----------------------------

@dataclass
class _FakeRPC:
    app_start_responses: dict[str, bool] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    default_response: bool = True

    async def app_start(self, name: str, args: str) -> bool:
        self.calls.append((name, args))
        return self.app_start_responses.get(name, self.default_response)


@dataclass
class _FakeStorageEntry:
    name: str
    is_dir: bool = False


@dataclass
class _FakeStorage:
    files: dict[str, str] = field(default_factory=dict)
    listings: dict[str, list[_FakeStorageEntry]] = field(default_factory=dict)

    async def list(self, path: str):
        return self.listings.get(path, [])

    async def read(self, path: str) -> str:
        if path not in self.files:
            raise FileNotFoundError(path)
        return self.files[path]


@dataclass
class _FakeFlipper:
    rpc: _FakeRPC = field(default_factory=_FakeRPC)
    storage: _FakeStorage = field(default_factory=_FakeStorage)


class TestRealBackend:
    """Drive the real backend via _FakeFlipper. No hardware."""

    def _add_capture_after_listing(
        self, flipper: _FakeFlipper, filename: str, content: str,
    ):
        """Helper: configure storage.list to return [] first, then the file
        on the second call. Simulates 'before' vs 'after' the operator
        tapped the card."""
        # Before-state: empty
        flipper.storage.listings["/ext/lfrfid"] = []

        # Patch list() to flip after the first call
        original_list = flipper.storage.list
        call_count = {"n": 0}

        async def patched_list(path: str):
            call_count["n"] += 1
            if call_count["n"] >= 2 and path == "/ext/lfrfid":
                return [_FakeStorageEntry(name=filename)]
            return await original_list(path)

        flipper.storage.list = patched_list  # type: ignore
        flipper.storage.files[f"/ext/lfrfid/{filename}"] = content

    def test_successful_em4100_capture(self):
        flipper = _FakeFlipper()
        backend = RealRFIDBackend(
            flipper=flipper, timeout_s=2.0, poll_interval_s=0.05,
        )
        self._add_capture_after_listing(
            flipper, "test.rfid",
            "Filetype: Flipper RFID key\n"
            "Version: 1\n"
            "Key type: EM4100\n"
            "Data: 12 34 56 78 9A\n",
        )
        det = asyncio.run(backend.scan())
        assert det.detected is True
        assert det.tentative_id == "em4100"
        assert det.cross_link == ("rfid_em4100", "123456789a")
        assert det.raw["security_score"] == 1
        assert det.raw["key_type"] == "EM4100"

    def test_no_card_tap_times_out(self):
        flipper = _FakeFlipper()
        flipper.storage.listings["/ext/lfrfid"] = []
        backend = RealRFIDBackend(
            flipper=flipper, timeout_s=0.3, poll_interval_s=0.05,
        )
        det = asyncio.run(backend.scan())
        assert det.detected is False
        assert det.confidence == "medium"
        assert "wrong face" in det.notes.lower() or "no new" in det.notes.lower()

    def test_no_flipper_returns_low_confidence(self):
        backend = RealRFIDBackend(flipper=None)
        det = asyncio.run(backend.scan())
        assert det.detected is False
        assert det.confidence == "low"
        assert "rpc" in det.notes.lower()

    def test_malformed_file_returns_low_confidence(self):
        flipper = _FakeFlipper()
        backend = RealRFIDBackend(
            flipper=flipper, timeout_s=2.0, poll_interval_s=0.05,
        )
        self._add_capture_after_listing(
            flipper, "broken.rfid",
            "this is not a valid rfid file\nat all\n",
        )
        det = asyncio.run(backend.scan())
        assert det.detected is False
        assert det.confidence == "low"
        assert "format" in det.notes.lower()

    def test_app_start_tries_multiple_names(self):
        flipper = _FakeFlipper()
        flipper.rpc.default_response = False  # all candidate names fail
        flipper.rpc.app_start_responses["lfrfid.fap"] = True  # except this one
        flipper.storage.listings["/ext/lfrfid"] = []
        backend = RealRFIDBackend(
            flipper=flipper, timeout_s=0.2, poll_interval_s=0.05,
        )
        # We don't care about detection — we want to verify all candidates were tried
        asyncio.run(backend.scan())
        called_names = {name for name, _ in flipper.rpc.calls}
        # First three should have been tried before lfrfid.fap succeeded
        assert "125 kHz RFID" in called_names
        assert "lfrfid.fap" in called_names


# ---------- Stub helpers + Mission integration -------------------------

@pytest.fixture
def storage():
    s = InMemoryStorage()
    set_storage(s)
    reset_session_id("rfid-test-session")
    yield s
    set_storage(None)


class TestStubHelpers:
    """The canned stub Detections for test fixtures."""

    def test_em4100_canned_shape(self):
        det = stub_rfid_em4100_canned("0123456789")
        assert det.detected is True
        assert det.tentative_id == "em4100"
        assert det.cross_link == ("rfid_em4100", "0123456789")
        assert det.raw["security_score"] == 1

    def test_hid_prox_canned_shape(self):
        det = stub_rfid_hid_prox_canned("0200123456")
        assert det.detected is True
        assert det.tentative_id == "hid_prox"
        assert det.cross_link == ("rfid_hid_prox", "0200123456")


class TestMissionIntegration:
    def test_em4100_capture_writes_audit_event(self, storage):
        stub = StubRFIDBackend(canned=stub_rfid_em4100_canned("0123456789"))
        result = asyncio.run(mission_rfid_capture(backend=stub))
        assert result["outputs"]["detected"] is True
        assert result["outputs"]["tentative_id"] == "em4100"
        assert result["outputs"]["security_score"] == 1
        assert result.get("cross_link") == ("rfid_em4100", "0123456789")

        events = list(storage.iter_events())
        assert len(events) == 1
        ev = events[0]
        assert ev["mission_name"] == "rfid_capture"
        assert ev["success"] is True
        assert ev["cross_link"]["type"] == "rfid_em4100"
        assert ev["cross_link"]["value"] == "0123456789"

    def test_no_card_no_cross_link(self, storage):
        stub = StubRFIDBackend(canned=Detection(
            sensor="rfid", detected=False, confidence="medium",
            notes="no card tapped",
        ))
        result = asyncio.run(mission_rfid_capture(backend=stub))
        assert result["outputs"]["detected"] is False
        assert "cross_link" not in result
        events = list(storage.iter_events())
        assert events[0]["success"] is True  # mission completed cleanly
        assert events[0]["cross_link"] is None

    def test_missing_backend_raises(self, storage):
        with pytest.raises(ValueError, match="backend"):
            asyncio.run(mission_rfid_capture())

    def test_hid_prox_classified_as_low_security(self, storage):
        stub = StubRFIDBackend(canned=stub_rfid_hid_prox_canned("0200123456"))
        result = asyncio.run(mission_rfid_capture(backend=stub))
        assert result["outputs"]["tentative_id"] == "hid_prox"
        assert result["outputs"]["security_score"] == 1
