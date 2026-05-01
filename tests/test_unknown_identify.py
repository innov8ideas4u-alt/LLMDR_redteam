"""Tests for mission_unknown_identify (triage sweep).

Uses StubBackends so no hardware is needed. Validates:
  - sweep order
  - winner selection across multiple positives
  - cross_link populated from positive sensor
  - next-action suggestions match tentative_id
  - "nothing detected" path
  - "fast" profile skips IR + SubGHz
  - decorator integration: event written, success=True, inputs captured
"""

import pytest

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.missions import mission_unknown_identify
from llmdr_redteam.missions.sensor_backends import (
    StubBackend,
    stub_nfc_negative, stub_nfc_ultralight, stub_nfc_classic_1k,
    stub_rfid_negative, stub_rfid_em4100,
    stub_ibutton_negative,
    stub_ir_passive_silent,
    stub_subghz_passive_silent, stub_subghz_signal,
)


@pytest.fixture
def storage():
    s = InMemoryStorage()
    set_storage(s)
    reset_session_id("triage-test-session")
    yield s
    set_storage(None)


def _backends_with(**overrides):
    """Build a backend map starting from all-negative, with overrides."""
    base = {
        "nfc":     StubBackend("nfc",     stub_nfc_negative()),
        "rfid":    StubBackend("rfid",    stub_rfid_negative()),
        "ibutton": StubBackend("ibutton", stub_ibutton_negative()),
        "ir":      StubBackend("ir",      stub_ir_passive_silent()),
        "subghz":  StubBackend("subghz",  stub_subghz_passive_silent()),
    }
    base.update(overrides)
    return base


# ---------- happy paths --------------------------------------------------

async def test_nothing_detected_anywhere(storage):
    """All sensors clean — winner=None, no cross_link, no suggestions."""
    result = await mission_unknown_identify(backends=_backends_with())
    out = result["outputs"]
    assert out["best_match"] is None
    assert out["next_action_suggestions"] == []
    assert len(out["detections"]) == 5
    assert all(d["detected"] is False for d in out["detections"])

    # Decorator wrote one event with no cross_link
    ev = list(storage.iter_events())[0]
    assert ev["cross_link"] is None
    assert ev["success"] is True


async def test_nfc_ultralight_detected(storage):
    backends = _backends_with(
        nfc=StubBackend("nfc", stub_nfc_ultralight("04:A2:1B:5C:DE:AD:BE")),
    )
    result = await mission_unknown_identify(backends=backends)
    out = result["outputs"]
    assert out["best_match"] == "mifare_ultralight_or_ntag21x"
    assert "nfc_capture" in out["next_action_suggestions"]
    assert "nfc_clone" in out["next_action_suggestions"]

    # Cross-link populated AND canonicalized in the audit event
    ev = list(storage.iter_events())[0]
    assert ev["cross_link"] is not None
    assert ev["cross_link"]["type"] == "nfc_uid"
    # 7-byte UID, separators stripped, lowercased
    assert ev["cross_link"]["value"] == "04a21b5cdeadbe"


async def test_classic_suggests_mfkey32(storage):
    backends = _backends_with(nfc=StubBackend("nfc", stub_nfc_classic_1k()))
    result = await mission_unknown_identify(backends=backends)
    suggestions = result["outputs"]["next_action_suggestions"]
    assert "nfc_mfkey32" in suggestions, (
        "Classic 1K should always suggest mfkey32 since CRYPTO1 is broken"
    )


async def test_rfid_detected(storage):
    backends = _backends_with(rfid=StubBackend("rfid", stub_rfid_em4100("DE:AD:BE:EF:01")))
    result = await mission_unknown_identify(backends=backends)
    out = result["outputs"]
    assert out["best_match"] == "em4100"

    ev = list(storage.iter_events())[0]
    assert ev["cross_link"]["type"] == "rfid_em4100"
    assert ev["cross_link"]["value"] == "deadbeef01"


async def test_subghz_detected(storage):
    backends = _backends_with(
        subghz=StubBackend("subghz", stub_subghz_signal(433920000, "AM650", "Princeton")),
    )
    result = await mission_unknown_identify(backends=backends)
    out = result["outputs"]
    assert out["best_match"] == "Princeton_433MHz"

    ev = list(storage.iter_events())[0]
    assert ev["cross_link"]["type"] == "subghz_signal"
    assert ev["cross_link"]["value"] == "433920000:AM650:Princeton"


# ---------- winner selection across multiple positives ------------------

async def test_nfc_wins_over_subghz(storage):
    """When both NFC and SubGHz fire, NFC takes priority (deterministic > passive)."""
    backends = _backends_with(
        nfc=StubBackend("nfc", stub_nfc_ultralight("04:00:00:01")),
        subghz=StubBackend("subghz", stub_subghz_signal()),
    )
    result = await mission_unknown_identify(backends=backends)
    assert result["outputs"]["best_match"] == "mifare_ultralight_or_ntag21x"
    assert result["cross_link"][0] == "nfc_uid"


async def test_all_detections_recorded_even_when_winner_is_set(storage):
    """Even though NFC wins, the SubGHz detection is still in the list."""
    backends = _backends_with(
        nfc=StubBackend("nfc", stub_nfc_ultralight()),
        subghz=StubBackend("subghz", stub_subghz_signal()),
    )
    result = await mission_unknown_identify(backends=backends)
    detections = result["outputs"]["detections"]
    detected_sensors = [d["sensor"] for d in detections if d["detected"]]
    assert "nfc" in detected_sensors
    assert "subghz" in detected_sensors


# ---------- profile=fast skips passive listens --------------------------

async def test_fast_profile_skips_ir_and_subghz(storage):
    """Fast profile: only NFC, RFID, iButton. ~3s instead of ~11s in production."""
    result = await mission_unknown_identify(
        backends=_backends_with(),
        profile="fast",
    )
    sensors = [d["sensor"] for d in result["outputs"]["detections"]]
    assert sensors == ["nfc", "rfid", "ibutton"]
    assert result["outputs"]["profile"] == "fast"


async def test_full_profile_includes_all_five(storage):
    result = await mission_unknown_identify(
        backends=_backends_with(),
        profile="full",
    )
    sensors = [d["sensor"] for d in result["outputs"]["detections"]]
    assert sensors == ["nfc", "rfid", "ibutton", "ir", "subghz"]


# ---------- error path --------------------------------------------------

class _BrokenBackend:
    sensor_name = "nfc"
    async def scan(self):
        raise RuntimeError("simulated sensor explosion")


async def test_backend_failure_recorded_as_low_confidence(storage):
    """A backend that raises shouldn't crash the mission — its detection
    just gets recorded as low-confidence with the error in notes."""
    backends = _backends_with(nfc=_BrokenBackend())
    result = await mission_unknown_identify(backends=backends)
    nfc_det = next(d for d in result["outputs"]["detections"] if d["sensor"] == "nfc")
    assert nfc_det["detected"] is False
    assert nfc_det["confidence"] == "low"
    assert "simulated sensor explosion" in nfc_det["notes"]

    # Mission overall still succeeded
    ev = list(storage.iter_events())[0]
    assert ev["success"] is True


# ---------- decorator integration ---------------------------------------

async def test_audit_event_captures_mission_metadata(storage):
    await mission_unknown_identify(backends=_backends_with(), profile="full")
    ev = list(storage.iter_events())[0]
    assert ev["mission_name"] == "unknown_identify"
    assert ev["mission_version"] == "0.1.0"
    assert ev["session_id"] == "triage-test-session"
    assert ev["inputs"]["profile"] == "full"
    # backends parameter is non-trivial; the decorator stringifies it. Just
    # confirm it's captured at all.
    assert "backends" in ev["inputs"]


async def test_business_context_works_on_triage(storage):
    """A volunteer might triage a found card and tag it 'lost_and_found'."""
    await mission_unknown_identify(
        backends=_backends_with(nfc=StubBackend("nfc", stub_nfc_ultralight())),
        business_context={
            "domain": "edge",
            "action": "fob_used",
            "member_id": "unknown_lost_and_found",
            "reason": "card found in wood shop, triaging before adding to lost-bin",
        },
        operator_note="found this on the workbench - figuring out who it belongs to",
    )
    ev = list(storage.iter_events())[0]
    assert ev["business_context"]["domain"] == "edge"
    assert ev["operator_note"].startswith("found this")
