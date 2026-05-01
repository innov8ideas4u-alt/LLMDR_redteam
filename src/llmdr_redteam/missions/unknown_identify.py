"""mission_unknown_identify — the triage sweep.

Plain English: hold something near the Kiisu, fire this mission, get back a
combined report from every sensor. The killer feature for non-experts —
they don't have to know whether they're holding NFC, RFID, or a SubGHz fob.

Sequence (Day 3, stub backends, ~total 0s test mode):
  1. NFC (active scan)        — 1s in production
  2. RFID 125 kHz (active)    — 1s
  3. iButton 1-wire (active)  — 1s
  4. IR (passive listen)      — 3s
  5. SubGHz sweep (passive)   — 5s

Total ~11s in production. Stubs run instantly.

Output shape (the decorator captures all of this):
  outputs = {
    "detections": [Detection.to_dict(), ...],
    "best_match": "<tentative_id from highest-priority positive sensor>" or None,
    "next_action_suggestions": ["nfc_capture", "nfc_clone", ...],
  }
  cross_link = (link_type, raw_id) from the highest-priority positive sensor
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional, Sequence

from ..audit import audit_logged, status_emit
from .sensor_backends import (
    Detection,
    SensorBackend,
    StubBackend,
    stub_nfc_negative,
    stub_rfid_negative,
    stub_ibutton_negative,
    stub_ir_passive_silent,
    stub_subghz_passive_silent,
)

log = logging.getLogger("llmdr_redteam.missions.unknown_identify")


# ---------- sensor priority for "best_match" + cross_link selection -----
# When multiple sensors return positives, we pick the highest-priority one
# for the cross_link and best_match fields. Lower number = higher priority.

_SENSOR_PRIORITY = {
    "nfc":     1,   # near-field, deterministic, most info-rich
    "rfid":    2,   # near-field, deterministic
    "ibutton": 3,   # near-field, deterministic
    "subghz":  4,   # passive, less reliable
    "ir":      5,   # passive, low info
}


# ---------- next-action mapping -----------------------------------------
# Given a tentative_id, what missions might the operator want to run next?

_NEXT_ACTIONS: dict[str, list[str]] = {
    "mifare_ultralight_or_ntag21x": ["nfc_capture", "nfc_clone"],
    "mifare_classic_1k":            ["nfc_capture", "nfc_mfkey32", "nfc_clone"],
    "mifare_classic_4k":            ["nfc_capture", "nfc_mfkey32", "nfc_clone"],
    "mifare_desfire":               ["nfc_capture"],   # cloning impractical
    "em4100":                       ["rfid_capture", "rfid_clone"],
    "hid_prox":                     ["rfid_capture", "rfid_clone", "rfid_brute"],
    "ibutton_dallas":               ["ibutton_capture", "ibutton_clone"],
}


def _suggest_next(detection: Detection) -> list[str]:
    if not detection.detected or not detection.tentative_id:
        return []
    return _NEXT_ACTIONS.get(detection.tentative_id, [])


def _pick_winner(detections: list[Detection]) -> Optional[Detection]:
    """From the positive detections, pick the one with highest sensor priority."""
    positives = [d for d in detections if d.detected]
    if not positives:
        return None
    positives.sort(key=lambda d: _SENSOR_PRIORITY.get(d.sensor, 99))
    return positives[0]


# ---------- the default sweep order -------------------------------------

_DEFAULT_SWEEP = ("nfc", "rfid", "ibutton", "ir", "subghz")
_FAST_SWEEP = ("nfc", "rfid", "ibutton")  # skips passive listens


def make_default_stub_backends() -> dict[str, SensorBackend]:
    """All-negative stub backends — useful for the 'nothing detected' test."""
    return {
        "nfc":     StubBackend("nfc", stub_nfc_negative()),
        "rfid":    StubBackend("rfid", stub_rfid_negative()),
        "ibutton": StubBackend("ibutton", stub_ibutton_negative()),
        "ir":      StubBackend("ir", stub_ir_passive_silent()),
        "subghz":  StubBackend("subghz", stub_subghz_passive_silent()),
    }


# ---------- the mission -------------------------------------------------

@audit_logged(mission_name="unknown_identify", mission_version="0.1.0")
async def mission_unknown_identify(
    *,
    backends: Optional[dict[str, SensorBackend]] = None,
    profile: str = "full",
    audit_event_id: str = "",  # injected by decorator
    **_kwargs: Any,
) -> dict[str, Any]:
    """Sweep all available sensors, return a combined detection report.

    Args:
        backends:  Map of sensor_name -> SensorBackend. If None, all-negative
                   stubs are used (for first-run pipeline proof). Production
                   wires real RPC/JS backends here.
        profile:   'full' (all 5 sensors) or 'fast' (skip IR + SubGHz).
        audit_event_id: Injected by decorator. Used for status_emit.

    Returns:
        Dict with 'outputs' and 'cross_link' for the decorator to capture.
    """
    if backends is None:
        backends = make_default_stub_backends()

    sweep_order = _FAST_SWEEP if profile == "fast" else _DEFAULT_SWEEP

    status_emit(audit_event_id, "triage: starting", stage="start", profile=profile)

    detections: list[Detection] = []
    for sensor_name in sweep_order:
        backend = backends.get(sensor_name)
        if backend is None:
            log.warning("no backend for sensor %r — skipping", sensor_name)
            continue

        status_emit(audit_event_id, f"triage: scanning {sensor_name}",
                    stage=f"scan_{sensor_name}")
        try:
            det = await backend.scan()
        except Exception as e:
            log.exception("backend %r raised — recording as low-confidence", sensor_name)
            det = Detection(
                sensor=sensor_name, detected=False, confidence="low",
                notes=f"backend error: {type(e).__name__}: {e}",
            )
        detections.append(det)

        if det.detected:
            status_emit(audit_event_id, f"triage: {sensor_name} hit: {det.tentative_id}",
                        sensor=sensor_name, tentative_id=det.tentative_id)
        else:
            status_emit(audit_event_id, f"triage: {sensor_name} clear",
                        sensor=sensor_name)

    winner = _pick_winner(detections)

    status_emit(audit_event_id, "triage: done",
                stage="done",
                positives=sum(1 for d in detections if d.detected),
                winner=(winner.tentative_id if winner else None))

    outputs: dict[str, Any] = {
        "detections": [d.to_dict() for d in detections],
        "best_match": winner.tentative_id if winner else None,
        "next_action_suggestions": _suggest_next(winner) if winner else [],
        "profile": profile,
    }

    result: dict[str, Any] = {"outputs": outputs}
    if winner is not None and winner.cross_link is not None:
        result["cross_link"] = winner.cross_link

    return result
