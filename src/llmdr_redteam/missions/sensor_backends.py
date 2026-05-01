"""Sensor backends for the triage mission.

Plain English: each sensor (NFC, RFID, iButton, IR, SubGHz) has a "backend"
that knows how to scan that sensor and return a Detection. The triage mission
calls each backend in sequence. Backends are pluggable so tests can use stubs
that return canned data, while production uses real RPC backends that drive
the Kiisu.

For Day 3 we ship:
  - The Backend protocol + Detection record
  - StubBackend (returns whatever you tell it to — for tests + first run)
  - StubFactory (groups stub backends for the full sweep)

Day 4+ adds:
  - JSBackend (pushes a JS scanner script to the Kiisu, reads result file)
  - RPCBackend (uses native protobuf RPC where available — e.g. NFC has
    direct RPC primitives in some firmware builds)

The triage mission code doesn't care which backend it gets. That's the point.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol


# ---------- the result type a backend returns ---------------------------

@dataclass
class Detection:
    """One sensor's report for one triage sweep.

    Fields:
        sensor:        'nfc' | 'rfid' | 'ibutton' | 'ir' | 'subghz'
        detected:      True if something was found, False if clean / silent
        confidence:    'high' | 'medium' | 'low'
                       - 'high' for active scans that completed cleanly
                       - 'medium' for passive listens (IR, SubGHz) that found
                         nothing — empty doesn't prove absence
                       - 'low' for ambiguous results
        raw:           Sensor-specific data — UID, ATQA/SAK for NFC, etc.
        tentative_id:  Best-guess identification ('mifare_ultralight', etc.)
                       Or None if the sensor didn't detect anything.
        cross_link:    Tuple (link_type, raw_id) suitable for canonicalize_cross_link
                       — only set when detected=True. None otherwise.
        notes:         Free-text per-sensor comment (e.g. 'IR is passive listen,
                       press a button if this is a remote')
    """
    sensor: str
    detected: bool
    confidence: str = "high"
    raw: dict[str, Any] = field(default_factory=dict)
    tentative_id: Optional[str] = None
    cross_link: Optional[tuple[str, Any]] = None
    notes: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensor": self.sensor,
            "detected": self.detected,
            "confidence": self.confidence,
            "raw": self.raw,
            "tentative_id": self.tentative_id,
            "notes": self.notes,
        }


# ---------- the backend interface ---------------------------------------

class SensorBackend(Protocol):
    """A backend scans one sensor and returns a Detection."""
    sensor_name: str
    async def scan(self) -> Detection: ...


# ---------- stub backend (tests + first run) ----------------------------

class StubBackend:
    """Returns a pre-configured Detection. Used for tests and first-run
    pipeline proofs before real RPC backends are wired."""

    def __init__(self, sensor_name: str, detection: Detection,
                 simulate_scan_seconds: float = 0.0):
        if detection.sensor != sensor_name:
            raise ValueError(
                f"StubBackend({sensor_name!r}) given Detection for "
                f"{detection.sensor!r} — sensor mismatch"
            )
        self.sensor_name = sensor_name
        self._detection = detection
        self._sim_secs = simulate_scan_seconds

    async def scan(self) -> Detection:
        if self._sim_secs > 0:
            await asyncio.sleep(self._sim_secs)
        return self._detection


# ---------- helpers for building common stub detections -----------------
# These are convenience constructors so tests don't have to remember the
# exact ATQA/SAK bytes for common card types. They also document what the
# real backends will produce when they ship.

def stub_nfc_negative() -> Detection:
    return Detection(
        sensor="nfc", detected=False, confidence="high",
        notes="Active scan completed, no NFC tag in field",
    )


def stub_nfc_ultralight(uid: str = "04:A2:1B:5C:DE:AD:BE") -> Detection:
    """Mifare Ultralight (or NTAG21x — same signature)."""
    return Detection(
        sensor="nfc", detected=True, confidence="high",
        raw={"uid": uid, "atqa": "0x0044", "sak": "0x00"},
        tentative_id="mifare_ultralight_or_ntag21x",
        cross_link=("nfc_uid", uid),
    )


def stub_nfc_classic_1k(uid: str = "04:A2:1B:5C") -> Detection:
    return Detection(
        sensor="nfc", detected=True, confidence="high",
        raw={"uid": uid, "atqa": "0x0004", "sak": "0x08"},
        tentative_id="mifare_classic_1k",
        cross_link=("nfc_uid", uid),
    )


def stub_rfid_negative() -> Detection:
    return Detection(
        sensor="rfid", detected=False, confidence="high",
        notes="125 kHz active scan, no LF tag in field",
    )


def stub_rfid_em4100(badge_id: str = "DE:AD:BE:EF:01") -> Detection:
    return Detection(
        sensor="rfid", detected=True, confidence="high",
        raw={"badge_id": badge_id, "modulation": "Manchester"},
        tentative_id="em4100",
        cross_link=("rfid_em4100", badge_id),
    )


def stub_ibutton_negative() -> Detection:
    return Detection(
        sensor="ibutton", detected=False, confidence="high",
        notes="1-wire bus quiet, no Dallas key probed",
    )


def stub_ir_passive_silent(duration_s: int = 3) -> Detection:
    return Detection(
        sensor="ir", detected=False, confidence="medium",
        notes=(
            f"Passive listen for {duration_s}s, nothing transmitted. "
            "If this is a remote control, press a button while the Kiisu is near it."
        ),
    )


def stub_subghz_passive_silent(duration_s: int = 5) -> Detection:
    return Detection(
        sensor="subghz", detected=False, confidence="medium",
        notes=(
            f"Swept ISM bands for {duration_s}s, nothing transmitted. "
            "If this is a key fob, press the button while sweeping."
        ),
    )


def stub_subghz_signal(freq_hz: int = 433920000, modulation: str = "AM650",
                       protocol: str = "Princeton") -> Detection:
    return Detection(
        sensor="subghz", detected=True, confidence="high",
        raw={"freq_hz": freq_hz, "modulation": modulation, "protocol": protocol},
        tentative_id=f"{protocol}_{freq_hz//1_000_000}MHz",
        cross_link=("subghz_signal", (freq_hz, modulation, protocol)),
    )
