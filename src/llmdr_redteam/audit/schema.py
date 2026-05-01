"""Audit event schema v1.0.

Plain English: every mission produces ONE record of this shape, written ONCE
to events/all/{event_id}. EDGE fob ledger, redteam audit, door blacklist —
all of those are views over this same log, NOT separate writes.

Schema versioning rule:
  - Adding optional fields: no version bump, old code reads them as None.
  - Changing meaning of an existing field: bump to 1.1 + write migration note.
  - Removing a field: don't. Mark deprecated, stop writing it.

Field 'screen_narrative' is RESERVED for the Kiisu screen UI chat (Day 8+).
Missions in v0.1 don't need to populate it. The decorator allows it through
when present.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

SCHEMA_VERSION = "1.0"


@dataclass
class CrossLink:
    """Canonicalized radio identifier. Output of canonicalize_cross_link()."""
    type: str          # nfc_uid, rfid_em4100, subghz_signal, ir_protocol, host, ...
    value: str         # canonical form — same input always produces same value
    raw: str           # what the operator/mission originally provided, str()ified


@dataclass
class BusinessContext:
    """The 'EDGE operations lens' on an event. Nullable.

    When populated, makes this event visible in EDGE views like fobs_issued
    or fobs_revoked. domain='edge' for now, but the field exists so other
    business domains can plug in later (e.g. 'classroom' for CompTIA).
    """
    domain: str                          # 'edge' | 'classroom' | ...
    action: str                          # 'fob_issued' | 'fob_revoked' | 'fob_used' | ...
    member_id: Optional[str] = None
    member_tier: Optional[str] = None    # 'maker' | 'student' | 'visitor' | ...
    reason: Optional[str] = None
    expires_at: Optional[str] = None     # ISO 8601 or None for no expiry


@dataclass
class ScreenNarrative:
    """Pre-rendered display payload for the Kiisu's 128x64 mono screen.

    RESERVED for Day 8+ visual layer chat. Missions in v0.1 leave this None
    and the screen-UI chat will populate it via the interpreter's screen.md
    audience template.

    Constraints (will be validated by the interpreter, not here):
        - headline:  ≤21 chars
        - lines:     ≤5 entries, each ≤21 chars
        - icon:      one of 'check' | 'cross' | 'spin' | 'dots' | 'alert' | None
        - progress:  float 0.0–1.0 or None
    """
    headline: str
    lines: list[str] = field(default_factory=list)
    icon: Optional[str] = None
    progress: Optional[float] = None


@dataclass
class AuditEvent:
    """One mission run. Single canonical record.

    The decorator builds this. Missions don't see it directly — they return
    their normal outputs and the decorator captures everything else.
    """
    # ---- identity ----
    event_id: str                          # uuid7 — time-sortable
    schema_version: str                    # always SCHEMA_VERSION at write time
    mission_name: str                      # e.g. 'nfc_clone'
    mission_version: str                   # mission code's own version
    operator_id: str                       # default 'self'
    session_id: str                        # uuid7 grouping one sitting

    # ---- when ----
    started_at: str                        # ISO 8601 UTC, microsecond precision
    ended_at: str                          # ISO 8601 UTC
    duration_ms: int                       # ended - started in ms

    # ---- where (hardware) ----
    flipper_uid: Optional[str]             # e.g. '5A3DEA0027E18000'
    flipper_firmware_version: Optional[str]
    transport: str                         # 'usb' | 'ble' | 'wifi_relay' | 'none'
    transport_addr: Optional[str]          # 'COM9' | BLE MAC | host:port

    # ---- what ----
    inputs: dict[str, Any]                 # mission params — operator's truth
    outputs: dict[str, Any]                # what the mission produced
    success: bool
    error: Optional[dict[str, str]] = None # {'type': ..., 'message': ...} or None

    # ---- why ----
    operator_note: Optional[str] = None    # free text

    # ---- cross-link ----
    cross_link: Optional[CrossLink] = None # canonicalized; None if no radio id
    parent_event_id: Optional[str] = None  # if mission triggered by another

    # ---- business lens (nullable) ----
    business_context: Optional[BusinessContext] = None

    # ---- meta ----
    backfilled: bool = False               # True if reconstructed after the fact

    # ---- screen lens (RESERVED for Day 8+) ----
    screen_narrative: Optional[ScreenNarrative] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to JSON-friendly dict for pgvector storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        """Round-trip from a stored dict back to a typed event."""
        # Rebuild nested dataclasses
        cl = data.get("cross_link")
        bc = data.get("business_context")
        sn = data.get("screen_narrative")
        return cls(
            event_id=data["event_id"],
            schema_version=data["schema_version"],
            mission_name=data["mission_name"],
            mission_version=data["mission_version"],
            operator_id=data["operator_id"],
            session_id=data["session_id"],
            started_at=data["started_at"],
            ended_at=data["ended_at"],
            duration_ms=data["duration_ms"],
            flipper_uid=data.get("flipper_uid"),
            flipper_firmware_version=data.get("flipper_firmware_version"),
            transport=data["transport"],
            transport_addr=data.get("transport_addr"),
            inputs=data.get("inputs", {}),
            outputs=data.get("outputs", {}),
            success=data["success"],
            error=data.get("error"),
            operator_note=data.get("operator_note"),
            cross_link=CrossLink(**cl) if cl else None,
            parent_event_id=data.get("parent_event_id"),
            business_context=BusinessContext(**bc) if bc else None,
            backfilled=data.get("backfilled", False),
            screen_narrative=ScreenNarrative(**sn) if sn else None,
        )
