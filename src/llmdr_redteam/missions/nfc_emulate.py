"""mission_nfc_emulate — make the Kiisu pretend to be a captured card.

PLAIN ENGLISH:
==============
You point this mission at a .nfc file you previously captured. The Kiisu
spends N seconds pretending to be that card, broadcasting its UID + ATQA
+ SAK + payload to any reader that asks. To a reader, it looks like
the original card just got tapped on it.

Common uses:
  - Reissue a lost EDGE makerspace fob without a fresh blank
  - Demo "your hotel keycard could be cloned" to a security audit client
  - Test whether a reader is doing UID-only checks (it'll accept the
    emulation) or full crypto checks (it won't)

NO TAGS REQUIRED FOR THIS MISSION TO RUN. The Kiisu IS the card. A
*reader* is needed to validate the emulation lands — but the makerspace
door, your office fob reader, etc., are all valid validation targets.

ARCHITECTURE:
=============
Mirrors mission_unknown_identify's stub-vs-real backend pattern:
  - StubNFCEmulateBackend → no hardware, returns canned Detection
  - RealNFCEmulateBackend → pushes JS to Kiisu, runs it, reads log

Mission code is identical between stub and real. Test suite uses stubs.
Operator wires real backend in production via flipper-mcp handle.

CROSS-LINK:
===========
On successful emulation we set cross_link to ('nfc_uid', emulated_uid).
That's the UID of the card we *broadcast* — typically the same as the
card we read it from, but if the operator hand-edited the .nfc file to
spoof a different UID, the cross_link still reflects what actually went
on the air. Audit log integrity > assumed equivalence.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ..audit import audit_logged, status_emit
from .nfc_emulate_backend import (
    EmulateRequest,
    RealNFCEmulateBackend,
    StubNFCEmulateBackend,
)

log = logging.getLogger("llmdr_redteam.missions.nfc_emulate")


@audit_logged(mission_name="nfc_emulate", mission_version="0.1.0")
async def mission_nfc_emulate(
    *,
    source_path: str,
    duration_s: float = 30.0,
    backend: Any = None,
    audit_event_id: str = "",  # injected by decorator
    **_kwargs: Any,
) -> dict[str, Any]:
    """Emulate a captured NFC card.

    Args:
        source_path: path on the Kiisu's SD card to the .nfc file. Typically
                     /ext/nfc/<name>.nfc — produced by a prior nfc_capture
                     or by the Kiisu's NFC > Read > Save flow.
        duration_s:  how long the Kiisu broadcasts. 1-300 seconds. Default
                     30 — long enough to walk to the door and tap.
        backend:     A RealNFCEmulateBackend (production) or
                     StubNFCEmulateBackend (tests). If None, mission fails
                     with a clear error — backends must be injected so
                     missions stay testable.

    Returns:
        {
          'outputs': {
            'source_path': str,
            'duration_s': float,
            'detected': bool,         # whether emulation actually started
            'confidence': str,
            'tentative_id': str | None,  # 'emulation_completed' on success
            'emulated_uid': str | None,  # the UID we broadcast
            'completion': 'done' | 'stopped' | None,
            'log_tail': [str],        # last lines from the JS mission log
            'notes': str,
          },
          'cross_link': ('nfc_uid', emulated_uid)  # only on success
        }
    """
    if not source_path:
        raise ValueError("source_path is required (e.g. '/ext/nfc/keycard.nfc')")

    if backend is None:
        raise ValueError(
            "backend is required — pass StubNFCEmulateBackend(...) for tests "
            "or RealNFCEmulateBackend(flipper=...) in production"
        )

    duration_s = max(1.0, min(float(duration_s), 300.0))

    status_emit(audit_event_id,
                f"emulate: starting — {source_path} for {duration_s:.1f}s",
                stage="start", source_path=source_path,
                duration_s=duration_s)

    req = EmulateRequest(source_path=source_path, duration_s=duration_s)
    detection = await backend.emulate(req)

    status_emit(audit_event_id,
                f"emulate: done — detected={detection.detected} "
                f"confidence={detection.confidence}",
                stage="done",
                detected=detection.detected,
                confidence=detection.confidence)

    raw = detection.raw or {}
    outputs: dict[str, Any] = {
        "source_path": source_path,
        "duration_s": duration_s,
        "detected": detection.detected,
        "confidence": detection.confidence,
        "tentative_id": detection.tentative_id,
        "emulated_uid": raw.get("emulated_uid"),
        "completion": raw.get("completion"),
        "log_tail": raw.get("log_tail", []),
        "notes": detection.notes,
    }

    out: dict[str, Any] = {"outputs": outputs}
    if detection.detected and detection.cross_link is not None:
        out["cross_link"] = detection.cross_link
    return out
