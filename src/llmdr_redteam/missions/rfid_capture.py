"""mission_rfid_capture — read a 125 kHz card to /ext/lfrfid/.

PLAIN ENGLISH:
==============
Hold a 125 kHz card to the BACK of the Kiisu (NOT the front — that's
NFC). This mission tells the Kiisu to listen, the operator taps,
the firmware saves a .rfid file. We read it back, parse it, and
return what we found.

Common targets:
  - EM4100 / EM4102: factory-burned ID stickers, lobby fobs, gym cards
  - HID Prox: 26-bit Wiegand corporate access cards
  - T5577: writable blanks (when read raw, before any clone has happened)
  - Indala / AWID / Paradox: legacy enterprise variants

The mission code is identical between StubRFIDBackend (tests) and
RealRFIDBackend (production) — same Detection contract, same cross_link
shape ('rfid_id', normalized_id).

CROSS-LINK semantics: 'rfid_id' is the Data field with separators
stripped and lowercased. So a HID Prox card showing "02 00 12 34 56"
canonicalizes to '0200123456'. That's stable across captures.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ..audit import audit_logged, status_emit
from .rfid_backend import RealRFIDBackend, StubRFIDBackend
from .sensor_backends import Detection

log = logging.getLogger("llmdr_redteam.missions.rfid_capture")


@audit_logged(mission_name="rfid_capture", mission_version="0.1.0")
async def mission_rfid_capture(
    *,
    backend: Any = None,
    audit_event_id: str = "",
    **_kwargs: Any,
) -> dict[str, Any]:
    """Read one 125 kHz card. Operator taps during the timeout window.

    Args:
        backend: A RealRFIDBackend (production) or StubRFIDBackend (tests).
                 If None, mission fails with a clear error.

    Returns:
        {
          'outputs': {
            'detected': bool,
            'confidence': str,
            'tentative_id': str | None,    # 'em4100', 'hid_prox', etc.
            'key_type': str | None,        # firmware-supplied raw name
            'data_hex': str | None,        # firmware-supplied data
            'normalized_id': str | None,   # canonicalized for cross-link
            'security_score': int | None,
            'source_path': str | None,     # /ext/lfrfid/<file>.rfid
            'notes': str,
          },
          'cross_link': ('rfid_id', normalized_id)  # only when detected
        }
    """
    if backend is None:
        raise ValueError(
            "backend is required — pass StubRFIDBackend(canned=Detection(...)) "
            "for tests or RealRFIDBackend(flipper=...) in production"
        )

    status_emit(audit_event_id, "rfid_capture: starting scan",
                stage="start")

    detection: Detection = await backend.scan()

    status_emit(audit_event_id,
                f"rfid_capture: done — detected={detection.detected} "
                f"tentative={detection.tentative_id}",
                stage="done",
                detected=detection.detected,
                tentative_id=detection.tentative_id)

    raw = detection.raw or {}
    outputs: dict[str, Any] = {
        "detected": detection.detected,
        "confidence": detection.confidence,
        "tentative_id": detection.tentative_id,
        "key_type": raw.get("key_type"),
        "data_hex": raw.get("data_hex"),
        "normalized_id": raw.get("normalized_id"),
        "security_score": raw.get("security_score"),
        "source_path": raw.get("source_path"),
        "notes": detection.notes,
    }

    out: dict[str, Any] = {"outputs": outputs}
    if detection.detected and detection.cross_link is not None:
        out["cross_link"] = detection.cross_link
    return out
