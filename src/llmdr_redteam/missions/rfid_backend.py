"""rfid_backend — drives the Kiisu's 125 kHz coil for read/clone/emulate.

PLAIN ENGLISH:
==============
The Kiisu has TWO antennas: NFC on the front (13.56 MHz), RFID on the
back (125 kHz). This file is for the back one. It handles:

  - Reading whatever 125 kHz card is held to the back (EM4100, HID
    Prox, T5577, etc.)
  - Parsing the .rfid text file the firmware saves
  - (Future) Writing a captured ID to a T5577 blank
  - (Future) Emulating a captured ID via the JS runtime

The .rfid file format is much simpler than .nfc — single Data line,
single Key type field. No paginated memory, no auth blocks.

PATTERN MIRRORS RealNFCBackend:
  1. Snapshot /ext/lfrfid/ before
  2. Launch Kiisu's RFID app via app_start("125 kHz RFID") or fallback
  3. Operator taps card on the BACK of the Kiisu, saves it
  4. Poll /ext/lfrfid/ for new .rfid files
  5. storage_read the new file, parse Key type + Data
  6. Return Detection

NOTE ON DIRECTORY: The Flipper firmware saves to /ext/lfrfid/, NOT
/ext/rfid/. Easy mistake — even reading the firmware code, the
inconsistency is real.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from .sensor_backends import Detection

log = logging.getLogger("llmdr_redteam.missions.rfid_backend")


# ---------- key type -> tentative_id mapping ----------------------------
# Per knowledge/rfid.md. The Kiisu firmware writes the protocol name in
# the "Key type:" field. We canonicalize to lowercase snake_case for
# tentative_id so it matches the keys in unknown_identify._NEXT_ACTIONS.

KEY_TYPE_TO_TENTATIVE: dict[str, str] = {
    "em4100":     "em4100",
    "em4102":     "em4100",         # firmware folds these together
    "h10301":     "hid_prox",       # 26-bit HID Prox standard format
    "hidprox":    "hid_prox",
    "hid_prox":   "hid_prox",
    "indala26":   "indala",
    "indala":     "indala",
    "ioprox":     "ioprox",
    "awid":       "awid",
    "paradox":    "paradox",
    "fdx-a":      "fdx_a_animal",
    "fdx-b":      "fdx_b_animal",
    "pyramid":    "pyramid",
    "viking":     "viking",
    "jablotron":  "jablotron",
    "nexwatch":   "nexwatch",
    "securakey":  "securakey",
    "gallagher":  "gallagher",
    "t55xx":      "t5577_raw",      # raw T5577 read, not yet protocol-decoded
    "t5577":      "t5577_raw",
}


# Security score per family. Lower = more vulnerable. Same 1-5 scale as
# vingcard.md, used by interpreter for narrative tone.
SECURITY_SCORE: dict[str, int] = {
    "em4100":         1,
    "hid_prox":       1,
    "indala":         2,
    "ioprox":         2,
    "awid":           2,
    "paradox":        2,
    "pyramid":        2,
    "viking":         2,
    "jablotron":      2,
    "nexwatch":       2,
    "securakey":      2,
    "gallagher":      3,   # has some auth in newer variants
    "fdx_a_animal":   1,   # animal IDs aren't security; mark as low
    "fdx_b_animal":   1,
    "t5577_raw":      1,   # if raw-readable, no password set
}


# Maps tentative_id -> the canonicalizer link_type to emit for cross_link.
# Each link_type has its own canonicalizer rules (see audit/canonicalize.py).
# Anything not in this map gets the generic 125 kHz bucket — still
# cross-linkable, just less specific.
TENTATIVE_TO_LINK_TYPE: dict[str, str] = {
    "em4100":       "rfid_em4100",
    "t5577_raw":    "rfid_t5577",
    "hid_prox":     "rfid_hid_prox",
    "indala":       "rfid_indala",
    "awid":         "rfid_awid",
    # Everything else flows through "rfid_generic" as the catch-all.
}


def link_type_for(tentative_id: Optional[str]) -> str:
    """Return the canonicalizer link_type for a parsed RFID family.

    Used by the backend to construct cross_link with a type the canonicalizer
    will accept. Falls through to 'rfid_generic' for any family we recognize
    but don't have a dedicated handler for yet.
    """
    if not tentative_id:
        return "rfid_generic"
    return TENTATIVE_TO_LINK_TYPE.get(tentative_id, "rfid_generic")


# ---------- parsed shape ------------------------------------------------

@dataclass
class RFIDCardData:
    raw_text: str
    source_path: Optional[str] = None
    file_format_version: Optional[str] = None
    key_type: Optional[str] = None        # firmware-supplied, e.g. "EM4100"
    data_hex: Optional[str] = None        # firmware-supplied, e.g. "12 34 56 78 9A"
    tentative_id: Optional[str] = None    # canonicalized via KEY_TYPE_TO_TENTATIVE
    security_score: Optional[int] = None
    extras: dict[str, str] = field(default_factory=dict)

    @property
    def normalized_id(self) -> Optional[str]:
        """data_hex with separators stripped, lowercased. Cross-link target."""
        if not self.data_hex:
            return None
        return re.sub(r"[^0-9a-f]", "", self.data_hex.lower())


# ---------- parser ------------------------------------------------------

class RFIDParseError(ValueError):
    """The .rfid file's content didn't match the expected shape."""


def parse_rfid_file(text: str, source_path: Optional[str] = None) -> RFIDCardData:
    """Parse the Flipper firmware's .rfid text format.

    Format (Version 1, the one in the wild):
        Filetype: Flipper RFID key
        Version: 1
        Key type: EM4100
        Data: 12 34 56 78 9A

    Forgiving: extra fields go into extras. Unknown key types pass
    through with tentative_id=None (so the interpreter can flag them
    as "we read it but don't recognize the family").
    """
    data = RFIDCardData(raw_text=text, source_path=source_path)
    found_filetype = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key_lower = key.strip().lower()
        value = value.strip()

        if key_lower == "filetype":
            found_filetype = True
            if "rfid" not in value.lower():
                raise RFIDParseError(
                    f"file type {value!r} doesn't look like an RFID key file"
                )
        elif key_lower == "version":
            data.file_format_version = value
        elif key_lower == "key type":
            data.key_type = value
            normalized = re.sub(r"[^a-z0-9]", "", value.lower())
            data.tentative_id = KEY_TYPE_TO_TENTATIVE.get(normalized)
            if data.tentative_id:
                data.security_score = SECURITY_SCORE.get(data.tentative_id)
        elif key_lower == "data":
            data.data_hex = value
        else:
            data.extras[key_lower] = value

    if not found_filetype:
        raise RFIDParseError("no Filetype: header — not a .rfid file")
    if not data.key_type:
        raise RFIDParseError("no 'Key type:' line — file is malformed")
    if not data.data_hex:
        raise RFIDParseError("no 'Data:' line — file is malformed")

    return data


# ---------- the backend -------------------------------------------------

class RealRFIDBackend:
    """Real RFID backend — drives the Kiisu via flipper-mcp RPC.

    Use this exactly where StubBackend was used in mission_unknown_identify.
    Mission code is unchanged across stub vs real.

    HARDWARE-VALIDATION STATUS: code path is fully testable via mocks
    (see test_rfid_backend.py), but live read against an EM4100 / T5577
    has NOT been hardware-validated yet. Pending tag delivery.
    Marker for future Claude/Victor: search this repo for
    "TODO_HARDWARE_VALIDATE_RFID" and exercise the live path.
    """

    sensor_name = "rfid"

    def __init__(
        self, flipper: Any, *,
        timeout_s: float = 30.0,
        rfid_dir: str = "/ext/lfrfid",   # firmware uses lfrfid, not rfid
        poll_interval_s: float = 1.5,
    ):
        self.flipper = flipper
        self.timeout_s = max(1.0, min(timeout_s, 120.0))
        self.rfid_dir = rfid_dir
        self.poll_interval_s = poll_interval_s

    async def scan(self) -> Detection:
        """Read one RFID card. Operator taps card on BACK of Kiisu.

        Returns a Detection. On timeout, detected=False with notes.
        On success, detected=True with key_type + data_hex + tentative_id.
        """
        # TODO_HARDWARE_VALIDATE_RFID: this whole flow has been logically
        # tested via _FakeFlipper but never run against a live tag.
        # When tags arrive, run mission_rfid_capture against an EM4100
        # and a T5577 and confirm Detection.detected=True with sensible
        # tentative_id values.

        if self.flipper is None or getattr(self.flipper, "rpc", None) is None:
            return Detection(
                sensor="rfid", detected=False, confidence="low",
                notes="No RPC connection to Flipper — check transport",
            )

        before = await self._list_rfid_files()
        log.debug("rfid backend: %d existing .rfid files before scan", len(before))

        launched_via = await self._launch_rfid_app()
        if launched_via:
            log.info("rfid backend: app launched via app_start(%r)", launched_via)
            launch_note = f"Launched RFID app via app_start({launched_via!r})."
        else:
            log.info("rfid backend: app_start refused — relying on operator")
            launch_note = (
                "Could not launch RFID app remotely. Open '125 kHz RFID' → "
                "Read manually on the device. REMINDER: hold card to the "
                "BACK of the Kiisu, not the front (front = NFC antenna)."
            )

        new_files = await self._wait_for_new_file(before)
        if not new_files:
            return Detection(
                sensor="rfid", detected=False, confidence="medium",
                notes=(launch_note + " No new .rfid file appeared in "
                       f"{self.timeout_s:.0f}s — operator may have skipped, "
                       "or card is on the wrong face."),
            )

        # Pick the newest one
        new_file = sorted(new_files)[-1]
        full_path = f"{self.rfid_dir}/{new_file}"
        try:
            text = await self.flipper.storage.read(full_path)
        except Exception as e:
            return Detection(
                sensor="rfid", detected=False, confidence="low",
                notes=f"could not read {full_path}: {type(e).__name__}: {e}",
            )

        try:
            card = parse_rfid_file(text, source_path=full_path)
        except RFIDParseError as e:
            return Detection(
                sensor="rfid", detected=False, confidence="low",
                notes=f"parsed file but format unrecognized: {e}",
                raw={"source_path": full_path},
            )

        return Detection(
            sensor="rfid", detected=True, confidence="high",
            raw={
                "key_type": card.key_type,
                "data_hex": card.data_hex,
                "normalized_id": card.normalized_id,
                "tentative_id": card.tentative_id,
                "security_score": card.security_score,
                "source_path": full_path,
                "file_format_version": card.file_format_version,
                "link_type": link_type_for(card.tentative_id),
            },
            tentative_id=card.tentative_id,
            cross_link=(
                (link_type_for(card.tentative_id), card.normalized_id)
                if card.normalized_id else None
            ),
            notes=(
                f"Saved by Kiisu firmware to {full_path}"
                + (f"; key_type={card.key_type!r}" if card.key_type else "")
                + (f"; auto-detected as {card.tentative_id} "
                   f"({card.security_score}/5 security)"
                   if card.tentative_id else "; UNKNOWN family")
            ),
        )

    # ---------- internals -----------------------------------------------

    async def _list_rfid_files(self) -> set[str]:
        try:
            entries = await self.flipper.storage.list(self.rfid_dir)
        except Exception as e:
            log.warning("storage.list(%s) failed: %s", self.rfid_dir, e)
            return set()
        out: set[str] = set()
        for entry in entries or []:
            name = getattr(entry, "name", None) or (entry if isinstance(entry, str) else None)
            if not name:
                continue
            if getattr(entry, "is_dir", False):
                continue
            if name.lower().endswith(".rfid"):
                out.add(name)
        return out

    async def _launch_rfid_app(self) -> Optional[str]:
        """Try common RFID app names. Mirrors NFC backend's pattern."""
        candidates = (
            "125 kHz RFID",                  # stock OFW display name
            "lfrfid",                        # internal id
            "LFRFID",                        # case variant
            "/ext/apps/RFID/lfrfid.fap",     # Momentum path-based
            "lfrfid.fap",                    # Momentum bare
        )
        for app_name in candidates:
            try:
                if await self.flipper.rpc.app_start(app_name, ""):
                    return app_name
            except Exception as e:
                log.debug("app_start(%r) failed: %s", app_name, e)
                continue
        return None

    async def _wait_for_new_file(self, before: set[str]) -> set[str]:
        deadline = asyncio.get_event_loop().time() + self.timeout_s
        while asyncio.get_event_loop().time() < deadline:
            current = await self._list_rfid_files()
            new = current - before
            if new:
                return new
            await asyncio.sleep(self.poll_interval_s)
        return set()


# ---------- stub backend for tests --------------------------------------

class StubRFIDBackend:
    """Returns a canned Detection. Mirror of StubBackend pattern."""

    sensor_name = "rfid"

    def __init__(self, canned: Detection):
        self.canned = canned

    async def scan(self) -> Detection:
        return self.canned


def stub_rfid_em4100_canned(uid_hex: str = "0123456789") -> Detection:
    """A pre-baked positive Detection for an EM4100. For test fixtures.
    EM4100 IDs are exactly 5 bytes (10 hex chars) — canonicalizer enforces."""
    return Detection(
        sensor="rfid",
        detected=True,
        confidence="high",
        raw={
            "key_type": "EM4100",
            "data_hex": " ".join(uid_hex[i:i+2] for i in range(0, len(uid_hex), 2)),
            "normalized_id": uid_hex.lower(),
            "tentative_id": "em4100",
            "security_score": 1,
            "source_path": "/ext/lfrfid/test.rfid",
            "link_type": "rfid_em4100",
        },
        tentative_id="em4100",
        cross_link=("rfid_em4100", uid_hex.lower()),
        notes="canned EM4100 stub",
    )


def stub_rfid_hid_prox_canned(card_id_hex: str = "0200123456") -> Detection:
    """A pre-baked positive Detection for a HID Prox 26-bit. For test fixtures."""
    return Detection(
        sensor="rfid",
        detected=True,
        confidence="high",
        raw={
            "key_type": "H10301",
            "data_hex": " ".join(card_id_hex[i:i+2] for i in range(0, len(card_id_hex), 2)),
            "normalized_id": card_id_hex.lower(),
            "tentative_id": "hid_prox",
            "security_score": 1,
            "source_path": "/ext/lfrfid/test.rfid",
            "link_type": "rfid_hid_prox",
        },
        tentative_id="hid_prox",
        cross_link=("rfid_hid_prox", card_id_hex.lower()),
        notes="canned HID Prox stub",
    )
