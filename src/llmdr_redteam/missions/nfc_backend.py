"""Real NFC backend — drives the Kiisu via flipper-mcp RPC.

Plain English: this is the production version of the StubBackend used in
Day 3 tests. Same `Detection` shape comes out. The mission code that uses
it (triage, nfc_clone) doesn't change between stub and real — that's the
whole point of the SensorBackend protocol.

Strategy mirrors LLMDR_app's proven mission_nfc_capture pattern:
  1. Snapshot /ext/nfc/ before
  2. Launch the Kiisu's native NFC app (RPC: app_start)
  3. Operator taps the card on the Kiisu, saves it
  4. Poll /ext/nfc/ for new .nfc files
  5. storage_read the new file, parse UID + ATQA + SAK
  6. Return Detection

The .nfc file format is a simple key=value text format. Parsing is
forgiving — fields we don't recognize get carried as 'extras'.

Day 4 ships read_card(). Write/verify land in clone-flow Day 4.5+.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from .sensor_backends import Detection

log = logging.getLogger("llmdr_redteam.missions.nfc_backend")


# ---------- ATQA/SAK -> tentative_id ------------------------------------
# Per knowledge/nfc.md. When a pairing is ambiguous (Ultralight vs NTAG21x),
# we return a hyphenated tentative_id to signal "could be either" and let
# the interpreter explain.
#
# IMPORTANT — ATQA byte order: the Flipper firmware writes ATQA in the order
# the bytes come off the wire (LSB first), e.g. an Ultralight's "0x0044"
# spec value appears as "44 00" in the .nfc file. We canonicalize ATQA by
# stripping spaces AND swapping bytes for 2-byte ATQAs, so both wire-order
# input ("44 00") and spec-order input ("00 44") land on the same key.

ATQA_SAK_FAMILY: dict[tuple[str, str], str] = {
    ("0044", "00"): "mifare_ultralight_or_ntag21x",
    ("0004", "08"): "mifare_classic_1k",
    ("0002", "18"): "mifare_classic_4k",
    ("0344", "20"): "mifare_desfire",
    ("0008", "88"): "mifare_plus",
}


def _normalize_short_hex(s: str) -> str:
    """Strip 0x, separators, lowercase. For 2-byte ATQA / 1-byte SAK fields."""
    s = s.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return re.sub(r"[^0-9a-f]", "", s)


def _normalize_atqa(s: str) -> str:
    """Canonicalize ATQA to spec-order ('0044'), regardless of whether the
    firmware emitted wire-order ('44 00') or spec-order ('00 44').

    Strategy: strip separators and 0x. If the result is 4 hex chars (2 bytes)
    AND looks like wire-order (low byte non-zero, high byte zero — typical
    ATQA shape), swap. Otherwise leave alone.

    This is necessary because Flipper firmware emits ATQA bytes in the order
    received from the tag (low byte first). Real Ultralight: "44 00" in the
    file → 0x0044 by spec.
    """
    h = _normalize_short_hex(s)
    if len(h) != 4:
        return h
    # Heuristic: if the visually-leading byte is non-zero and the trailing
    # byte is "00", that's wire-order; swap.
    high, low = h[:2], h[2:]
    if high != "00" and low == "00":
        return low + high
    return h


@dataclass
class NFCCardData:
    """Parsed contents of a .nfc file. Best-effort — fields may be empty.

    The Flipper firmware ships several format versions (Version 2 and Version 4
    are common as of 2026). Field availability varies:
      - Version 2: 'Device type' is specific (e.g. 'NTAG216'), ATQA in wire order.
      - Version 4: 'Device type' is a category ('NTAG/Ultralight'), with a
        secondary 'NTAG/Ultralight type' giving the exact variant. ATQA may
        appear in spec order. Adds '# comment lines' that we skip.

    `subtype` carries the v4 subtype field when present, so e.g. an Ultralight
    11 vs an NTAG216 can be told apart even though both classify as
    'mifare_ultralight_or_ntag21x' from ATQA/SAK alone.
    """
    uid: Optional[str] = None
    atqa: Optional[str] = None
    sak: Optional[str] = None
    device_type: Optional[str] = None     # firmware's primary family label
    subtype: Optional[str] = None         # firmware's subtype label (v4+)
    file_format_version: Optional[str] = None  # the .nfc file's own version
    raw_text: str = ""
    source_path: Optional[str] = None     # /ext/nfc/<filename>

    def tentative_id(self) -> Optional[str]:
        """Map ATQA/SAK + subtype to a canonical tentative_id.

        When the subtype field is populated (Version 4 files), use it for a
        more specific id. Falls back to the ATQA/SAK family when subtype
        isn't available.
        """
        # If we have a subtype, prefer it — it's more specific than the
        # ATQA/SAK pairing alone.
        if self.subtype:
            mapped = _SUBTYPE_TO_TENTATIVE_ID.get(self.subtype.lower().strip())
            if mapped:
                return mapped
        if not self.atqa or not self.sak:
            return None
        key = (_normalize_atqa(self.atqa), _normalize_short_hex(self.sak))
        return ATQA_SAK_FAMILY.get(key)


# ---------- subtype -> tentative_id (more specific than ATQA/SAK) -------
# Populated by Version 4 .nfc files in the 'NTAG/Ultralight type' field
# (and similar fields for other families). Mappings keyed on lowercased
# subtype string.

_SUBTYPE_TO_TENTATIVE_ID: dict[str, str] = {
    "mifare ultralight":     "mifare_ultralight",
    "mifare ultralight 11":  "mifare_ultralight_11",
    "mifare ultralight 21":  "mifare_ultralight_21",
    "mifare ultralight c":   "mifare_ultralight_c",
    "mifare ultralight ev1": "mifare_ultralight_ev1",
    "ntag203":               "ntag203",
    "ntag210":               "ntag210",
    "ntag212":               "ntag212",
    "ntag213":               "ntag213",
    "ntag215":               "ntag215",
    "ntag216":               "ntag216",
}


def parse_nfc_file(text: str, source_path: Optional[str] = None) -> NFCCardData:
    """Parse the Flipper firmware's .nfc text format into structured data.

    The format is line-oriented `Key: value`. We pick out the fields we need
    and ignore the rest. UID is canonicalized to lowercase hex by the
    canonicalizer downstream — here we keep the firmware's own formatting in
    `raw_text` and pass the UID through as-given so canonicalize_cross_link
    handles the normalization in one place (per the schema rule).

    Handles file format versions 2 and 4 transparently. Comment lines
    starting with '#' are skipped explicitly.
    """
    data = NFCCardData(raw_text=text, source_path=source_path)
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "version":
            # The .nfc FILE format version (2, 4, ...), not the firmware version
            data.file_format_version = value
        elif key == "uid":
            data.uid = value
        elif key == "atqa":
            data.atqa = value
        elif key == "sak":
            data.sak = value
        elif key == "device type":
            data.device_type = value
        elif key in (
            "ntag/ultralight type",   # v4 NTAG/Ultralight subtype
            "mifare classic type",    # v4 Mifare Classic subtype (1K vs 4K vs Plus)
            "mifare desfire type",    # v4 DESFire subtype (EV1 vs EV2 vs EV3)
        ):
            data.subtype = value
    return data


# ---------- the backend -------------------------------------------------

class RealNFCBackend:
    """Real NFC backend. Drives the Kiisu via the connected flipper-mcp RPC.

    Use this exactly where StubBackend was used. The mission code is
    unchanged.

    The constructor takes a `flipper` handle (the FlipperClient from
    flipper_mcp) so we can call rpc.app_start, storage.list, storage.read.
    """

    sensor_name = "nfc"

    def __init__(self, flipper: Any, *, timeout_s: float = 30.0,
                 nfc_dir: str = "/ext/nfc",
                 poll_interval_s: float = 1.5):
        self.flipper = flipper
        self.timeout_s = max(1.0, min(timeout_s, 120.0))
        self.nfc_dir = nfc_dir
        self.poll_interval_s = poll_interval_s

    async def scan(self) -> Detection:
        """Read one NFC card. Operator taps the card during the timeout window.

        Returns a Detection. On timeout (no tap), returns detected=False with
        notes explaining what happened. On read success, returns detected=True
        with UID + ATQA + SAK + tentative_id populated.
        """
        if self.flipper is None or getattr(self.flipper, "rpc", None) is None:
            return Detection(
                sensor="nfc", detected=False, confidence="low",
                notes="No RPC connection to Flipper — check transport",
            )

        before = await self._list_nfc_files()
        log.debug("nfc backend: %d existing .nfc files before scan", len(before))

        # Try to launch the NFC app. If something else is already running,
        # the firmware will refuse — that's fine; we still watch the
        # directory and trust the operator to navigate to NFC -> Read
        # manually. Either path produces a new .nfc file.
        launched_via = await self._launch_nfc_app()
        if launched_via:
            log.info("nfc backend: NFC app launched via app_start(%r), "
                     "watching %s for %.1fs", launched_via, self.nfc_dir,
                     self.timeout_s)
            launch_note = f"Launched NFC app via app_start({launched_via!r})."
        else:
            log.info("nfc backend: app_start refused (likely another app open) — "
                     "watching %s for %.1fs anyway", self.nfc_dir, self.timeout_s)
            launch_note = (
                "Could not launch NFC app remotely (another app likely already open "
                "on the Kiisu, or unrecognized name). Open NFC → Read manually "
                "on the device, tap the card, save it."
            )

        new_files = await self._wait_for_new_file(before)
        if not new_files:
            return Detection(
                sensor="nfc", detected=False, confidence="medium",
                notes=(
                    f"{launch_note} Watched {self.nfc_dir} for "
                    f"{int(self.timeout_s)}s, no new file appeared. "
                    "Card not tapped, not saved, or firmware wrote elsewhere."
                ),
            )

        # Read the most recent new file (usually only one)
        target_file = new_files[-1]
        full_path = f"{self.nfc_dir}/{target_file}"
        try:
            raw_bytes = await self.flipper.storage.read(full_path)
            if isinstance(raw_bytes, bytes):
                text = raw_bytes.decode("utf-8", errors="replace")
            else:
                text = str(raw_bytes)
        except Exception as e:
            return Detection(
                sensor="nfc", detected=False, confidence="low",
                notes=f"Read of {full_path} failed: {type(e).__name__}: {e}",
            )

        card = parse_nfc_file(text, source_path=full_path)
        if not card.uid:
            return Detection(
                sensor="nfc", detected=True, confidence="low",
                raw={"source_path": full_path, "raw_text_len": len(text)},
                notes=(
                    "File saved but no UID line found in the .nfc file. "
                    "May be a non-standard tag type the Kiisu firmware "
                    "stores differently."
                ),
            )

        tentative = card.tentative_id()
        return Detection(
            sensor="nfc",
            detected=True,
            confidence="high",
            raw={
                "uid": card.uid,
                "atqa": card.atqa,
                "sak": card.sak,
                "device_type": card.device_type,
                "subtype": card.subtype,
                "file_format_version": card.file_format_version,
                "source_path": full_path,
            },
            tentative_id=tentative,
            cross_link=("nfc_uid", card.uid),
            notes=(
                f"Saved by Kiisu firmware to {full_path}"
                + (f"; firmware labelled it {card.device_type!r}"
                   if card.device_type else "")
                + (f" (subtype: {card.subtype!r})" if card.subtype else "")
            ),
        )

    # ---------- internals -----------------------------------------------

    async def _list_nfc_files(self) -> set[str]:
        """List .nfc files in self.nfc_dir. Returns a set of filenames (no paths)."""
        try:
            entries = await self.flipper.storage.list(self.nfc_dir)
        except Exception as e:
            log.warning("storage.list(%s) failed: %s — assuming empty", self.nfc_dir, e)
            return set()
        out: set[str] = set()
        for entry in entries or []:
            # entry may be a string name or an object with .name + .is_dir
            name = getattr(entry, "name", None) or (entry if isinstance(entry, str) else None)
            if not name:
                continue
            is_dir = getattr(entry, "is_dir", False)
            if is_dir:
                continue
            if name.lower().endswith(".nfc"):
                out.add(name)
        return out

    async def _launch_nfc_app(self) -> Optional[str]:
        """Try common app names for the Kiisu NFC reader. Returns the name
        that worked, or None.

        Tried in order, most-likely-to-work first per Day-4 hardware findings.
        Stock OFW responds to bare 'NFC'. Momentum builds sometimes need
        the full .fap path. The dev who finds a NEW name that works should
        add it here.
        """
        candidates = (
            "NFC",                          # stock OFW
            "nfc",                          # case variant
            "Nfc",                          # case variant
            "/ext/apps/NFC/nfc.fap",        # Momentum path-based launch
            "nfc.fap",                      # Momentum bare-fap launch
        )
        for app_name in candidates:
            try:
                if await self.flipper.rpc.app_start(app_name, ""):
                    return app_name
            except Exception as e:
                log.debug("app_start(%r) failed: %s — trying next", app_name, e)
                continue
        return None

    async def _wait_for_new_file(self, before: set[str]) -> list[str]:
        """Poll self.nfc_dir until a new .nfc file appears or timeout.

        Returns sorted list of newly-appeared filenames (usually one).
        """
        polled = 0.0
        while polled < self.timeout_s:
            await asyncio.sleep(self.poll_interval_s)
            polled += self.poll_interval_s
            now = await self._list_nfc_files()
            added = sorted(now - before)
            if added:
                log.debug("new .nfc file(s) detected after %.1fs: %s",
                          polled, added)
                return added

        # One late look — files sometimes land just after the last poll tick.
        await asyncio.sleep(self.poll_interval_s)
        now = await self._list_nfc_files()
        return sorted(now - before)
