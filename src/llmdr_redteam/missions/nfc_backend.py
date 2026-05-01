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
    """Parsed contents of a .nfc file. Best-effort — fields may be empty."""
    uid: Optional[str] = None
    atqa: Optional[str] = None
    sak: Optional[str] = None
    device_type: Optional[str] = None     # firmware's own family label
    raw_text: str = ""
    source_path: Optional[str] = None     # /ext/nfc/<filename>

    def tentative_id(self) -> Optional[str]:
        if not self.atqa or not self.sak:
            return None
        key = (_normalize_atqa(self.atqa), _normalize_short_hex(self.sak))
        return ATQA_SAK_FAMILY.get(key)


def parse_nfc_file(text: str, source_path: Optional[str] = None) -> NFCCardData:
    """Parse the Flipper firmware's .nfc text format into structured data.

    The format is line-oriented `Key: value`. We pick out the fields we need
    and ignore the rest. UID is canonicalized to lowercase hex by the
    canonicalizer downstream — here we keep the firmware's own formatting in
    `raw_text` and pass the UID through as-given so canonicalize_cross_link
    handles the normalization in one place (per the schema rule).
    """
    data = NFCCardData(raw_text=text, source_path=source_path)
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if key == "uid":
            data.uid = value
        elif key == "atqa":
            data.atqa = value
        elif key == "sak":
            data.sak = value
        elif key == "device type":
            data.device_type = value
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

        launched_via = await self._launch_nfc_app()
        if not launched_via:
            return Detection(
                sensor="nfc", detected=False, confidence="low",
                notes=(
                    "Could not launch the NFC app on the Kiisu. Open NFC → "
                    "Read manually, tap the card, save it, and re-run."
                ),
            )

        log.info("nfc backend: NFC app launched via app_start(%r), "
                 "watching %s for %.1fs", launched_via, self.nfc_dir,
                 self.timeout_s)

        new_files = await self._wait_for_new_file(before)
        if not new_files:
            return Detection(
                sensor="nfc", detected=False, confidence="medium",
                notes=(
                    f"NFC app open for {int(self.timeout_s)}s, no new file "
                    f"appeared in {self.nfc_dir}. Card not tapped, or not "
                    f"saved, or the firmware wrote elsewhere."
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
                "source_path": full_path,
            },
            tentative_id=tentative,
            cross_link=("nfc_uid", card.uid),
            notes=(
                f"Saved by Kiisu firmware to {full_path}"
                + (f"; firmware labelled it {card.device_type!r}"
                   if card.device_type else "")
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
        that worked, or None."""
        for app_name in ("NFC", "nfc", "Nfc"):
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
