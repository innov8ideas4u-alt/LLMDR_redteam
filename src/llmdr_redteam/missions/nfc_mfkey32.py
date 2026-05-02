"""mission_nfc_mfkey32 — host-side Mifare Classic key recovery.

PLAIN ENGLISH:
==============
You captured a card+reader handshake using Flipper's "Detect Reader" mode.
The captures live in /ext/nfc/.mfkey32.log on the Kiisu (or any Flipper).

This mission:
  1. Pulls that log file off the device (or accepts an inline string).
  2. Parses the nonce pairs.
  3. Runs the mfkey32 solver against each (sector, key_type) group.
  4. Returns a list of recovered Mifare Classic sector keys.

NO RADIO TRANSMISSION HAPPENS. This is pure host-side compute. That's why
this mission can ship Day 5 even with no test tags on hand — the math
works on captures, not on live cards.

Cross-link is set to the card's CUID (the 4-byte UID from the captures)
when at least one key is recovered. That ties this mission's output back
to any prior triage / capture event for the same physical card.

USAGE PATTERN:
==============
  # 1. Field capture (separate mission, hardware-touching):
  #    Operator runs Flipper's NFC > Detect Reader, taps the reader twice.
  # 2. This mission (host-side, no hardware):
  await mission_nfc_mfkey32(log_text=<contents of .mfkey32.log>)
  # ⇒ outputs.recovered[0] = {sector: 1, key_type: 'A', key_hex: 'a0a1a2a3a4a5', ...}
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from ..audit import audit_logged, status_emit
from .mfkey32_solver import (
    SolverBinaryMissing,
    parse_mfkey32_log,
    solve,
)

log = logging.getLogger("llmdr_redteam.missions.nfc_mfkey32")


@audit_logged(mission_name="nfc_mfkey32", mission_version="0.1.0")
async def mission_nfc_mfkey32(
    *,
    log_text: Optional[str] = None,
    log_path: Optional[str] = None,
    solver_path: Optional[str] = None,
    audit_event_id: str = "",  # injected by decorator
    **_kwargs: Any,
) -> dict[str, Any]:
    """Recover Mifare Classic sector keys from captured nonces.

    Args:
        log_text:    .mfkey32.log contents as a string. Mutually exclusive
                     with log_path. Used by tests + by callers who already
                     pulled the log off the device.
        log_path:    Path to a .mfkey32.log file on the local filesystem.
                     If both log_text and log_path are None, the mission
                     fails with a clear error.
        solver_path: Optional explicit path to the mfkey32 binary. If None,
                     PATH autodiscovery is used.

    Returns:
        {
          'outputs': {
            'recovered': [{sector, key_type, key_hex, ...}, ...],
            'failed':    [{sector, key_type, reason, ...}, ...],
            'nonces_parsed': int,
            'solver_version': str,
            'cuid': str | None,
          },
          'cross_link': ('nfc_uid', cuid) | omitted
        }

    Raises:
        ValueError: if neither log_text nor log_path provided.
        FileNotFoundError: if log_path doesn't exist.
        mfkey32_solver.SolverBinaryMissing: if mfkey32 binary not found.
        mfkey32_solver.Mfkey32ParseError: if log file is malformed.
    """
    if log_text is None and log_path is None:
        raise ValueError(
            "must provide either log_text or log_path "
            "(the .mfkey32.log file from a Detect Reader capture)"
        )
    if log_text is not None and log_path is not None:
        raise ValueError("provide only one of log_text or log_path, not both")

    if log_path is not None:
        status_emit(audit_event_id, f"mfkey32: reading log from {log_path}",
                    stage="read_log", source="file")
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            log_text = f.read()
    else:
        status_emit(audit_event_id, "mfkey32: parsing inline log text",
                    stage="read_log", source="inline")

    pairs = parse_mfkey32_log(log_text or "")
    status_emit(audit_event_id,
                f"mfkey32: parsed {len(pairs)} nonce pair(s)",
                stage="parsed", n_pairs=len(pairs))

    if not pairs:
        return {
            "outputs": {
                "recovered": [],
                "failed": [],
                "nonces_parsed": 0,
                "solver_version": "n/a (no input)",
                "cuid": None,
                "notes": "log file was empty or contained only comments",
            }
        }

    # All pairs from a single .mfkey32.log come from the same physical card,
    # but operators occasionally concatenate logs from multiple cards. We
    # carry the first cuid as the cross-link target and warn if they
    # disagree.
    cuids_seen = sorted({p.cuid for p in pairs})
    primary_cuid = cuids_seen[0]
    if len(cuids_seen) > 1:
        status_emit(audit_event_id,
                    f"mfkey32: WARNING multiple cuids in one log: {cuids_seen}",
                    stage="multi_cuid", cuids=cuids_seen)

    status_emit(audit_event_id, "mfkey32: invoking solver",
                stage="solving")
    try:
        result = solve(pairs, solver_path=solver_path)
    except SolverBinaryMissing as e:
        status_emit(audit_event_id, "mfkey32: SOLVER MISSING",
                    stage="solver_missing")
        # Re-raise so the decorator records success=False with the
        # error message. Operator gets actionable install hints.
        raise

    status_emit(audit_event_id,
                f"mfkey32: recovered {len(result.recovered)} key(s), "
                f"{len(result.failed)} failed",
                stage="done",
                recovered=len(result.recovered),
                failed=len(result.failed))

    outputs: dict[str, Any] = result.to_dict()
    outputs["cuid"] = primary_cuid
    if len(cuids_seen) > 1:
        outputs["all_cuids"] = cuids_seen

    out: dict[str, Any] = {"outputs": outputs}
    if result.success:
        # Cross-link uses the canonical NFC UID type so this event chains
        # to any prior capture / triage event for the same card.
        out["cross_link"] = ("nfc_uid", primary_cuid)
    return out
