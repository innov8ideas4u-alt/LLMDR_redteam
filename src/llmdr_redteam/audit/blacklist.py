"""Door blacklist — derived state, rebuilt from the audit log on demand.

Plain English: the blacklist isn't maintained inline by the decorator. It's
a CACHE OF A FOLD over the event log. If it gets corrupted, throw it away
and rebuild from the log. That's the whole point of audit-trail-as-source-
of-truth.

Algorithm (per MiMo's review):
  1. Scan all events with business_context.domain == 'edge'
     and action in ('fob_issued', 'fob_revoked')
  2. For each member_id, take the most recent event (by ended_at)
  3. If most recent action == 'fob_issued' -> NOT on blacklist
     If most recent action == 'fob_revoked' -> ON blacklist
  4. Write to a temp file, then os.replace (atomic) onto the real path
  5. Bump generation counter

The atomic-swap protects against crash-during-write: either the new file
is fully there or the old one stays. No half-written blacklist.

Time travel for free: pass `as_of` to rebuild_blacklist_from_log to fold
events up to a specific timestamp. ('What was the blacklist on March 1st?')
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from .storage import get_storage

log = logging.getLogger("llmdr_redteam.audit.blacklist")


# Where the rebuilt blacklist lives. Override via constructor.
DEFAULT_BLACKLIST_PATH = Path.home() / ".llmdr_redteam" / "door_blacklist_current.json"


@dataclass
class BlacklistResult:
    """What rebuild_blacklist_from_log returns."""
    generation: int
    blacklisted_member_ids: list[str]
    last_event_seen_at: Optional[str]
    path: Path
    events_considered: int


class _GenerationCounter:
    """Tiny atomic monotonic counter, persisted alongside the blacklist file.

    Stored as a sibling .gen file. On corruption (missing/garbage), resets
    to 0 — the blacklist is regenerable, the counter is a hint, not gospel.
    """

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            current = 0
            if self.path.exists():
                try:
                    current = int(self.path.read_text(encoding="utf-8").strip())
                except (ValueError, OSError):
                    current = 0
            new = current + 1
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(str(new), encoding="utf-8")
            os.replace(tmp, self.path)
            return new


def rebuild_blacklist_from_log(
    *,
    blacklist_path: Path | str = DEFAULT_BLACKLIST_PATH,
    domain: str = "edge",
    as_of: Optional[str] = None,
) -> BlacklistResult:
    """Fold the audit log into the current blacklist.

    Args:
        blacklist_path: Where to write the result. Atomic swap.
        domain:         business_context.domain to filter on. Defaults to 'edge'.
        as_of:          Optional ISO 8601 cutoff. Events with ended_at > as_of
                        are excluded. Lets you reconstruct a historical blacklist.

    Returns:
        BlacklistResult with generation, blacklisted ids, latest event seen,
        the path it wrote to, and how many events it considered.
    """
    blacklist_path = Path(blacklist_path)
    blacklist_path.parent.mkdir(parents=True, exist_ok=True)

    # Per-member latest action — keyed by member_id, value is (ended_at, action)
    latest: dict[str, tuple[str, str]] = {}
    last_event_seen_at: Optional[str] = None
    considered = 0

    storage = get_storage()
    for ev in storage.iter_events():
        bc = ev.get("business_context")
        if not bc or bc.get("domain") != domain:
            continue
        action = bc.get("action")
        if action not in ("fob_issued", "fob_revoked"):
            continue
        member_id = bc.get("member_id")
        if not member_id:
            continue
        ended_at = ev.get("ended_at") or ev.get("started_at") or ""
        if as_of is not None and ended_at > as_of:
            continue

        considered += 1
        if last_event_seen_at is None or ended_at > last_event_seen_at:
            last_event_seen_at = ended_at

        prev = latest.get(member_id)
        if prev is None or ended_at >= prev[0]:
            latest[member_id] = (ended_at, action)

    blacklisted = sorted(
        member_id
        for member_id, (_, action) in latest.items()
        if action == "fob_revoked"
    )

    # Atomic write: temp + replace
    gen_path = blacklist_path.with_suffix(blacklist_path.suffix + ".gen")
    counter = _GenerationCounter(gen_path)
    new_gen = counter.next()

    payload = {
        "generation": new_gen,
        "domain": domain,
        "as_of": as_of,
        "rebuilt_at": last_event_seen_at,
        "blacklisted_member_ids": blacklisted,
        "events_considered": considered,
    }
    tmp = blacklist_path.with_suffix(blacklist_path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    os.replace(tmp, blacklist_path)

    log.info(
        "blacklist rebuilt: gen=%d, %d blacklisted members from %d events at %s",
        new_gen, len(blacklisted), considered, blacklist_path,
    )
    return BlacklistResult(
        generation=new_gen,
        blacklisted_member_ids=blacklisted,
        last_event_seen_at=last_event_seen_at,
        path=blacklist_path,
        events_considered=considered,
    )


def read_blacklist(blacklist_path: Path | str = DEFAULT_BLACKLIST_PATH) -> dict[str, Any]:
    """Read the most-recently-rebuilt blacklist. Returns empty dict if missing."""
    blacklist_path = Path(blacklist_path)
    if not blacklist_path.exists():
        return {"generation": 0, "blacklisted_member_ids": [], "events_considered": 0}
    try:
        return json.loads(blacklist_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        log.warning("blacklist file unreadable (%s): %s — returning empty", blacklist_path, e)
        return {"generation": 0, "blacklisted_member_ids": [], "events_considered": 0}
