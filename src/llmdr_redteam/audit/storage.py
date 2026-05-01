"""Audit log storage backend.

Plain English: where audit events go to live. v0.1 ships with a JSONL
file backend that's good enough for Day 2 testing AND for solo operation
on the dev box. The pgvector backend lands when we wire into the existing
pgvector_load infrastructure (separate task, not Day 2).

The Storage protocol is intentionally tiny:
    - write(event_dict): append one event
    - iter_events(): yield all events (for views, blacklist rebuild, etc.)
    - get(event_id): fetch one event by id

That's enough for everything v0.1 needs: writing missions, querying for
the interpreter, rebuilding the blacklist, cross-history joins.

When we plug in pgvector, it implements the same protocol. Decorator and
blacklist code don't change.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Iterator, Optional, Protocol

log = logging.getLogger("llmdr_redteam.storage")


class Storage(Protocol):
    """Audit log storage interface. Single-write append-only."""
    def write(self, event: dict[str, Any]) -> None: ...
    def iter_events(self) -> Iterator[dict[str, Any]]: ...
    def get(self, event_id: str) -> Optional[dict[str, Any]]: ...


# ---------- JSONL backend ------------------------------------------------

class JSONLStorage:
    """Newline-delimited JSON file. One event per line. Append-only.

    Good for:
      - v0.1 dev/testing
      - solo operation on the dev box
      - debugging — `cat events.jsonl | jq` works

    Not good for:
      - large-scale operation
      - concurrent multi-writer (we serialize via a thread lock anyway)
      - vector similarity search (that's pgvector's job)

    Plugging into pgvector later is a different class implementing the
    same Storage protocol. Decorator and views don't change.
    """

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Thread lock makes concurrent writes within one process safe.
        # Multi-process safety is NOT a goal for v0.1.
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
                f.write("\n")

    def iter_events(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for lineno, raw in enumerate(f, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    yield json.loads(raw)
                except json.JSONDecodeError:
                    log.warning("audit log %s line %d: bad JSON, skipping",
                                self.path, lineno)

    def get(self, event_id: str) -> Optional[dict[str, Any]]:
        for ev in self.iter_events():
            if ev.get("event_id") == event_id:
                return ev
        return None


# ---------- in-memory backend (tests only) -------------------------------

class InMemoryStorage:
    """RAM-only storage. Tests use this so they don't touch disk."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def write(self, event: dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)

    def iter_events(self) -> Iterator[dict[str, Any]]:
        with self._lock:
            snapshot = list(self.events)
        yield from snapshot

    def get(self, event_id: str) -> Optional[dict[str, Any]]:
        for ev in self.iter_events():
            if ev.get("event_id") == event_id:
                return ev
        return None


# ---------- process-global storage ---------------------------------------
# Decorator reaches for this. set_storage() swaps it. Tests configure their
# own InMemoryStorage. Production points at a JSONL file (or pgvector later).

_storage: Optional[Storage] = None


def set_storage(storage: Optional[Storage]) -> None:
    """Configure the global audit log storage. None to clear."""
    global _storage
    _storage = storage


def get_storage() -> Storage:
    """Read the configured storage. Raises if not configured."""
    if _storage is None:
        raise RuntimeError(
            "audit log storage not configured — call set_storage(JSONLStorage(...)) "
            "or set_storage(InMemoryStorage()) before running missions"
        )
    return _storage
