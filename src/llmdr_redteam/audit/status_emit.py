"""Status emission — the 'mic in every mission' hook.

Plain English: missions emit short status updates as they progress.
('Reading sector 1 of 16...', 'Authenticating...', 'Verify match.')

In v0.1 the publisher is a no-op (just a debug log). The point is to put
the mic in EVERY mission today, so when the Day-8+ Kiisu screen UI chat
shows up — or when chat live-narration (Flavor A) ships — every mission
already has the calls in place. No retrofit needed.

The publisher is process-global and swappable. Call set_publisher(...) to
swap in a real one (e.g. an in-flight pgvector writer, or a queue feeding
the Kiisu screen).

Future publishers:
  - PgvectorInFlightPublisher: writes to events/in_flight/{event_id}/status
    with a short TTL. Chat narrator subscribes to this stream.
  - KiisuScreenPublisher: pushes formatted lines to the Kiisu's 128x64
    screen via a JS overlay app or custom RPC frame.
  - TeePublisher: fans out to multiple downstream publishers at once.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Optional, Protocol

log = logging.getLogger("llmdr_redteam.status_emit")


class Publisher(Protocol):
    """A status publisher just needs to accept (event_id, message, **fields)."""
    def __call__(self, event_id: str, message: str, **fields: Any) -> None: ...


class NoOpPublisher:
    """Default publisher — logs at DEBUG, does nothing else.

    This is intentionally inert. v0.1 missions emit, nothing listens, no
    storage cost. When a real publisher is needed, swap it in via
    set_publisher() and the same emit calls start producing real output.
    """
    def __call__(self, event_id: str, message: str, **fields: Any) -> None:
        if fields:
            log.debug("[noop emit] event=%s msg=%s fields=%r",
                      event_id, message, fields)
        else:
            log.debug("[noop emit] event=%s msg=%s", event_id, message)


# Process-global publisher. Default is NoOp.
_publisher: Publisher = NoOpPublisher()


def set_publisher(publisher: Optional[Publisher]) -> None:
    """Replace the global status publisher.

    Pass None to reset to the no-op default.
    """
    global _publisher
    _publisher = publisher if publisher is not None else NoOpPublisher()


def get_publisher() -> Publisher:
    """Read the current publisher (mostly for tests)."""
    return _publisher


def status_emit(event_id: str, message: str, **fields: Any) -> None:
    """Emit a status update for an in-flight mission.

    Args:
        event_id:  The audit event's event_id this status belongs to.
                   Lets subscribers correlate streamed updates with the
                   final event record once it lands.
        message:   Short human-readable status string. Should fit in a
                   Kiisu screen line (≤21 chars) where possible, but
                   longer messages are tolerated and may be truncated
                   downstream.
        **fields:  Optional structured data — progress=0.42, stage='auth',
                   sector=12, etc. Subscribers can use these for richer
                   rendering (progress bars, stage indicators).

    Never raises — status emission must never break a mission. If the
    publisher throws, we swallow it and log.
    """
    try:
        _publisher(event_id, message, **fields)
    except Exception:
        log.exception("status_emit publisher raised — swallowing")
