"""mission_audit_smoketest — fake mission to exercise the audit pipeline.

Plain English: this mission doesn't talk to a Flipper. It pretends to do
something with a UID and returns success. Its purpose is purely to prove
the audit pipeline (decorator -> canonicalize -> storage -> read back)
works end-to-end before any real radio code lands.

When the canonicalizer is wrong, this test fails loudly.
When the decorator drops a field, this test fails loudly.
When the storage backend silently swallows writes, this test fails loudly.

Day 3 onwards, real missions look JUST like this — they just have RPC
calls in the body. The wrapper machinery is identical.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from ..audit import audit_logged, status_emit

log = logging.getLogger("llmdr_redteam.missions.audit_smoketest")


@audit_logged(mission_name="audit_smoketest", mission_version="0.1.0")
async def mission_audit_smoketest(
    *,
    fake_uid: str = "04:A2:1B:5C",
    simulate_failure: bool = False,
    audit_event_id: str = "",  # injected by decorator
    **_kwargs: Any,
) -> dict[str, Any]:
    """Fake mission that pretends to read a card and return.

    Args:
        fake_uid:          A fake NFC UID to canonicalize. Defaults to a 4-byte test UID.
        simulate_failure:  If True, raise a RuntimeError so error-path is tested too.
        audit_event_id:    Injected by the decorator. Used for status_emit().
        **_kwargs:         Catch-all for any extra kwargs the decorator passes through
                           (operator_note, business_context, parent_event_id, rpc...).

    Returns:
        Dict with 'outputs' and 'cross_link' for the decorator to capture.
    """
    status_emit(audit_event_id, "smoketest: starting", stage="start")

    # Pretend to do work
    await asyncio.sleep(0.001)
    status_emit(audit_event_id, "smoketest: simulated read", stage="read")

    if simulate_failure:
        raise RuntimeError("simulated mission failure")

    await asyncio.sleep(0.001)
    status_emit(audit_event_id, "smoketest: done", stage="done")

    return {
        "outputs": {
            "fake_read": True,
            "would_have_clone": True,
        },
        "cross_link": ("nfc_uid", fake_uid),
    }
