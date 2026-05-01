"""End-to-end smoketest of the audit pipeline.

Wraps mission_audit_smoketest, runs it, reads the event back out of
storage, and asserts every important field landed correctly.

If this passes, the whole audit pipeline works:
  decorator -> canonicalize -> storage write -> storage read.
"""

import asyncio
import pytest

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.missions import mission_audit_smoketest


@pytest.fixture
def in_memory_storage():
    """Each test gets a fresh storage. Reset session_id too."""
    storage = InMemoryStorage()
    set_storage(storage)
    reset_session_id("test-session-fixed-id")
    yield storage
    set_storage(None)


# ---------- happy path ---------------------------------------------------

async def test_smoketest_writes_one_event(in_memory_storage):
    result = await mission_audit_smoketest(fake_uid="04:A2:1B:5C")
    assert result["outputs"]["fake_read"] is True

    events = list(in_memory_storage.iter_events())
    assert len(events) == 1, f"expected 1 event, got {len(events)}"


async def test_smoketest_event_has_required_fields(in_memory_storage):
    await mission_audit_smoketest(fake_uid="04:A2:1B:5C")
    ev = list(in_memory_storage.iter_events())[0]

    assert ev["mission_name"] == "audit_smoketest"
    assert ev["mission_version"] == "0.1.0"
    assert ev["schema_version"] == "1.0"
    assert ev["operator_id"] == "self"
    assert ev["session_id"] == "test-session-fixed-id"
    assert ev["success"] is True
    assert ev["error"] is None
    assert ev["transport"] == "none"  # no rpc handle in test
    assert ev["duration_ms"] >= 0


async def test_smoketest_canonicalizes_cross_link(in_memory_storage):
    """The cross_link from the mission ('04:A2:1B:5C') must come out
    canonicalized to '04a21b5c'."""
    await mission_audit_smoketest(fake_uid="04:A2:1B:5C")
    ev = list(in_memory_storage.iter_events())[0]

    assert ev["cross_link"] is not None
    assert ev["cross_link"]["type"] == "nfc_uid"
    assert ev["cross_link"]["value"] == "04a21b5c"
    assert ev["cross_link"]["raw"] == "04:A2:1B:5C"


async def test_smoketest_inputs_captured(in_memory_storage):
    """Mission inputs (fake_uid) should land in the inputs snapshot,
    audit_event_id should NOT (it's redundant with event_id)."""
    await mission_audit_smoketest(fake_uid="04:A2:1B:5C")
    ev = list(in_memory_storage.iter_events())[0]

    assert ev["inputs"]["fake_uid"] == "04:A2:1B:5C"
    assert "audit_event_id" not in ev["inputs"]


async def test_smoketest_business_context_lands(in_memory_storage):
    """When business_context is passed, it should be captured in the event
    record so EDGE views can find it."""
    await mission_audit_smoketest(
        fake_uid="04:A2:1B:5C",
        business_context={
            "domain": "edge",
            "action": "fob_issued",
            "member_id": "edge_member_0047",
            "member_tier": "maker",
            "reason": "initial onboarding",
        },
    )
    ev = list(in_memory_storage.iter_events())[0]
    bc = ev["business_context"]
    assert bc is not None
    assert bc["domain"] == "edge"
    assert bc["action"] == "fob_issued"
    assert bc["member_id"] == "edge_member_0047"


async def test_smoketest_operator_note_lands(in_memory_storage):
    await mission_audit_smoketest(
        fake_uid="04:A2:1B:5C",
        operator_note="initial smoketest run",
    )
    ev = list(in_memory_storage.iter_events())[0]
    assert ev["operator_note"] == "initial smoketest run"


# ---------- failure path -------------------------------------------------

async def test_smoketest_failure_still_writes_event(in_memory_storage):
    """Mission errors are re-raised, but the audit event STILL writes.
    The event records success=False and the error type/message."""
    with pytest.raises(RuntimeError, match="simulated mission failure"):
        await mission_audit_smoketest(simulate_failure=True)

    events = list(in_memory_storage.iter_events())
    assert len(events) == 1
    ev = events[0]
    assert ev["success"] is False
    assert ev["error"]["type"] == "RuntimeError"
    assert "simulated mission failure" in ev["error"]["message"]


# ---------- session_id consistency ---------------------------------------

async def test_multiple_missions_share_session_id(in_memory_storage):
    """All missions in one sitting share a session_id. This is what
    makes 'show me everything I did Tuesday evening' a single-key lookup."""
    for uid in ["04:00:00:01", "04:00:00:02", "04:00:00:03"]:
        await mission_audit_smoketest(fake_uid=uid)

    events = list(in_memory_storage.iter_events())
    assert len(events) == 3
    session_ids = {ev["session_id"] for ev in events}
    assert len(session_ids) == 1, f"sessions diverged: {session_ids}"
    assert session_ids == {"test-session-fixed-id"}


async def test_event_ids_are_distinct(in_memory_storage):
    for uid in ["04:00:00:01", "04:00:00:02", "04:00:00:03"]:
        await mission_audit_smoketest(fake_uid=uid)
    events = list(in_memory_storage.iter_events())
    event_ids = {ev["event_id"] for ev in events}
    assert len(event_ids) == 3, f"duplicate event_ids: {event_ids}"
