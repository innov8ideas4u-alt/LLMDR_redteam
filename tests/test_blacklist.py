"""Tests for the blacklist rebuilder.

The blacklist is a CACHE OF A FOLD over the audit log. These tests
prove the fold logic is right and the atomic-swap write is safe.
"""

import asyncio
import pytest
from pathlib import Path

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.audit.blacklist import rebuild_blacklist_from_log, read_blacklist
from llmdr_redteam.missions import mission_audit_smoketest


@pytest.fixture
def storage_and_paths(tmp_path):
    storage = InMemoryStorage()
    set_storage(storage)
    reset_session_id("blacklist-test-session")
    blacklist_path = tmp_path / "door_blacklist_current.json"
    yield storage, blacklist_path
    set_storage(None)


async def _issue(member_id: str, tier: str = "maker"):
    await mission_audit_smoketest(
        fake_uid=f"04:00:00:{member_id[-2:].zfill(2)}",
        business_context={
            "domain": "edge",
            "action": "fob_issued",
            "member_id": member_id,
            "member_tier": tier,
            "reason": "test issuance",
        },
    )


async def _revoke(member_id: str):
    await mission_audit_smoketest(
        fake_uid=f"04:00:00:{member_id[-2:].zfill(2)}",
        business_context={
            "domain": "edge",
            "action": "fob_revoked",
            "member_id": member_id,
            "reason": "test revocation",
        },
    )


# ---------- empty log ----------------------------------------------------

async def test_empty_log_produces_empty_blacklist(storage_and_paths):
    storage, path = storage_and_paths
    result = rebuild_blacklist_from_log(blacklist_path=path)
    assert result.blacklisted_member_ids == []
    assert result.events_considered == 0
    assert result.generation == 1
    assert path.exists()


# ---------- happy path ---------------------------------------------------

async def test_issued_then_revoked_lands_on_blacklist(storage_and_paths):
    storage, path = storage_and_paths
    await _issue("m001")
    await _revoke("m001")

    result = rebuild_blacklist_from_log(blacklist_path=path)
    assert result.blacklisted_member_ids == ["m001"]
    assert result.events_considered == 2


async def test_issued_only_NOT_on_blacklist(storage_and_paths):
    storage, path = storage_and_paths
    await _issue("m002")

    result = rebuild_blacklist_from_log(blacklist_path=path)
    assert result.blacklisted_member_ids == []


async def test_revoked_then_reissued_NOT_on_blacklist(storage_and_paths):
    """Most-recent action wins. Revoke + re-issue = active again."""
    storage, path = storage_and_paths
    await _issue("m003")
    await _revoke("m003")
    await _issue("m003")  # re-issued

    result = rebuild_blacklist_from_log(blacklist_path=path)
    assert "m003" not in result.blacklisted_member_ids


async def test_multiple_members_independent(storage_and_paths):
    storage, path = storage_and_paths
    await _issue("alpha")
    await _issue("beta")
    await _issue("gamma")
    await _revoke("beta")  # only beta revoked

    result = rebuild_blacklist_from_log(blacklist_path=path)
    assert result.blacklisted_member_ids == ["beta"]


async def test_non_edge_events_ignored(storage_and_paths):
    storage, path = storage_and_paths
    # Plain mission with no business_context — must not affect blacklist
    await mission_audit_smoketest(fake_uid="04:00:00:99")
    await _issue("m004")
    await _revoke("m004")

    result = rebuild_blacklist_from_log(blacklist_path=path)
    assert result.blacklisted_member_ids == ["m004"]
    assert result.events_considered == 2  # the non-edge event was filtered out


# ---------- generation counter -------------------------------------------

async def test_generation_increments(storage_and_paths):
    storage, path = storage_and_paths
    await _issue("m005")

    r1 = rebuild_blacklist_from_log(blacklist_path=path)
    r2 = rebuild_blacklist_from_log(blacklist_path=path)
    r3 = rebuild_blacklist_from_log(blacklist_path=path)

    assert r1.generation < r2.generation < r3.generation


# ---------- read_blacklist round-trip -----------------------------------

async def test_read_blacklist_round_trip(storage_and_paths):
    storage, path = storage_and_paths
    await _issue("alpha")
    await _revoke("alpha")
    rebuild_blacklist_from_log(blacklist_path=path)

    payload = read_blacklist(path)
    assert payload["blacklisted_member_ids"] == ["alpha"]
    assert payload["generation"] >= 1


def test_read_blacklist_missing_file_returns_empty(tmp_path):
    """Reading before any rebuild gives a sensible empty record."""
    payload = read_blacklist(tmp_path / "does_not_exist.json")
    assert payload["blacklisted_member_ids"] == []
    assert payload["generation"] == 0


# ---------- time travel via as_of ----------------------------------------

async def test_as_of_excludes_later_events(storage_and_paths):
    """Pass as_of to fold only events up to a cutoff. (Time travel.)"""
    storage, path = storage_and_paths
    await _issue("m006")
    # Capture a cutoff between the two events
    midpoint_ev = list(storage.iter_events())[0]
    cutoff = midpoint_ev["ended_at"]
    await _revoke("m006")  # this event is AFTER cutoff

    # Without cutoff -> revoked, on blacklist
    result_now = rebuild_blacklist_from_log(blacklist_path=path)
    assert "m006" in result_now.blacklisted_member_ids

    # With as_of cutoff -> only the issuance was visible -> NOT on blacklist
    result_old = rebuild_blacklist_from_log(blacklist_path=path, as_of=cutoff)
    assert "m006" not in result_old.blacklisted_member_ids
