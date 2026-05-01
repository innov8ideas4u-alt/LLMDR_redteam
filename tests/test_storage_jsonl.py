"""Tests confirming JSONL backend round-trips events to disk and back."""

import asyncio
import json
import pytest

from llmdr_redteam.audit.storage import JSONLStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.missions import mission_audit_smoketest


@pytest.fixture
def jsonl_storage(tmp_path):
    path = tmp_path / "events.jsonl"
    storage = JSONLStorage(path)
    set_storage(storage)
    reset_session_id("jsonl-test-session")
    yield storage, path
    set_storage(None)


async def test_jsonl_writes_one_line_per_event(jsonl_storage):
    storage, path = jsonl_storage
    for uid in ["04:00:00:01", "04:00:00:02"]:
        await mission_audit_smoketest(fake_uid=uid)

    raw = path.read_text(encoding="utf-8").strip().split("\n")
    assert len(raw) == 2
    for line in raw:
        # Each line is valid JSON
        payload = json.loads(line)
        assert payload["mission_name"] == "audit_smoketest"


async def test_jsonl_iter_events_round_trips(jsonl_storage):
    storage, path = jsonl_storage
    await mission_audit_smoketest(fake_uid="04:A2:1B:5C")

    events = list(storage.iter_events())
    assert len(events) == 1
    assert events[0]["cross_link"]["value"] == "04a21b5c"


async def test_jsonl_get_by_event_id(jsonl_storage):
    storage, path = jsonl_storage
    await mission_audit_smoketest(fake_uid="04:A2:1B:5C")
    events = list(storage.iter_events())
    eid = events[0]["event_id"]

    fetched = storage.get(eid)
    assert fetched is not None
    assert fetched["event_id"] == eid


def test_jsonl_iter_skips_corrupt_lines(tmp_path):
    """A bad line in the middle shouldn't kill the whole iteration."""
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"event_id":"a","mission_name":"x"}\n'
        'not valid json\n'
        '{"event_id":"b","mission_name":"y"}\n',
        encoding="utf-8",
    )
    storage = JSONLStorage(path)
    events = list(storage.iter_events())
    assert len(events) == 2
    assert {e["event_id"] for e in events} == {"a", "b"}
