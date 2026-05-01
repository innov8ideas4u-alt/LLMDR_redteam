"""Tests for status_emit — the mic-in-every-mission hook."""

import pytest

from llmdr_redteam.audit.status_emit import (
    status_emit, set_publisher, get_publisher, NoOpPublisher,
)


def test_default_publisher_is_noop():
    """Out of the box, no real publisher is set. NoOp should be in place."""
    set_publisher(None)  # ensure default
    assert isinstance(get_publisher(), NoOpPublisher)


def test_status_emit_with_noop_publisher_does_not_raise():
    set_publisher(None)
    status_emit("event-id-123", "starting up")
    status_emit("event-id-123", "halfway", progress=0.5, stage="auth")


def test_set_publisher_swaps():
    """A custom publisher should receive every emit."""
    captured = []

    def my_publisher(event_id, message, **fields):
        captured.append({"event_id": event_id, "message": message, **fields})

    set_publisher(my_publisher)
    try:
        status_emit("e1", "hello")
        status_emit("e1", "with fields", progress=0.42, stage="read")
    finally:
        set_publisher(None)

    assert len(captured) == 2
    assert captured[0] == {"event_id": "e1", "message": "hello"}
    assert captured[1] == {
        "event_id": "e1", "message": "with fields",
        "progress": 0.42, "stage": "read",
    }


def test_publisher_exception_is_swallowed():
    """A broken publisher must NEVER propagate to the mission."""
    def broken(event_id, message, **fields):
        raise RuntimeError("publisher exploded")

    set_publisher(broken)
    try:
        # Should not raise
        status_emit("e1", "hi")
    finally:
        set_publisher(None)
