"""Tests for the interpreter — knowledge loading, prompt assembly, backends.

The 'inline' backend is testable without API keys. We verify:
  - Events are pulled from storage by id
  - Knowledge files for the right category load
  - Audience template loads
  - Prompt has all four sections labelled
  - Specific event values appear in the prompt (UID, mission_name)
  - Missing event_id raises ValueError
"""

import pytest

from llmdr_redteam.audit.storage import InMemoryStorage, set_storage
from llmdr_redteam.audit.decorator import reset_session_id
from llmdr_redteam.interpreter import interpret
from llmdr_redteam.interpreter.interpret import build_prompt, _load_knowledge, _load_audience
from llmdr_redteam.missions import mission_unknown_identify
from llmdr_redteam.missions.sensor_backends import (
    StubBackend, stub_nfc_negative, stub_nfc_ultralight,
    stub_rfid_negative, stub_ibutton_negative,
    stub_ir_passive_silent, stub_subghz_passive_silent,
)


@pytest.fixture
def storage():
    s = InMemoryStorage()
    set_storage(s)
    reset_session_id("interp-test-session")
    yield s
    set_storage(None)


def _ult_backends():
    return {
        "nfc":     StubBackend("nfc", stub_nfc_ultralight("04:A2:1B:5C:DE:AD:BE")),
        "rfid":    StubBackend("rfid", stub_rfid_negative()),
        "ibutton": StubBackend("ibutton", stub_ibutton_negative()),
        "ir":      StubBackend("ir", stub_ir_passive_silent()),
        "subghz":  StubBackend("subghz", stub_subghz_passive_silent()),
    }


# ---------- knowledge + audience loading --------------------------------

def test_load_knowledge_for_triage_includes_nfc():
    knowledge = _load_knowledge("unknown_identify")
    assert "triage" in knowledge
    assert "nfc" in knowledge
    # Sanity-check the content actually came through
    assert "ATQA" in knowledge["nfc"]


def test_load_knowledge_for_unmapped_mission_is_empty():
    """An unknown mission category just gets an empty dict — interpret falls
    back to event-only narrative without crashing."""
    knowledge = _load_knowledge("totally_made_up_mission")
    assert knowledge == {}


def test_load_audience_operator():
    text = _load_audience("operator")
    assert text is not None
    assert "operator" in text.lower()


def test_load_audience_unknown_returns_none():
    assert _load_audience("nonexistent_audience") is None


# ---------- prompt assembly ---------------------------------------------

async def test_build_prompt_contains_all_four_sections(storage):
    await mission_unknown_identify(backends=_ult_backends())
    ev = list(storage.iter_events())[0]
    prompt = build_prompt([ev], audience="operator", depth="medium", focus=None)

    assert "[knowledge]" in prompt
    assert "[audience]" in prompt
    assert "[events]" in prompt
    assert "[task]" in prompt


async def test_prompt_includes_specific_event_values(storage):
    """The prompt must cite the actual UID, not just talk about Ultralights
    in general. That's how the narrative ends up being about THIS event."""
    await mission_unknown_identify(backends=_ult_backends())
    ev = list(storage.iter_events())[0]
    prompt = build_prompt([ev], audience="operator", depth="medium", focus=None)

    assert "04a21b5cdeadbe" in prompt   # canonical UID
    assert "unknown_identify" in prompt  # mission name
    assert "mifare_ultralight_or_ntag21x" in prompt  # tentative_id


async def test_prompt_includes_focus_when_provided(storage):
    await mission_unknown_identify(backends=_ult_backends())
    ev = list(storage.iter_events())[0]
    prompt = build_prompt(
        [ev], audience="operator", depth="deep_dive",
        focus="security_implications",
    )
    assert "security_implications" in prompt


# ---------- interpret() inline backend ----------------------------------

async def test_interpret_inline_returns_full_prompt(storage):
    await mission_unknown_identify(backends=_ult_backends())
    ev_id = list(storage.iter_events())[0]["event_id"]

    result = interpret([ev_id], audience="operator", backend="inline")
    assert "[knowledge]" in result
    assert "[events]" in result
    assert "04a21b5cdeadbe" in result


async def test_interpret_missing_event_id_raises(storage):
    with pytest.raises(ValueError, match="not found in storage"):
        interpret(["does-not-exist"], audience="operator", backend="inline")


async def test_interpret_empty_event_list_raises(storage):
    with pytest.raises(ValueError, match="at least one event_id"):
        interpret([], audience="operator", backend="inline")


async def test_interpret_unknown_backend_raises(storage):
    await mission_unknown_identify(backends=_ult_backends())
    ev_id = list(storage.iter_events())[0]["event_id"]
    with pytest.raises(ValueError, match="unknown backend"):
        interpret([ev_id], backend="not_a_real_backend")


# ---------- multi-event interpretation ----------------------------------

async def test_interpret_multiple_events(storage):
    """Two triage events in one prompt — the narrative could compare them."""
    await mission_unknown_identify(backends=_ult_backends())
    await mission_unknown_identify(backends={
        "nfc": StubBackend("nfc", stub_nfc_negative()),
        "rfid": StubBackend("rfid", stub_rfid_negative()),
        "ibutton": StubBackend("ibutton", stub_ibutton_negative()),
        "ir": StubBackend("ir", stub_ir_passive_silent()),
        "subghz": StubBackend("subghz", stub_subghz_passive_silent()),
    })
    events = list(storage.iter_events())
    ids = [ev["event_id"] for ev in events]

    prompt = interpret(ids, audience="operator", backend="inline")
    assert "## event 1" in prompt
    assert "## event 2" in prompt


# ---------- inline backend with audit_smoketest -------------------------

async def test_interpret_works_for_smoketest_too(storage):
    """The category routing has audit_smoketest -> nfc, so even the
    Day-2 fake mission gets a sensible prompt."""
    from llmdr_redteam.missions import mission_audit_smoketest
    await mission_audit_smoketest(fake_uid="04:00:00:42")
    ev_id = list(storage.iter_events())[0]["event_id"]
    result = interpret([ev_id], audience="operator", backend="inline")
    assert "ATQA" in result   # nfc.md was loaded
    assert "04000042" in result  # canonical UID
