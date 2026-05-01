"""interpret() — turns audit events into human narratives.

Plain English: pull events from storage, figure out what category of mission
they were, load the right knowledge file + audience template, assemble a
prompt, and either:
  - 'inline' backend: return the assembled prompt for the current Claude in
    chat to use as context for its reply (free, contextual)
  - 'openrouter' backend: send to xiaomi/mimo-v2.5-pro and return the
    finished narrative string (costs cents, works headless)

The knowledge files (interpreter/knowledge/*.md) are field guides — read by
Claude/MiMo, not executed. Grow them over time as you encounter new tag
types or signal patterns.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Iterable, Optional

from ..audit.storage import get_storage

log = logging.getLogger("llmdr_redteam.interpreter")


# ---------- mission category routing -------------------------------------
# Maps mission_name -> set of knowledge files to load. Triage loads multiple
# because it crosses sensor boundaries by definition.

CATEGORY_KNOWLEDGE: dict[str, list[str]] = {
    "audit_smoketest":     ["nfc"],     # smoketest pretends to be NFC
    "unknown_identify":    ["triage", "nfc", "rfid", "subghz", "ir"],
    "nfc_capture":         ["nfc"],
    "nfc_clone":           ["nfc"],
    "nfc_emulate":         ["nfc"],
    "nfc_mfkey32":         ["nfc"],
    "rfid_clone":          ["rfid"],
    "rfid_brute":          ["rfid"],
    "subghz_replay":       ["subghz"],
    "subghz_jam":          ["subghz"],
    "ir_replay":           ["ir"],
    "ir_brute":            ["ir"],
    "badusb":              ["badusb"],
}


# Fingerprint-driven knowledge: when an event's outputs include a
# system_fingerprint (set by detect_card_system in the parser), load the
# matching vendor knowledge file ON TOP of the mission category files.
# This is what makes "we've seen a Sandman keycard before" work — the
# narrative pulls vingcard.md automatically without the operator asking.

FINGERPRINT_KNOWLEDGE: dict[str, list[str]] = {
    "vingcard_visionline_likely": ["vingcard"],
    # Add new vendor fingerprints here as new knowledge files land.
    # 'saflok_likely':    ['saflok'],
    # 'salto_likely':     ['salto'],
    # 'dormakaba_likely': ['dormakaba'],
}


# ---------- file resolution ----------------------------------------------

_HERE = Path(__file__).parent
KNOWLEDGE_DIR = _HERE / "knowledge"
AUDIENCES_DIR = _HERE / "audiences"


def _read_md(path: Path) -> Optional[str]:
    """Read a markdown file. Return None silently if missing."""
    if not path.exists():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except OSError as e:
        log.warning("could not read %s: %s", path, e)
        return None


def _load_knowledge(mission_name: str) -> dict[str, str]:
    """Load all relevant knowledge files for a mission. Returns {name: content}."""
    keys = CATEGORY_KNOWLEDGE.get(mission_name, [])
    out: dict[str, str] = {}
    for key in keys:
        content = _read_md(KNOWLEDGE_DIR / f"{key}.md")
        if content is not None:
            out[key] = content
    return out


def _load_audience(audience: str) -> Optional[str]:
    """Load an audience template by name. Returns None if missing."""
    return _read_md(AUDIENCES_DIR / f"{audience}.md")


# ---------- prompt assembly ----------------------------------------------

def _format_event_for_prompt(ev: dict[str, Any]) -> str:
    """Trim an event to the fields a narrative actually needs.

    Drops noisy meta (schema_version, backfilled, raw transport details)
    and keeps the operationally relevant data.
    """
    keep = {
        "event_id":          ev.get("event_id"),
        "mission_name":      ev.get("mission_name"),
        "started_at":        ev.get("started_at"),
        "duration_ms":       ev.get("duration_ms"),
        "success":           ev.get("success"),
        "error":             ev.get("error"),
        "inputs":            ev.get("inputs"),
        "outputs":           ev.get("outputs"),
        "operator_note":     ev.get("operator_note"),
        "cross_link":        ev.get("cross_link"),
        "business_context":  ev.get("business_context"),
    }
    return json.dumps(keep, indent=2, default=str)


def _harvest_fingerprints(events: list[dict[str, Any]]) -> list[str]:
    """Walk events looking for system_fingerprint values to load extra
    knowledge files for. Searches outputs.detection.raw, outputs.raw,
    outputs.detections[*].raw."""
    seen: list[str] = []
    for ev in events:
        outputs = ev.get("outputs") or {}

        # Single-detection mission shape (nfc_capture etc.)
        det = outputs.get("detection") or {}
        raw = det.get("raw") or {}
        fp = raw.get("system_fingerprint")
        if fp and fp not in seen:
            seen.append(fp)

        # Multi-detection (triage) shape
        for d in outputs.get("detections") or []:
            r = (d or {}).get("raw") or {}
            fp = r.get("system_fingerprint")
            if fp and fp not in seen:
                seen.append(fp)
    return seen


def build_prompt(
    events: list[dict[str, Any]],
    audience: str,
    depth: str,
    focus: Optional[str],
) -> str:
    """Assemble the full prompt for the chosen backend.

    Returns a single string with four labelled sections:
      [knowledge] -- field guides for the relevant categories AND any
                     vendor fingerprints detected in the events
      [audience]  -- tone / length / what-to-include rules
      [events]    -- the actual data to interpret
      [task]      -- the specific ask
    """
    # Mission-category knowledge (loaded by mission_name)
    primary_mission = events[0]["mission_name"] if events else "audit_smoketest"
    knowledge = _load_knowledge(primary_mission)

    # Fingerprint-driven knowledge: vendor-specific files when the parser
    # already auto-detected the system. Loaded on top of category knowledge.
    for fp in _harvest_fingerprints(events):
        for fname in FINGERPRINT_KNOWLEDGE.get(fp, []):
            if fname not in knowledge:
                content = _read_md(KNOWLEDGE_DIR / f"{fname}.md")
                if content:
                    knowledge[fname] = content

    audience_text = _load_audience(audience) or (
        f"# Audience: {audience}\n\n(no template found — using a neutral default tone)"
    )

    parts: list[str] = []

    parts.append("# [knowledge] — field guides for this mission category\n")
    if knowledge:
        for name, content in knowledge.items():
            parts.append(f"## {name}\n\n{content}\n")
    else:
        parts.append("(no knowledge files matched this mission — interpret from events alone)\n")

    parts.append("\n# [audience] — how to talk to this listener\n")
    parts.append(audience_text)

    parts.append("\n\n# [events] — what just happened\n")
    parts.append(f"depth={depth}" + (f", focus={focus}" if focus else ""))
    parts.append("\n")
    for i, ev in enumerate(events, 1):
        parts.append(f"## event {i}\n```json\n{_format_event_for_prompt(ev)}\n```\n")

    parts.append("\n# [task]\n")
    parts.append(
        "Write the narrative for the audience above, at the requested depth, "
        "drawing on the knowledge files. Lead with the answer. Cite specific "
        "values from the events (UID, ATQA/SAK, freq, protocol) so it's clearly "
        "this event being described, not a generic explanation. If the event "
        "shows a failure, explain what went wrong in plain English. "
        "If a system_fingerprint and security_score are present in the event, "
        "include the 1-5 security rating in the narrative — operators find "
        "this scale immediately useful."
    )
    if focus:
        parts.append(f"\nFocus on: {focus}.")

    return "\n".join(parts)


# ---------- backends ------------------------------------------------------

def _backend_inline(prompt: str) -> str:
    """The 'inline' backend just returns the assembled prompt.

    The current Claude in chat reads it as context and synthesizes the
    narrative in its reply. No API call. Free.
    """
    return prompt


def _backend_openrouter(prompt: str, model: str = "xiaomi/mimo-v2.5-pro") -> str:
    """Send to OpenRouter and return the finished narrative string."""
    import urllib.request
    import urllib.error

    api_key = os.environ.get("OPENROUTER_KEY") or os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "openrouter backend requires OPENROUTER_KEY env var "
            "(or OPENROUTER_API_KEY). Use backend='inline' to skip the API."
        )

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You translate radio mission audit events into human narratives. Follow the audience template and use the knowledge files as your source of fact."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 2000,
        "temperature": 0.4,
        "reasoning": {"exclude": True},
    }
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/innov8ideas4u-alt/LLMDR_redteam",
            "X-Title": "LLMDR Redteam Interpreter",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"openrouter HTTP {e.code}: {body}") from e

    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError(f"openrouter returned no choices: {data!r}")
    msg = choices[0].get("message") or {}
    content = msg.get("content") or msg.get("reasoning") or msg.get("reasoning_content")
    if not content:
        raise RuntimeError(f"openrouter returned empty content: {msg!r}")
    return content


# ---------- public entry point -------------------------------------------

def interpret(
    event_ids: Iterable[str],
    audience: str = "operator",
    depth: str = "medium",
    focus: Optional[str] = None,
    backend: str = "inline",
) -> str:
    """Render one or more audit events as a human narrative.

    Args:
        event_ids: One or more audit event_ids to interpret.
        audience:  'operator' | 'member' | 'student' | 'instructor' | 'screen'
        depth:     'headline' | 'medium' | 'deep_dive'
        focus:     Optional aspect to emphasize (e.g. 'security_implications')
        backend:   'inline' (returns assembled prompt for current Claude)
                   or 'openrouter' (calls API, returns finished narrative)

    Returns:
        For 'inline': the assembled prompt. The current Claude in chat reads
        this as context and writes the narrative in its reply.
        For 'openrouter': the model's narrative string.

    Raises:
        ValueError if event_ids is empty or any id can't be found in storage.
        RuntimeError if backend='openrouter' and no API key is configured.
    """
    ids = list(event_ids)
    if not ids:
        raise ValueError("interpret() requires at least one event_id")

    storage = get_storage()
    events: list[dict[str, Any]] = []
    missing: list[str] = []
    for eid in ids:
        ev = storage.get(eid)
        if ev is None:
            missing.append(eid)
        else:
            events.append(ev)
    if missing:
        raise ValueError(
            f"event_id(s) not found in storage: {missing}"
        )

    prompt = build_prompt(events, audience=audience, depth=depth, focus=focus)

    if backend == "inline":
        return _backend_inline(prompt)
    if backend == "openrouter":
        return _backend_openrouter(prompt)
    raise ValueError(
        f"unknown backend {backend!r}; use 'inline' or 'openrouter'"
    )
