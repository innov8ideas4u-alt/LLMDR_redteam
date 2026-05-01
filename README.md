# LLMDR Red Team

Adversarial mission catalog for Flipper-compatible devices (Kiisu V4B, etc.),
sibling to [LLMDR_app](../LLMDR) which handles reconnaissance.

## What's different from the recon arm

- **Same** transport, same RPC, same memory store (pgvector)
- **Different** mission set: clone, emulate, replay, brute, BadUSB, triage
- **New** infrastructure:
  - **Single-write append-only audit log** — every mission emits one event to
    `events/all/{event_id}` in pgvector. Redteam audit and EDGE makerspace
    operations (fob ledger, door blacklist) are *views* over the same log,
    not separate writes.
  - **Canonicalizer** — radio identifiers are normalized at the schema layer,
    not in mission code. `04:A2:1B:5C` and `04a21b5c` always join cleanly.
  - **Status-emit hook** — every mission publishes live status updates
    (no-op publisher in v0.1, real pgvector / Kiisu screen consumers later).
  - **Interpreter layer** — turns raw event data into human narratives, with
    audience-aware templates (operator / member / student / instructor / screen).

## Status

**v0.1 in active build.** See `docs/PLAN.md` for the day-by-day plan.

Day 2 (today): scaffolding + canonicalizer + decorator + smoketest. Zero hardware.
Day 3: triage mission + first interpreter pass.

## Install (dev)

```bash
# from this directory
pip install -e ../flippermcp
pip install -e .[dev]
pytest
```

## Scope

Authorized testing only — operator's own hardware, classroom CTFs, paid red-team
engagements with written authorization. The audit log is operational data, not
safety theater. Compliance is the operator's responsibility.

## License

MIT
