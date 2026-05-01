"""@audit_logged — the wrapper every mission inherits.

Plain English: you write a normal mission as a coroutine. You decorate it
with @audit_logged(mission_name='nfc_clone', mission_version='0.1.0').
The wrapper handles ALL of this for you, automatically:

  1. Mints a uuid7 event_id (time-sortable)
  2. Resolves a session_id (env var or process-global default)
  3. Captures started_at, hardware metadata
  4. Runs the mission, catches exceptions
  5. Captures ended_at, success/error
  6. Canonicalizes any cross-link the mission returned
  7. Writes the event to the configured storage — ONE write, ONE namespace
  8. Returns the mission's original return value to the caller

The mission only has to:
  - return a dict like {'outputs': {...}, 'cross_link': (type, raw)} (optional)
  - raise an exception on failure (or return success=False explicitly)
  - call status_emit(event_id, '...') for live progress (optional)

The decorator passes 'audit_event_id' as a kwarg into the mission so it
can use it for status_emit calls without having to mint one itself.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Optional

try:
    from uuid6 import uuid7
except ImportError:  # pragma: no cover
    # Fallback: uuid4 isn't time-sortable but works as a unique id.
    # We log a warning so the operator knows. Production should have uuid6.
    logging.getLogger("llmdr_redteam.audit").warning(
        "uuid6 not installed — falling back to uuid4 (event_ids won't be time-sortable). "
        "pip install uuid6"
    )
    def uuid7() -> uuid.UUID:  # type: ignore[misc]
        return uuid.uuid4()

from .canonicalize import canonicalize_cross_link, CanonicalizeError
from .schema import AuditEvent, BusinessContext, CrossLink, ScreenNarrative, SCHEMA_VERSION
from .storage import get_storage

log = logging.getLogger("llmdr_redteam.audit.decorator")


# ---------- session id management ----------------------------------------
# A "session" is one sitting — typically one Claude conversation, or one
# continuous block of operator work. All events from one session share a
# session_id so queries like "everything I did Tuesday evening" become a
# single-key lookup instead of a timestamp range.

_SESSION_ID: Optional[str] = None


def get_session_id() -> str:
    """Return the current session_id, minting one if needed.

    Honors the LLMDR_REDTEAM_SESSION_ID env var if set (lets external
    runners — e.g. an EDGE volunteer script — pin a session manually).
    """
    global _SESSION_ID
    if _SESSION_ID is not None:
        return _SESSION_ID
    env = os.environ.get("LLMDR_REDTEAM_SESSION_ID")
    if env:
        _SESSION_ID = env
    else:
        _SESSION_ID = str(uuid7())
    return _SESSION_ID


def reset_session_id(new_id: Optional[str] = None) -> str:
    """Set/reset the session_id. Mainly for tests and explicit session boundaries."""
    global _SESSION_ID
    _SESSION_ID = new_id if new_id is not None else str(uuid7())
    return _SESSION_ID


# ---------- operator id (default 'self') ---------------------------------

def get_operator_id() -> str:
    """Operator id — env-overridable, defaults to 'self'.

    For solo dev work this is just 'self'. For CTF / multi-operator setups,
    set LLMDR_REDTEAM_OPERATOR_ID in the environment.
    """
    return os.environ.get("LLMDR_REDTEAM_OPERATOR_ID", "self")


# ---------- hardware metadata (cached per session) -----------------------
# Pulled once per session and cached. The decorator passes the rpc/transport
# handle through the mission's kwargs (or via a thread-local — we use kwargs
# for now to keep things explicit and testable). If no rpc handle is present,
# hardware fields go through as None.

_HW_CACHE: dict[str, Any] = {}


def _hardware_metadata(rpc: Any) -> dict[str, Optional[str]]:
    """Best-effort hardware metadata pull. Cached per session.

    Returns dict with flipper_uid, flipper_firmware_version, transport,
    transport_addr — any of which may be None if the rpc handle doesn't
    expose them or no rpc was provided.
    """
    if rpc is None:
        return {
            "flipper_uid": None,
            "flipper_firmware_version": None,
            "transport": "none",
            "transport_addr": None,
        }
    cache_key = id(rpc)
    if cache_key in _HW_CACHE:
        return _HW_CACHE[cache_key]
    md = {
        "flipper_uid": _safe_attr(rpc, "device_uid"),
        "flipper_firmware_version": _safe_attr(rpc, "firmware_version"),
        "transport": _safe_attr(rpc, "transport_kind") or "unknown",
        "transport_addr": _safe_attr(rpc, "transport_addr"),
    }
    _HW_CACHE[cache_key] = md
    return md


def _safe_attr(obj: Any, name: str) -> Optional[str]:
    """Best-effort attribute pull. Returns None on any failure."""
    try:
        v = getattr(obj, name, None)
        if callable(v):
            v = v()
        return str(v) if v is not None else None
    except Exception:
        return None


# ---------- timing helpers -----------------------------------------------

def _now_iso() -> str:
    """UTC ISO 8601 with microsecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _ms_between(start_iso: str, end_iso: str) -> int:
    """Compute milliseconds between two ISO timestamps. Best-effort."""
    try:
        s = datetime.fromisoformat(start_iso)
        e = datetime.fromisoformat(end_iso)
        delta = (e - s).total_seconds() * 1000
        return int(round(delta))
    except Exception:
        return 0


# ---------- the decorator ------------------------------------------------

def audit_logged(
    *,
    mission_name: str,
    mission_version: str = "0.1.0",
):
    """Wrap a mission coroutine so every run produces a single audit event.

    Mission contract:
      - Coroutine: `async def mission(...)`
      - Receives an extra kwarg `audit_event_id` (for status_emit calls)
      - Should return either:
          * None / the bare result            -> auto outputs={}, no cross-link
          * A dict like:
              {
                'outputs': {...},                  # what the mission produced
                'cross_link': ('nfc_uid', '04:A2'),# OPTIONAL: (type, raw)
                'screen_narrative': {...},         # OPTIONAL: dict for ScreenNarrative
              }
      - Should accept these optional kwargs (decorator passes them through):
          * operator_note: Optional[str]
          * business_context: Optional[dict]   # plain dict, decorator wraps
          * parent_event_id: Optional[str]
          * rpc: Any  (transport handle for hardware metadata; optional)

    Errors raised by the mission become success=False events with the
    error captured. The exception is re-raised to the caller so they can
    handle it normally — auditing doesn't change control flow.
    """

    def decorator(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        if not inspect.iscoroutinefunction(fn):
            raise TypeError(
                f"@audit_logged requires an async function; "
                f"{fn.__qualname__} is sync"
            )

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            event_id = str(uuid7())
            session_id = get_session_id()
            started_at = _now_iso()

            # Decorator-only kwargs — pulled out before forwarding.
            operator_note = kwargs.pop("operator_note", None)
            business_context_raw = kwargs.pop("business_context", None)
            parent_event_id = kwargs.pop("parent_event_id", None)
            rpc = kwargs.get("rpc", None)  # peek, don't pop — mission likely needs it

            # Pass event_id INTO the mission so it can status_emit.
            kwargs["audit_event_id"] = event_id

            # Hardware metadata — best effort.
            hw = _hardware_metadata(rpc)

            inputs_snapshot = _capture_inputs(fn, args, kwargs)

            outputs: dict[str, Any] = {}
            cross_link: Optional[CrossLink] = None
            screen_narrative: Optional[ScreenNarrative] = None
            success = False
            error: Optional[dict[str, str]] = None
            mission_return: Any = None

            try:
                mission_return = await fn(*args, **kwargs)
                success = True
                outputs, cross_link, screen_narrative = _interpret_return(mission_return)
            except Exception as e:
                error = {
                    "type": type(e).__name__,
                    "message": str(e),
                }
                # Re-raise after we record. Auditing never swallows.
                raise
            finally:
                ended_at = _now_iso()
                # Wrap business_context dict into the dataclass if provided
                bc: Optional[BusinessContext] = None
                if business_context_raw is not None:
                    try:
                        bc = BusinessContext(**business_context_raw)
                    except Exception as bce:
                        log.warning(
                            "business_context malformed for event %s: %s — dropping",
                            event_id, bce,
                        )

                event = AuditEvent(
                    event_id=event_id,
                    schema_version=SCHEMA_VERSION,
                    mission_name=mission_name,
                    mission_version=mission_version,
                    operator_id=get_operator_id(),
                    session_id=session_id,
                    started_at=started_at,
                    ended_at=ended_at,
                    duration_ms=_ms_between(started_at, ended_at),
                    flipper_uid=hw["flipper_uid"],
                    flipper_firmware_version=hw["flipper_firmware_version"],
                    transport=hw["transport"],
                    transport_addr=hw["transport_addr"],
                    inputs=inputs_snapshot,
                    outputs=outputs,
                    success=success,
                    error=error,
                    operator_note=operator_note,
                    cross_link=cross_link,
                    parent_event_id=parent_event_id,
                    business_context=bc,
                    backfilled=False,
                    screen_narrative=screen_narrative,
                )
                try:
                    get_storage().write(event.to_dict())
                except Exception:
                    # Audit-log failures must NOT mask mission outcomes.
                    log.exception(
                        "FAILED to write audit event %s for mission %s",
                        event_id, mission_name,
                    )

            return mission_return

        # Tag the wrapper for introspection / dispatch
        wrapper.__audit_mission_name__ = mission_name      # type: ignore[attr-defined]
        wrapper.__audit_mission_version__ = mission_version  # type: ignore[attr-defined]
        return wrapper

    return decorator


# ---------- helpers ------------------------------------------------------

def _capture_inputs(fn: Callable, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Snapshot the mission's inputs. Best-effort, non-fatal on weird types.

    We bind args+kwargs to the function signature and stringify anything
    that isn't JSON-friendly. The audit_event_id we just injected is
    omitted (it's redundant with the event itself).
    """
    try:
        sig = inspect.signature(fn)
        bound = sig.bind_partial(*args, **kwargs)
    except TypeError:
        # Signature mismatch — fall back to raw kwargs only
        return {k: _jsonable(v) for k, v in kwargs.items() if k != "audit_event_id"}
    snapshot: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        if name in ("audit_event_id", "rpc"):
            # rpc handles aren't useful in inputs; transport is captured separately
            continue
        snapshot[name] = _jsonable(value)
    return snapshot


def _jsonable(v: Any) -> Any:
    """Make a value JSON-friendly for the inputs snapshot."""
    if isinstance(v, (str, int, float, bool, type(None))):
        return v
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    return repr(v)


def _interpret_return(ret: Any) -> tuple[dict[str, Any], Optional[CrossLink], Optional[ScreenNarrative]]:
    """Pull outputs / cross_link / screen_narrative out of a mission return value.

    Accepts:
      None                                          -> ({}, None, None)
      dict with optional keys                       -> use them
      anything else                                 -> outputs = {'result': ret}
    """
    if ret is None:
        return {}, None, None

    if isinstance(ret, dict):
        outputs = ret.get("outputs", {})
        if not isinstance(outputs, dict):
            outputs = {"value": _jsonable(outputs)}

        cl_raw = ret.get("cross_link")
        cross_link: Optional[CrossLink] = None
        if cl_raw is not None:
            try:
                if isinstance(cl_raw, CrossLink):
                    cross_link = cl_raw
                elif isinstance(cl_raw, (tuple, list)) and len(cl_raw) == 2:
                    link_type, raw = cl_raw
                    cl_dict = canonicalize_cross_link(link_type, raw)
                    cross_link = CrossLink(**cl_dict)
                elif isinstance(cl_raw, dict) and "type" in cl_raw and "raw" in cl_raw:
                    cl_dict = canonicalize_cross_link(cl_raw["type"], cl_raw["raw"])
                    cross_link = CrossLink(**cl_dict)
                else:
                    log.warning(
                        "cross_link in mission return has unsupported shape: %r — dropping",
                        cl_raw,
                    )
            except CanonicalizeError as ce:
                log.warning("cross_link canonicalize failed: %s — dropping", ce)

        sn_raw = ret.get("screen_narrative")
        screen_narrative: Optional[ScreenNarrative] = None
        if sn_raw is not None:
            try:
                if isinstance(sn_raw, ScreenNarrative):
                    screen_narrative = sn_raw
                elif isinstance(sn_raw, dict):
                    screen_narrative = ScreenNarrative(**sn_raw)
                else:
                    log.warning("screen_narrative shape not understood: %r", sn_raw)
            except Exception as e:
                log.warning("screen_narrative parse failed: %s", e)

        return outputs, cross_link, screen_narrative

    # Non-dict, non-None return — wrap it
    return {"result": _jsonable(ret)}, None, None
