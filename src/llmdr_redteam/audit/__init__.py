"""Audit subsystem — single-write append-only log + canonicalizer + status emit + blacklist fold."""

from .schema import AuditEvent, BusinessContext, CrossLink, ScreenNarrative, SCHEMA_VERSION
from .canonicalize import canonicalize_cross_link, CanonicalizeError
from .decorator import audit_logged
from .status_emit import status_emit, set_publisher, NoOpPublisher

__all__ = [
    "AuditEvent",
    "BusinessContext",
    "CrossLink",
    "ScreenNarrative",
    "SCHEMA_VERSION",
    "canonicalize_cross_link",
    "CanonicalizeError",
    "audit_logged",
    "status_emit",
    "set_publisher",
    "NoOpPublisher",
]
