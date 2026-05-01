"""Mission catalog package.

Day 2: audit_smoketest (no hardware, exercises the audit pipeline).
Day 3: unknown_identify (the triage sweep — first user-facing mission).
Day 4+: NFC family (clone, emulate, mfkey32) — real RPC.
Day 5+: RFID, iButton, SubGHz, IR, BadUSB.
"""

from .audit_smoketest import mission_audit_smoketest
from .unknown_identify import mission_unknown_identify

__all__ = [
    "mission_audit_smoketest",
    "mission_unknown_identify",
]
