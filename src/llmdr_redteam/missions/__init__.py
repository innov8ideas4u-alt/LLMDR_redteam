"""Mission catalog package.

Day 2: audit_smoketest (no hardware, exercises the audit pipeline).
Day 3: unknown_identify (the triage sweep — first user-facing mission).
Day 4: NFC family begins (capture/parse/fingerprint).
Day 5: nfc_mfkey32 (host-side Crypto-1 key recovery, no hardware).
Day 5+: NFC clone-write, emulate; RFID family.
"""

from .audit_smoketest import mission_audit_smoketest
from .nfc_mfkey32 import mission_nfc_mfkey32
from .unknown_identify import mission_unknown_identify

__all__ = [
    "mission_audit_smoketest",
    "mission_nfc_mfkey32",
    "mission_unknown_identify",
]
