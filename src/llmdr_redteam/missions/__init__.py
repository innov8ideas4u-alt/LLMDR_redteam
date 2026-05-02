"""Mission catalog package.

Day 2: audit_smoketest (no hardware, exercises the audit pipeline).
Day 3: unknown_identify (the triage sweep — first user-facing mission).
Day 4: NFC family begins (capture/parse/fingerprint).
Day 5: nfc_mfkey32 (host-side Crypto-1 key recovery, no hardware).
Day 5: nfc_emulate (Kiisu pretends to be a captured card, no tags needed).
Day 5: rfid_capture (125 kHz LF read, NO HARDWARE-VALIDATED YET).
Day 5+: NFC clone-write; rfid_clone, rfid_emulate.
"""

from .audit_smoketest import mission_audit_smoketest
from .nfc_emulate import mission_nfc_emulate
from .nfc_mfkey32 import mission_nfc_mfkey32
from .rfid_capture import mission_rfid_capture
from .unknown_identify import mission_unknown_identify

__all__ = [
    "mission_audit_smoketest",
    "mission_nfc_emulate",
    "mission_nfc_mfkey32",
    "mission_rfid_capture",
    "mission_unknown_identify",
]
