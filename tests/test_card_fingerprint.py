"""Tests for the auto-detection fingerprint system in nfc_backend.

The fingerprint detector identifies known card systems from their structure
(chip family + AUTH0 + OTP + payload entropy) so the interpreter can pull
in vendor-specific knowledge automatically without the operator asking.

Real-hardware fixtures from the Sandman keycard (VingCard) and the
RickRoll NTAG (NDEF URL) prove both the positive and negative paths.
"""

import pytest

from llmdr_redteam.missions.nfc_backend import (
    parse_nfc_file,
    detect_card_system,
    NFCCardData,
    _shannon_entropy,
    _hex_to_bytes,
)


# Real Sandman Hotels VingCard (UL EV1 UL11) — captured 2026-05-01.
# All five fingerprint markers should fire.
SANDMAN_FIXTURE = """\
Filetype: Flipper NFC device
Version: 4
Device type: NTAG/Ultralight
UID: 04 6D D7 0A 48 20 90
ATQA: 00 44
SAK: 00
Data format version: 2
NTAG/Ultralight type: Mifare Ultralight 11
Mifare version: 00 04 03 01 01 00 0B 03
Pages total: 20
Pages read: 16
Page 0: 04 6D D7 36
Page 1: 0A 48 20 90
Page 2: F2 48 08 00
Page 3: 17 0C 4D 15
Page 4: E5 1F D5 16
Page 5: BC D6 B0 8F
Page 6: D9 8E 8C 0F
Page 7: 47 4B 90 C2
Page 8: DE 79 F3 BD
Page 9: EC CA F4 8D
Page 10: 80 9A E2 6D
Page 11: B1 2B 83 93
Page 12: 83 8C 0E D0
Page 13: D5 4A B8 D5
Page 14: A3 18 B6 03
Page 15: A3 37 91 A4
Page 16: 00 00 00 10
Page 17: 80 00 00 00
Page 18: 00 00 00 00
Page 19: 00 00 00 00
"""


# Real RickRoll prank NTAG216 — captured 2026-05-01.
# NDEF URL marker should fire, NOT VingCard (different chip + low entropy).
RICKROLL_FIXTURE = """\
Filetype: Flipper NFC device
Version: 2
Device type: NTAG216
UID: 04 85 92 8A A0 61 81
ATQA: 44 00
SAK: 00
Mifare version: 00 04 04 02 01 00 13 03
Pages total: 231
Page 0: 04 39 91 24
Page 1: C2 FC 67 80
Page 2: D9 48 00 00
Page 3: E1 10 12 00
Page 4: 01 03 A0 0C
Page 5: 34 03 19 D1
Page 6: 01 15 55 04
Page 7: 79 6F 75 74
Page 8: 75 2E 62 65
Page 9: 2F 64 51 77
Page 10: 34 77 39 57
Page 11: 67 58 63 51
Page 12: FE 00 00 00
Page 13: 00 00 00 00
Page 14: 00 00 00 00
Page 15: 00 00 00 00
"""


# A factory-fresh blank — pages 4-15 all zero. Should NOT match VingCard.
BLANK_UL_FIXTURE = """\
Filetype: Flipper NFC device
Version: 4
Device type: NTAG/Ultralight
UID: 04 11 22 33 44 55 66
ATQA: 00 44
SAK: 00
NTAG/Ultralight type: Mifare Ultralight 11
Mifare version: 00 04 03 01 01 00 0B 03
Page 3: 00 00 00 00
Page 4: 00 00 00 00
Page 5: 00 00 00 00
Page 6: 00 00 00 00
Page 7: 00 00 00 00
Page 8: 00 00 00 00
Page 9: 00 00 00 00
Page 10: 00 00 00 00
Page 11: 00 00 00 00
Page 12: 00 00 00 00
Page 13: 00 00 00 00
Page 14: 00 00 00 00
Page 15: 00 00 00 00
Page 16: 00 00 00 00
"""


# ---------- helpers ------------------------------------------------------

def test_shannon_entropy_zero_for_constant():
    assert _shannon_entropy(b"\x00" * 32) == 0.0


def test_shannon_entropy_high_for_random_looking_data():
    # All distinct bytes -> entropy = log2(N)
    e = _shannon_entropy(bytes(range(32)))
    # 32 unique values, log2(32) = 5
    assert abs(e - 5.0) < 0.01


def test_hex_to_bytes_strips_separators():
    assert _hex_to_bytes("04 6D D7 0A") == bytes([0x04, 0x6D, 0xD7, 0x0A])
    assert _hex_to_bytes("04:6D:D7:0A") == bytes([0x04, 0x6D, 0xD7, 0x0A])
    assert _hex_to_bytes("046DD70A") == bytes([0x04, 0x6D, 0xD7, 0x0A])


def test_hex_to_bytes_returns_empty_on_garbage():
    assert _hex_to_bytes("") == b""
    assert _hex_to_bytes(None) == b""


# ---------- VingCard fingerprint -- the headline test -------------------

def test_sandman_card_classifies_as_vingcard():
    """The actual Sandman keycard MUST classify as vingcard_visionline_likely.
    This is the regression that proves the auto-detection works on the real
    card we built it for."""
    card = parse_nfc_file(SANDMAN_FIXTURE)
    assert card.system_fingerprint == "vingcard_visionline_likely"
    assert card.security_score == 3
    # Evidence list should explain WHY it matched
    assert len(card.fingerprint_evidence) >= 4
    joined = "\n".join(card.fingerprint_evidence).lower()
    assert "atqa" in joined
    assert "ul11" in joined or "ul ev1" in joined or "mifare version" in joined
    assert "auth0" in joined
    assert "otp" in joined
    assert "entropy" in joined


def test_sandman_uid_canonicalizes():
    """The UID should still canonicalize correctly even after fingerprinting."""
    card = parse_nfc_file(SANDMAN_FIXTURE)
    assert card.uid == "04 6D D7 0A 48 20 90"
    # via canonicalize_cross_link the value would be 046dd70a482090
    from llmdr_redteam.audit.canonicalize import canonicalize_cross_link
    cl = canonicalize_cross_link("nfc_uid", card.uid)
    assert cl["value"] == "046dd70a482090"


def test_sandman_otp_captured():
    """OTP page should be extracted as a separate field for fingerprint analysis."""
    card = parse_nfc_file(SANDMAN_FIXTURE)
    assert card.otp == "17 0C 4D 15"


def test_sandman_pages_captured():
    """All page values should be in card.pages dict for fingerprint analysis."""
    card = parse_nfc_file(SANDMAN_FIXTURE)
    assert card.pages.get(4) == "E5 1F D5 16"
    assert card.pages.get(15) == "A3 37 91 A4"
    assert card.pages.get(16) == "00 00 00 10"


def test_sandman_subtype_still_works_alongside_fingerprint():
    """Subtype-based tentative_id and fingerprint should both populate."""
    card = parse_nfc_file(SANDMAN_FIXTURE)
    assert card.tentative_id() == "mifare_ultralight_11"
    assert card.system_fingerprint == "vingcard_visionline_likely"


# ---------- NDEF URL fingerprint ----------------------------------------

def test_rickroll_classifies_as_ndef_url():
    """RickRoll tag has a clear NDEF URL record at page 4 onward.
    Should NOT match VingCard (low entropy + zeroed tail pages)."""
    card = parse_nfc_file(RICKROLL_FIXTURE)
    assert card.system_fingerprint == "ntag_ndef_url"
    assert card.security_score == 1


def test_rickroll_NOT_classified_as_vingcard():
    """Sanity check: a clearly-NDEF tag must not get tagged VingCard."""
    card = parse_nfc_file(RICKROLL_FIXTURE)
    assert card.system_fingerprint != "vingcard_visionline_likely"


# ---------- blank UL fingerprint ---------------------------------------

def test_blank_ul_classifies_as_blank():
    card = parse_nfc_file(BLANK_UL_FIXTURE)
    assert card.system_fingerprint == "ntag_blank"
    assert card.security_score == 1


def test_blank_ul_NOT_classified_as_vingcard():
    """The fingerprint must reject blank cards even though they're UL11."""
    card = parse_nfc_file(BLANK_UL_FIXTURE)
    assert card.system_fingerprint != "vingcard_visionline_likely"


# ---------- empty / minimal data ----------------------------------------

def test_empty_card_no_fingerprint():
    """A card with no payload data should not get any fingerprint."""
    card = parse_nfc_file(
        "Filetype: Flipper NFC device\nUID: 04 11 22 33\nATQA: 00 04\nSAK: 08\n"
    )
    assert card.system_fingerprint is None
    assert card.security_score is None


def test_classic_1k_no_vingcard_match():
    """A Classic 1K is not even close to UL11 chip — must not match VingCard."""
    classic_fixture = """\
Filetype: Flipper NFC device
Version: 4
Device type: Mifare Classic 1K
UID: 04 A2 1B 5C
ATQA: 00 04
SAK: 08
Block 0: 04 A2 1B 5C 48 08 04 00 62 63 64 65 66 67 68 69
"""
    card = parse_nfc_file(classic_fixture)
    assert card.system_fingerprint != "vingcard_visionline_likely"


# ---------- detect_card_system idempotence ------------------------------

def test_detect_can_be_called_directly():
    """detect_card_system can be re-run on an already-parsed card without
    breaking. Used when something amends pages after initial parse."""
    card = parse_nfc_file(SANDMAN_FIXTURE)
    assert card.system_fingerprint == "vingcard_visionline_likely"
    # Re-run idempotently
    detect_card_system(card)
    assert card.system_fingerprint == "vingcard_visionline_likely"
    assert card.security_score == 3
