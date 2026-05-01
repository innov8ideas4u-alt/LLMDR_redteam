"""Tests for the NFC file parser. No hardware needed — these are pure parse
tests against canned firmware output.

Real-hardware tests live in tests/hardware/ and are skipped by default.
"""

import pytest

from llmdr_redteam.missions.nfc_backend import (
    parse_nfc_file, ATQA_SAK_FAMILY, NFCCardData,
)


# Real Flipper firmware output for a Mifare Ultralight tap (sanitized UID)
# NOTE: The fixture below uses ATQA "00 44" (spec order). Real firmware
# actually writes ATQA in WIRE ORDER, e.g. "44 00". Both must classify
# correctly — see test_real_firmware_atqa_wire_order_classifies below.
ULTRALIGHT_FIXTURE = """\
Filetype: Flipper NFC device
Version: 4
Device type: NTAG215
UID: 04 A2 1B 5C DE AD BE
ATQA: 00 44
SAK: 00
Pages total: 135
Pages read: 135
Page 0: 04 A2 1B 5C
Page 1: DE AD BE 80
Page 2: 48 48 00 00
"""

# This is the actual byte-for-byte format the Flipper firmware produces
# (captured from a real NTAG216 on a Kiisu V4B, 2026-05-01). Note the
# wire-order ATQA ("44 00") — that's the bug the spec-order fixture
# above hides. Keep BOTH fixtures so we cover both byte orders forever.
REAL_NTAG216_FIXTURE = """\
Filetype: Flipper NFC device
Version: 2
Device type: NTAG216
UID: 04 85 92 8A A0 61 81
ATQA: 44 00
SAK: 00
Signature: 1B 84 EB 70 BD 4C BD 1B 1D E4 98 0B 18 58 BD 7C 72 85 B4 E4 7B 38 8E 96 CF 88 6B EE A3 43 AD 90
Mifare version: 00 04 04 02 01 00 13 03
Pages total: 231
Page 0: 04 39 91 24
Page 1: C2 FC 67 80
"""

CLASSIC_1K_FIXTURE = """\
Filetype: Flipper NFC device
Version: 4
Device type: Mifare Classic 1K
UID: 04 A2 1B 5C
ATQA: 00 04
SAK: 08
Block 0: 04 A2 1B 5C 48 08 04 00 62 63 64 65 66 67 68 69
Block 1: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Key A 0: FFFFFFFFFFFF
"""

DESFIRE_FIXTURE = """\
Filetype: Flipper NFC device
Version: 4
Device type: Mifare DESFire
UID: 04 12 34 56 78 9A BC
ATQA: 03 44
SAK: 20
"""

EMPTY_FIXTURE = """\
Filetype: Flipper NFC device
Version: 4
"""


# ---------- basic field extraction --------------------------------------

def test_parse_ultralight_extracts_uid():
    card = parse_nfc_file(ULTRALIGHT_FIXTURE)
    assert card.uid == "04 A2 1B 5C DE AD BE"


def test_parse_ultralight_extracts_atqa_sak():
    card = parse_nfc_file(ULTRALIGHT_FIXTURE)
    assert card.atqa == "00 44"
    assert card.sak == "00"


def test_parse_ultralight_extracts_device_type():
    card = parse_nfc_file(ULTRALIGHT_FIXTURE)
    assert card.device_type == "NTAG215"


def test_parse_classic_1k_all_fields():
    card = parse_nfc_file(CLASSIC_1K_FIXTURE)
    assert card.uid == "04 A2 1B 5C"
    assert card.atqa == "00 04"
    assert card.sak == "08"
    assert card.device_type == "Mifare Classic 1K"


# ---------- tentative_id mapping ----------------------------------------

def test_ultralight_tentative_id():
    card = parse_nfc_file(ULTRALIGHT_FIXTURE)
    assert card.tentative_id() == "mifare_ultralight_or_ntag21x"


def test_classic_1k_tentative_id():
    card = parse_nfc_file(CLASSIC_1K_FIXTURE)
    assert card.tentative_id() == "mifare_classic_1k"


def test_desfire_tentative_id():
    card = parse_nfc_file(DESFIRE_FIXTURE)
    assert card.tentative_id() == "mifare_desfire"


def test_empty_file_no_tentative_id():
    card = parse_nfc_file(EMPTY_FIXTURE)
    assert card.tentative_id() is None
    assert card.uid is None


# ---------- robustness --------------------------------------------------

def test_parse_handles_missing_atqa_or_sak():
    card = parse_nfc_file("UID: 04 A2 1B 5C\nDevice type: Unknown")
    assert card.uid == "04 A2 1B 5C"
    assert card.atqa is None
    assert card.tentative_id() is None  # can't classify without atqa+sak


def test_parse_ignores_unknown_keys():
    card = parse_nfc_file(
        "UID: 04 A2 1B 5C\n"
        "Some Future Field: weird value\n"
        "ATQA: 00 04\n"
        "SAK: 08\n"
    )
    assert card.uid == "04 A2 1B 5C"
    assert card.tentative_id() == "mifare_classic_1k"


def test_parse_keeps_raw_text():
    card = parse_nfc_file(ULTRALIGHT_FIXTURE)
    # raw_text preserved so callers can inspect everything if they want
    assert "Page 0: 04 A2 1B 5C" in card.raw_text


def test_parse_records_source_path_when_given():
    card = parse_nfc_file(ULTRALIGHT_FIXTURE, source_path="/ext/nfc/test.nfc")
    assert card.source_path == "/ext/nfc/test.nfc"


def test_parse_handles_blank_lines_and_comments():
    card = parse_nfc_file(
        "\n"
        "Filetype: Flipper NFC device\n"
        "\n"
        "UID: 04 A2 1B 5C\n"
        "ATQA: 00 04\n"
        "SAK: 08\n"
    )
    assert card.uid == "04 A2 1B 5C"
    assert card.tentative_id() == "mifare_classic_1k"


# ---------- canonicalization handoff ------------------------------------

def test_parsed_uid_canonicalizes_correctly():
    """The parser keeps the firmware's spaced format; the canonicalizer
    is responsible for collapsing it. End-to-end this means the cross_link
    in the audit event should be '04a21b5cdeadbe' even though the raw
    file contained '04 A2 1B 5C DE AD BE'."""
    from llmdr_redteam.audit.canonicalize import canonicalize_cross_link

    card = parse_nfc_file(ULTRALIGHT_FIXTURE)
    cl = canonicalize_cross_link("nfc_uid", card.uid)
    assert cl["value"] == "04a21b5cdeadbe"
    assert cl["raw"] == "04 A2 1B 5C DE AD BE"


# ---------- ATQA/SAK family table sanity --------------------------------

def test_family_table_entries_are_lowercase_normalized():
    """Every key in ATQA_SAK_FAMILY must be the canonical (atqa, sak) form
    we look up after normalization. Otherwise the table never matches."""
    from llmdr_redteam.missions.nfc_backend import _normalize_short_hex, _normalize_atqa
    for (atqa, sak), family in ATQA_SAK_FAMILY.items():
        assert atqa == _normalize_atqa(atqa), \
            f"family table key {atqa!r} not canonical for ATQA"
        assert sak == _normalize_short_hex(sak), \
            f"family table key {sak!r} not canonical for SAK"
        assert isinstance(family, str) and family


# ---------- THE byte-order test (caught with real hardware Day 4) -------

def test_real_firmware_atqa_wire_order_classifies():
    """Flipper firmware emits ATQA in wire order ('44 00' for an Ultralight),
    not spec order ('00 44'). The parser MUST identify it correctly anyway.

    This test exists because Day 4 hardware revealed the bug — the parser
    was originally key'd to '0044' but real files contained '44 00', so
    every Ultralight/NTAG would have come back unidentified."""
    card = parse_nfc_file(REAL_NTAG216_FIXTURE)
    assert card.uid == "04 85 92 8A A0 61 81"
    assert card.atqa == "44 00"   # raw firmware output preserved
    assert card.tentative_id() == "mifare_ultralight_or_ntag21x"
    assert card.device_type == "NTAG216"


def test_atqa_normalize_handles_both_byte_orders():
    """The parser's tentative_id() works regardless of byte order in the
    source file. Both spec order and wire order land on the same family."""
    from llmdr_redteam.missions.nfc_backend import _normalize_atqa

    # Spec order: '00 44' → '0044'
    assert _normalize_atqa("00 44") == "0044"
    # Wire order: '44 00' → '0044' (swapped to canonical)
    assert _normalize_atqa("44 00") == "0044"
    # Already canonical, no spaces
    assert _normalize_atqa("0044") == "0044"
    # 0x prefix tolerated
    assert _normalize_atqa("0x0044") == "0044"


def test_atqa_normalize_does_not_swap_when_both_bytes_nonzero():
    """If both bytes of ATQA are non-zero (rare but valid), don't swap.
    e.g. '03 44' (DESFire wire order) and '44 03' could both appear; we
    only swap when the trailing byte is zero (the unambiguous case)."""
    from llmdr_redteam.missions.nfc_backend import _normalize_atqa

    # Both non-zero: leave as-is (operator's table value should match)
    assert _normalize_atqa("03 44") == "0344"
