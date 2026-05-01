"""Tests for the canonicalizer — silent-failure killer.

These tests are the foundation. If canonicalization is wrong, every
operations query silently misses results. Test ruthlessly.
"""

import pytest

from llmdr_redteam.audit.canonicalize import (
    canonicalize_cross_link,
    CanonicalizeError,
    NFC_UID, RFID_EM4100, RFID_T5577, IBUTTON, SUBGHZ_SIGNAL, IR_PROTOCOL, HOST,
)


# ---------- NFC UID — variable length, hex, no separators ----------------

@pytest.mark.parametrize("raw", [
    "04:A2:1B:5C",
    "04-A2-1B-5C",
    "04 A2 1B 5C",
    "04A21B5C",
    "04a21b5c",
    "  04:a2:1b:5c  ",
])
def test_nfc_uid_4byte_variants_canonicalize_identically(raw):
    """The whole point: every 'flavor' of writing the same UID lands on
    the same canonical value. This is the join-doesn't-silently-miss test."""
    result = canonicalize_cross_link(NFC_UID, raw)
    assert result["type"] == NFC_UID
    assert result["value"] == "04a21b5c"
    assert result["raw"] == raw  # debug trail preserved


def test_nfc_uid_7byte():
    """Mifare Ultralight / DESFire UIDs are 7 bytes."""
    r = canonicalize_cross_link(NFC_UID, "04:A2:1B:5C:DE:AD:BE")
    assert r["value"] == "04a21b5cdeadbe"


def test_nfc_uid_rejects_odd_hex_length():
    with pytest.raises(CanonicalizeError, match="odd hex length"):
        canonicalize_cross_link(NFC_UID, "04A21B5")


def test_nfc_uid_rejects_non_hex():
    # 'xyz pq' contains zero hex characters
    with pytest.raises(CanonicalizeError, match="no hex digits"):
        canonicalize_cross_link(NFC_UID, "xyz pq")


def test_nfc_uid_rejects_text_with_some_hex_as_odd_length():
    # 'hello' has e, d, e — three hex digits, odd length -> different error
    with pytest.raises(CanonicalizeError, match="odd hex length"):
        canonicalize_cross_link(NFC_UID, "hello")


def test_nfc_uid_rejects_non_string():
    with pytest.raises(CanonicalizeError, match="expected string"):
        canonicalize_cross_link(NFC_UID, 12345)


# ---------- RFID EM4100 — must be exactly 5 bytes ------------------------

def test_rfid_em4100_canonical():
    r = canonicalize_cross_link(RFID_EM4100, "DE:AD:BE:EF:01")
    assert r["value"] == "deadbeef01"


def test_rfid_em4100_wrong_length_rejected():
    with pytest.raises(CanonicalizeError, match="expected 5 bytes"):
        canonicalize_cross_link(RFID_EM4100, "DE:AD:BE:EF")


# ---------- RFID T5577 — must be exactly 8 bytes -------------------------

def test_rfid_t5577_canonical():
    r = canonicalize_cross_link(RFID_T5577, "00 11 22 33 44 55 66 77")
    assert r["value"] == "0011223344556677"


def test_rfid_t5577_wrong_length_rejected():
    with pytest.raises(CanonicalizeError, match="expected 8 bytes"):
        canonicalize_cross_link(RFID_T5577, "0011223344")


# ---------- iButton — Dallas 8 bytes -------------------------------------

def test_ibutton_canonical():
    r = canonicalize_cross_link(IBUTTON, "01:DE:AD:BE:EF:00:00:55")
    assert r["value"] == "01deadbeef000055"


# ---------- SubGHz signal — compound (freq, mod, proto) ------------------

def test_subghz_signal_from_tuple():
    r = canonicalize_cross_link(SUBGHZ_SIGNAL, (433920000, "AM650", "Princeton"))
    assert r["value"] == "433920000:AM650:Princeton"


def test_subghz_signal_from_dict():
    r = canonicalize_cross_link(SUBGHZ_SIGNAL, {
        "freq_hz": 315000000,
        "modulation": "AM270",
        "protocol": "CAME",
    })
    assert r["value"] == "315000000:AM270:CAME"


def test_subghz_signal_freq_int_coercion():
    r = canonicalize_cross_link(SUBGHZ_SIGNAL, ("433920000", "AM650", "Princeton"))
    assert r["value"] == "433920000:AM650:Princeton"


def test_subghz_signal_rejects_zero_freq():
    with pytest.raises(CanonicalizeError, match="freq_hz must be > 0"):
        canonicalize_cross_link(SUBGHZ_SIGNAL, (0, "AM650", "Princeton"))


def test_subghz_signal_rejects_empty_proto():
    with pytest.raises(CanonicalizeError, match="cannot be empty"):
        canonicalize_cross_link(SUBGHZ_SIGNAL, (433920000, "AM650", ""))


def test_subghz_signal_rejects_bad_shape():
    with pytest.raises(CanonicalizeError, match="expected dict or 3-tuple"):
        canonicalize_cross_link(SUBGHZ_SIGNAL, "433920000")


# ---------- IR protocol --------------------------------------------------

def test_ir_protocol_from_tuple_with_hex_strings():
    r = canonicalize_cross_link(IR_PROTOCOL, ("NEC", "0x20DF", "0x10EF"))
    assert r["value"] == "NEC:0x20df:0x10ef"


def test_ir_protocol_from_dict_with_ints():
    r = canonicalize_cross_link(IR_PROTOCOL, {
        "protocol": "Sony",
        "address": 0x01,
        "command": 0x15,
    })
    # leading zeros stripped for ints
    assert r["value"] == "Sony:0x1:0x15"


def test_ir_protocol_strips_leading_zeros():
    r = canonicalize_cross_link(IR_PROTOCOL, ("RC5", "0x0001", "0x000F"))
    assert r["value"] == "RC5:0x1:0xf"


def test_ir_protocol_rejects_negative_int():
    with pytest.raises(CanonicalizeError, match="must be non-negative"):
        canonicalize_cross_link(IR_PROTOCOL, ("NEC", -1, 0))


# ---------- HOST ---------------------------------------------------------

def test_host_lowercased():
    r = canonicalize_cross_link(HOST, "LAB-VM-3")
    assert r["value"] == "lab-vm-3"


def test_host_strips_whitespace():
    r = canonicalize_cross_link(HOST, "  Lab.Internal  ")
    assert r["value"] == "lab.internal"


def test_host_rejects_empty():
    with pytest.raises(CanonicalizeError, match="empty hostname"):
        canonicalize_cross_link(HOST, "   ")


# ---------- unsupported types --------------------------------------------

def test_unsupported_type_raises():
    with pytest.raises(CanonicalizeError, match="unsupported link_type"):
        canonicalize_cross_link("zigbee_eui64", "00:11:22:33:44:55:66:77")


# ---------- the BIG one: same canonical form, different inputs -----------

def test_same_canonical_value_for_all_nfc_flavors():
    """The point of canonicalization in one test. If this passes, the
    cross-history join doesn't silently miss."""
    flavors = [
        "04:A2:1B:5C",
        "04A21B5C",
        "04 a2 1b 5c",
        "04-a2-1B-5C",
        "  04:A2:1B:5C  ",
    ]
    values = {canonicalize_cross_link(NFC_UID, f)["value"] for f in flavors}
    assert values == {"04a21b5c"}, f"flavors diverged: {values}"
