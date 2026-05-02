"""Cross-link canonicalizer.

Plain English: every radio identifier (NFC UID, RFID badge ID, SubGHz signal
fingerprint, IR protocol/address, hostname) gets normalized to ONE form before
it touches the audit log. So '04:A2:1B:5C' and '04a21b5c' and '04-A2-1B-5C'
all become '04a21b5c' and the cross-history join just works.

This is the most boring, most important module in the redteam app. If it's
wrong, every operations query silently misses results. Test it ruthlessly.

The decorator calls canonicalize_cross_link(...) at audit time. Mission code
returns whatever raw form it has on hand — separators, casing, padding don't
matter. The canonicalizer handles it.

Schema returned (matches CrossLink in schema.py):
    {
      "type":  "<one of the supported types>",
      "value": "<canonical form>",
      "raw":   "<what was passed in, str() of it for debug>",
    }
"""

from __future__ import annotations

import re
from typing import Any


class CanonicalizeError(ValueError):
    """Raised when a cross-link can't be normalized to a known form."""


# ---------- supported types ----------------------------------------------
# Add new radio identifier kinds here. Each gets a dedicated handler so the
# rules are explicit per type and we get sharp errors for malformed input
# instead of silent normalization that loses information.

NFC_UID = "nfc_uid"               # ISO14443 / 15693 — variable-length hex
RFID_EM4100 = "rfid_em4100"       # 125 kHz EM4100 — 5 bytes
RFID_T5577 = "rfid_t5577"         # 125 kHz T5577 — page-0 hash, 8 bytes
RFID_HID_PROX = "rfid_hid_prox"   # 125 kHz HID Prox / H10301 — variable bytes
                                   # (26-bit, 35-bit, 37-bit Wiegand variants
                                   # all fold into hex of varying length)
RFID_INDALA = "rfid_indala"       # 125 kHz Indala (26-bit, 224-bit) — variable
RFID_AWID = "rfid_awid"           # 125 kHz AWID — variable
RFID_GENERIC = "rfid_generic"     # 125 kHz family we recognized at the firmware
                                   # level but don't have a dedicated handler for
                                   # yet (Pyramid, Viking, Jablotron, Paradox,
                                   # IoProx, Nexwatch, Securakey, Gallagher,
                                   # FDX-A/B animal IDs, raw T5577 reads).
                                   # Variable-length hex.
IBUTTON = "ibutton"               # Dallas/1-wire — 8 bytes
SUBGHZ_SIGNAL = "subghz_signal"   # (freq_hz, modulation, protocol)
IR_PROTOCOL = "ir_protocol"       # (protocol, address, command)
HOST = "host"                     # BadUSB target — hostname/FQDN

SUPPORTED_TYPES = frozenset({
    NFC_UID,
    RFID_EM4100,
    RFID_T5577,
    RFID_HID_PROX,
    RFID_INDALA,
    RFID_AWID,
    RFID_GENERIC,
    IBUTTON,
    SUBGHZ_SIGNAL,
    IR_PROTOCOL,
    HOST,
})


# ---------- helpers ------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-f]+$")
_NON_HEX = re.compile(r"[^0-9a-fA-F]")


def _normalize_hex(raw: Any, *, expected_bytes: int | None = None,
                   type_label: str = "hex_id") -> str:
    """Strip separators, lowercase, optionally enforce byte length.

    Accepts str. Raises CanonicalizeError on anything else or on malformed input.
    """
    if not isinstance(raw, str):
        raise CanonicalizeError(
            f"{type_label}: expected string, got {type(raw).__name__}: {raw!r}"
        )
    cleaned = _NON_HEX.sub("", raw).lower()
    if not cleaned:
        raise CanonicalizeError(f"{type_label}: no hex digits in {raw!r}")
    if not _HEX_RE.match(cleaned):
        raise CanonicalizeError(f"{type_label}: malformed hex {raw!r} -> {cleaned!r}")
    if len(cleaned) % 2 != 0:
        raise CanonicalizeError(
            f"{type_label}: odd hex length ({len(cleaned)} chars) in {raw!r}"
        )
    if expected_bytes is not None and len(cleaned) != expected_bytes * 2:
        raise CanonicalizeError(
            f"{type_label}: expected {expected_bytes} bytes "
            f"({expected_bytes * 2} hex chars), got {len(cleaned) // 2} bytes "
            f"from {raw!r}"
        )
    return cleaned


def _normalize_host(raw: Any) -> str:
    """Lowercase a hostname. Strip whitespace. No FQDN inference."""
    if not isinstance(raw, str):
        raise CanonicalizeError(
            f"host: expected string, got {type(raw).__name__}: {raw!r}"
        )
    cleaned = raw.strip().lower()
    if not cleaned:
        raise CanonicalizeError(f"host: empty hostname in {raw!r}")
    return cleaned


def _normalize_subghz(raw: Any) -> str:
    """SubGHz signature: (freq_hz, modulation, protocol) -> 'freq:mod:proto'.

    Accepts:
      - tuple/list of (int_or_str, str, str)
      - dict with keys 'freq_hz', 'modulation', 'protocol'
    """
    if isinstance(raw, dict):
        try:
            freq = raw["freq_hz"]
            mod = raw["modulation"]
            proto = raw["protocol"]
        except KeyError as e:
            raise CanonicalizeError(
                f"subghz_signal: dict missing key {e!s}; need freq_hz, modulation, protocol"
            ) from None
    elif isinstance(raw, (tuple, list)) and len(raw) == 3:
        freq, mod, proto = raw
    else:
        raise CanonicalizeError(
            f"subghz_signal: expected dict or 3-tuple, got {raw!r}"
        )
    try:
        freq_int = int(freq)
    except (TypeError, ValueError):
        raise CanonicalizeError(
            f"subghz_signal: freq_hz must be int-coercible, got {freq!r}"
        ) from None
    if freq_int <= 0:
        raise CanonicalizeError(f"subghz_signal: freq_hz must be > 0, got {freq_int}")
    mod_s = str(mod).strip()
    proto_s = str(proto).strip()
    if not mod_s or not proto_s:
        raise CanonicalizeError(
            f"subghz_signal: modulation and protocol cannot be empty "
            f"({mod_s!r}, {proto_s!r})"
        )
    # Modulation/protocol kept case-as-given but stripped — these are short tokens
    # like 'AM650' or 'Princeton' where casing IS the canonical form per Flipper
    # firmware conventions.
    return f"{freq_int}:{mod_s}:{proto_s}"


def _normalize_ir(raw: Any) -> str:
    """IR signature: (protocol, address, command) -> 'protocol:addr:cmd'.

    Address and command are normalized as lowercase hex with '0x' prefix.
    Protocol kept case-as-given (e.g. 'NEC', 'Sony', 'RC5').
    """
    if isinstance(raw, dict):
        try:
            proto = raw["protocol"]
            addr = raw["address"]
            cmd = raw["command"]
        except KeyError as e:
            raise CanonicalizeError(
                f"ir_protocol: dict missing key {e!s}; need protocol, address, command"
            ) from None
    elif isinstance(raw, (tuple, list)) and len(raw) == 3:
        proto, addr, cmd = raw
    else:
        raise CanonicalizeError(
            f"ir_protocol: expected dict or 3-tuple, got {raw!r}"
        )
    proto_s = str(proto).strip()
    if not proto_s:
        raise CanonicalizeError(f"ir_protocol: protocol cannot be empty in {raw!r}")
    addr_s = _normalize_ir_value(addr, "address")
    cmd_s = _normalize_ir_value(cmd, "command")
    return f"{proto_s}:{addr_s}:{cmd_s}"


def _normalize_ir_value(v: Any, label: str) -> str:
    """IR addresses/commands: accept '0x20DF', '20DF', or int. Output '0x20df'."""
    if isinstance(v, int):
        if v < 0:
            raise CanonicalizeError(f"ir_protocol: {label} must be non-negative, got {v}")
        return f"0x{v:x}"
    if isinstance(v, str):
        s = v.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if not s or _NON_HEX.search(s):
            raise CanonicalizeError(f"ir_protocol: {label} not hex: {v!r}")
        # Strip leading zeros but keep at least one digit
        s = s.lstrip("0") or "0"
        return f"0x{s}"
    raise CanonicalizeError(f"ir_protocol: {label} must be int or str, got {v!r}")


# ---------- public entry point -------------------------------------------

def canonicalize_cross_link(link_type: str, raw: Any) -> dict:
    """Normalize a radio identifier into the canonical cross-link record.

    Args:
        link_type: One of SUPPORTED_TYPES (nfc_uid, rfid_em4100, etc.)
        raw:       Whatever the mission code has on hand. Tolerated:
                     - hex strings with any separator (':', '-', ' ')
                     - upper or lowercase
                     - tuples/lists for compound types (subghz, ir)
                     - dicts with documented keys for compound types

    Returns:
        {"type": link_type, "value": <canonical>, "raw": <str(raw)>}

    Raises:
        CanonicalizeError on any malformed or unsupported input. Never
        silently normalizes through ambiguity.
    """
    if link_type not in SUPPORTED_TYPES:
        raise CanonicalizeError(
            f"unsupported link_type {link_type!r}; "
            f"must be one of {sorted(SUPPORTED_TYPES)}"
        )

    if link_type == NFC_UID:
        # NFC UIDs are 4, 7, or 10 bytes per ISO14443. We don't enforce length
        # because the canonicalizer doesn't know the tag family yet — that's
        # downstream business. We just enforce hex-ness and even-length.
        value = _normalize_hex(raw, type_label="nfc_uid")
    elif link_type == RFID_EM4100:
        value = _normalize_hex(raw, expected_bytes=5, type_label="rfid_em4100")
    elif link_type == RFID_T5577:
        value = _normalize_hex(raw, expected_bytes=8, type_label="rfid_t5577")
    elif link_type == RFID_HID_PROX:
        # HID Prox variants (26-bit, 35-bit, 37-bit Wiegand) all serialize
        # to even-byte hex but at different lengths. Don't enforce length
        # — let the family fingerprint downstream interpret the bits.
        value = _normalize_hex(raw, type_label="rfid_hid_prox")
    elif link_type == RFID_INDALA:
        value = _normalize_hex(raw, type_label="rfid_indala")
    elif link_type == RFID_AWID:
        value = _normalize_hex(raw, type_label="rfid_awid")
    elif link_type == RFID_GENERIC:
        # Catch-all bucket for 125 kHz protocols without dedicated handlers
        # yet. Cross-links to other generic-bucket events of the same hex
        # value still work — just less specific than a typed link.
        value = _normalize_hex(raw, type_label="rfid_generic")
    elif link_type == IBUTTON:
        value = _normalize_hex(raw, expected_bytes=8, type_label="ibutton")
    elif link_type == SUBGHZ_SIGNAL:
        value = _normalize_subghz(raw)
    elif link_type == IR_PROTOCOL:
        value = _normalize_ir(raw)
    elif link_type == HOST:
        value = _normalize_host(raw)
    else:
        # Unreachable given the SUPPORTED_TYPES check, but defensive.
        raise CanonicalizeError(f"no handler for link_type {link_type!r}")

    return {
        "type": link_type,
        "value": value,
        "raw": str(raw),
    }
