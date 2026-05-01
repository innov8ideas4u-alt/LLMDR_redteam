# Knowledge: Triage / Multi-Sensor

> Used when the mission is `unknown_identify` — a sweep across all sensors.
> Tells the interpreter how to combine evidence from multiple sensors into
> one honest answer.

## How to combine evidence across sensors

When the triage mission returns detections from all five sensors, the
interpretation should follow this priority:

1. **If ANY sensor returned a positive detection with high confidence**:
   Lead with that. "This is an NFC card — Mifare Ultralight family."
2. **Acknowledge the sensors that came up empty BUT only if relevant**.
   "I checked RFID and iButton too — both clean, so it's not a 125 kHz fob
   or a Dallas key."
3. **Be honest about passive listens**. IR and SubGHz only catch active
   transmissions. If both came back empty, say so explicitly:
   *"I didn't see anything on IR or SubGHz, but those only catch active
   transmissions. If this is a remote control or fob, press a button while
   the Kiisu is near it and run triage again."*

## Confidence levels

Sensors report `confidence`: `high`, `medium`, or `low`.

- `high` for active scans that completed cleanly (NFC/RFID/iButton always
  high or absent — these are deterministic protocols)
- `medium` for passive listens that completed but found nothing (IR, SubGHz)
  — empty doesn't mean absent, just silent
- `low` for ambiguous results (e.g. SubGHz peak above noise floor but no
  protocol decoded)

The narrative should NEVER claim certainty above what the confidence supports.

## Common triage scenarios

**"Found NFC, nothing else"** — the most common case.
> "This is an NFC card. [details from nfc.md]. The other sensors came up
> clean, so it's not also storing a 125 kHz badge code or transmitting on
> SubGHz."

**"Found RFID (125 kHz), nothing else"** — older fob.
> "This is a 125 kHz RFID fob — no NFC chip, just the legacy LF coil.
> Common for older building access systems."

**"Found NFC AND RFID"** — dual-frequency card.
> "This card has BOTH NFC and 125 kHz RFID. Common for transitional access
> systems that have to support old + new readers, or multi-tenant buildings."

**"Nothing on active scans, IR/SubGHz idle"** — likely a passive remote.
> "Active scans found nothing. IR and SubGHz heard silence, but those need
> the device to transmit. If you're holding a remote, press a button while
> the Kiisu is near it and try triage again."

**"Nothing anywhere"** — actually nothing.
> "I didn't pick up signals on any sensor. This might be a non-RF object
> (mechanical key?), a Bluetooth device (we don't scan BT yet), or a card
> that needs to be brought closer (NFC range is ~3cm)."

## What triage does NOT identify

The Kiisu can't see:
- Bluetooth/BLE devices (different antenna purpose)
- WiFi (different chipset entirely)
- LoRa or 2.4 GHz proprietary radios
- UHF RFID (the 860–960 MHz inventory tags — Kiisu's CC1101 covers a
  different range)
- Active jamming or modulated wideband signals (noise-floor only)

The interpreter should mention these explicitly when triage comes up empty,
so the operator knows it's not a Kiisu failure — just a limitation.
