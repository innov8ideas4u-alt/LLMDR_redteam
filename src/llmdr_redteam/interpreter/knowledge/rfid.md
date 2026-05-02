# RFID 125 kHz — the older sibling of NFC

## What this is, in one paragraph

Before NFC (13.56 MHz) won the contactless wars, the 125 kHz LF
("low-frequency") family was everywhere. EM4100 stickers under cat
collars, T5577 fobs in apartment lobbies, HID Prox cards in office
buildings, Indala in legacy government installs. They're slower,
shorter-range, and almost universally insecure compared to NFC. They
are also still EVERYWHERE because replacement is expensive.

The Flipper Zero (and the Kiisu) have a dedicated 125 kHz coil
separate from the NFC antenna. The same hold-it-up-and-tap workflow
that works for NFC also works here, just on a different radio. The
Kiisu's RFID app reads, parses, and saves these cards to .rfid files.

## Why this matters (real-world stakes)

LF RFID is the easiest contactless attack surface in any modern
building. A ten-second swipe with a Kiisu near a target's pocket
captures most LF credentials cleanly. The captured ID can be
written to a $2 T5577 blank, and the blank opens whatever the
original opened.

Three stories that come up over and over:

**The forgotten parking garage fob.** Tenant lost theirs. Building
manager doesn't have spares because the original installer is gone.
Read with Kiisu, write to a T5577, replace the lost one in 90 seconds.
This is the #1 use case for everyday operators.

**The corporate office HID Prox.** "We use HID, that's secure right?"
Most HID Prox cards send a fixed 26-bit number with no auth. A read +
clone walks through the lobby. This is the demo that gets a security
budget approved.

**The pet microchip.** Same 125 kHz, same EM4xxx family. A vet
scanner reads the chip, the Kiisu can read the same chip. (Don't.
But you can.)

## The card families you will encounter

### EM4100 / EM4102 — the read-only baseline

**Frequency:** 125 kHz. **Memory:** 64 bits, factory-burned,
read-only. **What it broadcasts:** a 5-byte unique ID. **Auth:** none.
**Security score: 1/5.**

This is the "why does this still exist" card. It cannot be reprogrammed.
It cannot do crypto. It just shouts a fixed number when energized. Read
with Kiisu in 1 second. Cloning to T5577 is trivial. Use cases that
still ship in 2026: cheap door fobs, gym lockers, apartment buildings,
event wristbands.

If a triage hits EM4100, the answer to "is this clonable?" is always
yes, and the answer to "should it be securing anything important?" is
always no.

### T5577 — the universal writable blank

**Frequency:** 125 kHz. **Memory:** 7 blocks of 32 bits + config.
**What it does:** emulates other 125 kHz protocols by writing the
right bit pattern into its blocks. **Auth:** optional 32-bit password
(rarely used in the wild).

T5577 is what you write **to**, not what you find in the wild. It's the
"Magic blank" of the 125 kHz world — a Swiss Army knife that can
pretend to be EM4100, HID Prox, Indala, AWID, etc., as long as your
writer knows the right block configuration.

The Kiisu's RFID Write feature targets T5577 by default. Cost:
$1-3 each on AliExpress. Form factors: card, fob, sticker, glass capsule.

### HID Prox / Indala / AWID / Paradox — the legacy enterprise family

**Frequency:** 125 kHz. **Memory:** varies. **What they broadcast:**
formatted IDs (26-bit, 35-bit, 37-bit Wiegand variants). **Auth:**
none for HID Prox; Indala has weak XOR mangling; AWID similar.

These families are what's installed in 80% of mid-market US office
buildings. The 26-bit Wiegand HID Prox card in particular is everywhere
and 100% clonable. The Flipper community has pushed the Kiisu's HID
Prox support to the point where read+clone takes about as long as
EM4100. **Security score: 1/5 to 2/5** depending on whether the
backend system does any anti-cloning logic (most don't).

NOTE on EM4100 vs HID Prox confusion: both are 125 kHz, both broadcast
a fixed ID, but the *protocol on the wire* is different. The Kiisu
auto-detects, but a single .rfid file is one protocol. Operators
sometimes assume "125 kHz = EM4100" and get burned when they try to
clone an HID Prox card with EM4100 settings. Auto-detection prevents
this in our triage.

### EM4305 / EM4205 — read/write EM4xxx variant

**Frequency:** 125 kHz. **Memory:** 512 bits writable, password-protected.
**What it does:** like EM4100 but writable. **Auth:** 32-bit password.

Less common than T5577 in our region (Calgary makerspace experience
suggests 90% of writable LF blanks are T5577). Worth fingerprinting
because the read-back values look different.

### Microchip / FDX-B (animal ID) — same family, different UX

**Frequency:** 125-134 kHz. **What it broadcasts:** 15-digit ISO 11784
animal ID. **Auth:** none.

The Kiisu reads these. Operators occasionally encounter them when
sweeping unknown environments — pet collar tags, livestock ear tags.
Calling out so triage doesn't mis-label these as broken EM4100.

## Security scale summary

| Family             | Score | Why                                  |
|--------------------|-------|--------------------------------------|
| EM4100 / EM4102    | 1/5   | Fixed ID, no auth, read-only         |
| HID Prox 26-bit    | 1/5   | Fixed Wiegand, no auth               |
| Indala / AWID      | 2/5   | Weak XOR mangling, still clonable    |
| EM4305 (passworded)| 2/5   | Default password rarely changed      |
| T5577 (passworded) | 2/5   | Same                                 |
| HID iCLASS legacy  | 2/5   | Documented attacks, default keys     |
| HID iCLASS SE / SR | 4/5   | AES, properly deployed = strong      |
| HID Seos           | 5/5   | Modern AES, no documented breaks     |

The sub-2/5 entries are everywhere. The 4-5/5 entries are rare in
mid-market deployments — they cost more, install harder, and most
property managers don't know they exist.

## Mission catalog (Day 5+ targets)

This file ships ahead of the missions. The Kiisu has the radio. The
LLMDR_redteam mission catalog will grow these in order:

1. **mission_rfid_capture** — read whatever's nearby, save to /ext/rfid/.
   Mirrors mission_nfc_capture's pattern.
2. **mission_rfid_clone** — write a captured .rfid file to a T5577
   blank held to the Kiisu's coil.
3. **mission_rfid_emulate** — make the Kiisu pretend to be a captured
   card. Same JS-runtime pattern as nfc_emulate.
4. **mission_rfid_brute** — for HID Prox, walk through the 16M
   facility-code × 65k-card-id space against a target reader. Loud,
   slow, only for explicitly-authorized red-team work.

Everything will go through the same audit log + cross-link pipeline
as the NFC family. cross_link type for RFID is `rfid_id` (canonicalized
lowercase hex, separators stripped, leading zeros preserved).

## The .rfid file format (reference)

The Flipper firmware writes RFID captures as text files in
/ext/lfrfid/ (note: NOT /ext/rfid/ — the firmware uses lfrfid).
Format is similar to .nfc:

```
Filetype: Flipper RFID key
Version: 1
Key type: EM4100
Data: 12 34 56 78 9A
```

For HID Prox:
```
Filetype: Flipper RFID key
Version: 1
Key type: HIDProx
Data: 02 00 12 34 56
```

A single Data line, type-discriminated. Much simpler than .nfc's
page-by-page structure because LF protocols just don't have that much
state.

## Hardware validation gotcha

The Kiisu's 125 kHz coil is on the BACK of the device, opposite the
NFC antenna on the front. Operators new to the device often try to
read LF cards with the front face — they get nothing, conclude the
card is dead, move on. **Always orient with the back face toward the
target for LF reads/writes.**

This is also why simultaneous NFC + LF triage matters: if a card
can't be NFC-read, flip the Kiisu before concluding it's broken.

## Cross-references

- `nfc.md` — for the 13.56 MHz family
- `triage.md` — for the unknown-card sweep that includes RFID
- `emulate.md` — RFID emulate will mirror this pattern
- Sources used to build this knowledge:
  - Flipper Forum LF support threads
  - Dangerous Things forum (T5577 / EM4xxx writeups)
  - Proxmark3 documentation (deeper LF protocol references)
