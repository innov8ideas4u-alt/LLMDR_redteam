# Knowledge: VingCard / ASSA ABLOY Hospitality

> Field guide for VingCard (now ASSA ABLOY Hospitality / Visionline) keycards.
> Loaded by `interpret()` when a card is identified as `vingcard_visionline_likely`
> or when a Mifare Ultralight EV1 (UL11) is encountered with VingCard markers.

## What VingCard is

VingCard is the dominant hotel keylock vendor globally — owned by ASSA ABLOY,
sold under the brand "ASSA ABLOY Hospitality" with the Visionline backend.
Deployed by Sandman, IHG (Holiday Inn, Crowne Plaza, etc.), Hilton mid-tier,
Hyatt, Marriott franchises, and thousands of independents. If a hotel uses a
"plastic card you tap to a black box on the door," there's a ~60% chance it's
VingCard.

## How to recognize a VingCard UL EV1 hospitality card

Auto-detection markers (any 3+ together = high confidence VingCard):

1. **Chip**: Mifare Ultralight EV1, UL11 variant (`MF0UL1101`), 80 bytes total
2. **ATQA**: `0x0044`, **SAK**: `0x00`
3. **Mifare version block**: `00 04 03 01 01 00 0B 03` (vendor=NXP,
   product=Ultralight EV1, subtype=01, size=0B → 64↔32 byte UL11)
4. **AUTH0** (page 16, byte 4): `0x10` or higher — write-protected from
   page 16 onward, but pages 4-15 readable without password
5. **OTP** (page 3): non-zero, often with high bit set in byte 0
   (e.g. `F2 48 08 00`, `51 03 BE 1B`)
6. **Pages 4-15**: high-entropy bytes (encrypted payload), typically
   between 24 bytes (older systems, only pages 4-9 used) and 48 bytes
   (newer or feature-rich systems, all 12 pages used)

If at least 3 of (chip+ATQA, AUTH0=0x10, high-entropy pages, non-zero OTP)
match, tag as `vingcard_visionline_likely`.

## VingCard generations (per public Proxmark research)

VingCard ships seven distinct system versions. The three main ones for
contemporary hotels:

### "System A" — Old, fully broken
Mifare Classic 1K with default keys for some sectors and a known
key-diversification algorithm for sector 1. Cloneable in 30 seconds with
mfkey32. Largely retired but lingers in some legacy properties.
**Security: 1/5** — Insecure as designed.

### "System B" — Old + Chinese clones
Same family as A but later revisions added randomized keys for sectors
0, 1, 2, 6 (post-2017). Still Classic-based and still vulnerable to
nonce-attack key recovery.
**Security: 2/5** — Cloneable, but takes longer.

### "System C" — Current UL EV1 deployments
Mifare Ultralight EV1 with PWD/PACK protection. Pages 4-15 readable
without auth, but write-protected by a per-card password. The payload
in pages 4-15 is encrypted with a key diversified from the card's UID
plus the property's master secret. **This is what your typical Sandman
or IHG hotel card is in 2026.**
**Security: 3/5** — Public attack exists (see Unsaflok below).

## The Unsaflok attack (AAGS-HOSP-SA-2023-001)

Published 2022, disclosed publicly by ASSA ABLOY in 2023. The attack
recovers a property's master key by:

1. Reading any guest card from that property (requires brief proximity)
2. Reading the lock's response to a known-bad authentication attempt
   (requires brief proximity to a door reader)
3. Combining the two via the published derivation algorithm to recover
   the master secret
4. Forging arbitrary new cards for any room in that property

ASSA ABLOY's official mitigation is a firmware update for all locks +
all encoders + replacement of all cards in circulation — typically a
$50k-$200k upgrade per property. Most chains have NOT done this for
mid-tier brands (Sandman, Holiday Inn, Comfort Inn). **Luxury chains
are mostly upgraded; everyone else is exposed.**

Reference: <https://www.vingcard.com/documents/product-security/AAGS-HOSP-SA-2023-001.pdf>

## Card payload structure (what's in pages 4-15)

The 24-48 byte encrypted payload contains, per VingCard documentation
and partial reverse engineering:

- **Room number / lock authority bits** (which doors this card opens)
- **Valid-from timestamp** (check-in time)
- **Valid-until timestamp** (check-out time)
- **Card sequence number** (anti-replay; new card invalidates old card
  for the same room)
- **Property ID** (so a card from one Sandman doesn't open a different
  Sandman)
- **Feature flags** (breakfast, parking, gym, elevator floor restrictions,
  group access for connecting suites)

The exact layout depends on system version and isn't in any single public
document, but the general shape above is consistent across writeups.

**Why longer payloads (48 bytes, all 12 pages) suggest a "more featured"
property**: more flags, longer validity windows, multi-room authority
for suites. Sandman cards tend toward the longer payload — IHG mid-tier
toward the shorter (24 byte / pages 4-9 only) format.

## What you can and cannot do with a captured card

### Cosmetic clone (same UID, same bytes) — works, but doesn't open the door

A Magic UL EV1 (writable-page-0 variant) accepts the source UID and
all 48 bytes of payload. The clone reads identically when scanned by
ANY reader. **However**: VingCard locks do an originality-signature
check on a freshly-issued card (the IC signature in pages 21-22 is
ECC-signed by NXP). A Magic clone has the wrong signature and the lock
rejects it. Even if the signature were forged, the OTP at page 3 may
contribute to the password derivation — and OTP is one-time-programmable,
which means once you write to it on the magic blank, you can't undo it.

### Functional clone (door actually opens) — needs Unsaflok-style attack

You need:
1. Access to one card from the property (snapshot)
2. Access to one lock from the property (proximity, ~5 seconds)
3. The Unsaflok algorithm tooling (some published, some private)
4. A blank UL EV1 you can fully program (UID + payload + OTP + password)

Then you can issue arbitrary new cards for that property until the
property does a full system upgrade.

### Card emulation — works for testing, not for opening

A Proxmark3 or Flipper Zero can emulate the card byte-for-byte. The
lock will accept the emulation IF the underlying credential is valid
(i.e. the encrypted payload still matches what the lock expects).
But you can't modify the room number through emulation alone — the
encryption blocks that.

## Defensive recommendation cheat sheet

When the operator asks "should this hotel worry about a clone attack?":

| Hotel uses…                        | Cloneable?   | Mitigation                          |
|------------------------------------|--------------|--------------------------------------|
| VingCard System A (Classic)        | Trivially    | Replace entire system                |
| VingCard System B (Classic 2017+)  | Yes (slower) | Replace entire system                |
| VingCard System C (UL EV1)         | Yes (Unsaflok) | Apply ASSA ABLOY 2023 firmware patch |
| VingCard Allure (DESFire EV2)      | No (current) | Already good. Watch for future 0-days |
| Hotel-mobile-key (BLE/HCE)         | Mixed         | Depends entirely on the implementation |

## Region notes

- **Canada**: Sandman, Best Western, mid-tier Marriott — heavy VingCard System C.
  **Sandman specifically**: System C, longer 48-byte payloads observed.
- **US**: IHG, Holiday Inn, Hilton mid-tier — System C predominant.
- **EU**: Earlier migration to DESFire-based Allure on luxury, but Holiday
  Inn / Comfort tier still on UL EV1.
- **Asia**: More variation. Saflok and Onity are competitors with their own
  similar (or worse) security stories.
