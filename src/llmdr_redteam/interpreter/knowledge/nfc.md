# Knowledge: NFC (13.56 MHz)

> Field guide used by `interpret()` to turn raw NFC events into human narratives.
> The interpreter loads this file when a mission's category is NFC. Grow it as
> you encounter new tag types in the field.

## Tag families by ATQA + SAK

When a Kiisu reads an ISO14443 tag, it gets back two short bytes called ATQA
(Answer To reQuest, type-A) and SAK (Select AcKnowledge). Together they identify
the tag family. Some common pairings:

| ATQA   | SAK  | Family            | Memory  | Crypto                    | Common uses                          |
|--------|------|-------------------|---------|---------------------------|---------------------------------------|
| 0x0044 | 0x00 | Mifare Ultralight | 64 B    | None                      | Hotel keys, transit, event wristbands |
| 0x0044 | 0x00 | NTAG21x           | 144–924 B | Optional pwd            | Stickers, tags, marketing            |
| 0x0004 | 0x08 | Mifare Classic 1K | 1 KB    | CRYPTO1 (broken 2008)     | Building access, transit              |
| 0x0002 | 0x18 | Mifare Classic 4K | 4 KB    | CRYPTO1                   | Older building access systems         |
| 0x0344 | 0x20 | Mifare DESFire EV1| 2/4/8 K | 3DES, AES                 | Modern transit, secure access         |
| 0x0344 | 0x20 | Mifare DESFire EV2| 8 KB    | AES                       | Government IDs, new transit systems   |
| 0x0008 | 0x88 | Mifare Plus       | 2/4 K   | CRYPTO1 + AES upgrade     | Transitional access systems           |

Note: ATQA/SAK overlap means you can't ALWAYS distinguish Ultralight from NTAG
without reading the version page. The interpreter should hedge appropriately
("Mifare Ultralight or NTAG21x — would need a version read to be certain").

## What "modified sectors" means on a Mifare Classic 1K

A 1K Classic has 16 sectors of 4 blocks each. The factory ships them with a
default key (often `FFFFFFFFFFFF`). When a building reuses the card, they
typically overwrite some sectors with their own key + access bits. The number
of modified sectors hints at the system:

- **0–1 modified**: Card hasn't been provisioned, or single-app system
- **2–4 modified**: Standard building access (one app, light data)
- **5–10 modified**: Multi-app card (transit + building + payment)
- **11+ modified**: Custom system, possibly bespoke (rare in commodity hardware)

## CRYPTO1 — broken 2008, still everywhere

Mifare Classic uses a stream cipher called CRYPTO1. It was reverse-engineered
in 2008 by Karsten Nohl and Henryk Plötz. Within a year, attacks recovered any
key in seconds (mfkey32, hardnested) given a modest amount of captured traffic.

**This means:** any Mifare Classic deployment is essentially read-only-but-not-
really to anyone with $30 of hardware and ten minutes. Modern facilities have
moved to DESFire/NTAG with proper crypto, but Classic is still in service for
cost reasons in transit, hotels, gyms, and lower-tier office buildings.

## NTAG vs Ultralight — the distinguishing read

Both share ATQA `0x0044` / SAK `0x00`. To tell them apart, send a
`GET_VERSION` command (0x60). Ultralights respond with NAK; NTAG21x respond
with 8 bytes including a "vendor" byte (0x04 = NXP) and product byte that
identifies NTAG213/215/216 vs Ultralight C/EV1.

For triage purposes, calling it "Ultralight or NTAG21x" is honest and
sufficient — the next mission (read or clone) can read the version page if
the operator wants disambiguation.

## Default keys to try

Common factory and convention keys to test on Classic sectors before falling
back to mfkey32 nonce attacks:

- `FFFFFFFFFFFF` (factory default)
- `A0A1A2A3A4A5` (NDEF / common transit)
- `D3F7D3F7D3F7` (NDEF write key)
- `000000000000` (uninitialized)
- `B0B1B2B3B4B5` (some hotel systems)
- `4D3A99C351DD` (transit, regional)

The Flipper firmware ships a dictionary file (`mf_classic_dict.nfc`) with
hundreds of community-collected keys. Worth running before any nonce attack.

## Cloning compatibility — what you actually get

A "clone" depends on the destination tag. From a Classic 1K source:

- **Magic Gen1A** (a.k.a. "Chinese magic"): Block 0 writable, perfect clone,
  works in any reader the original works in. Sold cheap online.
- **Magic Gen2 / CUID**: Block 0 writable but tag responds to specific
  unlock command. Some readers detect and reject.
- **Stock blank Classic**: Block 0 NOT writable. UID will differ from
  source — useless for UID-based access, fine for whitelist-by-content.

From an Ultralight source:
- **Stock blank Ultralight**: UID NOT writable on most. Same caveat.
- **Magic Ultralight**: Available, cheap, works in commodity readers.
- **NTAG215** (used in Amiibo cloning scene): Cheap, writable, common.

## Defensive recommendation cheat sheet

When the operator asks "should this system worry about a clone attack?":

| System uses…                       | Cloneable?  | Mitigation                      |
|------------------------------------|-------------|----------------------------------|
| Bare UID-only check, Mifare Classic| Trivially   | Migrate to DESFire/NTAG or add PIN |
| Sector-content + Classic CRYPTO1   | Yes (mfkey32) | Migrate; rotate keys won't save it |
| DESFire EV1 with AES               | Not practical | Already good. Watch for downgrade attacks. |
| DESFire EV2 with AES + diversification | No        | Best-in-class for commodity NFC  |

## Region notes

NFC works the same globally — no regional frequency differences (13.56 MHz
is unlicensed worldwide). Where regions diverge is in WHICH systems are
deployed:

- **North America**: Heavy Classic in transit (replaced slowly), strong DESFire
  in newer office buildings and federal IDs
- **EU**: Earlier DESFire migration, more Mifare Plus transitional systems
- **Asia**: FeliCa is common in Japan (different from ISO14443), DESFire elsewhere
