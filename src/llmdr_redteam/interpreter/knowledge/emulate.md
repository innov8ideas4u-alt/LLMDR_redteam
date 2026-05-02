# NFC Emulation — making the Kiisu pretend to be a captured card

## What this is, in one paragraph

You captured a card in a previous mission. The .nfc file holding its
UID + ATQA + SAK + payload sits on the Kiisu's SD card. Emulation tells
the Kiisu: "stop being a Flipper, start being THAT card." The Kiisu's
NFC antenna starts broadcasting the captured identity. To any reader
nearby, it looks like the original card just got tapped on it.

No external tag is involved. The Kiisu IS the card. That's why this
mission ships even when you have zero blank tags on hand.

## Why this matters (real-world stakes)

Three audiences:

**Makerspace operations.** A member loses their EDGE fob. Without
emulation, you can't reissue without a fresh blank. With emulation, you
walk to the door with the Kiisu, hold it up, and the door opens — the
member is unblocked while a real replacement is on order.

**Security demos.** "Could a stranger walk into our office with the same
fob you carry?" A 30-second emulation against the office reader, with
the Kiisu standing in for an attacker's cloned card, makes the answer
visible to non-technical decision-makers in a way no slide deck can.

**Reader fingerprinting.** Some readers do UID-only checks (they'll
accept any card with the right number). Others do full Crypto-1 mutual
auth (they won't accept emulation). Running emulate against a target
reader and watching the result tells you which family of attack to
mount next — clone (UID-only readers) vs key recovery (auth-checking
readers).

## Security scale impact

This mission **does not break** any cryptography on its own. It re-plays
what the original card already broadcast. So:

- **Mifare Ultralight / NTAG21x** (no auth): emulation typically works
  against any reader that accepts these. Security score against
  these readers: **1/5**.
- **Mifare Classic with default keys**: emulation works if the .nfc file
  contains the sector keys. Same 1/5.
- **Mifare Classic with strong keys**: emulation alone fails — reader
  challenges with a nonce, Kiisu can't compute the right response
  without the key. You need `nfc_mfkey32` first.
- **Mifare DESFire / Plus AES**: emulation alone always fails. AES
  keys are not in the .nfc file unless someone leaked them. **5/5**
  remains 5/5.

## Firmware requirement

This mission uses Momentum's `nfc` JavaScript module. **Stock OFW
does not have it.** The Kiisu running mntm-dev is the supported target.

Detection of "wrong firmware" is automatic — the mission's log will be
empty or stuck at `[start]` without `[parsed]`. The Detection comes
back with `detected=False` and a `notes` field pointing at firmware.

## Mission inputs

```python
await mission_nfc_emulate(
    source_path="/ext/nfc/sandman_room205.nfc",  # captured earlier
    duration_s=30.0,                              # 1-300s
    backend=RealNFCEmulateBackend(flipper=...),
)
```

`duration_s` is the Kiisu's broadcast window. Operator picks based on
context: 5s for a quick reader-fingerprint test, 30s to walk to the
door, 120s for a sustained demo. Maximum 300s — past that, batteries
and patience both deplete.

## How the mission works under the hood

1. Renders a tiny mJS script with your `source_path` and `duration_s`
   baked in.
2. Pushes it to `/ext/apps_data/mcp/mcp_nfc_emulate.js` on the Kiisu.
3. Launches it via the JS runner (the same plumbing tested on Day 1
   BLE capability probes).
4. The script imports `nfc`, calls `nfc.parseFile(source_path)`, then
   `nfc.emulate(card, duration_ms)`.
5. Status log written to `/ext/apps_data/mcp_logs/mcp_nfc_emulate.log`
   with `[start] / [parsed] / [done]` markers.
6. Host backend reads the log back, parses status, builds Detection.

The host blocks for `duration_s + ~1.5s startup grace` before reading
the log — ensures the JS finished writing.

## Cross-link semantics

On successful emulation, `cross_link = ('nfc_uid', emulated_uid)`.

Note: `emulated_uid` is the UID actually pulled from the .nfc file by
the JS runtime — *not* the source filename. If you hand-edited the file
to spoof a different UID, the cross_link reflects what actually went on
the air. Audit log integrity beats assumed equivalence.

## Validation without tags (how to know it works)

You don't need a blank to test emulation. You need a reader. Options
ranked by accessibility:

1. **Phone NFC** — any iPhone or Android phone with NFC reads UIDs.
   Use NFC Tools app, hold phone to Kiisu during emulation. UID
   matches the captured card → emulation works.
2. **EDGE makerspace door** — your own deployment, your own permission.
   Hold the Kiisu where a member would tap. Door opens → emulation
   works against this reader family.
3. **Random hotel/office reader** — only if you have explicit written
   authorization. Otherwise this is illegal in most jurisdictions.

## Failure modes

- **Empty log / no `[parsed]`** → wrong firmware. Need Momentum.
- **`[error] nfc.parseFile returned null`** → source path wrong, or
  .nfc file format unparseable. Try `view /ext/nfc/<file>` first.
- **`[parsed]` but reader doesn't open** → reader does crypto auth,
  not just UID. Run `nfc_mfkey32` against captures from this reader
  to recover keys, then try emulate again with the keyed file.
- **`[stopped]` instead of `[done]`** → another NFC operation
  preempted, or duration was too short. Re-run with longer duration_s.

## Cross-references

- `nfc.md` — capture format, UID/ATQA/SAK semantics
- `mfkey32.md` — what to do when emulate fails against an auth-checking
  reader
- `triage.md` — finding cards to capture in the first place
- `vingcard.md` — for keycard-specific quirks (Sandman uses 12 payload
  pages, vanilla VingCard uses 6 — both emulate fine)
