# mfkey32 — recovering Mifare Classic keys from captured handshakes

## What this is, in one paragraph

You held a Flipper near a Mifare Classic reader (a hotel door, an office
fob reader, a transit gate, a vending machine) while it tried to talk to
a card. Flipper's "Detect Reader" mode recorded the *encrypted handshake
fragments* the reader broadcast. Those fragments leak just enough
information that a 2008 cryptographic attack can mathematically reverse
out the secret key that's protecting that sector.

That attack is mfkey32. The math runs on your laptop, not the Flipper.
This mission wraps it and writes the result to the audit log.

## Why this matters (real-world stakes)

Mifare Classic is the most-deployed contactless card in history. Hotels,
universities, transit, parking, factory access, vending — billions of
cards. Despite being known-broken since 2008, it is still being installed
in 2026 because:

- Replacement is expensive (every reader, every card)
- Most installations don't know they're vulnerable
- Compatibility cycles favour "what works" over "what's secure"

A red-team test that recovers a sector key on a customer's badge in 10
seconds is the kind of demonstration that gets a security budget approved.

## Security scale

Mifare Classic 1K / 4K (the variants this attack works on): **1/5**.
Considered cryptographically broken. Do not use for new deployments.
A single 2-pair capture against a vulnerable reader yields the key.

Variants this does **not** break:
- Mifare Plus (security level 3 mode) — uses AES, not Crypto-1
- Mifare DESFire — uses 3DES/AES
- NTAG21x / Ultralight — no Crypto-1, no sectors, no keys to recover

## Capture workflow (the part that needs hardware)

This mission does not capture nonces. You capture them with the Flipper's
built-in NFC app:

1. On the Flipper: **NFC > Detect Reader**
2. Hold the Flipper to the target reader.
3. The reader broadcasts auth challenges. The Flipper logs them to
   `/ext/nfc/.mfkey32.log`.
4. **Repeat at least twice for the same sector + key type.** mfkey32
   needs two captures to converge — it intersects candidate-key sets
   from each capture to find the unique key.
5. More captures = faster + more reliable recovery on weak nonces.

A typical .mfkey32.log line:
```
Sec 1 key A cuid 1234abcd nt 89abcdef nr fedcba98 ar 76543210 at 0fedcba9
```

That's: sector 1, key A, card UID, tag-nonce, reader-nonce, reader-auth,
tag-auth.

## Running this mission (host side, no hardware)

```python
from llmdr_redteam.missions import mission_nfc_mfkey32

# Option A: pull the log from the Flipper first, then pass the path
result = await mission_nfc_mfkey32(log_path="/path/to/.mfkey32.log")

# Option B: pass the contents directly (useful in scripts / pipelines)
with open("captures/door3.log") as f:
    result = await mission_nfc_mfkey32(log_text=f.read())
```

The decorator writes the recovered keys, parse stats, and CUID
cross-link to the audit log automatically. If one or more keys come back,
the cross-link binds this event to any prior `nfc_capture` / `triage`
event for the same physical card UID.

## Solver dependency

This mission shells out to the `mfkey32` binary (or `mfkey32v2`).

**Why not pure Python?** The Crypto-1 LFSR rollback is ~400 lines of
bit-twiddling that's easy to get subtly wrong, and Python is ~1000x
slower than the C reference. The C tool is battle-tested and free.

Install:
- **Linux**: `apt install libnfc-bin` for the libnfc family, then build
  `mfkey32v2` from https://github.com/equipter/mfkey32v2 with `make`.
- **macOS**: `brew install libnfc`, then build `mfkey32v2` from source.
- **Windows**: Build `mfkey32v2.exe` with MSYS2 + gcc, drop on PATH.

If the binary is missing, the mission fails with a clear install hint
(captured in the audit log). It will not silently fake the result.

## Failure modes worth understanding

- **`< 2 pairs for a (sector, key_type)`** — recovery needs at least two
  captures from the same group. Capture more.
- **Solver runs but no key emerges** — the captures are weak (the reader
  is using a hardened Crypto-1 variant, or the card is mfPlus in
  backwards-compat mode). Capture more pairs from a different angle.
- **`SolverBinaryMissing`** — install mfkey32v2 (above).
- **Multiple CUIDs in one log** — operator concatenated captures from
  different cards. Mission still runs, but the cross-link binds to the
  first CUID only. Splitting logs per-card before running is cleaner.

## Why this is the safest mission to run

Zero TX. Zero hardware risk. Zero blacklist exposure. The card and
reader you captured from are unaffected by this mission — you're doing
math on data you already have. The audit log records everything in
case the recovered key is later used for a write or emulate operation
(those *are* hardware-touching and *do* go through the blacklist).

## Cross-references

- `nfc.md` — UID, ATQA, SAK, family fingerprinting
- `triage.md` — the unknown-card identification sweep
- (future) `nfc_clone.md` — what to do with a recovered key
- Reference: equipter/mfkey32v2 on GitHub
- Original break: Garcia, Koning Gans, Muijrers, van Rossum, Verdult,
  Wichers Schreur, Jacobs — "Dismantling MIFARE Classic", ESORICS 2008.
