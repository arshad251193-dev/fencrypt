# fencrypt

A password-based file encryption CLI. Small enough to read in one sitting, built
on vetted primitives rather than home-grown crypto.

## Setup

```bash
pip install -r requirements.txt
```

On Windows, `fencrypt.bat` is a launcher that runs the tool through this
project's `.venv`, so you don't need to activate anything or install packages
globally. It works from any directory:

```
C:\some\other\folder> C:\Users\arsha\Desktop\test-projecttt\fencrypt.bat encrypt notes.txt
```

## Usage

```bash
python fencrypt.py encrypt secrets.txt
```

That prompts for a password (twice) and writes `secrets.txt.enc`. To reverse it:

```bash
python fencrypt.py decrypt secrets.txt.enc
```

Other flags:

- `-o/--output PATH` — choose the output path explicitly
- `-f/--force` — allow overwriting an existing output file
- `--password-env VAR` — read the password from an environment variable (for scripts/CI)
- `--scrypt-n N` — scrypt cost, a power of 2 (encrypt only). The value is stored in the
  header, so raising it for a sensitive file doesn't break decryption of older files.
  The scrypt paper suggests `2**14` for interactive use and up to `2**20` for sensitive
  files (that's ~1 GB of RAM per attempt); the default here is `2**15`.

Note that the input file is **not** deleted after encrypting. That's deliberate —
securely erasing a file is much harder than it looks (journaling filesystems,
SSD wear-leveling, and backups all keep copies), so this tool doesn't pretend to
do it. Delete the original yourself once you've verified you can decrypt.

## Security design

| Choice | Why |
| --- | --- |
| **AES-256-GCM** | Authenticated encryption — gives confidentiality *and* tamper detection. Modifying one bit of the file makes decryption fail loudly rather than returning corrupted plaintext. |
| **scrypt** (n=2^15, r=8, p=1) | Memory-hard KDF. Turning a weak human password into a key should be slow and RAM-hungry, so offline brute-force costs real money. Plain SHA-256 would be billions of guesses/sec on a GPU. |
| **Random 16-byte salt per file** | The same password produces a different key in every file, so precomputed/rainbow tables are useless and identical files aren't detectable. |
| **Random 12-byte nonce per encryption** | GCM's security collapses if a nonce is ever reused under the same key. Fresh randomness each time avoids that. |
| **Header authenticated as AAD** | The salt and scrypt parameters are stored in plaintext (they have to be — you need them to decrypt). Feeding them to GCM as additional authenticated data means a modified header fails the tag check instead of silently decrypting. **But see the note below — this does not protect the KDF step itself.** |
| **KDF parameters bounds-checked before use** | The real defense for the header's `n`/`r`/`p` values. See below. |
| **Password never in argv** | Command-line arguments are visible in shell history and to other users via `ps`. Password comes from a hidden prompt or an env var. |
| **Atomic writes** | Output goes to a `.tmp` file then gets renamed, so an interrupted run can't leave a truncated, unrecoverable file. |

### Why AAD isn't enough: validate before you act

This one is worth internalizing, because it's a general lesson and it bit this
tool during development.

The scrypt parameters live in the file header, which means they are
**attacker-controlled**. The header is authenticated as AAD — so surely tampering
is caught? Not in time. Verifying the GCM tag requires the key, and deriving the
key requires running scrypt with the parameters from that same header. The order
is forced:

```
read header  ->  run scrypt with header's n/r/p  ->  verify tag
                 ^^^^ still untrusted here
```

By the time authentication would catch the tampering, you have already done
whatever the header told you to do. A single bit flipped in the `r` field was
enough to make this tool attempt a **261 GB** allocation — a denial of service
from nothing but a corrupted file.

The fix isn't better authentication, it's validating untrusted input *before*
acting on it: `_validate_kdf_params()` rejects any header whose parameters would
need more than 1 GiB of memory, aren't a power of two, or carry an absurd `p`.
AEAD is not a substitute for input validation on data you must parse before the
tag check.

### Known limits

Worth being honest about what this doesn't do:

- **Whole file is read into memory.** Fine for documents; don't point it at a 50 GB disk image. Streaming AEAD needs chunking with per-chunk nonces and a scheme to prevent chunk reordering/truncation.
- **A password prompt happens before the header is validated.** Harmless, but it means you can type a password only to be told the file is malformed.
- **The password lives in a Python `bytes`.** Python doesn't let you reliably zero memory, so a core dump or swap file could expose it. Real key management uses an OS keystore or HSM.
- **No metadata protection.** File size and modification time leak; the filename isn't encrypted.
- **`MAX_KDF_MEMORY` is a policy choice, not a law.** 1 GiB permits the scrypt paper's most expensive recommended setting. Lower it if you only ever use the defaults.

## Tests

```bash
python -m pytest -q
```

The suite covers the round trip, wrong passwords, bit-flip tampering in the
ciphertext / salt / nonce, truncated files, nonce and salt uniqueness, hostile
KDF parameters in the header (the 261 GB case above, plus non-powers-of-two,
zeroes, and an absurd `p`), and the CLI paths including refusing to clobber
existing files.

## Setup notes

The tests were run against Python 3.13.15, `cryptography` 50.0.0, and pytest
9.1.1 in a local `.venv`. If `python` isn't on your PATH on Windows, note that
`python.exe` under `AppData\Local\Microsoft\WindowsApps` may be the Microsoft
Store redirector stub rather than a real interpreter.
