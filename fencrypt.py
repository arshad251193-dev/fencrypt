#!/usr/bin/env python3
"""fencrypt - a small, secure file encryption CLI.

Design in one breath:
  * AES-256-GCM for authenticated encryption (confidentiality + integrity).
  * scrypt for turning a human password into a 256-bit key (memory-hard,
    so it resists brute-force / GPU cracking).
  * A random salt per file (defeats rainbow tables) and a random nonce per
    encryption (GCM security breaks if a nonce is ever reused with a key).
  * The whole header is fed to GCM as "additional authenticated data" (AAD),
    so an attacker can't silently downgrade the KDF parameters.

All crypto comes from the `cryptography` library. We never invent our own.
"""
from __future__ import annotations

import argparse
import getpass
import os
import struct
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- Format constants --------------------------------------------------------
MAGIC = b"FEN1"          # file identifier + format version
SALT_LEN = 16
NONCE_LEN = 12           # 96-bit nonce is the recommended size for GCM
KEY_LEN = 32             # 32 bytes = AES-256

# scrypt work factors. n MUST be a power of 2. Bigger n = more time+memory to
# derive the key = more expensive for an attacker to brute force. These defaults
# use ~33 MB of memory per attempt.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# Ceilings for parameters read out of a file header. See _validate_kdf_params.
MAX_KDF_MEMORY = 1 << 30   # 1 GiB -- enough for n=2**20, r=8 (the scrypt paper's
                           # "sensitive files" setting) and nothing more.
MAX_SCRYPT_P = 16          # p costs CPU, not memory; cap it to bound the runtime.

# header layout (big-endian): magic(4) n(4) r(4) p(4) salt(16) nonce(12)
HEADER_FMT = ">4sIII16s12s"
HEADER_LEN = struct.calcsize(HEADER_FMT)


# --- Core crypto -------------------------------------------------------------
def _validate_kdf_params(n: int, r: int, p: int) -> None:
    """Bounds-check scrypt parameters before handing them to the KDF.

    This matters more than it looks. The parameters live in the file header, so
    they are ATTACKER-CONTROLLED. We authenticate the header as AAD, but that
    check happens inside AESGCM.decrypt() -- which we can only call once we
    already have a key, i.e. *after* running the KDF. So authentication cannot
    protect this step; by the time the tag is verified, we have already
    allocated whatever the header asked for.

    Without these checks, a one-bit flip in the r field is enough to make the
    tool try to allocate hundreds of gigabytes. Validate untrusted input before
    you act on it, not after.
    """
    if n < 2 or (n & (n - 1)) != 0:
        raise ValueError(f"invalid scrypt n={n}: must be a power of 2 and at least 2")
    if r < 1:
        raise ValueError(f"invalid scrypt r={r}: must be at least 1")
    if not 1 <= p <= MAX_SCRYPT_P:
        raise ValueError(f"invalid scrypt p={p}: must be between 1 and {MAX_SCRYPT_P}")
    # scrypt's working set is 128 * n * r bytes.
    needed = 128 * n * r
    if needed > MAX_KDF_MEMORY:
        raise ValueError(
            f"header asks for {needed >> 20} MiB of memory to derive the key, "
            f"over the {MAX_KDF_MEMORY >> 20} MiB limit -- refusing "
            "(the file is corrupted, or crafted to exhaust memory)"
        )


def derive_key(password: bytes, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Stretch a password into a 32-byte key with scrypt."""
    _validate_kdf_params(n, r, p)
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=n, r=r, p=p)
    return kdf.derive(password)


def encrypt_bytes(data: bytes, password: bytes, n: int = SCRYPT_N) -> bytes:
    """Return header + ciphertext for the given plaintext.

    `n` is the scrypt cost. It gets stored in the header, so decryption picks it
    up automatically -- you can raise it for sensitive files without breaking
    compatibility with files encrypted at a lower cost.
    """
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt, n, SCRYPT_R, SCRYPT_P)
    header = struct.pack(HEADER_FMT, MAGIC, n, SCRYPT_R, SCRYPT_P, salt, nonce)
    # Passing `header` as AAD authenticates it: tampering with the stored
    # scrypt parameters or salt makes decryption fail instead of silently
    # weakening the key derivation.
    ciphertext = AESGCM(key).encrypt(nonce, data, header)
    return header + ciphertext


def decrypt_bytes(blob: bytes, password: bytes) -> bytes:
    """Verify and decrypt a header+ciphertext blob back to plaintext."""
    if len(blob) < HEADER_LEN:
        raise ValueError("file too short to be a fencrypt file")
    header, ciphertext = blob[:HEADER_LEN], blob[HEADER_LEN:]
    magic, n, r, p, salt, nonce = struct.unpack(HEADER_FMT, header)
    if magic != MAGIC:
        raise ValueError("bad magic bytes - not a fencrypt file (or wrong version)")
    key = derive_key(password, salt, n, r, p)
    try:
        # GCM verifies the authentication tag first; a wrong password derives a
        # wrong key, which fails that check -> InvalidTag.
        return AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ValueError(
            "decryption failed - wrong password, or the file is corrupted/tampered"
        )


# --- File helpers ------------------------------------------------------------
def _write_output(out_path: Path, data: bytes, force: bool) -> None:
    if out_path.exists() and not force:
        raise FileExistsError(f"{out_path} already exists (use --force to overwrite)")
    # Write to a temp file then atomically rename, so a crash mid-write never
    # leaves a half-written (unrecoverable) output in place of your data.
    tmp = out_path.with_name(out_path.name + ".tmp")
    tmp.write_bytes(data)
    os.replace(tmp, out_path)


def _resolve_out(in_path: Path, out: str | None, mode: str) -> Path:
    if out:
        return Path(out)
    if mode == "encrypt":
        return in_path.with_name(in_path.name + ".enc")
    # decrypt: strip a trailing .enc if present, else add .dec
    if in_path.suffix == ".enc":
        return in_path.with_suffix("")
    return in_path.with_name(in_path.name + ".dec")


def _get_password(confirm: bool, env_var: str | None) -> bytes:
    """Read the password. Prefer an env var for automation; never take it from
    argv (which leaks into shell history and `ps` output)."""
    if env_var:
        pw = os.environ.get(env_var)
        if pw is None:
            raise ValueError(f"environment variable {env_var} is not set")
        return pw.encode("utf-8")
    pw = getpass.getpass("Password: ")
    if not pw:
        raise ValueError("empty password")
    if confirm:
        if pw != getpass.getpass("Confirm password: "):
            raise ValueError("passwords do not match")
    return pw.encode("utf-8")


# --- CLI ---------------------------------------------------------------------
def _run(args: argparse.Namespace) -> None:
    in_path = Path(args.input)
    if not in_path.is_file():
        raise ValueError(f"input file not found: {in_path}")
    out_path = _resolve_out(in_path, args.output, args.command)
    password = _get_password(confirm=(args.command == "encrypt"), env_var=args.password_env)

    if args.command == "encrypt":
        blob = encrypt_bytes(in_path.read_bytes(), password, n=args.scrypt_n)
        _write_output(out_path, blob, args.force)
        print(f"encrypted -> {out_path}")
    else:
        _write_output(out_path, decrypt_bytes(in_path.read_bytes(), password), args.force)
        print(f"decrypted -> {out_path}")


def _scrypt_cost(value: str) -> int:
    """Validate --scrypt-n up front so a typo fails before we prompt for a
    password, rather than deep inside the KDF."""
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer")
    try:
        _validate_kdf_params(n, SCRYPT_R, SCRYPT_P)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))
    return n


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fencrypt",
        description="Encrypt/decrypt files with a password (AES-256-GCM + scrypt).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("encrypt", "encrypt a file"), ("decrypt", "decrypt a file")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("input", help="path to the input file")
        p.add_argument("-o", "--output", help="output path (default: derived from input)")
        p.add_argument("-f", "--force", action="store_true", help="overwrite output if it exists")
        p.add_argument(
            "--password-env",
            metavar="VAR",
            help="read the password from this environment variable instead of prompting",
        )
        if name == "encrypt":
            p.add_argument(
                "--scrypt-n",
                type=_scrypt_cost,
                default=SCRYPT_N,
                metavar="N",
                help=(
                    f"scrypt cost, a power of 2 (default: {SCRYPT_N}). Raise it for "
                    "sensitive files; decryption reads it from the header."
                ),
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        _run(args)
        return 0
    except (ValueError, FileExistsError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except MemoryError:
        # Backstop: the bounds check above keeps requests reasonable, but a
        # machine under pressure can still fail to allocate.
        print("error: not enough memory to derive the key", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
