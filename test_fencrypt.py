"""Tests for fencrypt. Run with: python -m pytest -q"""
import os
import struct

import pytest

from fencrypt import (
    HEADER_LEN,
    MAGIC,
    build_parser,
    decrypt_bytes,
    encrypt_bytes,
    main,
)

PW = b"correct horse battery staple"


def test_roundtrip():
    data = b"attack at dawn"
    assert decrypt_bytes(encrypt_bytes(data, PW), PW) == data


def test_roundtrip_empty_and_large():
    for data in (b"", os.urandom(1_000_000)):
        assert decrypt_bytes(encrypt_bytes(data, PW), PW) == data


def test_wrong_password_fails():
    blob = encrypt_bytes(b"secret", PW)
    with pytest.raises(ValueError, match="wrong password"):
        decrypt_bytes(blob, b"wrong password")


def test_ciphertext_is_not_plaintext():
    data = b"this string must not appear in the output"
    assert data not in encrypt_bytes(data, PW)


def test_same_plaintext_gives_different_ciphertext():
    """Random salt+nonce per encryption means no two outputs match. If these
    were equal, an attacker could tell that two files have the same content."""
    a, b = encrypt_bytes(b"same", PW), encrypt_bytes(b"same", PW)
    assert a != b


def test_tampered_ciphertext_is_rejected():
    """This is the whole point of AEAD: flipping a bit is detected, not
    silently decrypted into garbage."""
    blob = bytearray(encrypt_bytes(b"important data", PW))
    blob[-1] ^= 0x01
    with pytest.raises(ValueError):
        decrypt_bytes(bytes(blob), PW)


def test_tampered_salt_is_rejected():
    """The header is authenticated as AAD, so editing the salt fails too.

    Header layout: magic(0-3) n(4-7) r(8-11) p(12-15) salt(16-31) nonce(32-43).
    """
    blob = bytearray(encrypt_bytes(b"important data", PW))
    blob[20] ^= 0xFF  # inside the salt
    with pytest.raises(ValueError):
        decrypt_bytes(bytes(blob), PW)


def test_tampered_nonce_is_rejected():
    blob = bytearray(encrypt_bytes(b"important data", PW))
    blob[35] ^= 0xFF  # inside the nonce
    with pytest.raises(ValueError):
        decrypt_bytes(bytes(blob), PW)


# --- Hostile KDF parameters --------------------------------------------------
# The scrypt parameters are stored in the header, so they are attacker
# controlled, and they are consumed BEFORE the GCM tag can be checked (you need
# the key to check the tag). Authentication therefore cannot protect this step;
# only explicit bounds checks can. These tests pin that down.

def _with_header_field(offset: int, value: int) -> bytes:
    """Return a valid blob with one 4-byte big-endian header field overwritten."""
    blob = bytearray(encrypt_bytes(b"payload", PW))
    blob[offset:offset + 4] = struct.pack(">I", value)
    return bytes(blob)


def test_absurd_r_is_rejected_without_allocating():
    """The original failing case: a bit-flip in r demanded 261 GB of RAM."""
    blob = _with_header_field(8, 65288)  # r field
    with pytest.raises(ValueError, match="over the"):
        decrypt_bytes(blob, PW)


def test_absurd_n_is_rejected():
    blob = _with_header_field(4, 2**31)  # n field
    with pytest.raises(ValueError, match="over the"):
        decrypt_bytes(blob, PW)


def test_non_power_of_two_n_is_rejected():
    blob = _with_header_field(4, 1000)
    with pytest.raises(ValueError, match="power of 2"):
        decrypt_bytes(blob, PW)


def test_zero_valued_params_are_rejected():
    for offset, name in ((4, "n"), (8, "r"), (12, "p")):
        with pytest.raises(ValueError, match=f"scrypt {name}="):
            decrypt_bytes(_with_header_field(offset, 0), PW)


def test_absurd_p_is_rejected():
    """p drives CPU cost rather than memory, so it needs its own ceiling."""
    blob = _with_header_field(12, 2**30)
    with pytest.raises(ValueError, match="scrypt p="):
        decrypt_bytes(blob, PW)


def test_bad_magic_rejected():
    blob = b"XXXX" + encrypt_bytes(b"x", PW)[4:]
    with pytest.raises(ValueError, match="bad magic"):
        decrypt_bytes(blob, PW)


def test_truncated_file_rejected():
    with pytest.raises(ValueError, match="too short"):
        decrypt_bytes(b"FEN1", PW)


def test_header_shape():
    blob = encrypt_bytes(b"x", PW)
    assert blob[:4] == MAGIC
    # header + 16-byte GCM tag + 1 byte of plaintext
    assert len(blob) == HEADER_LEN + 16 + 1


def test_cli_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("FENCRYPT_PW", "s3cret")
    src = tmp_path / "notes.txt"
    src.write_bytes(b"cli test data")

    assert main(["encrypt", str(src), "--password-env", "FENCRYPT_PW"]) == 0
    enc = tmp_path / "notes.txt.enc"
    assert enc.exists() and enc.read_bytes() != src.read_bytes()

    out = tmp_path / "out.txt"
    assert main(["decrypt", str(enc), "-o", str(out), "--password-env", "FENCRYPT_PW"]) == 0
    assert out.read_bytes() == b"cli test data"


def test_cli_refuses_to_clobber(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("FENCRYPT_PW", "s3cret")
    src = tmp_path / "a.txt"
    src.write_bytes(b"data")
    (tmp_path / "a.txt.enc").write_bytes(b"pre-existing")

    assert main(["encrypt", str(src), "--password-env", "FENCRYPT_PW"]) == 1
    assert "already exists" in capsys.readouterr().err
    assert (tmp_path / "a.txt.enc").read_bytes() == b"pre-existing"


def test_cli_missing_input(tmp_path, monkeypatch):
    monkeypatch.setenv("FENCRYPT_PW", "s3cret")
    missing = tmp_path / "nope.txt"
    assert main(["encrypt", str(missing), "--password-env", "FENCRYPT_PW"]) == 1


def test_custom_scrypt_cost_roundtrips():
    """A file encrypted at a non-default cost still decrypts, because n is read
    back from the header rather than assumed."""
    blob = encrypt_bytes(b"tuned", PW, n=2**12)
    assert decrypt_bytes(blob, PW) == b"tuned"


def test_scrypt_cost_validator_rejects_non_powers_of_two():
    parser = build_parser()
    for bad in ("1000", "0", "-8", "abc"):
        with pytest.raises(SystemExit):
            parser.parse_args(["encrypt", "f.txt", "--scrypt-n", bad])
    # a valid power of 2 parses fine
    assert parser.parse_args(["encrypt", "f.txt", "--scrypt-n", "4096"]).scrypt_n == 4096


def test_missing_password_env_is_a_clean_error(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("FENCRYPT_PW", raising=False)
    src = tmp_path / "a.txt"
    src.write_bytes(b"data")
    assert main(["encrypt", str(src), "--password-env", "FENCRYPT_PW"]) == 1
    assert "not set" in capsys.readouterr().err
