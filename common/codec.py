from __future__ import annotations

import base64
import os
import zlib
from hashlib import pbkdf2_hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CODEC_VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
KDF_ITERATIONS = 200_000
DEFAULT_PSK_ENV = "NETSEC_PSK"
AAD = b"NS-ICMP-CODEC-v1"


def _resolve_psk(psk: str | bytes | None) -> bytes:
    if psk is None or psk == "":
        psk = os.getenv(DEFAULT_PSK_ENV)
    if psk is None or psk == "":
        raise ValueError("Missing PSK: pass --psk or set NETSEC_PSK")

    if isinstance(psk, str):
        psk_bytes = psk.encode("utf-8")
    else:
        psk_bytes = bytes(psk)

    if len(psk_bytes) < 8:
        raise ValueError("PSK must be at least 8 bytes")
    return psk_bytes


def _derive_key(psk_bytes: bytes, salt: bytes) -> bytes:
    return pbkdf2_hmac("sha256", psk_bytes, salt, KDF_ITERATIONS, dklen=KEY_LEN)


def encode_payload(plain: bytes, psk: str | bytes | None = None) -> bytes:
    compressed = zlib.compress(plain, level=6)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(_resolve_psk(psk), salt)
    ciphertext = AESGCM(key).encrypt(nonce, compressed, AAD)
    return bytes([CODEC_VERSION]) + salt + nonce + ciphertext


def decode_payload(encoded: bytes, psk: str | bytes | None = None) -> bytes:
    if not encoded:
        raise ValueError("Encoded payload is empty")

    if encoded[0] != CODEC_VERSION:
        # Backward compatibility with the initial skeleton format.
        compressed = base64.b64decode(encoded)
        return zlib.decompress(compressed)

    min_len = 1 + SALT_LEN + NONCE_LEN + 16
    if len(encoded) < min_len:
        raise ValueError("Encoded payload is truncated")

    salt_start = 1
    nonce_start = salt_start + SALT_LEN
    cipher_start = nonce_start + NONCE_LEN

    salt = encoded[salt_start:nonce_start]
    nonce = encoded[nonce_start:cipher_start]
    ciphertext = encoded[cipher_start:]

    key = _derive_key(_resolve_psk(psk), salt)
    try:
        compressed = AESGCM(key).decrypt(nonce, ciphertext, AAD)
    except InvalidTag as exc:
        raise ValueError("Decryption failed (wrong PSK or corrupted payload)") from exc

    return zlib.decompress(compressed)
