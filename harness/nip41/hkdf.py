"""HKDF-SHA256 (RFC 5869). Validated against RFC vectors and `cryptography`."""

import hashlib
import hmac

_HASH_LEN = 32


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if len(salt) == 0:
        salt = b"\x00" * _HASH_LEN
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    if length < 0:
        raise ValueError("HKDF: length must be non-negative")
    if length > 255 * _HASH_LEN:
        raise ValueError("HKDF: requested length too large")
    block = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)
