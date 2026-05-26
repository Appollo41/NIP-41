"""BIP-341 Taproot key-path tweak, transcribed from the BIP-341 text.

Reference: https://github.com/bitcoin/bips/blob/master/bip-0341/bip-0341.mediawiki
section "Constructing and spending Taproot outputs". The `_with_t` variants take
the tweak scalar directly so they can be used as the independent oracle for a
construction (NIP-41) that computes the tweak with a plain hash instead of the
BIP-341 tagged hash.
"""

import hashlib

from vendor.bip340_reference import (
    G, n, point_add, point_mul, lift_x, has_even_y, x, bytes_from_point,
)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def tweak_pubkey_with_t(internal_pubkey_xonly: bytes, t: int):
    """Returns (parity, tweaked_xonly) for an x-only internal key and scalar t."""
    if not 0 <= t < n:
        raise ValueError("tweak scalar out of range")
    P = lift_x(int.from_bytes(internal_pubkey_xonly, "big"))
    if P is None:
        raise ValueError("internal pubkey not on curve")
    Q = point_add(P, point_mul(G, t))
    return (0 if has_even_y(Q) else 1), bytes_from_point(Q)


def tweak_seckey_with_t(internal_seckey: int, t: int) -> int:
    """Returns the BIP-340 signing scalar for the tweaked key."""
    if not 0 <= t < n:
        raise ValueError("tweak scalar out of range")
    P = point_mul(G, internal_seckey)
    d_even = internal_seckey if has_even_y(P) else n - internal_seckey
    d = (d_even + t) % n
    Q = point_mul(G, d)
    return d if has_even_y(Q) else n - d


def taproot_tweak_pubkey(internal_pubkey_xonly: bytes, merkle_root: bytes):
    """The real BIP-341 function (tagged hash). Used only to validate the
    transcription against the official wallet test vectors."""
    t = int.from_bytes(tagged_hash("TapTweak", internal_pubkey_xonly + merkle_root), "big")
    return tweak_pubkey_with_t(internal_pubkey_xonly, t)
