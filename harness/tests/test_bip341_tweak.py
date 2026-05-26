import json
from pathlib import Path

from oracles.bip341_tweak import (
    tagged_hash,
    taproot_tweak_pubkey,
    tweak_pubkey_with_t,
    tweak_seckey_with_t,
)
from vendor.bip340_reference import G, point_mul, has_even_y, bytes_from_point

VECTORS = Path(__file__).parent.parent / "vendor" / "bip341_wallet_vectors.json"


def test_tagged_hash_matches_bip341_definition():
    import hashlib
    tag = hashlib.sha256(b"TapTweak").digest()
    assert tagged_hash("TapTweak", b"abc") == hashlib.sha256(tag + tag + b"abc").digest()


def test_taproot_tweak_pubkey_against_wallet_vectors():
    data = json.loads(VECTORS.read_text())
    # NOTE: the actual internalPubkey/tweakedPubkey vectors are in "scriptPubKey",
    # not "keyPathSpending" (which covers spending witness data).
    checked = 0
    for case in data["scriptPubKey"]:
        given = case["given"]["internalPubkey"]
        merkle = case["intermediary"].get("merkleRoot")
        internal = bytes.fromhex(given)
        h = b"" if merkle is None else bytes.fromhex(merkle)
        _, tweaked = taproot_tweak_pubkey(internal, h)
        assert tweaked.hex() == case["intermediary"]["tweakedPubkey"]
        checked += 1
    assert checked == 7


def test_with_t_pubkey_and_seckey_are_consistent():
    """The scalar from tweak_seckey_with_t must produce the point from
    tweak_pubkey_with_t, for both even-y and odd-y internal keys."""
    t = 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF
    # pick one even-y and one odd-y internal scalar
    even_d = next(d for d in range(2, 200) if has_even_y(point_mul(G, d)))
    odd_d = next(d for d in range(2, 200) if not has_even_y(point_mul(G, d)))
    for d0 in (even_d, odd_d):
        P0 = point_mul(G, d0)
        parity, q_pub = tweak_pubkey_with_t(bytes_from_point(P0), t)
        d = tweak_seckey_with_t(d0, t)
        Q = point_mul(G, d)
        assert has_even_y(Q)
        assert bytes_from_point(Q) == q_pub, f"d0={d0}: pubkey/seckey mismatch"
