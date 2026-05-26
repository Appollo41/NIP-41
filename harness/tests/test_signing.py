from vendor.bip340_reference import G, point_mul, has_even_y, bytes_from_point
from nip41.chain import build_chain
from nip41.signing import signing_key

ROOT = bytes.fromhex("33" * 32)


def test_signing_key_point_equals_published_npub():
    """For every generation, signing_key * G must be the published npub
    (x-only), and the point must be even-y so BIP-340 signatures verify."""
    chain = build_chain(ROOT, N=16)
    for i in range(16):
        d = signing_key(chain, i)
        Q = point_mul(G, d)
        assert has_even_y(Q), f"generation {i}: signing point is odd-y"
        assert bytes_from_point(Q) == chain.npub[i], f"generation {i}: pubkey mismatch"


def test_terminal_generation_signing_key():
    chain = build_chain(ROOT, N=4)
    d = signing_key(chain, 3)
    assert bytes_from_point(point_mul(G, d)) == chain.npub[3]
