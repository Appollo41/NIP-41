from nip41.chain import build_chain, tweak_scalar
from nip41.signing import signing_key
from oracles.bip341_tweak import tweak_pubkey_with_t, tweak_seckey_with_t
from vendor.bip340_reference import bytes_from_point

ROOTS = [bytes([b]) * 32 for b in (0x44, 0x9A, 0xC3, 0x07, 0xFE)]


def test_commitment_matches_bip341_oracle():
    """Our npub[i] must equal the BIP-341 oracle's tweaked pubkey, using the
    same tweak scalar. Confirms C2 (point parity) and C1's shape."""
    for root in ROOTS:
        chain = build_chain(root, N=20)
        # generations 0..N-2 only; generation N-1 is terminal (no tweak),
        # its key is covered by test_signing.py instead
        for i in range(19):
            t = tweak_scalar(chain.P_internal[i], chain.npub[i + 1])
            internal_xonly = bytes_from_point(chain.P_internal[i])
            _, oracle_pub = tweak_pubkey_with_t(internal_xonly, t)
            assert oracle_pub == chain.npub[i], f"root {root[0]:#x} gen {i}"


def test_signing_key_matches_bip341_oracle():
    """Our signing scalar must equal the BIP-341 oracle's tweaked seckey."""
    for root in ROOTS:
        chain = build_chain(root, N=20)
        # generations 0..N-2 only; generation N-1 is terminal (no tweak),
        # its key is covered by test_signing.py instead
        for i in range(19):
            t = tweak_scalar(chain.P_internal[i], chain.npub[i + 1])
            oracle_d = tweak_seckey_with_t(chain.p_internal[i], t)
            assert signing_key(chain, i) == oracle_d, f"root {root[0]:#x} gen {i}"
