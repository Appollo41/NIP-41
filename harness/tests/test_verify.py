from vendor.bip340_reference import bytes_from_point
from nip41.chain import build_chain
from nip41.verify import verify_chain_rotation, resolve

ROOT = bytes.fromhex("55" * 32)


def test_honest_rotation_verifies():
    chain = build_chain(ROOT, N=8)
    for i in range(7):
        proof = bytes_from_point(chain.P_internal[i])
        assert verify_chain_rotation(chain.npub[i], chain.npub[i + 1], proof)


def test_wrong_successor_fails():
    chain = build_chain(ROOT, N=8)
    proof = bytes_from_point(chain.P_internal[0])
    # claim a rotation to generation 2 instead of generation 1
    assert not verify_chain_rotation(chain.npub[0], chain.npub[2], proof)


def test_tampered_proof_fails():
    chain = build_chain(ROOT, N=8)
    # Flip the high byte of the proof's x-only encoding to produce a non-curve point
    real = bytes_from_point(chain.P_internal[0])
    bad = bytes([real[0] ^ 0xFF]) + b"\x00" * 31  # garbage x
    assert not verify_chain_rotation(chain.npub[0], chain.npub[1], bad)


def test_resolve_walks_multi_hop_chain():
    chain = build_chain(ROOT, N=8)
    # rotations are an i -> (newpub, proof) map
    rotations = {
        chain.npub[i]: (chain.npub[i + 1], bytes_from_point(chain.P_internal[i]))
        for i in range(4)
    }
    assert resolve(chain.npub[0], rotations) == chain.npub[4]


def test_resolve_ignores_invalid_rotation():
    chain = build_chain(ROOT, N=8)
    rotations = {chain.npub[0]: (chain.npub[2], bytes_from_point(chain.P_internal[0]))}
    # invalid claim -> resolve returns the original key (fail closed)
    assert resolve(chain.npub[0], rotations) == chain.npub[0]
