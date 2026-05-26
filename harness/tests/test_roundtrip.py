import os

from vendor.bip340_reference import schnorr_sign as ref_sign, schnorr_verify as ref_verify
from oracles.coincurve_oracle import schnorr_sign as cc_sign, schnorr_verify as cc_verify
from nip41.chain import build_chain
from nip41.signing import signing_key

ROOTS = [bytes([b]) * 32 for b in (0x77, 0xAB, 0x10, 0xEE)]


def test_signatures_verify_across_two_independent_implementations():
    """Sign with each implementation, verify with the other, under the
    published npub[i]. If the §3 parity were wrong, this fails."""
    msg = bytes.fromhex("9f" * 32)
    for root in ROOTS:
        chain = build_chain(root, N=24)
        for i in range(24):
            sk = signing_key(chain, i)
            npub = chain.npub[i]

            ref_sig = ref_sign(msg, sk.to_bytes(32, "big"), os.urandom(32))
            cc_sig = cc_sign(sk, msg)

            # cross-verify: each signature checked by the OTHER implementation
            assert cc_verify(npub, msg, ref_sig), f"root {root[0]:#x} gen {i}: cc rejects ref sig"
            assert ref_verify(msg, npub, cc_sig), f"root {root[0]:#x} gen {i}: ref rejects cc sig"
