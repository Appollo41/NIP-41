"""Demonstrates *why* the even-y lift in nip41/chain.py is required.

The earlier NIP-41 draft (2026-05-20) literally wrote `Q = P_internal + t*G`
with the RAW internal point. The §5 verifier reconstructs `Q` with lift_x
(even-y) — so when the raw internal point is odd-y, the two disagree. The
current draft has been fixed to use `lift_x(P_internal) + t*G`; this test
isolates the parity bug as a regression guard against re-introducing it.

The test uses the *current* tagged-hash domain (matching the verifier) so the
ONLY difference between this helper and the harness's correct construction is
the missing even-y lift — making this a clean isolation of the parity issue."""

from vendor.bip340_reference import (
    G, n, point_add, point_mul, has_even_y, bytes_from_point, tagged_hash,
)
from nip41.chain import TWEAK_TAG
from nip41.derivation import internal_key
from nip41.verify import verify_chain_rotation


def _draft_literal_npub(P_internal_point, next_npub: bytes) -> bytes:
    # Q = RAW P_internal + t*G  (no even-y lift) -- the pre-fix draft formula,
    # using the current tagged_hash so only the parity error is left to isolate.
    p_xonly = bytes_from_point(P_internal_point)
    t = int.from_bytes(tagged_hash(TWEAK_TAG, p_xonly + next_npub), "big") % n
    Q = point_add(P_internal_point, point_mul(G, t))
    return bytes_from_point(Q)


def test_draft_literal_formula_breaks_on_odd_y_generations():
    root = bytes.fromhex("8c" * 32)
    odd_y_seen = False
    for i in range(40):
        d_i, P_i = internal_key(root, i)
        d_next, P_next = internal_key(root, i + 1)
        next_npub = bytes_from_point(P_next)

        old_npub_literal = _draft_literal_npub(P_i, next_npub)
        proof = bytes_from_point(P_i)
        ok = verify_chain_rotation(old_npub_literal, next_npub, proof)

        if has_even_y(P_i):
            assert ok, f"gen {i}: even-y should still verify"
        else:
            odd_y_seen = True
            assert not ok, f"gen {i}: odd-y draft-literal npub unexpectedly verified"
    assert odd_y_seen, "test did not exercise an odd-y generation; widen the range"
