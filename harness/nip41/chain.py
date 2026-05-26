"""Building the committed identity chain backwards."""

from dataclasses import dataclass

from vendor.bip340_reference import (
    G, n, point_add, point_mul, lift_x, x, bytes_from_point, tagged_hash,
)
from nip41.derivation import internal_key


# Per NIP-41 Succession tweak, the tweak uses a BIP-340 tagged hash with this
# domain tag to guarantee non-collision with Bitcoin Taproot or any other
# tagged-hash use.
TWEAK_TAG = "nip41/succession"


@dataclass(frozen=True)
class Chain:
    p_internal: tuple   # internal private scalars, index 0..N-1
    P_internal: tuple   # internal public points, index 0..N-1
    npub: tuple         # published x-only public keys (bytes), index 0..N-1


def tweak_scalar(P_internal_point, next_npub: bytes) -> int:
    """t[i] = tagged_hash("nip41/succession", bytes(P_internal[i]) || npub[i+1])
    reduced mod n. Matches the NIP-41 Succession tweak."""
    p_xonly = bytes_from_point(P_internal_point)
    digest = tagged_hash(TWEAK_TAG, p_xonly + next_npub)
    return int.from_bytes(digest, "big") % n


def commitment_point(P_internal_point, next_npub: bytes):
    """Q[i] = lift_x(bytes(P_internal[i])) + t[i]*G  — even-y lift, per NIP-41 Committed public key."""
    t = tweak_scalar(P_internal_point, next_npub)
    P_even = lift_x(x(P_internal_point))   # the even-y lift the verifier reconstructs
    Q = point_add(P_even, point_mul(G, t))
    if Q is None:
        raise ValueError("commitment point is the point at infinity (negligible-probability edge case)")
    return Q


def build_chain(root_secret: bytes, N: int) -> Chain:
    if N < 2:
        raise ValueError("chain length N must be >= 2")
    p_internal, P_internal = [], []
    for i in range(N):
        d, P = internal_key(root_secret, i)
        p_internal.append(d)
        P_internal.append(P)

    npub = [None] * N
    npub[N - 1] = bytes_from_point(P_internal[N - 1])   # terminal: commits to nothing
    for i in range(N - 2, -1, -1):
        npub[i] = bytes_from_point(commitment_point(P_internal[i], npub[i + 1]))

    return Chain(p_internal=tuple(p_internal), P_internal=tuple(P_internal), npub=tuple(npub))
