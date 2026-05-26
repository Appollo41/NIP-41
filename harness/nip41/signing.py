"""The BIP-340 signing scalar for each generation, with parity."""

from vendor.bip340_reference import G, n, point_mul, has_even_y
from nip41.chain import Chain, tweak_scalar


def signing_key(chain: Chain, i: int) -> int:
    """Private scalar that produces BIP-340 signatures verifying under
    chain.npub[i]. Returns the scalar of the even-y point, per BIP-340."""
    N = len(chain.npub)
    if not (0 <= i < N):
        raise IndexError(f"generation index {i} out of range [0, {N})")
    d_internal = chain.p_internal[i]
    P_internal = chain.P_internal[i]

    if i == N - 1:
        # terminal generation: no tweak, npub is the plain internal key
        return d_internal if has_even_y(P_internal) else n - d_internal

    # adjust the internal scalar to its even-y lift, then add the tweak
    d_even = d_internal if has_even_y(P_internal) else n - d_internal
    t = tweak_scalar(P_internal, chain.npub[i + 1])
    d = (d_even + t) % n

    # BIP-340: the signing scalar is that of the even-y tweaked point
    Q = point_mul(G, d)
    return d if has_even_y(Q) else n - d
