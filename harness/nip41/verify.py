"""Offline verification and identity resolution."""

from vendor.bip340_reference import (
    G, n, point_add, point_mul, lift_x, bytes_from_point, tagged_hash,
)

# Must match nip41.chain.TWEAK_TAG. Kept independent here so the verifier has
# no dependency on the construction module (only on the vendored primitives).
TWEAK_TAG = "nip41/succession"


def verify_chain_rotation(oldpub: bytes, newpub: bytes, proof_internal_xonly: bytes) -> bool:
    """True iff `proof` opens `oldpub`'s commitment to successor `newpub`."""
    if len(proof_internal_xonly) != 32 or len(oldpub) != 32 or len(newpub) != 32:
        return False
    P_int = lift_x(int.from_bytes(proof_internal_xonly, "big"))
    if P_int is None:
        return False
    t = int.from_bytes(tagged_hash(TWEAK_TAG, proof_internal_xonly + newpub), "big") % n
    Q = point_add(P_int, point_mul(G, t))
    if Q is None:
        return False
    return bytes_from_point(Q) == oldpub


def resolve(pubkey: bytes, rotations: dict[bytes, tuple[bytes, bytes]]) -> bytes:
    """Walk the chain forward. `rotations` maps oldpub -> (newpub, proof).
    Fails closed: an invalid rotation is ignored and resolution stops."""
    seen = set()
    current = pubkey
    while current in rotations and current not in seen:
        seen.add(current)
        newpub, proof = rotations[current]
        if not verify_chain_rotation(current, newpub, proof):
            return current
        current = newpub
    return current
