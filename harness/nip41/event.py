"""kind:1041 rotation events — NIP-01 event id + BIP-340 signature."""

import hashlib
import json

from vendor.bip340_reference import bytes_from_point
from oracles.coincurve_oracle import schnorr_sign


def event_id(pubkey_hex: str, created_at: int, kind: int, tags: list, content: str) -> str:
    """NIP-01 event id: sha256 of the compact JSON serialization."""
    serialized = json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def build_chain_birth_event(chain, signing_scalar: int,
                            created_at: int = 1716100000,
                            content: str = "") -> dict:
    """Build a signed chain-birth kind:1041 event per nip-41.md §"The kind:1041 event".

    Declares npub[0] as a committed-chain head whose successor is npub[1].
    Carries one self-successor `successor` tag plus its discovery `p` tag,
    and is signed by nsec[0]. Per the spec, this is the FIRST event the
    chain ever signs."""
    if len(chain.npub) < 2:
        raise ValueError("chain-birth requires at least two generations")
    head_pub_hex = chain.npub[0].hex()
    next_pub_hex = chain.npub[1].hex()
    self_proof_hex = bytes_from_point(chain.P_internal[0]).hex()
    tags = [
        ["p", head_pub_hex, "", "successor"],
        ["successor", head_pub_hex, self_proof_hex, next_pub_hex],
    ]
    eid = event_id(head_pub_hex, created_at, 1041, tags, content)
    sig = schnorr_sign(signing_scalar, bytes.fromhex(eid))
    return {
        "id": eid,
        "pubkey": head_pub_hex,
        "created_at": created_at,
        "kind": 1041,
        "tags": tags,
        "content": content,
        "sig": sig.hex(),
    }


def build_rotation_event(chain, old_index: int, signing_scalar: int,
                         created_at: int = 1716200000,
                         content: str = "") -> dict:
    """Build a signed kind:1041 rotation event per nip-41.md §"The kind:1041 event".

    Rotates npub[old_index] -> npub[old_index+1]. Signed by the NEW key.
    Carries one predecessor-proof `successor` tag, one self-successor `successor`
    tag, plus the discovery `p` tags. The new key's self-successor requires the
    next-next generation, so old_index must be in [0, N-3]."""
    if not (0 <= old_index < len(chain.npub) - 2):
        raise IndexError(
            f"old_index {old_index} must be in [0, {len(chain.npub) - 3}] "
            f"(rotation requires a successor for the new key as well)"
        )
    new_index = old_index + 1
    old_pub_hex = chain.npub[old_index].hex()
    new_pub_hex = chain.npub[new_index].hex()
    next_pub_hex = chain.npub[new_index + 1].hex()
    pred_proof_hex = bytes_from_point(chain.P_internal[old_index]).hex()
    self_proof_hex = bytes_from_point(chain.P_internal[new_index]).hex()
    tags = [
        ["p", old_pub_hex, "", "predecessor"],
        ["p", new_pub_hex, "", "successor"],
        ["successor", old_pub_hex, pred_proof_hex, new_pub_hex],
        ["successor", new_pub_hex, self_proof_hex, next_pub_hex],
    ]
    eid = event_id(new_pub_hex, created_at, 1041, tags, content)
    sig = schnorr_sign(signing_scalar, bytes.fromhex(eid))
    return {
        "id": eid,
        "pubkey": new_pub_hex,
        "created_at": created_at,
        "kind": 1041,
        "tags": tags,
        "content": content,
        "sig": sig.hex(),
    }
