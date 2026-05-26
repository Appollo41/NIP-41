from nip41.chain import build_chain
from nip41.signing import signing_key
from nip41.event import build_rotation_event, build_chain_birth_event, event_id
from nip41.verify import verify_chain_rotation
from oracles.coincurve_oracle import schnorr_verify
from vendor.bip340_reference import bytes_from_point, schnorr_verify as ref_verify

ROOT = bytes.fromhex("66" * 32)


def test_event_id_is_32_byte_hex():
    eid = event_id("aa" * 32, 1716200000, 1041, [], "")
    assert len(eid) == 64
    assert bytes.fromhex(eid)  # valid hex
    # pinned regression guard for the NIP-01 serialization
    assert eid == "709e0ea813fb3db900f0c55138feab1f4b9711cac070369d62fa1dc03b13328a"


def test_rotation_event_is_well_formed_and_signed():
    chain = build_chain(ROOT, N=8)
    sk = signing_key(chain, 1)  # signed by the NEW key, npub[1]
    event = build_rotation_event(chain, old_index=0, signing_scalar=sk)

    assert event["kind"] == 1041
    assert event["pubkey"] == chain.npub[1].hex()

    old_pub_hex = chain.npub[0].hex()
    new_pub_hex = chain.npub[1].hex()
    next_pub_hex = chain.npub[2].hex()
    pred_proof_hex = bytes_from_point(chain.P_internal[0]).hex()
    self_proof_hex = bytes_from_point(chain.P_internal[1]).hex()

    # Per nip-41.md §"The kind:1041 event" → Rotation: two `successor` tags
    # (predecessor proof + self-successor) plus two discovery `p` tags.
    assert ["p", old_pub_hex, "", "predecessor"] in event["tags"]
    assert ["p", new_pub_hex, "", "successor"] in event["tags"]
    assert ["successor", old_pub_hex, pred_proof_hex, new_pub_hex] in event["tags"]
    assert ["successor", new_pub_hex, self_proof_hex, next_pub_hex] in event["tags"]

    # Both successor tags must satisfy the verification equation
    assert verify_chain_rotation(chain.npub[0], chain.npub[1], bytes_from_point(chain.P_internal[0]))
    assert verify_chain_rotation(chain.npub[1], chain.npub[2], bytes_from_point(chain.P_internal[1]))

    # the signature must verify under the new key with the independent oracle
    eid = bytes.fromhex(event["id"])
    assert schnorr_verify(chain.npub[1], eid, bytes.fromhex(event["sig"]))

    # cross-verify with the independent vendored BIP-340 reference
    # (note: the reference's signature is (msg, pubkey, sig))
    assert ref_verify(eid, chain.npub[1], bytes.fromhex(event["sig"]))


def test_chain_birth_event_is_well_formed_and_signed():
    chain = build_chain(ROOT, N=8)
    sk0 = signing_key(chain, 0)  # signed by npub[0]
    event = build_chain_birth_event(chain, signing_scalar=sk0)

    assert event["kind"] == 1041
    assert event["pubkey"] == chain.npub[0].hex()
    assert event["content"] == ""

    head_pub_hex = chain.npub[0].hex()
    next_pub_hex = chain.npub[1].hex()
    self_proof_hex = bytes_from_point(chain.P_internal[0]).hex()

    # Per nip-41.md §"The kind:1041 event" → Chain birth: single self-successor
    # tag plus its discovery p-tag. No predecessor side.
    assert ["p", head_pub_hex, "", "successor"] in event["tags"]
    assert ["successor", head_pub_hex, self_proof_hex, next_pub_hex] in event["tags"]
    assert len(event["tags"]) == 2  # exactly these two — no predecessor side

    # The self-successor tag must satisfy the verification equation
    assert verify_chain_rotation(chain.npub[0], chain.npub[1], bytes_from_point(chain.P_internal[0]))

    # Signature verifies under npub[0] with both independent oracles
    eid = bytes.fromhex(event["id"])
    assert schnorr_verify(chain.npub[0], eid, bytes.fromhex(event["sig"]))
    assert ref_verify(eid, chain.npub[0], bytes.fromhex(event["sig"]))


def _get_tag(event, marker: str):
    """Return the `["successor", subject, P_internal, npub_next]` tag whose
    subject matches the given marker key (hex)."""
    return next(t for t in event["tags"]
                if t[0] == "successor" and t[1] == marker)


# --- Bullet 8(a): forged `successor` tags must fail verify_chain_proof. -------

def test_forged_self_successor_in_chain_birth_event_fails():
    """An attacker swaps the chain-birth self-successor's npub_next for a key
    they control. The signature is still valid (signed by nsec[0]), but the
    equation rejects the tag."""
    chain = build_chain(ROOT, N=8)
    sk0 = signing_key(chain, 0)
    event = build_chain_birth_event(chain, signing_scalar=sk0)

    head, _proof, _next = _get_tag(event, chain.npub[0].hex())[1:]
    attacker_npub = bytes.fromhex("ee" * 32)
    proof = bytes_from_point(chain.P_internal[0])

    assert not verify_chain_rotation(bytes.fromhex(head), attacker_npub, proof)


def test_forged_predecessor_proof_in_rotation_event_fails():
    """An attacker rewrites the predecessor-proof `successor` tag to claim
    rotation to a key they control. verify_chain_proof rejects it."""
    chain = build_chain(ROOT, N=8)
    sk1 = signing_key(chain, 1)
    event = build_rotation_event(chain, old_index=0, signing_scalar=sk1)

    pred_tag = _get_tag(event, chain.npub[0].hex())
    _subject, proof_hex, _orig_next = pred_tag[1:]
    attacker_npub = bytes.fromhex("ee" * 32)

    assert not verify_chain_rotation(
        chain.npub[0], attacker_npub, bytes.fromhex(proof_hex))


def test_forged_self_successor_in_rotation_event_fails():
    """An attacker rewrites the self-successor tag of a rotation event to
    bind the new key to an attacker successor. verify_chain_proof rejects it."""
    chain = build_chain(ROOT, N=8)
    sk1 = signing_key(chain, 1)
    event = build_rotation_event(chain, old_index=0, signing_scalar=sk1)

    self_tag = _get_tag(event, chain.npub[1].hex())
    _subject, proof_hex, _orig_next = self_tag[1:]
    attacker_npub = bytes.fromhex("ee" * 32)

    assert not verify_chain_rotation(
        chain.npub[1], attacker_npub, bytes.fromhex(proof_hex))


# --- Cross-validation against nip-41-test-vectors.md ----------------------
# The spec ships a test-vectors document. Building events from the spec's
# root + created_at values must reproduce its published event_ids exactly.
# (Signatures use random aux_rand and are not pinned; the NIP-01 event_id
# is deterministic from pubkey/created_at/kind/tags/content.)

SPEC_ROOT = bytes.fromhex("890b93ded88a65e0707db157704ab04f84bbeec0fe6075c27ba98dcb9e5a2a13")
SPEC_CHAIN_LENGTH = 4


def test_chain_birth_event_id_matches_spec_vectors():
    chain = build_chain(SPEC_ROOT, N=SPEC_CHAIN_LENGTH)
    sk0 = signing_key(chain, 0)
    event = build_chain_birth_event(chain, signing_scalar=sk0, created_at=1716100000)
    assert event["id"] == "5d4d1f22f7de47ed8d4ce89b38d36f353b27123c424da8a4fb3fd585ec399b8c"


def test_rotation_0_to_1_event_id_matches_spec_vectors():
    chain = build_chain(SPEC_ROOT, N=SPEC_CHAIN_LENGTH)
    sk1 = signing_key(chain, 1)
    event = build_rotation_event(
        chain, old_index=0, signing_scalar=sk1,
        created_at=1716200000, content="optional human-readable note")
    assert event["id"] == "53a326f7e153f2b3c5d9aa195b461f9f20c03e32a15d318f4de65fc2ca3574ec"


def test_rotation_1_to_2_event_id_matches_spec_vectors():
    chain = build_chain(SPEC_ROOT, N=SPEC_CHAIN_LENGTH)
    sk2 = signing_key(chain, 2)
    event = build_rotation_event(
        chain, old_index=1, signing_scalar=sk2, created_at=1716300000)
    assert event["id"] == "ee29aa36003e01576947017879cd672298f134be45e90613e7e3fa67b126eb59"
