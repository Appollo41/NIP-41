#!/usr/bin/env python3
"""
NIP-41 (proposed) -- Nostr Identity Chain
Reference implementation + test-vector generator.

Pure Python, standard library only. No external dependencies.

The elliptic-curve / Schnorr code is the BIP-340 reference implementation
(https://github.com/bitcoin/bips/blob/master/bip-0340). The key-path tweak is
BIP-341 (Taproot) key-path tweaking with a NIP-41 domain-separation tag.

Run:  python3 nip-41-test-vectors.py
It executes assertions over real elliptic-curve arithmetic and, on success,
writes nip-41-test-vectors.md next to this file.
"""

import hashlib
import hmac
import json
import os
import sys

# ---------------------------------------------------------------------------
# secp256k1 constants
# ---------------------------------------------------------------------------
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# ---------------------------------------------------------------------------
# BIP-340 reference: curve arithmetic
# ---------------------------------------------------------------------------
def tagged_hash(tag, msg):
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()

def px(point): return point[0]
def py(point): return point[1]

def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if px(p1) == px(p2) and py(p1) != py(p2):
        return None
    if p1 == p2:
        lam = (3 * px(p1) * px(p1) * pow(2 * py(p1), P_FIELD - 2, P_FIELD)) % P_FIELD
    else:
        lam = ((py(p2) - py(p1)) * pow(px(p2) - px(p1), P_FIELD - 2, P_FIELD)) % P_FIELD
    x3 = (lam * lam - px(p1) - px(p2)) % P_FIELD
    return (x3, (lam * (px(p1) - x3) - py(p1)) % P_FIELD)

def point_mul(point, k):
    r = None
    for i in range(256):
        if (k >> i) & 1:
            r = point_add(r, point)
        point = point_add(point, point)
    return r

def bytes_from_int(i): return i.to_bytes(32, "big")
def int_from_bytes(b): return int.from_bytes(b, "big")
def bytes_from_point(point): return bytes_from_int(px(point))
def has_even_y(point): return py(point) % 2 == 0

def lift_x(b):
    xi = int_from_bytes(b)
    if xi >= P_FIELD:
        return None
    y_sq = (pow(xi, 3, P_FIELD) + 7) % P_FIELD
    yi = pow(y_sq, (P_FIELD + 1) // 4, P_FIELD)
    if pow(yi, 2, P_FIELD) != y_sq:
        return None
    return (xi, yi if yi % 2 == 0 else P_FIELD - yi)

def xor_bytes(a, b):
    return bytes(c ^ d for c, d in zip(a, b))

# ---------------------------------------------------------------------------
# BIP-340 reference: Schnorr sign / verify
# ---------------------------------------------------------------------------
def schnorr_sign(msg, seckey, aux_rand):
    d0 = int_from_bytes(seckey)
    if not (1 <= d0 <= N_ORDER - 1):
        raise ValueError("secret key out of range")
    point = point_mul(G, d0)
    d = d0 if has_even_y(point) else N_ORDER - d0
    t = xor_bytes(bytes_from_int(d), tagged_hash("BIP0340/aux", aux_rand))
    rand = tagged_hash("BIP0340/nonce", t + bytes_from_point(point) + msg)
    k0 = int_from_bytes(rand) % N_ORDER
    if k0 == 0:
        raise RuntimeError("nonce k0 == 0")
    r = point_mul(G, k0)
    k = k0 if has_even_y(r) else N_ORDER - k0
    e = int_from_bytes(tagged_hash("BIP0340/challenge",
            bytes_from_point(r) + bytes_from_point(point) + msg)) % N_ORDER
    sig = bytes_from_point(r) + bytes_from_int((k + e * d) % N_ORDER)
    if not schnorr_verify(msg, bytes_from_point(point), sig):
        raise RuntimeError("self-verify failed")
    return sig

def schnorr_verify(msg, pubkey, sig):
    if len(pubkey) != 32 or len(sig) != 64:
        return False
    point = lift_x(pubkey)
    if point is None:
        return False
    r = int_from_bytes(sig[0:32])
    s = int_from_bytes(sig[32:64])
    if r >= P_FIELD or s >= N_ORDER:
        return False
    e = int_from_bytes(tagged_hash("BIP0340/challenge",
            sig[0:32] + pubkey + msg)) % N_ORDER
    rr = point_add(point_mul(G, s), point_mul(point, N_ORDER - e))
    if rr is None or not has_even_y(rr) or px(rr) != r:
        return False
    return True

# ---------------------------------------------------------------------------
# HKDF-SHA256 (RFC 5869)
# ---------------------------------------------------------------------------
def hkdf_sha256(ikm, salt, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, c = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha256).digest()
        okm += t
        c += 1
    return okm[:length]

# ---------------------------------------------------------------------------
# NIP-41 -- derivation, tweak, identity chain
# ---------------------------------------------------------------------------
HKDF_SALT = b"nip41-key-rotation-v1"
TWEAK_TAG = "nip41/succession"

def nip41_internal_seckey(root_secret, i):
    """Internal private key for generation i (HKDF). Reject-and-rederive if
    the output is not a valid secp256k1 scalar."""
    counter = 0
    while True:
        info = b"internal-key" + i.to_bytes(4, "big")
        if counter:
            info += bytes([counter])
        d = int_from_bytes(hkdf_sha256(root_secret, HKDF_SALT, info, 32))
        if 1 <= d <= N_ORDER - 1:
            return d
        counter += 1
        if counter > 255:
            raise RuntimeError("derivation failed")

def nip41_tweak(internal_xonly, successor_xonly):
    """NIP-41 tweak scalar material: a BIP-340 tagged hash committing the
    internal key to its successor identity."""
    return tagged_hash(TWEAK_TAG, internal_xonly + successor_xonly)

def nip41_tweak_pubkey(internal_xonly, successor_xonly):
    """BIP-341 key-path pubkey tweak, NIP-41 domain tag.
    Returns (parity, tweaked_xonly_pubkey)."""
    t = int_from_bytes(nip41_tweak(internal_xonly, successor_xonly))
    if t >= N_ORDER:
        raise ValueError("tweak >= curve order; re-derive internal key")
    point = lift_x(internal_xonly)
    if point is None:
        raise ValueError("invalid internal x-only key")
    q = point_add(point, point_mul(G, t))
    if q is None:
        raise ValueError("tweaked key is the point at infinity")
    return (0 if has_even_y(q) else 1, bytes_from_point(q))

def nip41_tweak_seckey(internal_seckey, successor_xonly):
    """BIP-341 key-path secret-key tweak, NIP-41 domain tag.
    Returns the BIP-340 signing private key for the tweaked identity."""
    d0 = int_from_bytes(internal_seckey)
    point = point_mul(G, d0)
    d = d0 if has_even_y(point) else N_ORDER - d0
    t = int_from_bytes(nip41_tweak(bytes_from_point(point), successor_xonly))
    if t >= N_ORDER:
        raise ValueError("tweak >= curve order; re-derive internal key")
    return bytes_from_int((d + t) % N_ORDER)

def build_chain(root_secret, length):
    """Build an identity chain of the given length. Built backwards: each
    generation commits to its successor."""
    p_int = [nip41_internal_seckey(root_secret, i) for i in range(length)]
    points = [point_mul(G, d) for d in p_int]
    internal_xonly = [bytes_from_point(pt) for pt in points]

    npub = [None] * length
    nsec = [None] * length
    tweak = [None] * length

    # terminal generation commits to nothing -- plain (even-y) key
    npub[length - 1] = internal_xonly[length - 1]
    last = p_int[length - 1]
    nsec[length - 1] = bytes_from_int(
        last if has_even_y(points[length - 1]) else N_ORDER - last)

    for i in range(length - 2, -1, -1):
        tweak[i] = nip41_tweak(internal_xonly[i], npub[i + 1])
        _, npub[i] = nip41_tweak_pubkey(internal_xonly[i], npub[i + 1])
        nsec[i] = nip41_tweak_seckey(bytes_from_int(p_int[i]), npub[i + 1])

    return {"p_int": p_int, "internal_xonly": internal_xonly,
            "npub": npub, "nsec": nsec, "tweak": tweak}

def verify_chain_proof(subject, npub_next, internal_xonly):
    """NIP-41 verify_chain_proof predicate (spec line 945):
    returns true iff applying the succession tweak to internal_xonly with
    npub_next reproduces subject."""
    try:
        _, q = nip41_tweak_pubkey(internal_xonly, npub_next)
    except ValueError:
        return False
    return q == subject

# ---------------------------------------------------------------------------
# Nostr event helpers
# ---------------------------------------------------------------------------
def nostr_event_id(pubkey_hex, created_at, kind, tags, content):
    ser = json.dumps([0, pubkey_hex, created_at, kind, tags, content],
                     separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(ser.encode("utf-8")).digest()

def sign_event(nsec, pubkey, created_at, kind, tags, content):
    pubkey_hex = pubkey.hex()
    eid = nostr_event_id(pubkey_hex, created_at, kind, tags, content)
    sig = schnorr_sign(eid, nsec, bytes(32))
    return {"id": eid.hex(), "pubkey": pubkey_hex, "created_at": created_at,
            "kind": kind, "tags": tags, "content": content, "sig": sig.hex()}

def make_chain_birth_event(nsec0, npub0, internal_xonly0, npub1, created_at):
    """kind:1041 chain-birth event (spec lines 330-348): a single self-successor
    tag and a single ["p", npub0, "", "successor"] discovery tag."""
    tags = [
        ["p", npub0.hex(), "", "successor"],
        ["successor", npub0.hex(), internal_xonly0.hex(), npub1.hex()],
    ]
    return sign_event(nsec0, npub0, created_at, 1041, tags, "")

def make_rotation_event(prev_npub, prev_internal_xonly,
                        new_nsec, new_npub, new_internal_xonly,
                        next_npub, created_at, content=""):
    """kind:1041 rotation event (spec lines 354-368): predecessor-proof
    successor tag + self-successor tag, plus the two p-marker discovery tags."""
    tags = [
        ["p", prev_npub.hex(), "", "predecessor"],
        ["p", new_npub.hex(), "", "successor"],
        ["successor", prev_npub.hex(), prev_internal_xonly.hex(),
                                       new_npub.hex()],
        ["successor", new_npub.hex(), new_internal_xonly.hex(),
                                      next_npub.hex()],
    ]
    return sign_event(new_nsec, new_npub, created_at, 1041, tags, content)

def make_kind1042_commitment(legacy_nsec, legacy_npub, fresh_npub0, created_at):
    """kind:1042 bridge commitment (spec 'The bridge for existing keys',
    lines 589-602): a one-time event signed by the legacy key committing
    to migrate into a fresh committed chain whose npub[0] is given.
    Carries exactly one `commits` tag."""
    tags = [["commits", fresh_npub0.hex()]]
    return sign_event(legacy_nsec, legacy_npub, created_at, 1042, tags, "")

def make_bridge_rotation_event(legacy_npub, kind1042_id,
                               fresh_nsec0, fresh_npub0,
                               fresh_internal_xonly0, fresh_npub1,
                               created_at, content=""):
    """Bridge kind:1041 event (spec 'The bridge for existing keys',
    lines 613-627). Signed by the fresh chain's nsec[0]. Carries the
    bridge tag in place of a predecessor-proof successor tag, plus a
    self-successor establishing the fresh chain as a committed identity."""
    tags = [
        ["p", legacy_npub.hex(), "", "predecessor"],
        ["p", fresh_npub0.hex(), "", "successor"],
        ["bridge", legacy_npub.hex(), kind1042_id.hex()],
        ["successor", fresh_npub0.hex(), fresh_internal_xonly0.hex(),
                                         fresh_npub1.hex()],
    ]
    return sign_event(fresh_nsec0, fresh_npub0, created_at, 1041, tags, content)

# ---------------------------------------------------------------------------
# NIP-41 event-validity predicate (spec lines 404-424). Bridge support
# deferred; bridge tags are treated as invalid here.
# ---------------------------------------------------------------------------
class Verification:
    def __init__(self, ok, kind=None, predecessor=None, subject=None,
                 successor=None, legacypub=None, kind1042_id=None, reason=None):
        self.ok = ok
        self.kind = kind                   # "chain_birth" | "rotation" | "bridge"
        self.predecessor = predecessor     # bytes or None
        self.subject = subject             # bytes
        self.successor = successor         # bytes
        self.legacypub = legacypub         # bytes (only for bridge)
        self.kind1042_id = kind1042_id     # bytes (only for bridge)
        self.reason = reason               # str describing why invalid

    @classmethod
    def chain_birth(cls, subject, successor):
        return cls(True, "chain_birth", None, subject, successor)

    @classmethod
    def rotation(cls, predecessor, subject, successor):
        return cls(True, "rotation", predecessor, subject, successor)

    @classmethod
    def bridge(cls, legacypub, subject, successor, kind1042_id):
        """Bridge event from a legacy (uncommitted) key into a fresh
        committed chain (spec 'The bridge for existing keys'). Returned
        on intrinsic verification only -- the external gates (no
        isCommitted(legacypub), referenced kind:1042 valid and
        uncontested) are checked by verify_bridge."""
        return cls(True, "bridge", None, subject, successor,
                   legacypub=legacypub, kind1042_id=kind1042_id)

    @classmethod
    def invalid(cls, reason):
        return cls(False, reason=reason)

def verify_event(event):
    """Apply the event-validity rules from spec lines 404-424. Returns a
    Verification of kind chain_birth, rotation, or bridge on intrinsic
    success; otherwise invalid. Bridge events additionally require
    verify_bridge with the external context (kind:1042 + isCommitted +
    conflict search) before they may be acted on."""
    if event.get("kind") != 1041:
        return Verification.invalid("kind != 1041")

    try:
        pubkey = bytes.fromhex(event["pubkey"])
        sig = bytes.fromhex(event["sig"])
    except (KeyError, ValueError):
        return Verification.invalid("malformed pubkey or sig")
    if len(pubkey) != 32 or len(sig) != 64:
        return Verification.invalid("pubkey or sig wrong length")

    eid = nostr_event_id(event["pubkey"], event["created_at"], event["kind"],
                         event["tags"], event["content"])
    if eid.hex() != event["id"]:
        return Verification.invalid("event id does not match canonical serialization")
    if not schnorr_verify(eid, pubkey, sig):
        return Verification.invalid("invalid signature")

    self_successor = None
    predecessor_proof = None
    bridge = None                       # (legacypub_b, kind1042_id_b)
    p_successor_values = []
    p_predecessor_values = []

    for tag in event["tags"]:
        if not tag:
            continue
        if tag[0] == "successor":
            if len(tag) != 4:
                return Verification.invalid("successor tag wrong arity")
            try:
                subject_b = bytes.fromhex(tag[1])
                internal_b = bytes.fromhex(tag[2])
                npub_next_b = bytes.fromhex(tag[3])
            except ValueError:
                return Verification.invalid("successor tag bad hex")
            if not verify_chain_proof(subject_b, npub_next_b, internal_b):
                return Verification.invalid("successor tag fails verify_chain_proof")
            is_self = subject_b == pubkey and npub_next_b != pubkey
            is_pred = subject_b != pubkey and npub_next_b == pubkey
            if not (is_self or is_pred):
                return Verification.invalid("successor tag fits neither pattern")
            if is_self:
                if self_successor is not None:
                    return Verification.invalid("multiple self-successor tags")
                self_successor = (subject_b, npub_next_b)
            else:
                if predecessor_proof is not None:
                    return Verification.invalid("multiple predecessor-proof tags")
                predecessor_proof = (subject_b, npub_next_b)
        elif tag[0] == "bridge":
            if len(tag) != 3:
                return Verification.invalid("bridge tag wrong arity")
            if bridge is not None:
                return Verification.invalid("multiple bridge tags")
            try:
                legacypub_b = bytes.fromhex(tag[1])
                k1042_id_b = bytes.fromhex(tag[2])
            except ValueError:
                return Verification.invalid("bridge tag bad hex")
            if len(legacypub_b) != 32 or len(k1042_id_b) != 32:
                return Verification.invalid("bridge tag values wrong length")
            bridge = (legacypub_b, k1042_id_b)
        elif tag[0] == "p" and len(tag) >= 4:
            if tag[3] == "successor":
                p_successor_values.append(tag[1])
            elif tag[3] == "predecessor":
                p_predecessor_values.append(tag[1])

    # Bridge replaces the predecessor-proof successor tag; carrying both
    # is a shape error (spec "Event shapes": rotation has predecessor
    # proof, bridge has bridge tag -- never both).
    if bridge is not None and predecessor_proof is not None:
        return Verification.invalid(
            "event must not carry both a bridge tag and a predecessor-proof successor tag")

    if self_successor is None and predecessor_proof is None and bridge is None:
        return Verification.invalid("no predecessor proof, no bridge, and no self-successor")

    if len(p_successor_values) != 1:
        return Verification.invalid("must have exactly one ['p',_,_,'successor'] tag")
    if p_successor_values[0] != event["pubkey"]:
        return Verification.invalid("successor p-tag value != event.pubkey")

    if bridge is not None:
        # A bridge event must carry a self-successor (it is the chain
        # birth of the fresh committed chain) and a predecessor p-tag
        # pointing at the legacy key being bridged.
        if self_successor is None:
            return Verification.invalid("bridge event missing self-successor tag")
        if len(p_predecessor_values) != 1:
            return Verification.invalid("bridge event must have exactly one predecessor p-tag")
        if p_predecessor_values[0] != bridge[0].hex():
            return Verification.invalid("bridge event predecessor p-tag does not match bridge legacypub")
        return Verification.bridge(
            legacypub=bridge[0],
            subject=self_successor[0],
            successor=self_successor[1],
            kind1042_id=bridge[1],
        )

    if predecessor_proof is not None:
        if self_successor is None:
            return Verification.invalid("rotation event missing self-successor tag")
        expected_pred_hex = predecessor_proof[0].hex()
        if len(p_predecessor_values) != 1:
            return Verification.invalid("must have exactly one predecessor p-tag when predecessor present")
        if p_predecessor_values[0] != expected_pred_hex:
            return Verification.invalid("predecessor p-tag does not match predecessor proof")
        return Verification.rotation(
            predecessor=predecessor_proof[0],
            subject=pubkey,
            successor=self_successor[1],
        )

    # chain-birth: no predecessor proof, no bridge, must have
    # self-successor, no predecessor p-tag
    if len(p_predecessor_values) != 0:
        return Verification.invalid("chain-birth event must not have predecessor p-tag")
    return Verification.chain_birth(
        subject=self_successor[0],
        successor=self_successor[1],
    )

# ---------------------------------------------------------------------------
# Bridge support (spec "The bridge for existing keys")
# ---------------------------------------------------------------------------

class K1042Verification:
    """Outcome of verifying a kind:1042 bridge commitment."""
    def __init__(self, ok, commits=None, reason=None):
        self.ok = ok
        self.commits = commits         # bytes (32) -- target npub[0]
        self.reason = reason

    @classmethod
    def valid(cls, commits):
        return cls(True, commits=commits)

    @classmethod
    def invalid(cls, reason):
        return cls(False, reason=reason)

def verify_kind1042_event(event):
    """Verify a candidate kind:1042 bridge commitment (spec 'Bridge
    commitment kind:1042'). Accepts iff kind == 1042, event id matches
    the canonical serialization, the BIP-340 signature is valid, and
    exactly one `commits` tag is present with a 32-byte hex value."""
    if event.get("kind") != 1042:
        return K1042Verification.invalid("kind != 1042")

    try:
        pubkey = bytes.fromhex(event["pubkey"])
        sig = bytes.fromhex(event["sig"])
    except (KeyError, ValueError):
        return K1042Verification.invalid("malformed pubkey or sig")
    if len(pubkey) != 32 or len(sig) != 64:
        return K1042Verification.invalid("pubkey or sig wrong length")

    eid = nostr_event_id(event["pubkey"], event["created_at"], event["kind"],
                         event["tags"], event["content"])
    if eid.hex() != event["id"]:
        return K1042Verification.invalid("event id does not match canonical serialization")
    if not schnorr_verify(eid, pubkey, sig):
        return K1042Verification.invalid("invalid signature")

    commits_tags = [t for t in event["tags"] if t and t[0] == "commits"]
    if len(commits_tags) == 0:
        return K1042Verification.invalid("missing commits tag")
    if len(commits_tags) > 1:
        return K1042Verification.invalid("multiple commits tags")
    if len(commits_tags[0]) != 2:
        return K1042Verification.invalid("commits tag wrong arity")
    try:
        commits = bytes.fromhex(commits_tags[0][1])
    except ValueError:
        return K1042Verification.invalid("commits value bad hex")
    if len(commits) != 32:
        return K1042Verification.invalid("commits value wrong length")
    return K1042Verification.valid(commits)

def is_committed(subject, events):
    """Spec 'Client verification' / isCommitted(K): true iff some event
    in `events` is a valid kind:1041 (ChainBirth, Rotation, or Bridge)
    whose pubkey equals `subject`. Bridge events count because their
    self-successor binds event.pubkey to its successor; the bridge tag
    attaches a legacy origin but does not weaken the self-commitment."""
    if len(subject) != 32:
        return False
    for event in events:
        try:
            pk = bytes.fromhex(event.get("pubkey", ""))
        except ValueError:
            continue
        if pk != subject:
            continue
        v = verify_event(event)
        if v.ok and v.kind in ("chain_birth", "rotation", "bridge"):
            return True
    return False

def bridge_commits_conflict(legacypub, events):
    """Spec 'The bridge for existing keys' fail-closed rule (lines
    678-682): true iff more than one kind:1042 signed by legacypub is
    seen with **different** commits targets. Invalid events do not count
    -- a malformed kind:1042 cannot manufacture a contest."""
    if len(legacypub) != 32:
        return False
    targets = set()
    for event in events:
        try:
            pk = bytes.fromhex(event.get("pubkey", ""))
        except ValueError:
            continue
        if pk != legacypub:
            continue
        v = verify_kind1042_event(event)
        if not v.ok:
            continue
        targets.add(v.commits)
    return len(targets) > 1

class BridgeVerification:
    """Outcome of the external bridge gates from spec 'The bridge for
    existing keys' (verify_bridge, lines 649-666)."""
    def __init__(self, ok, reason=None):
        self.ok = ok
        self.reason = reason

    @classmethod
    def valid(cls):
        return cls(True)

    @classmethod
    def invalid(cls, reason):
        return cls(False, reason=reason)

def verify_bridge(bridge_outcome, is_committed_decision,
                  kind1042_event, legacypub_kind1042_events):
    """Spec 'The bridge for existing keys' / verify_bridge (lines
    649-666): the three-conjunct predicate that gates a bridge rotation.

    bridge_outcome             -- a Verification of kind 'bridge' from
                                   verify_event
    is_committed_decision      -- the caller's is_committed(legacypub, ...)
                                   answer evaluated against the broad-poll
                                   relay set
    kind1042_event             -- the kind:1042 event whose id matches
                                   bridge_outcome.kind1042_id, or None
    legacypub_kind1042_events  -- all known kind:1042 events purportedly
                                   signed by bridge_outcome.legacypub, for
                                   the conflict search
    """
    # Gate 1: legacypub must not be a committed-chain generation.
    if is_committed_decision:
        return BridgeVerification.invalid(
            "legacypub is committed; bridges only apply to legacy keys")

    # Gate 2: referenced kind:1042 must exist, verify, be signed by
    # legacypub, and commit to bridge_outcome.subject.
    if kind1042_event is None:
        return BridgeVerification.invalid("missing referenced kind:1042 event")
    try:
        ref_id = bytes.fromhex(kind1042_event.get("id", ""))
        ref_pubkey = bytes.fromhex(kind1042_event.get("pubkey", ""))
    except ValueError:
        return BridgeVerification.invalid("malformed kind:1042 id or pubkey hex")
    if ref_id != bridge_outcome.kind1042_id:
        return BridgeVerification.invalid("kind:1042 event id does not match bridge tag")
    if ref_pubkey != bridge_outcome.legacypub:
        return BridgeVerification.invalid("kind:1042 event not signed by bridge legacypub")
    k1042 = verify_kind1042_event(kind1042_event)
    if not k1042.ok:
        return BridgeVerification.invalid("kind:1042 invalid: %s" % k1042.reason)
    if k1042.commits != bridge_outcome.subject:
        return BridgeVerification.invalid("kind:1042 commits target != bridge subject")

    # Gate 3: fail-closed conflict rule.
    if bridge_commits_conflict(bridge_outcome.legacypub, legacypub_kind1042_events):
        return BridgeVerification.invalid(
            "legacypub kind:1042 commitments are contested (conflict)")

    return BridgeVerification.valid()

# ---------------------------------------------------------------------------
# Test-vector generation + assertions
# ---------------------------------------------------------------------------
def main():
    root_secret = hashlib.sha256(b"nip-41 test vector root secret v1").digest()
    length = 4
    chain = build_chain(root_secret, length)
    npub, nsec = chain["npub"], chain["nsec"]
    internal_xonly, tweak, p_int = (chain["internal_xonly"],
                                    chain["tweak"], chain["p_int"])

    results = []
    def check(name, cond):
        results.append((name, bool(cond)))
        if not cond:
            print("FAILED:", name)
            sys.exit(1)

    # ----- chain self-consistency ------------------------------------------

    # each signing key reproduces its published identity
    for i in range(length):
        pt = point_mul(G, int_from_bytes(nsec[i]))
        check("gen%d: nsec*G x-only equals npub" % i,
              bytes_from_point(pt) == npub[i])

    # each signing key produces valid BIP-340 signatures for its npub
    for i in range(length):
        msg = hashlib.sha256(("message from gen %d" % i).encode()).digest()
        sig = schnorr_sign(msg, nsec[i], bytes(32))
        check("gen%d: BIP-340 sign+verify round-trip" % i,
              schnorr_verify(msg, npub[i], sig))

    # each non-terminal commitment verifies via verify_chain_proof
    for i in range(length - 1):
        check("gen%d -> gen%d: tweak commitment verifies" % (i, i + 1),
              verify_chain_proof(npub[i], npub[i + 1], internal_xonly[i]))

    # ----- positive events: chain-birth + two rotations --------------------

    birth = make_chain_birth_event(nsec[0], npub[0], internal_xonly[0],
                                   npub[1], 1716100000)
    v_birth = verify_event(birth)
    check("chain-birth event: verify_event returns ChainBirth",
          v_birth.ok and v_birth.kind == "chain_birth")
    check("chain-birth event: subject == npub[0]",
          v_birth.subject == npub[0])
    check("chain-birth event: successor == npub[1]",
          v_birth.successor == npub[1])

    rot01 = make_rotation_event(npub[0], internal_xonly[0],
                                nsec[1], npub[1], internal_xonly[1],
                                npub[2], 1716200000,
                                content="optional human-readable note")
    v01 = verify_event(rot01)
    check("rotation 0->1: verify_event returns Rotation",
          v01.ok and v01.kind == "rotation")
    check("rotation 0->1: predecessor == npub[0]", v01.predecessor == npub[0])
    check("rotation 0->1: subject == npub[1]",     v01.subject == npub[1])
    check("rotation 0->1: successor == npub[2]",   v01.successor == npub[2])

    rot12 = make_rotation_event(npub[1], internal_xonly[1],
                                nsec[2], npub[2], internal_xonly[2],
                                npub[3], 1716300000)
    v12 = verify_event(rot12)
    check("rotation 1->2: verify_event returns Rotation",
          v12.ok and v12.kind == "rotation")
    check("rotation 1->2: predecessor == npub[1]", v12.predecessor == npub[1])
    check("rotation 1->2: subject == npub[2]",     v12.subject == npub[2])

    # ----- cryptographic negatives (verify_chain_proof level) --------------

    attacker_npub = bytes_from_point(point_mul(G, 0xA77ACC))
    check("crypto-neg: real internal key + attacker successor -> rejected",
          not verify_chain_proof(npub[0], attacker_npub, internal_xonly[0]))
    rand_internal = bytes_from_point(point_mul(G, 0xBADBADBAD))
    check("crypto-neg: random internal key + attacker successor -> rejected",
          not verify_chain_proof(npub[0], attacker_npub, rand_internal))
    check("crypto-neg: real internal key + wrong successor (gen2) -> rejected",
          not verify_chain_proof(npub[0], npub[2], internal_xonly[0]))

    # ----- event-validity negatives (verify_event level) ------------------

    # missing the ["p", _, _, "successor"] discovery tag
    neg_missing_succ_p = sign_event(
        nsec[1], npub[1], 1716200000, 1041,
        [
            ["p", npub[0].hex(), "", "predecessor"],
            ["successor", npub[0].hex(), internal_xonly[0].hex(), npub[1].hex()],
            ["successor", npub[1].hex(), internal_xonly[1].hex(), npub[2].hex()],
        ], "")
    v_miss = verify_event(neg_missing_succ_p)
    check("event-neg: missing successor p-tag rejected",
          not v_miss.ok and "successor" in v_miss.reason)

    # predecessor p-tag value disagrees with the predecessor-proof tag
    neg_bad_pred_p = sign_event(
        nsec[1], npub[1], 1716200000, 1041,
        [
            ["p", attacker_npub.hex(), "", "predecessor"],   # wrong: not npub[0]
            ["p", npub[1].hex(), "", "successor"],
            ["successor", npub[0].hex(), internal_xonly[0].hex(), npub[1].hex()],
            ["successor", npub[1].hex(), internal_xonly[1].hex(), npub[2].hex()],
        ], "")
    v_bad_pred = verify_event(neg_bad_pred_p)
    check("event-neg: mismatched predecessor p-tag rejected",
          not v_bad_pred.ok and "predecessor" in v_bad_pred.reason)

    # two self-successor tags (multiplicity rule)
    neg_two_self = sign_event(
        nsec[1], npub[1], 1716200000, 1041,
        [
            ["p", npub[0].hex(), "", "predecessor"],
            ["p", npub[1].hex(), "", "successor"],
            ["successor", npub[0].hex(), internal_xonly[0].hex(), npub[1].hex()],
            ["successor", npub[1].hex(), internal_xonly[1].hex(), npub[2].hex()],
            ["successor", npub[1].hex(), internal_xonly[1].hex(), npub[2].hex()],
        ], "")
    v_two_self = verify_event(neg_two_self)
    check("event-neg: two self-successor tags rejected",
          not v_two_self.ok and "self-successor" in v_two_self.reason)

    # ----- forged-by-attacker rotation: signature valid but verify_chain_proof
    #       (and therefore verify_event) rejects it.
    forged = make_rotation_event(
        npub[0], internal_xonly[0],
        bytes_from_int(0xA77ACC), attacker_npub, internal_xonly[1],
        npub[2], 1716200000)
    check("crypto-neg: forged event has a valid signature (as expected)",
          schnorr_verify(bytes.fromhex(forged["id"]), attacker_npub,
                         bytes.fromhex(forged["sig"])))
    check("crypto-neg: forged event FAILS verify_event",
          not verify_event(forged).ok)

    # ----- bridge for existing keys ----------------------------------------
    # Fixtures: a deterministic legacy nsec, plus a separate "fresh" chain
    # that the legacy key bridges into. Keeping the fresh chain distinct
    # from the existing rotation chain (root_secret above) makes the
    # narrative clean -- npub[0] of the main chain remains a chain-birth
    # case, and the bridge case uses an unrelated fresh chain head.

    legacy_nsec = hashlib.sha256(b"nip-41 bridge test vector legacy v1").digest()
    legacy_d0 = int_from_bytes(legacy_nsec)
    assert 1 <= legacy_d0 <= N_ORDER - 1, "legacy seckey out of range"
    legacy_npub = bytes_from_point(point_mul(G, legacy_d0))

    fresh_root = hashlib.sha256(b"nip-41 bridge test vector fresh root v1").digest()
    fresh = build_chain(fresh_root, 2)  # minimum length: needs npub[1] for self-successor
    fresh_npub, fresh_nsec = fresh["npub"], fresh["nsec"]
    fresh_internal_xonly = fresh["internal_xonly"]

    # Scenario A: kind:1042 happy path -- legacy commits to fresh npub[0].
    k1042_happy = make_kind1042_commitment(
        legacy_nsec, legacy_npub, fresh_npub[0], 1716100100)
    v_k1042 = verify_kind1042_event(k1042_happy)
    check("bridge: kind:1042 verifies", v_k1042.ok)
    check("bridge: kind:1042 commits target == fresh.npub[0]",
          v_k1042.commits == fresh_npub[0])

    # Scenario B: bridge kind:1041 happy path + verify_bridge trace.
    k1042_happy_id = bytes.fromhex(k1042_happy["id"])
    bridge_event = make_bridge_rotation_event(
        legacy_npub, k1042_happy_id,
        fresh_nsec[0], fresh_npub[0], fresh_internal_xonly[0], fresh_npub[1],
        1716100200)
    v_bridge_intrinsic = verify_event(bridge_event)
    check("bridge: verify_event returns Bridge",
          v_bridge_intrinsic.ok and v_bridge_intrinsic.kind == "bridge")
    check("bridge: intrinsic legacypub == legacy_npub",
          v_bridge_intrinsic.legacypub == legacy_npub)
    check("bridge: intrinsic subject == fresh.npub[0]",
          v_bridge_intrinsic.subject == fresh_npub[0])
    check("bridge: intrinsic successor == fresh.npub[1]",
          v_bridge_intrinsic.successor == fresh_npub[1])
    check("bridge: intrinsic kind1042_id matches the bridge tag",
          v_bridge_intrinsic.kind1042_id == k1042_happy_id)

    v_bridge_full = verify_bridge(
        v_bridge_intrinsic,
        is_committed_decision=False,
        kind1042_event=k1042_happy,
        legacypub_kind1042_events=[k1042_happy])
    check("bridge: verify_bridge accepts when all three gates pass",
          v_bridge_full.ok)

    # Scenario C: contested legacypub -- a second kind:1042 from legacy
    # pointing at a different target. The conflict rule MUST fire.
    contesting_target = bytes_from_point(point_mul(G, 0xC0FFEE))
    k1042_contest = make_kind1042_commitment(
        legacy_nsec, legacy_npub, contesting_target, 1716100300)
    check("bridge: bridge_commits_conflict fires for two distinct targets",
          bridge_commits_conflict(legacy_npub, [k1042_happy, k1042_contest]))
    v_bridge_contested = verify_bridge(
        v_bridge_intrinsic,
        is_committed_decision=False,
        kind1042_event=k1042_happy,
        legacypub_kind1042_events=[k1042_happy, k1042_contest])
    check("bridge: verify_bridge refuses a contested legacypub",
          not v_bridge_contested.ok and "contest" in v_bridge_contested.reason)

    # Scenario D: mismatched kind:1042 commits target -- the legacy key
    # publishes a kind:1042 whose commits value disagrees with the bridge
    # event's subject. verify_bridge MUST refuse it.
    mismatch_target = bytes_from_point(point_mul(G, 0xBADBEEF))
    k1042_mismatch = make_kind1042_commitment(
        legacy_nsec, legacy_npub, mismatch_target, 1716100400)
    k1042_mismatch_id = bytes.fromhex(k1042_mismatch["id"])
    bridge_event_mismatch = make_bridge_rotation_event(
        legacy_npub, k1042_mismatch_id,
        fresh_nsec[0], fresh_npub[0], fresh_internal_xonly[0], fresh_npub[1],
        1716100500)
    v_mismatch_intrinsic = verify_event(bridge_event_mismatch)
    check("bridge: mismatch-scenario intrinsic verification still returns Bridge",
          v_mismatch_intrinsic.ok and v_mismatch_intrinsic.kind == "bridge")
    v_mismatch_full = verify_bridge(
        v_mismatch_intrinsic,
        is_committed_decision=False,
        kind1042_event=k1042_mismatch,
        legacypub_kind1042_events=[k1042_mismatch])
    check("bridge: verify_bridge refuses kind:1042 with wrong commits target",
          not v_mismatch_full.ok and "commits" in v_mismatch_full.reason)

    bridge_artifacts = {
        "legacy_nsec":          legacy_nsec,
        "legacy_npub":          legacy_npub,
        "fresh_root":           fresh_root,
        "fresh":                fresh,
        "k1042_happy":          k1042_happy,
        "bridge_event":         bridge_event,
        "contesting_target":    contesting_target,
        "k1042_contest":        k1042_contest,
        "mismatch_target":      mismatch_target,
        "k1042_mismatch":       k1042_mismatch,
        "bridge_event_mismatch": bridge_event_mismatch,
    }

    md_path = write_markdown(root_secret, length, chain,
                             birth, rot01, rot12,
                             neg_bad_pred_p, bridge_artifacts, results)
    md_sha = hashlib.sha256(open(md_path, "rb").read()).hexdigest()
    print("ALL %d ASSERTIONS PASSED" % len(results))
    print("Test vectors written to nip-41-test-vectors.md")
    print("SHA-256(nip-41-test-vectors.md) = %s" % md_sha)

def write_markdown(root_secret, length, chain, birth, rot01, rot12,
                   neg_event, bridge, results):
    npub, nsec = chain["npub"], chain["nsec"]
    internal_xonly, tweak, p_int = (chain["internal_xonly"],
                                    chain["tweak"], chain["p_int"])
    L = []
    L.append("# NIP-41 Draft -- Test Vectors")
    L.append("")
    L.append("> Generated by `nip-41-test-vectors.py`. Do not edit by hand.")
    L.append("> Every value below was produced by real secp256k1 / BIP-340 "
             "arithmetic")
    L.append("> (pure-Python BIP-340 reference code) and checked by the "
             "assertions in")
    L.append("> that script. If the script runs without error, these vectors "
             "hold.")
    L.append("")
    L.append("## Parameters")
    L.append("")
    L.append("- HKDF salt: `nip41-key-rotation-v1`")
    L.append("- Tweak tag (BIP-340 tagged hash): `nip41/succession`")
    L.append("- Event kind: `1041` (chain-birth and rotation)")
    L.append("- Chain length for this vector: `%d`" % length)
    L.append("- `root_secret` (test value = SHA-256 of a fixed string):")
    L.append("  ```")
    L.append("  " + root_secret.hex())
    L.append("  ```")
    L.append("")
    L.append("## Identity chain")
    L.append("")
    L.append("Built backwards: generation `i` commits to generation `i+1`. "
             "The terminal")
    L.append("generation commits to nothing. All keys are 32-byte hex.")
    L.append("")
    for i in range(length):
        L.append("### Generation %d%s" % (
            i, "  (terminal)" if i == length - 1 else ""))
        L.append("")
        L.append("```")
        L.append("internal seckey p_internal : %s" %
                 bytes_from_int(p_int[i]).hex())
        L.append("internal pubkey (x-only)   : %s" % internal_xonly[i].hex())
        if tweak[i] is not None:
            L.append("tweak  = H(tag | internal | npub[i+1]) :")
            L.append("                             %s" % tweak[i].hex())
        else:
            L.append("tweak                      : (none -- terminal)")
        L.append("npub  (published identity) : %s" % npub[i].hex())
        L.append("nsec  (BIP-340 signing key): %s" % nsec[i].hex())
        L.append("```")
        L.append("")

    L.append("## Chain-birth event (kind 1041)")
    L.append("")
    L.append("Published from `npub[0]` as the first event the chain ever signs.")
    L.append("Carries a single self-successor tag declaring `npub[0]` as a")
    L.append("committed-chain generation whose successor is `npub[1]`.")
    L.append("Signed by `nsec[0]`.")
    L.append("")
    L.append("```json")
    L.append(json.dumps(birth, indent=2))
    L.append("```")
    L.append("")

    L.append("## Rotation event (kind 1041): generation 0 -> generation 1")
    L.append("")
    L.append("Signed by `nsec[1]` (the NEW key). Carries a predecessor proof")
    L.append("for `npub[0]` and a self-successor for `npub[1]`.")
    L.append("")
    L.append("```json")
    L.append(json.dumps(rot01, indent=2))
    L.append("```")
    L.append("")
    L.append("### Verification trace")
    L.append("")
    L.append("```")
    L.append("1. signature valid for pubkey npub[1]              : PASS")
    L.append("2. event id recomputes from serialization          : PASS")
    L.append("3. predecessor-proof successor tag values          :")
    L.append("   subject     = npub[0]")
    L.append("   P_internal  = %s" % rot01["tags"][2][2])
    L.append("   npub_next   = npub[1]")
    L.append("   verify_chain_proof(npub[0], npub[1], P_internal) : PASS")
    L.append("4. self-successor tag values                        :")
    L.append("   subject     = npub[1]")
    L.append("   P_internal  = %s" % rot01["tags"][3][2])
    L.append("   npub_next   = npub[2]")
    L.append("   verify_chain_proof(npub[1], npub[2], P_internal) : PASS")
    L.append("5. discovery p-tag cross-check                      : PASS")
    L.append("   ['p', npub[0], '', 'predecessor']")
    L.append("   ['p', npub[1], '', 'successor']  (== event.pubkey)")
    L.append("6. multiplicity (<=1 self, <=1 predecessor)         : PASS")
    L.append("=> rotation VERIFIED, identity moves 0 -> 1")
    L.append("```")
    L.append("")

    L.append("## Rotation event (kind 1041): generation 1 -> generation 2")
    L.append("")
    L.append("Signed by `nsec[2]`. Same shape as the previous, one generation on.")
    L.append("Included so the vectors exercise an interior rotation in addition")
    L.append("to the chain head.")
    L.append("")
    L.append("```json")
    L.append(json.dumps(rot12, indent=2))
    L.append("```")
    L.append("")

    L.append("## Negative -- predecessor p-tag does not match the proof")
    L.append("")
    L.append("Same cryptographic content as the 0 -> 1 rotation, but the")
    L.append("`['p', _, '', 'predecessor']` discovery tag points at an attacker")
    L.append("key instead of `npub[0]`. The cryptographic `successor` tags still")
    L.append("verify, but the p-tag cross-check rule rejects the event.")
    L.append("")
    L.append("```json")
    L.append(json.dumps(neg_event, indent=2))
    L.append("```")
    L.append("")
    L.append("```")
    L.append("signature valid                                     : PASS (as expected)")
    L.append("successor tags pass verify_chain_proof              : PASS (as expected)")
    L.append("predecessor p-tag matches predecessor proof         : REJECTED (correct)")
    L.append("```")
    L.append("")

    # =====================================================================
    # Bridge for existing keys (spec "The bridge for existing keys")
    # =====================================================================
    fresh = bridge["fresh"]
    fresh_npub = fresh["npub"]
    fresh_internal_xonly = fresh["internal_xonly"]
    fresh_p_int = fresh["p_int"]
    fresh_nsec_list = fresh["nsec"]

    L.append("## Bridge fixtures")
    L.append("")
    L.append("These vectors exercise the spec's bridge mechanism, which lets a")
    L.append("legacy (uncommitted) key migrate **once** into a fresh committed")
    L.append("chain. The legacy key and the fresh chain are independent of the")
    L.append("rotation chain above; reusing values across the two would make the")
    L.append("narrative ambiguous (a key is either a chain head OR a bridge")
    L.append("target, never both in the same world line).")
    L.append("")
    L.append("- `legacy_nsec` (test value = SHA-256 of a fixed string):")
    L.append("  ```")
    L.append("  " + bridge["legacy_nsec"].hex())
    L.append("  ```")
    L.append("- `legacy_npub` (BIP-340 x-only pubkey of `legacy_nsec`):")
    L.append("  ```")
    L.append("  " + bridge["legacy_npub"].hex())
    L.append("  ```")
    L.append("- `fresh_root` (test value = SHA-256 of a fixed string):")
    L.append("  ```")
    L.append("  " + bridge["fresh_root"].hex())
    L.append("  ```")
    L.append("")
    L.append("The fresh chain has length 2 (the minimum: a bridge event carries")
    L.append("a self-successor for `fresh.npub[0]`, which needs `fresh.npub[1]`")
    L.append("to exist).")
    L.append("")
    for i in range(2):
        L.append("### Fresh generation %d%s" % (
            i, "  (terminal)" if i == 1 else ""))
        L.append("")
        L.append("```")
        L.append("internal seckey p_internal : %s" %
                 bytes_from_int(fresh_p_int[i]).hex())
        L.append("internal pubkey (x-only)   : %s" % fresh_internal_xonly[i].hex())
        if fresh["tweak"][i] is not None:
            L.append("tweak  = H(tag | internal | npub[i+1]) :")
            L.append("                             %s" % fresh["tweak"][i].hex())
        else:
            L.append("tweak                      : (none -- terminal)")
        L.append("npub  (published identity) : %s" % fresh_npub[i].hex())
        L.append("nsec  (BIP-340 signing key): %s" % fresh_nsec_list[i].hex())
        L.append("```")
        L.append("")

    L.append("## Bridge commitment (kind 1042) -- happy path")
    L.append("")
    L.append("The legacy key signs a single `kind:1042` event with one `commits`")
    L.append("tag pointing at `fresh.npub[0]`. This is the only thing the legacy")
    L.append("key ever signs under NIP-41; once the bridge is consumed the key is")
    L.append("permanently retired.")
    L.append("")
    L.append("```json")
    L.append(json.dumps(bridge["k1042_happy"], indent=2))
    L.append("```")
    L.append("")

    L.append("## Bridge event (kind 1041) -- happy path")
    L.append("")
    L.append("Signed by `fresh.nsec[0]` -- never by the legacy key. Carries the")
    L.append("`bridge` tag in place of a predecessor-proof `successor` tag (a")
    L.append("legacy key has no in-key commitment to open), plus a self-successor")
    L.append("that establishes `fresh.npub[0]` as a committed-chain head.")
    L.append("")
    L.append("```json")
    L.append(json.dumps(bridge["bridge_event"], indent=2))
    L.append("```")
    L.append("")
    L.append("### Verification trace")
    L.append("")
    L.append("```")
    L.append("1. signature valid for pubkey fresh.npub[0]         : PASS")
    L.append("2. event id recomputes from serialization           : PASS")
    L.append("3. bridge tag is well-formed                        : PASS")
    L.append("   legacypub   = " + bridge["legacy_npub"].hex())
    L.append("   k1042_id    = " + bridge["k1042_happy"]["id"])
    L.append("4. self-successor tag values                        :")
    L.append("   subject     = fresh.npub[0]")
    L.append("   P_internal  = %s" % fresh_internal_xonly[0].hex())
    L.append("   npub_next   = fresh.npub[1]")
    L.append("   verify_chain_proof(npub[0], npub[1], P_internal) : PASS")
    L.append("5. discovery p-tag cross-check                      : PASS")
    L.append("   ['p', legacy_npub, '', 'predecessor']  (matches bridge legacypub)")
    L.append("   ['p', fresh_npub[0], '', 'successor']  (== event.pubkey)")
    L.append("6. verify_event returns Bridge                      : PASS")
    L.append("--- external gates (verify_bridge) ----------------------")
    L.append("7. isCommitted(legacy_npub) == false                : PASS")
    L.append("8. referenced kind:1042 exists, valid, from legacy  : PASS")
    L.append("   commits target == fresh.npub[0]                  : PASS")
    L.append("9. no conflicting kind:1042 from legacy             : PASS")
    L.append("=> bridge VERIFIED, identity moves legacy_npub -> fresh.npub[0]")
    L.append("```")
    L.append("")

    L.append("## Negative -- contested legacypub (conflicting kind:1042)")
    L.append("")
    L.append("The legacy key has published a *second* `kind:1042` pointing at a")
    L.append("different target. The fail-closed rule (spec lines 678-682) says")
    L.append("the identity is contested and no bridge MAY be honoured. Both the")
    L.append("legitimate user and the attacker are denied the takeover; neither")
    L.append("side can complete a migration off this legacy key.")
    L.append("")
    L.append("Contesting target (an arbitrary other x-only key):")
    L.append("```")
    L.append(bridge["contesting_target"].hex())
    L.append("```")
    L.append("")
    L.append("Contesting `kind:1042` event:")
    L.append("```json")
    L.append(json.dumps(bridge["k1042_contest"], indent=2))
    L.append("```")
    L.append("")
    L.append("```")
    L.append("bridge_commits_conflict(legacy_npub, [happy, contest])  : TRUE")
    L.append("verify_bridge with contested legacypub                  : REJECTED (correct)")
    L.append("```")
    L.append("")

    L.append("## Negative -- kind:1042 commits target does not match the bridge")
    L.append("")
    L.append("The bridge event's `bridge` tag references a `kind:1042` event id,")
    L.append("but the referenced event commits to a target other than the bridge")
    L.append("event's self-successor subject. `verify_bridge` MUST refuse this:")
    L.append("an attacker could otherwise hand a valid kind:1042 from the legacy")
    L.append("key that commits somewhere else and ride a different chain head's")
    L.append("self-successor in.")
    L.append("")
    L.append("Mismatch target (an arbitrary other x-only key the kind:1042 commits to):")
    L.append("```")
    L.append(bridge["mismatch_target"].hex())
    L.append("```")
    L.append("")
    L.append("Mismatching `kind:1042` event:")
    L.append("```json")
    L.append(json.dumps(bridge["k1042_mismatch"], indent=2))
    L.append("```")
    L.append("")
    L.append("Bridge event referencing it:")
    L.append("```json")
    L.append(json.dumps(bridge["bridge_event_mismatch"], indent=2))
    L.append("```")
    L.append("")
    L.append("```")
    L.append("verify_event(bridge_event_mismatch)                     : Bridge (intrinsic OK)")
    L.append("verify_bridge.commits == bridge_outcome.subject         : FALSE")
    L.append("verify_bridge returns Invalid('commits ... != subject') : REJECTED (correct)")
    L.append("```")
    L.append("")

    L.append("## Assertions executed")
    L.append("")
    for name, ok in results:
        L.append("- [%s] %s" % ("x" if ok else " ", name))
    L.append("")
    L.append("_%d/%d assertions passed._" %
             (sum(1 for _, ok in results if ok), len(results)))
    L.append("")
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "nip-41-test-vectors.md")
    with open(out, "w") as f:
        f.write("\n".join(L))
    return out

if __name__ == "__main__":
    main()
