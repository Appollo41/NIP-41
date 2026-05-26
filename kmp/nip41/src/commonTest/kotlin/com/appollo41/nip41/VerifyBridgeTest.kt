package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec "The bridge for existing keys" / `verifyBridge` (spec lines 649-666):
 * the three-conjunct predicate that gates a bridge rotation.
 *
 * Pure predicate. The lib does no network I/O — the caller obtains the
 * referenced `kind:1042` event, the set of conflicting `kind:1042` events
 * from `legacypub`, and the `isCommitted(legacypub)` decision, then asks
 * `verifyBridge` whether the rotation may apply.
 *
 * Also covers the new behaviour of `verifyKind1041Event` for events that
 * carry a `bridge` tag: structurally valid bridges now produce a
 * [Kind1041Verification.Bridge] outcome instead of being rejected with
 * "bridge not yet supported".
 */
class VerifyBridgeTest {

    // Legacy identity that owns the kind:1042 commitment.
    private val legacyNsec: ByteArray = ByteArray(32).apply { this[31] = 0x42 }
    private val legacyNpubBytes: ByteArray = Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33)
    private val legacyNpubHex: String = Hex.encode(legacyNpubBytes)

    // Fresh committed chain that is the bridge target.
    private val freshChain = deriveIdentityChain(
        CryptoUtils.sha256("nip41-verifybridge-fresh".encodeToByteArray()),
        4,
    )

    // The canonical "happy path" pair: kind:1042 + matching kind:1041 bridge event.
    private val kind1042Event: SignedNostrEvent =
        buildBridgeCommitment(legacyNsec, freshChain.npub[0], createdAt = 1L)
    private val kind1042Id: String = kind1042Event.id
    private val bridgeEvent: SignedNostrEvent =
        freshChain.buildBridgeRotationEvent(legacyNpubHex, kind1042Id, createdAt = 2L)

    // --- verifyKind1041Event recognising bridge events ---------------------

    @Test fun verifyKind1041_acceptsStructurallyValidBridge_returnsBridgeOutcome() {
        val result = verifyKind1041Event(bridgeEvent)
        val bridge = assertIs<Kind1041Verification.Bridge>(result)
        assertEquals(legacyNpubHex, bridge.legacypub)
        assertEquals(freshChain.npub[0], bridge.subject)
        assertEquals(freshChain.npub[1], bridge.successor)
        assertEquals(kind1042Id, bridge.kind1042Id)
    }

    @Test fun verifyKind1041_rejectsEventWithBothBridgeAndPredecessorProof() {
        // Hand-build a kind:1041 from freshChain.npub[0] that carries BOTH a
        // bridge tag AND a predecessor-proof successor tag. Spec "Event
        // shapes" makes these mutually exclusive; the bridge replaces the
        // predecessor proof. Mixing both must be rejected.
        val freshNpub0Hex = freshChain.npub[0]
        val freshNpub1Hex = freshChain.npub[1]
        val freshInternal0Hex = freshChain.internalXonly[0]

        // Build a fake "predecessor proof" successor tag pointing at the
        // legacy npub — its chain proof will fail verifyChainProof because
        // the legacy key isn't a committed identity. That alone would reject
        // the event, but combined with the bridge tag the verifier should
        // bail earlier for the structural reason.
        val tags = listOf(
            listOf("p", legacyNpubHex, "", "predecessor"),
            listOf("p", freshNpub0Hex, "", "successor"),
            listOf("bridge", legacyNpubHex, kind1042Id),
            // a phony predecessor-proof successor tag (will not verify; the
            // verifier should reject either on that or on the duplication —
            // we just assert Invalid)
            listOf("successor", legacyNpubHex, freshInternal0Hex, freshNpub0Hex),
            listOf("successor", freshNpub0Hex, freshInternal0Hex, freshNpub1Hex),
        )
        val ev = UnsignedNostrEvent(
            pubkey = freshNpub0Hex,
            createdAt = 0L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(freshChain.nsec[0])
        assertIs<Kind1041Verification.Invalid>(verifyKind1041Event(ev))
    }

    @Test fun verifyKind1041_rejectsMultipleBridgeTags() {
        // Two bridge tags in the same event is malformed.
        val freshNpub0Hex = freshChain.npub[0]
        val freshNpub1Hex = freshChain.npub[1]
        val freshInternal0Hex = freshChain.internalXonly[0]
        val tags = listOf(
            listOf("p", legacyNpubHex, "", "predecessor"),
            listOf("p", freshNpub0Hex, "", "successor"),
            listOf("bridge", legacyNpubHex, kind1042Id),
            listOf("bridge", legacyNpubHex, kind1042Id),
            listOf("successor", freshNpub0Hex, freshInternal0Hex, freshNpub1Hex),
        )
        val ev = UnsignedNostrEvent(
            pubkey = freshNpub0Hex,
            createdAt = 0L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(freshChain.nsec[0])
        val result = verifyKind1041Event(ev)
        val invalid = assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(invalid.reason.contains("bridge"), "reason should mention bridge; got '${invalid.reason}'")
    }

    @Test fun verifyKind1041_rejectsBridgeTagWithWrongArity() {
        val freshNpub0Hex = freshChain.npub[0]
        val freshNpub1Hex = freshChain.npub[1]
        val freshInternal0Hex = freshChain.internalXonly[0]
        val tags = listOf(
            listOf("p", legacyNpubHex, "", "predecessor"),
            listOf("p", freshNpub0Hex, "", "successor"),
            listOf("bridge", legacyNpubHex),                    // missing kind1042 id
            listOf("successor", freshNpub0Hex, freshInternal0Hex, freshNpub1Hex),
        )
        val ev = UnsignedNostrEvent(
            pubkey = freshNpub0Hex,
            createdAt = 0L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(freshChain.nsec[0])
        assertIs<Kind1041Verification.Invalid>(verifyKind1041Event(ev))
    }

    @Test fun verifyKind1041_rejectsBridgeWithoutMatchingPredecessorPtag() {
        // Bridge tag references legacypub, but the predecessor p-tag points
        // somewhere else. Mismatch must be rejected.
        val freshNpub0Hex = freshChain.npub[0]
        val freshNpub1Hex = freshChain.npub[1]
        val freshInternal0Hex = freshChain.internalXonly[0]
        val wrongLegacyHex = "ee".repeat(32)
        val tags = listOf(
            listOf("p", wrongLegacyHex, "", "predecessor"),
            listOf("p", freshNpub0Hex, "", "successor"),
            listOf("bridge", legacyNpubHex, kind1042Id),
            listOf("successor", freshNpub0Hex, freshInternal0Hex, freshNpub1Hex),
        )
        val ev = UnsignedNostrEvent(
            pubkey = freshNpub0Hex,
            createdAt = 0L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(freshChain.nsec[0])
        assertIs<Kind1041Verification.Invalid>(verifyKind1041Event(ev))
    }

    // --- verifyBridge: happy path ----------------------------------------

    @Test fun verifyBridge_allGatesPass_returnsValid() {
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = kind1042Event,
            legacypubKind1042Events = listOf(kind1042Event),
        )
        assertIs<BridgeVerification.Valid>(result)
    }

    // --- verifyBridge: gating rules --------------------------------------

    @Test fun verifyBridge_refusesWhenLegacyKeyIsCommitted() {
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = true,
            kind1042Event = kind1042Event,
            legacypubKind1042Events = listOf(kind1042Event),
        )
        val invalid = assertIs<BridgeVerification.Invalid>(result)
        assertTrue(invalid.reason.contains("committed"))
    }

    @Test fun verifyBridge_refusesWhenKind1042EventMissing() {
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = null,
            legacypubKind1042Events = emptyList(),
        )
        assertIs<BridgeVerification.Invalid>(result)
    }

    @Test fun verifyBridge_refusesWhenKind1042IdDoesntMatchBridgeTag() {
        // The caller hands a kind:1042 event whose id is NOT the one the
        // bridge tag references. The verifier must refuse: an attacker
        // could otherwise hand a different valid kind:1042 from the same
        // legacy key and bypass the bridge tag's binding.
        val differentKind1042 = buildBridgeCommitment(legacyNsec, freshChain.npub[1], createdAt = 99L)
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = differentKind1042,
            legacypubKind1042Events = listOf(differentKind1042),
        )
        assertIs<BridgeVerification.Invalid>(result)
    }

    @Test fun verifyBridge_refusesWhenKind1042SignedByDifferentKey() {
        // The kind:1042 in hand has the right event id but was signed by a
        // different key. Forging this requires a hash collision (event id
        // depends on pubkey), but the verifier still treats it as the
        // distinct "wrong pubkey" failure case.
        val attackerNsec = ByteArray(32).apply { this[31] = 0x77 }
        val attacker1042 = buildBridgeCommitment(attackerNsec, freshChain.npub[0], createdAt = 1L)
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = attacker1042,
            legacypubKind1042Events = listOf(attacker1042),
        )
        assertIs<BridgeVerification.Invalid>(result)
    }

    @Test fun verifyBridge_refusesWhenKind1042CommitsToWrongTarget() {
        // The kind:1042 in hand is from the legacy key but commits to
        // someone other than the fresh chain's npub[0]. The bridge tag
        // points at *this* kind:1042 by id, so we need to build that
        // event id into the bridge first — which means rebuilding the
        // bridge event with the mismatching id. This test arranges that
        // configuration.
        val mismatchedTarget: String = Hex.encode(ByteArray(32).apply { fill(0x33.toByte()) })
        val mismatched1042 = buildBridgeCommitment(legacyNsec, mismatchedTarget, createdAt = 1L)
        val mismatched1042Id: String = mismatched1042.id
        val bridgeEventWithMismatch = freshChain.buildBridgeRotationEvent(
            legacyNpubHex,
            mismatched1042Id,
            createdAt = 2L,
        )
        val intrinsic = verifyKind1041Event(bridgeEventWithMismatch) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = mismatched1042,
            legacypubKind1042Events = listOf(mismatched1042),
        )
        val invalid = assertIs<BridgeVerification.Invalid>(result)
        assertTrue(invalid.reason.contains("commits"))
    }

    @Test fun verifyBridge_refusesWhenConflictingKind1042Exists() {
        // Fail-closed rule: a second kind:1042 from legacypub pointing to a
        // different target makes the identity contested. Verifier must
        // refuse the bridge.
        val contestingChain = deriveIdentityChain(
            CryptoUtils.sha256("nip41-bridge-contest".encodeToByteArray()),
            2,
        )
        val contestingKind1042 = buildBridgeCommitment(legacyNsec, contestingChain.npub[0], createdAt = 5L)
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = kind1042Event,
            legacypubKind1042Events = listOf(kind1042Event, contestingKind1042),
        )
        val invalid = assertIs<BridgeVerification.Invalid>(result)
        assertTrue(invalid.reason.contains("contest") || invalid.reason.contains("conflict"))
    }

    @Test fun verifyBridge_ignoresKind1042FromDifferentKey_inConflictList() {
        // Noise from other authors must not manufacture a contest.
        val unrelatedNsec = ByteArray(32).apply { this[30] = 0x11 }
        val unrelated1042 = buildBridgeCommitment(unrelatedNsec, freshChain.npub[1], createdAt = 5L)
        val intrinsic = verifyKind1041Event(bridgeEvent) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = kind1042Event,
            legacypubKind1042Events = listOf(kind1042Event, unrelated1042),
        )
        assertIs<BridgeVerification.Valid>(result)
    }
}
