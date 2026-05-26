package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Byte-exact conformance against the bridge vectors in
 * `docs/superpowers/specs/nip-41-test-vectors.md`. The Python reference
 * (`nip-41-test-vectors.py`) is the source of these values; if our KMP
 * impl agrees with it byte-for-byte, the two implementations are
 * interoperable on the bridge construction.
 *
 * If the Python script is ever regenerated and the values drift, this
 * test must update at the same commit as the markdown — that mutual
 * pin is the whole point of conformance vectors.
 */
class BridgeSpecVectorsTest {

    // --- legacy key fixture (spec test vectors) ----------------------------

    private val legacyNsec: ByteArray = Hex.decode(
        "baeb2736bd09a8cfdc97ab015bc2c151aa119f6ea178df24597bc0c01feabf1a")
    private val legacyNpubExpected: ByteArray = Hex.decode(
        "1a393666fafd21140d4a9749bf94e6596599f1227ca538102478c10c1757f297")

    // --- fresh-chain fixture (spec test vectors) ---------------------------

    private val freshRoot: ByteArray =
        CryptoUtils.sha256("nip-41 bridge test vector fresh root v1".encodeToByteArray())
    private val freshChain: IdentityChain = deriveIdentityChain(freshRoot, 2)

    private val expectedFreshRoot = "5310304143234eb387bdaa22cb65a508ea6d7712e3603cbf8b0381e72947d88a"
    private val expectedFreshNpub0 = "3ca523181fb2d031c360165a93ed8004e29421a72b4522b9611b2cb4bf1afbac"
    private val expectedFreshNpub1 = "a4896f8555cfc706bb505f75e05be41b5373b882268d22eb41e1a3e44a95ed54"
    private val expectedFreshInternal0 = "3d6298eb850c0ed440ae724a4909fffda354c0f6a713773ccf253cc2255698aa"
    private val expectedFreshNsec0 = "420667da61b7fc5320e6ed8536d5b247c410207385470d8d863e3cc2dabcb208"

    // --- vector values from the .md (the source of truth) ------------------

    private val k1042HappyId = "4c94b57b82104829381c59b44f205e45de8935c8f5d7953d856973e93d279f5f"
    private val k1042HappySig =
        "b4ae0038a0e6c8ce96f57806e77cf475e695af70342bec16a3826e526d7eed27" +
            "29659091b1fd577db915f99be8cce9a7a165363a8c3570407be9c6ab946d0222"
    private val k1042HappyCreatedAt = 1716100100L

    private val bridgeEventId = "5a2ca9b9ef8d753d99c802b9d4084ccbb2c53fdbefea5fd66c27387fe836e6e4"
    private val bridgeEventSig =
        "5256b0a8d0808d793764d1564fe3195626cb1fc709afc79563d1e1ab2070fc72" +
            "7f6827f7ba9fdf699eb2cc4c97e04c487fca204ecab65364477012ad4a40590c"
    private val bridgeEventCreatedAt = 1716100200L

    private val contestingTarget = "2a5bbcb0eede528e6abe5f2ec50ad7887eb5677af383a460b05ee23bf892dfe5"
    private val k1042ContestId = "a0cba74c158416a8b9c8eec4ba3d75e6fae52683ac4030b015f7b9dd41f13bf0"
    private val k1042ContestCreatedAt = 1716100300L

    private val mismatchTarget = "a2ac1e7238943ad9f9bca07e577101fdb315a16301244453cecdf71cde13592f"
    private val k1042MismatchId = "33159f43a980fcb9d40766dac6a005d707b9363792632f7c25b3f29ad4e8e9ad"
    private val k1042MismatchCreatedAt = 1716100400L

    private val bridgeEventMismatchId = "5d115d46abdc28ca3df8c4d298f6e750e31e40fa32cb9fc6c577543ee9fa32be"
    private val bridgeEventMismatchCreatedAt = 1716100500L

    // --- fixture cross-checks: KMP-derived values match the .md values -----

    @Test fun freshRoot_matchesSpec() {
        assertEquals(expectedFreshRoot, Hex.encode(freshRoot))
    }

    @Test fun legacyNpub_matchesSpec() {
        // Derive the legacy npub via the same path the Python reference uses:
        // BIP-340 x-only of (legacy_nsec * G).
        val legacyPub = Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33)
        assertEquals(Hex.encode(legacyNpubExpected), Hex.encode(legacyPub))
    }

    @Test fun freshChain_npub0_matchesSpec() {
        assertEquals(expectedFreshNpub0, freshChain.npub[0])
    }

    @Test fun freshChain_npub1_matchesSpec() {
        assertEquals(expectedFreshNpub1, freshChain.npub[1])
    }

    @Test fun freshChain_internalXonly0_matchesSpec() {
        assertEquals(expectedFreshInternal0, freshChain.internalXonly[0])
    }

    @Test fun freshChain_nsec0_matchesSpec() {
        assertEquals(expectedFreshNsec0, Hex.encode(freshChain.nsec[0]))
    }

    // --- kind:1042 happy path: byte-exact ----------------------------------

    @Test fun k1042Happy_idAndSig_matchSpec() {
        val event = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        assertEquals(k1042HappyId, event.id)
        assertEquals(k1042HappySig, event.sig)
        assertEquals(NIP41_KIND_1042, event.kind)
        assertEquals(Hex.encode(legacyNpubExpected), event.pubkey)
    }

    @Test fun k1042Happy_verifies_andCommitsToFreshNpub0() {
        val event = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        val v = verifyKind1042Event(event)
        val valid = assertIs<Kind1042Verification.Valid>(v)
        assertEquals(freshChain.npub[0], valid.commits)
    }

    // --- bridge kind:1041 happy path: byte-exact ---------------------------

    @Test fun bridgeEvent_idAndSig_matchSpec() {
        val k1042 = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        val event = freshChain.buildBridgeRotationEvent(
            legacyNpub = Hex.encode(legacyNpubExpected),
            kind1042EventId = k1042.id,
            createdAt = bridgeEventCreatedAt,
        )
        assertEquals(bridgeEventId, event.id)
        assertEquals(bridgeEventSig, event.sig)
        assertEquals(NIP41_KIND_1041, event.kind)
        assertEquals(freshChain.npub[0], event.pubkey)
    }

    @Test fun bridgeEvent_verifies_intrinsically_asBridge() {
        val k1042 = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        val event = freshChain.buildBridgeRotationEvent(
            legacyNpub = Hex.encode(legacyNpubExpected),
            kind1042EventId = k1042.id,
            createdAt = bridgeEventCreatedAt,
        )
        val v = verifyKind1041Event(event)
        val bridge = assertIs<Kind1041Verification.Bridge>(v)
        assertEquals(Hex.encode(legacyNpubExpected), bridge.legacypub)
        assertEquals(freshChain.npub[0], bridge.subject)
        assertEquals(freshChain.npub[1], bridge.successor)
        assertEquals(k1042.id, bridge.kind1042Id)
    }

    @Test fun bridgeEvent_fullVerifyBridge_returnsValid_withHappyContext() {
        val k1042 = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        val event = freshChain.buildBridgeRotationEvent(
            legacyNpub = Hex.encode(legacyNpubExpected),
            kind1042EventId = k1042.id,
            createdAt = bridgeEventCreatedAt,
        )
        val intrinsic = verifyKind1041Event(event) as Kind1041Verification.Bridge
        val result = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = k1042,
            legacypubKind1042Events = listOf(k1042),
        )
        assertIs<BridgeVerification.Valid>(result)
    }

    // --- Negative: contested legacypub (byte-exact .md vector) -------------

    @Test fun contestingKind1042_id_matchesSpec() {
        val contest = buildBridgeCommitment(
            legacyNsec,
            contestingTarget,
            createdAt = k1042ContestCreatedAt,
        )
        assertEquals(k1042ContestId, contest.id)
    }

    @Test fun bridgeCommitsConflict_firesWithSpecVectors() {
        val happy = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        val contest = buildBridgeCommitment(
            legacyNsec,
            contestingTarget,
            createdAt = k1042ContestCreatedAt,
        )
        assertTrue(
            bridgeCommitsConflict(Hex.encode(legacyNpubExpected), listOf(happy, contest)),
            "conflict must fire when two valid kind:1042 from legacypub point at different targets",
        )
    }

    @Test fun verifyBridge_refusesContestedLegacypub() {
        val happy = buildBridgeCommitment(
            legacyNsec, freshChain.npub[0], createdAt = k1042HappyCreatedAt)
        val contest = buildBridgeCommitment(
            legacyNsec,
            contestingTarget,
            createdAt = k1042ContestCreatedAt,
        )
        val event = freshChain.buildBridgeRotationEvent(
            legacyNpub = Hex.encode(legacyNpubExpected),
            kind1042EventId = happy.id,
            createdAt = bridgeEventCreatedAt,
        )
        val intrinsic = verifyKind1041Event(event) as Kind1041Verification.Bridge
        val v = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = happy,
            legacypubKind1042Events = listOf(happy, contest),
        )
        val invalid = assertIs<BridgeVerification.Invalid>(v)
        assertTrue(
            invalid.reason.contains("contest") || invalid.reason.contains("conflict"),
            "reason should cite the contest/conflict; got '${invalid.reason}'",
        )
    }

    // --- Negative: mismatched kind:1042 commits target ---------------------

    @Test fun mismatchingKind1042_id_matchesSpec() {
        val mismatch = buildBridgeCommitment(
            legacyNsec,
            mismatchTarget,
            createdAt = k1042MismatchCreatedAt,
        )
        assertEquals(k1042MismatchId, mismatch.id)
    }

    @Test fun bridgeEventReferencingMismatch_id_matchesSpec() {
        val mismatch = buildBridgeCommitment(
            legacyNsec,
            mismatchTarget,
            createdAt = k1042MismatchCreatedAt,
        )
        val bridge = freshChain.buildBridgeRotationEvent(
            legacyNpub = Hex.encode(legacyNpubExpected),
            kind1042EventId = mismatch.id,
            createdAt = bridgeEventMismatchCreatedAt,
        )
        assertEquals(bridgeEventMismatchId, bridge.id)
    }

    @Test fun verifyBridge_refusesMismatchedCommitsTarget() {
        val mismatch = buildBridgeCommitment(
            legacyNsec,
            mismatchTarget,
            createdAt = k1042MismatchCreatedAt,
        )
        val bridge = freshChain.buildBridgeRotationEvent(
            legacyNpub = Hex.encode(legacyNpubExpected),
            kind1042EventId = mismatch.id,
            createdAt = bridgeEventMismatchCreatedAt,
        )
        val intrinsic = verifyKind1041Event(bridge) as Kind1041Verification.Bridge
        val v = verifyBridge(
            bridgeOutcome = intrinsic,
            isCommittedDecision = false,
            kind1042Event = mismatch,
            legacypubKind1042Events = listOf(mismatch),
        )
        val invalid = assertIs<BridgeVerification.Invalid>(v)
        assertTrue(
            invalid.reason.contains("commits"),
            "reason should cite the commits mismatch; got '${invalid.reason}'",
        )
    }
}
