package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Spec "The bridge for existing keys" / fail-closed rule: if more than one
 * `kind:1042` signed by the legacy key is seen with **different** `commits`
 * targets, the identity is contested and clients MUST honour no bridge
 * rotation for it.
 *
 * `bridgeCommitsConflict` is the pure predicate that decides whether such a
 * contest exists, given a pre-fetched list of events. Network I/O lives in
 * the caller.
 */
class BridgeCommitsConflictTest {

    private val legacyNsec: ByteArray = ByteArray(32).apply { this[31] = 0x42 }
    private val legacyNpubBytes: ByteArray = Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33)
    private val legacyNpubHex: String = Hex.encode(legacyNpubBytes)

    private val otherNsec: ByteArray = ByteArray(32).apply { this[31] = 0x77 }
    private val otherNpubBytes: ByteArray = Secp256k1.pubkeyCreate(otherNsec).copyOfRange(1, 33)

    private val chainA = deriveIdentityChain(CryptoUtils.sha256("conflict-test-A".encodeToByteArray()), 2)
    private val chainB = deriveIdentityChain(CryptoUtils.sha256("conflict-test-B".encodeToByteArray()), 2)

    // --- baseline ---------------------------------------------------------

    @Test fun emptyList_noConflict() {
        assertFalse(bridgeCommitsConflict(legacyNpubHex, emptyList()))
    }

    @Test fun singleValidCommitment_noConflict() {
        val e = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 0L)
        assertFalse(bridgeCommitsConflict(legacyNpubHex, listOf(e)))
    }

    @Test fun multipleCommitmentsToSameTarget_noConflict() {
        // Re-publishing the same commitment (e.g. retransmit to more relays)
        // produces multiple events with identical `commits` values and
        // different created_at. That is NOT a contest.
        val e1 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val e2 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 2L)
        assertFalse(bridgeCommitsConflict(legacyNpubHex, listOf(e1, e2)))
    }

    // --- the contest -----------------------------------------------------

    @Test fun twoDifferentTargets_signedByLegacy_isContested() {
        val e1 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val e2 = buildBridgeCommitment(legacyNsec, chainB.npub[0], createdAt = 2L)
        assertTrue(bridgeCommitsConflict(legacyNpubHex, listOf(e1, e2)))
    }

    @Test fun threeEventsTwoDistinctTargets_isContested() {
        val e1 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val e2 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 2L)
        val e3 = buildBridgeCommitment(legacyNsec, chainB.npub[0], createdAt = 3L)
        assertTrue(bridgeCommitsConflict(legacyNpubHex, listOf(e1, e2, e3)))
    }

    // --- adversarial noise must be ignored -------------------------------

    @Test fun commitmentSignedByDifferentKey_isIgnored() {
        // Attacker publishes a kind:1042 from a different key pointing
        // somewhere else. It is not signed by legacypub, so the spec's
        // fail-closed rule does not consider it a contest of legacypub's
        // identity.
        val legitimate = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val attacker = buildBridgeCommitment(otherNsec, chainB.npub[0], createdAt = 2L)
        assertFalse(bridgeCommitsConflict(legacyNpubHex, listOf(legitimate, attacker)))
    }

    @Test fun invalidEventFromLegacyKey_isIgnored() {
        // A genuinely-from-legacy event with a tampered signature does not
        // verify, so it cannot manufacture a contest. Otherwise an attacker
        // who saw a single legit kind:1042 could fabricate a colliding
        // "contested" event with no valid signature and lock the legitimate
        // user out.
        val legit = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val tampered = buildBridgeCommitment(legacyNsec, chainB.npub[0], createdAt = 2L)
            .copy(content = "tampered after signing") // breaks event id
        assertFalse(bridgeCommitsConflict(legacyNpubHex, listOf(legit, tampered)))
    }

    @Test fun mixedNoiseAndConflict_stillContested() {
        val legit = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val realConflict = buildBridgeCommitment(legacyNsec, chainB.npub[0], createdAt = 2L)
        val unrelatedAuthor = buildBridgeCommitment(otherNsec, chainA.npub[0], createdAt = 3L)
        val malformed = legit.copy(content = "tampered")
        val events = listOf(legit, realConflict, unrelatedAuthor, malformed)
        assertTrue(bridgeCommitsConflict(legacyNpubHex, events))
    }

    // --- programmer-error guard ------------------------------------------

    @Test fun wrongLengthLegacypub_returnsFalse() {
        val e = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 0L)
        assertFalse(bridgeCommitsConflict(Hex.encode(ByteArray(31)), listOf(e)))
    }

    @Suppress("unused")
    private fun ByteArray.toHex(): String = Hex.encode(this)
}
