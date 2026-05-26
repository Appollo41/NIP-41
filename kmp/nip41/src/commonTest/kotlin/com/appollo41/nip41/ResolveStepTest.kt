package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/**
 * Spec "Client verification" / `resolve(P)`: pure single-step walk.
 *
 * Given a current pubkey and a set of fetched `kind:1041` events, find
 * the unique valid event that advances the identity off that pubkey.
 * The full multi-hop walk lives in the orchestration layer because each
 * step requires a fresh network fetch; the lib only owns the per-step
 * cryptographic decision.
 *
 * `resolveStep` handles chain rotations only. Bridge resolution requires
 * external context (the referenced `kind:1042`, the `isCommitted`
 * decision, the conflict search) and is exposed separately as
 * `findBridgeFor` — which returns the intrinsically-valid `Bridge`
 * outcome for the caller to feed into [verifyBridge].
 */
class ResolveStepTest {

    private val rootA: ByteArray =
        CryptoUtils.sha256("nip41-resolveStep-A".encodeToByteArray())
    private val rootB: ByteArray =
        CryptoUtils.sha256("nip41-resolveStep-B".encodeToByteArray())
    private val chainA = deriveIdentityChain(rootA, 4)
    private val chainB = deriveIdentityChain(rootB, 4)

    // --- resolveStep: chain rotations -------------------------------------

    @Test fun resolveStep_emptyEvents_returnsNull() {
        assertNull(resolveStep(chainA.npub[0], emptyList()))
    }

    @Test fun resolveStep_validRotationFromCurrent_returnsNewPubkey() {
        val rotation = chainA.buildRotationEvent(toGeneration = 1, createdAt = 1716200000L)
        val next = resolveStep(chainA.npub[0], listOf(rotation))
        assertNotNull(next)
        assertEquals(chainA.npub[1], next)
    }

    @Test fun resolveStep_rotationFromAnotherPubkey_returnsNull() {
        // The rotation event advances chainA's npub[0] -> npub[1]. Asking
        // about chainA.npub[2] (a key never touched by this event) must
        // return null.
        val rotation = chainA.buildRotationEvent(toGeneration = 1, createdAt = 0L)
        assertNull(resolveStep(chainA.npub[2], listOf(rotation)))
    }

    @Test fun resolveStep_chainBirthEvent_returnsNull() {
        // Chain-birth events have no predecessor proof. They establish a
        // chain head but they don't advance any prior identity, so they
        // are not a valid resolveStep target.
        val birth = chainA.buildChainBirthEvent(createdAt = 0L)
        assertNull(resolveStep(chainA.npub[0], listOf(birth)))
    }

    @Test fun resolveStep_invalidEvent_isIgnored() {
        val rotation = chainA.buildRotationEvent(toGeneration = 1, createdAt = 0L)
        val tampered = rotation.copy(content = "tampered after signing")
        assertNull(resolveStep(chainA.npub[0], listOf(tampered)))
    }

    @Test fun resolveStep_multipleHopsInOneList_takesOnlyTheOneFromCurrent() {
        // Build events for two distinct hops, then ask for the first hop.
        // resolveStep MUST find the npub[0] -> npub[1] event, not the
        // npub[1] -> npub[2] event.
        val hop1 = chainA.buildRotationEvent(toGeneration = 1, createdAt = 1L)
        val hop2 = chainA.buildRotationEvent(toGeneration = 2, createdAt = 2L)
        val next = resolveStep(chainA.npub[0], listOf(hop2, hop1))
        assertNotNull(next)
        assertEquals(chainA.npub[1], next)
    }

    @Test fun resolveStep_bridgeEvent_isIgnoredHere() {
        // Bridge events are recognized by findBridgeFor, not resolveStep.
        // Treating them transparently in resolveStep would skip the
        // verifyBridge external-context check.
        val legacyNsec = ByteArray(32).apply { this[31] = 0x42 }
        val legacyNpub = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
        val k1042 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val bridge = chainA.buildBridgeRotationEvent(
            legacyNpub,
            k1042.id,
            createdAt = 2L,
        )
        assertNull(resolveStep(legacyNpub, listOf(bridge)))
    }

    @Test fun resolveStep_wrongLengthCurrentPubkey_returnsNull() {
        val rotation = chainA.buildRotationEvent(toGeneration = 1, createdAt = 0L)
        assertNull(resolveStep(Hex.encode(ByteArray(31)), listOf(rotation)))
    }

    @Test fun resolveStep_ignoresNoiseFromUnrelatedChains() {
        val a = chainA.buildRotationEvent(toGeneration = 1, createdAt = 1L)
        val b = chainB.buildRotationEvent(toGeneration = 1, createdAt = 1L)
        val next = resolveStep(chainA.npub[0], listOf(b, a))
        assertNotNull(next)
        assertEquals(chainA.npub[1], next)
        // And asking from chainB returns chainB's successor.
        val nextB = resolveStep(chainB.npub[0], listOf(b, a))
        assertNotNull(nextB)
        assertEquals(chainB.npub[1], nextB)
    }

    // --- findBridgeFor ----------------------------------------------------

    @Test fun findBridgeFor_emptyEvents_returnsNull() {
        assertNull(findBridgeFor(chainA.npub[0], emptyList()))
    }

    @Test fun findBridgeFor_intrinsicallyValidBridge_returnsBridgeOutcome() {
        val legacyNsec = ByteArray(32).apply { this[31] = 0x42 }
        val legacyNpub = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
        val k1042 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val bridge = chainA.buildBridgeRotationEvent(
            legacyNpub,
            k1042.id,
            createdAt = 2L,
        )
        val result = findBridgeFor(legacyNpub, listOf(bridge))
        assertNotNull(result)
        assertEquals(legacyNpub, result.legacypub)
        assertEquals(chainA.npub[0], result.subject)
        assertEquals(chainA.npub[1], result.successor)
    }

    @Test fun findBridgeFor_bridgeTargetingDifferentLegacy_returnsNull() {
        val legacyNsec = ByteArray(32).apply { this[31] = 0x42 }
        val legacyNpub = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
        val otherNpub = Hex.encode(ByteArray(32).apply { this[31] = 0x77 })
        val k1042 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val bridge = chainA.buildBridgeRotationEvent(
            legacyNpub,
            k1042.id,
            createdAt = 2L,
        )
        // Asking about a different legacy pubkey must return null.
        assertNull(findBridgeFor(otherNpub, listOf(bridge)))
    }

    @Test fun findBridgeFor_invalidBridge_isIgnored() {
        val legacyNsec = ByteArray(32).apply { this[31] = 0x42 }
        val legacyNpub = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
        val k1042 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val bridge = chainA.buildBridgeRotationEvent(
            legacyNpub,
            k1042.id,
            createdAt = 2L,
        ).copy(content = "tampered") // breaks id
        assertNull(findBridgeFor(legacyNpub, listOf(bridge)))
    }

    @Test fun findBridgeFor_rotationEvent_isIgnored() {
        // Rotation events are not bridges. findBridgeFor only returns Bridge.
        val rotation = chainA.buildRotationEvent(toGeneration = 1, createdAt = 0L)
        assertNull(findBridgeFor(chainA.npub[0], listOf(rotation)))
    }

    @Test fun findBridgeFor_multipleBridgesToSameTarget_contested_returnsNull() {
        // Two bridge events from the same legacy key — even pointing at the
        // same chain head — represent a malformed or duplicate state.
        // findBridgeFor returns null fail-closed when more than one
        // candidate matches: a contest at this layer must be resolved by
        // the caller, not silently resolved by picking the first.
        val legacyNsec = ByteArray(32).apply { this[31] = 0x42 }
        val legacyNpub = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
        val k1042 = buildBridgeCommitment(legacyNsec, chainA.npub[0], createdAt = 1L)
        val bridge1 = chainA.buildBridgeRotationEvent(legacyNpub, k1042.id, createdAt = 2L)
        val bridge2 = chainA.buildBridgeRotationEvent(legacyNpub, k1042.id, createdAt = 3L)
        assertNull(findBridgeFor(legacyNpub, listOf(bridge1, bridge2)))
    }
}
