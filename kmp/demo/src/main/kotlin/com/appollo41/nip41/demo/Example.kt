package com.appollo41.nip41.demo

import com.appollo41.nip41.BridgeVerification
import com.appollo41.nip41.Kind1041Verification
import com.appollo41.nip41.Nip19
import com.appollo41.nip41.buildBridgeCommitment
import com.appollo41.nip41.buildBridgeRotationEvent
import com.appollo41.nip41.buildChainBirthEvent
import com.appollo41.nip41.buildRotationEvent
import com.appollo41.nip41.deriveIdentityChain
import com.appollo41.nip41.findBridgeFor
import com.appollo41.nip41.isCommitted
import com.appollo41.nip41.resolveStep
import com.appollo41.nip41.verifyBridge
import com.appollo41.nip41.verifyKind1041Event
import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import java.security.MessageDigest

/**
 * Code-as-documentation walkthrough of the NIP-41 public API. No prints; the
 * `check(...)` lines show what each call returns. Read top to bottom:
 * derive → sign → verify → walk → bridge → portability.
 *
 *   gradle :demo:example
 */
fun main() {
    // ---- 1. Derive an identity chain from a 32-byte root secret. ----------
    val rootSecret = sha256("example root secret".encodeToByteArray())
    val chain = deriveIdentityChain(rootSecret, length = 4)

    // Public material is hex; secret material stays as ByteArray.
    val gen0: String = chain.npub[0]
    val gen1: String = chain.npub[1]

    // ---- 2. Build NIP-41 events. ------------------------------------------
    val birth = chain.buildChainBirthEvent(createdAt = 1716100000L)
    val rotation = chain.buildRotationEvent(toGeneration = 1, createdAt = 1716200000L)

    // ---- 3. Verify events (pure predicate; no network). ------------------
    val birthResult = verifyKind1041Event(birth)
    check(birthResult is Kind1041Verification.ChainBirth)
    check(birthResult.subject == gen0)

    val rotationResult = verifyKind1041Event(rotation)
    check(rotationResult is Kind1041Verification.Rotation)
    check(rotationResult.predecessor == gen0)
    check(rotationResult.subject == gen1)

    // ---- 4. Walk one step: caller supplies the events to consider. -------
    val next: String? = resolveStep(currentPubkey = gen0, events = listOf(rotation))
    check(next == gen1)

    // ---- 5. Bridge a legacy (uncommitted) key into a fresh chain. --------
    val legacyNsec = sha256("legacy identity v1".encodeToByteArray())
    val legacyNpub: String = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
    val freshChain = deriveIdentityChain(sha256("fresh chain root".encodeToByteArray()), length = 4)

    val kind1042 = buildBridgeCommitment(
        legacyNsec = legacyNsec,
        freshNpub0 = freshChain.npub[0],
        createdAt = 1716300000L,
    )
    val bridgeEvent = freshChain.buildBridgeRotationEvent(
        legacyNpub = legacyNpub,
        kind1042EventId = kind1042.id,
        createdAt = 1716300001L,
    )

    val candidate = findBridgeFor(currentPubkey = legacyNpub, events = listOf(bridgeEvent))
    checkNotNull(candidate)

    val bridgeResult = verifyBridge(
        bridgeOutcome = candidate,
        isCommittedDecision = isCommitted(subject = legacyNpub, events = emptyList()),
        kind1042Event = kind1042,
        legacypubKind1042Events = listOf(kind1042),
    )
    check(bridgeResult is BridgeVerification.Valid)
    check(candidate.subject == freshChain.npub[0])

    // ---- 6. NIP-19 portability for the root secret. -----------------------
    val nroot = Nip19.encodeNroot(rootSecret)
    check(Nip19.decodeNroot(nroot).contentEquals(rootSecret))
}

private fun sha256(data: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").digest(data)
