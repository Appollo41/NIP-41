package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Spec "Client verification" event-validity rules. We assert both halves:
 *  (1) conformance — chain-birth and rotation events from the spec test
 *      vectors are accepted with the right outcome; AND
 *  (2) every event-validity rule rejects an event that violates it.
 *
 * `verifyKind1041Event` is fail-closed by design: any deviation returns
 * [Kind1041Verification.Invalid] with a short reason for diagnostics.
 */
class VerifierTest {

    private val specRootSecret: ByteArray =
        CryptoUtils.sha256("nip-41 test vector root secret v1".encodeToByteArray())

    private val chain = deriveIdentityChain(specRootSecret, 4)

    // --- verifyChainProof: pure crypto predicate ---------------------------

    @Test fun verifyChainProof_holdsForEveryLegitimateHopInChain() {
        for (i in 0 until chain.length - 1) {
            assertTrue(
                verifyChainProof(chain.npub[i], chain.npub[i + 1], chain.internalXonly[i]),
                "verify_chain_proof must hold for hop $i -> ${i + 1}",
            )
        }
    }

    @Test fun verifyChainProof_rejects_realInternalKey_withAttackerSuccessor() {
        val attackerNpub = Hex.encode(
            Secp256k1.pubkeyCreate(ByteArray(32).apply { this[31] = 0x42 })
                .copyOfRange(1, 33),
        )
        assertFalse(verifyChainProof(chain.npub[0], attackerNpub, chain.internalXonly[0]))
    }

    @Test fun verifyChainProof_rejects_realInternalKey_withWrongSuccessor() {
        assertFalse(verifyChainProof(chain.npub[0], chain.npub[2], chain.internalXonly[0]))
    }

    @Test fun verifyChainProof_rejects_invalidInternalXOnly() {
        val notOnCurve = Hex.encode(ByteArray(32) { 0xff.toByte() }) // x = 2^256-1 is > p
        assertFalse(verifyChainProof(chain.npub[0], chain.npub[1], notOnCurve))
    }

    // --- verifyKind1041Event: positive paths ------------------------------

    @Test fun verifyKind1041_acceptsChainBirth() {
        val event = chain.buildChainBirthEvent(createdAt = 1716100000L)
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.ChainBirth>(result)
        assertEquals(chain.npub[0], result.subject)
        assertEquals(chain.npub[1], result.successor)
    }

    @Test fun verifyKind1041_acceptsRotation_returnsPredecessorAndSuccessor() {
        val event = chain.buildRotationEvent(toGeneration = 1, createdAt = 1716200000L)
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Rotation>(result)
        assertEquals(chain.npub[0], result.predecessor)
        assertEquals(chain.npub[1], result.subject)
        assertEquals(chain.npub[2], result.successor)
    }

    @Test fun verifyKind1041_acceptsInteriorRotation_1to2() {
        val event = chain.buildRotationEvent(toGeneration = 2, createdAt = 0L)
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Rotation>(result)
        assertEquals(chain.npub[1], result.predecessor)
    }

    // --- verifyKind1041Event: negative paths ------------------------------

    @Test fun reject_wrongKind() {
        val event = chain.buildRotationEvent(toGeneration = 1, createdAt = 0L).copy(kind = 1)
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
        assertEquals("kind != $NIP41_KIND_1041", result.reason)
    }

    @Test fun reject_tamperedContent_idMismatch() {
        val event = chain.buildRotationEvent(toGeneration = 1, createdAt = 0L)
            .copy(content = "tampered")
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("event id"))
    }

    @Test fun reject_attackerForgedEvent_signatureValidButCommitmentFails() {
        // Attacker controls a key, signs a rotation event with their own
        // pubkey claiming to be the successor of npub[0]. Schnorr sig is
        // valid, event id recomputes — but verify_chain_proof rejects.
        val attackerNsec = ByteArray(32).apply { this[31] = 0x42 }
        val attackerNpubBytes = Secp256k1.pubkeyCreate(attackerNsec).copyOfRange(1, 33)
        val attackerNpubHex = Hex.encode(attackerNpubBytes)
        val forgedTags = listOf(
            listOf("p", chain.npub[0], "", "predecessor"),
            listOf("p", attackerNpubHex, "", "successor"),
            listOf(
                "successor",
                chain.npub[0],
                chain.internalXonly[0],
                attackerNpubHex,
            ),
            listOf(
                "successor",
                attackerNpubHex,
                chain.internalXonly[1],
                chain.npub[2],
            ),
        )
        val unsigned = UnsignedNostrEvent(
            pubkey = attackerNpubHex,
            createdAt = 1716200000L,
            kind = NIP41_KIND_1041,
            tags = forgedTags,
            content = "",
        )
        val forged = unsigned.sign(attackerNsec)
        // The Schnorr signature itself is valid against the attacker's key.
        assertTrue(
            CryptoUtils.verifySchnorr(
                Hex.decode(forged.sig),
                Hex.decode(forged.id),
                attackerNpubBytes,
            ),
        )
        val result = verifyKind1041Event(forged)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("verify_chain_proof"))
    }

    @Test fun reject_missingSuccessorPTag() {
        val event = chain.buildRotationEvent(toGeneration = 1, createdAt = 1716200000L)
        // Strip the ["p", _, _, "successor"] discovery tag and re-sign so the
        // event id and signature stay self-consistent — exercises the p-tag
        // multiplicity rule, not the id-mismatch rule.
        val stripped = UnsignedNostrEvent(
            pubkey = event.pubkey,
            createdAt = event.createdAt,
            kind = event.kind,
            tags = event.tags.filter { !(it.firstOrNull() == "p" && it.getOrNull(3) == "successor") },
            content = event.content,
        ).sign(chain.nsec[1])
        val result = verifyKind1041Event(stripped)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("successor"))
    }

    @Test fun reject_mismatchedPredecessorPTag() {
        // Predecessor p-tag points at attackerNpub, but the predecessor-proof
        // successor tag opens npub[0]. The cross-check rule rejects.
        val attackerNpub = Hex.encode(
            Secp256k1.pubkeyCreate(ByteArray(32).apply { this[31] = 0x99.toByte() })
                .copyOfRange(1, 33),
        )
        val tags = listOf(
            listOf("p", attackerNpub, "", "predecessor"),
            listOf("p", chain.npub[1], "", "successor"),
            listOf(
                "successor",
                chain.npub[0],
                chain.internalXonly[0],
                chain.npub[1],
            ),
            listOf(
                "successor",
                chain.npub[1],
                chain.internalXonly[1],
                chain.npub[2],
            ),
        )
        val event = UnsignedNostrEvent(
            pubkey = chain.npub[1],
            createdAt = 1716200000L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(chain.nsec[1])
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("predecessor"))
    }

    @Test fun reject_twoSelfSuccessorTags() {
        val tags = listOf(
            listOf("p", chain.npub[0], "", "predecessor"),
            listOf("p", chain.npub[1], "", "successor"),
            listOf(
                "successor",
                chain.npub[0],
                chain.internalXonly[0],
                chain.npub[1],
            ),
            listOf(
                "successor",
                chain.npub[1],
                chain.internalXonly[1],
                chain.npub[2],
            ),
            listOf(
                "successor",
                chain.npub[1],
                chain.internalXonly[1],
                chain.npub[2],
            ),
        )
        val event = UnsignedNostrEvent(
            pubkey = chain.npub[1],
            createdAt = 1716200000L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(chain.nsec[1])
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("self-successor"))
    }

    @Test fun reject_chainBirthEventWithPredecessorPTag() {
        // Chain-birth event with an extraneous predecessor p-tag is invalid
        // per spec "Client verification" ("Chain-birth events carry no predecessor p-tag").
        val pubkeyHex = chain.npub[0]
        val tags = listOf(
            listOf("p", chain.npub[1], "", "predecessor"),
            listOf("p", pubkeyHex, "", "successor"),
            listOf(
                "successor",
                pubkeyHex,
                chain.internalXonly[0],
                chain.npub[1],
            ),
        )
        val event = UnsignedNostrEvent(
            pubkey = pubkeyHex,
            createdAt = 0L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(chain.nsec[0])
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("chain-birth"))
    }

    @Test fun reject_bridgeTagWithoutPredecessorPtag() {
        // A bridge kind:1041 event MUST carry a predecessor p-tag pointing
        // at the legacy key being bridged (spec "Client verification" rule:
        // "If the event carries a predecessor (chain proof or bridge),
        // exactly one ['p', _, _, 'predecessor'] tag is present"). Here we
        // construct a chain-birth-shaped event with a bridge tag but no
        // predecessor p-tag — the verifier must refuse it on shape.
        val pubkeyHex = chain.npub[0]
        val tags = listOf(
            listOf("p", pubkeyHex, "", "successor"),
            listOf("bridge", chain.npub[2], "deadbeef".repeat(8)),
            listOf(
                "successor",
                pubkeyHex,
                chain.internalXonly[0],
                chain.npub[1],
            ),
        )
        val event = UnsignedNostrEvent(
            pubkey = pubkeyHex,
            createdAt = 0L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(chain.nsec[0])
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
        assertTrue(result.reason.contains("bridge"))
    }
}
