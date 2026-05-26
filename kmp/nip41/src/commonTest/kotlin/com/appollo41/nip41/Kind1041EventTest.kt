package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Byte-exact conformance against the spec test vectors in
 * `../nips/docs/superpowers/specs/nip-41-test-vectors.md`.
 *
 * Pass = our Kotlin/KMP builders produce the same `kind:1041` events as the
 * pure-Python BIP-340 reference, byte-for-byte (id and sig) under
 * `auxRand32 = 0x00 * 32`.
 */
class Kind1041EventTest {

    private val specRootSecret: ByteArray =
        CryptoUtils.sha256("nip-41 test vector root secret v1".encodeToByteArray())

    private val chain = deriveIdentityChain(specRootSecret, 4)

    // --- Chain-birth event ---------------------------------------------------

    @Test fun chainBirthEvent_idAndSig_matchSpec() {
        val event = chain.buildChainBirthEvent(createdAt = 1716100000L)

        assertEquals("5d4d1f22f7de47ed8d4ce89b38d36f353b27123c424da8a4fb3fd585ec399b8c", event.id)
        assertEquals(
            "be663eef140bdcbc7fc707c6c0e20a44c24a92b7a049b61ba7f6afdedd9d2d10" +
                "456c2e4a3972b9a02b7d1ba3a3a6e51b30c92b56d6b08ee0afe72504aacf5e1b",
            event.sig,
        )
        assertEquals(1041, event.kind)
        assertEquals(chain.npub[0], event.pubkey)
    }

    @Test fun chainBirthEvent_tagShape_matchesSpec() {
        val event = chain.buildChainBirthEvent(createdAt = 1716100000L)
        assertEquals(2, event.tags.size)
        assertContentEquals(
            listOf("p", chain.npub[0], "", "successor"),
            event.tags[0],
        )
        assertContentEquals(
            listOf(
                "successor",
                chain.npub[0],
                chain.internalXonly[0],
                chain.npub[1],
            ),
            event.tags[1],
        )
    }

    @Test fun chainBirthEvent_signature_verifies() {
        val event = chain.buildChainBirthEvent(createdAt = 1716100000L)
        assertTrue(
            CryptoUtils.verifySchnorr(Hex.decode(event.sig), Hex.decode(event.id), Hex.decode(chain.npub[0])),
        )
    }

    @Test fun chainBirthEvent_rejectsLengthOne_noSuccessorAvailable() {
        // A length-1 chain has no successor for npub[0] to commit to.
        val singleton = deriveIdentityChain(specRootSecret, 1)
        assertFailsWith<IllegalArgumentException> {
            singleton.buildChainBirthEvent(createdAt = 0L)
        }
    }

    // --- Rotation event 0 -> 1 ----------------------------------------------

    @Test fun rotation0to1_idAndSig_matchSpec() {
        val event = chain.buildRotationEvent(
            toGeneration = 1,
            createdAt = 1716200000L,
            content = "optional human-readable note",
        )

        assertEquals("53a326f7e153f2b3c5d9aa195b461f9f20c03e32a15d318f4de65fc2ca3574ec", event.id)
        assertEquals(
            "884fbb8d63f48b88d008a4c2d7a8b427276db700e624854dbfc3ce5ebf4801ae" +
                "4e548887274d90c4df9a0dcbd199848560745dbcf4ed3152ce418dfa556e1c3b",
            event.sig,
        )
        assertEquals(1041, event.kind)
        assertEquals(chain.npub[1], event.pubkey)
    }

    @Test fun rotation0to1_tagShape_matchesSpec() {
        val event = chain.buildRotationEvent(toGeneration = 1, createdAt = 1716200000L)
        assertEquals(4, event.tags.size)
        assertContentEquals(
            listOf("p", chain.npub[0], "", "predecessor"),
            event.tags[0],
        )
        assertContentEquals(
            listOf("p", chain.npub[1], "", "successor"),
            event.tags[1],
        )
        assertContentEquals(
            listOf(
                "successor",
                chain.npub[0],
                chain.internalXonly[0],
                chain.npub[1],
            ),
            event.tags[2],
        )
        assertContentEquals(
            listOf(
                "successor",
                chain.npub[1],
                chain.internalXonly[1],
                chain.npub[2],
            ),
            event.tags[3],
        )
    }

    // --- Rotation event 1 -> 2 (interior rotation) --------------------------

    @Test fun rotation1to2_idAndSig_matchSpec() {
        val event = chain.buildRotationEvent(toGeneration = 2, createdAt = 1716300000L)
        assertEquals("ee29aa36003e01576947017879cd672298f134be45e90613e7e3fa67b126eb59", event.id)
        assertEquals(
            "75ac96e9d055a028ac3c9e7f18e1f4fabded27dce352b5910a4f570c8dea5b29" +
                "ddc4103e7bac07e9711cdde48868267d552dbe025315ae1533fb9294e1b684bf",
            event.sig,
        )
        assertEquals(chain.npub[2], event.pubkey)
    }

    // --- Boundary: rotation into terminal generation is refused ------------

    @Test fun rotationToTerminalGeneration_isRefused() {
        // Chain length 4 -> terminal index is 3 -> rotation event would
        // require self-successor for gen 3, but there is no gen 4.
        assertFailsWith<IllegalArgumentException> {
            chain.buildRotationEvent(toGeneration = 3, createdAt = 0L)
        }
    }

    @Test fun rotationToGenerationZero_isRefused() {
        // Rotation events require a predecessor; you cannot rotate "into" gen 0.
        assertFailsWith<IllegalArgumentException> {
            chain.buildRotationEvent(toGeneration = 0, createdAt = 0L)
        }
    }
}
