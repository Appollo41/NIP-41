package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Spec "The bridge for existing keys" — bridge `kind:1041` event from a fresh
 * committed chain that consumes a legacy key's `kind:1042` commitment.
 *
 * Event shape (spec lines 613-627):
 *  - `kind == 1041`, `pubkey == fresh npub[0]`, signed by `fresh nsec[0]`
 *  - tags, in spec order:
 *      ["p", legacy_npub, "", "predecessor"]
 *      ["p", fresh_npub0, "", "successor"]
 *      ["bridge", legacy_npub, kind1042_event_id]
 *      ["successor", fresh_npub0, P_internal[0], fresh_npub1]
 *
 * The bridge tag replaces what would be the predecessor-proof `successor`
 * tag in an ordinary chain rotation (a legacy key has no in-key commitment
 * to open).
 */
class BridgeRotationEventTest {

    private val legacyNsec: ByteArray = ByteArray(32).apply { this[31] = 0x42 }
    private val legacyNpubHex: String =
        Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))

    private val freshChain = deriveIdentityChain(
        CryptoUtils.sha256("nip41-bridge-rotation-test".encodeToByteArray()),
        4,
    )

    // Use a real kind:1042 event id so any future end-to-end checks have a
    // reference target; structurally the builder only needs the 32 bytes.
    private val kind1042Event = buildBridgeCommitment(legacyNsec, freshChain.npub[0], createdAt = 1L)
    private val kind1042IdHex: String = kind1042Event.id

    // --- shape -----------------------------------------------------------

    @Test fun bridgeEvent_hasKind1041_andPubkeyEqualsFreshNpub0() {
        val event = freshChain.buildBridgeRotationEvent(legacyNpubHex, kind1042IdHex, createdAt = 0L)
        assertEquals(1041, event.kind)
        assertEquals(freshChain.npub[0], event.pubkey)
    }

    @Test fun bridgeEvent_tagsAreInSpecOrder_andContents() {
        val event = freshChain.buildBridgeRotationEvent(legacyNpubHex, kind1042IdHex, createdAt = 0L)
        val expectedFreshNpub0Hex = freshChain.npub[0]
        val expectedFreshInternal0Hex = freshChain.internalXonly[0]
        val expectedFreshNpub1Hex = freshChain.npub[1]
        assertEquals(
            listOf(
                listOf("p", legacyNpubHex, "", "predecessor"),
                listOf("p", expectedFreshNpub0Hex, "", "successor"),
                listOf("bridge", legacyNpubHex, kind1042IdHex),
                listOf("successor", expectedFreshNpub0Hex, expectedFreshInternal0Hex, expectedFreshNpub1Hex),
            ),
            event.tags,
        )
    }

    @Test fun bridgeEvent_signatureVerifies() {
        val event = freshChain.buildBridgeRotationEvent(legacyNpubHex, kind1042IdHex, createdAt = 0L)
        val computedId = UnsignedNostrEvent(
            pubkey = event.pubkey,
            createdAt = event.createdAt,
            kind = event.kind,
            tags = event.tags,
            content = event.content,
        ).eventId()
        assertEquals(Hex.encode(computedId), event.id)
        val sig = Hex.decode(event.sig)
        val pubkey = Hex.decode(event.pubkey)
        assertTrue(
            CryptoUtils.verifySchnorr(sig, computedId, pubkey),
            "bridge event signature must verify under BIP-340",
        )
    }

    // --- input validation -----------------------------------------------

    @Test fun build_rejectsWrongLegacyNpubLength() {
        assertFailsWith<IllegalArgumentException> {
            freshChain.buildBridgeRotationEvent("aa".repeat(31), kind1042IdHex, createdAt = 0L)
        }
    }

    @Test fun build_rejectsWrongKind1042IdLength() {
        assertFailsWith<IllegalArgumentException> {
            freshChain.buildBridgeRotationEvent(legacyNpubHex, "aa".repeat(31), createdAt = 0L)
        }
    }

    @Test fun build_rejectsChainShorterThan2() {
        // A bridge event carries a self-successor for npub[0], which needs
        // npub[1] to exist — so the chain must be at least 2 generations.
        val tinyChain = deriveIdentityChain(
            CryptoUtils.sha256("nip41-bridge-tiny".encodeToByteArray()),
            1,
        )
        assertFailsWith<IllegalArgumentException> {
            tinyChain.buildBridgeRotationEvent(legacyNpubHex, kind1042IdHex, createdAt = 0L)
        }
    }
}
