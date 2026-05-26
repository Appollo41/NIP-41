package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Defensive: verification must reject any `internal_xonly` ≥ field prime `p`.
 * libsecp256k1 happens to reject such inputs at `pubkeyParse`, but pinning the
 * check in our own code makes the invariant explicit and robust to library
 * swaps.
 */
class FieldPrimeBoundTest {

    private val specRoot = CryptoUtils.sha256("nip-41 test vector root secret v1".encodeToByteArray())
    private val chain = deriveIdentityChain(specRoot, 4)

    // --- isValidSecp256k1XCoordinate ---------------------------------------

    @Test fun coordinateZero_isAcceptedByBoundCheck_evenThoughNoPointHasX0() {
        // The bound check answers `x < p`, not "on curve". 0 < p so this returns true.
        assertTrue(isValidSecp256k1XCoordinate(ByteArray(32)))
    }

    @Test fun coordinateEqualToP_isRejected() {
        assertFalse(isValidSecp256k1XCoordinate(SECP256K1_P.copyOf()))
    }

    @Test fun coordinatePMinusOne_isAccepted() {
        val pMinus1 = SECP256K1_P.copyOf().apply { this[31] = (this[31].toInt() - 1).toByte() }
        assertTrue(isValidSecp256k1XCoordinate(pMinus1))
    }

    @Test fun coordinateAllOnes_isRejected_because_greaterThanP() {
        assertFalse(isValidSecp256k1XCoordinate(ByteArray(32) { 0xff.toByte() }))
    }

    @Test fun realSpecInternalXOnly_isAccepted() {
        for (i in 0 until chain.length) {
            assertTrue(
                isValidSecp256k1XCoordinate(Hex.decode(chain.internalXonly[i])),
                "spec internal_xonly[$i] must pass the bound check",
            )
        }
    }

    // --- verifyKind1041Event rejects events whose proof internal-xonly is ≥ p

    @Test fun verifier_rejects_event_with_xOnly_atOrAboveFieldPrime() {
        val badInternal = ByteArray(32) { 0xff.toByte() } // = 2^256-1, > p
        val pubkeyHex = chain.npub[1]
        val tags = listOf(
            listOf("p", chain.npub[0], "", "predecessor"),
            listOf("p", pubkeyHex, "", "successor"),
            listOf(
                "successor",
                chain.npub[0],
                Hex.encode(badInternal), // ≥ p, must be rejected
                pubkeyHex,
            ),
            listOf(
                "successor",
                pubkeyHex,
                chain.internalXonly[1],
                chain.npub[2],
            ),
        )
        val event = UnsignedNostrEvent(
            pubkey = pubkeyHex,
            createdAt = 1716200000L,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = "",
        ).sign(chain.nsec[1])
        val result = verifyKind1041Event(event)
        assertIs<Kind1041Verification.Invalid>(result)
    }

    @Test fun verifyChainProof_rejects_xOnly_atFieldPrime() {
        assertFalse(
            verifyChainProof(
                subject = chain.npub[0],
                npubNext = chain.npub[1],
                internalXonly = Hex.encode(SECP256K1_P.copyOf()),
            ),
        )
    }
}
