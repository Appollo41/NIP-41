package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The user's worry: a TDD impl pinned only to the spec's single N=4 vector could
 * pass by overfitting (e.g. hardcoding those exact npubs/nsecs). These tests
 * exercise the chain construction against many random roots and chain lengths,
 * asserting invariants that must hold for ANY input. An overfit implementation
 * cannot pass these.
 */
class ChainPropertiesTest {

    // Seeded once so failures are reproducible.
    private val rng = Random(0xA77ACC_5E3D_1234L)

    private val roots: List<ByteArray> = List(8) { ByteArray(32).also(rng::nextBytes) }
    private val lengths: List<Int> = listOf(1, 2, 4, 16, 64, 128)

    // --- Invariant 1: each nsec actually corresponds to its npub --------------
    // pubkeyCreate(nsec[i]) x-only == npub[i].
    // An impl that hardcodes spec npubs would fail because the nsec wouldn't
    // tweak/sign to that exact pubkey.

    @Test fun nsecTimesG_equalsNpub_forEveryGeneration() {
        forEachChain { chain ->
            for (i in 0 until chain.length) {
                val derived = Secp256k1.pubkeyCreate(chain.nsec[i]).copyOfRange(1, 33)
                assertEquals(
                    chain.npub[i],
                    Hex.encode(derived),
                    "nsec[$i]*G x-only must equal npub[$i] (length=${chain.length})",
                )
            }
        }
    }

    // --- Invariant 2: BIP-340 sign+verify roundtrip per generation ------------
    // Catches: nsec computed wrong but happens to match a static vector,
    // wrong parity handling that BIP-340 silently rejects.

    @Test fun bip340_signVerify_roundtrip_forEveryGeneration() {
        val zeroAux = ByteArray(32)
        forEachChain { chain ->
            for (i in 0 until chain.length) {
                val msg = CryptoUtils.sha256(
                    "test-msg gen $i len ${chain.length}".encodeToByteArray(),
                )
                val sig = CryptoUtils.signSchnorr(msg, chain.nsec[i], zeroAux)
                assertTrue(
                    CryptoUtils.verifySchnorr(sig, msg, Hex.decode(chain.npub[i])),
                    "schnorr sig from nsec[$i] must verify against npub[$i] (length=${chain.length})",
                )
            }
        }
    }

    // --- Invariant 3: chain-proof commitment check holds for every legitimate hop ------

    @Test fun chainProofVerifies_forEveryLegitimateHop() {
        forEachChain { chain ->
            for (i in 0 until chain.length - 1) {
                assertTrue(
                    rawChainProofCheck(chain.npub[i], chain.internalXonly[i], chain.npub[i + 1]),
                    "commitment must verify for hop $i -> ${i + 1} (length=${chain.length})",
                )
            }
        }
    }

    // --- Invariant 4: chain-proof rejects ANY single-bit corruption --------------------
    // Flip one bit in the revealed internal_xonly OR the successor OR oldpub:
    // each must cause the check to fail. Catches an impl that returns true
    // unconditionally or ignores one of its three inputs.

    @Test fun chainProofRejectsBitFlipsInAnyInput() {
        val chain = deriveIdentityChain(roots[0], 4)
        val i = 0
        val good = chain.internalXonly[i] to chain.npub[i + 1]
        val oldpub = chain.npub[i]

        // Sanity: untouched must verify
        assertTrue(rawChainProofCheck(oldpub, good.first, good.second), "baseline must verify")

        // Flip a bit in revealed internal_xonly
        for (byteIdx in listOf(0, 7, 16, 31)) {
            val corrupted = Hex.encode(
                Hex.decode(chain.internalXonly[i]).apply {
                    this[byteIdx] = (this[byteIdx].toInt() xor 1).toByte()
                },
            )
            assertFalse(
                rawChainProofCheck(oldpub, corrupted, good.second),
                "corrupted internal_xonly@byte$byteIdx must NOT verify",
            )
        }
        // Flip a bit in successor (npub[i+1])
        for (byteIdx in listOf(0, 7, 16, 31)) {
            val corrupted = Hex.encode(
                Hex.decode(good.second).apply {
                    this[byteIdx] = (this[byteIdx].toInt() xor 1).toByte()
                },
            )
            assertFalse(
                rawChainProofCheck(oldpub, good.first, corrupted),
                "corrupted successor@byte$byteIdx must NOT verify",
            )
        }
        // Flip a bit in oldpub
        for (byteIdx in listOf(0, 7, 16, 31)) {
            val corrupted = Hex.encode(
                Hex.decode(oldpub).apply {
                    this[byteIdx] = (this[byteIdx].toInt() xor 1).toByte()
                },
            )
            assertFalse(
                rawChainProofCheck(corrupted, good.first, good.second),
                "corrupted oldpub@byte$byteIdx must NOT verify",
            )
        }
    }

    // --- Invariant 5: determinism --------------------------------------------

    @Test fun derivationIsDeterministic() {
        val root = roots[1]
        val a = deriveIdentityChain(root, 16)
        val b = deriveIdentityChain(root, 16)
        for (i in 0 until 16) {
            assertEquals(a.npub[i], b.npub[i], "npub[$i] must match across runs")
            assertContentEqualsLabeled(a.nsec[i], b.nsec[i], "nsec[$i] must match across runs")
        }
    }

    // --- Invariant 6: different roots → different chains ----------------------

    @Test fun independentRoots_yieldIndependentChains() {
        val a = deriveIdentityChain(roots[2], 8)
        val b = deriveIdentityChain(roots[3], 8)
        // It is astronomically unlikely any single key collides.
        for (i in 0 until 8) {
            assertNotEquals(
                a.npub[i],
                b.npub[i],
                "different roots must produce different npub[$i]",
            )
            assertFalse(
                a.nsec[i].contentEquals(b.nsec[i]),
                "different roots must produce different nsec[$i]",
            )
        }
    }

    // --- Invariant 7: terminal generation is special --------------------------

    @Test fun terminalGeneration_hasNoTweak_andNpubEqualsInternalXonly() {
        for (n in lengths) {
            val chain = deriveIdentityChain(roots[4], n)
            assertNull(chain.tweak[n - 1], "terminal tweak must be null (N=$n)")
            assertEquals(
                chain.internalXonly[n - 1],
                chain.npub[n - 1],
                "terminal npub == internal x-only (N=$n)",
            )
        }
    }

    // --- Invariant 8: edge cases at small N -----------------------------------

    @Test fun n1_chainWorks_singleTerminalKey() {
        val chain = deriveIdentityChain(roots[5], 1)
        assertEquals(1, chain.length)
        assertNull(chain.tweak[0])
        // Sign+verify roundtrip
        val msg = CryptoUtils.sha256("hello".encodeToByteArray())
        val sig = CryptoUtils.signSchnorr(msg, chain.nsec[0], ByteArray(32))
        assertTrue(CryptoUtils.verifySchnorr(sig, msg, Hex.decode(chain.npub[0])))
    }

    @Test fun n2_smallestRotatableChain_oneCommitment() {
        val chain = deriveIdentityChain(roots[6], 2)
        assertEquals(2, chain.length)
        assertNotNull(chain.tweak[0])
        assertNull(chain.tweak[1])
        assertTrue(rawChainProofCheck(chain.npub[0], chain.internalXonly[0], chain.npub[1]))
    }

    // --- Helpers -------------------------------------------------------------

    private fun forEachChain(block: (IdentityChain) -> Unit) {
        for (root in roots) {
            for (n in lengths) {
                block(deriveIdentityChain(root, n))
            }
        }
    }

    /**
     * Raw chain-proof commitment check (NIP-41 "The successor tag" equation),
     * computed inline so this test doesn't depend on (and can't be silently
     * weakened by) the Verifier. A deliberate independent reimplementation.
     */
    private fun rawChainProofCheck(oldNpub: String, revealedInternalXonly: String, successorNpub: String): Boolean = try {
        val oldBytes = Hex.decode(oldNpub)
        val internalBytes = Hex.decode(revealedInternalXonly)
        val successorBytes = Hex.decode(successorNpub)
        val t = taggedHash(NIP41_TWEAK_TAG, internalBytes + successorBytes)
        val lifted = Secp256k1.pubkeyParse(byteArrayOf(0x02) + internalBytes)
        val tweaked = Secp256k1.pubKeyTweakAdd(lifted, t)
        val qXOnly = tweaked.copyOfRange(1, 33)
        qXOnly.contentEquals(oldBytes)
    } catch (_: Throwable) {
        false
    }

    private fun assertContentEqualsLabeled(expected: ByteArray, actual: ByteArray, message: String) {
        if (!expected.contentEquals(actual)) {
            throw AssertionError("$message\n  expected = ${Hex.encode(expected)}\n  actual   = ${Hex.encode(actual)}")
        }
    }
}
