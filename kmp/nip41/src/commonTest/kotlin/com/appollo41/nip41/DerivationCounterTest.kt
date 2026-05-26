package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Tests for the per-counter derivation primitive that the chain builder uses to
 * retry both (a) when HKDF→scalar produces an invalid scalar, and (b) when the
 * resulting tweak `t = TaggedHash(...)` is ≥ n (spec "Succession tweak": "If
 * t[i] ≥ n it is invalid — re-derive P_internal[i]").
 *
 * The tweak-overflow path is statistically unreachable (~2^-128 per generation)
 * but the spec mandates it, so the machinery must be present and correct.
 */
class DerivationCounterTest {

    private val specRoot = CryptoUtils.sha256("nip-41 test vector root secret v1".encodeToByteArray())

    @Test fun atCounter0_returnsSameScalarAs_publicDerivation_forSpecVector() {
        for (i in 0..3) {
            val (scalar, counterUsed) = deriveScalarAtCounter(specRoot, i, 0)
            assertEquals(
                0,
                counterUsed,
                "spec vector should never require retry for gen $i (sanity)",
            )
            assertContentEquals(
                nip41InternalSeckey(specRoot, i),
                scalar,
                "deriveScalarAtCounter(c=0) must match nip41InternalSeckey for gen $i",
            )
        }
    }

    @Test fun atCounter_returnsTheCounterActuallyUsed() {
        // For the spec vector, every generation succeeds at counter=0.
        val (_, c) = deriveScalarAtCounter(specRoot, 0, 0)
        assertEquals(0, c)
    }

    @Test fun advancingCounter_producesDifferentScalar() {
        // counter=0 uses info = "internal-key" || u32be(i)
        // counter=1 uses info = "internal-key" || u32be(i) || 0x01
        // Different info → different HKDF output → different scalar.
        val (s0, _) = deriveScalarAtCounter(specRoot, 0, 0)
        val (s1, c1) = deriveScalarAtCounter(specRoot, 0, 1)
        assertEquals(1, c1, "starting at counter=1 with spec root, gen 0 succeeds immediately")
        assertFalse(
            s0.contentEquals(s1),
            "different counters must yield different scalars (different HKDF info)",
        )
    }

    @Test fun counterIsThreadedThroughCorrectly_acrossSeveralValues() {
        // Each counter k in [0..5] starting from k itself must succeed at k (the
        // probability that any of these specific HKDF outputs is an invalid
        // scalar is ~6/2^128 — astronomically zero on this fixed input).
        val seen = mutableSetOf<String>()
        for (k in 0..5) {
            val (s, c) = deriveScalarAtCounter(specRoot, 0, k)
            assertEquals(k, c, "starting at counter=$k should immediately succeed here")
            assertTrue(seen.add(Hex.encode(s)), "counter $k must produce a distinct scalar")
        }
    }

    @Test fun publicDerivation_isUnaffected_byRefactor() {
        // Regression: existing API surface unchanged.
        assertContentEquals(
            Hex.decode("bb4c39a664630418d82a3792d8c4269982ba7c1b62044315b89cd9d06bd6e815"),
            nip41InternalSeckey(specRoot, 0),
        )
    }
}
