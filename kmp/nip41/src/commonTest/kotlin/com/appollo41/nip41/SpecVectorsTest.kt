package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Byte-exact conformance against the spec's pre-computed N=4 vector in
 * `docs/superpowers/specs/nip-41-test-vectors.md`.
 *
 * Pass = our Kotlin/KMP impl produces the same identity chain as the pure-Python
 * BIP-340 reference. Combined with the property tests in ChainPropertiesTest,
 * this defends against both spec-divergence AND implementation overfit.
 */
class SpecVectorsTest {

    private val specRootSecret: ByteArray =
        CryptoUtils.sha256("nip-41 test vector root secret v1".encodeToByteArray())

    private val expected = arrayOf(
        // Each row: internal_xonly, tweak (null for terminal), npub, nsec
        Gen(
            internalXonly = "589ab097fb0dc109d597ab8714b8363b6c96238e735b4f749fad4377aa8871cf",
            tweak = "862d816fd3c538cd8593d91a5b19ad02fd0b2d7444be314ef4bf8102eb227d40",
            npub = "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4",
            nsec = "cae147c96f6234b4ad69a1878255866834ff8e3f92028e74fbf505bf4f81d66c",
        ),
        Gen(
            internalXonly = "b78bf4bbe86f70f8262a7916a7e414cd3b65eb708db7ce011b9a1133ce693094",
            tweak = "1f6079c83e0d6d0b2fb186aefc18a3295c8e39d1b001031952a5a09124eacfd5",
            npub = "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111",
            nsec = "7a82e3581da2e0b78a53796b00c3ebd4b191705453335129e9f9c47a93fd16cc",
        ),
        Gen(
            internalXonly = "dd1415d639d25dcdeef73a4abac1b79c5100bb88812c14cf4bab6ed45e647bbc",
            tweak = "545f4f534847d25cfff3606ea3f950cdae920902f6c1f2384bc2eafafcacc3d6",
            npub = "06632001932f623c61df08d7dde11900aa6680748f9fc01a8f244fb4b0a70d2a",
            nsec = "167cba4200a314f5b66dae459fae1912f4dcbf5309a9f20e38791cc078c7520d",
        ),
        Gen(
            internalXonly = "7433e1c24405e0e30dda5250db991019ceb41dbe83bddea539ca0cb1f2fcc2c9",
            // terminal generation commits to nothing
            tweak = null,
            npub = "7433e1c24405e0e30dda5250db991019ceb41dbe83bddea539ca0cb1f2fcc2c9",
            nsec = "4b43828795a57dd0d26f9244fbe83ec06e0cf05788048b063c761f89c4751c05",
        ),
    )

    @Test fun fullChainN4_matchesSpec() {
        val chain = deriveIdentityChain(specRootSecret, 4)

        assertEquals(4, chain.length)

        for (i in 0..3) {
            assertEquals(
                expected[i].internalXonly,
                chain.internalXonly[i],
                "internalXonly[$i]",
            )
            assertEquals(
                expected[i].npub,
                chain.npub[i],
                "npub[$i]",
            )
            assertContentEquals(
                Hex.decode(expected[i].nsec),
                chain.nsec[i],
                "nsec[$i]",
            )
            if (expected[i].tweak == null) {
                assertNull(chain.tweak[i], "tweak[$i] must be null (terminal)")
            } else {
                assertEquals(
                    expected[i].tweak,
                    chain.tweak[i],
                    "tweak[$i]",
                )
            }
        }
    }

    private data class Gen(
        val internalXonly: String,
        val tweak: String?,
        val npub: String,
        val nsec: String,
    )
}
