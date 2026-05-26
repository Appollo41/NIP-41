package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/**
 * BIP-340 tagged hash: `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
 *
 * The mistake the spec warns about (and the one that silently breaks interop)
 * is forgetting that `SHA256(tag)` is prepended TWICE. We pin one byte-exact
 * NIP-41-domain vector to catch that, plus symbolic property checks to make
 * sure the implementation isn't getting away by coincidence on a single vector.
 */
class TaggedHashTest {

    @Test fun nip41_succession_gen0_tweak_matches_spec() {
        // From nip-41-test-vectors.md, generation 0:
        //   internal_xonly[0] = 589ab097...
        //   npub[1]           = dcfd5f47...
        //   tweak             = 862d816f...
        val internalXonly0 = Hex.decode("589ab097fb0dc109d597ab8714b8363b6c96238e735b4f749fad4377aa8871cf")
        val npub1 = Hex.decode("dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111")
        val expected = Hex.decode("862d816fd3c538cd8593d91a5b19ad02fd0b2d7444be314ef4bf8102eb227d40")

        assertContentEquals(expected, taggedHash("nip41/succession", internalXonly0 + npub1))
    }

    @Test fun differentTag_givesDifferentHash() {
        // Same message, different tag — must produce different digests, or the
        // implementation has lost the tag and is just doing SHA-256 of the msg.
        val msg = Hex.decode("deadbeef")
        val a = taggedHash("tag-a", msg)
        val b = taggedHash("tag-b", msg)
        assertFalse(a.contentEquals(b), "different tags must produce different hashes")
    }

    @Test fun differentMessage_givesDifferentHash() {
        val a = taggedHash("nip41/succession", byteArrayOf(0x00))
        val b = taggedHash("nip41/succession", byteArrayOf(0x01))
        assertFalse(a.contentEquals(b), "different messages must produce different hashes")
    }

    @Test fun deterministic_sameInputsGiveSameOutput() {
        val msg = ByteArray(64) { it.toByte() }
        assertContentEquals(
            taggedHash("nip41/succession", msg),
            taggedHash("nip41/succession", msg),
        )
    }

    @Test fun outputIs32Bytes() {
        assertEquals(32, taggedHash("anything", byteArrayOf()).size)
    }
}
