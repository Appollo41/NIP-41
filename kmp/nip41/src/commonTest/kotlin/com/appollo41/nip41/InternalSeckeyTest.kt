package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The spec's test vector uses `root_secret = SHA-256("nip-41 test vector root secret v1")`.
 * Derive `p_internal[0..3]` from that root_secret and assert byte-for-byte against
 * the spec vectors. Then a small property suite to keep us honest if someone hardcodes
 * the spec values into the impl.
 */
class InternalSeckeyTest {

    private val specRootSecret: ByteArray =
        CryptoUtils.sha256("nip-41 test vector root secret v1".encodeToByteArray())

    // --- Layer 1: byte-exact against spec ------------------------------------

    @Test fun gen0_pInternal_matchesSpec() {
        assertContentEquals(
            Hex.decode("bb4c39a664630418d82a3792d8c4269982ba7c1b62044315b89cd9d06bd6e815"),
            nip41InternalSeckey(specRootSecret, 0),
        )
    }

    @Test fun gen1_pInternal_matchesSpec() {
        assertContentEquals(
            Hex.decode("a4dd9670206a8c53a55e0d43fb54b75365aba6640c16522b287e3aa36123fa4a"),
            nip41InternalSeckey(specRootSecret, 1),
        )
    }

    @Test fun gen2_pInternal_matchesSpec() {
        assertContentEquals(
            Hex.decode("c21d6aeeb85b4298b67a4dd6fbb4c84400f99336c230a011ac8890524c50cf78"),
            nip41InternalSeckey(specRootSecret, 2),
        )
    }

    @Test fun gen3_pInternal_matchesSpec() {
        assertContentEquals(
            Hex.decode("b4bc7d786a5a822f2d906dbb0417c13e4ca1ec8f27441535835c3f030bc1253c"),
            nip41InternalSeckey(specRootSecret, 3),
        )
    }

    // --- Layer 2: properties that must hold for ANY root / index -------------

    @Test fun deterministic_sameRootAndIndex_sameOutput() {
        val root = ByteArray(32) { it.toByte() }
        assertContentEquals(
            nip41InternalSeckey(root, 7),
            nip41InternalSeckey(root, 7),
        )
    }

    @Test fun differentIndex_sameRoot_differentOutput() {
        val root = ByteArray(32) { (it * 13 + 5).toByte() }
        val a = nip41InternalSeckey(root, 0)
        val b = nip41InternalSeckey(root, 1)
        assertFalse(a.contentEquals(b), "different generation indices must give different seckeys")
    }

    @Test fun differentRoot_sameIndex_differentOutput() {
        val rootA = ByteArray(32) { 0xAA.toByte() }
        val rootB = ByteArray(32) { 0xBB.toByte() }
        assertFalse(
            nip41InternalSeckey(rootA, 0).contentEquals(nip41InternalSeckey(rootB, 0)),
            "different root secrets must give different seckeys at the same generation",
        )
    }

    @Test fun outputIsAValidSecp256k1Scalar_forManyInputs() {
        // 1 <= d < N for every derivation we try. Statistically the rederive
        // path will not fire here, but this proves the bounds check is present
        // and doesn't reject legitimate keys.
        for (seed in 0 until 32) {
            val root = ByteArray(32) { ((seed * 31 + it) and 0xff).toByte() }
            for (i in 0 until 8) {
                val d = nip41InternalSeckey(root, i)
                assertTrue(d.size == 32, "seckey must be 32 bytes")
                assertTrue(d.any { it != 0.toByte() }, "seckey must not be zero")
                assertTrue(Secp256k1.secKeyVerify(d), "seckey must be < N for seed=$seed i=$i")
            }
        }
    }
}
