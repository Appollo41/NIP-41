package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * RFC 5869 (HMAC-based KDF) Appendix A test cases — the canonical interop vectors.
 * If our HKDF reproduces these, we know the building block under NIP-41's key
 * derivation is correct independent of any NIP-41-specific test vector.
 */
class HkdfTest {

    @Test fun rfc5869_caseA1_sha256_basic() {
        val ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = Hex.decode("000102030405060708090a0b0c")
        val info = Hex.decode("f0f1f2f3f4f5f6f7f8f9")
        val length = 42
        val expected = Hex.decode(
            "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865",
        )

        assertContentEquals(expected, hkdfSha256(ikm, salt, info, length))
    }

    @Test fun rfc5869_caseA2_sha256_long() {
        val ikm = Hex.decode(
            "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f",
        )
        val salt = Hex.decode(
            "606162636465666768696a6b6c6d6e6f" +
                "707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f" +
                "909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        val info = Hex.decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        val length = 82
        val expected = Hex.decode(
            "b11e398dc80327a1c8e7f78c596a4934" +
                "4f012eda2d4efad8a050cc4c19afa97c" +
                "59045a99cac7827271cb41c65e590e09" +
                "da3275600c2f09b8367793a9aca3db71" +
                "cc30c58179ec3e87c14c01d5c1f3434f" +
                "1d87",
        )

        assertContentEquals(expected, hkdfSha256(ikm, salt, info, length))
    }

    @Test fun rfc5869_caseA3_sha256_emptySaltAndInfo() {
        val ikm = Hex.decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = ByteArray(0)
        val info = ByteArray(0)
        val length = 42
        val expected = Hex.decode(
            "8da4e775a563c18f715f802a063c5a31" +
                "b8a11f5c5ee1879ec3454e5f3c738d2d" +
                "9d201395faa4b61a96c8",
        )

        assertContentEquals(expected, hkdfSha256(ikm, salt, info, length))
    }
}
