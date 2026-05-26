package com.appollo41.nip41

private const val SHA256_LEN = 32

/**
 * HKDF-SHA256 per RFC 5869 (extract-then-expand).
 *
 * Internal: the library's own derivation code uses this; consumers who want
 * HKDF should depend on `org.kotlincrypto` directly rather than going
 * through NIP-41's published ABI.
 *
 * @param ikm     input keying material
 * @param salt    salt (may be empty; RFC 5869 treats empty as HashLen zero bytes)
 * @param info    context/application-specific info (may be empty)
 * @param length  desired output length in bytes (1..255*HashLen)
 */
internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length in 1..(255 * SHA256_LEN)) {
        "length must be in 1..${255 * SHA256_LEN}, got $length"
    }

    val effectiveSalt = if (salt.isEmpty()) ByteArray(SHA256_LEN) else salt
    val prk = CryptoUtils.hmacSha256(effectiveSalt, ikm)

    val n = (length + SHA256_LEN - 1) / SHA256_LEN
    val out = ByteArray(length)
    var t = ByteArray(0)
    var pos = 0
    for (i in 1..n) {
        t = CryptoUtils.hmacSha256(prk, t + info + byteArrayOf(i.toByte()))
        val copy = minOf(SHA256_LEN, length - pos)
        t.copyInto(out, pos, 0, copy)
        pos += copy
    }
    return out
}
