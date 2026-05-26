package com.appollo41.nip41

import fr.acinq.secp256k1.Secp256k1
import org.kotlincrypto.hash.sha2.SHA256
import org.kotlincrypto.macs.hmac.sha2.HmacSHA256

/**
 * Thin façade over the project's crypto primitives.
 *
 * Implementation choices:
 *  - SHA-256: `org.kotlincrypto.hash:sha2` (pure-Kotlin, KMP).
 *  - HMAC-SHA256: `org.kotlincrypto.macs:hmac-sha2` (pure-Kotlin, KMP).
 *  - secp256k1 ops (Schnorr, key tweak): `fr.acinq.secp256k1` (KMP wrapper
 *    around libsecp256k1, the only path NIP-41 "Signing key" mandates).
 *
 * Internal: NIP-41 consumers don't need a direct dependency on these
 * primitives; they're used by the library's own derivation, hashing, and
 * verification code. Keeping the façade out of the published ABI avoids
 * locking the library into a specific SHA-256 / HMAC / secp256k1 wrapper.
 */
internal object CryptoUtils {

    /** SHA-256 of `data`. Returns 32 bytes. */
    fun sha256(data: ByteArray): ByteArray = SHA256().apply { update(data) }.digest()

    /** HMAC-SHA256 per RFC 2104. Returns 32 bytes. */
    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray = HmacSHA256(key).doFinal(message)

    /**
     * BIP-340 tagged hash: `SHA-256( SHA-256(tag) || SHA-256(tag) || msg )`.
     * The tag's hash is prepended TWICE: the silent footgun the spec warns
     * about. Tag is UTF-8 encoded.
     */
    fun taggedHash(tag: String, message: ByteArray): ByteArray {
        val th = sha256(tag.encodeToByteArray())
        return SHA256().apply {
            update(th)
            update(th)
            update(message)
        }.digest()
    }

    /**
     * BIP-340 Schnorr signature over `message` with 32-byte `privateKey`.
     * `auxRand32` must be 32 bytes; pass all-zeros for deterministic signing
     * (which is what makes our signatures match the spec's test vector).
     */
    fun signSchnorr(message: ByteArray, privateKey: ByteArray, auxRand32: ByteArray): ByteArray =
        Secp256k1.signSchnorr(message, privateKey, auxRand32)

    /** BIP-340 Schnorr signature verification against a 32-byte x-only `pubkey`. */
    fun verifySchnorr(signature: ByteArray, message: ByteArray, pubkey: ByteArray): Boolean =
        Secp256k1.verifySchnorr(signature, message, pubkey)
}
