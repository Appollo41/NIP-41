package com.appollo41.nip41

import fr.acinq.secp256k1.Secp256k1

/**
 * NIP-41 "Identity chain": derive the internal private key for generation `i`
 * from the root secret.
 *
 * `p_internal[i] = HKDF-SHA256(IKM=root_secret, salt="nip41-key-rotation-v1",
 *                              info="internal-key" || u32be(i), L=32)`
 *
 * If the reduced scalar is 0 or ≥ n (negligibly rare, ~2^-128) the spec says
 * to retry with one extra counter byte appended to `info`: `info || u8(counter)`,
 * starting at counter=1 and incrementing.
 *
 * [rootSecret] is read by HKDF and not retained or mutated; the caller may
 * zero its buffer after this call returns. The returned 32-byte scalar is a
 * fresh buffer the caller owns and is responsible for zeroing when done.
 */
public fun nip41InternalSeckey(rootSecret: ByteArray, generation: Int): ByteArray =
    deriveScalarAtCounter(rootSecret, generation, counterStart = 0).first

/**
 * Per-counter derivation primitive. Searches counter values `[counterStart, 255]`
 * and returns the first one whose HKDF output is a valid secp256k1 scalar (i.e.
 * `1 ≤ d < n`), together with the counter value that was actually used.
 *
 * Exposed so the chain builder can:
 *  - call with `counterStart = 0` for the normal path, and
 *  - call with `counterStart = previousCounter + 1` when the resulting tweak
 *    `t = TaggedHash(...)` is itself ≥ n (spec "Succession tweak": "If
 *    `t[i] ≥ n` it is invalid; re-derive `P_internal[i]`"). Re-deriving means
 *    stepping past the counter that produced the offending internal key.
 *
 * Encoding rule (matches the spec's Python reference):
 *  - counter == 0  →  info = "internal-key" || u32be(generation)
 *  - counter > 0   →  info = "internal-key" || u32be(generation) || u8(counter)
 */
internal fun deriveScalarAtCounter(rootSecret: ByteArray, generation: Int, counterStart: Int): Pair<ByteArray, Int> {
    require(rootSecret.size == 32) { "root_secret must be 32 bytes, got ${rootSecret.size}" }
    require(generation >= 0) { "generation must be >= 0, got $generation" }
    require(counterStart in 0..255) { "counterStart must be in 0..255, got $counterStart" }

    val baseInfo = "internal-key".encodeToByteArray() + u32be(generation)

    var counter = counterStart
    while (counter <= 255) {
        val info = if (counter == 0) baseInfo else baseInfo + byteArrayOf(counter.toByte())
        val d = hkdfSha256(rootSecret, NIP41_HKDF_SALT, info, 32)
        if (Secp256k1.secKeyVerify(d)) return d to counter
        counter++
    }
    error(
        "internal seckey derivation exhausted 256 counter values from $counterStart " +
            "(should be infeasible at ~256 × 2^-128 probability)",
    )
}

/** Big-endian 32-bit encoding. */
internal fun u32be(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xff).toByte(),
    ((value ushr 16) and 0xff).toByte(),
    ((value ushr 8) and 0xff).toByte(),
    (value and 0xff).toByte(),
)
