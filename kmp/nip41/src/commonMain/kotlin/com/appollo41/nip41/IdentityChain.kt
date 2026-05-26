package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1

/**
 * A NIP-41 identity chain: [length] generations derived from one root secret,
 * each generation `i < length-1` cryptographically committing to generation
 * `i+1`. Built backwards (NIP-41 "Committed identities") because each
 * commitment needs the next generation's npub.
 *
 * The chain is a pure function of (rootSecret, length): no network, no time.
 *
 * ### Public material vs. secret material
 *
 *  | Public (readable, lowercase 64-char hex) | Secret (hidden behind methods)  |
 *  | ---------------------------------------- | ------------------------------- |
 *  | [npub]: x-only signing pubkey            | per-generation BIP-340 nsec     |
 *  | [internalXonly]: pre-tweak x             | per-generation pre-tweak scalar |
 *  | [tweak]: succession tweak (or null on the terminal generation)             |
 *
 * Public identifiers are hex strings to match the Nostr wire shape: that is
 * what a `SignedNostrEvent.pubkey` carries and what relays return in REQ
 * results, so no decode/encode is needed at the call site. Secret material
 * stays as raw [ByteArray] so it can be zeroized; see [exportNsec].
 *
 * Signing keys are never exposed as a `List<ByteArray>`. Use [signWith] to
 * produce a `kind:1` (or any other) signed event with the key for a given
 * generation, or [exportNsec] to obtain a defensive copy of the raw nsec when
 * a consumer genuinely needs it (e.g. to encode as `nsec1…` via
 * [Nip19.encodeNsec]).
 *
 * ### Lifecycle and zeroization
 *
 * [IdentityChain] implements [AutoCloseable]. Call [close] (or wrap in
 * `chain.use { … }`) to best-effort zero the private-key arrays held inside.
 * After [close], [signWith] and [exportNsec] will operate on zeroed bytes
 * and produce invalid (or curve-rejected) output; the chain is not reusable.
 *
 * ### Equality
 *
 * Equality is reference identity (the default from [Any]). Two chains
 * derived from the same root secret are not `==`; compare what you care
 * about explicitly (typically `chain.npub[0]` against another). `data class`
 * was deliberately avoided to keep the synthesized `equals`/`hashCode`
 * (broken on `List<ByteArray>`), `copy()` (shallow-copies secret arrays),
 * and `toString()` from showing up on a secret-bearing type.
 *
 * Indexes line up across the three public lists: index `i` describes
 * generation `i`. `tweak[i]` is `null` only for the terminal generation,
 * which commits to nothing.
 */
public class IdentityChain internal constructor(
    public val internalXonly: List<String>,
    public val tweak: List<String?>,
    public val npub: List<String>,
    internal val nsec: List<ByteArray>,
    private val pInternal: List<ByteArray>,
) : AutoCloseable {

    public val length: Int get() = npub.size

    /**
     * Sign [event] with the BIP-340 signing key for [generation], producing
     * a [SignedNostrEvent] whose `pubkey` should already be set to
     * `npub[generation]` by the caller. This is the preferred
     * way to sign with a chain-derived key: the private key never leaves
     * the chain.
     *
     * [auxRand32] is read by the underlying BIP-340 signer and not retained
     * or mutated by this call; the caller may zero its buffer afterward.
     *
     * @throws IllegalArgumentException if [generation] is out of range, or
     *   if [auxRand32] is not 32 bytes (per BIP-340).
     */
    public fun signWith(
        generation: Int,
        event: UnsignedNostrEvent,
        auxRand32: ByteArray = ByteArray(32),
    ): SignedNostrEvent {
        requireGeneration(generation)
        return event.sign(nsec[generation], auxRand32)
    }

    /**
     * Returns a defensive **copy** of the 32-byte signing key for
     * [generation]. The caller owns the returned [ByteArray] and is
     * responsible for zeroing it when done.
     *
     * Intended for export only, typically `Nip19.encodeNsec(chain.exportNsec(i))`
     * for cross-client portability, or for handing the key to another crypto
     * library. For in-process signing, prefer [signWith], which never
     * materializes the key outside the chain.
     *
     * @throws IllegalArgumentException if [generation] is out of range.
     */
    public fun exportNsec(generation: Int): ByteArray {
        requireGeneration(generation)
        return nsec[generation].copyOf()
    }

    /**
     * Best-effort wipe of the per-generation private-key material
     * (`nsec[*]` and the pre-tweak scalars). On JVM/JNI this overwrites
     * the underlying byte buffers; the GC may already have moved earlier
     * copies, so this is hygiene, not a hard guarantee.
     *
     * After this call the chain is no longer functional: [signWith] will
     * sign with zero bytes (rejected by libsecp256k1), and [exportNsec]
     * returns a copy of zeros.
     */
    override fun close() {
        for (key in nsec) key.fill(0)
        for (key in pInternal) key.fill(0)
    }

    /**
     * Diagnostic only. Never includes private-key material; only the
     * chain length and a short hex prefix of `npub[0]` (which is public).
     */
    override fun toString(): String {
        val head = if (npub.isNotEmpty()) npub[0].take(16) else "-"
        return "IdentityChain(length=$length, npub[0]=${head}…)"
    }

    private fun requireGeneration(generation: Int) {
        require(generation in 0 until length) {
            "generation must be in 0..${length - 1}, got $generation"
        }
    }
}

/**
 * Derive a full identity chain of the given length (NIP-41 "Identity chain"
 * + "Committed identities").
 *
 * All elliptic-curve operations go through `fr.acinq.secp256k1.Secp256k1`
 * (libsecp256k1 under the hood). Per NIP-41 "Signing key", we do not
 * hand-roll curve arithmetic. Parity handling is inherited from the audited
 * BIP-341 implementation in libsecp256k1.
 *
 * Two re-derivation cases are handled (both spec-mandated, both with ~2^-128
 * per-generation probability, exercised by the machinery, never by real input):
 *  - HKDF output is an invalid scalar (0 or ≥ n): advance counter, retry.
 *  - Tagged-hash tweak `t` is ≥ n: advance counter past the offending internal
 *    key, retry. See [deriveScalarAtCounter].
 *
 * [rootSecret] is read once into HKDF derivation and not retained or mutated;
 * the caller may zero its buffer after this call returns. The chain's own
 * derived per-generation secrets are zeroed by [IdentityChain.close].
 */
public fun deriveIdentityChain(rootSecret: ByteArray, length: Int): IdentityChain {
    require(length >= 1) { "chain length must be >= 1, got $length" }

    val pInternal = arrayOfNulls<ByteArray>(length)
    val internalXonly = arrayOfNulls<ByteArray>(length)
    val npub = arrayOfNulls<ByteArray>(length)
    val nsec = arrayOfNulls<ByteArray>(length)
    val tweak = arrayOfNulls<ByteArray>(length)

    // Terminal generation: no tweak. nsec needs BIP-340 parity correction so
    // nsec*G x-only == npub.
    val last = length - 1
    val (pLast, _) = deriveScalarAtCounter(rootSecret, last, 0)
    val pubLast = Secp256k1.pubkeyCreate(pLast)
    pInternal[last] = pLast
    internalXonly[last] = uncompressedXOnly(pubLast)
    npub[last] = internalXonly[last]
    nsec[last] = if (hasEvenY(pubLast)) pLast else Secp256k1.privKeyNegate(pLast)

    // "Committed identities": backwards build. Each generation commits to the next via a tagged hash.
    // If the tweak overflows (t ≥ n), re-derive the internal key from the next
    // counter. This preserves all downstream commitments because we recompute
    // npub[i] etc. from the new internal key before the i-1 iteration consumes it.
    for (i in last - 1 downTo 0) {
        var counterStart = 0
        while (true) {
            val (pi, counterUsed) = deriveScalarAtCounter(rootSecret, i, counterStart)
            val pubI = Secp256k1.pubkeyCreate(pi)
            val xo = uncompressedXOnly(pubI)
            val t = taggedHash(NIP41_TWEAK_TAG, xo + npub[i + 1]!!)

            if (!Secp256k1.secKeyVerify(t)) {
                // Spec "Succession tweak": tweak ≥ n is invalid; re-derive internal key.
                counterStart = counterUsed + 1
                require(counterStart <= 255) {
                    "tweak rederivation exhausted counter for generation $i; infeasible"
                }
                continue
            }

            // lift_x is the BIP-340 even-y lift: parse a compressed pubkey with prefix 0x02.
            val liftedUncompressed = Secp256k1.pubkeyParse(byteArrayOf(0x02) + xo)
            val tweakedUncompressed = Secp256k1.pubKeyTweakAdd(liftedUncompressed, t)
            val d = if (hasEvenY(pubI)) pi else Secp256k1.privKeyNegate(pi)

            pInternal[i] = pi
            internalXonly[i] = xo
            tweak[i] = t
            npub[i] = uncompressedXOnly(tweakedUncompressed)
            nsec[i] = Secp256k1.privKeyTweakAdd(d, t)
            break
        }
    }

    return IdentityChain(
        internalXonly = internalXonly.map { Hex.encode(it!!) },
        tweak = tweak.map { it?.let(Hex::encode) },
        npub = npub.map { Hex.encode(it!!) },
        nsec = nsec.map { it!! },
        pInternal = pInternal.map { it!! },
    )
}

// --- helpers on libsecp256k1's uncompressed 65-byte pubkey form -----------
// Layout: 0x04 || X(32 BE) || Y(32 BE)

private fun uncompressedXOnly(uncompressed: ByteArray): ByteArray {
    require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte()) {
        "expected 65-byte uncompressed pubkey, got ${uncompressed.size} bytes"
    }
    return uncompressed.copyOfRange(1, 33)
}

private fun hasEvenY(uncompressed: ByteArray): Boolean {
    require(uncompressed.size == 65 && uncompressed[0] == 0x04.toByte()) {
        "expected 65-byte uncompressed pubkey"
    }
    return (uncompressed[64].toInt() and 1) == 0
}
