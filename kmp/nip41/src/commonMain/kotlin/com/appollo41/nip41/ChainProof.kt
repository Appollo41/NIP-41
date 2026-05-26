package com.appollo41.nip41

import fr.acinq.secp256k1.Secp256k1
import fr.acinq.secp256k1.Secp256k1Exception

/**
 * Spec "Implementation pseudocode" `verify_chain_proof`: the pure
 * cryptographic predicate underlying every `successor` tag check. Returns
 * true iff applying the succession tweak to `internalXonly` with `npubNext`
 * reproduces `subject`.
 *
 * Pure function, no network or time. Catches any error from the curve
 * primitives (e.g. an x-only that isn't on the curve) and converts it to
 * `false`. Fail-closed.
 *
 * All three arguments are lowercase 64-char hex (32-byte x-only values).
 * Malformed hex returns `false` rather than throwing. Parameter order matches
 * the spec exactly.
 */
public fun verifyChainProof(subject: String, npubNext: String, internalXonly: String): Boolean {
    val subjectBytes = decodeHexOrNull(subject) ?: return false
    val npubNextBytes = decodeHexOrNull(npubNext) ?: return false
    val internalXonlyBytes = decodeHexOrNull(internalXonly) ?: return false
    return verifyChainProofBytes(subjectBytes, npubNextBytes, internalXonlyBytes)
}

/**
 * Internal byte-level variant of [verifyChainProof]. The byte form is the
 * crypto-edge path used by [verifyKind1041Event] once it has decoded the tag
 * values; the public [verifyChainProof] entry decodes hex once and delegates
 * here.
 */
internal fun verifyChainProofBytes(subject: ByteArray, npubNext: ByteArray, internalXonly: ByteArray): Boolean {
    if (subject.size != 32 || npubNext.size != 32 || internalXonly.size != 32) return false
    if (!isValidSecp256k1XCoordinate(internalXonly)) return false
    if (!isValidSecp256k1XCoordinate(subject)) return false
    if (!isValidSecp256k1XCoordinate(npubNext)) return false

    return try {
        val t = taggedHash(NIP41_TWEAK_TAG, internalXonly + npubNext)
        // Tagged-hash output ≥ n is invalid as a tweak (spec "Succession
        // tweak"). Verifier rejects rather than re-deriving; only honest
        // chain construction can re-derive (which would change the npub the
        // attacker is targeting, which they can't fake).
        if (!Secp256k1.secKeyVerify(t)) return false
        val lifted = Secp256k1.pubkeyParse(byteArrayOf(0x02) + internalXonly)
        val tweaked = Secp256k1.pubKeyTweakAdd(lifted, t)
        val q = tweaked.copyOfRange(1, 33)
        q.contentEquals(subject)
    } catch (_: IllegalArgumentException) {
        false
    } catch (_: Secp256k1Exception) {
        // Curve-level rejection (off-curve x, identity result). Caught by
        // type so R8/ProGuard minification on Android can't break this branch
        // by renaming the simple class name.
        false
    }
}
