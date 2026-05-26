package com.appollo41.nip41

import fr.acinq.secp256k1.Hex

/**
 * The HKDF salt that pins every NIP-41 v1 derivation. Changing a single byte
 * here silently fragments interop; implementations would derive different
 * keys from the same root secret. Frozen by the spec.
 *
 * Internal because exposing a mutable `ByteArray` publicly is a footgun:
 * any consumer could write into it and silently corrupt every derivation
 * in the process. Consumers needing to verify the salt value can read
 * the public spec.
 */
internal val NIP41_HKDF_SALT: ByteArray = "nip41-key-rotation-v1".encodeToByteArray()

/**
 * The BIP-340 tagged-hash domain separator for the "Committed identities"
 * commitment. Also frozen.
 */
public const val NIP41_TWEAK_TAG: String = "nip41/succession"

/**
 * Nostr event kind for both chain-birth and rotation events. There is no
 * separate kind for chain birth; the distinction is recovered from tag
 * content (presence/absence of a predecessor-proof `successor` tag).
 */
public const val NIP41_KIND_1041: Int = 1041

/**
 * Nostr event kind for the bridge commitment event signed by a legacy key
 * (spec "Bridge commitment kind:1042").
 */
public const val NIP41_KIND_1042: Int = 1042

/**
 * Fixed identity-chain length pinned by the spec. Chain creation is one-time
 * and the full backward build is roughly 50 to 200 ms on modern hardware,
 * so a deep chain is cheap. Tests may use shorter chains for readability
 * (the derivation is length-parametric), but on-the-network chains MUST be this
 * length.
 */
public const val NIP41_CHAIN_LENGTH: Int = 1024

/**
 * The closed set of tag names defined by NIP-41 (see spec "The kind:1041
 * event", "Client verification", and "Bridge commitment kind:1042"). Pinned
 * here so a typo at any single callsite can't silently produce a
 * non-conformant event, and exposed as a namespaced object so consumers
 * can pattern-match against the full enumeration:
 *
 * ```kotlin
 * when (tag[0]) {
 *     Nip41Tags.SUCCESSOR   -> …
 *     Nip41Tags.PREDECESSOR -> …
 *     Nip41Tags.BRIDGE      -> …
 *     Nip41Tags.P           -> …
 *     Nip41Tags.COMMITS     -> …
 * }
 * ```
 */
public object Nip41Tags {
    /** `successor`: opens a key's commitment to its next generation. */
    public const val SUCCESSOR: String = "successor"

    /** `predecessor`: marker on the discovery `p`-tag pointing at the previous key. */
    public const val PREDECESSOR: String = "predecessor"

    /** `bridge`: declares a legacy-to-fresh-chain bridge, referencing a kind:1042. */
    public const val BRIDGE: String = "bridge"

    /** `p`: the standard NIP-01 person discovery tag, used here with `successor`/`predecessor` markers. */
    public const val P: String = "p"

    /** `commits`: the kind:1042 tag committing a legacy key to a fresh chain's `npub[0]`. */
    public const val COMMITS: String = "commits"
}

/**
 * Big-endian byte encoding of the secp256k1 field prime `p = 2^256 − 2^32 − 977`.
 * A 32-byte value is a valid x-coordinate of an affine point iff `x < p`.
 *
 * We bounds-check x-only inputs against this before lifting via libsecp256k1,
 * so that the validity guarantee lives in our code rather than as an undocumented
 * dependency on the library's `pubkeyParse` behaviour.
 */
internal val SECP256K1_P: ByteArray =
    Hex.decode("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")

/**
 * `true` iff the 32-byte big-endian value `x` is in `[0, p)`, i.e. a valid
 * representative of an x-coordinate on the curve's affine plane (whether it
 * actually corresponds to a point on the curve is a separate, weaker question
 * answered by attempting `lift_x`).
 *
 * Internal: the only caller is [verifyChainProof]'s fail-closed preflight.
 * Consumers don't need a curve-membership predicate as part of NIP-41.
 */
internal fun isValidSecp256k1XCoordinate(x: ByteArray): Boolean {
    if (x.size != 32) return false
    return unsignedLess(x, SECP256K1_P)
}

private fun unsignedLess(a: ByteArray, b: ByteArray): Boolean {
    for (i in 0 until 32) {
        val ai = a[i].toInt() and 0xff
        val bi = b[i].toInt() and 0xff
        if (ai < bi) return true
        if (ai > bi) return false
    }
    return false // equal
}
