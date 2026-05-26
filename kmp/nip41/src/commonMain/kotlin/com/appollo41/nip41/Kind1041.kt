package com.appollo41.nip41

/**
 * Build the chain-birth `kind:1041` event for this chain (spec "Event shapes":
 * chain birth). Signed by `nsec[0]` and published as the first event the
 * chain ever signs.
 *
 * Carries a single self-successor `successor` tag declaring `npub[0]` as a
 * committed-chain generation whose successor is `npub[1]`, plus the
 * matching `["p", npub[0], "", "successor"]` discovery tag.
 *
 * Deterministic signing by default (`auxRand32 = 0x00 * 32`), which is what
 * makes signatures reproducible against the spec test vectors. In production,
 * pass 32 random bytes for the standard BIP-340 nonce rerandomization.
 * [auxRand32] is read once by the signer and not retained or mutated; the
 * caller may zero its buffer afterward.
 */
public fun IdentityChain.buildChainBirthEvent(
    createdAt: Long,
    content: String = "",
    auxRand32: ByteArray = ByteArray(32),
): SignedNostrEvent {
    require(length >= 2) {
        "chain-birth event needs a successor; chain length must be >= 2, got $length"
    }
    val pubkeyHex = npub[0]
    val tags = listOf(
        listOf(Nip41Tags.P, pubkeyHex, "", Nip41Tags.SUCCESSOR),
        listOf(
            Nip41Tags.SUCCESSOR,
            pubkeyHex,
            internalXonly[0],
            npub[1],
        ),
    )
    return signWith(
        generation = 0,
        event = UnsignedNostrEvent(
            pubkey = pubkeyHex,
            createdAt = createdAt,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = content,
        ),
        auxRand32 = auxRand32,
    )
}

/**
 * Build a bridge `kind:1041` event for this fresh committed chain that
 * consumes a legacy key's `kind:1042` commitment (spec "The bridge for
 * existing keys"). Signed by `nsec[0]`, never by the legacy key.
 *
 * Carries four tags in the spec's canonical order:
 *  1. `["p", legacy_npub, "", "predecessor"]`
 *  2. `["p", npub[0],     "", "successor"]`
 *  3. `["bridge", legacy_npub, kind1042_event_id]`
 *  4. self-successor for `npub[0]` opening its commitment to `npub[1]`
 *
 * The `bridge` tag replaces the predecessor-proof `successor` tag that an
 * ordinary chain rotation would carry: a legacy key has no in-key
 * commitment to open, so the link to it is established indirectly via the
 * referenced `kind:1042` event.
 *
 * Requires chain length >= 2 because the bridge event includes a
 * self-successor for `npub[0]`, which needs `npub[1]` to exist.
 *
 * [auxRand32] is read once by the signer and not retained or mutated; the
 * caller may zero its buffer afterward.
 *
 * @param legacyNpub        lowercase 64-char hex x-only pubkey of the legacy key
 * @param kind1042EventId   lowercase 64-char hex id of the referenced kind:1042 event
 */
public fun IdentityChain.buildBridgeRotationEvent(
    legacyNpub: String,
    kind1042EventId: String,
    createdAt: Long,
    content: String = "",
    auxRand32: ByteArray = ByteArray(32),
): SignedNostrEvent {
    requireHex32("legacyNpub", legacyNpub)
    requireHex32("kind1042EventId", kind1042EventId)
    require(length >= 2) {
        "bridge event carries a self-successor for npub[0]; chain length must be >= 2, got $length"
    }
    val freshNpub0Hex = npub[0]
    val tags = listOf(
        listOf(Nip41Tags.P, legacyNpub, "", Nip41Tags.PREDECESSOR),
        listOf(Nip41Tags.P, freshNpub0Hex, "", Nip41Tags.SUCCESSOR),
        listOf(Nip41Tags.BRIDGE, legacyNpub, kind1042EventId),
        listOf(
            Nip41Tags.SUCCESSOR,
            freshNpub0Hex,
            internalXonly[0],
            npub[1],
        ),
    )
    return signWith(
        generation = 0,
        event = UnsignedNostrEvent(
            pubkey = freshNpub0Hex,
            createdAt = createdAt,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = content,
        ),
        auxRand32 = auxRand32,
    )
}

/**
 * Build a rotation `kind:1041` event moving the identity from generation
 * `toGeneration - 1` to `toGeneration` (spec "Event shapes": rotation).
 *
 * `toGeneration` is the index of the new active key. It must be in
 * `1..length-2`: a rotation event MUST carry a self-successor tag, which
 * requires the generation it lands on to be non-terminal. The terminal
 * generation `length - 1` exists in the chain construction but cannot be
 * rotated into.
 *
 * The event carries four tags in the spec's canonical order:
 *  1. `["p", npub[toGeneration-1], "", "predecessor"]`
 *  2. `["p", npub[toGeneration],   "", "successor"]`
 *  3. predecessor-proof `successor` tag opening the previous key's commitment
 *  4. self-successor `successor` tag opening the new key's commitment
 *
 * Signed by `nsec[toGeneration]`. The previous key's `nsec` is never used.
 *
 * [auxRand32] is read once by the signer and not retained or mutated; the
 * caller may zero its buffer afterward.
 */
public fun IdentityChain.buildRotationEvent(
    toGeneration: Int,
    createdAt: Long,
    content: String = "",
    auxRand32: ByteArray = ByteArray(32),
): SignedNostrEvent {
    require(toGeneration in 1..length - 2) {
        "toGeneration must be in 1..${length - 2} (rotation requires a self-successor, " +
            "so generation must be non-terminal); got $toGeneration"
    }
    val prev = toGeneration - 1
    val next = toGeneration + 1
    val prevHex = npub[prev]
    val newHex = npub[toGeneration]
    val tags = listOf(
        listOf(Nip41Tags.P, prevHex, "", Nip41Tags.PREDECESSOR),
        listOf(Nip41Tags.P, newHex, "", Nip41Tags.SUCCESSOR),
        listOf(Nip41Tags.SUCCESSOR, prevHex, internalXonly[prev], newHex),
        listOf(
            Nip41Tags.SUCCESSOR,
            newHex,
            internalXonly[toGeneration],
            npub[next],
        ),
    )
    return signWith(
        generation = toGeneration,
        event = UnsignedNostrEvent(
            pubkey = newHex,
            createdAt = createdAt,
            kind = NIP41_KIND_1041,
            tags = tags,
            content = content,
        ),
        auxRand32 = auxRand32,
    )
}

/**
 * Validate that [value] is a lowercase 64-char hex string (32-byte payload).
 * Used by build APIs that take pubkeys / event ids as hex `String`. Throws
 * `IllegalArgumentException` to match the existing `require(…)` contract
 * shared by every builder in this module.
 */
internal fun requireHex32(name: String, value: String) {
    require(value.length == 64) {
        "$name must be 64 hex chars (32 bytes), got ${value.length}"
    }
    require(value.all { it in '0'..'9' || it in 'a'..'f' }) {
        "$name must be lowercase hex"
    }
}
