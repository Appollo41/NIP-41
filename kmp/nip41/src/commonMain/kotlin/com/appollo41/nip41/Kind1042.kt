package com.appollo41.nip41

import fr.acinq.secp256k1.Hex
import fr.acinq.secp256k1.Secp256k1

/**
 * Spec "Bridge commitment kind:1042": a single one-time event signed by the
 * legacy key that commits the legacy identity to migrating into a fresh
 * committed chain whose `npub[0]` is given.
 *
 * The event carries exactly one `commits` tag (and no other NIP-41 tags).
 * Deterministic signing by default (`auxRand32 = 0x00 * 32`) so the event
 * is reproducible against spec test vectors; pass 32 random bytes for the
 * standard BIP-340 nonce rerandomization in production.
 *
 * Both [legacyNsec] and [auxRand32] are read once by the BIP-340 signer and
 * not retained or mutated by this call; the caller may zero either buffer
 * after the call returns.
 *
 * @param legacyNsec       32-byte BIP-340 signing key for the legacy identity
 * @param freshNpub0       lowercase 64-char hex x-only `npub[0]` of a fresh committed chain
 * @param createdAt        unix seconds (the event's NIP-01 created_at)
 * @param content          optional human-readable note (defaults to "")
 * @param auxRand32        32-byte BIP-340 aux randomness (defaults to zero)
 */
public fun buildBridgeCommitment(
    legacyNsec: ByteArray,
    freshNpub0: String,
    createdAt: Long,
    content: String = "",
    auxRand32: ByteArray = ByteArray(32),
): SignedNostrEvent {
    require(legacyNsec.size == 32) { "legacyNsec must be 32 bytes, got ${legacyNsec.size}" }
    requireHex32("freshNpub0", freshNpub0)

    val legacyPubkeyHex = Hex.encode(Secp256k1.pubkeyCreate(legacyNsec).copyOfRange(1, 33))
    val tags = listOf(listOf(Nip41Tags.COMMITS, freshNpub0))
    return UnsignedNostrEvent(
        pubkey = legacyPubkeyHex,
        createdAt = createdAt,
        kind = NIP41_KIND_1042,
        tags = tags,
        content = content,
    ).sign(legacyNsec, auxRand32)
}

/**
 * Spec "The bridge for existing keys" / fail-closed rule (lines 678-682):
 * if more than one `kind:1042` signed by `legacypub` is seen with **different**
 * `commits` targets, the identity is contested. Clients MUST honour no bridge
 * for it.
 *
 * Pure predicate. Network I/O lives in the caller.
 *
 * Only events that (a) verify as kind:1042 and (b) are signed by `legacypub`
 * count. Anyone can publish events claiming to be from `legacypub`; only the
 * holder of `nsec` can produce a valid signature, so a malformed event
 * cannot manufacture a contest.
 *
 * @param legacypub lowercase 64-char hex x-only pubkey
 */
public fun bridgeCommitsConflict(legacypub: String, events: List<SignedNostrEvent>): Boolean {
    if (decodeHexOrNull(legacypub)?.size != 32) return false
    val distinctTargets = events.asSequence()
        .filter { event -> event.pubkey == legacypub }
        .mapNotNull { event ->
            when (val r = verifyKind1042Event(event)) {
                is Kind1042Verification.Valid -> r.commits
                is Kind1042Verification.Invalid -> null
            }
        }
        .toSet()
    return distinctTargets.size > 1
}
