package com.appollo41.nip41

/**
 * Outcome of [verifyEventEnvelope], the shared envelope check that both
 * [verifyKind1041Event] and [verifyKind1042Event] run before their kind-
 * specific tag scanning. Each caller maps [Fail] into its own `Invalid` outcome.
 */
internal sealed class EnvelopeCheck {
    class Ok(val pubkeyBytes: ByteArray) : EnvelopeCheck()
    class Fail(val reason: String) : EnvelopeCheck()
}

/**
 * Verify the event envelope: kind, canonical-id consistency, and BIP-340
 * signature. Returns the decoded x-only pubkey bytes on success so callers
 * can use them for tag cross-checks without re-decoding.
 *
 * Extracted to remove the byte-identical preamble that previously lived in
 * both `verifyKind1041Event` and `verifyKind1042Event`.
 */
internal fun verifyEventEnvelope(event: SignedNostrEvent, expectedKind: Int): EnvelopeCheck {
    if (event.kind != expectedKind) return EnvelopeCheck.Fail("kind != $expectedKind")

    val pubkey = decodeHexOrNull(event.pubkey) ?: return EnvelopeCheck.Fail("malformed pubkey hex")
    if (pubkey.size != 32) return EnvelopeCheck.Fail("pubkey wrong length")

    val claimedId = decodeHexOrNull(event.id) ?: return EnvelopeCheck.Fail("malformed event id hex")
    val computedId = UnsignedNostrEvent(
        pubkey = event.pubkey,
        createdAt = event.createdAt,
        kind = event.kind,
        tags = event.tags,
        content = event.content,
    ).eventId()
    if (!claimedId.contentEquals(computedId)) {
        return EnvelopeCheck.Fail("event id does not match canonical serialization")
    }

    val sig = decodeHexOrNull(event.sig) ?: return EnvelopeCheck.Fail("malformed sig hex")
    if (sig.size != 64) return EnvelopeCheck.Fail("sig wrong length")
    if (!CryptoUtils.verifySchnorr(sig, computedId, pubkey)) {
        return EnvelopeCheck.Fail("invalid signature")
    }

    return EnvelopeCheck.Ok(pubkey)
}
