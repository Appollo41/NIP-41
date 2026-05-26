package com.appollo41.nip41

/**
 * Spec "Client verification": `isCommitted(K)` returns true iff at least one
 * valid `kind:1041` event has a self-successor whose `subject == K`.
 *
 * Network I/O lives in the caller. This is the pure predicate over a
 * pre-fetched set of events, as a client framework would obtain via a
 * `{"kinds":[1041], "authors":["<K hex>"]}` REQ.
 *
 * The predicate gates [The bridge for existing keys] (spec): a committed key
 * cannot be bridge-rotated. To keep that gate sound under adversarial input,
 * `isCommitted` MUST refuse to count any event that does not actually verify
 * (otherwise an attacker could spoof commitment by publishing a malformed
 * `kind:1041` that "looks like" a self-successor). We delegate to
 * [verifyKind1041Event] for validity and only ChainBirth / Rotation outcomes
 * count, both of which carry a self-successor whose subject is the event's
 * own pubkey by construction.
 *
 * @param subject  the lowercase 64-char hex x-only candidate pubkey to test
 * @param events   pre-fetched `kind:1041` events (filtering by `authors`
 *                 is the caller's responsibility, but the predicate is safe
 *                 against unfiltered noise: it ignores any event whose
 *                 pubkey doesn't match [subject])
 *
 * @return `true` iff some event in [events] is a valid `kind:1041`
 *         whose pubkey equals [subject]. `false` for any other case,
 *         including a malformed [subject].
 */
public fun isCommitted(subject: String, events: List<SignedNostrEvent>): Boolean {
    if (decodeHexOrNull(subject)?.size != 32) return false
    return events.any { event ->
        if (event.pubkey != subject) return@any false
        when (verifyKind1041Event(event)) {
            is Kind1041Verification.ChainBirth -> true
            is Kind1041Verification.Rotation -> true
            // A bridge event is also a chain-birth event for the fresh
            // committed chain: its self-successor binds event.pubkey to
            // its npub[1]. The bridge tag attaches a legacy origin to that
            // birth, but does not weaken the self-commitment. So a bridge
            // outcome makes event.pubkey committed for the purposes of the
            // isCommitted gate (spec "The bridge for existing keys":
            // "the self-successor tag is the same as in any kind:1041 event
            // and is what establishes the fresh npub[0] as a
            // committed-chain head, protecting it from a subsequent bridge
            // takeover").
            is Kind1041Verification.Bridge -> true
            is Kind1041Verification.Invalid -> false
        }
    }
}
