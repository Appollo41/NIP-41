package com.appollo41.nip41

/**
 * Spec "Client verification" / `resolve(P)`: pure single-step walk.
 *
 * Given a current pubkey [currentPubkey] (lowercase 64-char hex) and a set
 * of pre-fetched `kind:1041` events, return the pubkey the identity advances
 * to via a **chain rotation**, or `null` if no valid rotation moves off
 * [currentPubkey].
 *
 * Bridge events are intentionally ignored here. They require external
 * context (the referenced `kind:1042`, the `isCommitted` decision against
 * the broad-poll relay set, the conflict search) that this pure predicate
 * cannot supply on its own. Use [findBridgeFor] to surface the intrinsic
 * bridge outcome, then [verifyBridge] to finalize it with the gates the
 * orchestration layer can fetch.
 *
 * The multi-hop walk is the caller's loop:
 *
 * ```kotlin
 * var current = startingPubkey
 * while (true) {
 *     val events = relayClient.fetchKind1041ByPredecessor(current)
 *     val next = resolveStep(current, events) ?: break
 *     current = next
 * }
 * return current
 * ```
 *
 * If somehow multiple valid rotation events claim to move off the same
 * predecessor (impossible for a committed identity per spec
 * "Conflicting rotation events", but possible if the caller passes a
 * deliberately broken event set), this function returns `null` rather
 * than picking one. Fail-closed: the caller must investigate.
 */
public fun resolveStep(currentPubkey: String, events: List<SignedNostrEvent>): String? {
    if (decodeHexOrNull(currentPubkey)?.size != 32) return null
    var found: String? = null
    for (event in events) {
        val verification = verifyKind1041Event(event)
        if (verification !is Kind1041Verification.Rotation) continue
        if (verification.predecessor != currentPubkey) continue
        if (found != null) return null      // ambiguous; fail closed
        found = verification.subject
    }
    return found
}

/**
 * Find the unique intrinsically-valid bridge event in [events] whose
 * `legacypub` matches [currentPubkey], returning the
 * [Kind1041Verification.Bridge] outcome for the caller to feed into
 * [verifyBridge]. Returns `null` if no such event exists, or if more than
 * one candidate matches (fail-closed: the caller must investigate the
 * contest).
 *
 * This is the bridge counterpart to [resolveStep]. The full bridge
 * resolution flow is:
 *
 *  1. Call `findBridgeFor(currentPubkey, fetchedEvents)` to obtain a
 *     candidate bridge outcome.
 *  2. Fetch the referenced `kind:1042` event from the broad-poll relay
 *     set, plus all `kind:1042` events from `legacypub` for the conflict
 *     search.
 *  3. Compute `isCommitted(legacypub, …)` against events the broad-poll
 *     relay set returns for that author.
 *  4. Call `verifyBridge(candidate, isCommittedDecision, kind1042Event,
 *     legacypubKind1042Events)`. If `Valid`, advance the identity to
 *     `candidate.subject`.
 *
 * @param currentPubkey lowercase 64-char hex x-only pubkey
 */
public fun findBridgeFor(currentPubkey: String, events: List<SignedNostrEvent>): Kind1041Verification.Bridge? {
    if (decodeHexOrNull(currentPubkey)?.size != 32) return null
    var found: Kind1041Verification.Bridge? = null
    for (event in events) {
        val verification = verifyKind1041Event(event)
        if (verification !is Kind1041Verification.Bridge) continue
        if (verification.legacypub != currentPubkey) continue
        if (found != null) return null      // ambiguous; fail closed
        found = verification
    }
    return found
}
