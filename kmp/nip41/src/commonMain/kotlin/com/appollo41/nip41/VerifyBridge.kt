package com.appollo41.nip41

/**
 * Outcome of running the external bridge gates from spec
 * "The bridge for existing keys" (`verifyBridge`, lines 649-666).
 */
public sealed class BridgeVerification {
    /** All three gates passed; the bridge may apply. */
    public object Valid : BridgeVerification()

    /** One gate failed; the bridge MUST NOT apply. [reason] is for diagnostics. */
    public data class Invalid(public val reason: String) : BridgeVerification()
}

/**
 * Spec "The bridge for existing keys" / `verifyBridge` (lines 649-666):
 * the three-conjunct predicate that gates a bridge rotation.
 *
 * Given an intrinsically-valid [Kind1041Verification.Bridge] outcome
 * (produced by [verifyKind1041Event]) and the external context the caller
 * has fetched, returns [BridgeVerification.Valid] iff all three gates hold:
 *
 *  1. `isCommitted(legacypub) == false`. Committed keys are protected from
 *     bridge takeover; this gate is what makes the
 *     [self-successor disclosure](spec "Properties") load-bearing.
 *  2. A `kind:1042` event with id `bridgeOutcome.kind1042Id` exists, is
 *     signed by `bridgeOutcome.legacypub`, and carries a `commits` tag
 *     whose value equals `bridgeOutcome.subject` (the fresh chain's
 *     `npub[0]`).
 *  3. The fail-closed conflict rule holds: among the supplied
 *     `legacypubKind1042Events`, no two events from `legacypub` carry
 *     different `commits` targets.
 *
 * Pure predicate. The caller is responsible for the network fetches that
 * supply [isCommittedDecision], [kind1042Event], and
 * [legacypubKind1042Events].
 *
 * @param bridgeOutcome           the intrinsic verification result for the
 *                                bridge `kind:1041` event
 * @param isCommittedDecision     the caller's answer to
 *                                `isCommitted(bridgeOutcome.legacypub)`
 *                                (see [isCommitted]); MUST be evaluated
 *                                against the broad-poll relay set per spec
 *                                "Caution window"
 * @param kind1042Event           the `kind:1042` event whose id matches
 *                                `bridgeOutcome.kind1042Id`, or null if no
 *                                such event has been fetched
 * @param legacypubKind1042Events all known `kind:1042` events purportedly
 *                                signed by `bridgeOutcome.legacypub`,
 *                                used for the conflict check
 */
public fun verifyBridge(
    bridgeOutcome: Kind1041Verification.Bridge,
    isCommittedDecision: Boolean,
    kind1042Event: SignedNostrEvent?,
    legacypubKind1042Events: List<SignedNostrEvent>,
): BridgeVerification {
    // Gate 1: legacypub must not be a committed-chain generation.
    if (isCommittedDecision) {
        return BridgeVerification.Invalid("legacypub is committed; bridges only apply to legacy keys")
    }

    // Gate 2: referenced kind:1042 event must exist, verify, be signed by
    // legacypub, and commit to the fresh chain's npub[0].
    if (kind1042Event == null) {
        return BridgeVerification.Invalid("missing referenced kind:1042 event")
    }
    if (kind1042Event.id != bridgeOutcome.kind1042Id) {
        return BridgeVerification.Invalid("kind:1042 event id does not match bridge tag")
    }
    if (kind1042Event.pubkey != bridgeOutcome.legacypub) {
        return BridgeVerification.Invalid("kind:1042 event not signed by bridge legacypub")
    }
    val valid = when (val v = verifyKind1042Event(kind1042Event)) {
        is Kind1042Verification.Valid -> v
        is Kind1042Verification.Invalid -> return BridgeVerification.Invalid("kind:1042 invalid: ${v.reason}")
    }
    if (valid.commits != bridgeOutcome.subject) {
        return BridgeVerification.Invalid("kind:1042 commits target != bridge subject")
    }

    // Gate 3: fail-closed conflict rule.
    if (bridgeCommitsConflict(bridgeOutcome.legacypub, legacypubKind1042Events)) {
        return BridgeVerification.Invalid("legacypub kind:1042 commitments are contested (conflict)")
    }

    return BridgeVerification.Valid
}
