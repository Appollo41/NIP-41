package com.appollo41.nip41

/**
 * Outcome of verifying a `kind:1041` event against the spec's event-validity
 * rules ("Client verification").
 *
 * The valid outcomes mirror the spec's event shapes:
 *  - [ChainBirth]: declares its own key as a committed-chain head.
 *  - [Rotation]: declares both that it succeeds a prior key and that its
 *    own key is committed.
 *  - [Bridge]: declares that a legacy (uncommitted) key has migrated into
 *    this fresh committed chain via a `kind:1042` commitment (spec
 *    "The bridge for existing keys"). [Bridge] is the result of *intrinsic*
 *    verification only: structure, signature, and the chain proof on the
 *    fresh chain's self-successor. The external gates (the legacy key must
 *    not already be committed, the referenced `kind:1042` must exist and
 *    be uncontested) are checked by [verifyBridge], which the caller
 *    invokes with whatever events it has fetched from relays.
 *  - [Invalid]: carries a short reason string for diagnostics.
 *
 * All pubkey / event-id fields are lowercase 64-char hex.
 */
public sealed class Kind1041Verification {
    public data class ChainBirth(public val subject: String, public val successor: String) : Kind1041Verification()

    public data class Rotation(
        public val predecessor: String,
        public val subject: String,
        public val successor: String,
    ) : Kind1041Verification()

    /**
     * Intrinsically-valid bridge event from a fresh committed chain. The
     * full bridge gate (spec "The bridge for existing keys") additionally
     * requires the caller to run [verifyBridge] with the referenced
     * `kind:1042` event and an `isCommitted(legacypub)` decision.
     *
     * @param legacypub   the legacy key being bridged away from (hex)
     * @param subject     the fresh chain's `npub[0]` (also `event.pubkey`) (hex)
     * @param successor   the fresh chain's `npub[1]` (hex)
     * @param kind1042Id  the id of the referenced `kind:1042` (hex)
     */
    public data class Bridge(
        public val legacypub: String,
        public val subject: String,
        public val successor: String,
        public val kind1042Id: String,
    ) : Kind1041Verification()

    public data class Invalid(public val reason: String) : Kind1041Verification()
}

/**
 * Spec "Client verification" event-validity check for a single `kind:1041`
 * event. Returns one of [Kind1041Verification.ChainBirth],
 * [Kind1041Verification.Rotation], or [Kind1041Verification.Bridge] on
 * intrinsic success; otherwise [Kind1041Verification.Invalid] with a short
 * reason.
 *
 * Fail-closed: under no circumstance does an invalid event cause a different
 * identity to be adopted. The worst case is no-op, which is today's
 * behaviour for Nostr clients.
 *
 * Bridge events are recognised intrinsically (structure + signature + chain
 * proof on the self-successor) but the external gates from spec
 * "The bridge for existing keys" (no `isCommitted(legacypub)`, referenced
 * `kind:1042` exists and is uncontested) are checked separately by
 * [verifyBridge], which the caller invokes with the events it has fetched.
 */
public fun verifyKind1041Event(event: SignedNostrEvent): Kind1041Verification {
    val pubkeyBytes = when (val env = verifyEventEnvelope(event, NIP41_KIND_1041)) {
        is EnvelopeCheck.Ok -> env.pubkeyBytes
        is EnvelopeCheck.Fail -> return Kind1041Verification.Invalid(env.reason)
    }

    var selfSuccessor: Pair<String, String>? = null
    var predecessorProof: Pair<String, String>? = null
    var bridge: Pair<String, String>? = null   // (legacypub, kind1042Id) as hex
    val pSuccessorValues = mutableListOf<String>()
    val pPredecessorValues = mutableListOf<String>()

    for (tag in event.tags) {
        if (tag.isEmpty()) continue
        when (tag[0]) {
            Nip41Tags.SUCCESSOR -> {
                if (tag.size != 4) return Kind1041Verification.Invalid("successor tag wrong arity")
                val subject = tag[1]
                val internal = tag[2]
                val npubNext = tag[3]
                val subjectBytes = decodeHexOrNull(subject)
                    ?: return Kind1041Verification.Invalid("successor tag bad subject hex")
                val internalBytes = decodeHexOrNull(internal)
                    ?: return Kind1041Verification.Invalid("successor tag bad internal hex")
                val npubNextBytes = decodeHexOrNull(npubNext)
                    ?: return Kind1041Verification.Invalid("successor tag bad npub_next hex")
                if (!verifyChainProofBytes(subjectBytes, npubNextBytes, internalBytes)) {
                    return Kind1041Verification.Invalid("successor tag fails verify_chain_proof")
                }
                val isSelf = subjectBytes.contentEquals(pubkeyBytes) && !npubNextBytes.contentEquals(pubkeyBytes)
                val isPred = !subjectBytes.contentEquals(pubkeyBytes) && npubNextBytes.contentEquals(pubkeyBytes)
                when {
                    isSelf -> {
                        if (selfSuccessor != null) {
                            return Kind1041Verification.Invalid("multiple self-successor tags")
                        }
                        selfSuccessor = subject to npubNext
                    }
                    isPred -> {
                        if (predecessorProof != null) {
                            return Kind1041Verification.Invalid("multiple predecessor-proof tags")
                        }
                        predecessorProof = subject to npubNext
                    }
                    else -> return Kind1041Verification.Invalid("successor tag fits neither self nor predecessor pattern")
                }
            }
            Nip41Tags.BRIDGE -> {
                if (tag.size != 3) return Kind1041Verification.Invalid("bridge tag wrong arity")
                if (bridge != null) return Kind1041Verification.Invalid("multiple bridge tags")
                val legacypubHex = tag[1]
                val kind1042IdHex = tag[2]
                val legacypubBytes = decodeHexOrNull(legacypubHex)
                    ?: return Kind1041Verification.Invalid("bridge tag bad legacypub hex")
                if (legacypubBytes.size != 32) return Kind1041Verification.Invalid("bridge tag legacypub wrong length")
                val kind1042IdBytes = decodeHexOrNull(kind1042IdHex)
                    ?: return Kind1041Verification.Invalid("bridge tag bad kind1042Id hex")
                if (kind1042IdBytes.size != 32) return Kind1041Verification.Invalid("bridge tag kind1042Id wrong length")
                bridge = legacypubHex to kind1042IdHex
            }
            Nip41Tags.P -> {
                if (tag.size >= 4) {
                    when (tag[3]) {
                        Nip41Tags.SUCCESSOR -> pSuccessorValues += tag[1]
                        Nip41Tags.PREDECESSOR -> pPredecessorValues += tag[1]
                    }
                }
            }
        }
    }

    // Bridge replaces the predecessor-proof successor tag. Carrying both is a
    // shape error (spec "Event shapes": rotation has predecessor proof,
    // bridge has bridge tag; never both).
    if (bridge != null && predecessorProof != null) {
        return Kind1041Verification.Invalid("event must not carry both a bridge tag and a predecessor-proof successor tag")
    }

    if (selfSuccessor == null && predecessorProof == null && bridge == null) {
        return Kind1041Verification.Invalid("no predecessor proof, no bridge, and no self-successor")
    }

    if (pSuccessorValues.size != 1) {
        return Kind1041Verification.Invalid("must have exactly one [\"p\",_,_,\"successor\"] tag")
    }
    if (pSuccessorValues[0] != event.pubkey) {
        return Kind1041Verification.Invalid("successor p-tag value != event.pubkey")
    }

    if (bridge != null) {
        // A bridge event must carry a self-successor (it is the chain birth
        // of the fresh committed chain) and a predecessor p-tag pointing at
        // the legacy key being bridged.
        val self = selfSuccessor
            ?: return Kind1041Verification.Invalid("bridge event missing self-successor tag")
        if (pPredecessorValues.size != 1) {
            return Kind1041Verification.Invalid("bridge event must have exactly one predecessor p-tag")
        }
        if (pPredecessorValues[0] != bridge.first) {
            return Kind1041Verification.Invalid("bridge event predecessor p-tag does not match bridge legacypub")
        }
        return Kind1041Verification.Bridge(
            legacypub = bridge.first,
            subject = self.first,
            successor = self.second,
            kind1042Id = bridge.second,
        )
    }

    if (predecessorProof != null) {
        if (pPredecessorValues.size != 1) {
            return Kind1041Verification.Invalid("must have exactly one predecessor p-tag when predecessor proof present")
        }
        if (pPredecessorValues[0] != predecessorProof.first) {
            return Kind1041Verification.Invalid("predecessor p-tag does not match predecessor proof")
        }
        return Kind1041Verification.Rotation(
            predecessor = predecessorProof.first,
            subject = event.pubkey,
            successor = selfSuccessor?.second
                // A rotation event without a self-successor is technically
                // syntactically expressible (predecessor proof only), but
                // spec "Event shapes" (Rotation) requires both. Reject.
                ?: return Kind1041Verification.Invalid("rotation event missing self-successor tag"),
        )
    }

    // Chain-birth path: predecessorProof == null, bridge == null, selfSuccessor != null.
    if (pPredecessorValues.isNotEmpty()) {
        return Kind1041Verification.Invalid("chain-birth event must not have predecessor p-tag")
    }
    return Kind1041Verification.ChainBirth(
        subject = selfSuccessor!!.first,
        successor = selfSuccessor.second,
    )
}

/**
 * Outcome of verifying a `kind:1042` bridge commitment.
 *
 * [Valid] carries the `commits` target as lowercase 64-char hex; [Invalid]
 * carries a short reason string for diagnostics. Fail-closed: any deviation
 * returns [Invalid] rather than letting an event slip through.
 */
public sealed class Kind1042Verification {
    public data class Valid(public val commits: String) : Kind1042Verification()
    public data class Invalid(public val reason: String) : Kind1042Verification()
}

/**
 * Spec "Bridge commitment kind:1042": verify a candidate `kind:1042` event.
 *
 * Accepts iff:
 *  - `kind == 1042`
 *  - `event.id` matches the NIP-01 canonical serialization
 *  - the BIP-340 signature is valid against the event id and pubkey
 *  - exactly one `commits` tag is present, with arity 2 (tag name + value),
 *    and the value is a 32-byte hex string
 *
 * Other tags are permitted and ignored. The verifier intentionally does not
 * check anything about `pubkey` against an expected legacy key; the caller
 * filters by `pubkey` upstream (e.g. via a Nostr REQ) and tests like
 * [bridgeCommitsConflict] verify it again.
 */
public fun verifyKind1042Event(event: SignedNostrEvent): Kind1042Verification {
    when (val env = verifyEventEnvelope(event, NIP41_KIND_1042)) {
        is EnvelopeCheck.Ok -> Unit
        is EnvelopeCheck.Fail -> return Kind1042Verification.Invalid(env.reason)
    }

    val commitsTags = event.tags.filter { it.firstOrNull() == Nip41Tags.COMMITS }
    if (commitsTags.isEmpty()) {
        return Kind1042Verification.Invalid("missing commits tag")
    }
    if (commitsTags.size > 1) {
        return Kind1042Verification.Invalid("multiple commits tags")
    }
    val tag = commitsTags[0]
    if (tag.size != 2) {
        return Kind1042Verification.Invalid("commits tag wrong arity")
    }
    val commitsHex = tag[1]
    val commitsBytes = decodeHexOrNull(commitsHex) ?: return Kind1042Verification.Invalid("commits value bad hex")
    if (commitsBytes.size != 32) {
        return Kind1042Verification.Invalid("commits value wrong length")
    }

    return Kind1042Verification.Valid(commitsHex)
}
