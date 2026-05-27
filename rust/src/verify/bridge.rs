//! Spec "The bridge for existing keys": `verifyBridge` (three-gate predicate)
//! and the fail-closed conflict search `bridgeCommitsConflict`. Mirrors
//! KMP's `VerifyBridge.kt` and `Kind1042.kt::bridgeCommitsConflict`.
//!
//! Network I/O lives in the caller. These are pure predicates over the
//! candidate bridge outcome, the `isCommitted(legacypub)` decision, the
//! referenced kind:1042 event, and the conflict-search corpus.

use crate::crypto::decode_hex32;
use crate::event::SignedNostrEvent;
use crate::verify::{verify_kind_1042_event, Kind1041Verification, Kind1042Verification};
use std::collections::HashSet;

/// Outcome of running the external bridge gates from spec "The bridge for
/// existing keys" (`verifyBridge`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeVerification {
    /// All three gates passed; the bridge may apply.
    Valid,
    /// One gate failed; the bridge MUST NOT apply. [`Invalid`] carries a
    /// short reason string for diagnostics.
    ///
    /// [`Invalid`]: BridgeVerification::Invalid
    Invalid(String),
}

/// Spec "The bridge for existing keys" fail-closed conflict rule
/// (`bridgeCommitsConflict`): true iff two kind:1042 events from
/// `legacypub` are seen with **different** `commits` targets.
///
/// Pure predicate. Only events that (a) verify as kind:1042 and (b) are
/// signed by `legacypub` count. Anyone can publish events claiming to be
/// from `legacypub`; only the holder of `nsec` can produce a valid
/// signature, so a malformed event cannot manufacture a contest.
///
/// Returns `false` if `legacypub` is malformed hex (fail-closed).
pub fn bridge_commits_conflict(legacypub: &str, events: &[SignedNostrEvent]) -> bool {
    if decode_hex32(legacypub).is_none() {
        return false;
    }
    let mut distinct: HashSet<String> = HashSet::new();
    for event in events {
        if event.pubkey != legacypub {
            continue;
        }
        if let Kind1042Verification::Valid { commits } = verify_kind_1042_event(event) {
            distinct.insert(commits);
            if distinct.len() > 1 {
                return true;
            }
        }
    }
    false
}

/// Spec "The bridge for existing keys" `verifyBridge`: the three-conjunct
/// predicate gating a bridge rotation.
///
/// Given an intrinsically-valid [`Kind1041Verification::Bridge`] outcome
/// (produced by [`crate::verify_kind_1041_event`]) and the external context
/// the caller has fetched, returns [`BridgeVerification::Valid`] iff all
/// three gates hold:
///
///   1. `isCommitted(legacypub) == false`. Committed keys are protected from
///      bridge takeover.
///   2. A kind:1042 event with id `bridge_outcome.kind1042_id` exists, is
///      signed by `bridge_outcome.legacypub`, and carries a `commits` tag
///      whose value equals `bridge_outcome.subject` (the fresh chain's
///      `npub[0]`).
///   3. The fail-closed conflict rule holds: among the supplied
///      `legacypub_kind1042_events`, no two events from `legacypub` carry
///      different `commits` targets.
///
/// If `bridge_outcome` is not the [`Kind1041Verification::Bridge`] variant,
/// returns [`BridgeVerification::Invalid`] with a diagnostic string -
/// `verify_bridge` is only meaningful on a verified bridge event.
///
/// Pure predicate. The caller is responsible for the network fetches that
/// supply `is_committed_decision`, `kind1042_event`, and
/// `legacypub_kind1042_events`.
pub fn verify_bridge(
    bridge_outcome: &Kind1041Verification,
    is_committed_decision: bool,
    kind1042_event: Option<&SignedNostrEvent>,
    legacypub_kind1042_events: &[SignedNostrEvent],
) -> BridgeVerification {
    let Kind1041Verification::Bridge {
        legacypub,
        subject,
        kind1042_id,
        ..
    } = bridge_outcome
    else {
        return BridgeVerification::Invalid(
            "verify_bridge expects a Kind1041Verification::Bridge outcome".into(),
        );
    };

    // Gate 1: legacypub must not be a committed-chain generation.
    if is_committed_decision {
        return BridgeVerification::Invalid(
            "legacypub is committed; bridges only apply to legacy keys".into(),
        );
    }

    // Gate 2: referenced kind:1042 event must exist, verify, be signed by
    // legacypub, and commit to the fresh chain's npub[0].
    let Some(k1042) = kind1042_event else {
        return BridgeVerification::Invalid("missing referenced kind:1042 event".into());
    };
    if &k1042.id != kind1042_id {
        return BridgeVerification::Invalid(
            "kind:1042 event id does not match bridge tag".into(),
        );
    }
    if &k1042.pubkey != legacypub {
        return BridgeVerification::Invalid(
            "kind:1042 event not signed by bridge legacypub".into(),
        );
    }
    let commits = match verify_kind_1042_event(k1042) {
        Kind1042Verification::Valid { commits } => commits,
        Kind1042Verification::Invalid(reason) => {
            return BridgeVerification::Invalid(format!("kind:1042 invalid: {reason}"));
        }
    };
    if &commits != subject {
        return BridgeVerification::Invalid(
            "kind:1042 commits target != bridge subject".into(),
        );
    }

    // Gate 3: fail-closed conflict rule.
    if bridge_commits_conflict(legacypub, legacypub_kind1042_events) {
        return BridgeVerification::Invalid(
            "legacypub kind:1042 commitments are contested (conflict)".into(),
        );
    }

    BridgeVerification::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build_bridge_commitment, verify_kind_1041_event, IdentityChain};

    fn fresh_chain() -> IdentityChain {
        // Distinct root so npub[0] is distinct from any legacy key in the tests.
        IdentityChain::derive(&[0x77u8; 32], 4).unwrap()
    }

    // ──── bridge_commits_conflict ────

    #[test]
    fn conflict_search_detects_two_distinct_targets() {
        let legacy_nsec = [0x33u8; 32];
        let target_a =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let target_b =
            "0000000000000000000000000000000000000000000000000000000000000002";
        let a = build_bridge_commitment(&legacy_nsec, target_a, 1716100100, "", &[0u8; 32])
            .unwrap();
        let b = build_bridge_commitment(&legacy_nsec, target_b, 1716100200, "", &[0u8; 32])
            .unwrap();
        let legacypub = a.pubkey.clone();
        assert!(bridge_commits_conflict(&legacypub, &[a, b]));
    }

    #[test]
    fn conflict_search_clean_returns_false_for_duplicate_targets() {
        let legacy_nsec = [0x33u8; 32];
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        let a = build_bridge_commitment(&legacy_nsec, target, 1716100100, "", &[0u8; 32]).unwrap();
        let b = build_bridge_commitment(&legacy_nsec, target, 1716100200, "", &[0u8; 32]).unwrap();
        let legacypub = a.pubkey.clone();
        assert!(!bridge_commits_conflict(&legacypub, &[a, b]));
    }

    #[test]
    fn conflict_search_ignores_other_legacy_keys() {
        // Two kind:1042 events with different commits targets but signed by
        // *different* legacy keys: no conflict for either legacypub.
        let legacy_a = [0x33u8; 32];
        let legacy_b = [0x44u8; 32];
        let target_a =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let target_b =
            "0000000000000000000000000000000000000000000000000000000000000002";
        let a = build_bridge_commitment(&legacy_a, target_a, 1716100100, "", &[0u8; 32]).unwrap();
        let b = build_bridge_commitment(&legacy_b, target_b, 1716100200, "", &[0u8; 32]).unwrap();
        let a_pubkey = a.pubkey.clone();
        let b_pubkey = b.pubkey.clone();
        assert!(!bridge_commits_conflict(&a_pubkey, &[a.clone(), b.clone()]));
        assert!(!bridge_commits_conflict(&b_pubkey, &[a, b]));
    }

    #[test]
    fn conflict_search_malformed_legacypub_returns_false() {
        let legacy_nsec = [0x33u8; 32];
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        let a = build_bridge_commitment(&legacy_nsec, target, 1716100100, "", &[0u8; 32]).unwrap();
        assert!(!bridge_commits_conflict("not hex", std::slice::from_ref(&a)));
    }

    // ──── verify_bridge ────

    fn happy_bridge_setup() -> (Kind1041Verification, SignedNostrEvent) {
        let fresh = fresh_chain();
        let legacy_nsec = [0x33u8; 32];
        let k1042 = build_bridge_commitment(
            &legacy_nsec,
            fresh.npub(0),
            1716100100,
            "",
            &[0u8; 32],
        )
        .unwrap();
        let bridge_event = fresh
            .build_bridge_rotation_event(&k1042.pubkey, &k1042.id, 1716100200, "", &[0u8; 32])
            .unwrap();
        let outcome = verify_kind_1041_event(&bridge_event);
        (outcome, k1042)
    }

    #[test]
    fn happy_bridge_validates() {
        let (outcome, k1042) = happy_bridge_setup();
        let result = verify_bridge(&outcome, false, Some(&k1042), std::slice::from_ref(&k1042));
        assert_eq!(result, BridgeVerification::Valid);
    }

    #[test]
    fn committed_legacy_is_refused() {
        let (outcome, k1042) = happy_bridge_setup();
        let result = verify_bridge(&outcome, true, Some(&k1042), std::slice::from_ref(&k1042));
        match result {
            BridgeVerification::Invalid(reason) => {
                assert!(reason.contains("committed"));
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn missing_kind1042_refused() {
        let (outcome, _k1042) = happy_bridge_setup();
        let result = verify_bridge(&outcome, false, None, &[]);
        match result {
            BridgeVerification::Invalid(reason) => {
                assert_eq!(reason, "missing referenced kind:1042 event");
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn wrong_kind1042_id_refused() {
        let (outcome, mut k1042) = happy_bridge_setup();
        // Flip one byte of the id so it no longer matches bridge_outcome.kind1042_id.
        // We can't just edit k1042.id and keep the signature valid; instead
        // we resign a fresh kind:1042 with a different content so the id
        // differs. The envelope check passes on the new event, but its id
        // doesn't match the bridge's referenced id.
        let other = build_bridge_commitment(
            &[0x33u8; 32],
            "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4",
            1716100101, // distinct created_at => distinct id
            "",
            &[0u8; 32],
        )
        .unwrap();
        // Ensure k1042 was the one referenced; pass `other` as the candidate.
        assert_ne!(other.id, k1042.id);
        k1042 = other;
        let result = verify_bridge(&outcome, false, Some(&k1042), std::slice::from_ref(&k1042));
        match result {
            BridgeVerification::Invalid(reason) => {
                assert_eq!(reason, "kind:1042 event id does not match bridge tag");
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn kind1042_pubkey_mismatch_refused() {
        // The bridge outcome's legacypub == k1042.pubkey == sha256-derived
        // from [0x33; 32]. Pass a kind:1042 signed by a different legacy
        // key but with matching id (manufactured: we just resign with
        // matching created_at and a different key, then hand-patch the
        // bridge to reference *that* id). Simpler: construct a brand-new
        // bridge_outcome that references some real kind:1042 signed by
        // [0x44;32], then pass a *different* kind:1042 signed by [0x55;32]
        // - but its id won't match. The cleanest forgery is: use the
        // happy_setup, then replace the candidate k1042 with one signed by
        // a different key. That fails the id check first.
        //
        // Instead, build a custom bridge_outcome that references a real
        // kind:1042 signed by [0x44;32], then pass the same event as
        // candidate - gate 1+2 pass - but tell verify_bridge the legacypub
        // is [0x55;32]'s pubkey via a hand-crafted Bridge variant.
        let fresh = fresh_chain();
        let legacy_a = [0x33u8; 32];
        let k1042 = build_bridge_commitment(&legacy_a, fresh.npub(0), 1716100100, "", &[0u8; 32])
            .unwrap();
        // Bridge variant that claims legacypub belongs to [0x55;32] but
        // references k1042 (signed by [0x33;32]).
        let outcome = Kind1041Verification::Bridge {
            legacypub: "5555555555555555555555555555555555555555555555555555555555555555"
                .into(),
            subject: fresh.npub(0).into(),
            successor: fresh.npub(1).into(),
            kind1042_id: k1042.id.clone(),
        };
        let result = verify_bridge(&outcome, false, Some(&k1042), &[]);
        match result {
            BridgeVerification::Invalid(reason) => {
                assert_eq!(reason, "kind:1042 event not signed by bridge legacypub");
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn kind1042_commits_target_mismatch_refused() {
        // bridge outcome's subject is fresh.npub(0); pass a kind:1042 from
        // legacy_nsec that commits to a *different* target.
        let fresh = fresh_chain();
        let legacy_nsec = [0x33u8; 32];
        let other_target =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let k1042 =
            build_bridge_commitment(&legacy_nsec, other_target, 1716100100, "", &[0u8; 32])
                .unwrap();
        let bridge_event = fresh
            .build_bridge_rotation_event(&k1042.pubkey, &k1042.id, 1716100200, "", &[0u8; 32])
            .unwrap();
        let outcome = verify_kind_1041_event(&bridge_event);
        // Sanity: bridge_event references this k1042 by id, and is signed by
        // fresh.npub(0). The intrinsic Bridge variant should still surface.
        assert!(matches!(outcome, Kind1041Verification::Bridge { .. }));
        let result = verify_bridge(&outcome, false, Some(&k1042), std::slice::from_ref(&k1042));
        match result {
            BridgeVerification::Invalid(reason) => {
                assert_eq!(reason, "kind:1042 commits target != bridge subject");
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn conflicting_kind1042_corpus_refused() {
        // Happy bridge setup, but the conflict corpus includes a second
        // kind:1042 from legacypub committing to a *different* target.
        let (outcome, k1042) = happy_bridge_setup();
        let conflict = build_bridge_commitment(
            &[0x33u8; 32],
            "0000000000000000000000000000000000000000000000000000000000000001",
            1716100300,
            "",
            &[0u8; 32],
        )
        .unwrap();
        let corpus = vec![k1042.clone(), conflict];
        let result = verify_bridge(&outcome, false, Some(&k1042), &corpus);
        match result {
            BridgeVerification::Invalid(reason) => {
                assert!(reason.contains("contested"));
            }
            _ => panic!("expected Invalid"),
        }
    }

    #[test]
    fn non_bridge_outcome_refused() {
        // verify_bridge MUST refuse a non-Bridge variant.
        let outcome = Kind1041Verification::ChainBirth {
            subject: "aa".repeat(32),
            successor: "bb".repeat(32),
        };
        let result = verify_bridge(&outcome, false, None, &[]);
        match result {
            BridgeVerification::Invalid(reason) => {
                assert!(reason.contains("Kind1041Verification::Bridge"));
            }
            _ => panic!("expected Invalid"),
        }
    }
}
