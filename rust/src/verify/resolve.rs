//! Spec "Client verification" walkers: pure single-step `resolve_step` and
//! `find_bridge_for`. Mirror KMP's `Resolve.kt` line-for-line.
//!
//! Both walkers are pure predicates over a pre-fetched event corpus; network
//! I/O lives in the caller's relay layer. The multi-hop walk is the
//! caller's loop: fetch the next event set, call `resolve_step`, advance.
//!
//! `resolve_step` considers only [`Kind1041Verification::Rotation`] events.
//! Bridge events require external context ([`crate::is_committed()`], the
//! referenced kind:1042 event, the conflict search) that a pure predicate
//! cannot supply. Use [`find_bridge_for`] to surface the intrinsic bridge
//! outcome, then [`crate::verify_bridge`] to finalize it with the gates the
//! orchestration layer can fetch.

use crate::crypto::decode_hex32;
use crate::event::SignedNostrEvent;
use crate::verify::{verify_kind_1041_event, Kind1041Verification};

/// Spec "Client verification" / `resolve(P)`: pure single-step walk.
///
/// Given a current pubkey `current_pubkey` (lowercase 64-char hex) and a
/// pre-fetched set of kind:1041 events, return the pubkey the identity
/// advances to via a **chain rotation**, or `None` if no valid rotation
/// moves off `current_pubkey`.
///
/// Bridge events are intentionally ignored here (they require external
/// context). Use [`find_bridge_for`] for the bridge counterpart.
///
/// Fail-closed: if more than one valid rotation event claims to move off
/// the same predecessor (impossible for a committed identity per spec
/// "Conflicting rotation events", but possible if the caller passes a
/// deliberately broken event set), returns `None` rather than picking one.
/// The caller must investigate the contest.
pub fn resolve_step(current_pubkey: &str, events: &[SignedNostrEvent]) -> Option<String> {
    if decode_hex32(current_pubkey).is_none() {
        return None;
    }
    let mut found: Option<String> = None;
    for event in events {
        let outcome = verify_kind_1041_event(event);
        let Kind1041Verification::Rotation {
            predecessor,
            subject,
            ..
        } = outcome
        else {
            continue;
        };
        if predecessor != current_pubkey {
            continue;
        }
        if found.is_some() {
            // Ambiguous: a committed chain can't legitimately rotate to two
            // different successors. Fail closed.
            return None;
        }
        found = Some(subject);
    }
    found
}

/// Find the unique intrinsically-valid bridge event in `events` whose
/// `legacypub == current_pubkey`. Returns the [`Kind1041Verification`]
/// (specifically the [`Kind1041Verification::Bridge`] variant) so the
/// caller has `subject`, `successor`, and `kind1042_id` already extracted
/// to feed into [`crate::verify_bridge`].
///
/// Returns `None` if no candidate matches, or if more than one matches
/// (fail-closed: the caller must investigate the contest).
///
/// The full bridge resolution flow:
///  1. `find_bridge_for(current_pubkey, fetched_events)` → candidate bridge
///     outcome.
///  2. Fetch the referenced kind:1042 from the broad-poll relay set, plus
///     all kind:1042 events from `legacypub` for the conflict search.
///  3. Compute `is_committed(current_pubkey, …)` against the broad-poll
///     relay set's kind:1041 events for `current_pubkey`.
///  4. Call [`crate::verify_bridge`]. If `Valid`, advance the identity to
///     the bridge's `subject`.
pub fn find_bridge_for(
    current_pubkey: &str,
    events: &[SignedNostrEvent],
) -> Option<Kind1041Verification> {
    if decode_hex32(current_pubkey).is_none() {
        return None;
    }
    let mut found: Option<Kind1041Verification> = None;
    for event in events {
        let outcome = verify_kind_1041_event(event);
        let matches = matches!(
            &outcome,
            Kind1041Verification::Bridge { legacypub, .. } if legacypub == current_pubkey
        );
        if !matches {
            continue;
        }
        if found.is_some() {
            // Ambiguous bridge claim: fail closed.
            return None;
        }
        found = Some(outcome);
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityChain;

    fn chain() -> IdentityChain {
        let root = hex_literal::hex!(
            "890b93ded88a65e0707db157704ab04f84bbeec0fe6075c27ba98dcb9e5a2a13"
        );
        IdentityChain::derive(&root, 4).unwrap()
    }

    // ──── resolve_step ────

    #[test]
    fn resolve_step_returns_subject_on_rotation() {
        let c = chain();
        let rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        assert_eq!(
            resolve_step(c.npub(0), std::slice::from_ref(&rot)).as_deref(),
            Some(c.npub(1)),
        );
    }

    #[test]
    fn resolve_step_ignores_chain_birth() {
        let c = chain();
        let birth = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        assert!(resolve_step(c.npub(0), std::slice::from_ref(&birth)).is_none());
    }

    #[test]
    fn resolve_step_ignores_bridge_events() {
        // Bridge events require external gates; the pure walker skips them.
        let c = chain();
        let legacy = "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id = "0000000000000000000000000000000000000000000000000000000000000002";
        let bridge = c
            .build_bridge_rotation_event(legacy, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        // resolve_step from the legacy pubkey through a bridge event returns
        // None because the walker only matches Rotation outcomes.
        assert!(resolve_step(legacy, std::slice::from_ref(&bridge)).is_none());
    }

    #[test]
    fn resolve_step_empty_corpus_returns_none() {
        let c = chain();
        assert!(resolve_step(c.npub(0), &[]).is_none());
    }

    #[test]
    fn resolve_step_malformed_pubkey_returns_none() {
        let c = chain();
        let rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        assert!(resolve_step("not hex", std::slice::from_ref(&rot)).is_none());
    }

    #[test]
    fn resolve_step_ambiguous_corpus_returns_none() {
        // Two rotation events from different chains, both claiming to
        // succeed off the same predecessor pubkey. (Impossible for a
        // committed chain in practice, but the walker must fail closed.)
        // We can't easily synthesize two rotations from one predecessor;
        // instead, dup the same rotation event so the walker sees two
        // hits for the same predecessor.
        let c = chain();
        let rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        let corpus = vec![rot.clone(), rot];
        assert!(resolve_step(c.npub(0), &corpus).is_none());
    }

    #[test]
    fn resolve_step_skips_invalid_rotation() {
        // A tampered rotation event no longer verifies, so the walker
        // skips it and returns None.
        let c = chain();
        let mut rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        rot.content = "tampered".into();
        assert!(resolve_step(c.npub(0), std::slice::from_ref(&rot)).is_none());
    }

    // ──── find_bridge_for ────

    #[test]
    fn find_bridge_for_returns_bridge_outcome() {
        let c = chain();
        let legacy =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id =
            "0000000000000000000000000000000000000000000000000000000000000002";
        let bridge = c
            .build_bridge_rotation_event(legacy, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        let outcome = find_bridge_for(legacy, std::slice::from_ref(&bridge)).unwrap();
        match outcome {
            Kind1041Verification::Bridge {
                legacypub,
                subject,
                kind1042_id: id,
                ..
            } => {
                assert_eq!(legacypub, legacy);
                assert_eq!(subject, c.npub(0));
                assert_eq!(id, kind1042_id);
            }
            other => panic!("expected Bridge, got {other:?}"),
        }
    }

    #[test]
    fn find_bridge_for_returns_none_when_no_match() {
        let c = chain();
        let legacy =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id =
            "0000000000000000000000000000000000000000000000000000000000000002";
        let bridge = c
            .build_bridge_rotation_event(legacy, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        // Different legacy pubkey: walker finds nothing.
        let other_legacy =
            "0000000000000000000000000000000000000000000000000000000000000099";
        assert!(find_bridge_for(other_legacy, std::slice::from_ref(&bridge)).is_none());
    }

    #[test]
    fn find_bridge_for_ignores_chain_birth_and_rotation() {
        let c = chain();
        let birth = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        let rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        // Neither event is a Bridge variant, so find_bridge_for returns None
        // for *every* candidate pubkey.
        assert!(find_bridge_for(c.npub(0), &[birth.clone(), rot.clone()]).is_none());
        assert!(find_bridge_for(c.npub(1), &[birth, rot]).is_none());
    }

    #[test]
    fn find_bridge_for_ambiguous_returns_none() {
        let c = chain();
        let legacy =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id =
            "0000000000000000000000000000000000000000000000000000000000000002";
        let bridge = c
            .build_bridge_rotation_event(legacy, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        // Duplicate the bridge event in the corpus: ambiguous claim.
        let corpus = vec![bridge.clone(), bridge];
        assert!(find_bridge_for(legacy, &corpus).is_none());
    }

    #[test]
    fn find_bridge_for_malformed_pubkey_returns_none() {
        let c = chain();
        let legacy =
            "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id =
            "0000000000000000000000000000000000000000000000000000000000000002";
        let bridge = c
            .build_bridge_rotation_event(legacy, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        assert!(find_bridge_for("not hex", std::slice::from_ref(&bridge)).is_none());
    }
}
