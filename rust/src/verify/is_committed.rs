//! Spec "Client verification" `isCommitted(K)`: pure predicate over a
//! pre-fetched set of kind:1041 events. Mirrors KMP's
//! `IsCommitted.kt::isCommitted`.
//!
//! Network I/O lives in the caller. A client framework would obtain the
//! event list via a `{"kinds":[1041], "authors":["<K hex>"]}` REQ before
//! invoking this predicate.

use crate::crypto::decode_hex32;
use crate::event::SignedNostrEvent;
use crate::verify::{verify_kind_1041_event, Kind1041Verification};

/// Spec "Client verification" `isCommitted(K)`: returns `true` iff at least
/// one event in `events` is a valid kind:1041 whose `pubkey == subject` and
/// whose verification outcome carries a self-successor for `subject`.
///
/// To keep the bridge gate sound under adversarial input, only events that
/// *actually* verify count: a malformed kind:1041 cannot manufacture
/// commitment by "looking like" a self-successor. We delegate to
/// [`verify_kind_1041_event`]; [`ChainBirth`], [`Rotation`], and [`Bridge`]
/// outcomes all carry a self-successor binding `event.pubkey` to its
/// `npub[1]` and so count as committed; an [`Invalid`] outcome does not.
///
/// Bridge events also count: a bridge event *is* a chain-birth event for the
/// fresh committed chain. Its self-successor tag binds `event.pubkey` to its
/// `npub[1]`, establishing the fresh `npub[0]` as a committed-chain head
/// (spec "The bridge for existing keys": "the self-successor tag is the
/// same as in any kind:1041 event and is what establishes the fresh npub\[0\]
/// as a committed-chain head, protecting it from a subsequent bridge
/// takeover").
///
/// # Arguments
/// * `subject` - lowercase 64-char hex x-only candidate pubkey
/// * `events`  - pre-fetched kind:1041 events. The caller's relay filter
///   should already restrict to `authors == [subject]`, but the predicate
///   is safe against unfiltered noise: any event whose pubkey doesn't match
///   `subject` is skipped.
///
/// Returns `false` for any malformed `subject` (non-64 hex chars, non-hex
/// bytes, etc.).
///
/// [`ChainBirth`]: Kind1041Verification::ChainBirth
/// [`Rotation`]: Kind1041Verification::Rotation
/// [`Bridge`]: Kind1041Verification::Bridge
/// [`Invalid`]: Kind1041Verification::Invalid
pub fn is_committed(subject: &str, events: &[SignedNostrEvent]) -> bool {
    if decode_hex32(subject).is_none() {
        return false;
    }
    events.iter().any(|event| {
        if event.pubkey != subject {
            return false;
        }
        matches!(
            verify_kind_1041_event(event),
            Kind1041Verification::ChainBirth { .. }
                | Kind1041Verification::Rotation { .. }
                | Kind1041Verification::Bridge { .. }
        )
    })
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

    #[test]
    fn chain_birth_makes_npub_0_committed() {
        let c = chain();
        let birth = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        assert!(is_committed(c.npub(0), std::slice::from_ref(&birth)));
    }

    #[test]
    fn rotation_makes_npub_to_committed() {
        let c = chain();
        let rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        // event.pubkey is npub(1); a rotation event commits its own subject.
        assert!(is_committed(c.npub(1), std::slice::from_ref(&rot)));
    }

    #[test]
    fn bridge_makes_fresh_npub_0_committed() {
        let fresh = chain();
        let legacy_npub = "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id = "0000000000000000000000000000000000000000000000000000000000000002";
        let bridge_event = fresh
            .build_bridge_rotation_event(legacy_npub, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        assert!(is_committed(fresh.npub(0), std::slice::from_ref(&bridge_event)));
        // The legacy key is *not* made committed by a bridge event signed
        // by the fresh chain.
        assert!(!is_committed(legacy_npub, std::slice::from_ref(&bridge_event)));
    }

    #[test]
    fn empty_event_set_returns_false() {
        let c = chain();
        assert!(!is_committed(c.npub(0), &[]));
    }

    #[test]
    fn malformed_subject_returns_false() {
        let c = chain();
        let birth = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        assert!(!is_committed("not hex", std::slice::from_ref(&birth)));
        // Uppercase: decode_hex32 is lenient on case so this still returns
        // true if the subject byte-equals event.pubkey. But event.pubkey is
        // lowercase, so the string comparison fails - confirm.
        let upper = c.npub(0).to_uppercase();
        assert!(!is_committed(&upper, std::slice::from_ref(&birth)));
    }

    #[test]
    fn invalid_event_does_not_count() {
        let c = chain();
        let mut birth = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        birth.content = "tampered".into(); // breaks the canonical id
        assert!(!is_committed(c.npub(0), std::slice::from_ref(&birth)));
    }

    #[test]
    fn unfiltered_noise_safely_ignored() {
        // Subject is npub(0). Pass it a rotation event whose pubkey is
        // npub(1). The predicate must skip the event (pubkey mismatch) and
        // return false.
        let c = chain();
        let rot = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        assert!(!is_committed(c.npub(0), std::slice::from_ref(&rot)));
    }
}
