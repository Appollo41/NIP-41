//! Spec "Client verification" event-validity rules for kind:1041 events.
//!
//! Mirrors KMP's `EventVerifier.kt::verifyKind1041Event` line-for-line so
//! the two ports agree on outcomes and diagnostic strings. Tag hex values
//! are decoded with a lenient case-insensitive decoder to match KMP's
//! `decodeHexOrNull`; only the *builders* (via `require_hex_32` in
//! `crypto.rs`) enforce the lowercase wire format on producer input.
//!
//! Returns one of [`Kind1041Verification::ChainBirth`],
//! [`Kind1041Verification::Rotation`], [`Kind1041Verification::Bridge`] on
//! intrinsic success; otherwise [`Kind1041Verification::Invalid`] with a
//! short reason string. Fail-closed: under no circumstance does an invalid
//! event cause a different identity to be adopted.

use crate::chain::proof::verify_chain_proof_bytes;
use crate::consts::{tags, NIP41_KIND_1041};
use crate::crypto::decode_hex32;
use crate::event::envelope::{verify_event_envelope, EnvelopeCheck};
use crate::event::SignedNostrEvent;

/// Outcome of verifying a kind:1041 event.
///
/// The three valid outcomes mirror the spec's event shapes:
///  - [`Kind1041Verification::ChainBirth`]: declares its own key as a
///    committed-chain head.
///  - [`Kind1041Verification::Rotation`]: declares both that it succeeds a
///    prior key and that its own key is committed.
///  - [`Kind1041Verification::Bridge`]: declares that a legacy (uncommitted)
///    key has migrated into this fresh committed chain via a kind:1042
///    commitment. This is the result of intrinsic verification only;
///    [`crate::verify_bridge`] runs the external gates (uncommitted legacy,
///    referenced kind:1042 exists, no conflict).
///  - [`Kind1041Verification::Invalid`] carries a short reason string for
///    diagnostics.
///
/// All pubkey / event-id fields are lowercase 64-char hex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind1041Verification {
    /// Chain birth event: announces a brand-new committed chain whose head
    /// is `subject`, committing to `successor` as the next generation.
    ChainBirth {
        /// The event's `pubkey` and the new chain's `npub[0]`.
        subject: String,
        /// The new chain's `npub[1]` (target of the self-successor tag).
        successor: String,
    },
    /// Rotation event: `subject` opens its predecessor's commitment
    /// (`predecessor` → `subject`) and commits to its own `successor`.
    Rotation {
        /// Previous generation that this event is rotating away from.
        predecessor: String,
        /// The event's `pubkey` and the new generation's `npub`.
        subject: String,
        /// The next generation that `subject` commits to.
        successor: String,
    },
    /// Intrinsically-valid bridge event from a fresh committed chain.
    /// The external gates live in [`crate::verify_bridge`].
    Bridge {
        /// Legacy key being bridged away from.
        legacypub: String,
        /// Fresh chain's `npub[0]` (== `event.pubkey`).
        subject: String,
        /// Fresh chain's `npub[1]`.
        successor: String,
        /// Id of the referenced kind:1042 event.
        kind1042_id: String,
    },
    /// Verification failed; the wrapped string is a short diagnostic.
    Invalid(String),
}

/// Spec "Client verification" event-validity check for a single kind:1041
/// event. See [`Kind1041Verification`] for the outcome shapes.
///
/// Fail-closed: under no circumstance does an invalid event cause a different
/// identity to be adopted. The worst case is no-op, which is today's
/// behaviour for Nostr clients.
pub fn verify_kind_1041_event(event: &SignedNostrEvent) -> Kind1041Verification {
    let pubkey_bytes = match verify_event_envelope(event, NIP41_KIND_1041) {
        EnvelopeCheck::Ok { pubkey_bytes } => pubkey_bytes,
        EnvelopeCheck::Fail(reason) => return Kind1041Verification::Invalid(reason),
    };

    let mut self_successor: Option<(String, String)> = None;
    let mut predecessor_proof: Option<(String, String)> = None;
    let mut bridge: Option<(String, String)> = None; // (legacypub_hex, kind1042_id_hex)
    let mut p_successor_values: Vec<String> = Vec::new();
    let mut p_predecessor_values: Vec<String> = Vec::new();

    for tag in &event.tags {
        if tag.is_empty() {
            continue;
        }
        match tag[0].as_str() {
            tags::SUCCESSOR => {
                if tag.len() != 4 {
                    return Kind1041Verification::Invalid("successor tag wrong arity".into());
                }
                let subject = &tag[1];
                let internal = &tag[2];
                let npub_next = &tag[3];
                let Some(subject_b) = decode_hex32(subject) else {
                    return Kind1041Verification::Invalid(
                        "successor tag bad subject hex".into(),
                    );
                };
                let Some(internal_b) = decode_hex32(internal) else {
                    return Kind1041Verification::Invalid(
                        "successor tag bad internal hex".into(),
                    );
                };
                let Some(npub_next_b) = decode_hex32(npub_next) else {
                    return Kind1041Verification::Invalid(
                        "successor tag bad npub_next hex".into(),
                    );
                };
                if !verify_chain_proof_bytes(&subject_b, &npub_next_b, &internal_b) {
                    return Kind1041Verification::Invalid(
                        "successor tag fails verify_chain_proof".into(),
                    );
                }
                let is_self = subject_b == pubkey_bytes && npub_next_b != pubkey_bytes;
                let is_pred = subject_b != pubkey_bytes && npub_next_b == pubkey_bytes;
                if is_self {
                    if self_successor.is_some() {
                        return Kind1041Verification::Invalid(
                            "multiple self-successor tags".into(),
                        );
                    }
                    self_successor = Some((subject.clone(), npub_next.clone()));
                } else if is_pred {
                    if predecessor_proof.is_some() {
                        return Kind1041Verification::Invalid(
                            "multiple predecessor-proof tags".into(),
                        );
                    }
                    predecessor_proof = Some((subject.clone(), npub_next.clone()));
                } else {
                    return Kind1041Verification::Invalid(
                        "successor tag fits neither self nor predecessor pattern".into(),
                    );
                }
            }
            tags::BRIDGE => {
                if tag.len() != 3 {
                    return Kind1041Verification::Invalid("bridge tag wrong arity".into());
                }
                if bridge.is_some() {
                    return Kind1041Verification::Invalid("multiple bridge tags".into());
                }
                if decode_hex32(&tag[1]).is_none() {
                    return Kind1041Verification::Invalid(
                        "bridge tag bad legacypub hex".into(),
                    );
                }
                if decode_hex32(&tag[2]).is_none() {
                    return Kind1041Verification::Invalid(
                        "bridge tag bad kind1042Id hex".into(),
                    );
                }
                bridge = Some((tag[1].clone(), tag[2].clone()));
            }
            tags::P => {
                if tag.len() >= 4 {
                    match tag[3].as_str() {
                        tags::SUCCESSOR => p_successor_values.push(tag[1].clone()),
                        tags::PREDECESSOR => p_predecessor_values.push(tag[1].clone()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    // Bridge replaces the predecessor-proof successor tag. Carrying both is a
    // shape error (spec "Event shapes": rotation has predecessor proof,
    // bridge has bridge tag; never both).
    if bridge.is_some() && predecessor_proof.is_some() {
        return Kind1041Verification::Invalid(
            "event must not carry both a bridge tag and a predecessor-proof successor tag".into(),
        );
    }
    if self_successor.is_none() && predecessor_proof.is_none() && bridge.is_none() {
        return Kind1041Verification::Invalid(
            "no predecessor proof, no bridge, and no self-successor".into(),
        );
    }
    if p_successor_values.len() != 1 {
        return Kind1041Verification::Invalid(
            r#"must have exactly one ["p",_,_,"successor"] tag"#.into(),
        );
    }
    if p_successor_values[0] != event.pubkey {
        return Kind1041Verification::Invalid(
            "successor p-tag value != event.pubkey".into(),
        );
    }

    if let Some((legacypub, kind1042_id)) = bridge {
        // A bridge event must carry a self-successor (it is the chain birth
        // of the fresh committed chain) and a predecessor p-tag pointing at
        // the legacy key being bridged.
        let Some((subject, successor)) = self_successor else {
            return Kind1041Verification::Invalid(
                "bridge event missing self-successor tag".into(),
            );
        };
        if p_predecessor_values.len() != 1 {
            return Kind1041Verification::Invalid(
                "bridge event must have exactly one predecessor p-tag".into(),
            );
        }
        if p_predecessor_values[0] != legacypub {
            return Kind1041Verification::Invalid(
                "bridge event predecessor p-tag does not match bridge legacypub".into(),
            );
        }
        return Kind1041Verification::Bridge {
            legacypub,
            subject,
            successor,
            kind1042_id,
        };
    }

    if let Some((pred_subject, _pred_next)) = predecessor_proof {
        if p_predecessor_values.len() != 1 {
            return Kind1041Verification::Invalid(
                "must have exactly one predecessor p-tag when predecessor proof present".into(),
            );
        }
        if p_predecessor_values[0] != pred_subject {
            return Kind1041Verification::Invalid(
                "predecessor p-tag does not match predecessor proof".into(),
            );
        }
        let Some((_, self_next)) = self_successor else {
            // Per spec "Event shapes" a rotation event carries both a
            // predecessor proof AND a self-successor; a predecessor-only
            // event is rejected.
            return Kind1041Verification::Invalid(
                "rotation event missing self-successor tag".into(),
            );
        };
        return Kind1041Verification::Rotation {
            predecessor: pred_subject,
            subject: event.pubkey.clone(),
            successor: self_next,
        };
    }

    // Chain-birth path: predecessor_proof == None, bridge == None,
    // self_successor != None.
    if !p_predecessor_values.is_empty() {
        return Kind1041Verification::Invalid(
            "chain-birth event must not have predecessor p-tag".into(),
        );
    }
    let (subject, successor) = self_successor.expect("checked above");
    Kind1041Verification::ChainBirth { subject, successor }
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

    // ──── positive path ────

    #[test]
    fn chain_birth_event_verifies() {
        let c = chain();
        let e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        match verify_kind_1041_event(&e) {
            Kind1041Verification::ChainBirth { subject, successor } => {
                assert_eq!(subject, c.npub(0));
                assert_eq!(successor, c.npub(1));
            }
            other => panic!("expected ChainBirth, got {other:?}"),
        }
    }

    #[test]
    fn rotation_event_verifies() {
        let c = chain();
        let e = c.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();
        match verify_kind_1041_event(&e) {
            Kind1041Verification::Rotation {
                predecessor,
                subject,
                successor,
            } => {
                assert_eq!(predecessor, c.npub(0));
                assert_eq!(subject, c.npub(1));
                assert_eq!(successor, c.npub(2));
            }
            other => panic!("expected Rotation, got {other:?}"),
        }
    }

    #[test]
    fn intrinsic_bridge_event_verifies_as_bridge() {
        let fresh = chain();
        let legacy_npub = "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id = "0000000000000000000000000000000000000000000000000000000000000002";
        let e = fresh
            .build_bridge_rotation_event(legacy_npub, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        match verify_kind_1041_event(&e) {
            Kind1041Verification::Bridge {
                legacypub,
                subject,
                successor,
                kind1042_id: id,
            } => {
                assert_eq!(legacypub, legacy_npub);
                assert_eq!(subject, fresh.npub(0));
                assert_eq!(successor, fresh.npub(1));
                assert_eq!(id, kind1042_id);
            }
            other => panic!("expected Bridge, got {other:?}"),
        }
    }

    // ──── envelope rejection ────

    #[test]
    fn tampered_content_rejected() {
        let c = chain();
        let mut e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        e.content = "tampered".into(); // id no longer matches
        assert!(matches!(
            verify_kind_1041_event(&e),
            Kind1041Verification::Invalid(_)
        ));
    }

    #[test]
    fn wrong_kind_rejected() {
        let c = chain();
        let mut e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        e.kind = 9999;
        match verify_kind_1041_event(&e) {
            Kind1041Verification::Invalid(reason) => assert_eq!(reason, "kind != 1041"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // ──── forgery rejection ────

    #[test]
    fn forged_successor_target_rejected() {
        // Build a chain birth and surgically replace the successor's npub
        // target (tag[1][3]) with a different valid pubkey. The
        // verify_chain_proof check inside the verifier must reject it.
        let c = chain();
        let mut e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        // Pick a different known-good x-only key (npub[2]).
        let bad = c.npub(2).to_string();
        e.tags[1][3] = bad;
        // The id no longer matches; verifier rejects (envelope or chain proof).
        assert!(matches!(
            verify_kind_1041_event(&e),
            Kind1041Verification::Invalid(_)
        ));
    }

    #[test]
    fn forged_successor_target_with_resigned_id_rejected_by_chain_proof() {
        // To isolate the chain-proof check from the envelope check, rebuild
        // and resign the event with the forged successor target. The new id
        // and signature will be canonical, but the chain proof will fail.
        let c = chain();
        let mut e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        // Replace the successor's npub_next target with npub(2) (still a
        // valid x-only key, but not the one npub(0) committed to).
        let bad = c.npub(2).to_string();
        e.tags[1][3] = bad;
        // Recompute id and sign with the chain-birth signing key (nsec[0]).
        let unsigned = crate::event::UnsignedNostrEvent {
            pubkey: e.pubkey.clone(),
            created_at: e.created_at,
            kind: e.kind,
            tags: e.tags.clone(),
            content: e.content.clone(),
        };
        let resigned = c.sign_with(0, &unsigned, &[0u8; 32]).unwrap();
        match verify_kind_1041_event(&resigned) {
            Kind1041Verification::Invalid(reason) => {
                assert!(
                    reason.contains("verify_chain_proof"),
                    "expected chain-proof failure, got {reason}",
                );
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // ──── arity / shape ────

    #[test]
    fn missing_successor_tag_rejected() {
        // Drop the self-successor tag. The verifier rejects via the
        // "no predecessor proof, no bridge, and no self-successor" path or
        // the envelope check (id mismatch). Resign so the chain-proof scan
        // gets exercised.
        let c = chain();
        let e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        let unsigned = crate::event::UnsignedNostrEvent {
            pubkey: e.pubkey.clone(),
            created_at: e.created_at,
            kind: e.kind,
            tags: vec![e.tags[0].clone()], // keep only the p-discovery tag
            content: e.content.clone(),
        };
        let resigned = c.sign_with(0, &unsigned, &[0u8; 32]).unwrap();
        assert!(matches!(
            verify_kind_1041_event(&resigned),
            Kind1041Verification::Invalid(_)
        ));
    }

    #[test]
    fn extra_successor_tag_rejected_as_multiple_self_successors() {
        // Two self-successor tags. KMP: "multiple self-successor tags".
        let c = chain();
        let e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        let mut tags = e.tags.clone();
        tags.push(tags[1].clone()); // duplicate the self-successor tag
        let unsigned = crate::event::UnsignedNostrEvent {
            pubkey: e.pubkey.clone(),
            created_at: e.created_at,
            kind: e.kind,
            tags,
            content: e.content.clone(),
        };
        let resigned = c.sign_with(0, &unsigned, &[0u8; 32]).unwrap();
        match verify_kind_1041_event(&resigned) {
            Kind1041Verification::Invalid(reason) => {
                assert_eq!(reason, "multiple self-successor tags");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn successor_tag_wrong_arity_rejected() {
        // Truncate the self-successor tag to arity 3.
        let c = chain();
        let e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        let mut tags = e.tags.clone();
        tags[1].pop();
        let unsigned = crate::event::UnsignedNostrEvent {
            pubkey: e.pubkey.clone(),
            created_at: e.created_at,
            kind: e.kind,
            tags,
            content: e.content.clone(),
        };
        let resigned = c.sign_with(0, &unsigned, &[0u8; 32]).unwrap();
        match verify_kind_1041_event(&resigned) {
            Kind1041Verification::Invalid(reason) => {
                assert_eq!(reason, "successor tag wrong arity");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    // ──── case-insensitive hex decoding (KMP parity) ────

    #[test]
    fn uppercase_hex_in_successor_tag_accepted_per_kmp_parity() {
        // Replace the successor target with its uppercase variant. KMP's
        // `decodeHexOrNull` is case-insensitive; the Rust verifier matches
        // that lenient behaviour. NIP-41 wire format is lowercase-only, but
        // the strictness is enforced at the *builder* layer
        // (`require_hex_32`), not the verifier - exactly as KMP does it.
        let c = chain();
        let e = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        let mut tags = e.tags.clone();
        tags[1][3] = tags[1][3].to_uppercase();
        let unsigned = crate::event::UnsignedNostrEvent {
            pubkey: e.pubkey.clone(),
            created_at: e.created_at,
            kind: e.kind,
            tags,
            content: e.content.clone(),
        };
        let resigned = c.sign_with(0, &unsigned, &[0u8; 32]).unwrap();
        match verify_kind_1041_event(&resigned) {
            Kind1041Verification::ChainBirth { .. } => { /* expected */ }
            other => panic!("expected ChainBirth (uppercase hex tolerated), got {other:?}"),
        }
    }
}
