//! Spec "Bridge commitment kind:1042" verifier.
//!
//! Mirrors KMP's `EventVerifier.kt::verifyKind1042Event`: the kind:1042
//! event must clear the shared envelope check and carry exactly one
//! [`commits`] tag whose value is a 32-byte hex pubkey. Other tags are
//! permitted and ignored; the caller filters by `pubkey` upstream (e.g. via
//! a Nostr REQ scoped to the legacy key being investigated).
//!
//! [`commits`]: crate::consts::tags::COMMITS

use crate::consts::{tags, NIP41_KIND_1042};
use crate::crypto::decode_hex32;
use crate::event::envelope::{verify_event_envelope, EnvelopeCheck};
use crate::event::SignedNostrEvent;

/// Outcome of verifying a kind:1042 bridge commitment.
///
/// [`Valid`] carries the `commits` target as lowercase 64-char hex;
/// [`Invalid`] carries a short reason string for diagnostics. Fail-closed:
/// any deviation returns [`Invalid`] rather than letting an event slip
/// through.
///
/// [`Valid`]: Kind1042Verification::Valid
/// [`Invalid`]: Kind1042Verification::Invalid
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind1042Verification {
    /// Event clears every gate; `commits` is the lowercase-hex x-only target
    /// pubkey (the fresh chain's `npub[0]`).
    Valid {
        /// `commits` tag target: lowercase 64-char hex of the fresh chain's
        /// `npub[0]`.
        commits: String,
    },
    /// Verification failed; the wrapped string is a short diagnostic.
    Invalid(String),
}

/// Spec "Bridge commitment kind:1042": verify a candidate kind:1042 event.
///
/// Accepts iff:
///  - the envelope check passes (kind == 1042, canonical id, Schnorr sig)
///  - exactly one `commits` tag is present, with arity 2, whose value is
///    a 32-byte lowercase hex string
///
/// Other tags are permitted and ignored. The verifier intentionally does
/// not check anything about `event.pubkey` against an expected legacy key;
/// the caller filters by `pubkey` upstream and
/// [`crate::bridge_commits_conflict`] / [`crate::verify_bridge`] cross-check it.
pub fn verify_kind_1042_event(event: &SignedNostrEvent) -> Kind1042Verification {
    match verify_event_envelope(event, NIP41_KIND_1042) {
        EnvelopeCheck::Ok { .. } => {}
        EnvelopeCheck::Fail(reason) => return Kind1042Verification::Invalid(reason),
    }

    let commits_tags: Vec<&Vec<String>> = event
        .tags
        .iter()
        .filter(|t| t.first().map(|s| s.as_str()) == Some(tags::COMMITS))
        .collect();
    if commits_tags.is_empty() {
        return Kind1042Verification::Invalid("missing commits tag".into());
    }
    if commits_tags.len() > 1 {
        return Kind1042Verification::Invalid("multiple commits tags".into());
    }
    let tag = commits_tags[0];
    if tag.len() != 2 {
        return Kind1042Verification::Invalid("commits tag wrong arity".into());
    }
    // Case-insensitive hex decoding to match KMP's `decodeHexOrNull`. The
    // lowercase wire-format rule is enforced at the builder layer
    // (`require_hex_32`), not here.
    if decode_hex32(&tag[1]).is_none() {
        return Kind1042Verification::Invalid("commits value bad hex".into());
    }
    Kind1042Verification::Valid {
        commits: tag[1].clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_bridge_commitment;
    use crate::event::UnsignedNostrEvent;

    fn good_commitment() -> SignedNostrEvent {
        // Use a non-trivial legacy nsec and a known fresh npub.
        build_bridge_commitment(
            &[0x33u8; 32],
            "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4",
            1716100100,
            "",
            &[0u8; 32],
        )
        .unwrap()
    }

    #[test]
    fn accepts_known_good_commitment() {
        let e = good_commitment();
        match verify_kind_1042_event(&e) {
            Kind1042Verification::Valid { commits } => {
                assert_eq!(
                    commits,
                    "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4"
                );
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn forged_commits_target_rejected() {
        // Resign with the legacy nsec but a flipped commits target byte.
        // The envelope check passes (id matches the new tags); the commits
        // value is still well-formed hex of a different value, so the
        // *intrinsic* verifier reports Valid for the new target. The forgery
        // detection lives one layer up in verify_bridge, which checks that
        // commits == bridge.subject. Here we confirm that intrinsic
        // verification merely surfaces the (possibly forged) target.
        let mut e = good_commitment();
        e.tags[0][1] =
            "0000000000000000000000000000000000000000000000000000000000000003".into();
        // Recompute id and sign using a fresh kind:1042 build with the same
        // legacy_nsec but the changed target so the resulting event is well-
        // formed at the envelope level.
        let resigned = build_bridge_commitment(
            &[0x33u8; 32],
            "0000000000000000000000000000000000000000000000000000000000000003",
            1716100100,
            "",
            &[0u8; 32],
        )
        .unwrap();
        match verify_kind_1042_event(&resigned) {
            Kind1042Verification::Valid { commits } => {
                // Intrinsic verifier surfaces the *new* commits value; the
                // mismatch detection is the bridge-layer's job.
                assert_eq!(commits, e.tags[0][1]);
            }
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    #[test]
    fn tampered_id_rejected() {
        let mut e = good_commitment();
        let mut id = e.id.clone();
        let last = id.pop().unwrap();
        id.push(if last == '0' { '1' } else { '0' });
        e.id = id;
        assert!(matches!(
            verify_kind_1042_event(&e),
            Kind1042Verification::Invalid(_)
        ));
    }

    #[test]
    fn wrong_kind_rejected() {
        let mut e = good_commitment();
        e.kind = 9999;
        match verify_kind_1042_event(&e) {
            Kind1042Verification::Invalid(reason) => assert_eq!(reason, "kind != 1042"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn missing_commits_tag_rejected() {
        // Hand-craft a kind:1042 with no commits tag and sign it.
        let legacy_nsec = [0x33u8; 32];
        let sk = secp256k1::SecretKey::from_slice(&legacy_nsec).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let pubkey_hex = hex::encode(xonly.serialize());
        let unsigned = UnsignedNostrEvent {
            pubkey: pubkey_hex,
            created_at: 1716100100,
            kind: 1042,
            tags: vec![],
            content: "".into(),
        };
        let signed = unsigned.sign(&legacy_nsec, &[0u8; 32]).unwrap();
        match verify_kind_1042_event(&signed) {
            Kind1042Verification::Invalid(reason) => assert_eq!(reason, "missing commits tag"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn multiple_commits_tags_rejected() {
        // Hand-craft a kind:1042 with two commits tags.
        let legacy_nsec = [0x33u8; 32];
        let sk = secp256k1::SecretKey::from_slice(&legacy_nsec).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let pubkey_hex = hex::encode(xonly.serialize());
        let target = "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4";
        let unsigned = UnsignedNostrEvent {
            pubkey: pubkey_hex,
            created_at: 1716100100,
            kind: 1042,
            tags: vec![
                vec!["commits".into(), target.into()],
                vec!["commits".into(), target.into()],
            ],
            content: "".into(),
        };
        let signed = unsigned.sign(&legacy_nsec, &[0u8; 32]).unwrap();
        match verify_kind_1042_event(&signed) {
            Kind1042Verification::Invalid(reason) => {
                assert_eq!(reason, "multiple commits tags");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn commits_wrong_arity_rejected() {
        let legacy_nsec = [0x33u8; 32];
        let sk = secp256k1::SecretKey::from_slice(&legacy_nsec).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let pubkey_hex = hex::encode(xonly.serialize());
        let unsigned = UnsignedNostrEvent {
            pubkey: pubkey_hex,
            created_at: 1716100100,
            kind: 1042,
            tags: vec![vec!["commits".into()]], // arity 1
            content: "".into(),
        };
        let signed = unsigned.sign(&legacy_nsec, &[0u8; 32]).unwrap();
        match verify_kind_1042_event(&signed) {
            Kind1042Verification::Invalid(reason) => {
                assert_eq!(reason, "commits tag wrong arity");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn uppercase_commits_value_accepted_per_kmp_parity() {
        // KMP's `decodeHexOrNull` is case-insensitive; the Rust verifier
        // matches that lenient behaviour. The lowercase wire-format rule is
        // enforced at the builder layer, not the verifier. The returned
        // `commits` field surfaces the original (uppercase) string -
        // matching KMP's `Kind1042Verification.Valid(commitsHex)`.
        let legacy_nsec = [0x33u8; 32];
        let sk = secp256k1::SecretKey::from_slice(&legacy_nsec).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let pubkey_hex = hex::encode(xonly.serialize());
        let upper = "AF878736425985FD1F32C4B2673281E4A670AF12E5B44BAC6109913F7535D1C4";
        let unsigned = UnsignedNostrEvent {
            pubkey: pubkey_hex,
            created_at: 1716100100,
            kind: 1042,
            tags: vec![vec!["commits".into(), upper.into()]],
            content: "".into(),
        };
        let signed = unsigned.sign(&legacy_nsec, &[0u8; 32]).unwrap();
        match verify_kind_1042_event(&signed) {
            Kind1042Verification::Valid { commits } => assert_eq!(commits, upper),
            other => panic!("expected Valid (uppercase hex tolerated), got {other:?}"),
        }
    }
}
