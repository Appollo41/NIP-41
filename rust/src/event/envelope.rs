//! Internal envelope verifier: the kind / id / signature preamble shared by
//! every kind-specific verifier (`verify_kind_1041_event`,
//! `verify_kind_1042_event`). Mirrors KMP's `Envelope.kt` line-for-line so
//! the two ports return the same diagnostic strings on the same inputs.
//!
//! Not in the public API: callers go through the kind-specific verifiers
//! which map [`EnvelopeCheck::Fail`] into their own `Invalid` variant.

use crate::crypto::decode_hex32;
use crate::event::{SignedNostrEvent, UnsignedNostrEvent};
use secp256k1::{schnorr, XOnlyPublicKey, SECP256K1};

/// Outcome of [`verify_event_envelope`]. On [`Ok`] the caller receives the
/// already-decoded 32-byte x-only pubkey so the kind verifier can perform tag
/// cross-checks without re-decoding.
pub(crate) enum EnvelopeCheck {
    Ok { pubkey_bytes: [u8; 32] },
    Fail(String),
}

/// Run the shared envelope check. Returns [`EnvelopeCheck::Ok`] iff:
///   - `event.kind == expected_kind`
///   - `event.pubkey` is well-formed hex and a valid x-only point on secp256k1
///   - `event.id` equals `hex(sha256(canonical_serialization(event)))`
///   - `event.sig` is a valid 64-byte Schnorr signature over `event.id` under
///     `event.pubkey`
///
/// On any failure returns [`EnvelopeCheck::Fail`] with a short diagnostic
/// string; the kind verifier wraps that string into its own `Invalid` variant.
pub(crate) fn verify_event_envelope(
    event: &SignedNostrEvent,
    expected_kind: u32,
) -> EnvelopeCheck {
    if event.kind != expected_kind {
        return EnvelopeCheck::Fail(format!("kind != {expected_kind}"));
    }

    let Some(pubkey) = decode_hex32(&event.pubkey) else {
        return EnvelopeCheck::Fail("malformed pubkey hex".into());
    };

    let Some(claimed_id) = decode_hex32(&event.id) else {
        return EnvelopeCheck::Fail("malformed event id hex".into());
    };

    let computed_id = UnsignedNostrEvent {
        pubkey: event.pubkey.clone(),
        created_at: event.created_at,
        kind: event.kind,
        tags: event.tags.clone(),
        content: event.content.clone(),
    }
    .event_id();

    if computed_id != claimed_id {
        return EnvelopeCheck::Fail("event id does not match canonical serialization".into());
    }

    let Ok(sig_bytes) = hex::decode(&event.sig) else {
        return EnvelopeCheck::Fail("malformed sig hex".into());
    };
    if sig_bytes.len() != 64 {
        return EnvelopeCheck::Fail("sig wrong length".into());
    }

    // KMP collapses off-curve pubkey, malformed Schnorr-signature bytes, and
    // verifySchnorr-returns-false into the single string "invalid signature".
    // Match that for cross-language byte parity in the diagnostic surface.
    let verify_ok = schnorr::Signature::from_slice(&sig_bytes)
        .ok()
        .zip(XOnlyPublicKey::from_slice(&pubkey).ok())
        .map(|(sig, xonly)| SECP256K1.verify_schnorr(&sig, &computed_id, &xonly).is_ok())
        .unwrap_or(false);
    if !verify_ok {
        return EnvelopeCheck::Fail("invalid signature".into());
    }

    EnvelopeCheck::Ok {
        pubkey_bytes: pubkey,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::{NIP41_KIND_1041, NIP41_KIND_1042};
    use crate::IdentityChain;

    fn chain() -> IdentityChain {
        let root = hex_literal::hex!(
            "890b93ded88a65e0707db157704ab04f84bbeec0fe6075c27ba98dcb9e5a2a13"
        );
        IdentityChain::derive(&root, 4).unwrap()
    }

    fn good_chain_birth() -> SignedNostrEvent {
        chain()
            .build_chain_birth_event(1716100000, "", &[0u8; 32])
            .unwrap()
    }

    #[test]
    fn accepts_known_good_event() {
        let e = good_chain_birth();
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Ok { pubkey_bytes } => {
                assert_eq!(hex::encode(pubkey_bytes), e.pubkey);
            }
            EnvelopeCheck::Fail(r) => panic!("expected Ok, got Fail({r})"),
        }
    }

    #[test]
    fn rejects_wrong_kind() {
        let e = good_chain_birth();
        match verify_event_envelope(&e, NIP41_KIND_1042) {
            EnvelopeCheck::Fail(reason) => assert_eq!(reason, "kind != 1042"),
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_tampered_content() {
        let mut e = good_chain_birth();
        e.content = "tampered".into();
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => {
                assert_eq!(reason, "event id does not match canonical serialization");
            }
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_tampered_id() {
        // Flip the last hex char of the id. Canonical recomputation will
        // detect the divergence.
        let mut e = good_chain_birth();
        let mut id = e.id.clone();
        let last = id.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        id.push(flipped);
        e.id = id;
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => {
                assert_eq!(reason, "event id does not match canonical serialization");
            }
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_tampered_sig() {
        let mut e = good_chain_birth();
        // Flip the first byte of the signature. The id and pubkey are still
        // canonical, so the canonical-serialization check passes; the Schnorr
        // verification fails.
        let mut sig_bytes = hex::decode(&e.sig).unwrap();
        sig_bytes[0] ^= 0x01;
        e.sig = hex::encode(sig_bytes);
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => assert_eq!(reason, "invalid signature"),
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_wrong_pubkey() {
        // Swap event.pubkey for a different (still valid) x-only key. The
        // canonical-serialization check fails first because the pubkey is in
        // the canonical message - but if the attacker also retargets the id
        // and sig, the signature check is the final gate. Here we change just
        // the pubkey to confirm the early canonical-id failure.
        let mut e = good_chain_birth();
        // Replace the first hex char of pubkey.
        let mut pk = e.pubkey.clone();
        let first = pk.chars().next().unwrap();
        let flipped = if first == 'a' { 'b' } else { 'a' };
        pk.replace_range(0..1, &flipped.to_string());
        e.pubkey = pk;
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => {
                // Pubkey is in the canonical message, so changing it makes
                // the id no longer match the canonical serialization.
                assert_eq!(reason, "event id does not match canonical serialization");
            }
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_malformed_pubkey_hex() {
        let mut e = good_chain_birth();
        e.pubkey = "zz".repeat(32);
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => assert_eq!(reason, "malformed pubkey hex"),
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_malformed_id_hex() {
        let mut e = good_chain_birth();
        e.id = "zz".repeat(32);
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => assert_eq!(reason, "malformed event id hex"),
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_malformed_sig_hex() {
        let mut e = good_chain_birth();
        e.sig = "zz".repeat(64);
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => assert_eq!(reason, "malformed sig hex"),
            _ => panic!("expected Fail"),
        }
    }

    #[test]
    fn rejects_wrong_sig_length() {
        let mut e = good_chain_birth();
        e.sig = "aa".repeat(63);
        match verify_event_envelope(&e, NIP41_KIND_1041) {
            EnvelopeCheck::Fail(reason) => assert_eq!(reason, "sig wrong length"),
            _ => panic!("expected Fail"),
        }
    }
}
