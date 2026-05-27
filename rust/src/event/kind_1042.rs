//! kind:1042 bridge-commitment builder (spec "Bridge commitment kind:1042").
//!
//! The kind:1042 event is signed by the **legacy** key - not by any chain
//! generation - so this is a free function rather than an `IdentityChain`
//! method. It pins the legacy identity to a fresh committed chain whose
//! `npub[0]` is given.

use crate::consts::{tags, NIP41_KIND_1042};
use crate::crypto::require_hex_32;
use crate::error::Error;
use crate::event::{SignedNostrEvent, UnsignedNostrEvent};
use secp256k1::{Keypair, SecretKey, SECP256K1};

/// Spec "Bridge commitment kind:1042": a one-time event signed by the legacy
/// key that commits the legacy identity to migrating into a fresh committed
/// chain whose `npub[0]` is given.
///
/// The event carries exactly one `commits` tag and no other NIP-41 tags.
/// Deterministic signing by default (`aux_rand_32 = [0; 32]`) so the event
/// is reproducible against spec test vectors; pass 32 random bytes for the
/// standard BIP-340 nonce rerandomization in production.
///
/// Both `legacy_nsec` and `aux_rand_32` are read once by the BIP-340 signer
/// and not retained or mutated; the caller may zero either buffer after the
/// call returns.
///
/// Uses the secp256k1 global verification+signing context
/// (`secp256k1::SECP256K1`, enabled by the `global-context` Cargo feature)
/// so this call does not allocate a fresh context per invocation.
///
/// # Arguments
/// * `legacy_nsec`   - 32-byte BIP-340 signing key for the legacy identity
/// * `fresh_npub_0`  - lowercase 64-char hex x-only `npub[0]` of a fresh
///                     committed chain (the migration target)
/// * `created_at`    - unix seconds (the event's NIP-01 created_at)
/// * `content`       - optional human-readable note (use `""` if unused)
/// * `aux_rand_32`   - 32-byte BIP-340 aux randomness
pub fn build_bridge_commitment(
    legacy_nsec: &[u8; 32],
    fresh_npub_0: &str,
    created_at: i64,
    content: &str,
    aux_rand_32: &[u8; 32],
) -> Result<SignedNostrEvent, Error> {
    require_hex_32("fresh_npub_0", fresh_npub_0)?;

    let sk = SecretKey::from_slice(legacy_nsec)?;
    let kp = Keypair::from_secret_key(SECP256K1, &sk);
    let (xonly, _parity) = kp.x_only_public_key();
    let legacy_pubkey_hex = hex::encode(xonly.serialize());

    let tags_vec: Vec<Vec<String>> = vec![vec![tags::COMMITS.into(), fresh_npub_0.into()]];
    let event = UnsignedNostrEvent {
        pubkey: legacy_pubkey_hex,
        created_at,
        kind: NIP41_KIND_1042,
        tags: tags_vec,
        content: content.into(),
    };
    event.sign(legacy_nsec, aux_rand_32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_kind_1042_with_single_commits_tag() {
        let legacy_nsec = [0x33u8; 32];
        let fresh_npub_0 =
            "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4";
        let signed = build_bridge_commitment(
            &legacy_nsec,
            fresh_npub_0,
            1716100100,
            "",
            &[0u8; 32],
        )
        .unwrap();
        assert_eq!(signed.kind, 1042);
        assert_eq!(signed.tags.len(), 1);
        assert_eq!(signed.tags[0][0], "commits");
        assert_eq!(signed.tags[0][1], fresh_npub_0);
        assert_eq!(signed.created_at, 1716100100);
        // Pubkey is derived from legacy_nsec; we don't pin it here but it
        // must be present and 64 hex chars.
        assert_eq!(signed.pubkey.len(), 64);
        assert_eq!(signed.sig.len(), 128);
    }

    #[test]
    fn id_is_deterministic_for_pinned_inputs() {
        // Same inputs => same id, twice. Validates the canonicalizer's
        // determinism end-to-end through this builder.
        let legacy_nsec = [0x33u8; 32];
        let fresh =
            "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4";
        let a =
            build_bridge_commitment(&legacy_nsec, fresh, 1716100100, "", &[0u8; 32]).unwrap();
        let b =
            build_bridge_commitment(&legacy_nsec, fresh, 1716100100, "", &[0u8; 32]).unwrap();
        assert_eq!(a.id, b.id);
        // With aux_rand pinned to zero, the signature is also deterministic.
        assert_eq!(a.sig, b.sig);
    }

    #[test]
    fn rejects_bad_fresh_npub_hex_short() {
        let legacy_nsec = [0x33u8; 32];
        let err =
            build_bridge_commitment(&legacy_nsec, "not hex", 0, "", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::InvalidHex { field: "fresh_npub_0" }));
    }

    #[test]
    fn rejects_bad_fresh_npub_hex_uppercase() {
        let legacy_nsec = [0x33u8; 32];
        // Right length, wrong case - NIP-41 fixes lowercase hex.
        let upper = "AF878736425985FD1F32C4B2673281E4A670AF12E5B44BAC6109913F7535D1C4";
        let err = build_bridge_commitment(&legacy_nsec, upper, 0, "", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::InvalidHex { field: "fresh_npub_0" }));
    }

    #[test]
    fn rejects_zero_legacy_nsec() {
        let fresh =
            "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4";
        let err = build_bridge_commitment(&[0u8; 32], fresh, 0, "", &[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::Secp256k1(_)));
    }
}
