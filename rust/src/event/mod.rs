//! Nostr event types and the NIP-01 canonical id derivation.
//!
//! `UnsignedNostrEvent` holds the six fields whose canonical JSON form is
//! sha256'd to produce the NIP-01 event id; `SignedNostrEvent` is the wire
//! form with `id` and `sig` filled in. `canonical_serialization()` reproduces
//! Python's `json.dumps(..., separators=(",", ":"), ensure_ascii=False)`
//! byte-for-byte: compact (no whitespace), array-form, raw UTF-8 for
//! non-ASCII. `serde_json`'s default `to_string` matches this - it never
//! emits `\uXXXX` escapes for code points outside the ASCII control range,
//! so we can rely on it without a custom formatter.

use crate::crypto::sha256;
use crate::error::Error;
use secp256k1::{Keypair, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};

pub(crate) mod envelope;
pub mod kind_1041;
pub mod kind_1042;

pub use kind_1042::build_bridge_commitment;

/// The fields that determine the event id (NIP-01). No `id` or `sig` here.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsignedNostrEvent {
    /// Signer's x-only pubkey as lowercase 64-char hex.
    pub pubkey: String,
    /// Unix-seconds timestamp; matches NIP-01 `created_at`.
    #[serde(rename = "created_at")]
    pub created_at: i64,
    /// NIP-01 event kind (1041, 1042, …).
    pub kind: u32,
    /// Tag matrix; each tag is a list of strings, NIP-01 array form.
    pub tags: Vec<Vec<String>>,
    /// Event content; raw UTF-8, NIP-01 string form.
    pub content: String,
}

impl UnsignedNostrEvent {
    /// NIP-01 canonical serialization:
    /// `[0, pubkey, created_at, kind, tags, content]` as compact JSON, no
    /// whitespace, raw UTF-8 for non-ASCII.
    ///
    /// Python's `json.dumps(..., separators=(",", ":"), ensure_ascii=False)`
    /// and kotlinx-serialization's `JsonArray.toString()` both produce this
    /// exact form, and `serde_json::to_string` matches them: integers are
    /// unquoted, no whitespace is inserted, and non-ASCII code points are
    /// emitted as raw UTF-8 bytes rather than `\uXXXX` escapes. Only ASCII
    /// control characters and the quote/backslash get JSON-escaped, which
    /// matches the spec.
    pub fn canonical_serialization(&self) -> String {
        let payload = serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content,
        ]);
        serde_json::to_string(&payload).expect("JSON serialization of owned values is infallible")
    }

    /// SHA-256 of the canonical serialization: this is the value the BIP-340
    /// signer signs.
    pub fn event_id(&self) -> [u8; 32] {
        sha256(self.canonical_serialization().as_bytes())
    }

    /// Sign this event with `nsec` (a 32-byte BIP-340 signing key), producing
    /// a fully-serialised [`SignedNostrEvent`].
    ///
    /// `aux_rand_32 = [0; 32]` produces deterministic signatures - the mode
    /// the test vectors pin. In production, pass 32 random bytes for the
    /// standard BIP-340 nonce rerandomization guarantees.
    ///
    /// Uses the secp256k1 global verification+signing context
    /// (`secp256k1::SECP256K1`, enabled by the `global-context` Cargo
    /// feature) so this call does not allocate a fresh context per
    /// invocation.
    pub fn sign(
        &self,
        nsec: &[u8; 32],
        aux_rand_32: &[u8; 32],
    ) -> Result<SignedNostrEvent, Error> {
        let id = self.event_id();
        let sk = SecretKey::from_slice(nsec)?;
        let keypair = Keypair::from_secret_key(SECP256K1, &sk);
        let sig = SECP256K1.sign_schnorr_with_aux_rand(&id, &keypair, aux_rand_32);
        Ok(SignedNostrEvent {
            id: hex::encode(id),
            pubkey: self.pubkey.clone(),
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
            sig: hex::encode(sig.as_ref()),
        })
    }
}

/// A signed Nostr event in wire form.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedNostrEvent {
    /// NIP-01 event id as lowercase 64-char hex (SHA-256 of the canonical
    /// serialization of the unsigned event).
    pub id: String,
    /// Signer's x-only pubkey as lowercase 64-char hex.
    pub pubkey: String,
    /// Unix-seconds timestamp.
    #[serde(rename = "created_at")]
    pub created_at: i64,
    /// NIP-01 event kind.
    pub kind: u32,
    /// Tag matrix; same shape as [`UnsignedNostrEvent::tags`].
    pub tags: Vec<Vec<String>>,
    /// Event content; raw UTF-8.
    pub content: String,
    /// BIP-340 Schnorr signature as lowercase 128-char hex (64 bytes).
    pub sig: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_serialization_is_compact() {
        let e = UnsignedNostrEvent {
            pubkey: "a".repeat(64),
            created_at: 1716100000,
            kind: 1,
            tags: vec![vec!["p".into(), "b".repeat(64)]],
            content: "hi".into(),
        };
        let s = e.canonical_serialization();
        // No spaces, array-form, integer fields not quoted.
        assert!(!s.contains(' '), "expected no whitespace, got {s}");
        assert!(s.starts_with("[0,\""));
        assert!(s.ends_with(",\"hi\"]"));
        // Integers must not be quoted.
        assert!(s.contains(",1716100000,"));
        assert!(s.contains(",1,"));
    }

    #[test]
    fn canonical_serialization_preserves_non_ascii() {
        let e = UnsignedNostrEvent {
            pubkey: "a".repeat(64),
            created_at: 0,
            kind: 1,
            tags: vec![],
            content: "héllo \u{1F389}".into(),
        };
        // Spec mandates `ensure_ascii=False`-equivalent: raw UTF-8, no
        // `\uXXXX` escapes for code points outside the ASCII control range.
        let s = e.canonical_serialization();
        assert!(s.contains("héllo"), "expected raw UTF-8, got {s}");
        assert!(s.contains('\u{1F389}'), "expected raw emoji, got {s}");
        assert!(
            !s.contains("\\u"),
            "found Unicode escape in canonical serialization: {s}",
        );
    }

    #[test]
    fn sign_round_trip_id_matches_recomputed() {
        // A made-up but valid 32-byte nsec. Determinism (aux_rand = 0) makes
        // this test reproducible. The point of the round-trip is to confirm
        // that the id reported by `sign` is exactly sha256(canonical_form);
        // we do not need to verify the signature itself here (that lands in
        // the envelope verifier in M4).
        let nsec = [0x42u8; 32];
        let sk = SecretKey::from_slice(&nsec).unwrap();
        let pk = sk.x_only_public_key(SECP256K1).0;
        let pubkey_hex = hex::encode(pk.serialize());

        let event = UnsignedNostrEvent {
            pubkey: pubkey_hex,
            created_at: 1716100000,
            kind: 1,
            tags: vec![vec!["t".into(), "test".into()]],
            content: "hello".into(),
        };

        let expected_id = hex::encode(event.event_id());
        let signed = event.sign(&nsec, &[0u8; 32]).unwrap();
        assert_eq!(signed.id, expected_id);
        assert_eq!(signed.pubkey, event.pubkey);
        assert_eq!(signed.created_at, event.created_at);
        assert_eq!(signed.kind, event.kind);
        assert_eq!(signed.tags, event.tags);
        assert_eq!(signed.content, event.content);
        // Schnorr sig is 64 bytes / 128 hex chars.
        assert_eq!(signed.sig.len(), 128);
    }

    #[test]
    fn sign_rejects_zero_nsec() {
        let event = UnsignedNostrEvent {
            pubkey: "a".repeat(64),
            created_at: 0,
            kind: 1,
            tags: vec![],
            content: "".into(),
        };
        let err = event.sign(&[0u8; 32], &[0u8; 32]).unwrap_err();
        assert!(matches!(err, Error::Secp256k1(_)));
    }
}
