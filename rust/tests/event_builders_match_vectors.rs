//! Byte-exact conformance for kind:1041 builders against the JSON vectors.
//!
//! The JSON fixture pins `id`, `pubkey`, `created_at`, `kind`, `tags`, and
//! `content` - every field that goes into the canonical serialization.
//! `sig` is NOT pinned: the Python harness that generated the fixture used
//! random `aux_rand`, so the captured signature is one of many valid
//! Schnorr signatures for the same id. Determinism of `event_id()` is the
//! cross-language byte-parity guarantee we care about here; full signature
//! cross-validation lives in the envelope verifier (M4).

use nip41::{IdentityChain, SignedNostrEvent};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Vectors {
    root_secret: String,
    chain_length: usize,
    chain_birth_event: SignedNostrEvent,
    rotation_event: SignedNostrEvent,
}

fn load() -> Vectors {
    let path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "..",
        "harness",
        "vectors",
        "nip41-test-vectors.json",
    ]
    .iter()
    .collect();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("vectors JSON well-formed")
}

fn root_from_hex(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("32-byte hex");
    out
}

#[test]
fn chain_birth_event_matches_vector() {
    let v = load();
    let chain = IdentityChain::derive(&root_from_hex(&v.root_secret), v.chain_length).unwrap();

    let built = chain
        .build_chain_birth_event(
            v.chain_birth_event.created_at,
            &v.chain_birth_event.content,
            &[0u8; 32],
        )
        .unwrap();

    assert_eq!(built.id, v.chain_birth_event.id);
    assert_eq!(built.pubkey, v.chain_birth_event.pubkey);
    assert_eq!(built.kind, v.chain_birth_event.kind);
    assert_eq!(built.created_at, v.chain_birth_event.created_at);
    assert_eq!(built.tags, v.chain_birth_event.tags);
    assert_eq!(built.content, v.chain_birth_event.content);
}

#[test]
fn rotation_event_matches_vector() {
    let v = load();
    let chain = IdentityChain::derive(&root_from_hex(&v.root_secret), v.chain_length).unwrap();

    let built = chain
        .build_rotation_event(
            1,
            v.rotation_event.created_at,
            &v.rotation_event.content,
            &[0u8; 32],
        )
        .unwrap();

    assert_eq!(built.id, v.rotation_event.id);
    assert_eq!(built.pubkey, v.rotation_event.pubkey);
    assert_eq!(built.kind, v.rotation_event.kind);
    assert_eq!(built.created_at, v.rotation_event.created_at);
    assert_eq!(built.tags, v.rotation_event.tags);
    assert_eq!(built.content, v.rotation_event.content);
}

/// Sanity check the canonicalizer the other way around: take the JSON vector
/// SignedNostrEvent verbatim, treat its non-id/non-sig fields as
/// `UnsignedNostrEvent`, recompute `event_id()`, and confirm it matches the
/// stored `id`. This proves the canonical-serialization implementation
/// reproduces the spec without needing the verifier (M4 territory).
#[test]
fn canonical_id_reproduces_chain_birth_vector_id() {
    let v = load();
    let unsigned = nip41::UnsignedNostrEvent {
        pubkey: v.chain_birth_event.pubkey.clone(),
        created_at: v.chain_birth_event.created_at,
        kind: v.chain_birth_event.kind,
        tags: v.chain_birth_event.tags.clone(),
        content: v.chain_birth_event.content.clone(),
    };
    assert_eq!(hex::encode(unsigned.event_id()), v.chain_birth_event.id);
}

#[test]
fn canonical_id_reproduces_rotation_vector_id() {
    let v = load();
    let unsigned = nip41::UnsignedNostrEvent {
        pubkey: v.rotation_event.pubkey.clone(),
        created_at: v.rotation_event.created_at,
        kind: v.rotation_event.kind,
        tags: v.rotation_event.tags.clone(),
        content: v.rotation_event.content.clone(),
    };
    assert_eq!(hex::encode(unsigned.event_id()), v.rotation_event.id);
}
