//! Consolidated spec-vector coverage: cross-validation of the published
//! events in the JSON harness fixture against every public verifier.
//!
//! The JSON fixture's `sig` is NOT deterministic (the Python harness uses
//! random `aux_rand`), so this test does NOT pin sigs against the JSON.
//! What we DO assert is that the captured events verify intrinsically
//! against `verify_kind_1041_event` and round-trip through the downstream
//! predicates (`is_committed`, `resolve_step`). Byte-exact builder parity
//! is covered by `event_builders_match_vectors.rs` (id-only). Deterministic
//! sig coverage comes from `bridge_vectors.rs`, which pins sigs computed
//! with `aux_rand_32 = 0`.

use nip41::{
    is_committed, resolve_step, verify_kind_1041_event, Kind1041Verification, SignedNostrEvent,
};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Vectors {
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

// Pinned identity hex from the JSON's generations[0..3].npub values. The
// JSON itself is the source of truth; these literals are mirrored here so
// the assertions read naturally and so that test failure messages cite the
// exact expected hex rather than a JSON-path indirection.
const NPUB_0: &str = "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4";
const NPUB_1: &str = "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111";
const NPUB_2: &str = "06632001932f623c61df08d7dde11900aa6680748f9fc01a8f244fb4b0a70d2a";

#[test]
fn chain_birth_event_verifies_as_chain_birth() {
    let v = load();
    let outcome = verify_kind_1041_event(&v.chain_birth_event);
    match outcome {
        Kind1041Verification::ChainBirth { subject, successor } => {
            assert_eq!(subject, NPUB_0);
            assert_eq!(subject, v.chain_birth_event.pubkey);
            assert_eq!(successor, NPUB_1);
        }
        other => panic!("expected ChainBirth, got {other:?}"),
    }
}

#[test]
fn rotation_event_verifies_as_rotation() {
    let v = load();
    let outcome = verify_kind_1041_event(&v.rotation_event);
    match outcome {
        Kind1041Verification::Rotation {
            predecessor,
            subject,
            successor,
        } => {
            assert_eq!(predecessor, NPUB_0);
            assert_eq!(subject, NPUB_1);
            assert_eq!(subject, v.rotation_event.pubkey);
            assert_eq!(successor, NPUB_2);
        }
        other => panic!("expected Rotation, got {other:?}"),
    }
}

#[test]
fn is_committed_recognises_chain_birth_head() {
    let v = load();
    // The chain-birth event commits npub[0] as a committed-chain head.
    assert!(
        is_committed(NPUB_0, std::slice::from_ref(&v.chain_birth_event)),
        "npub[0] should be is_committed against its own chain-birth event"
    );
}

#[test]
fn is_committed_recognises_rotation_subject() {
    let v = load();
    // The rotation event commits npub[1] (its subject == event.pubkey).
    assert!(
        is_committed(NPUB_1, std::slice::from_ref(&v.rotation_event)),
        "npub[1] should be is_committed against its own rotation event"
    );
}

#[test]
fn is_committed_rejects_uncommitted_pubkey() {
    let v = load();
    let stranger = "00".repeat(32);
    assert!(
        !is_committed(&stranger, &[v.chain_birth_event, v.rotation_event]),
        "an unrelated pubkey must not be is_committed against this corpus"
    );
}

#[test]
fn resolve_step_walks_npub0_to_npub1() {
    let v = load();
    // From the chain head's perspective, the next chain step is the
    // rotation that lands on npub[1]. resolve_step inspects only rotation
    // events (not chain-birth), so we feed both.
    let corpus = [v.chain_birth_event, v.rotation_event];
    let next = resolve_step(NPUB_0, &corpus);
    assert_eq!(next.as_deref(), Some(NPUB_1));
}

#[test]
fn resolve_step_at_terminal_returns_none() {
    let v = load();
    let corpus = [v.chain_birth_event, v.rotation_event];
    // npub[1] is the most-recent subject; no rotation event opens its
    // predecessor commitment, so the walker has no next step.
    assert_eq!(resolve_step(NPUB_1, &corpus), None);
}
