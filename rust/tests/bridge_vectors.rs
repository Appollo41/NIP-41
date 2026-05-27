//! Byte-exact bridge-construction vectors.
//!
//! **Source of truth:** `test-vectors/nip-41-test-vectors.md` (produced
//! by `test-vectors/nip-41-test-vectors.py`). These values are pinned
//! inline because the JSON harness fixture
//! (`harness/vectors/nip41-test-vectors.json`) does not currently include
//! bridge events. KMP's `BridgeSpecVectorsTest.kt` is a peer consumer of
//! the same `.md` file, not the source of these constants.
//!
//! Coverage matches the `.md` document:
//!  - happy bridge: pinned kind:1042 id+sig, pinned bridge-rotation id+sig
//!  - contested legacypub: the fail-closed conflict rule
//!  - mismatched commits target: the bridge event references a kind:1042
//!    whose `commits` value does not match the bridge subject

use nip41::{
    bridge_commits_conflict, build_bridge_commitment, is_committed, verify_bridge,
    verify_kind_1041_event, BridgeVerification, IdentityChain, Kind1041Verification,
};
use sha2::{Digest, Sha256};

// ── Legacy key fixture ────────────────────────────────────────────────────
const LEGACY_NSEC: [u8; 32] = hex_literal::hex!(
    "baeb2736bd09a8cfdc97ab015bc2c151aa119f6ea178df24597bc0c01feabf1a"
);
const LEGACY_NPUB_EXPECTED: &str =
    "1a393666fafd21140d4a9749bf94e6596599f1227ca538102478c10c1757f297";

// ── Fresh chain fixture ───────────────────────────────────────────────────
const EXPECTED_FRESH_ROOT: &str =
    "5310304143234eb387bdaa22cb65a508ea6d7712e3603cbf8b0381e72947d88a";
const EXPECTED_FRESH_NPUB_0: &str =
    "3ca523181fb2d031c360165a93ed8004e29421a72b4522b9611b2cb4bf1afbac";
const EXPECTED_FRESH_NPUB_1: &str =
    "a4896f8555cfc706bb505f75e05be41b5373b882268d22eb41e1a3e44a95ed54";

// ── Pinned event ids/sigs (kind:1042 happy, bridge happy) ─────────────────
const K1042_HAPPY_ID: &str = "4c94b57b82104829381c59b44f205e45de8935c8f5d7953d856973e93d279f5f";
const K1042_HAPPY_SIG: &str = "b4ae0038a0e6c8ce96f57806e77cf475e695af70342bec16a3826e526d7eed2729659091b1fd577db915f99be8cce9a7a165363a8c3570407be9c6ab946d0222";
const K1042_HAPPY_CREATED_AT: i64 = 1716100100;

const BRIDGE_EVENT_ID: &str = "5a2ca9b9ef8d753d99c802b9d4084ccbb2c53fdbefea5fd66c27387fe836e6e4";
const BRIDGE_EVENT_SIG: &str = "5256b0a8d0808d793764d1564fe3195626cb1fc709afc79563d1e1ab2070fc727f6827f7ba9fdf699eb2cc4c97e04c487fca204ecab65364477012ad4a40590c";
const BRIDGE_EVENT_CREATED_AT: i64 = 1716100200;

// ── Contest vectors ───────────────────────────────────────────────────────
const CONTESTING_TARGET: &str =
    "2a5bbcb0eede528e6abe5f2ec50ad7887eb5677af383a460b05ee23bf892dfe5";
const K1042_CONTEST_ID: &str = "a0cba74c158416a8b9c8eec4ba3d75e6fae52683ac4030b015f7b9dd41f13bf0";
const K1042_CONTEST_CREATED_AT: i64 = 1716100300;

// ── Mismatch vectors ──────────────────────────────────────────────────────
const MISMATCH_TARGET: &str =
    "a2ac1e7238943ad9f9bca07e577101fdb315a16301244453cecdf71cde13592f";
const K1042_MISMATCH_ID: &str = "33159f43a980fcb9d40766dac6a005d707b9363792632f7c25b3f29ad4e8e9ad";
const K1042_MISMATCH_CREATED_AT: i64 = 1716100400;
const BRIDGE_MISMATCH_ID: &str = "5d115d46abdc28ca3df8c4d298f6e750e31e40fa32cb9fc6c577543ee9fa32be";
const BRIDGE_MISMATCH_CREATED_AT: i64 = 1716100500;

fn fresh_root() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"nip-41 bridge test vector fresh root v1");
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn fresh_chain() -> IdentityChain {
    IdentityChain::derive(&fresh_root(), 2).unwrap()
}

#[test]
fn fresh_root_matches_spec() {
    assert_eq!(hex::encode(fresh_root()), EXPECTED_FRESH_ROOT);
}

#[test]
fn fresh_chain_npubs_match_spec() {
    let c = fresh_chain();
    assert_eq!(c.npub(0), EXPECTED_FRESH_NPUB_0);
    assert_eq!(c.npub(1), EXPECTED_FRESH_NPUB_1);
}

#[test]
fn k1042_happy_id_and_sig_match_spec() {
    let c = fresh_chain();
    let signed = build_bridge_commitment(
        &LEGACY_NSEC,
        c.npub(0),
        K1042_HAPPY_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    assert_eq!(signed.id, K1042_HAPPY_ID);
    assert_eq!(signed.sig, K1042_HAPPY_SIG);
    assert_eq!(signed.pubkey, LEGACY_NPUB_EXPECTED);
    assert_eq!(signed.kind, 1042);
}

#[test]
fn bridge_event_id_and_sig_match_spec() {
    let c = fresh_chain();
    let k1042 = build_bridge_commitment(
        &LEGACY_NSEC,
        c.npub(0),
        K1042_HAPPY_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = c
        .build_bridge_rotation_event(
            LEGACY_NPUB_EXPECTED,
            &k1042.id,
            BRIDGE_EVENT_CREATED_AT,
            "",
            &[0u8; 32],
        )
        .unwrap();
    assert_eq!(bridge.id, BRIDGE_EVENT_ID);
    assert_eq!(bridge.sig, BRIDGE_EVENT_SIG);
    assert_eq!(bridge.pubkey, c.npub(0));
}

#[test]
fn bridge_full_verify_returns_valid_with_happy_context() {
    let c = fresh_chain();
    let k1042 = build_bridge_commitment(
        &LEGACY_NSEC,
        c.npub(0),
        K1042_HAPPY_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = c
        .build_bridge_rotation_event(
            LEGACY_NPUB_EXPECTED,
            &k1042.id,
            BRIDGE_EVENT_CREATED_AT,
            "",
            &[0u8; 32],
        )
        .unwrap();
    let intrinsic = verify_kind_1041_event(&bridge);
    assert!(
        matches!(intrinsic, Kind1041Verification::Bridge { .. }),
        "happy bridge event must classify as Bridge intrinsically; got {intrinsic:?}"
    );
    let result = verify_bridge(&intrinsic, false, Some(&k1042), std::slice::from_ref(&k1042));
    assert_eq!(result, BridgeVerification::Valid);
}

#[test]
fn contesting_kind1042_id_matches_spec() {
    let contest = build_bridge_commitment(
        &LEGACY_NSEC,
        CONTESTING_TARGET,
        K1042_CONTEST_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    assert_eq!(contest.id, K1042_CONTEST_ID);
}

#[test]
fn bridge_conflict_fires_with_two_distinct_targets() {
    let c = fresh_chain();
    let happy = build_bridge_commitment(
        &LEGACY_NSEC,
        c.npub(0),
        K1042_HAPPY_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let contest = build_bridge_commitment(
        &LEGACY_NSEC,
        CONTESTING_TARGET,
        K1042_CONTEST_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    assert!(bridge_commits_conflict(
        LEGACY_NPUB_EXPECTED,
        &[happy, contest]
    ));
}

#[test]
fn verify_bridge_refuses_contested_legacypub() {
    let c = fresh_chain();
    let happy = build_bridge_commitment(
        &LEGACY_NSEC,
        c.npub(0),
        K1042_HAPPY_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let contest = build_bridge_commitment(
        &LEGACY_NSEC,
        CONTESTING_TARGET,
        K1042_CONTEST_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = c
        .build_bridge_rotation_event(
            LEGACY_NPUB_EXPECTED,
            &happy.id,
            BRIDGE_EVENT_CREATED_AT,
            "",
            &[0u8; 32],
        )
        .unwrap();
    let intrinsic = verify_kind_1041_event(&bridge);
    let result = verify_bridge(&intrinsic, false, Some(&happy), &[happy.clone(), contest]);
    match result {
        BridgeVerification::Invalid(reason) => {
            assert!(
                reason.contains("contest") || reason.contains("conflict"),
                "reason should cite the contest/conflict; got '{reason}'"
            );
        }
        BridgeVerification::Valid => panic!("expected Invalid, got Valid"),
    }
}

#[test]
fn mismatching_kind1042_id_matches_spec() {
    let mismatch = build_bridge_commitment(
        &LEGACY_NSEC,
        MISMATCH_TARGET,
        K1042_MISMATCH_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    assert_eq!(mismatch.id, K1042_MISMATCH_ID);
}

#[test]
fn bridge_referencing_mismatch_id_matches_spec() {
    let c = fresh_chain();
    let mismatch = build_bridge_commitment(
        &LEGACY_NSEC,
        MISMATCH_TARGET,
        K1042_MISMATCH_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = c
        .build_bridge_rotation_event(
            LEGACY_NPUB_EXPECTED,
            &mismatch.id,
            BRIDGE_MISMATCH_CREATED_AT,
            "",
            &[0u8; 32],
        )
        .unwrap();
    assert_eq!(bridge.id, BRIDGE_MISMATCH_ID);
}

#[test]
fn verify_bridge_refuses_mismatched_commits_target() {
    let c = fresh_chain();
    let mismatch = build_bridge_commitment(
        &LEGACY_NSEC,
        MISMATCH_TARGET,
        K1042_MISMATCH_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = c
        .build_bridge_rotation_event(
            LEGACY_NPUB_EXPECTED,
            &mismatch.id,
            BRIDGE_MISMATCH_CREATED_AT,
            "",
            &[0u8; 32],
        )
        .unwrap();
    let intrinsic = verify_kind_1041_event(&bridge);
    let result = verify_bridge(
        &intrinsic,
        false,
        Some(&mismatch),
        std::slice::from_ref(&mismatch),
    );
    assert!(matches!(result, BridgeVerification::Invalid(_)));
}

#[test]
fn is_committed_returns_false_for_legacy_on_clean_corpus() {
    // The legacy npub is, by spec definition, NOT a chain head - there are
    // no kind:1041 events from it. Even with the happy kind:1042 and the
    // fresh chain's bridge event in the corpus, `is_committed(legacy_npub)`
    // must remain false: kind:1042 events are not committed-chain proofs.
    let c = fresh_chain();
    let k1042 = build_bridge_commitment(
        &LEGACY_NSEC,
        c.npub(0),
        K1042_HAPPY_CREATED_AT,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = c
        .build_bridge_rotation_event(
            LEGACY_NPUB_EXPECTED,
            &k1042.id,
            BRIDGE_EVENT_CREATED_AT,
            "",
            &[0u8; 32],
        )
        .unwrap();
    // is_committed only looks at kind:1041 events; pass the bridge event.
    // The bridge event's pubkey is fresh.npub[0], NOT legacy - so legacy is
    // not committed.
    assert!(!is_committed(LEGACY_NPUB_EXPECTED, &[bridge]));
}
