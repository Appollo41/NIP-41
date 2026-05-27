//! Code-as-documentation walkthrough of the NIP-41 public API.
//!
//! Read top to bottom: derive → encode/decode → build → verify → walk →
//! bridge → `is_committed`. Verification is carried by `assert!`s; the
//! handful of `println!` calls narrate progress to a human running the
//! example locally.
//!
//!   cargo run --example walkthrough

use nip41::{
    BridgeVerification, IdentityChain, Kind1041Verification, build_bridge_commitment,
    decode_npub, decode_nroot, decode_nsec, encode_npub, encode_nroot, encode_nsec,
    find_bridge_for, is_committed, resolve_step, verify_bridge, verify_kind_1041_event,
};
use sha2::{Digest, Sha256};

fn sha256_label(s: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).expect("64-char lowercase hex");
    out
}

fn main() {
    // ── 1. Derive an identity chain from a 32-byte root secret. ────────────
    // In production, `root_secret` is 32 bytes from a CSPRNG or a passkey
    // PRF derivation. Here we hash a fixed label so the walkthrough is
    // reproducible.
    let root_secret = sha256_label("example root secret");
    let chain = IdentityChain::derive(&root_secret, 4).unwrap();
    let gen_0 = chain.npub(0).to_string();
    let gen_1 = chain.npub(1).to_string();
    println!("derived chain of length {}", chain.length());
    println!("  gen 0 npub: {gen_0}");
    println!("  gen 1 npub: {gen_1}");

    // ── 2. NIP-19 portability. Encode/decode the root secret and the
    //    generation-0 pubkey and signing key. ───────────────────────────────
    let nroot = encode_nroot(&root_secret);
    assert_eq!(decode_nroot(&nroot).unwrap(), root_secret);

    let gen_0_bytes = hex_to_32(&gen_0);
    let npub_1 = encode_npub(&gen_0_bytes);
    assert_eq!(decode_npub(&npub_1).unwrap(), gen_0_bytes);

    let nsec_0 = chain.export_nsec(0).unwrap();
    let nsec_str = encode_nsec(&nsec_0);
    let decoded_nsec = decode_nsec(&nsec_str).unwrap();
    assert_eq!(*decoded_nsec, *nsec_0);
    println!("nip-19 round-trips (nroot, npub, nsec): OK");

    // ── 3. Build NIP-41 events. ────────────────────────────────────────────
    // `aux_rand_32 = [0; 32]` produces deterministic signatures, the mode
    // the test vectors pin. Pass 32 random bytes in production.
    let birth = chain
        .build_chain_birth_event(1716100000, "", &[0u8; 32])
        .unwrap();
    let rotation = chain
        .build_rotation_event(1, 1716200000, "", &[0u8; 32])
        .unwrap();

    // ── 4. Verify events (pure predicate; no network). ─────────────────────
    match verify_kind_1041_event(&birth) {
        Kind1041Verification::ChainBirth { subject, successor } => {
            assert_eq!(subject, gen_0);
            assert_eq!(successor, gen_1);
        }
        other => panic!("expected ChainBirth, got {other:?}"),
    }
    match verify_kind_1041_event(&rotation) {
        Kind1041Verification::Rotation {
            predecessor,
            subject,
            ..
        } => {
            assert_eq!(predecessor, gen_0);
            assert_eq!(subject, gen_1);
        }
        other => panic!("expected Rotation, got {other:?}"),
    }
    println!("chain-birth and rotation events verified");

    // ── 5. Walk one step: caller supplies the events to consider. ──────────
    // `resolve_step` is a pure predicate over a pre-fetched event corpus;
    // network I/O lives in the caller's relay layer.
    let next = resolve_step(&gen_0, std::slice::from_ref(&rotation));
    assert_eq!(next.as_deref(), Some(gen_1.as_str()));

    // ── 6. `is_committed`: was a kind:1041 from this pubkey seen? ─────────
    // The chain-birth event is what makes `npub[0]` a committed-chain head.
    assert!(is_committed(&gen_0, std::slice::from_ref(&birth)));
    // A legacy key with no kind:1041 events is not committed; the bridge
    // gate downstream uses this fact to refuse takeover of committed keys.
    let legacy_npub = "0000000000000000000000000000000000000000000000000000000000000099";
    assert!(!is_committed(legacy_npub, &[]));
    println!("is_committed agrees: gen 0 is committed, legacy key is not");

    // ── 7. Bridge a legacy (uncommitted) key into a fresh committed chain.
    let legacy_nsec = sha256_label("legacy identity v1");
    let fresh = IdentityChain::derive(&sha256_label("fresh chain root"), 4).unwrap();
    let k1042 = build_bridge_commitment(
        &legacy_nsec,
        fresh.npub(0),
        1716300000,
        "",
        &[0u8; 32],
    )
    .unwrap();
    let bridge = fresh
        .build_bridge_rotation_event(&k1042.pubkey, &k1042.id, 1716300100, "", &[0u8; 32])
        .unwrap();

    // 7a. `find_bridge_for` surfaces the intrinsic bridge outcome for the
    //     legacy pubkey from a pre-fetched event corpus.
    let intrinsic = find_bridge_for(&k1042.pubkey, std::slice::from_ref(&bridge)).unwrap();
    assert!(matches!(intrinsic, Kind1041Verification::Bridge { .. }));

    // 7b. `verify_bridge` runs the three external gates: legacy is not
    //     committed, kind:1042 matches, and no conflicting kind:1042 exists.
    let result = verify_bridge(
        &intrinsic,
        is_committed(&k1042.pubkey, &[]),
        Some(&k1042),
        std::slice::from_ref(&k1042),
    );
    assert_eq!(result, BridgeVerification::Valid);

    // 7c. After the bridge, the fresh chain's npub[0] is committed.
    assert!(is_committed(fresh.npub(0), std::slice::from_ref(&bridge)));
    println!("bridge from legacy {} verified", k1042.pubkey);
    println!("fresh chain head {} is now committed", fresh.npub(0));

    println!("walkthrough OK");
}
