//! Full-flow demonstration of NIP-41: derivation, signed events, multi-step
//! rotation walk, bridge migration from a legacy key, and NIP-19 portability.
//!
//! Richer counterpart to the `walkthrough` example: this one prints the
//! intermediate values so a human reader can see what each phase yields.
//! Mirrors the spirit of KMP's `demo/Demo.kt`.
//!
//!   cargo run --example full_flow

use nip41::{
    BridgeVerification, IdentityChain, Kind1041Verification, build_bridge_commitment,
    encode_npub, encode_nroot, encode_nsec, find_bridge_for, is_committed, resolve_step,
    verify_bridge, verify_kind_1041_event,
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

fn banner(title: &str) {
    let bar = "=".repeat(78);
    println!();
    println!("{bar}");
    println!("{title}");
    println!("{bar}");
}

fn section(title: &str) {
    println!();
    println!("{title}");
    println!("{}", "-".repeat(78));
}

fn main() {
    banner("NIP-41 Nostr Identity Chain - Rust reference implementation");

    // ── [A] Phase A - derive the identity chain ────────────────────────────
    section("[A] Phase A - Derive the identity chain");
    let root = sha256_label("nip-41 full-flow demo v1");
    println!("root_secret (hex)  : {}", hex::encode(root));
    println!("root_secret (nroot): {}", encode_nroot(&root));
    println!(
        "                  (32 bytes from CSPRNG or passkey PRF in production;"
    );
    println!("                   here a SHA-256 of a fixed label so the demo reproduces.)");

    // Demo length 4 keeps the output small; on-the-network chains MUST be
    // NIP41_CHAIN_LENGTH (1024).
    let chain = IdentityChain::derive(&root, 4).unwrap();
    println!();
    println!(
        "chain length: {} (demo size; spec mandates 1024 on the network)",
        chain.length()
    );
    for i in 0..chain.length() {
        let npub_bytes = hex_to_32(chain.npub(i));
        let tag = if i == 0 {
            "  (active)"
        } else if i == chain.length() - 1 {
            "  (terminal - commits to nothing)"
        } else {
            ""
        };
        println!("  gen {i}{tag}");
        println!("    npub  hex  : {}", chain.npub(i));
        println!("    npub  nip19: {}", encode_npub(&npub_bytes));
    }

    // ── [B] Phase B - chain birth ──────────────────────────────────────────
    section("[B] Phase B - Chain-birth kind:1041 event (declares npub[0] committed)");
    let birth = chain
        .build_chain_birth_event(1716100000, "hello from nip-41", &[0u8; 32])
        .unwrap();
    println!("id  : {}", birth.id);
    println!("sig : {}", birth.sig);
    let outcome = verify_kind_1041_event(&birth);
    assert!(matches!(outcome, Kind1041Verification::ChainBirth { .. }));
    println!("verify_kind_1041_event -> ChainBirth (OK)");
    assert!(is_committed(chain.npub(0), std::slice::from_ref(&birth)));
    println!("is_committed(npub[0]) -> true");

    // ── [C] Phase C - multi-step rotation walk ─────────────────────────────
    section("[C] Phase C - Rotate 0 → 1 → 2, then walk via resolve_step");
    let rot1 = chain
        .build_rotation_event(1, 1716200000, "", &[0u8; 32])
        .unwrap();
    let rot2 = chain
        .build_rotation_event(2, 1716300000, "", &[0u8; 32])
        .unwrap();
    let pool = vec![birth.clone(), rot1.clone(), rot2.clone()];
    println!("rotation events: rot1.id={}, rot2.id={}", rot1.id, rot2.id);
    let mut current = chain.npub(0).to_string();
    let mut hops = 0;
    while let Some(next) = resolve_step(&current, &pool) {
        hops += 1;
        println!("  hop {hops}: {current} → {next}");
        current = next;
    }
    assert_eq!(current, chain.npub(2));
    println!("walked {hops} hop(s) to current identity: {current}");

    // ── [D] Phase D - bridge migration from a legacy key ───────────────────
    section("[D] Phase D - Bridge migration from a legacy (uncommitted) key");
    let legacy_nsec = sha256_label("legacy identity v1");
    let fresh = IdentityChain::derive(&sha256_label("fresh chain after bridge"), 4).unwrap();
    let k1042 = build_bridge_commitment(
        &legacy_nsec,
        fresh.npub(0),
        1716400000,
        "",
        &[0u8; 32],
    )
    .unwrap();
    println!(
        "kind:1042 from legacy {} commits to fresh npub[0] {}",
        k1042.pubkey,
        fresh.npub(0),
    );
    println!("kind:1042 id : {}", k1042.id);

    let bridge = fresh
        .build_bridge_rotation_event(&k1042.pubkey, &k1042.id, 1716400100, "", &[0u8; 32])
        .unwrap();
    println!("kind:1041 bridge event id: {}", bridge.id);

    // find_bridge_for surfaces the intrinsic outcome ready for verify_bridge.
    let intrinsic = find_bridge_for(&k1042.pubkey, std::slice::from_ref(&bridge)).unwrap();
    assert!(matches!(intrinsic, Kind1041Verification::Bridge { .. }));

    // The three external gates: legacy must not be committed, kind:1042 must
    // match by id/pubkey/commits, no conflicting kind:1042 may exist.
    let verdict = verify_bridge(
        &intrinsic,
        is_committed(&k1042.pubkey, &[]),
        Some(&k1042),
        std::slice::from_ref(&k1042),
    );
    assert_eq!(verdict, BridgeVerification::Valid);
    println!("verify_bridge -> Valid (three gates all hold)");
    assert!(is_committed(fresh.npub(0), std::slice::from_ref(&bridge)));
    println!("is_committed(fresh.npub[0]) -> true (bridge event commits the fresh head)");

    // ── [E] Phase E - NIP-19 portability ───────────────────────────────────
    section("[E] Phase E - NIP-19 portability");
    println!("root  (nroot): {}", encode_nroot(&root));
    let npub_0_bytes = hex_to_32(chain.npub(0));
    println!("npub[0]      : {}", encode_npub(&npub_0_bytes));
    let nsec_0 = chain.export_nsec(0).unwrap();
    println!("nsec[0]      : {}", encode_nsec(&nsec_0));
    println!(
        "(nsec is only emitted here as the export path; in production it"
    );
    println!(" stays inside the IdentityChain, which zeroes it on drop.)");

    banner("Done.");
}
