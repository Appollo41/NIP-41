//! Property and edge-case coverage for `IdentityChain`.
//!
//! Exercises the boundaries the integration tests should never silently
//! drift across: length validation, terminal-only chains, deterministic
//! derivation under the same root, out-of-range rejection on
//! `export_nsec` / `sign_with`, and rotation-target bounds.

use nip41::{Error, IdentityChain, UnsignedNostrEvent};

#[test]
fn rejects_length_zero() {
    let err = IdentityChain::derive(&[0u8; 32], 0).unwrap_err();
    assert!(
        matches!(err, Error::ChainLength { got: 0, min: 1 }),
        "expected ChainLength {{ got: 0, min: 1 }}, got {err:?}"
    );
}

#[test]
fn terminal_only_chain_has_no_tweak() {
    let c = IdentityChain::derive(&[7u8; 32], 1).unwrap();
    assert_eq!(c.length(), 1);
    // Terminal generation has no successor commitment, so no tweak.
    assert!(c.tweak(0).is_none());
    // Terminal: published npub equals the internal x-only key (no taproot
    // tweak applied because there is nothing to commit to).
    assert_eq!(c.npub(0), c.internal_xonly(0));
}

#[test]
fn non_terminal_generations_have_tweak() {
    let c = IdentityChain::derive(&[7u8; 32], 4).unwrap();
    assert!(c.tweak(0).is_some());
    assert!(c.tweak(1).is_some());
    assert!(c.tweak(2).is_some());
    // Terminal generation has no successor to commit to.
    assert!(c.tweak(3).is_none());
}

#[test]
fn derive_is_deterministic_under_same_root() {
    let a = IdentityChain::derive(&[42u8; 32], 4).unwrap();
    let b = IdentityChain::derive(&[42u8; 32], 4).unwrap();
    for i in 0..4 {
        assert_eq!(a.npub(i), b.npub(i), "npub({i}) mismatch");
        assert_eq!(
            a.internal_xonly(i),
            b.internal_xonly(i),
            "internal_xonly({i}) mismatch"
        );
        assert_eq!(a.tweak(i), b.tweak(i), "tweak({i}) mismatch");
    }
}

#[test]
fn distinct_roots_produce_distinct_chains() {
    let a = IdentityChain::derive(&[1u8; 32], 4).unwrap();
    let b = IdentityChain::derive(&[2u8; 32], 4).unwrap();
    // The chains must differ at every generation; if any two indices
    // collided we'd be looking at a derivation-domain bug.
    for i in 0..4 {
        assert_ne!(a.npub(i), b.npub(i), "npub({i}) collision");
        assert_ne!(
            a.internal_xonly(i),
            b.internal_xonly(i),
            "internal_xonly({i}) collision"
        );
    }
}

#[test]
fn export_nsec_rejects_out_of_range() {
    let c = IdentityChain::derive(&[7u8; 32], 2).unwrap();
    let err = c.export_nsec(99).unwrap_err();
    assert!(
        matches!(
            err,
            Error::GenerationOutOfRange {
                generation: 99,
                length: 2
            }
        ),
        "expected GenerationOutOfRange, got {err:?}"
    );
}

#[test]
fn sign_with_rejects_out_of_range() {
    let c = IdentityChain::derive(&[7u8; 32], 2).unwrap();
    let e = UnsignedNostrEvent {
        pubkey: c.npub(0).into(),
        created_at: 0,
        kind: 1,
        tags: vec![],
        content: "".into(),
    };
    let err = c.sign_with(99, &e, &[0u8; 32]).unwrap_err();
    assert!(
        matches!(
            err,
            Error::GenerationOutOfRange {
                generation: 99,
                length: 2
            }
        ),
        "expected GenerationOutOfRange, got {err:?}"
    );
}

#[test]
fn build_rotation_rejects_out_of_range_targets() {
    let c = IdentityChain::derive(&[7u8; 32], 4).unwrap();
    // Generation 0 is chain head, not a rotation target: rotation events
    // require an in-key predecessor commitment to open.
    assert!(c.build_rotation_event(0, 0, "", &[0u8; 32]).is_err());
    // Generation 3 is terminal - no rotation can land there because the
    // event carries a self-successor for its subject and there is no
    // npub[4] to bind.
    assert!(c.build_rotation_event(3, 0, "", &[0u8; 32]).is_err());
    // Valid rotations: 1 and 2 (length-2 == 2, so range is 1..=2).
    assert!(c.build_rotation_event(1, 0, "", &[0u8; 32]).is_ok());
    assert!(c.build_rotation_event(2, 0, "", &[0u8; 32]).is_ok());
}
