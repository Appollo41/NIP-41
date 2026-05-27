//! kind:1041 event builders (spec "Event shapes"). Inherent methods on
//! `IdentityChain`. Three shapes, all signed internally and all returning
//! a [`SignedNostrEvent`] ready for relay:
//!
//! - chain birth: a single self-successor declaring `npub[0]`'s commitment
//!   to `npub[1]`.
//! - rotation: a four-tag event opening the previous generation's commitment
//!   and declaring the new generation's commitment, signed by the new key.
//! - bridge rotation: as chain-birth but with a `bridge` tag replacing the
//!   predecessor-proof successor tag, used when migrating from a legacy
//!   (uncommitted) key.
//!
//! Tag arities and ordering mirror KMP's `Kind1041.kt` line-for-line so the
//! Rust port reproduces the spec test vectors byte-for-byte.

use crate::chain::IdentityChain;
use crate::consts::{tags, NIP41_KIND_1041};
use crate::crypto::require_hex_32;
use crate::error::Error;
use crate::event::{SignedNostrEvent, UnsignedNostrEvent};

impl IdentityChain {
    /// Spec "Event shapes": chain birth.
    ///
    /// Carries:
    /// 1. `["p", npub[0], "", "successor"]` discovery tag
    /// 2. `["successor", npub[0], internal_xonly[0], npub[1]]`
    ///    self-successor opening `npub[0]`'s commitment.
    ///
    /// Signed by `nsec[0]`. Requires `length >= 2` so the self-successor has
    /// a successor to bind.
    pub fn build_chain_birth_event(
        &self,
        created_at: i64,
        content: &str,
        aux_rand_32: &[u8; 32],
    ) -> Result<SignedNostrEvent, Error> {
        if self.length() < 2 {
            return Err(Error::ChainLength {
                got: self.length(),
                min: 2,
            });
        }
        let pubkey = self.npub(0).to_string();
        let tags_vec: Vec<Vec<String>> = vec![
            vec![
                tags::P.into(),
                pubkey.clone(),
                String::new(),
                tags::SUCCESSOR.into(),
            ],
            vec![
                tags::SUCCESSOR.into(),
                pubkey.clone(),
                self.internal_xonly(0).into(),
                self.npub(1).into(),
            ],
        ];
        let event = UnsignedNostrEvent {
            pubkey,
            created_at,
            kind: NIP41_KIND_1041,
            tags: tags_vec,
            content: content.into(),
        };
        self.sign_with(0, &event, aux_rand_32)
    }

    /// Spec "Event shapes": rotation.
    ///
    /// Carries four tags in spec order:
    /// 1. `["p", npub[to-1], "", "predecessor"]`
    /// 2. `["p", npub[to],   "", "successor"]`
    /// 3. predecessor-proof `successor` tag opening the previous key's
    ///    commitment.
    /// 4. self-successor `successor` tag opening the new key's commitment.
    ///
    /// Signed by `nsec[to_generation]`. `to_generation` MUST be in
    /// `1..=length-2`: the lower bound (1) excludes the chain-birth case
    /// (which has no predecessor to rotate from), and the upper bound
    /// (`length-2`) is enforced because a rotation event carries a
    /// self-successor for `to_generation`, which requires `to_generation+1`
    /// to exist as a non-terminal generation.
    pub fn build_rotation_event(
        &self,
        to_generation: usize,
        created_at: i64,
        content: &str,
        aux_rand_32: &[u8; 32],
    ) -> Result<SignedNostrEvent, Error> {
        let max = self.length().saturating_sub(2);
        if to_generation < 1 || to_generation > max {
            return Err(Error::RotationTargetOutOfRange {
                got: to_generation,
                max,
            });
        }
        let prev = to_generation - 1;
        let next = to_generation + 1;
        let prev_hex = self.npub(prev).to_string();
        let new_hex = self.npub(to_generation).to_string();
        let next_hex = self.npub(next).to_string();
        let tags_vec: Vec<Vec<String>> = vec![
            vec![
                tags::P.into(),
                prev_hex.clone(),
                String::new(),
                tags::PREDECESSOR.into(),
            ],
            vec![
                tags::P.into(),
                new_hex.clone(),
                String::new(),
                tags::SUCCESSOR.into(),
            ],
            vec![
                tags::SUCCESSOR.into(),
                prev_hex,
                self.internal_xonly(prev).into(),
                new_hex.clone(),
            ],
            vec![
                tags::SUCCESSOR.into(),
                new_hex.clone(),
                self.internal_xonly(to_generation).into(),
                next_hex,
            ],
        ];
        let event = UnsignedNostrEvent {
            pubkey: new_hex,
            created_at,
            kind: NIP41_KIND_1041,
            tags: tags_vec,
            content: content.into(),
        };
        self.sign_with(to_generation, &event, aux_rand_32)
    }

    /// Spec "The bridge for existing keys": a kind:1041 event from a fresh
    /// committed chain's `npub[0]` that bridges a legacy key.
    ///
    /// Carries four tags in spec order:
    /// 1. `["p", legacy_npub, "", "predecessor"]`
    /// 2. `["p", npub[0],     "", "successor"]`
    /// 3. `["bridge", legacy_npub, kind1042_event_id]` - replaces the
    ///    predecessor-proof `successor` tag that a regular rotation event
    ///    would carry, because a legacy key has no in-key commitment to
    ///    open; the link is established indirectly via the referenced
    ///    kind:1042 event.
    /// 4. self-successor for `npub[0]` opening its commitment to `npub[1]`.
    ///
    /// Signed by `nsec[0]`, never by the legacy key. Requires `length >= 2`
    /// because the bridge event carries a self-successor for `npub[0]`,
    /// which needs `npub[1]` to exist.
    pub fn build_bridge_rotation_event(
        &self,
        legacy_npub: &str,
        kind1042_event_id: &str,
        created_at: i64,
        content: &str,
        aux_rand_32: &[u8; 32],
    ) -> Result<SignedNostrEvent, Error> {
        if self.length() < 2 {
            return Err(Error::ChainLength {
                got: self.length(),
                min: 2,
            });
        }
        require_hex_32("legacy_npub", legacy_npub)?;
        require_hex_32("kind1042_event_id", kind1042_event_id)?;

        let fresh_hex = self.npub(0).to_string();
        let tags_vec: Vec<Vec<String>> = vec![
            vec![
                tags::P.into(),
                legacy_npub.into(),
                String::new(),
                tags::PREDECESSOR.into(),
            ],
            vec![
                tags::P.into(),
                fresh_hex.clone(),
                String::new(),
                tags::SUCCESSOR.into(),
            ],
            vec![
                tags::BRIDGE.into(),
                legacy_npub.into(),
                kind1042_event_id.into(),
            ],
            vec![
                tags::SUCCESSOR.into(),
                fresh_hex.clone(),
                self.internal_xonly(0).into(),
                self.npub(1).into(),
            ],
        ];
        let event = UnsignedNostrEvent {
            pubkey: fresh_hex,
            created_at,
            kind: NIP41_KIND_1041,
            tags: tags_vec,
            content: content.into(),
        };
        self.sign_with(0, &event, aux_rand_32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> IdentityChain {
        // Matches the JSON test-vectors fixture.
        let root = hex_literal::hex!(
            "890b93ded88a65e0707db157704ab04f84bbeec0fe6075c27ba98dcb9e5a2a13"
        );
        IdentityChain::derive(&root, 4).unwrap()
    }

    #[test]
    fn chain_birth_matches_json_vector_id() {
        let c = chain();
        // chain_birth_event values pinned from
        // harness/vectors/nip41-test-vectors.json. The JSON fixture's `sig`
        // was produced with random aux_rand at vector-generation time and
        // is intentionally not pinned (the Python harness comment notes
        // this); the event id is deterministic and the cross-language
        // checkpoint.
        let built = c.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
        assert_eq!(
            built.id,
            "5d4d1f22f7de47ed8d4ce89b38d36f353b27123c424da8a4fb3fd585ec399b8c"
        );
        assert_eq!(built.kind, 1041);
        assert_eq!(built.pubkey, c.npub(0));
        // Two tags: discovery `p` then self-successor.
        assert_eq!(built.tags.len(), 2);
        assert_eq!(built.tags[0][0], "p");
        assert_eq!(built.tags[1][0], "successor");
        // Signature is 64 bytes / 128 hex chars; precise value depends on
        // aux_rand and is verified end-to-end by the M4 envelope verifier.
        assert_eq!(built.sig.len(), 128);
    }

    #[test]
    fn rotation_matches_json_vector_id() {
        let c = chain();
        // rotation_event in the JSON fixture is at to_generation = 1.
        let built = c
            .build_rotation_event(1, 1716200000, "", &[0u8; 32])
            .unwrap();
        assert_eq!(
            built.id,
            "979a8bf001216e9499287c4d4d5b1093d1e048fc2eeb4ebaf49a7d7df641af9d"
        );
        assert_eq!(built.pubkey, c.npub(1));
        assert_eq!(built.tags.len(), 4);
        assert_eq!(built.sig.len(), 128);
    }

    #[test]
    fn rotation_rejects_zero_to_generation() {
        let c = chain();
        let err = c
            .build_rotation_event(0, 1716200000, "", &[0u8; 32])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::RotationTargetOutOfRange { got: 0, .. }
        ));
    }

    #[test]
    fn rotation_rejects_terminal_to_generation() {
        // length = 4, so max non-terminal-with-successor = length - 2 = 2.
        // to_generation = 3 (the terminal) MUST be rejected because the
        // rotation event needs a self-successor, which the terminal lacks.
        let c = chain();
        let err = c
            .build_rotation_event(3, 1716200000, "", &[0u8; 32])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::RotationTargetOutOfRange { got: 3, max: 2 }
        ));
    }

    #[test]
    fn chain_birth_rejects_length_below_2() {
        let chain1 = IdentityChain::derive(&[0x42u8; 32], 1).unwrap();
        let err = chain1
            .build_chain_birth_event(1716100000, "", &[0u8; 32])
            .unwrap_err();
        assert!(matches!(err, Error::ChainLength { got: 1, min: 2 }));
    }

    #[test]
    fn bridge_rotation_builds_with_expected_tags() {
        let c = chain();
        let legacy = "0000000000000000000000000000000000000000000000000000000000000001";
        let kind1042_id = "0000000000000000000000000000000000000000000000000000000000000002";
        let built = c
            .build_bridge_rotation_event(legacy, kind1042_id, 1716100200, "", &[0u8; 32])
            .unwrap();
        assert_eq!(built.kind, 1041);
        assert_eq!(built.pubkey, c.npub(0));
        assert_eq!(built.tags.len(), 4);
        // Tag ordering: [p,predecessor], [p,successor], [bridge,…], [successor,…]
        assert_eq!(built.tags[0][0], "p");
        assert_eq!(built.tags[0][1], legacy);
        assert_eq!(built.tags[0][3], "predecessor");
        assert_eq!(built.tags[1][0], "p");
        assert_eq!(built.tags[1][1], c.npub(0));
        assert_eq!(built.tags[1][3], "successor");
        assert_eq!(built.tags[2][0], "bridge");
        assert_eq!(built.tags[2][1], legacy);
        assert_eq!(built.tags[2][2], kind1042_id);
        assert_eq!(built.tags[3][0], "successor");
        assert_eq!(built.tags[3][1], c.npub(0));
        assert_eq!(built.tags[3][3], c.npub(1));
    }

    #[test]
    fn bridge_rotation_rejects_bad_legacy_npub_hex() {
        let c = chain();
        let kind1042_id = "0000000000000000000000000000000000000000000000000000000000000002";
        let err = c
            .build_bridge_rotation_event("not hex", kind1042_id, 0, "", &[0u8; 32])
            .unwrap_err();
        assert!(matches!(err, Error::InvalidHex { field: "legacy_npub" }));
    }

    #[test]
    fn bridge_rotation_rejects_bad_kind1042_id_hex() {
        let c = chain();
        let legacy = "0000000000000000000000000000000000000000000000000000000000000001";
        let err = c
            .build_bridge_rotation_event(legacy, "ZZ", 0, "", &[0u8; 32])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidHex {
                field: "kind1042_event_id"
            }
        ));
    }
}
