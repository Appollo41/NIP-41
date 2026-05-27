//! Spec-pinned constants and tag names.

/// HKDF salt that pins every NIP-41 v1 derivation. Internal: exposing a
/// `&[u8]` here lets consumers accidentally rebind a static via `static mut`
/// games; the spec is the source of truth for the value.
pub(crate) const NIP41_HKDF_SALT: &[u8] = b"nip41-key-rotation-v1";

/// BIP-340 tagged-hash domain separator for the "Committed identities"
/// commitment. Frozen by the spec.
pub const NIP41_TWEAK_TAG: &str = "nip41/succession";

/// Nostr event kind for both chain-birth and rotation events.
pub const NIP41_KIND_1041: u32 = 1041;

/// Nostr event kind for the bridge commitment from a legacy key.
pub const NIP41_KIND_1042: u32 = 1042;

/// Spec-pinned identity-chain length. Tests may use shorter chains; on-the-
/// network chains MUST be this length.
pub const NIP41_CHAIN_LENGTH: usize = 1024;

/// Closed set of NIP-41 tag names. Group them under one module so a typo
/// at any callsite can't silently produce a non-conformant event.
pub mod tags {
    /// `successor` tag name: opens a key's commitment to the next generation.
    pub const SUCCESSOR: &str = "successor";
    /// `predecessor` role label on a `p` tag identifying the rotation source.
    pub const PREDECESSOR: &str = "predecessor";
    /// `bridge` tag name on a bridge-rotation event referencing a kind:1042.
    pub const BRIDGE: &str = "bridge";
    /// NIP-01 generic-pubkey `p` tag.
    pub const P: &str = "p";
    /// `commits` tag name on a kind:1042 event pinning the fresh chain head.
    pub const COMMITS: &str = "commits";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_values() {
        assert_eq!(NIP41_TWEAK_TAG, "nip41/succession");
        assert_eq!(NIP41_KIND_1041, 1041);
        assert_eq!(NIP41_KIND_1042, 1042);
        assert_eq!(NIP41_CHAIN_LENGTH, 1024);
        assert_eq!(NIP41_HKDF_SALT, b"nip41-key-rotation-v1");
        assert_eq!(tags::SUCCESSOR, "successor");
        assert_eq!(tags::PREDECESSOR, "predecessor");
        assert_eq!(tags::BRIDGE, "bridge");
        assert_eq!(tags::P, "p");
        assert_eq!(tags::COMMITS, "commits");
    }
}
