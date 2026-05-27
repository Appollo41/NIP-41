//! Cryptographic primitives: SHA-256, BIP-340 tagged hash,
//! x-coordinate-in-field preflight, and small `secp256k1` wrappers.

use sha2::{Digest, Sha256};

/// Big-endian bytes of the secp256k1 field prime p = 2^256 − 2^32 − 977.
/// A 32-byte value is a valid x-coordinate of an affine point iff x < p.
const SECP256K1_P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f,
];

pub(crate) fn sha256(msg: &[u8]) -> [u8; 32] {
    Sha256::digest(msg).into()
}

/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg).
pub(crate) fn tagged_hash(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash);
    h.update(tag_hash);
    h.update(msg);
    h.finalize().into()
}

/// True iff `x` is in `[0, p)`. The fail-closed preflight before any `lift_x`
/// so that NIP-41 validity doesn't rely on undocumented `pubkey_parse`
/// behavior. Slice `Ord` on `[u8; 32]` is lexicographic, which on big-endian
/// unsigned bytes is exactly the integer ordering we want.
pub(crate) fn is_valid_x_coord(x: &[u8; 32]) -> bool {
    x < &SECP256K1_P
}

/// Parse a lowercase 64-char hex string into a 32-byte array. Returns `None`
/// for any other length or non-hex character. Shared between the verifier
/// (proof.rs) and downstream event verification (M3+).
pub(crate) fn decode_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

/// Validate that `s` is a *lowercase* 64-char hex string (32-byte payload)
/// without producing the decoded bytes. Returns `Err(Error::InvalidHex)`
/// tagged with `field` so callers can attribute the failure to a specific
/// input. Shared by every builder that accepts pubkeys / event ids as hex.
///
/// Distinct from `decode_hex32`: `decode_hex32` delegates to the `hex` crate
/// and accepts uppercase, but NIP-41 wire format is lowercase-only, so the
/// builder validators must reject uppercase to stay spec-compliant.
pub(crate) fn require_hex_32(field: &'static str, s: &str) -> Result<(), crate::error::Error> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(crate::error::Error::InvalidHex { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty_string() {
        // Well-known vector: SHA-256 of the empty string.
        let h = sha256(b"");
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn tagged_hash_is_deterministic() {
        // The full BIP-340 tagged-hash construction is covered transitively
        // by `chain::derivation::tests::matches_spec_vector_index_0` and the
        // integration spec-vector tests, which both fail loudly if
        // `tagged_hash` is wrong. Here we only assert determinism - same
        // input ⇒ same output.
        let a = tagged_hash("nip41/succession", b"hello");
        let b = tagged_hash("nip41/succession", b"hello");
        assert_eq!(a, b);
        let c = tagged_hash("nip41/succession", b"world");
        assert_ne!(a, c);
        let d = tagged_hash("different/tag", b"hello");
        assert_ne!(a, d);
    }

    #[test]
    fn x_coord_bounds() {
        // Just below p: valid.
        let mut just_below = SECP256K1_P;
        just_below[31] -= 1;
        assert!(is_valid_x_coord(&just_below));

        // Exactly p: invalid (not strictly less than p).
        assert!(!is_valid_x_coord(&SECP256K1_P));

        // 0x00…00: valid (smaller than p; whether it's on the curve is a
        // separate question answered by lift_x).
        assert!(is_valid_x_coord(&[0u8; 32]));

        // 0xff…ff: invalid (greater than p).
        assert!(!is_valid_x_coord(&[0xffu8; 32]));
    }
}
