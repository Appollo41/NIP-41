//! Spec "Implementation pseudocode" `verifyChainProof`: the pure
//! cryptographic predicate underlying every `successor` tag check.

use crate::consts::NIP41_TWEAK_TAG;
use crate::crypto::{decode_hex32, is_valid_x_coord, tagged_hash};
use secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};

/// Hex-string entry point. All three arguments are lowercase 64-char hex
/// (32-byte x-only values). Malformed hex returns `false`. Fail-closed.
pub fn verify_chain_proof(subject: &str, npub_next: &str, internal_xonly: &str) -> bool {
    let Some(subject) = decode_hex32(subject) else {
        return false;
    };
    let Some(npub_next) = decode_hex32(npub_next) else {
        return false;
    };
    let Some(internal_xonly) = decode_hex32(internal_xonly) else {
        return false;
    };
    verify_chain_proof_bytes(&subject, &npub_next, &internal_xonly)
}

/// Byte-level variant. Used by the event verifier once tag values have been
/// decoded once.
pub(crate) fn verify_chain_proof_bytes(
    subject: &[u8; 32],
    npub_next: &[u8; 32],
    internal_xonly: &[u8; 32],
) -> bool {
    if !is_valid_x_coord(subject)
        || !is_valid_x_coord(npub_next)
        || !is_valid_x_coord(internal_xonly)
    {
        return false;
    }

    let mut msg = [0u8; 64];
    msg[..32].copy_from_slice(internal_xonly);
    msg[32..].copy_from_slice(npub_next);
    let t = tagged_hash(NIP41_TWEAK_TAG, &msg);

    // t must be a valid scalar in [1, n). KMP's secKeyVerify rejects both 0
    // and >= n; `Scalar::from_be_bytes` only rejects >= n, so we screen 0
    // explicitly to keep cross-language byte parity.
    if t == [0u8; 32] {
        return false;
    }
    let Ok(tweak) = Scalar::from_be_bytes(t) else {
        return false;
    };

    let Ok(xonly) = XOnlyPublicKey::from_slice(internal_xonly) else {
        return false;
    };

    let secp = Secp256k1::verification_only();
    let Ok((tweaked, _parity)) = xonly.add_tweak(&secp, &tweak) else {
        return false;
    };
    tweaked.serialize() == *subject
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pinned from harness/vectors/nip41-test-vectors.json
    // generation 0:
    const SUBJECT_0: &str = "af878736425985fd1f32c4b2673281e4a670af12e5b44bac6109913f7535d1c4";
    const INTERNAL_0: &str = "589ab097fb0dc109d597ab8714b8363b6c96238e735b4f749fad4377aa8871cf";
    // npub of generation 1 (i.e., npub_next for the subject above):
    const NPUB_1: &str = "dcfd5f479fbc68ae0af338c914826713df5c94fda0534c14ebb62fffbcc5a111";

    #[test]
    fn accepts_known_good_triple() {
        assert!(verify_chain_proof(SUBJECT_0, NPUB_1, INTERNAL_0));
    }

    #[test]
    fn rejects_wrong_npub_next() {
        // Wrong successor: bind to npub_next with the last byte flipped.
        let mut bad = NPUB_1.to_string();
        bad.replace_range(62..64, "00");
        assert!(!verify_chain_proof(SUBJECT_0, &bad, INTERNAL_0));
    }

    #[test]
    fn rejects_malformed_hex() {
        assert!(!verify_chain_proof("zz", NPUB_1, INTERNAL_0));
        assert!(!verify_chain_proof(SUBJECT_0, "zz", INTERNAL_0));
        assert!(!verify_chain_proof(SUBJECT_0, NPUB_1, "zz"));
    }

    #[test]
    fn rejects_x_coord_at_or_above_p() {
        let p_hex = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        assert!(!verify_chain_proof(SUBJECT_0, NPUB_1, p_hex));
        assert!(!verify_chain_proof(p_hex, NPUB_1, INTERNAL_0));
    }
}
