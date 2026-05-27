//! NIP-19 bech32 encoding for `nroot`, `npub`, and `nsec`.
//!
//! Format: `<hrp>1<bech32 payload of 32 bytes>`. NIP-19 uses the
//! original bech32 (not bech32m) checksum, so we encode with the
//! `bech32::Bech32` variant explicitly. `bech32::decode` accepts either
//! checksum variant for resilience and matches the KMP reference port,
//! which delegates to `Bech32.decodeBytes` (also lenient on the checksum
//! variant on decode).
//!
//! Public-identifier flavors (`npub`, `nroot`) round-trip raw 32-byte
//! arrays. The secret-bearing flavor (`nsec`) returns a
//! [`Zeroizing`] wrapper so the decoded buffer zeros on drop.

use crate::error::Nip19Error;
use bech32::{Bech32, Hrp};
use zeroize::Zeroizing;

const HRP_NROOT: &str = "nroot";
const HRP_NPUB: &str = "npub";
const HRP_NSEC: &str = "nsec";

fn encode(hrp_str: &'static str, payload: &[u8; 32]) -> String {
    let hrp = Hrp::parse(hrp_str).expect("static HRP is always valid");
    bech32::encode::<Bech32>(hrp, payload).expect("32-byte payload is always encodable")
}

fn decode(s: &str, expected_hrp: &'static str) -> Result<[u8; 32], Nip19Error> {
    let (hrp, data) = bech32::decode(s).map_err(|e| Nip19Error::Bech32(e.to_string()))?;
    if hrp.as_str() != expected_hrp {
        return Err(Nip19Error::HrpMismatch {
            expected: expected_hrp,
            got: hrp.as_str().to_string(),
        });
    }
    if data.len() != 32 {
        return Err(Nip19Error::PayloadLength { got: data.len() });
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

/// Encode a 32-byte NIP-41 root secret as `nroot1…`.
///
/// `root` is read once and not retained or mutated; the caller may zero
/// its buffer after this call returns.
pub fn encode_nroot(root: &[u8; 32]) -> String {
    encode(HRP_NROOT, root)
}

/// Decode an `nroot1…` string back into the raw 32-byte root secret.
pub fn decode_nroot(s: &str) -> Result<[u8; 32], Nip19Error> {
    decode(s, HRP_NROOT)
}

/// Encode a 32-byte BIP-340 x-only pubkey as `npub1…`.
pub fn encode_npub(npub: &[u8; 32]) -> String {
    encode(HRP_NPUB, npub)
}

/// Decode an `npub1…` string back into the raw 32-byte x-only pubkey.
pub fn decode_npub(s: &str) -> Result<[u8; 32], Nip19Error> {
    decode(s, HRP_NPUB)
}

/// Encode a 32-byte BIP-340 signing key as `nsec1…`.
///
/// `nsec` is read once and not retained or mutated; the caller may zero
/// its buffer after this call returns.
pub fn encode_nsec(nsec: &[u8; 32]) -> String {
    encode(HRP_NSEC, nsec)
}

/// Decode an `nsec1…` string back into the raw 32-byte signing key.
///
/// Returns a [`Zeroizing`] wrapper so the decoded key zeros on drop.
pub fn decode_nsec(s: &str) -> Result<Zeroizing<[u8; 32]>, Nip19Error> {
    let bytes = decode(s, HRP_NSEC)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── KMP-oracle vectors ─────────────────────────────────────────────────
    // Pinned against the KMP reference port's bech32 conformance tests
    // (`kmp/.../Nip19Test.kt`, `Nip19NrootTest.kt`). Cross-implementation
    // byte parity for these encoded strings is the spec-level guarantee
    // implementations are entitled to rely on.

    /// NIP-19 spec npub vector (also pinned by KMP `Nip19Test`).
    const SPEC_NPUB_HEX: &str =
        "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
    const SPEC_NPUB_BECH: &str =
        "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";

    fn hex_to_32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).expect("32-byte hex");
        out
    }

    #[test]
    fn npub_encodes_kmp_oracle_vector() {
        let bytes = hex_to_32(SPEC_NPUB_HEX);
        assert_eq!(encode_npub(&bytes), SPEC_NPUB_BECH);
    }

    #[test]
    fn npub_decodes_kmp_oracle_vector() {
        let bytes = decode_npub(SPEC_NPUB_BECH).unwrap();
        assert_eq!(hex::encode(bytes), SPEC_NPUB_HEX);
    }

    #[test]
    fn nroot_round_trips_kmp_sample_root() {
        // KMP `Nip19NrootTest.sampleRoot` = 0x01,0x02,…,0x20. The bech32
        // checksum is deterministic, so any conformant implementation must
        // produce the same encoded string for this payload.
        let mut root = [0u8; 32];
        for (i, b) in root.iter_mut().enumerate() {
            *b = (i + 1) as u8;
        }
        let s = encode_nroot(&root);
        assert!(s.starts_with("nroot1"), "expected nroot1 prefix, got {s}");
        let decoded = decode_nroot(&s).unwrap();
        assert_eq!(decoded, root);
        // Stability across invocations.
        assert_eq!(encode_nroot(&root), s);
    }

    #[test]
    fn nroot_round_trips_arbitrary_bytes() {
        let root: [u8; 32] = [0x42; 32];
        let s = encode_nroot(&root);
        assert!(s.starts_with("nroot1"));
        assert_eq!(decode_nroot(&s).unwrap(), root);
    }

    #[test]
    fn npub_round_trips_arbitrary_bytes() {
        let pk: [u8; 32] = [0x11; 32];
        let s = encode_npub(&pk);
        assert!(s.starts_with("npub1"));
        assert_eq!(decode_npub(&s).unwrap(), pk);
    }

    #[test]
    fn nsec_round_trips_and_zeroizes() {
        let sk: [u8; 32] = [0x99; 32];
        let s = encode_nsec(&sk);
        assert!(s.starts_with("nsec1"));
        let decoded = decode_nsec(&s).unwrap();
        assert_eq!(decoded.as_ref(), &sk);
    }

    #[test]
    fn hrp_mismatch_rejected_npub_as_nroot() {
        // KMP `Nip19NrootTest.decodeNroot_rejectsNpubHrp` - cross-HRP foot-gun
        // is the single biggest thing the bech32 HRP exists to prevent.
        let root: [u8; 32] = [0x42; 32];
        let as_npub = encode_npub(&root);
        let err = decode_nroot(&as_npub).unwrap_err();
        assert!(matches!(
            err,
            Nip19Error::HrpMismatch { expected: "nroot", .. }
        ));
    }

    #[test]
    fn hrp_mismatch_rejected_nsec_as_npub() {
        // KMP `Nip19Test.decodeNpub_rejectsNsecPrefix`.
        let sk: [u8; 32] = [0x07; 32];
        let nsec = encode_nsec(&sk);
        let err = decode_npub(&nsec).unwrap_err();
        assert!(matches!(
            err,
            Nip19Error::HrpMismatch { expected: "npub", .. }
        ));
    }

    #[test]
    fn malformed_bech32_rejected() {
        // KMP `Nip19NrootTest.decodeNroot_rejectsTotalGarbage`.
        let err = decode_nroot("not even bech32").unwrap_err();
        assert!(matches!(err, Nip19Error::Bech32(_)));
    }

    #[test]
    fn corrupted_checksum_rejected() {
        // KMP `Nip19Test.decodeNpub_rejectsCorruptedChecksum` - flipping a
        // single data-section character must invalidate the bech32 checksum.
        let bad = SPEC_NPUB_BECH.replacen('8', "9", 1);
        let err = decode_npub(&bad).unwrap_err();
        assert!(matches!(err, Nip19Error::Bech32(_)));
    }

    #[test]
    fn payload_length_mismatch_rejected() {
        // Hand-roll a valid bech32 string with a 31-byte payload under the
        // `nroot` HRP. `bech32::decode` accepts it (the checksum is valid),
        // and our payload-length gate must then reject it.
        let short_payload = [0u8; 31];
        let hrp = Hrp::parse(HRP_NROOT).unwrap();
        let bad = bech32::encode::<Bech32>(hrp, &short_payload).unwrap();
        let err = decode_nroot(&bad).unwrap_err();
        assert!(
            matches!(err, Nip19Error::PayloadLength { got: 31 }),
            "expected PayloadLength {{ got: 31 }}, got {err:?}"
        );
    }
}
