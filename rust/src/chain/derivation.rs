//! HKDF-to-scalar derivation with counter rederivation.
//!
//! Spec: NIP-41 "Identity chain". The base info is
//! `"internal-key" || u32be(i)`. If the resulting scalar is 0 or >= n,
//! retry by appending a counter byte: counter = 0 is the initial (no-byte)
//! attempt; rejections advance to counter = 1, 2, … each appending that
//! single byte to `info`.

use crate::consts::NIP41_HKDF_SALT;
use crate::error::Error;
use hkdf::Hkdf;
use sha2::Sha256;
use secp256k1::SecretKey;
use zeroize::Zeroizing;

/// Result of one accepted derivation: the secret scalar (as a `SecretKey`,
/// which checks it's in `[1, n)`) and the counter value that produced it.
pub(crate) struct DerivedScalar {
    pub(crate) secret_key: SecretKey,
    pub(crate) bytes: Zeroizing<[u8; 32]>,
    pub(crate) counter_used: u8,
}

/// Spec "Identity chain": derive `p_internal[i]`, retrying with an
/// incrementing counter byte appended to `info` on out-of-range outputs.
/// `counter_start` lets the caller skip past counter values already
/// consumed by an earlier rejection at this index.
pub(crate) fn derive_scalar_at_counter(
    root_secret: &[u8; 32],
    i: u32,
    counter_start: u8,
) -> Result<DerivedScalar, Error> {
    let hk = Hkdf::<Sha256>::new(Some(NIP41_HKDF_SALT), root_secret);
    let mut counter = counter_start;
    let mut base_info = Vec::with_capacity(16);
    base_info.extend_from_slice(b"internal-key");
    base_info.extend_from_slice(&i.to_be_bytes());

    loop {
        let info: Vec<u8> = if counter == 0 {
            base_info.clone()
        } else {
            let mut v = base_info.clone();
            v.push(counter);
            v
        };

        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(&info, okm.as_mut())
            .expect("HKDF expand 32 bytes always succeeds for SHA-256");

        // SecretKey::from_slice rejects 0 and values >= n. That's exactly the
        // spec's "0 or >= n" rejection condition.
        match SecretKey::from_slice(okm.as_ref()) {
            Ok(sk) => {
                return Ok(DerivedScalar {
                    secret_key: sk,
                    bytes: okm,
                    counter_used: counter,
                });
            }
            Err(_) => {
                if counter == u8::MAX {
                    return Err(Error::CounterExhausted { generation: i as usize });
                }
                counter += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    /// Determinism: same input ⇒ same scalar.
    #[test]
    fn deterministic_under_same_root() {
        let root: [u8; 32] = [0x42; 32];
        let a = derive_scalar_at_counter(&root, 0, 0).unwrap();
        let b = derive_scalar_at_counter(&root, 0, 0).unwrap();
        assert_eq!(a.bytes.as_ref(), b.bytes.as_ref());
        assert_eq!(a.counter_used, 0);
    }

    /// Spec vector: index 0 from the JSON fixtures' root, when run through
    /// secp256k1 to obtain the x-only public key, must match the pinned
    /// `internal_key` from the JSON vectors. (The fixture's `internal_key` is
    /// the x-only PUBLIC key for `p_internal[i]`, not the raw scalar; the
    /// scalar is private and only published as `nsec`.)
    #[test]
    fn matches_spec_vector_index_0() {
        use secp256k1::{Keypair, Secp256k1};

        // root_secret from harness/vectors/nip41-test-vectors.json
        let root = hex!("890b93ded88a65e0707db157704ab04f84bbeec0fe6075c27ba98dcb9e5a2a13");
        let derived = derive_scalar_at_counter(&root, 0, 0).unwrap();
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, &derived.secret_key);
        let (xonly, _parity) = kp.x_only_public_key();
        assert_eq!(
            hex::encode(xonly.serialize()),
            "589ab097fb0dc109d597ab8714b8363b6c96238e735b4f749fad4377aa8871cf"
        );
        assert_eq!(derived.counter_used, 0);
    }
}
