//! `IdentityChain`: the public type. Holds public hex strings and zeroizing
//! secret scalars.

use crate::chain::derivation::{derive_scalar_at_counter, DerivedScalar};
use crate::consts::NIP41_TWEAK_TAG;
use crate::crypto::tagged_hash;
use crate::error::Error;
use secp256k1::{Keypair, Parity, Scalar, Secp256k1};
use zeroize::Zeroizing;

/// A NIP-41 identity chain: `length` generations derived from one root
/// secret, each generation `i < length-1` cryptographically committing to
/// generation `i+1`. Built backwards (NIP-41 "Committed identities") because
/// each commitment needs the next generation's npub.
///
/// Secret material (`nsec[i]`, `p_internal[i]`) is held in `Zeroizing`
/// buffers; dropping the chain zeroes them automatically.
///
/// Equality is reference-by-fields; deriving the same chain twice produces
/// equal-looking structs but they are independent allocations.
pub struct IdentityChain {
    pub(crate) npub_hex: Vec<String>,
    pub(crate) internal_xonly_hex: Vec<String>,
    pub(crate) tweak_hex: Vec<Option<String>>,
    pub(crate) nsec_bytes: Vec<Zeroizing<[u8; 32]>>,
    // Pre-tweak internal scalar per generation. The chain doesn't read this
    // back after derive() returns; it is held only so the value is owned in
    // a Zeroizing buffer and zeroed on drop alongside `nsec_bytes`. KMP
    // keeps the same field for the same reason.
    #[allow(dead_code)]
    pub(crate) p_internal_bytes: Vec<Zeroizing<[u8; 32]>>,
}

impl IdentityChain {
    /// Number of generations in this chain (the `length` argument originally
    /// passed to [`Self::derive`]). Spec-pinned to
    /// [`crate::consts::NIP41_CHAIN_LENGTH`] on the network; tests may use
    /// shorter chains.
    pub fn length(&self) -> usize {
        self.npub_hex.len()
    }

    /// Lowercase 64-char x-only public key (`npub`) for generation `i`.
    ///
    /// # Panics
    /// Panics if `i >= length()`.
    pub fn npub(&self, i: usize) -> &str {
        &self.npub_hex[i]
    }

    /// Lowercase 64-char x-only internal pubkey for generation `i` - the
    /// untweaked key derived directly from the root secret. Used as the
    /// middle field of a `successor` tag.
    ///
    /// # Panics
    /// Panics if `i >= length()`.
    pub fn internal_xonly(&self, i: usize) -> &str {
        &self.internal_xonly_hex[i]
    }

    /// BIP-341 x-only tweak `t` for generation `i`, as lowercase 64-char
    /// hex. Returns `None` for the terminal generation (no tweak).
    ///
    /// # Panics
    /// Panics if `i >= length()`.
    pub fn tweak(&self, i: usize) -> Option<&str> {
        self.tweak_hex[i].as_deref()
    }

    /// Returns a defensive zeroizing copy of `nsec[i]`. Caller owns the
    /// returned buffer; the chain still holds its own copy.
    ///
    /// This is the consumer-facing boundary for per-generation secret bytes.
    /// Internal callsites that just need to feed `nsec[i]` to a signer use a
    /// crate-private borrowing accessor to avoid the per-call defensive
    /// allocation.
    pub fn export_nsec(&self, generation: usize) -> Result<Zeroizing<[u8; 32]>, Error> {
        if generation >= self.length() {
            return Err(Error::GenerationOutOfRange {
                generation,
                length: self.length(),
            });
        }
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(self.nsec_bytes[generation].as_ref());
        Ok(out)
    }

    /// Borrowing accessor for `nsec[i]` used by internal callsites (notably
    /// `sign_with` and the kind:1041/1042 builders) so that signing the
    /// chain's events does not allocate a defensive copy per signature.
    ///
    /// The returned reference is bound to the chain's lifetime; when the
    /// chain is dropped, the `Zeroizing` buffer this borrows from is zeroed.
    pub(crate) fn nsec_bytes(&self, generation: usize) -> Result<&[u8; 32], Error> {
        if generation >= self.length() {
            return Err(Error::GenerationOutOfRange {
                generation,
                length: self.length(),
            });
        }
        // `&*Zeroizing<[u8; 32]>` is `&[u8; 32]`; `.as_ref()` would coerce to
        // `&[u8]` via the `AsRef<[u8]>` impl on arrays.
        Ok(&self.nsec_bytes[generation])
    }

    /// Sign `event` with the BIP-340 key for `generation`. The chain's key
    /// stays inside the chain; no caller-side defensive copy is materialized.
    ///
    /// `aux_rand_32 = [0; 32]` produces deterministic signatures - the mode
    /// the test vectors pin. In production, pass 32 random bytes for the
    /// standard BIP-340 nonce rerandomization guarantees.
    ///
    /// In debug builds, this asserts that `event.pubkey` matches the chain's
    /// `npub(generation)`. A mismatch produces a signed event whose `id`
    /// (computed from the canonical form including `pubkey`) won't verify
    /// against the signing key - a sharp-edge bug that's silent until the
    /// envelope verifier rejects it. Release builds skip the check.
    pub fn sign_with(
        &self,
        generation: usize,
        event: &crate::event::UnsignedNostrEvent,
        aux_rand_32: &[u8; 32],
    ) -> Result<crate::event::SignedNostrEvent, Error> {
        let nsec = self.nsec_bytes(generation)?;
        debug_assert_eq!(
            event.pubkey,
            self.npub(generation),
            "sign_with: event.pubkey does not match chain.npub(generation); \
             the produced signature will not verify",
        );
        event.sign(nsec, aux_rand_32)
    }
}

impl IdentityChain {
    /// Spec "Identity chain" + "Committed identities": derive the full chain
    /// backwards from the root secret.
    ///
    /// Terminal generation has no tweak; its `nsec` is parity-corrected so
    /// that `nsec*G` has even-y (BIP-340 x-only). Earlier generations are
    /// built via BIP-341 x-only tweak with `t = tagged_hash("nip41/succession",
    /// internal_xonly[i] || npub[i+1])`, using libsecp256k1's
    /// `Keypair::add_xonly_tweak` which handles parity internally.
    ///
    /// `root_secret` is read once into HKDF and not retained; the caller may
    /// zero it after this call returns. Per-generation secrets live in the
    /// returned chain and are zeroed automatically on drop.
    pub fn derive(root_secret: &[u8; 32], length: usize) -> Result<Self, Error> {
        if length < 1 {
            return Err(Error::ChainLength {
                got: length,
                min: 1,
            });
        }

        let secp = Secp256k1::new();

        let mut npub_hex: Vec<String> = vec![String::new(); length];
        let mut internal_xonly_hex: Vec<String> = vec![String::new(); length];
        let mut tweak_hex: Vec<Option<String>> = vec![None; length];
        let mut nsec_bytes: Vec<Zeroizing<[u8; 32]>> =
            (0..length).map(|_| Zeroizing::new([0u8; 32])).collect();
        let mut p_internal_bytes: Vec<Zeroizing<[u8; 32]>> =
            (0..length).map(|_| Zeroizing::new([0u8; 32])).collect();
        let mut npub_bytes: Vec<[u8; 32]> = vec![[0u8; 32]; length];

        // ── Terminal generation: no tweak. nsec must be parity-corrected so
        //    nsec*G has even-y x-coordinate equal to npub.
        let last = length - 1;
        let DerivedScalar {
            secret_key,
            bytes: p_last_bytes,
            ..
        } = derive_scalar_at_counter(root_secret, last as u32, 0)?;
        let kp_last = Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_last, parity_last) = kp_last.x_only_public_key();
        let xonly_last_bytes = xonly_last.serialize();
        let nsec_last: [u8; 32] = match parity_last {
            Parity::Even => *p_last_bytes,
            Parity::Odd => secret_key.negate().secret_bytes(),
        };
        p_internal_bytes[last].copy_from_slice(p_last_bytes.as_ref());
        nsec_bytes[last].copy_from_slice(&nsec_last);
        internal_xonly_hex[last] = hex::encode(xonly_last_bytes);
        npub_hex[last] = hex::encode(xonly_last_bytes);
        npub_bytes[last] = xonly_last_bytes;

        // ── Earlier generations: backwards build, with shared-counter
        //    rederivation on either p_internal-rejection (inside
        //    derive_scalar_at_counter) or t >= n.
        for i in (0..last).rev() {
            let mut counter_start: u8 = 0;
            loop {
                let DerivedScalar {
                    secret_key: sk,
                    bytes: p_bytes,
                    counter_used,
                } = derive_scalar_at_counter(root_secret, i as u32, counter_start)?;

                let kp = Keypair::from_secret_key(&secp, &sk);
                let (xonly_internal, _parity_internal) = kp.x_only_public_key();
                let xonly_internal_bytes = xonly_internal.serialize();

                // t = tagged_hash("nip41/succession", xonly || npub[i+1])
                let mut msg = [0u8; 64];
                msg[..32].copy_from_slice(&xonly_internal_bytes);
                msg[32..].copy_from_slice(&npub_bytes[i + 1]);
                let t = tagged_hash(NIP41_TWEAK_TAG, &msg);

                // KMP's secKeyVerify rejects both 0 and >= n. `Scalar::from_be_bytes`
                // only rejects >= n, so we screen 0 explicitly to keep cross-language
                // byte parity. On either rejection, advance counter past the offender.
                let tweak_valid = if t == [0u8; 32] {
                    None
                } else {
                    Scalar::from_be_bytes(t).ok()
                };
                let tweak = match tweak_valid {
                    Some(s) => s,
                    None => {
                        if counter_used == u8::MAX {
                            return Err(Error::CounterExhausted { generation: i });
                        }
                        counter_start = counter_used + 1;
                        continue;
                    }
                };

                // add_xonly_tweak: BIP-341 x-only tweak on the keypair,
                // returning the tweaked keypair whose pubkey is the tweaked
                // x-only and whose secret_key is the parity-corrected
                // signing scalar.
                let tweaked = kp.add_xonly_tweak(&secp, &tweak)?;
                let (xonly_out, _parity_out) = tweaked.x_only_public_key();
                let xonly_out_bytes = xonly_out.serialize();
                let nsec_i = tweaked.secret_key().secret_bytes();

                p_internal_bytes[i].copy_from_slice(p_bytes.as_ref());
                nsec_bytes[i].copy_from_slice(&nsec_i);
                internal_xonly_hex[i] = hex::encode(xonly_internal_bytes);
                tweak_hex[i] = Some(hex::encode(t));
                npub_hex[i] = hex::encode(xonly_out_bytes);
                npub_bytes[i] = xonly_out_bytes;
                break;
            }
        }

        Ok(IdentityChain {
            npub_hex,
            internal_xonly_hex,
            tweak_hex,
            nsec_bytes,
            p_internal_bytes,
        })
    }
}

impl std::fmt::Debug for IdentityChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let head = self
            .npub_hex
            .first()
            .map(|s| &s[..16.min(s.len())])
            .unwrap_or("-");
        write!(f, "IdentityChain(length={}, npub[0]={head}…)", self.length())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn fixture() -> IdentityChain {
        IdentityChain {
            npub_hex: vec!["a".repeat(64), "b".repeat(64)],
            internal_xonly_hex: vec!["c".repeat(64), "d".repeat(64)],
            tweak_hex: vec![Some("e".repeat(64)), None],
            nsec_bytes: vec![Zeroizing::new([1u8; 32]), Zeroizing::new([2u8; 32])],
            p_internal_bytes: vec![Zeroizing::new([3u8; 32]), Zeroizing::new([4u8; 32])],
        }
    }

    #[test]
    fn accessors() {
        let c = fixture();
        assert_eq!(c.length(), 2);
        assert_eq!(c.npub(0), &"a".repeat(64));
        assert_eq!(c.internal_xonly(1), &"d".repeat(64));
        assert_eq!(c.tweak(0), Some("e".repeat(64).as_str()));
        assert_eq!(c.tweak(1), None);
    }

    #[test]
    fn export_nsec_returns_defensive_copy() {
        let c = fixture();
        let nsec = c.export_nsec(0).unwrap();
        assert_eq!(nsec.as_ref(), &[1u8; 32]);
        // Independent buffer: zeroing this one does not affect the chain.
        drop(nsec);
        assert_eq!(c.nsec_bytes[0].as_ref(), &[1u8; 32]);
    }

    #[test]
    fn export_nsec_out_of_range() {
        let c = fixture();
        let err = c.export_nsec(99).unwrap_err();
        assert!(matches!(
            err,
            Error::GenerationOutOfRange {
                generation: 99,
                length: 2
            }
        ));
    }

    #[test]
    fn debug_does_not_show_secrets() {
        let c = fixture();
        let s = format!("{c:?}");
        assert!(s.contains("IdentityChain(length=2"));
        // No private bytes in the Debug output.
        assert!(!s.contains("01010101"));
    }

    #[test]
    fn sign_with_uses_per_generation_key() {
        use crate::event::UnsignedNostrEvent;

        // Match the JSON fixture's root so the produced npub is the same one
        // exercised throughout the test suite.
        let root = hex_literal::hex!(
            "890b93ded88a65e0707db157704ab04f84bbeec0fe6075c27ba98dcb9e5a2a13"
        );
        let chain = IdentityChain::derive(&root, 4).unwrap();
        let event = UnsignedNostrEvent {
            pubkey: chain.npub(0).into(),
            created_at: 1716100000,
            kind: 1041,
            tags: vec![],
            content: "".into(),
        };

        // Recomputing the id independently and comparing to `signed.id`
        // proves that `sign_with` did not mutate the event payload before
        // hashing - which would silently break verification downstream.
        let expected_id = hex::encode(event.event_id());
        let signed = chain.sign_with(0, &event, &[0u8; 32]).unwrap();
        assert_eq!(signed.id, expected_id);
        assert_eq!(signed.pubkey, chain.npub(0));
        // Schnorr sig is 64 bytes / 128 hex chars.
        assert_eq!(signed.sig.len(), 128);
    }

    #[test]
    fn sign_with_out_of_range_is_rejected() {
        use crate::event::UnsignedNostrEvent;
        let root = [0x42u8; 32];
        let chain = IdentityChain::derive(&root, 2).unwrap();
        let event = UnsignedNostrEvent {
            pubkey: chain.npub(0).into(),
            created_at: 0,
            kind: 1,
            tags: vec![],
            content: "".into(),
        };
        let err = chain.sign_with(5, &event, &[0u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            Error::GenerationOutOfRange {
                generation: 5,
                length: 2
            }
        ));
    }

    #[test]
    fn nsec_bytes_borrows_without_allocation() {
        // Confirms the borrowing accessor returns a reference that aliases
        // the chain's own buffer (same address), proving no defensive copy.
        let root = [0x42u8; 32];
        let chain = IdentityChain::derive(&root, 2).unwrap();
        let borrowed: &[u8; 32] = chain.nsec_bytes(0).unwrap();
        let owned_ref: &[u8; 32] = &chain.nsec_bytes[0];
        assert!(std::ptr::eq(borrowed, owned_ref));
    }
}
