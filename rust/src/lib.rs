//! NIP-41 Nostr Identity Chain - reference implementation in Rust.
//!
//! [NIP-41] specifies a Nostr key-rotation scheme where a single root secret
//! derives a chain of `length` generations, each generation `i < length-1`
//! cryptographically committing to generation `i + 1` via a BIP-340 x-only
//! tweak. A `kind:1041` event opens one generation's commitment in favor of
//! the next; a `kind:1042` event from a legacy (uncommitted) key bridges
//! that identity into a fresh committed chain.
//!
//! This crate mirrors the locked Kotlin Multiplatform reference under
//! `kmp/nip41/` and the Python harness under `harness/`, validated
//! byte-for-byte against the shared vectors at
//! `harness/vectors/nip41-test-vectors.json` and the bridge-flow vectors
//! at `test-vectors/nip-41-test-vectors.md`.
//!
//! [NIP-41]: https://github.com/nostr-protocol/nips
//!
//! # Quick start
//!
//! ```no_run
//! use nip41::{IdentityChain, Kind1041Verification, verify_kind_1041_event};
//!
//! // 32 bytes from CSPRNG or a passkey PRF in production.
//! let root_secret = [0u8; 32];
//! let chain = IdentityChain::derive(&root_secret, 1024).unwrap();
//!
//! // Build and verify a chain-birth event.
//! let birth = chain
//!     .build_chain_birth_event(1716100000, "", &[0u8; 32])
//!     .unwrap();
//! match verify_kind_1041_event(&birth) {
//!     Kind1041Verification::ChainBirth { subject, .. } => {
//!         assert_eq!(subject, chain.npub(0));
//!     }
//!     other => panic!("expected ChainBirth, got {other:?}"),
//! }
//! ```
//!
//! See `examples/walkthrough.rs` for a top-to-bottom tour of the public
//! surface, and `examples/full_flow.rs` for a richer narrated demo
//! including the bridge-migration flow.
//!
//! # Public surface
//!
//! - [`IdentityChain`] holds derived `npub` / `nsec` material and exposes
//!   the event builders ([`IdentityChain::build_chain_birth_event`],
//!   [`IdentityChain::build_rotation_event`],
//!   [`IdentityChain::build_bridge_rotation_event`]).
//! - [`build_bridge_commitment`] signs the legacy-side `kind:1042` event.
//! - [`verify_kind_1041_event`] / [`verify_kind_1042_event`] are the
//!   intrinsic event-validity predicates; their outcomes are the
//!   [`Kind1041Verification`] / [`Kind1042Verification`] enums.
//! - [`is_committed()`], [`resolve_step`], [`find_bridge_for`],
//!   [`verify_bridge`], and [`bridge_commits_conflict`] are corpus-level
//!   predicates operating on a pre-fetched event set (no network I/O).
//! - [`encode_npub`] / [`encode_nroot`] / [`encode_nsec`] and the
//!   matching `decode_*` functions cover NIP-19 portability.
//! - [`verify_chain_proof`] is the pure cryptographic predicate behind
//!   every `successor` tag.
//!
//! # Modules
//!
//! - [`chain`] - `IdentityChain`, derivation, [`verify_chain_proof`].
//! - [`event`] - event types, NIP-01 canonical id, BIP-340 signing,
//!   kind:1041/1042 builders.
//! - [`verify`] - kind:1041/1042 verification, bridge gates, walkers.
//! - [`nip19`] - bech32 `nroot` / `npub` / `nsec` encoding.
//! - [`consts`] - spec-pinned constants ([`NIP41_TWEAK_TAG`],
//!   [`NIP41_KIND_1041`], [`NIP41_KIND_1042`], [`NIP41_CHAIN_LENGTH`],
//!   tag names).
//! - [`error`] - [`Error`] and [`Nip19Error`].
//!
//! [`NIP41_TWEAK_TAG`]: crate::consts::NIP41_TWEAK_TAG
//! [`NIP41_KIND_1041`]: crate::consts::NIP41_KIND_1041
//! [`NIP41_KIND_1042`]: crate::consts::NIP41_KIND_1042
//! [`NIP41_CHAIN_LENGTH`]: crate::consts::NIP41_CHAIN_LENGTH

#![deny(missing_docs)]

pub mod chain;
pub mod consts;
pub(crate) mod crypto;
pub mod error;
pub mod event;
pub mod nip19;
pub mod verify;

pub use chain::{IdentityChain, verify_chain_proof};
pub use error::{Error, Nip19Error};
pub use event::{SignedNostrEvent, UnsignedNostrEvent, build_bridge_commitment};
pub use nip19::{decode_npub, decode_nroot, decode_nsec, encode_npub, encode_nroot, encode_nsec};
pub use verify::{
    BridgeVerification, Kind1041Verification, Kind1042Verification, bridge_commits_conflict,
    find_bridge_for, is_committed, resolve_step, verify_bridge, verify_kind_1041_event,
    verify_kind_1042_event,
};
