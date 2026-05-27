//! Identity-chain construction and verification.

pub(crate) mod derivation;
mod identity;
pub(crate) mod proof;

pub use identity::IdentityChain;
pub use proof::verify_chain_proof;
