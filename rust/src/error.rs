//! Error types for NIP-41 operations.
//!
//! Verification predicates do NOT return `Result`; a failed event is an
//! expected outcome carried in the verification enum's `Invalid(reason)`
//! variant. `Error` and `Nip19Error` cover input violations, crypto
//! failures, and encoding failures.

use thiserror::Error;

/// Errors returned by the producer-side of the NIP-41 API: chain derivation,
/// event building, and signing.
#[derive(Debug, Error)]
pub enum Error {
    /// Chain length argument was below the required minimum.
    #[error("chain length must be >= {min}, got {got}")]
    ChainLength {
        /// Length the caller requested.
        got: usize,
        /// Minimum length the operation requires.
        min: usize,
    },

    /// Generation index was outside `0..length`.
    #[error("generation must be in 0..{length}, got {generation}")]
    GenerationOutOfRange {
        /// Generation index the caller requested.
        generation: usize,
        /// Chain length at the time of the call.
        length: usize,
    },

    /// Rotation `to_generation` argument was outside `1..=length-2`.
    #[error("toGeneration must be in 1..={max} (must be non-terminal), got {got}")]
    RotationTargetOutOfRange {
        /// Value the caller passed for `to_generation`.
        got: usize,
        /// Upper bound (`length - 2`) for the current chain.
        max: usize,
    },

    /// A hex-string argument was not 64 lowercase hex chars / 32 bytes.
    #[error("{field} must be 64 lowercase hex chars (32-byte payload)")]
    InvalidHex {
        /// Static name of the offending parameter (for diagnostics).
        field: &'static str,
    },

    /// `nsec` argument was not 32 bytes.
    #[error("nsec must be 32 bytes, got {got}")]
    InvalidNsecLength {
        /// Length the caller passed.
        got: usize,
    },

    /// `aux_rand_32` argument was not 32 bytes.
    #[error("aux_rand_32 must be 32 bytes")]
    InvalidAuxRandLength,

    /// Backward chain-build counter exhausted without finding a valid
    /// tweak; theoretically possible but cryptographically infeasible.
    #[error("counter rederivation exhausted for generation {generation} (infeasible in practice)")]
    CounterExhausted {
        /// Generation at which derivation stalled.
        generation: usize,
    },

    /// Wraps an underlying libsecp256k1 error (invalid key, bad signature, …).
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),

    /// Wraps a NIP-19 encode/decode error surfaced through this crate.
    #[error(transparent)]
    Nip19(#[from] Nip19Error),
}

/// Errors returned by the [`crate::nip19`] encode/decode functions.
#[derive(Debug, Error)]
pub enum Nip19Error {
    /// Bech32 decode failed (bad checksum, illegal character, …); the
    /// wrapped string is the underlying library's diagnostic.
    #[error("bech32 decode failed: {0}")]
    Bech32(String),

    /// The decoded HRP did not match the expected NIP-19 flavor.
    #[error("expected HRP '{expected}', got '{got}'")]
    HrpMismatch {
        /// Expected HRP (`"nroot"`, `"npub"`, or `"nsec"`).
        expected: &'static str,
        /// HRP actually present in the input.
        got: String,
    },

    /// Decoded payload was not 32 bytes.
    #[error("payload must be 32 bytes, got {got}")]
    PayloadLength {
        /// Length of the decoded payload.
        got: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_strings_match_spec() {
        let e = Error::ChainLength { got: 0, min: 1 };
        assert_eq!(format!("{e}"), "chain length must be >= 1, got 0");

        let e = Error::GenerationOutOfRange { generation: 5, length: 4 };
        assert_eq!(format!("{e}"), "generation must be in 0..4, got 5");

        let e = Error::InvalidHex { field: "subject" };
        assert_eq!(
            format!("{e}"),
            "subject must be 64 lowercase hex chars (32-byte payload)"
        );

        let e = Nip19Error::HrpMismatch { expected: "nroot", got: "npub".into() };
        assert_eq!(format!("{e}"), "expected HRP 'nroot', got 'npub'");
    }
}
