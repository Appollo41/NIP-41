//! Event-validity rules and predicates for NIP-41 (spec "Client verification").
//!
//! The intrinsic verifiers ([`verify_kind_1041_event`],
//! [`verify_kind_1042_event`]) consume a single signed event and return an
//! outcome enum carrying the structured fields a caller needs to act on it.
//! The corpus-level predicates ([`is_committed()`], [`verify_bridge`],
//! [`resolve_step`], [`find_bridge_for`]) consume a pre-fetched event set;
//! network I/O lives in the caller's relay layer.
//!
//! All hex fields in the returned variants are lowercase 64-char x-only
//! (32-byte) values, matching the wire format.

pub mod bridge;
pub mod is_committed;
pub mod kind_1041;
pub mod kind_1042;
pub mod resolve;

pub use bridge::{bridge_commits_conflict, verify_bridge, BridgeVerification};
pub use is_committed::is_committed;
pub use kind_1041::{verify_kind_1041_event, Kind1041Verification};
pub use kind_1042::{verify_kind_1042_event, Kind1042Verification};
pub use resolve::{find_bridge_for, resolve_step};
