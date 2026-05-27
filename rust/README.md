# nip41 - Rust reference implementation

A native Rust reference port of [NIP-41 (Nostr Identity Chain)][nip41]. A
single 32-byte root secret derives a chain of `length` generations; each
generation `i < length-1` cryptographically commits to generation `i+1` via
a BIP-340 x-only tweak. A `kind:1041` event opens one generation's
commitment in favor of the next; a `kind:1042` event from a legacy
(uncommitted) key bridges that identity into a fresh committed chain.

Cross-validated byte-for-byte against the locked Kotlin Multiplatform
reference at [`kmp/nip41/`](../kmp/nip41/) and the Python harness at
[`harness/`](../harness/) via the shared test vectors.

[nip41]: https://github.com/nostr-protocol/nips

## Status

Experimental. NIP-41 itself is still under active development; the spec,
the harness, and all reference ports move together. The Rust port matches
the KMP reference and the Python harness today, but neither is published
to a registry yet. Treat the API as 0.x - breaking changes track the
spec.

## Install

This crate is not on crates.io yet. Use a path or git dependency.

```toml
# Path dep (e.g. from a workspace alongside this repo):
[dependencies]
nip41 = { path = "../nip41/rust" }

# Or git dep:
[dependencies]
nip41 = { git = "https://github.com/appollo41/nip41", rev = "<commit>" }
```

Requires Rust 1.85+ (Edition 2024).

## Quick start

```rust
use nip41::{
    BridgeVerification, IdentityChain, Kind1041Verification,
    build_bridge_commitment, find_bridge_for, is_committed, resolve_step,
    verify_bridge, verify_kind_1041_event,
};

// 1. Derive an identity chain from a 32-byte root secret.
//    In production: 32 bytes from a CSPRNG or a passkey PRF.
let root_secret = [0u8; 32];
let chain = IdentityChain::derive(&root_secret, 1024).unwrap();

// 2. Build NIP-41 events. `aux_rand_32 = [0; 32]` makes signing
//    deterministic; pass 32 random bytes in production.
let birth = chain.build_chain_birth_event(1716100000, "", &[0u8; 32]).unwrap();
let rotation = chain.build_rotation_event(1, 1716200000, "", &[0u8; 32]).unwrap();

// 3. Verify and walk.
assert!(matches!(verify_kind_1041_event(&birth), Kind1041Verification::ChainBirth { .. }));
let next = resolve_step(chain.npub(0), std::slice::from_ref(&rotation));
assert_eq!(next.as_deref(), Some(chain.npub(1)));

// 4. Bridge a legacy key into a fresh committed chain.
let legacy_nsec = [0x33u8; 32];
let fresh = IdentityChain::derive(&[0x77u8; 32], 1024).unwrap();
let k1042 = build_bridge_commitment(&legacy_nsec, fresh.npub(0), 1716100100, "", &[0u8; 32]).unwrap();
let bridge = fresh
    .build_bridge_rotation_event(&k1042.pubkey, &k1042.id, 1716100200, "", &[0u8; 32])
    .unwrap();
let intrinsic = find_bridge_for(&k1042.pubkey, std::slice::from_ref(&bridge)).unwrap();
let verdict = verify_bridge(
    &intrinsic,
    is_committed(&k1042.pubkey, &[]),
    Some(&k1042),
    std::slice::from_ref(&k1042),
);
assert_eq!(verdict, BridgeVerification::Valid);
```

Two runnable examples cover the surface end-to-end:

```
cargo run --example walkthrough   # assert-driven tour of the public API
cargo run --example full_flow     # narrated demo with prints
```

## API surface

Re-exported from the crate root:

- **`IdentityChain::derive(root_secret, length) -> Result<IdentityChain, Error>`** - backward chain build.
- **`IdentityChain::npub(i) / .internal_xonly(i) / .tweak(i) / .length()`** - per-generation accessors.
- **`IdentityChain::export_nsec(i)`** - defensive zeroizing copy of `nsec[i]`.
- **`IdentityChain::sign_with(generation, event, aux_rand_32)`** - sign an unsigned event with `nsec[generation]`.
- **`IdentityChain::build_chain_birth_event(...)`** - kind:1041 declaring `npub[0]` a committed-chain head.
- **`IdentityChain::build_rotation_event(...)`** - kind:1041 rotating `npub[to-1] -> npub[to]`.
- **`IdentityChain::build_bridge_rotation_event(...)`** - kind:1041 bridging a legacy key.
- **`build_bridge_commitment(legacy_nsec, fresh_npub_0, ...)`** - kind:1042 signed by the legacy key.
- **`verify_kind_1041_event(&event) -> Kind1041Verification`** - intrinsic event-validity predicate; outcomes: `ChainBirth`, `Rotation`, `Bridge`, `Invalid(reason)`.
- **`verify_kind_1042_event(&event) -> Kind1042Verification`** - outcomes: `Valid { commits }`, `Invalid(reason)`.
- **`is_committed(subject, &events) -> bool`** - corpus predicate.
- **`resolve_step(current_pubkey, &events) -> Option<String>`** - single-step rotation walker.
- **`find_bridge_for(current_pubkey, &events) -> Option<Kind1041Verification>`** - single-step bridge walker.
- **`verify_bridge(&bridge_outcome, is_committed_decision, kind1042_event, &legacypub_kind1042_events) -> BridgeVerification`** - outcomes: `Valid`, `Invalid(reason)`.
- **`bridge_commits_conflict(legacypub, &events) -> bool`** - fail-closed conflict search.
- **`verify_chain_proof(subject, npub_next, internal_xonly) -> bool`** - pure cryptographic predicate behind every `successor` tag.
- **`encode_nroot / encode_npub / encode_nsec`** + matching `decode_*` - NIP-19 bech32 portability.
- **`UnsignedNostrEvent`** - NIP-01 event input; carries `canonical_serialization()`, `event_id()`, and `sign(nsec, aux_rand_32)`. **`SignedNostrEvent`** - the wire-form data type with `id`, `pubkey`, `sig`, etc.
- **`Error` / `Nip19Error`** - producer-side error types.

Spec-pinned constants live in [`nip41::consts`](src/consts.rs):
`NIP41_TWEAK_TAG`, `NIP41_KIND_1041`, `NIP41_KIND_1042`,
`NIP41_CHAIN_LENGTH` (= 1024), plus the closed `tags::*` set.

Verification predicates intentionally do **not** return `Result` - a
failed event is an expected outcome carried in the `Invalid(reason)`
variant of the outcome enum. Fail-closed everywhere: any deviation
returns `Invalid`, never a different valid identity.

## Cross-language byte parity

The Rust port reproduces the Python harness output byte-for-byte under
the same inputs. The cross-port pins are:

- **`harness/vectors/nip41-test-vectors.json`** - derived chain, signed
  events, intermediate values for `length = 4` from a fixed root secret.
  Generated by the Python harness; both KMP and Rust verify against it.
- **`test-vectors/nip-41-test-vectors.md`** - bridge-flow vectors:
  kind:1042 events, bridge-rotation events, and the `verify_bridge`
  outcome for each.

The Kotlin Multiplatform reference under `kmp/nip41/` is the locked
behavioural reference. Where any port disagrees with the JSON or the
markdown, the port is wrong.

## Testing

```
cargo test --all-targets
```

138 tests across `lib` and integration suites
(`tests/derive_matches_vectors.rs`, `tests/event_builders_match_vectors.rs`,
`tests/spec_vectors.rs`, `tests/bridge_vectors.rs`,
`tests/chain_properties.rs`). All four integration suites verify Rust
output against the JSON/markdown pins.

To exercise the benchmark (the spec-pinned length 1024 chain derive):

```
cargo bench --bench chain          # full run (~30s)
cargo bench --bench chain -- --quick   # one sample, fast
```

To browse the rendered docs locally:

```
cargo doc --no-deps --open
```

## License

MIT. See [`../LICENSE`](../LICENSE) and the `license` field in
[`Cargo.toml`](Cargo.toml).
