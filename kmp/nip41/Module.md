# Module nip41

A reference implementation of **[NIP-41](https://github.com/nostr-protocol/nips): Nostr Identity Chain**, for Kotlin Multiplatform.

NIP-41 lets a Nostr identity move from one key to another in a way that any client can verify **cryptographically against the key itself**, without trusting timestamps, web-of-trust, external chains, or any specific relay. The rotation event is fetched like any other Nostr event; once a client has it, verification is purely local.

This module provides the pure cryptographic primitives a client needs:
- derive an identity chain from a 32-byte root secret,
- build the kind:1041 and kind:1042 events the spec defines,
- verify those events fail-closed,
- walk the chain from a starting `npub` to its current active key.

Targets: JVM, Android, iOS (arm64 / x64 / simulator-arm64), macOS arm64, Linux (x64 / arm64). All public API lives in [com.appollo41.nip41].

# Package com.appollo41.nip41

The public API maps to the four phases of a NIP-41-aware client. Reading them in order is a guided tour of the library:

## 1. Derive (or load) an identity chain

A chain is a pure function of `(rootSecret, length)`: no network, no time, no state.

| Entry point                       | What it does                                                                                                   |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| [deriveIdentityChain]             | Derive a [IdentityChain] of `length` generations from a 32-byte secret. Roughly 50 to 200 ms for `NIP41_CHAIN_LENGTH` = 1024 generations. |
| [IdentityChain]                   | The resulting structure. Public material (`npub`, `internalXonly`, `tweak`) is readable; signing keys are hidden behind [IdentityChain.signWith] and [IdentityChain.exportNsec]. Implements [AutoCloseable] for best-effort zeroization. |
| [nip41InternalSeckey]             | Derive a single per-generation pre-tweak scalar without building a full chain. Useful for tests and tooling. |

## 2. Build events

Signing helpers for the two NIP-41-defined event kinds:

| Entry point                         | Event kind | Purpose                                                                                  |
| ----------------------------------- | ---------- | ---------------------------------------------------------------------------------------- |
| [buildChainBirthEvent]              | 1041       | Declare `npub[0]` as a committed-chain head.                                             |
| [buildRotationEvent]                | 1041       | Announce a rotation from one generation to the next.                                     |
| [buildBridgeCommitment]             | 1042       | Signed by a **legacy** key; commits the legacy identity to migrate into a fresh chain.   |
| [buildBridgeRotationEvent]          | 1041       | Signed by the fresh chain's `npub[0]`; consumes a kind:1042 to absorb the legacy identity. |

[UnsignedNostrEvent.sign] lets you sign with an arbitrary nsec; that's the path the legacy-key bridge commitment uses. For chain-derived keys, prefer [IdentityChain.signWith], which keeps the signing key inside the chain.

## 3. Verify events

Every verifier here is a **pure predicate**. The caller supplies pre-fetched events; the network lives outside this module. All verifiers are fail-closed: any deviation from the spec produces an `Invalid` outcome (or `false`/`null`) rather than a partial result.



| Entry point                          | Outcome type                       | What it checks                                                                                                   |
| ------------------------------------ | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| [verifyKind1041Event]                | [Kind1041Verification]             | Intrinsic validity of a kind:1041 event: signature, canonical id, and chain-proof on its `successor` tag. Produces a [Kind1041Verification.ChainBirth], [Kind1041Verification.Rotation], or [Kind1041Verification.Bridge]. |
| [verifyKind1042Event]                | [Kind1042Verification]             | Intrinsic validity of a kind:1042 bridge commitment.                                                             |
| [verifyBridge]                       | [BridgeVerification]               | The three external gates from spec _"The bridge for existing keys"_: legacy key must not be committed, the referenced kind:1042 must exist and match, and no conflicting kind:1042s exist. |
| [verifyChainProof]                   | `Boolean`                          | The pure cryptographic predicate behind every `successor` tag: does applying the succession tweak reproduce the subject? Reused by all the higher-level verifiers. |

## 4. Walk the chain

Once a verifier has classified events, these are the navigation predicates a client uses to resolve "what is this identity's current key?":

| Entry point                | What it returns                                                                                                              |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [resolveStep]              | Given a current pubkey and a set of kind:1041 events, the next pubkey via a **rotation** (or `null` if no rotation applies). Bridges are excluded; they require external context. Use [findBridgeFor] instead. |
| [findBridgeFor]            | The intrinsic [Kind1041Verification.Bridge] outcome for `currentPubkey`, ready for [verifyBridge].                            |
| [isCommitted]              | `isCommitted(K, events)`: true iff at least one valid kind:1041 self-commits to `K`. Gates whether `K` can be bridged.        |
| [bridgeCommitsConflict]    | True iff a single legacy key has signed more than one kind:1042 with different `commits` targets (a fail-closed contest).    |

The multi-hop walk is the caller's loop; see pseudocode in [resolveStep]'s KDoc.

## Spec constants

| Symbol                  | Value                                | Purpose                                                                              |
| ----------------------- | ------------------------------------ | ------------------------------------------------------------------------------------ |
| [NIP41_CHAIN_LENGTH]    | `1024`                               | Pinned chain length for on-the-network chains.                                       |
| [NIP41_TWEAK_TAG]       | `"nip41/succession"`                 | BIP-340 tagged-hash domain separator for chain commitments.                          |
| [NIP41_KIND_1041]       | `1041`                               | Event kind for chain-birth, rotation, and bridge-rotation events.                    |
| [NIP41_KIND_1042]       | `1042`                               | Event kind for legacy-key bridge commitments.                                        |
| [Nip41Tags]             | _(object)_                           | The closed set of NIP-41 tag names: `SUCCESSOR`, `PREDECESSOR`, `BRIDGE`, `P`, `COMMITS`. |

## NIP-19 encoding

[Nip19] provides bech32 encoders and decoders for `npub1…`, `nsec1…`, and `nroot1…` strings (the spec-mandated portable form of the root secret).
