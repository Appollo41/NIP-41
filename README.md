> **Working repository for NIP-41.** This is where the spec is being drafted
> and reviewed before it is submitted as a pull request to
> [`nostr-protocol/nips`](https://github.com/nostr-protocol/nips). It is
> shared so collaborators and friends can read, comment, and verify against
> the accompanying test vectors and reference implementations.

## Open questions

The draft has following open questions:

- **Rotation event history depth.** Should every `kind:1041` rotation
  event carry only the immediate predecessor's chain proof, or every
  prior step's proof up to the current identity? See
  [open-questions/rotation-event-history-depth.md](open-questions/rotation-event-history-depth.md).
- **Legacy bridge.** The bridge design for existing keys
  (`kind:1042` + OpenTimestamps + bridge `kind:1041`) is still
  unsettled. Whether its current shape is right, whether a different
  format would serve better, or whether it belongs in this NIP.

---
NIP-41
======

Nostr Identity Chain
--------------------

`draft` `optional`

## Abstract

This NIP lets a Nostr identity move from one key to another in a way that any
client can verify **cryptographically against the key itself**, without
trusting timestamps, web-of-trust, external chains, or any specific relay.
The rotation event is fetched from a relay like any other event; once a
client has it, verification is purely local. The one-shot bridge from a
pre-existing legacy key into a committed chain is a separate mechanism that
anchors to Bitcoin via [NIP-03](https://github.com/nostr-protocol/nips/blob/master/03.md)
OpenTimestamps for cryptographic firstness; see
[The bridge for existing keys](#the-bridge-for-existing-keys).

It works by **committing each key to its successor at the moment the key is
created**. The successor's identity is woven into the public key itself using
a Taproot-style tweak (BIP-341). Because the commitment is part of the key,
there is exactly one valid successor, it cannot be forged or overwritten, and
it does not depend on any event surviving on any relay.

Identities created this way are normal Nostr identities: a normal `npub`, a
normal `nsec`, normal BIP-340 signatures. The chain is declared on the
network through a single event kind, `kind:1041`, whose `successor` tags
state the chain's commitment relationships. A `kind:1041` event from a
brand-new chain head declares its own key as a committed generation; a
later `kind:1041` event states both that it succeeds a prior key and
that its own key is a committed generation. Legacy keys, which carry no
`kind:1041`, are treated as ordinary uncommitted identities.

## Motivation

In Nostr, the identity is the public key. If the private key leaks, the
user has no way to move their followers to a safe key, and no way to
tell a legitimate move from an attacker's. A client today has no
mechanism to migrate a user without breaking trust.

A rotation standard for Nostr cannot rely on event ordering or relay
completeness. Relays may drop or expire events, and no relay is required
to have seen every event a user has produced. If a rotation is published
as an ordinary signed event, two competing rotations, one legitimate and
one signed by an attacker with the leaked key, are indistinguishable to
a fresh observer.

## Terminology

- **root secret**: 32 bytes of high-entropy material that every key in the
  chain is derived from. It never signs events and never appears on the
  network.
- **identity chain**: the ordered sequence of public keys derived from one
  root secret, where each key commits to the next. "Chain" as in linked
  list. There are no blocks and no global ledger.
- **generation**: one key in the chain, indexed `0, 1, 2, …`. Generation 0
  is the identity the user starts with.
- **committed identity**: a public key constructed with the tweak in
  [Committed identities](#committed-identities), so that it
  cryptographically commits to its successor.
- **rotation**: moving the active identity from generation `i` to generation
  `i+1`. Declared on the network by a `kind:1041` event (see
  [The `kind:1041` event](#the-kind1041-event)).

## Overview

A **root secret** is the persistent root of an identity. It never signs
events and never appears on the network. From it the client derives a
fixed-length **identity chain** of generations, each one cryptographically
committed to its successor by construction. At any moment, one generation
is the active key. The active key publishes a `kind:1041` event whose
`successor` tag declares its commitment to the next generation. When the
active key needs to move, the new generation publishes another `kind:1041`
event whose `successor` tags declare both that it succeeds the prior key
and that it commits to its own next generation; every follower's client
verifies one equation per `successor` tag and walks the identity forward.

Two constraints follow from the construction and cannot be lifted:

- **A leaked root secret is unrecoverable.** It derives the entire chain,
  so an attacker holding it can rotate as fast as the legitimate owner.
  The only response is to abandon the chain and re-establish followers
  out of band. See [Root-secret compromise](#root-secret-compromise).
- **A pre-existing `npub` cannot become a committed identity.** The
  commitment is baked in at key creation; an `npub` that already exists
  has no commitment to open. It can perform **one** move into a fresh
  committed chain via a separate mechanism. See
  [The bridge for existing keys](#the-bridge-for-existing-keys).

The flow:

1. **Create.** Derive an identity chain from a root secret. Generation 0's
   public key is built so it commits to generation 1 (see
   [Identity chain](#identity-chain) and
   [Committed identities](#committed-identities)). Publish a `kind:1041`
   event from `npub[0]` (see
   [The `kind:1041` event](#the-kind1041-event)) as the first event the
   chain ever signs.
2. **Use.** Generation 0 is a perfectly normal Nostr key.
3. **Rotate.** When needed, generation 1 publishes a `kind:1041` event
   declaring it succeeds generation 0 and committing to generation 2.
4. **Verify.** Any client checks one equation per `successor` tag (see
   [Client verification](#client-verification)) and moves the identity from
   generation 0 to generation 1. No trusted relay, timestamp, or web of
   trust is required.

## Root secret

The root secret is 32 bytes of high-entropy material. The source is the
implementer's choice (e.g., a CSPRNG, a FIDO2 passkey PRF derivation, an
OS keychain entry) so long as the result is 32 uniformly random bytes.
This NIP defines everything *downstream* of the root secret. The portable,
cross-client primitive is the root secret itself; see
[Portability](#portability-root-secret-export) below.

### Portability (root-secret export)

Because some root-secret sources are bound to the device or domain that
produced them (a FIDO2 passkey, an OS keychain entry), any implementation
that holds the root secret **MUST** be able to export and import it
independently of its source. This applies to dedicated signers (NIP-46,
NIP-55), hardware-signer interfaces, and clients that manage keys
directly. Clients that never hold the root secret are not required to
handle root-secret import/export.

The interchange encoding is **bech32** with HRP `nroot`, following
[NIP-19](19.md). The data is the 32 bytes of the root secret:

```
nroot1<bech32 payload of the 32-byte root secret>
```

An importing client derives the chain locally from the decoded root
secret (see [Identity chain](#identity-chain)) and resolves the current
active generation by walking `kind:1041` events from the user's relays
(see [Client verification](#client-verification)).

The root secret is strictly more dangerous than an nsec because it derives
the entire rotation chain. Clients **SHOULD** warn at export accordingly,
and **SHOULD** prompt the user to back up the root secret at onboarding.

### Root-secret lifecycle

Root-secret handling has three distinct phases.

- **Creation.** Any implementation MAY generate a new identity chain,
  which requires deriving a root secret. The generating implementation
  **MUST** prompt the user to back up the root secret and **SHOULD NOT**
  retain it past onboarding. After onboarding, the everyday client
  retains only `nsec[0]` (or a remote-signing session) for ordinary
  signing.
- **Login.** Everyday clients **SHOULD NOT** accept `nroot` as a login
  method. Importing an `nroot` confers permanent control over the entire
  identity chain (every past and future generation) and is appropriate
  only for key-custodian implementations such as dedicated signer apps
  or hardware-signer interfaces. Ordinary login flows **SHOULD** accept
  `nsec` or a remote-signing session (NIP-46 bunker URI, NIP-55) instead.
- **Custody.** Long-term storage of the root secret **SHOULD** live in a
  dedicated signer, a hardware-backed store, or an offline backup, not
  alongside the `nsec` in everyday-client local storage. The security of
  the rotation chain depends on the root secret being harder to steal
  than any single `nsec`; storing both in the same place collapses that
  property.

## Identity chain

An identity chain has a fixed length `N = 1024`. For each generation `i` in
`0 … N-1`, derive an **internal key**:

```
p_internal[i] = int( HKDF-SHA256(IKM  = root_secret,
                                 salt = utf8("nip41-key-rotation-v1"),
                                 info = utf8("internal-key") ‖ u32be(i),
                                 L    = 32) )
P_internal[i] = p_internal[i] · G
```

All 32-byte hash and HKDF outputs in this NIP are interpreted as
big-endian unsigned integers, matching the BIP-340 / BIP-341
convention.

If `p_internal[i]` is `0` or `≥ n`, re-derive with the same inputs
except `info = utf8("internal-key") ‖ u32be(i) ‖ u8(counter)`, where
`counter` is `1` on the first re-derivation and increments by 1 on
each subsequent rejection. (`counter = 0` is reserved to denote the
initial attempt, whose `info` carries no counter byte.) The counter
is local to index `i` and resets when computing the next index. The
same counter mechanism applies if `t[i] ≥ n` per
[Succession tweak](#succession-tweak): the rejection re-derives
`P_internal[i]` by advancing this counter.

The HKDF-to-scalar reduction carries a negligible (~2⁻¹²⁸) bias. On
rejection the retry stays at the same generation index `i` and appends
a counter byte to the HKDF `info`, rather than advancing `i`; this
keeps the chain-position semantics intact (each `i` is the `i`-th
generation, with no gaps).

`N = 1024` covers any realistic identity lifetime. Derivation is one-time
at chain creation; on a modern phone with libsecp256k1 the full backward
build takes roughly 50–200ms and is then never repeated. Signing and
verifying are unchanged thereafter. The chain is a hard cap: if a chain
ever exhausts its generations (extraordinarily unlikely at `N = 1024`),
no further rotation is possible and the user remains on the last
reachable generation indefinitely. There is no escape hatch out of a
committed chain.

The chain is **finite** by necessity:
[Committed identities](#committed-identities) builds each key from its
successor, so the successor must already exist.

## Committed identities

The commitment is a [BIP-341](https://bips.xyz/341) (Taproot) key-path
tweak with a NIP-41 domain-separation tag. Test vectors accompany this NIP.

### Succession tweak

For generation `i`, define the tweak over a BIP-340 *tagged hash*:

```
tagged_hash(tag, m) = SHA256( SHA256(tag) ‖ SHA256(tag) ‖ m )

t[i] = tagged_hash( "nip41/succession", bytes(P_internal[i]) ‖ npub[i+1] )
```

`bytes(P_internal[i])` is the 32-byte BIP-340 x-only encoding of the
internal key; `npub[i+1]` is the 32-byte x-only successor identity. If
`t[i] ≥ n` it is invalid; re-derive `P_internal[i]` (negligibly rare). The
domain tag `"nip41/succession"` ensures a NIP-41 tweak can never collide
with a Bitcoin Taproot tweak or any other tagged-hash use.

### Committed public key

The chain is built **backwards**. The terminal generation commits to nothing:

```
npub[N-1] = bytes(P_internal[N-1])
```

Every other generation `i` (from `N-2` down to `0`) is the Taproot-tweaked
output key, identical to BIP-341 `taproot_tweak_pubkey`:

```
npub[i] = bytes( lift_x(bytes(P_internal[i])) + t[i]·G )
```

`lift_x` is the BIP-340 even-`y` lift. `npub[i]` is the user's published
identity for that generation: an ordinary BIP-340 x-only public key.

### Signing key

The signing private key for generation `i` is the BIP-341
`taproot_tweak_seckey` of the internal key:

```
d        = p_internal[i]              if P_internal[i] has even y
d        = n - p_internal[i]          if P_internal[i] has odd  y
nsec[i]  = ( d + t[i] ) mod n
```

Only the internal-key parity needs explicit handling. Output-key parity is
taken care of by the BIP-340 signer: when the output point has odd `y` the
signer negates the signing scalar, and signatures verify against the
x-only `npub[i]` unchanged.

Implementations **MUST** perform the tweak using `libsecp256k1`'s x-only
tweak functions (`secp256k1_xonly_pubkey_tweak_add` and
`secp256k1_keypair_xonly_tweak_add`). These functions take BIP-340 x-only
keys directly and compute the [committed-public-key tweak](#committed-public-key)
atomically, applying the BIP-340 lift on the internal key and the
output-parity flip without exposing curve arithmetic to the caller.
Parity correctness is inherited from consensus-critical, audited code.

### Properties

`npub[0]` is the user's published identity. `nsec[0]` signs ordinary Nostr
events. Signature shape and key encoding are unchanged from BIP-340; the
construction is visible only through published `kind:1041` events.

- *Binding.* To "open" `npub[i]` to a different successor, an attacker
  needs a second `(P', npub')` whose tweak lands on the same point `Q[i]`.
  Because `P'` appears inside the tweak hash, this is a fixed-point /
  grinding problem on SHA-256 rather than a literal preimage: each
  candidate `P'` satisfies the equation
  `lift_x(P') + tagged_hash("nip41/succession", P' ‖ npub')·G = Q[i]` with
  probability ~2⁻²⁵⁶, which is infeasible. There is exactly one successor
  that `npub[i]` commits to.
- *Bounded disclosure.* A self-successor declaration for `npub[i]` (a
  `successor` tag whose `subject` is `npub[i]`; see
  [The `kind:1041` event](#the-kind1041-event)) discloses `P_internal[i]`
  and `npub[i+1]`. Deeper generations (`npub[i+2]`, `npub[i+3]`, …) stay
  hidden inside their own commitments; recovering them requires inverting
  the HKDF derivation of the root secret. See
  [Conflicting rotation events](#conflicting-rotation-events).

## The `kind:1041` event

NIP-41 declares the identity chain through a single event kind,
`kind:1041`. The event carries one or more `successor` tags. Each
`successor` tag states that one key in the chain commits to another, and
the values of the tags fully determine the role of the event (chain
birth or rotation).

### The `successor` tag

```
["successor", "<subject hex>", "<P_internal hex>", "<npub_next hex>"]
```

The tag asserts that `subject` commits to `npub_next` with opening
`P_internal`. The verifier accepts the tag iff

```
lift_x(P_internal) +
    tagged_hash("nip41/succession", P_internal ‖ npub_next)·G
    == subject
```

(the same equation as `verifyChainProof`; see
[Implementation pseudocode](#implementation-pseudocode)).

The role each tag plays in the event is determined by the relation
between `subject`, `npub_next`, and the event's own `pubkey`:

- **Self-successor.** `subject == event.pubkey` and
  `npub_next != event.pubkey`. The event declares its own key as a
  committed-chain generation whose successor is `npub_next`. This is
  what allows verifiers to refuse a bridge takeover of the key (see
  [The bridge for existing keys](#the-bridge-for-existing-keys)).
- **Predecessor proof.** `subject != event.pubkey` and
  `npub_next == event.pubkey`. The event declares that `subject`
  rotated to `event.pubkey`, with `P_internal` opening `subject`'s
  commitment. This is the rotation step.

Any `successor` tag that does not match one of those two patterns is
invalid and MUST be rejected.

### Event shapes

A `kind:1041` event has one of the following structures, determined by
its `successor` tags. There is no separate event kind, no mode flag, and
no distinct event family for chain birth versus rotation: the
distinction is fully recoverable from tag content.

**Chain birth.** One `successor` tag, self-successor only. Signed by
`nsec[0]`. Published as the first event the chain ever signs; see
[Chain-birth client](#chain-birth-client) for the ordering rule that
keeps other `npub[0]` events from preceding it.

```jsonc
{
  "kind": 1041,
  "pubkey": "<npub[0] hex>",
  "created_at": 1716100000,
  "content": "",
  "tags": [
    ["p", "<npub[0] hex>", "", "successor"],
    ["successor", "<npub[0] hex>", "<P_internal[0] hex>", "<npub[1] hex>"]
  ],
  "sig": "<signed by nsec[0]>"
}
```

**Rotation.** Two `successor` tags: one predecessor proof, one
self-successor. Signed by `nsec[i+1]`, never by the old key (which may
be compromised).

```jsonc
{
  "kind": 1041,
  "pubkey": "<npub[i+1] hex: the NEW key>",
  "created_at": 1716200000,
  "content": "optional human-readable note",
  "tags": [
    ["p", "<npub[i] hex>",   "", "predecessor"],
    ["p", "<npub[i+1] hex>", "", "successor"],
    ["successor", "<npub[i] hex>",   "<P_internal[i] hex>",   "<npub[i+1] hex>"],
    ["successor", "<npub[i+1] hex>", "<P_internal[i+1] hex>", "<npub[i+2] hex>"]
  ],
  "sig": "<signed by nsec[i+1]>"
}
```

Every rotation event MUST carry both a predecessor proof and a
self-successor. The construction therefore caps rotation at `npub[N-2]`:
the last reachable generation. `npub[N-1]` exists in the chain
construction (it is what `npub[N-2]` commits to), but no `kind:1041`
event can ever rotate into it, because a self-successor for `npub[N-1]`
would require a key beyond the chain. At `N = 1024` this cap is far
beyond any realistic identity lifetime.

**Bridge rotation** from a legacy key uses a separate `bridge` tag in
place of the predecessor-proof `successor` tag (a legacy key has no
in-key commitment to open); see
[The bridge for existing keys](#the-bridge-for-existing-keys).

### Signing rule

A `kind:1041` event is, like any Nostr event, signed by the private key
corresponding to `event.pubkey`. Because `event.pubkey` is always the
new active key being installed (`npub[0]` at chain birth, `npub[i+1]`
at rotation), the signing key is always `nsec[0]` or `nsec[i+1]`. The
previous generation `nsec[i]` MUST NOT sign the `kind:1041` event that
rotates away from it: that key may be compromised, and the rotation
must come from the new generation's authority, not the old one's.

A verified rotation is a **hard cutover at the sender**: once the
rotation `kind:1041` has been published, the rotating client signs no
further events with `nsec[i]` (see
[Rotating user's client](#rotating-users-client)). There is no
protocol-defined grace window or dual-post mode.

On the receiving side, once `resolve(npub[i]) ≠ npub[i]`, the
rotation has been observed: the resolved npub is *the* npub for the
user, and follower clients tag, route, and follow the resolved key
per [Follower's client](#followers-client). Any event still signed
by `nsec[i]` after this point is not authored by the current
identity; it is post-rotation residue and is not propagated as the
user's content.

## Client verification

Given any public key `P`, a client resolves the current identity by
walking valid `kind:1041` events forward from `P` until no further
rotation is found.

**Event validity.** A `kind:1041` event is valid iff all of the
following hold:

- The event signature is valid.
- Every `successor` tag passes `verifyChainProof` (see
  [Implementation pseudocode](#implementation-pseudocode)).
- At most one `successor` tag is a *self-successor*
  (`subject == event.pubkey`, `npub_next != event.pubkey`), and at most
  one is a *predecessor proof* (`subject != event.pubkey`,
  `npub_next == event.pubkey`). Any `successor` tag that fits neither
  pattern is invalid.
- At most one `bridge` tag is present; if present, `verifyBridge` (see
  [The bridge for existing keys](#the-bridge-for-existing-keys))
  returns true.
- At least one of {predecessor proof, `bridge`, self-successor} is
  present.
- Exactly one `["p", _, _, "successor"]` tag is present, with value
  equal to `event.pubkey`.
- If the event carries a predecessor (chain proof or bridge), exactly
  one `["p", _, _, "predecessor"]` tag is present whose value matches
  that predecessor. Chain-birth events carry no `predecessor` p-tag.

Other `p` tags (different marker, or no marker) are permitted and
ignored by the resolver.

**`resolve(P)`.** Given `P`, the client fetches
`{"kinds":[1041], "#p":["<P hex>"]}`. Among the valid events
returned, the resolver follows the one whose predecessor proof or
`bridge` tag references `P`, then recurses on that event's `pubkey`
as the new active key. If no such event exists, `P` is the current
identity. The recursion is bounded by `N` to fail closed against any
malformed loop.

**`isCommitted(K)`.** The client fetches
`{"kinds":[1041], "authors":["<K hex>"]}`. `K` is a committed-chain
generation iff at least one valid event returned has a self-successor
whose `subject == K`. This holds for the chain-birth event and for any
rotation event landing on `K`.

**`priorNpubs(P)`.** The client fetches
`{"kinds":[1041], "authors":["<P hex>"]}` and finds the valid event
carrying a `predecessor` p-tag; that tag's value is `P`'s immediate
predecessor. Recursing on that predecessor yields `P`'s ancestor list,
ordered oldest first. The recursion terminates at a chain-birth event
(no `predecessor` p-tag) and at a bridge: the legacy npub reached via
a `bridge` tag is included in the list but not recursed on, since a
legacy key signs no `kind:1041` of its own. The recursion is bounded
by `N`. For a fresh (non-bridged) chain, `priorNpubs(npub[0])` is the
empty list.

Key properties:

- For a **chain rotation**, verification uses only `oldpub` and the
  rotation event itself; it is purely local.
- For a **bridge rotation**, verification additionally fetches the
  referenced `kind:1042` and its `kind:1040` attestation, and runs
  `verifyBridge`; see
  [The bridge for existing keys](#the-bridge-for-existing-keys).
- A forged rotation does not "look suspicious"; it fails the equation and
  is rejected. There is no contested case for a committed identity.
- **Fail closed.** Anything that does not verify is ignored. The NIP can
  never be used to *steal* an identity; the worst case is that no rotation
  is honoured, which is today's status quo.

### Conflicting rotation events

For a [committed](#committed-identities) identity, at most one `kind:1041`
event can ever verify as rotating away from a given `oldpub`; forging a
second is infeasible. If a client sees multiple `kind:1041` events with
a predecessor-proof `successor` tag targeting the same committed key,
the invalid ones fail the validity rules in
[Client verification](#client-verification) and are dropped. No
tie-break is needed.

**Committed keys cannot be bridge-rotated.** `verifyBridge` (see
[The bridge for existing keys](#the-bridge-for-existing-keys)) refuses any
bridge whose `oldpub` is committed, where "committed" is decided by
`isCommitted(oldpub)` above. This closes the takeover that would
otherwise be available to an attacker holding `nsec[i]`: they could sign
a `kind:1042` from `npub[i]` and bridge to a key they control, because
without a published self-successor a verifier cannot distinguish a
committed `npub[i]` from a legacy `npub` by inspecting the key bytes
alone.

For a **bridged** legacy key, conflicts among `kind:1042` events are
resolved by `verifyBridge`; see
[The bridge for existing keys](#the-bridge-for-existing-keys).

### Client behaviour

Three client roles appear in this NIP. A client may play any or all of
them at different times. The protocol-visible behaviour required of each
role is intentionally minimal so every implementation behaves identically
at the protocol layer.

The roles below describe protocol-visible behaviour, not which piece of
software a user is looking at. Any MUST in this section that requires
the root secret or a non-current `nsec[i]` (chain birth, rotation,
bridge) binds the **implementation that performs the operation**, which
in a delegated-signing deployment (NIP-46, NIP-55, hardware signer) is
the signer rather than the everyday client.

#### Chain-birth client

This role applies once per identity, when the chain is first created.

**MUST:**

1. Sign and publish the chain-birth `kind:1041` event (see
   [The `kind:1041` event](#the-kind1041-event)) from `npub[0]` to
   multiple relays (recommend ≥ 5) for survivability, **before** any
   other event from `npub[0]` is signed. This minimises the chain-birth
   race window in which an attacker who has stolen `nsec[0]` could
   publish a bridge from `npub[0]` and take over the chain (see
   [The bridge for existing keys](#the-bridge-for-existing-keys)).
2. Publish the user's `kind:0` profile, `kind:3` contacts list, and
   NIP-65 `kind:10002` relay list from `npub[0]` as normal Nostr
   onboarding, after the `kind:1041` event has been sent to its relays.

#### Rotating user's client

This role applies whenever the user moves from generation `i` to
generation `i+1`.

**MUST:**

1. Sign and publish the rotation `kind:1041` event (see
   [The `kind:1041` event](#the-kind1041-event)) to multiple relays
   (recommend ≥ 5) for survivability. The event is signed by
   `nsec[i+1]`, never by `nsec[i]`, and MUST carry both a predecessor
   proof for `npub[i]` and a self-successor for `npub[i+1]`.
2. Publish a fresh `kind:0` profile event from `npub[i+1]` mirroring the
   display name, picture, and bio of the prior profile.
3. Publish a fresh `kind:3` contacts/follow list event from `npub[i+1]`
   mirroring the prior follow list.
4. Switch the client's active signing key to `nsec[i+1]`. `nsec[i]` is no
   longer used to sign new events.
5. Publish the new identity's NIP-65 (`kind:10002` for `npub[i+1]`) to
   the same relays as the `kind:1041` event, so followers who find the
   rotation can locate the new identity's future events.
6. Update [NIP-05](05.md), if applicable. The rotating client either
   controls the NIP-05 record or it does not:
   a. If it controls the record (same vendor hosts both), it MUST update
      the `.well-known/nostr.json` entry to map to `npub[i+1]`.
   b. If it does not control the record (e.g., third-party hosting), it
      MUST inform the user to update the record with their NIP-05
      provider.

   Without this update, fresh clients (which start from NIP-05) cannot
   discover the rotated identity.

#### Follower's client

**MUST:**

1. On encountering any `npub`, call `resolve(npub)` per the procedure
   above. Use the result everywhere as **the** npub for that user: there
   is always exactly one current npub for an identity, returned by
   `resolve`. The client's internal data model does not need to track
   multiple concurrent npubs; the resolver is a translation at the
   protocol boundary.
2. Update the follower's own `kind:3` follow list: replace `npub[i]` with
   `resolve(npub[i])` and re-publish. This is what propagates rotation
   through the network: each follower's kind:3 update advances the
   migration one client at a time.

**Backward routing: historical mentions.** When the rotated user filters
for their own notifications, the filter must include every npub they have
ever held: `["p", npub[0]] OR ["p", npub[1]] OR …`. The client builds
the list with `priorNpubs(current)`. Old events that tagged a prior
npub remain reachable by the current owner.

**Forward routing: new mentions.** Any author tagging any pubkey calls
`resolve()` first and tags the resolved npub. Subsequent reads of that
event by any NIP-41-aware client route correctly to the current identity.

## The bridge for existing keys

An `npub` created before this NIP has no commitment baked in. It cannot
become a committed identity (you cannot change a key that already exists).
It can do **exactly one** move, into a fresh committed chain.

The bridge is composed of three events:

1. A `kind:1042` **bridge commitment** signed by the legacy key, linking
   itself to a fresh committed chain.
2. A [NIP-03](https://github.com/nostr-protocol/nips/blob/master/03.md)
   `kind:1040` **OpenTimestamps attestation** anchoring the `kind:1042`
   to a Bitcoin block.
3. A `kind:1041` **bridge migration** signed by the fresh chain head,
   activating the cutover.

Clients SHOULD publish the `kind:1042` and its `kind:1040` attestation
at NIP-41 onboarding. Pre-anchor compromise is unrecoverable; see
[Residual concerns](#residual-concerns).

### Bridge commitment `kind:1042`

```jsonc
{
  "kind": 1042,
  "pubkey": "<legacy npub hex>",
  "created_at": 1716100000,
  "content": "",
  "tags": [
    ["commits", "<npub[0] hex of a fresh committed chain>"]
  ],
  "sig": "<signed by the legacy key>"
}
```

The following tag MUST be present:

- `commits`: a single tag whose value is the hex-encoded `npub[0]` of
  a fresh committed chain.

### Bridge attestation (OpenTimestamps `kind:1040`)

A bridge MUST be accompanied by a
[NIP-03](https://github.com/nostr-protocol/nips/blob/master/03.md)
OpenTimestamps attestation targeting the `kind:1042` event id. The
Bitcoin attestation in the proof MUST be confirmed to at least **6
blocks** at the moment of verification; NIP-03 itself does not
constrain confirmation depth, so the 6-block floor is added by this
NIP.

The publishing client SHOULD submit the `kind:1042` id to one or more
OpenTimestamps calendars immediately after publishing the `kind:1042`,
wait for Bitcoin confirmation (typically ~1 hour), then publish the
resulting `kind:1040` to the same relays as the `kind:1042`.

### Bridge migration `kind:1041`

The fresh chain's `npub[0]` publishes a `kind:1041` event with two
tags: a `bridge` tag referencing the `kind:1042` event, and a
self-successor tag opening the fresh chain's own commitment.

```jsonc
{
  "kind": 1041,
  "pubkey": "<fresh npub[0] hex>",
  "created_at": 1716100100,
  "content": "",
  "tags": [
    ["p", "<legacy npub hex>",     "", "predecessor"],
    ["p", "<fresh npub[0] hex>",   "", "successor"],
    ["bridge", "<legacy npub hex>", "<kind:1042 event id>"],
    ["successor", "<fresh npub[0] hex>", "<P_internal[0] hex>", "<npub[1] hex>"]
  ],
  "sig": "<signed by fresh nsec[0]>"
}
```

The `bridge` tag replaces the predecessor-proof `successor` tag used in
chain rotation. The self-successor tag is identical to a chain-rotation
self-successor.

The rotating client MUST also publish the new chain's NIP-65 for the
fresh `npub[0]` to the same relays, and MUST perform all remaining
steps in [Rotating user's client](#rotating-users-client).

### `verifyBridge(E)`

Given a `kind:1041` event `E` whose `bridge` tag is
`["bridge", "<legacypub>", "<kind:1042_id>"]`, the bridge is valid iff
all of the following hold:

- **`isCommitted(legacypub)` is false,** decided against the
  [broad-poll relay set](#broad-poll-relay-set).
- **The `kind:1042` exists,** is signed by `legacypub`, has a valid
  signature, and carries a `commits` tag whose value equals
  `E.pubkey`.
- **A [NIP-03](https://github.com/nostr-protocol/nips/blob/master/03.md)
  `kind:1040` attestation for `kind:1042_id` exists,** and its Bitcoin
  attestation is at least **6 confirmations** deep at the moment of
  verification.
- **Bitcoin firstness.** The referenced `kind:1042` has the earliest
  confirmed Bitcoin block height among all `kind:1042` events signed by
  `legacypub` that pass the attestation check above, queried against
  the [broad-poll relay set](#broad-poll-relay-set). Same-block ties
  break on lexicographically lower event id.

A `verifyBridge` failure caused by a missing or not-yet-deep-enough
`kind:1040`, or by a transient reorg below 6 confirmations, is
**pending, not permanent**: verifiers SHOULD re-evaluate when fresh
`kind:1040` events or new Bitcoin blocks arrive.

### Broad-poll relay set

Bridge verification MUST query a **broad-poll relay set**: a
client-configured set that is not narrowed by any relay list under the
control of the keys being verified, including NIP-65 signed by the
legacy key. Used for the `isCommitted`, `kind:1042`, and `kind:1040`
lookups in `verifyBridge`.

### Residual concerns

- **Pre-anchor compromise is unrecoverable.** If the legacy `nsec` is
  in attacker hands before the legitimate `kind:1042` is Bitcoin-
  anchored, the attacker can publish a competing `kind:1042` and may
  anchor it earlier; that bridge then wins for every verifier. The
  fallback is the same as [Root-secret compromise](#root-secret-compromise):
  abandon the legacy identity and re-establish followers socially.
- **Pre-confirmation publication window.** Between publishing
  `kind:1042` and the Bitcoin anchor reaching the 6-confirmation depth
  (~1 hour), the bridge does not yet bind. A compromise during this
  window can be raced.

## Appendix

### Root-secret compromise

If the **root secret** itself leaks, the attacker can derive the entire
identity chain: every generation, every successor. Rotation within the
chain is useless because the attacker simply rotates too.

The only response is to **abandon the chain and start a new identity**
from a fresh root secret, and re-establish the link to followers **socially**.

The root secret should therefore live in a hardware-backed store
(passkey, secure element, OS keychain) and be exported only as a backup
(see [Portability](#portability-root-secret-export)).

### Encrypted messages across rotation

Messages encrypted to `npub[i]` cannot be decrypted with `nsec[i+1]`; they
are different keys. This NIP does not change any encryption scheme. Two
practical notes:

- **Reading old messages still works for the owner.** Each generation
  derives from one root secret, so the implementation holding the root
  secret can re-derive `nsec[i]` at any time and decrypt historical
  messages. This is an advantage over schemes whose keys have
  independent entropy.
- **New messages.** Once a correspondent's client has resolved the
  rotation (see [Client verification](#client-verification)), it encrypts
  to the current key. There is no protocol-defined dual-encryption
  window: a verified rotation is a hard cutover, and senders SHOULD
  encrypt to `npub[i+1]` only.

### Security considerations

#### Threat model

| Asset compromised | Result |
|---|---|
| A signing key `nsec[i]`, root secret safe, `kind:1041` self-successor for `npub[i]` already on relays | **Recoverable.** The owner rotates to `i+1`. The thief cannot forge a chain rotation (cannot open the commitment), cannot bridge-rotate (the self-successor makes `npub[i]` ineligible for bridging via `isCommitted`), and cannot derive `nsec[i+1]` (HKDF is one-way). |
| `nsec[0]` leaked **before** the chain-birth `kind:1041` reaches relays | **Race-dependent.** An attacker can attempt a bridge from `npub[0]`, but the bridge does not bind until its `kind:1042` has a Bitcoin-anchored attestation (~1 hour). The legitimate chain-birth `kind:1041` propagates in seconds and, once seen, retroactively invalidates the attacker's bridge via `isCommitted`. The chain-birth client MUST publish the `kind:1041` as the first event from `npub[0]` to keep this window minimal. |
| The **root secret** | **Not recoverable.** Whole chain exposed. See [Root-secret compromise](#root-secret-compromise). |
| A legacy key, already compromised before its `kind:1042` is Bitcoin-anchored | **Not recoverable.** See [The bridge for existing keys](#the-bridge-for-existing-keys). |

#### What an attacker can and cannot do

*Can:* post as the user until the user rotates (this is ordinary key
compromise; today's reality).

*Cannot:*

- Forge a chain rotation of `npub[i]` to a key of their choosing; it
  fails the verification equation (would need a SHA-256 preimage).
- Forge a self-successor for `npub[i]` to a chosen `(P', npub')`; this
  requires the same fixed-point grind as forging a chain rotation.
  Infeasible.
- Publish a competing commitment; the commitment is in the key, immutable.
- Bridge-rotate `npub[i]` once its self-successor `kind:1041` has
  propagated to the
  [broad-poll relay set](#broad-poll-relay-set); bridge verification
  refuses bridges for keys that pass `isCommitted`.
- Derive `nsec[i+1]` or any deeper signing key; HKDF is one-way.
- Rotate `npub[i]` to the *real* `npub[i+1]` themselves; that requires
  `nsec[i+1]`, which only the root-secret holder can derive.

#### Residual concerns

- **Spam.** An attacker can publish many invalid `kind:1041` events;
  clients reject them with a cheap check. Relay-level spam handling is
  outside the scope of this NIP.
- **Chain-birth race.** If `nsec[0]` leaks before the chain-birth
  `kind:1041` propagates, an attacker can attempt a bridge from
  `npub[0]`. Mitigated at the sender by
  [Chain-birth client](#chain-birth-client) (publish-first MUST), at
  the follower by the [broad-poll relay set](#broad-poll-relay-set)
  requirement on bridge verification, and by the ~1-hour Bitcoin
  anchoring delay before any bridge binds.
- **`created_at` is self-reported** throughout Nostr; this NIP avoids
  depending on it for anything security-critical (verification uses no
  timestamps).
- **Revocation without rotation.** This NIP defines no separate "revoke
  without rotation" mechanism. For a committed chain, the next-generation
  key is always derivable from the root secret, so there is no "successor
  not ready yet" state; the user simply rotates. For a legacy key
  suspected of compromise before bridging, no protocol mechanism can help
  (a self-signed revocation event is contradictable by an attacker holding
  the same key); users may signal suspected compromise via ordinary notes,
  the social weight of which is outside the scope of this NIP.
- **Group keys, delegation, threshold (FROST) signing.** Separate problems,
  outside the scope of this NIP.

### Implementation pseudocode

The functions below implement the cryptographic primitives from this
NIP and are intended to guide implementers. Production code MUST use
libsecp256k1 (or an equivalent audited library) for curve operations
and modular arithmetic, not hand-rolled implementations.

**Constants:**

- `G`: the [secp256k1](https://www.secg.org/sec2-v2.pdf) generator point
- `n`: the secp256k1 group order
- `N = 1024`: identity chain length (see [Identity chain](#identity-chain))

**Operators:**

- `‖`: byte concatenation
- `xonly(P)`: the 32-byte [BIP-340](https://bips.xyz/340) x-only encoding of point `P`
- `lift_x(X)`: the BIP-340 inverse (point with x-coordinate `X` and even `y`)
- `has_even_y(P)`: true iff `P.y` is even

**Cryptographic methods:**

- `hkdf_sha256(ikm, salt, info, length)`: HKDF-SHA256 [(RFC 5869)](https://datatracker.ietf.org/doc/html/rfc5869)
- `tagged_hash(tag, msg)`: BIP-340 tagged hash (formula in [Succession tweak](#succession-tweak))
- BIP-341 `taproot_tweak_seckey`: x-only secret-key tweak (see [BIP-341](https://bips.xyz/341))

#### internalKey(root_secret, i, counter_start = 0) → (p_internal, P_internal, counter_used)

Derives the internal scalar and point for generation `i` from the root
secret. Uses HKDF-SHA256 with NIP-41-specific salt and info. The
optional `counter_start` lets a caller skip past counter values that
prior derivations have already consumed. This is needed when a tweak
rejection (`t[i] ≥ n` in `chainStep` below) re-derives `P_internal[i]`
with the shared counter (see [Identity chain](#identity-chain)). The
returned `counter_used` is the counter value that produced the
accepted scalar.

```python
def internal_key(root_secret, i, counter_start=0):
    base_info = b"internal-key" + i.to_bytes(4, "big")
    counter = counter_start
    while True:
        info = base_info if counter == 0 else base_info + bytes([counter])
        okm = hkdf_sha256(ikm=root_secret,
                          salt=b"nip41-key-rotation-v1",
                          info=info,
                          length=32)
        d = int.from_bytes(okm, "big")
        if 0 < d < n:
            return d, d * G, counter
        counter += 1
```

#### chainStep(P_internal, npub_next) → (t, npub)

Computes the committed pubkey for one generation by applying the
succession tweak to `P_internal` with the next generation's `npub`.
Returns the tweak scalar `t` alongside the committed `xonly(Q)` so
the caller can detect `t ≥ n` and re-derive `P_internal` with an
advanced counter (per [Identity chain](#identity-chain)). One step in
the backward chain construction. See
[Committed identities](#committed-identities).

```python
def chain_step(P_internal, npub_next):
    t = int.from_bytes(
        tagged_hash("nip41/succession", xonly(P_internal) + npub_next),
        "big",
    )
    if t >= n:
        return t, None                  # caller re-derives P_internal
    Q = lift_x(xonly(P_internal)) + t * G
    return t, xonly(Q)
```

#### buildChain(root_secret, N) → npub[0..N-1]

Builds the full identity chain backwards from the terminal generation
to the root. `npub[N-1]` is the x-only encoding of `P_internal[N-1]`
(commits to nothing); each earlier generation is derived by
`chainStep`. The inner loop handles the shared-counter re-derivation
for both `p_internal` rejection (inside `internal_key`) and `t ≥ n`
rejection (signaled by `chain_step` returning `None`). See
[Identity chain](#identity-chain) and
[Committed identities](#committed-identities).

```python
def build_chain(root_secret, N):
    npub = [None] * N

    # Terminal generation: commits to nothing. Only p_internal rejection
    # applies (handled inside internal_key).
    _, P_terminal, _ = internal_key(root_secret, N - 1)
    npub[N - 1] = xonly(P_terminal)

    # Earlier generations: p_internal rejection and t >= n rejection
    # share the same counter, so a t >= n result advances past the
    # counter that internal_key just used.
    for i in range(N - 2, -1, -1):
        counter_start = 0
        while True:
            _, P_internal, counter_used = internal_key(root_secret, i, counter_start)
            _, committed = chain_step(P_internal, npub[i + 1])
            if committed is not None:
                npub[i] = committed
                break
            counter_start = counter_used + 1
    return npub
```

#### signingKey(root_secret, i, npub_next) → nsec

Derives the signing scalar (`nsec[i]`) for generation `i`. For
non-terminal generations, combines `internalKey` with BIP-341
`taproot_tweak_seckey` using the succession tweak; the same
shared-counter re-derivation as `buildChain` applies if `t ≥ n`. For
the terminal generation (`i == N-1`), `npub_next` is `None` and the
signing key is `p_internal[N-1]` directly. See
[Signing key](#signing-key).

```python
def signing_key(root_secret, i, npub_next):
    if npub_next is None:                # terminal: commits to nothing
        p_internal, _, _ = internal_key(root_secret, i)
        return p_internal

    counter_start = 0
    while True:
        p_internal, P_internal, counter_used = internal_key(
            root_secret, i, counter_start)
        t, committed = chain_step(P_internal, npub_next)
        if committed is not None:
            d = p_internal if has_even_y(P_internal) else n - p_internal
            return (d + t) % n
        counter_start = counter_used + 1
```

#### verifyChainProof(subject, npub_next, P_internal) → bool

Pure cryptographic predicate underlying every `successor` tag check:
returns true iff applying the succession tweak to `P_internal` with
`npub_next` reproduces `subject`. The event-level
[Client verification](#client-verification) calls this once per
`successor` tag.

```python
def verify_chain_proof(subject, npub_next, P_internal):
    t = tagged_hash("nip41/succession", P_internal + npub_next)
    Q = lift_x(P_internal) + int(t) * G
    return xonly(Q) == subject
```

### Test vectors

Test vectors accompany this NIP. They cover the cryptographic
construction and the validity of `kind:1041` events:

- Forward derivation of `(p_internal[i], P_internal[i])` from a root
  secret for representative indices, including both even-`y` and
  odd-`y` internal keys.
- Backward construction of the committed chain `npub[0..N-1]`.
- Construction and verification of a chain-birth `kind:1041` event
  (single self-successor tag), with pinned `id` and signature.
- Construction and verification of two rotation `kind:1041` events
  (predecessor proof + self-successor tags), exercising both a chain
  head and an interior step, with pinned `id`s and signatures.
- `isCommitted` outcomes for the events above: a chain-birth head and
  a mid-chain generation reached through rotation.
- Discovery `p`-tag cross-check: events whose `predecessor` /
  `successor` p-tags match the verification content (accepted), and
  one whose `predecessor` p-tag disagrees with the `successor` tag's
  content (rejected at the event-validity layer even though the
  cryptographic equation still holds).
- Negative tests at the equation layer: forged `successor` tags whose
  `npub_next` does not match the binding (rejected by
  `verifyChainProof`); a forged event whose BIP-340 signature still
  validates but is rejected by the event-validity rules in
  [Client verification](#client-verification).
- Negative tests at the event-validity layer: rotation event missing
  the required `["p", _, "", "successor"]` tag (rejected); rotation
  event carrying two self-successor tags (rejected).
