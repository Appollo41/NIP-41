# Should `kind:1041` rotation events carry the full chain history?

When a user rotates to a new identity, should the resulting `kind:1041`
event carry **only** the immediate predecessor's chain proof (current
draft), or **every prior step's chain proof up to the new identity**?

## Why it matters

A rotation event already publishes the proof that opens the previous
key's commitment to the new key. The disclosed `P_internal[i]` is
public on the network the moment that rotation is signed. Extending the
proof set to cover every prior generation discloses nothing new, but the
choice changes:

- How clients discover prior identities (one-shot read vs. recursive walk).
- How a client locates the current identity from any historical `npub`
  (one filter query vs. step-by-step forward walk).
- Whether a single rotation event is self-sufficient for verifying the
  full chain.
- Event size, and the cost of `#p` queries on relays.

## Option 1: Immediate predecessor only (current draft)

Each rotation event carries the predecessor-proof `successor` tag for
the step it performs, plus its own self-successor. To enumerate prior
identities or resolve the current identity from an old `npub`, a client
walks rotation events one step at a time.

### Example: rotation at generation `k+1`

```jsonc
{
  "kind": 1041,
  "pubkey": "<npub[k+1]>",
  "created_at": 1716200000,
  "content": "",
  "tags": [
    ["p", "<npub[k]>",   "", "predecessor"],
    ["p", "<npub[k+1]>", "", "successor"],
    ["successor", "<npub[k]>",   "<P_internal[k]>",   "<npub[k+1]>"],
    ["successor", "<npub[k+1]>", "<P_internal[k+1]>", "<npub[k+2]>"]
  ],
  "sig": "<signed by nsec[k+1]>"
}
```

### Client lookups

- `priorNpubs(P)`: walk `predecessor` p-tags backward, one fetch per
  generation. `O(k)` round-trips.
- `resolve(P)`: walk `#p:[P]` matches forward, one fetch per
  generation. `O(k)` round-trips.

### Pros

- **Constant-size rotation events** regardless of chain depth.
- **Constant verifier work per event** (one predecessor proof + one
  self-successor tweak check).
- **Smallest filter result sets**: `#p:[npub[i]]` matches exactly one
  event (the gen `i+1` rotation).
- **Lowest construction overhead**: the producer needs only its own
  `P_internal` values for the current step.

### Cons

- **Backward walk is `O(k)` round-trips** to enumerate prior identities.
- **Forward walk is `O(k)` round-trips** to resolve current identity
  from a historical `npub`.
- **Not self-contained**: verifying past provenance requires every
  intermediate rotation event to still be reachable on some relay.
- **Single-event loss breaks lineage**: if any intermediate `kind:1041`
  is dropped by all relays a client polls, the historical chain cannot
  be fully reconstructed past that gap (the new identity remains
  verifiable in isolation; only the linkage to earlier generations is
  lost).

## Option 2: Full chain to current identity

Each rotation event carries chain proofs and `p`-tags for **every**
prior generation back to chain-birth (or, for bridged chains, back to
the bridged origin), plus its own self-successor and self `p`-tag. The
`bridge` tag, when present, is carried forward in every subsequent
rotation event so the bridged origin is recorded in any single event.

### Example: rotation at generation `k+1` (committed chain, no bridge)

```jsonc
{
  "kind": 1041,
  "pubkey": "<npub[k+1]>",
  "created_at": 1716200000,
  "content": "",
  "tags": [
    ["p", "<npub[0]>",   "", "predecessor"],
    ["p", "<npub[1]>",   "", "predecessor"],
    // ... one predecessor p-tag per prior generation ...
    ["p", "<npub[k]>",   "", "predecessor"],
    ["p", "<npub[k+1]>", "", "successor"],

    ["successor", "<npub[0]>",   "<P_internal[0]>",   "<npub[1]>"],
    ["successor", "<npub[1]>",   "<P_internal[1]>",   "<npub[2]>"],
    // ... one chain proof per prior step ...
    ["successor", "<npub[k]>",   "<P_internal[k]>",   "<npub[k+1]>"],
    ["successor", "<npub[k+1]>", "<P_internal[k+1]>", "<npub[k+2]>"]
  ],
  "sig": "<signed by nsec[k+1]>"
}
```

### Example: rotation at generation `k+1` of a bridged chain

```jsonc
{
  "kind": 1041,
  "pubkey": "<npub[k+1]>",
  "created_at": 1716200000,
  "content": "",
  "tags": [
    ["p", "<legacy npub>", "", "predecessor"],
    ["p", "<npub[0]>",     "", "predecessor"],
    // ... ...
    ["p", "<npub[k]>",     "", "predecessor"],
    ["p", "<npub[k+1]>",   "", "successor"],

    ["bridge", "<legacy npub>", "<kind:1042 event id>"],

    ["successor", "<npub[0]>",   "<P_internal[0]>",   "<npub[1]>"],
    // ... one chain proof per prior step ...
    ["successor", "<npub[k+1]>", "<P_internal[k+1]>", "<npub[k+2]>"]
  ],
  "sig": "<signed by nsec[k+1]>"
}
```

Chain-birth events (gen-0 first publication) are unchanged: a single
self-successor and, for bridged chains, a single `bridge` tag, since
there are no prior steps to embed. The cumulative growth begins at gen-2 (a
gen-1 rotation event already only has one prior step, so it is
byte-identical to Option 1).

### Client lookups

- `priorNpubs(P)`: one tag read on any rotation event signed by `P`.
  No recursion.
- `resolve(P)`: one `#p:[P]` query; the client picks the matching event
  with the longest verified chain. No forward walk.
- Bridge verification (`kind:1042` fetch + conflict-search) is
  unchanged. Legacy keys have no self-certifying commitment, so the
  caution window and broad-poll requirement still apply. Carrying the
  `bridge` tag forward only removes the need to re-walk to find which
  event introduced the bridge.

### Pros

- **Single rotation event verifies the entire chain** from gen-0 (or
  bridge) up to the current identity, locally, without recursion.
- **One-shot client lookup in both directions**: `priorNpubs` and
  `resolve` collapse from `O(k)` round-trips to a single query each.
- **Resilient to relay loss** of intermediate rotation events: the
  latest event reproduces the full proof on its own.
- **Independent auditability**: any holder of one rotation event can
  verify provenance end-to-end.
- **No new disclosure**: every `P_internal[i]` is already public from
  its own rotation event; later events only collate already-published
  data.

### Cons

- **Event size grows linearly** in chain depth, roughly 200 bytes per
  prior generation across the `p`-tag and the chain-proof `successor`
  tag combined:
  - gen 20 ≈ 4 KB
  - gen 100 ≈ 20 KB
  - theoretical `N = 1024` ≈ 200 KB, which exceeds common relay
    event-size limits.
- **More `#p` matches per query**: every subsequent rotation event tags
  every prior `npub`, so `#p:[npub[i]]` returns a result set linear in
  remaining rotations rather than a single event. Total bandwidth to
  fully resolve grows; latency to first answer drops.
- **Producer assembles more material per rotation**: all prior
  `P_internal[i]` must be re-derived from the root secret at signing
  time. The capability requirement is unchanged (the root secret is
  already required to sign a rotation), but construction is `O(k)`
  rather than `O(1)`.
- **Verifier does `O(k)` tweak checks per event** instead of one. Each
  check is sub-millisecond, so this is not a practical concern at
  realistic depths.

## Related considerations (separate questions)

- **Chain length cap `N = 1024`.** If Option 2 is adopted, deep chains
  push against relay event-size limits long before exhausting `N`. A
  follow-up question may explore reducing `N` (e.g. to 512) or
  capping the embedded history depth per event (e.g. last 32
  generations, with older proofs reachable by recursion). Filed as a
  separate open question if and when Option 2 is selected.

## Decision

Pending community feedback.
