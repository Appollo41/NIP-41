# NIP-41 Construction — Confirmation Report

Generated: 2026-05-26 · Test suite: ALL GREEN

| Item | What | Tests | Result |
|------|------|-------|--------|
| C1 | Commitment soundness (shape) | `test_differential_tweak.py` | Confirmed (shape) — formal binding/hiding proof still needs a cryptographer |
| C2 | BIP-340/341 parity | `test_differential_tweak.py test_roundtrip.py test_bip341_tweak.py test_draft_literal_bug.py` | Confirmed — executable |
| C3 | HKDF -> scalar reduction | `test_hkdf.py test_derivation.py` | Confirmed — executable |
| C4 | Revealing internal key leaks nothing | `(structural)` | Evidence only — flagged for cryptographer |
| C5 | Signing key cannot be split | `(structural)` | Evidence only — flagged for cryptographer |
| A2 | Generation-index encoding | `test_derivation.py` | Confirmed |
| res | resolve / multi-hop rotation walk | `test_verify.py test_properties.py` | Confirmed (rotation walk only) |
| evt | kind:1041 event construction + equation forgery | `test_event.py` | Confirmed |

## pytest output

```
..............................................                           [100%]
46 passed in 2067.55s (0:34:27)
```

## Notes

- C4 and C5 are the honest limit of an executable harness: it produces
  strong structural evidence but not a formal proof of hiding/one-wayness.
- If any differential or round-trip test failed, the construction's parity
  handling disagrees with BIP-341 — see the failing test output above and
  record the concrete spec fix for the affected section.
