"""NIP-41 confirmation harness — inspection CLI.

  python cli.py selfcheck
  python cli.py inspect --root <hex64> --length N
  python cli.py vectors --root <hex64> --length N --out vectors/nip41-test-vectors.json
"""

import argparse
import json
import sys

from vendor.bip340_reference import bytes_from_point
from nip41.chain import build_chain
from nip41.signing import signing_key
from nip41.event import build_rotation_event, build_chain_birth_event
from nip41.verify import verify_chain_rotation
from oracles.coincurve_oracle import schnorr_verify


def _chain_records(root: bytes, length: int):
    chain = build_chain(root, length)
    records = []
    for i in range(length):
        records.append({
            "index": i,
            "internal_key": bytes_from_point(chain.P_internal[i]).hex(),
            "npub": chain.npub[i].hex(),
            "nsec": signing_key(chain, i).to_bytes(32, "big").hex(),
        })
    return chain, records


def _parse_root_and_length(args):
    """Returns (root_bytes, error_code_or_None). Prints an error message to
    stderr when validation fails."""
    try:
        root = bytes.fromhex(args.root)
    except ValueError as e:
        print(f"error: --root must be valid hex: {e}", file=sys.stderr)
        return None, 1
    if len(root) != 32:
        print(f"error: --root must be 32 bytes (64 hex chars), got {len(root)}", file=sys.stderr)
        return None, 1
    if args.length < 2:
        print(f"error: --length must be >= 2, got {args.length}", file=sys.stderr)
        return None, 1
    return root, None


def cmd_inspect(args):
    root, err = _parse_root_and_length(args)
    if err is not None:
        return err
    _, records = _chain_records(root, args.length)
    print(f"root_secret: {root.hex()}")
    for r in records:
        print(f"  gen {r['index']:3d}  internal={r['internal_key']}")
        print(f"            npub    ={r['npub']}")
        print(f"            nsec    ={r['nsec']}")
    return 0


def cmd_vectors(args):
    root, err = _parse_root_and_length(args)
    if err is not None:
        return err
    chain, records = _chain_records(root, args.length)
    sk0 = signing_key(chain, 0)
    sk1 = signing_key(chain, 1)
    chain_birth = build_chain_birth_event(chain, signing_scalar=sk0)
    rotation = build_rotation_event(chain, old_index=0, signing_scalar=sk1)
    doc = {
        "root_secret": root.hex(),
        "chain_length": args.length,
        "generations": records,
        "chain_birth_event": chain_birth,
        "rotation_event": rotation,
    }
    with open(args.out, "w") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")
    print(f"wrote {args.out}")
    print(json.dumps({"chain_birth_event": chain_birth, "rotation_event": rotation}, indent=2))
    return 0


def cmd_selfcheck(args):
    root = bytes.fromhex("a5" * 32)
    chain, _ = _chain_records(root, 8)
    sk1 = signing_key(chain, 1)
    event = build_rotation_event(chain, old_index=0, signing_scalar=sk1)

    rotation_ok = verify_chain_rotation(
        chain.npub[0], chain.npub[1], bytes_from_point(chain.P_internal[0]))
    sig_ok = schnorr_verify(chain.npub[1], bytes.fromhex(event["id"]),
                            bytes.fromhex(event["sig"]))
    if rotation_ok and sig_ok:
        print("selfcheck: OK — chain builds, rotation verifies, signature valid")
        return 0
    print(f"selfcheck: FAILED rotation_ok={rotation_ok} sig_ok={sig_ok}")
    return 1


def main():
    parser = argparse.ArgumentParser(description="NIP-41 confirmation harness")
    sub = parser.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("selfcheck"); sc.set_defaults(func=cmd_selfcheck)

    ins = sub.add_parser("inspect")
    ins.add_argument("--root", required=True)
    ins.add_argument("--length", type=int, default=8)
    ins.set_defaults(func=cmd_inspect)

    vec = sub.add_parser("vectors")
    vec.add_argument("--root", required=True)
    vec.add_argument("--length", type=int, default=8)
    vec.add_argument("--out", default="vectors/nip41-test-vectors.json")
    vec.set_defaults(func=cmd_vectors)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
