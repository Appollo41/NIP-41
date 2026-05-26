"""Generate CONFIRMATION-REPORT.md from a full pytest run."""

import subprocess
import sys
from datetime import date

ROWS = [
    ("C1", "Commitment soundness (shape)", "test_differential_tweak.py",
     "Confirmed (shape) — formal binding/hiding proof still needs a cryptographer"),
    ("C2", "BIP-340/341 parity",
     "test_differential_tweak.py test_roundtrip.py test_bip341_tweak.py test_draft_literal_bug.py",
     "Confirmed — executable"),
    ("C3", "HKDF -> scalar reduction", "test_hkdf.py test_derivation.py",
     "Confirmed — executable"),
    ("C4", "Revealing internal key leaks nothing", "(structural)",
     "Evidence only — flagged for cryptographer"),
    ("C5", "Signing key cannot be split", "(structural)",
     "Evidence only — flagged for cryptographer"),
    ("A2", "Generation-index encoding", "test_derivation.py", "Confirmed"),
    ("res", "resolve / multi-hop rotation walk",
     "test_verify.py test_properties.py", "Confirmed (rotation walk only)"),
    ("evt", "kind:1041 event construction + equation forgery",
     "test_event.py", "Confirmed"),
]


def main():
    run = subprocess.run([sys.executable, "-m", "pytest", "-q"],
                         capture_output=True, text=True)
    passed = run.returncode == 0
    lines = [
        "# NIP-41 Construction — Confirmation Report",
        "",
        f"Generated: {date.today().isoformat()} · "
        f"Test suite: {'ALL GREEN' if passed else 'FAILURES PRESENT'}",
        "",
    ]
    if not passed:
        lines.append(
            "> **WARNING: the test suite has FAILURES. The per-row Result column "
            "below lists the *intended* outcomes, not actual pass/fail. "
            "See the pytest output section for what actually failed.**"
        )
        lines.append("")
    lines += [
        "| Item | What | Tests | Result |",
        "|------|------|-------|--------|",
    ]
    for ident, what, tests, result in ROWS:
        lines.append(f"| {ident} | {what} | `{tests}` | {result} |")
    output = run.stdout.strip() or "(no output)"
    if len(output) > 8000:
        output = "...(truncated)...\n" + output[-8000:]
    lines += [
        "",
        "## pytest output",
        "",
        "```",
        output,
        "```",
        "",
        "## Notes",
        "",
        "- C4 and C5 are the honest limit of an executable harness: it produces",
        "  strong structural evidence but not a formal proof of hiding/one-wayness.",
        "- If any differential or round-trip test failed, the construction's parity",
        "  handling disagrees with BIP-341 — see the failing test output above and",
        "  record the concrete spec fix for the affected section.",
    ]
    with open("CONFIRMATION-REPORT.md", "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("wrote CONFIRMATION-REPORT.md")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
