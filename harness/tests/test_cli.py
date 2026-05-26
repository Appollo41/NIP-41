import json
import subprocess
import sys
from pathlib import Path

HARNESS = Path(__file__).parent.parent


def _run(*args):
    return subprocess.run(
        [sys.executable, "cli.py", *args],
        cwd=HARNESS, capture_output=True, text=True,
    )


def test_selfcheck_exits_zero():
    result = _run("selfcheck")
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_inspect_prints_hex_keys():
    result = _run("inspect", "--root", "ab" * 32, "--length", "6")
    assert result.returncode == 0, result.stderr
    assert "npub" in result.stdout and "nsec" in result.stdout
    assert "internal" in result.stdout


def test_inspect_rejects_wrong_length_root():
    result = _run("inspect", "--root", "ab" * 31, "--length", "4")  # 31 bytes, invalid
    assert result.returncode != 0
    assert "32 bytes" in result.stderr


def test_vectors_command_writes_valid_json(tmp_path):
    out = tmp_path / "vectors.json"
    result = _run("vectors", "--root", "cd" * 32, "--length", "5", "--out", str(out))
    assert result.returncode == 0, result.stderr
    data = json.loads(out.read_text())
    assert len(data["generations"]) == 5
    assert "chain_birth_event" in data
    assert "rotation_event" in data
    for gen in data["generations"]:
        assert set(gen) >= {"index", "internal_key", "npub", "nsec"}
    # Both events use the spec's tag shape: `successor` (4-element) tag(s).
    assert any(t[0] == "successor" for t in data["chain_birth_event"]["tags"])
    assert any(t[0] == "successor" for t in data["rotation_event"]["tags"])
