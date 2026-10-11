"""Run the complete independent native-prover corpus through its public CLI."""

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures/native_prover"
VERIFIER = FIXTURES / "verify_kats_v1.py"


def test_complete_native_kats_from_an_unrelated_directory(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(VERIFIER)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Fixed category counts prevent silent coverage loss or a partial replay.
    assert result.stdout.strip() == (
        f"{FIXTURES / 'kats_v1.json'}: verified points=132, params=22, "
        "blake2b_challenges=30, poseidon_transcript_challenges=30, "
        "native_hashes=54, confidential_boundary_vectors=218, rejections=20"
    )


def test_forged_transcript_challenge_fails_the_cli(tmp_path: Path) -> None:
    document = json.loads((FIXTURES / "kats_v1.json").read_text(encoding="utf-8"))
    operation = next(
        operation
        for script in document["blake2b_transcript"]["eq"]["scripts"]
        for operation in script["ops"]
        if operation["op"] == "squeeze"
    )
    altered = bytearray.fromhex(operation["challenge"])
    altered[0] ^= 1
    operation["challenge"] = altered.hex()
    forged = tmp_path / "forged-kats.json"
    forged.write_text(json.dumps(document), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-I", "-S", str(VERIFIER), str(forged)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode != 0
    assert "AssertionError" in result.stderr
    assert "verified points=" not in result.stdout
