"""Independent arithmetic checks keep the captured confidential corpus complete."""

import copy
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures/native_prover"
SPEC = importlib.util.spec_from_file_location("native_prover_vector_check", FIXTURES / "verify_kats_v1.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
KATS = json.loads((FIXTURES / "kats_v1.json").read_text())
VECTORS = json.loads((FIXTURES / "confidential_poseidon_v1.json").read_text())


def test_complete_both_field_corpus() -> None:
    assert CHECKER.check_confidential_vectors(KATS, VECTORS) == 218


@pytest.mark.parametrize("mutation", ["output", "field", "row", "domain", "inputs"])
def test_forged_or_incomplete_corpus_rejects(mutation: str) -> None:
    bad = copy.deepcopy(VECTORS)
    if mutation == "output":
        bad["fields"]["fp"]["domain_outputs"][0] = "00" * 32
    elif mutation == "field":
        del bad["fields"]["fq"]
    elif mutation == "row":
        bad["fields"]["fp"]["boundary_outputs"].pop()
    elif mutation == "domain":
        bad["boundary_domains"][2] ^= 1
    else:
        bad["domain_cases"][0]["inputs"][0] += 1
    with pytest.raises(AssertionError):
        CHECKER.check_confidential_vectors(KATS, bad)
