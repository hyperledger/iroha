"""Concrete prefix mutations preserve the outer fixture proof and advertised scope."""
from pathlib import Path
import sys
import struct
from unittest.mock import patch
import json

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import parliament_ballot_allocation_cases as cases


def test_complete_unique_case_inventory_and_finite_grammars():
    values = cases.build_cases()
    assert len(values) == len({case["name"] for case in values}) == 66
    for case in values:
        for accelerated in (False, True):
            events = cases.grammar(case, accelerated)
            assert bool(events) == (case["expected_charge"] == 1)
    valid = [case for case in values if case["case"] == "valid"]
    assert len(valid) == 8
    assert {case["seats"] for case in valid} == {0, 3, 500, 1000}


def test_pack_and_fixture_parse_exact_lengths():
    statement = cases.resource.frame(b"X", [b"", b"hello"])
    assert cases.split_record(cases.pack(statement, b"proof")) == (b"X", [b"", b"hello"], b"proof")
    with pytest.raises(ValueError):
        cases.split_record(cases.pack(statement, b"proof") + b"x")
    malformed = bytearray(statement); struct.pack_into("<I", malformed, 9, 100)
    with pytest.raises((ValueError, struct.error)):
        cases.split_record(cases.pack(malformed, b"proof"))
    with pytest.raises(ValueError, match="trailing"):
        cases.split_record(cases.pack(statement + b"x", b"proof"))


def test_length_variants_and_charged_read_failures_are_explicit():
    values = cases.build_cases()
    for case in values:
        if "registration_lengths_" in case["case"]:
            _, fields, _ = cases.split_record(case["input"])
            assert list(map(len, fields[1:8])) == case["registration_lengths"]
            assert fields[8] == cases.hashlib.sha3_512(cases.resource.frame(b"PARL/BODY/v1", [
                cases.resource.fixture_record(cases.ROOT, case["row"], 0)[4]["P16"], fields[1]])).digest()
        if case["case"].startswith("charged_read_"):
            assert case["expected_charge"] == 1 and case["expected_exit"] == 3
            assert [event["op"] for event in cases.grammar(case, False)] == ["alloc", "free"]
    with patch.object(sys, "argv", ["cases"]):
        with patch("builtins.print") as output:
            assert cases.main() == 0
            report = json.loads(output.call_args.args[0])
            assert len(report["cases"]) == 66 and not report["profile_qualified"]
