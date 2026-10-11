"""Closed deterministic IVM fault payload validation."""

from copy import deepcopy

import pytest

from iroha_python.client import _normalize_ivm_fault


def fault():
    return {
        "kind": {"kind": "Numeric", "value": {"kind": "DivisionByZero", "value": None}},
        "site": {
            "code_hash": "11" * 32,
            "selector": {"kind": "Entrypoint", "value": (1 << 32) - 1},
            "position": {"kind": "Execute", "value": {"pc_offset": (1 << 64) - 1}},
        },
    }


def test_typed_fault_retains_exact_unsigned_origin_and_snapshots_input():
    value = fault()
    normalized = _normalize_ivm_fault(value)
    assert normalized == value
    value["site"]["position"]["value"]["pc_offset"] = 0
    assert normalized["site"]["position"]["value"]["pc_offset"] == (1 << 64) - 1


@pytest.mark.parametrize("mutation", ["unknown", "subtype", "ordinal", "pc", "bool", "extra", "missing", "stage"])
def test_typed_fault_rejects_invalid_closed_shape(mutation):
    value = deepcopy(fault())
    if mutation == "unknown":
        value["kind"]["kind"] = "DebugString"
    elif mutation == "subtype":
        value["kind"]["value"]["kind"] = "WrongType"
    elif mutation == "ordinal":
        value["site"]["selector"]["value"] = 1 << 32
    elif mutation == "pc":
        value["site"]["position"]["value"]["pc_offset"] = 1 << 64
    elif mutation == "bool":
        value["site"]["position"]["value"]["pc_offset"] = True
    elif mutation == "extra":
        value["site"]["local_pointer"] = 7
    elif mutation == "missing":
        del value["site"]["code_hash"]
    elif mutation == "stage":
        value["site"]["position"]["kind"] = "ReturnValidation"
    with pytest.raises(ValueError):
        _normalize_ivm_fault(value)
