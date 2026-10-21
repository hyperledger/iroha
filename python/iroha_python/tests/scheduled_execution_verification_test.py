"""Strict native Time API rejection; positive Commit-QC cases are Rust tests."""
import pytest

from iroha_python import NetworkId, verify_scheduled_trigger_execution_v1


def selected():
    return {
        "native_finality_proof_chain_json": "[]",
        "expected_network_id": NetworkId.from_bytes(bytes([1]) * 32),
        "expected_chain": "selected-chain", "trusted_checkpoint": b"invalid-checkpoint",
        "expected_chain_discriminant": 753,
    }


@pytest.mark.parametrize("wire", [None, "bytes", bytearray(b"wire"), memoryview(b"wire"), b""])
def test_scheduled_verifier_requires_exact_immutable_original_wire(wire):
    with pytest.raises((TypeError, ValueError)):
        verify_scheduled_trigger_execution_v1(wire, "fixture", **selected())


@pytest.mark.parametrize("prefix", [True, -1, 65536, "753", 753.0])
def test_scheduled_verifier_requires_exact_selected_chain_prefix(prefix):
    args = selected()
    args["expected_chain_discriminant"] = prefix
    with pytest.raises((TypeError, ValueError)):
        verify_scheduled_trigger_execution_v1(b"invalid-original", "fixture", **args)


@pytest.mark.parametrize("field,value", [
    ("trusted_checkpoint", bytearray(b"checkpoint")),
    ("native_finality_proof_chain_json", {}),
    ("expected_chain", ""),
])
def test_scheduled_verifier_refuses_noncanonical_boundary_values(field, value):
    args = selected()
    args[field] = value
    with pytest.raises((TypeError, ValueError)):
        verify_scheduled_trigger_execution_v1(b"invalid-original", "fixture", **args)
