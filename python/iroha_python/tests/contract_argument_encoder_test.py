"""Public API checks against the installed native encoder, without signing.

These controls require the matching native extension. Positive schema parity
also runs in the native suite and the current-fixture installed-wheel smoke.
"""
from __future__ import annotations

import inspect

import pytest
from iroha_native import load_crypto_extension

import iroha_python


def options():
    return {
        "expected_code_hash_hex": "00" * 32,
        "expected_abi_hash_hex": "00" * 32,
        "chain_discriminant": 369,
    }


def test_public_argument_encoder_is_the_original_native_callable():
    encoder = iroha_python.encode_contract_arguments_v1
    assert encoder is load_crypto_extension().encode_contract_arguments_v1
    assert inspect.isbuiltin(encoder)
    assert "encode_contract_arguments_v1" in iroha_python.__all__
    signature = inspect.signature(encoder)
    assert signature.parameters["payload_json"].default is None
    for name in options():
        assert signature.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
        assert signature.parameters[name].default is inspect.Parameter.empty


class BytesSubclass(bytes):
    pass


@pytest.mark.parametrize("artifact", [bytearray(b"x"), memoryview(b"x"), [1], "x", BytesSubclass(b"x")])
def test_public_argument_encoder_refuses_mutable_or_coerced_artifacts(artifact):
    with pytest.raises(TypeError, match="exact immutable bytes"):
        iroha_python.encode_contract_arguments_v1(artifact, "quote", **options())


@pytest.mark.parametrize("prefix", [True, False, -1, 65536, "369", 369.0])
def test_public_argument_encoder_requires_exact_chain_context(prefix):
    selected = options()
    selected["chain_discriminant"] = prefix
    with pytest.raises((TypeError, ValueError, OverflowError), match="chain_discriminant"):
        iroha_python.encode_contract_arguments_v1(b"not an artifact", "quote", **selected)


@pytest.mark.parametrize("field", ["expected_code_hash_hex", "expected_abi_hash_hex"])
@pytest.mark.parametrize("pin", ["AA" * 32, "0x" + "00" * 32, "00", " " + "00" * 32])
def test_public_argument_encoder_refuses_noncanonical_hash_pins_before_artifact_parsing(field, pin):
    selected = options()
    selected[field] = pin
    with pytest.raises(ValueError, match=field):
        iroha_python.encode_contract_arguments_v1(b"not an artifact", "quote", **selected)


@pytest.mark.parametrize("missing", ["expected_code_hash_hex", "expected_abi_hash_hex", "chain_discriminant"])
def test_public_argument_encoder_cannot_omit_selected_context(missing):
    selected = options()
    selected.pop(missing)
    with pytest.raises(TypeError, match=missing):
        iroha_python.encode_contract_arguments_v1(b"not an artifact", "quote", **selected)


@pytest.mark.parametrize("artifact, message", [(b"", "artifact must contain"), (b"not an artifact", "invalid contract artifact")])
def test_public_argument_encoder_refuses_missing_or_invalid_artifact_without_signing(artifact, message):
    with pytest.raises(ValueError, match=message):
        iroha_python.encode_contract_arguments_v1(artifact, "quote", **options())
