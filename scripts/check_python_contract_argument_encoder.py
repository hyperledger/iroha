#!/usr/bin/env python3
"""Check an installed native encoder with a fresh same-source compiler fixture.

Run with the release consumer's already-admitted Python environment. This script
does not alter sys.path, load source shims, sign transactions or contact a node.
Its report is component evidence; source/build custody is supplied by its runner.
"""
from __future__ import annotations

import argparse
import hashlib
import inspect
import json
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture", type=Path)
    source.add_argument("--native-fixture-log", type=Path)
    arguments = parser.parse_args()
    path = arguments.fixture or arguments.native_fixture_log
    with path.open("rb") as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    require(0 < len(raw) <= 8 * 1024 * 1024, "fixture exceeds its local bound")
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if arguments.native_fixture_log:
        marker = b"IROHA_CONTRACT_ARGUMENT_FIXTURE_V1 "
        matches = [line.partition(marker)[2] for line in raw.splitlines() if marker in line]
        require(len(matches) == 1, "native test log must contain exactly one tagged fixture")
        raw = matches[0]
    fixture = json.loads(raw)
    require(type(fixture) is dict and fixture.get("schema") == "iroha.python.contract-argument-fixture.v1",
            "unexpected native fixture schema")
    require(set(fixture) == {"schema", "artifact_hex", "code_hash", "abi_hash", "chain_discriminant",
                            "payload_json", "expected_arguments_hex", "changed_payload_json",
                            "changed_arguments_hex", "foreign_payload_json"}, "unexpected fixture fields")
    require(type(fixture["chain_discriminant"]) is int and fixture["chain_discriminant"] == 369,
            "unexpected fixture presentation context")
    require(all(type(value) is str for key, value in fixture.items() if key != "chain_discriminant"),
            "fixture fields must retain their exact native representation")
    import iroha_python
    from iroha_native import load_crypto_extension

    native = load_crypto_extension()
    encode = iroha_python.encode_contract_arguments_v1
    require(encode is native.encode_contract_arguments_v1 and inspect.isbuiltin(encode),
            "public encoder must be the selected original native callable")
    artifact = bytes.fromhex(fixture["artifact_hex"])
    options = {
        "expected_code_hash_hex": fixture["code_hash"],
        "expected_abi_hash_hex": fixture["abi_hash"],
        "chain_discriminant": fixture["chain_discriminant"],
    }
    completed = []
    for payload_key, expected_key in [
        ("payload_json", "expected_arguments_hex"),
        ("changed_payload_json", "changed_arguments_hex"),
    ]:
        actual = encode(artifact, "quote", fixture[payload_key], **options)
        require(type(actual) is bytes and actual == bytes.fromhex(fixture[expected_key]),
                f"installed encoder differs from independent native ABI fixture: {payload_key}")
        completed.append(payload_key)
    require(fixture["expected_arguments_hex"] != fixture["changed_arguments_hex"],
            "changed payment quantity must have a distinct native record")
    require(encode(artifact, "ready", **options) is None, "absent arguments were not preserved")
    require(encode(artifact, "ready", None, **options) is None, "explicit absent arguments differ")
    completed.append("zero_argument_absence")

    def refuse(name, selected_artifact=artifact, entrypoint="quote", payload=None, selected_options=None):
        try:
            encode(selected_artifact, entrypoint, payload, **(options if selected_options is None else selected_options))
        except (ValueError, TypeError, OverflowError):
            completed.append(name)
        else:
            raise RuntimeError(f"installed encoder accepted {name}")

    refuse("missing_parameterized_payload")
    refuse("null_is_not_absence", entrypoint="ready", payload="null")
    refuse("empty_object_is_not_absence", entrypoint="ready", payload="{}")
    refuse("foreign_account_context", payload=fixture["foreign_payload_json"])
    refuse("wrong_code_pin", payload=fixture["payload_json"],
           selected_options={**options, "expected_code_hash_hex": "00" * 32})
    refuse("wrong_abi_pin", payload=fixture["payload_json"],
           selected_options={**options, "expected_abi_hash_hex": "00" * 32})
    refuse("wrong_chain_context", payload=fixture["payload_json"],
           selected_options={**options, "chain_discriminant": 117})
    refuse("mutable_artifact", selected_artifact=bytearray(artifact), payload=fixture["payload_json"])
    corrupted = bytes([artifact[0] ^ 1]) + artifact[1:]
    refuse("corrupted_artifact", selected_artifact=corrupted, payload=fixture["payload_json"])
    # A failed call must not alter the original encoder's selected context.
    require(encode(artifact, "quote", fixture["payload_json"], **options)
            == bytes.fromhex(fixture["expected_arguments_hex"]), "original encoding changed after refusal")
    completed.append("original_context_after_refusals")
    print(json.dumps({
        "schema": "iroha.python.contract-argument-installed-smoke.v1",
        "status": "passed",
        "fixture_sha256": hashlib.sha256(raw).hexdigest(),
        "fixture_source_sha256": source_sha256,
        "public_sdk_origin": str(Path(iroha_python.__file__).resolve()),
        "native_origin": str(Path(native.__file__).resolve()),
        "controls": completed,
        "transactions_signed": 0,
        "network_requests": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
