from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from iroha_torii_client import (  # noqa: E402
    ToriiClient,
    encode_identifier_resolution_receipt_attestation,
    encode_identifier_resolution_receipt_payload,
    inspect_i105_network_prefix,
    verify_identifier_resolution_receipt,
)
from iroha_torii_client.client import (  # noqa: E402
    _decode_canonical_i105_string,
    _decode_i105_string,
    _parse_i105_sentinel_and_payload,
)
from iroha_torii_client.identifier_receipts import _identifier_byte_vec  # noqa: E402

CANONICAL_OWNER = "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
CHECKSUM_VALID_ZERO_KEY_OWNER = (
    "sorauﾛ1NcMBm2dﾌBokヱDﾑﾅekAbｶﾍﾜﾇﾐMFｽヱﾋZﾘ2u4WGUMMS63EY6"
)


def test_identifier_byte_vector_encoding_is_exact_for_every_byte_value() -> None:
    payload = bytes(range(256))

    encoded = _identifier_byte_vec(payload)

    assert encoded[:8] == len(payload).to_bytes(8, "little")
    assert encoded[8::2] == b"\x01" * len(payload)
    assert encoded[9::2] == payload


def test_i105_decoder_rejects_out_of_range_numeric_discriminants() -> None:
    payload = CANONICAL_OWNER.removeprefix("sora")

    assert _decode_i105_string(f"n65535{payload}")
    prefix = inspect_i105_network_prefix(CANONICAL_OWNER, expected_chain_discriminant=0x02F1)
    assert prefix.sentinel == "sora"
    assert prefix.chain_discriminant == 0x02F1
    assert prefix.profile == "minamoto"
    numeric_prefix = inspect_i105_network_prefix(f"n65535{payload}")
    assert numeric_prefix.sentinel == "n65535"
    assert numeric_prefix.chain_discriminant == 65535
    assert numeric_prefix.profile is None
    with pytest.raises(ValueError, match="discriminant mismatch"):
        inspect_i105_network_prefix(CANONICAL_OWNER, expected_chain_discriminant=0x0171)
    for literal in (f"n65536{payload}", f"n70000{payload}"):
        with pytest.raises(ValueError, match="unsigned 16-bit"):
            _parse_i105_sentinel_and_payload(literal)
        with pytest.raises(ValueError, match="invalid account address"):
            _decode_i105_string(literal)


def test_canonical_i105_decoder_rejects_checksum_valid_malformed_controller() -> None:
    with pytest.raises(ValueError, match="invalid public key payload for declared curve"):
        _decode_canonical_i105_string(CHECKSUM_VALID_ZERO_KEY_OWNER)


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "0.000000001",
        str(1 << 128),
        str((1 << 511) - 1),
        "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824.503042047",
    ],
    ids=["zero", "nanoxor", "over-u128", "max-mantissa", "max-scaled"],
)
def test_sorafs_orderbook_xor_quantity_parser_preserves_exact_boundaries(
    value: str,
) -> None:
    assert ToriiClient._normalize_sorafs_orderbook_xor_quantity(value, "amount") == value


@pytest.mark.parametrize(
    "value",
    [
        1,
        1.0,
        True,
        None,
        "",
        "+1",
        "-1",
        " 1",
        "1 ",
        "01",
        "1.",
        ".1",
        "1.0",
        "1.000000000",
        "1e0",
        "0.0000000001",
        str(1 << 511),
        "1" * 156,
        "1" * 10_000,
    ],
    ids=[
        "json-integer",
        "json-float",
        "json-bool",
        "json-null",
        "empty",
        "plus",
        "negative",
        "leading-space",
        "trailing-space",
        "leading-zero",
        "missing-fraction",
        "missing-whole",
        "trailing-zero",
        "nine-trailing-zeros",
        "exponent",
        "over-scale",
        "mantissa-overflow",
        "text-bound-overflow",
        "oversized-input",
    ],
)
def test_sorafs_orderbook_xor_quantity_parser_rejects_adversarial_values(
    value: Any,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        ToriiClient._normalize_sorafs_orderbook_xor_quantity(value, "amount")


def test_identifier_resolution_receipt_matches_shared_vectors() -> None:
    fixture = json.loads(
        (PACKAGE_ROOT.parent / "fixtures/soracloud/identifier_receipt_vectors_v1.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["vector_set"] == "identifier-receipt-attestation-v1"

    payload_bytes = encode_identifier_resolution_receipt_payload(fixture["receipt"]["payload"])
    assert hashlib.sha256(payload_bytes).hexdigest().upper() == fixture["canonical_payload_sha256"]
    assert verify_identifier_resolution_receipt(fixture["receipt"], fixture["policy"]) is True

    network_id = fixture["receipt"]["payload"]["network_id"]
    for malformed_network in (
        None,
        "",
        network_id.upper(),
        f" {network_id}",
        f"{network_id} ",
        f"0x{network_id}",
        network_id[:-2],
        network_id + "00",
        "g" + network_id[1:],
        network_id[:-1] + "0",
    ):
        malformed_payload = dict(fixture["receipt"]["payload"], network_id=malformed_network)
        with pytest.raises((TypeError, ValueError), match=r"payload\.network_id"):
            encode_identifier_resolution_receipt_payload(malformed_payload)

    for kind in (" signed", "signed ", "Signed"):
        non_exact_kind = json.loads(json.dumps(fixture["receipt"]["attestation"]))
        non_exact_kind["kind"] = kind
        with pytest.raises(ValueError, match="identifier receipt attestation.kind"):
            encode_identifier_resolution_receipt_attestation(non_exact_kind)

    padded_backend_payload = json.loads(json.dumps(fixture["receipt"]["payload"]))
    padded_backend_payload["execution"]["backend"] = " hkdf-sha3-512-prf-v1"
    with pytest.raises(
        ValueError, match="payload.execution.backend must not contain surrounding whitespace"
    ):
        encode_identifier_resolution_receipt_payload(padded_backend_payload)

    padded_mode_payload = json.loads(json.dumps(fixture["receipt"]["payload"]))
    padded_mode_payload["execution"]["verification_mode"] = "signed "
    with pytest.raises(
        ValueError,
        match="payload.execution.verification_mode must not contain surrounding whitespace",
    ):
        encode_identifier_resolution_receipt_payload(padded_mode_payload)

    for vector in fixture["attestation_vectors"]:
        encoded = encode_identifier_resolution_receipt_attestation(vector["attestation"])
        assert len(encoded) == vector["expected_attestation_bytes"], vector["name"]
        assert hashlib.sha256(encoded).hexdigest().upper() == vector["expected_attestation_sha256"]
        if vector["attestation"]["kind"] == "signed":
            for signature in (
                f" {vector['attestation']['signature']}",
                f"{vector['attestation']['signature']} ",
            ):
                padded_signature = json.loads(json.dumps(vector["attestation"]))
                padded_signature["signature"] = signature
                with pytest.raises(
                    ValueError,
                    match="identifier receipt attestation.signature must not contain surrounding whitespace",
                ):
                    encode_identifier_resolution_receipt_attestation(padded_signature)
        if vector["attestation"]["kind"] == "proof":
            padded_proof_backend = json.loads(json.dumps(vector["attestation"]))
            padded_proof_backend["proof_backend"] = f"{padded_proof_backend['proof_backend']} "
            with pytest.raises(
                ValueError,
                match="identifier receipt attestation.proof_backend must not contain surrounding whitespace",
            ):
                encode_identifier_resolution_receipt_attestation(padded_proof_backend)

            malformed_proof_b64 = json.loads(json.dumps(vector["attestation"]))
            malformed_proof_b64["proof_b64"] = "@@@"
            with pytest.raises(ValueError, match="attestation.proof_b64 must be valid base64"):
                encode_identifier_resolution_receipt_attestation(malformed_proof_b64)

            for proof_b64 in (
                f" {vector['attestation']['proof_b64']}",
                f"{vector['attestation']['proof_b64']} ",
            ):
                padded_proof_b64 = json.loads(json.dumps(vector["attestation"]))
                padded_proof_b64["proof_b64"] = proof_b64
                with pytest.raises(
                    ValueError,
                    match="identifier receipt attestation.proof_b64 must not contain surrounding whitespace",
                ):
                    encode_identifier_resolution_receipt_attestation(padded_proof_b64)

            with pytest.raises(
                RuntimeError, match="proof attestations require an external verifier"
            ):
                verify_identifier_resolution_receipt(
                    {
                        "payload": fixture["receipt"]["payload"],
                        "attestation": vector["attestation"],
                    },
                    fixture["policy"],
                )

    for opening_signature in (
        f" {fixture['receipt']['payload']['opening']['signature']}",
        f"{fixture['receipt']['payload']['opening']['signature']} ",
    ):
        padded_opening = json.loads(json.dumps(fixture["receipt"]))
        padded_opening["payload"]["opening"]["signature"] = opening_signature
        with pytest.raises(
            ValueError,
            match="payload.opening.signature must not contain surrounding whitespace",
        ):
            verify_identifier_resolution_receipt(padded_opening, fixture["policy"])

    for policy_id in (" phone#retail", "phone#retail ", "phone #retail", "phone# retail"):
        padded_policy_id = json.loads(json.dumps(fixture["receipt"]))
        padded_policy_id["payload"]["policy_id"] = policy_id
        with pytest.raises(ValueError, match="payload.policy_id"):
            verify_identifier_resolution_receipt(padded_policy_id, fixture["policy"])

    for program_id in (" identifier_lookup_retail", "identifier_lookup_retail "):
        padded_execution_program = json.loads(json.dumps(fixture["receipt"]))
        padded_execution_program["payload"]["execution"]["program_id"] = program_id
        with pytest.raises(ValueError, match="payload.execution.program_id"):
            verify_identifier_resolution_receipt(padded_execution_program, fixture["policy"])

        padded_opening_program = json.loads(json.dumps(fixture["receipt"]))
        padded_opening_program["payload"]["opening"]["payload"]["program_id"] = program_id
        with pytest.raises(ValueError, match="payload.opening.payload.program_id"):
            verify_identifier_resolution_receipt(padded_opening_program, fixture["policy"])

    for account_id in (
        f" {fixture['receipt']['payload']['account_id']}",
        f"{fixture['receipt']['payload']['account_id']} ",
    ):
        padded_account_id = json.loads(json.dumps(fixture["receipt"]))
        padded_account_id["payload"]["account_id"] = account_id
        with pytest.raises(ValueError, match="payload.account_id"):
            verify_identifier_resolution_receipt(padded_account_id, fixture["policy"])

    hash_exactness_cases = (
        ("payload.opaque_id", ("payload", "opaque_id"), fixture["receipt"]["payload"]["opaque_id"]),
        (
            "payload.receipt_hash",
            ("payload", "receipt_hash"),
            fixture["receipt"]["payload"]["receipt_hash"],
        ),
        ("payload.uaid", ("payload", "uaid"), fixture["receipt"]["payload"]["uaid"]),
        (
            "payload.execution.program_digest",
            ("payload", "execution", "program_digest"),
            fixture["receipt"]["payload"]["execution"]["program_digest"],
        ),
        (
            "payload.opening.payload.input_ciphertext_hash",
            ("payload", "opening", "payload", "input_ciphertext_hash"),
            fixture["receipt"]["payload"]["opening"]["payload"]["input_ciphertext_hash"],
        ),
    )
    for context, path, value in hash_exactness_cases:
        for padded_value in (f" {value}", f"{value} "):
            padded_hash = json.loads(json.dumps(fixture["receipt"]))
            target = padded_hash
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = padded_value
            with pytest.raises(ValueError, match=context.replace(".", r"\.")):
                verify_identifier_resolution_receipt(padded_hash, fixture["policy"])

    canonical_uaid = fixture["receipt"]["payload"]["uaid"]
    for noncanonical_uaid in (
        canonical_uaid.removeprefix("uaid:"),
        canonical_uaid.upper(),
        "uaid:A" + canonical_uaid.removeprefix("uaid:")[1:],
    ):
        mutated = json.loads(json.dumps(fixture["receipt"]))
        mutated["payload"]["uaid"] = noncanonical_uaid
        with pytest.raises(ValueError, match=r"payload\.uaid"):
            verify_identifier_resolution_receipt(mutated, fixture["policy"])

    timestamp_exactness_cases = (
        (
            "payload.execution.executed_at_ms",
            ("payload", "execution", "executed_at_ms"),
            fixture["receipt"]["payload"]["execution"]["executed_at_ms"],
        ),
        (
            "payload.execution.expires_at_ms",
            ("payload", "execution", "expires_at_ms"),
            fixture["receipt"]["payload"]["execution"]["expires_at_ms"],
        ),
        (
            "payload.opening.payload.opened_at_ms",
            ("payload", "opening", "payload", "opened_at_ms"),
            fixture["receipt"]["payload"]["opening"]["payload"]["opened_at_ms"],
        ),
        (
            "payload.opening.payload.expires_at_ms",
            ("payload", "opening", "payload", "expires_at_ms"),
            fixture["receipt"]["payload"]["opening"]["payload"]["expires_at_ms"],
        ),
    )
    for context, path, value in timestamp_exactness_cases:
        for padded_value in (f" {value}", f"{value} "):
            padded_timestamp = json.loads(json.dumps(fixture["receipt"]))
            target = padded_timestamp
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = padded_value
            with pytest.raises((TypeError, ValueError), match=context.replace(".", r"\.")):
                verify_identifier_resolution_receipt(padded_timestamp, fixture["policy"])

    for negative in fixture["negative_cases"]:
        receipt = json.loads(json.dumps(fixture["receipt"]))
        policy = json.loads(json.dumps(fixture["policy"]))
        if negative["mutation"] == "receipt.payload.network_id":
            receipt["payload"]["network_id"] = negative["value"]
            assert encode_identifier_resolution_receipt_payload(receipt["payload"]) != payload_bytes
        elif negative["mutation"] == "receipt.payload.execution.output_ciphertext_hash":
            receipt["payload"]["execution"]["output_ciphertext_hash"] = negative["value"]
        elif negative["mutation"] == "policy.resolver_public_key":
            policy["resolver_public_key"] = negative["value"]
        elif negative["mutation"] == "policy.policy_id":
            policy["policy_id"] = negative["value"]
        elif negative["mutation"] == "receipt.attestation.signature":
            receipt["attestation"]["signature"] = negative["value"]
        elif negative["mutation"] == "receipt.attestation":
            receipt["attestation"] = negative["value"]
        else:
            raise AssertionError(f"unhandled receipt vector mutation {negative['mutation']}")

        expected_error = negative.get("expected_error_contains")
        if expected_error:
            with pytest.raises((RuntimeError, ValueError), match=expected_error):
                verify_identifier_resolution_receipt(receipt, policy)
        else:
            assert (
                verify_identifier_resolution_receipt(receipt, policy) is negative["expected_result"]
            ), negative["name"]
