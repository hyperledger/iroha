"""Canonical identifier-resolution receipt encoding and verification."""

from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _require_exact_non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{context} must be a non-empty string")
    if stripped != value:
        raise ValueError(f"{context} must not contain surrounding whitespace")
    return value


_IDENTIFIER_COMPACT_ALGORITHM_TAGS = {
    0x01: 0,  # Ed25519
    0x04: 1,  # secp256k1
    0x03: 2,  # BLS normal
    0x05: 3,  # BLS small
    0x02: 4,  # ML-DSA
    0x0A: 5,  # GOST R 34.10-2012 256 A
    0x0B: 6,  # GOST R 34.10-2012 256 B
    0x0C: 7,  # GOST R 34.10-2012 256 C
    0x0D: 8,  # GOST R 34.10-2012 512 A
    0x0E: 9,  # GOST R 34.10-2012 512 B
    0x0F: 10,  # SM2
}

_IDENTIFIER_PUBLIC_KEY_MULTICODEC = {
    0xED: "ed25519",
    0xEE: "ml-dsa",
    0xEA: "bls_normal",
    0xE7: "secp256k1",
    0xEB: "bls_small",
    0x1200: "gost3410-2012-256-paramset-a",
    0x1201: "gost3410-2012-256-paramset-b",
    0x1202: "gost3410-2012-256-paramset-c",
    0x1203: "gost3410-2012-512-paramset-a",
    0x1204: "gost3410-2012-512-paramset-b",
    0x1306: "sm2",
}


def _identifier_compact_length(value: int) -> bytes:
    if value < 0:
        raise ValueError("Norito compact length must be non-negative")
    remaining = int(value)
    out = bytearray()
    while remaining >= 0x80:
        out.append((remaining & 0x7F) | 0x80)
        remaining >>= 7
    out.append(remaining)
    return bytes(out)


def _identifier_sized_field(payload: Union[bytes, bytearray, memoryview]) -> bytes:
    data = bytes(payload)
    return _identifier_compact_length(len(data)) + data


def _identifier_u32(value: int, context: str) -> bytes:
    integer = _identifier_unsigned_integer(value, context)
    if integer > 0xFFFF_FFFF:
        raise ValueError(f"{context} must fit in u32")
    return integer.to_bytes(4, "little")


def _identifier_u64(value: Any, context: str) -> bytes:
    integer = _identifier_unsigned_integer(value, context)
    if integer > 0xFFFF_FFFF_FFFF_FFFF:
        raise ValueError(f"{context} must fit in u64")
    return integer.to_bytes(8, "little")


def _identifier_unsigned_integer(value: Any, context: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{context} must be a non-negative integer")
    if isinstance(value, int):
        integer = value
    elif isinstance(value, str) and value.isdigit():
        integer = int(value, 10)
    else:
        raise TypeError(f"{context} must be a non-negative integer")
    if integer < 0:
        raise ValueError(f"{context} must be a non-negative integer")
    return integer


def _identifier_string(value: Any, context: str) -> bytes:
    text = _require_non_empty_string(value, context)
    data = text.encode("utf-8")
    return _identifier_compact_length(len(data)) + data


def _identifier_exact_string(value: Any, context: str) -> bytes:
    text = _require_exact_non_empty_string(value, context)
    data = text.encode("utf-8")
    return _identifier_compact_length(len(data)) + data


def _identifier_byte_vec(payload: Union[bytes, bytearray, memoryview]) -> bytes:
    data = bytes(payload)
    encoded = bytearray(8 + 2 * len(data))
    encoded[:8] = len(data).to_bytes(8, "little")
    encoded[8::2] = b"\x01" * len(data)
    encoded[9::2] = data
    return bytes(encoded)


def _identifier_raw_byte_vec(payload: Union[bytes, bytearray, memoryview]) -> bytes:
    data = bytes(payload)
    return len(data).to_bytes(8, "little") + data


def _identifier_network_id_payload(raw: Any) -> bytes:
    value = _require_exact_non_empty_string(raw, "payload.network_id")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("payload.network_id must be an exact 32-byte lowercase hex literal")
    if int(value[-1], 16) % 2 == 0:
        raise ValueError("payload.network_id must be a marked genesis hash")
    return bytes.fromhex(value)


def _identifier_policy_id_payload(raw: Any) -> bytes:
    value = _require_exact_non_empty_string(raw, "payload.policy_id")
    parts = value.split("#", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("payload.policy_id must use kind#rule")
    if parts[0].strip() != parts[0]:
        raise ValueError("payload.policy_id.kind must not contain surrounding whitespace")
    if parts[1].strip() != parts[1]:
        raise ValueError("payload.policy_id.rule must not contain surrounding whitespace")
    return b"".join(
        (
            _identifier_sized_field(_identifier_string(parts[0], "payload.policy_id.kind")),
            _identifier_sized_field(_identifier_string(parts[1], "payload.policy_id.rule")),
        )
    )


def _identifier_hash_bytes(raw: Any, context: str) -> bytes:
    value = _require_exact_non_empty_string(raw, context)
    body = value
    if body.lower().startswith("hash:"):
        body = body[5:]
    if body.startswith(("0x", "0X")):
        body = body[2:]
    if "#" in body:
        body = body.split("#", 1)[0]
    if len(body) != 64:
        raise ValueError(f"{context} must contain 32 bytes")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"{context} contains non-hex characters") from exc


def _identifier_hex_bytes(raw: Any, context: str) -> bytes:
    value = _require_non_empty_string(raw, context)
    body = value.strip()
    if body.startswith(("0x", "0X")):
        body = body[2:]
    if len(body) % 2 != 0:
        raise ValueError(f"{context} must contain an even number of hex characters")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"{context} contains non-hex characters") from exc


def _identifier_exact_hex_bytes(raw: Any, context: str) -> bytes:
    value = _require_exact_non_empty_string(raw, context)
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) % 2 != 0:
        raise ValueError(f"{context} must contain an even number of hex characters")
    try:
        return bytes.fromhex(body)
    except ValueError as exc:
        raise ValueError(f"{context} contains non-hex characters") from exc


def _identifier_exact_tag(raw: Any, context: str) -> str:
    value = _require_exact_non_empty_string(raw, context)
    if value != value.lower():
        raise ValueError(f"{context} must be an exact lowercase RAM-LFE tag")
    return value


def _identifier_backend_tag(raw: Any) -> int:
    value = _identifier_exact_tag(raw, "payload.execution.backend")
    tags = {
        "hkdf-sha3-512-prf-v1": 0,
        "bfv-affine-v1": 1,
        "bfv-programmed-v1": 2,
    }
    try:
        return tags[value]
    except KeyError as exc:
        raise ValueError(f"unsupported RAM-LFE backend: {value}") from exc


def _identifier_verification_mode_tag(raw: Any) -> int:
    value = _identifier_exact_tag(raw, "payload.execution.verification_mode")
    tags = {"signed": 0, "proof": 1}
    try:
        return tags[value]
    except KeyError as exc:
        raise ValueError(f"unsupported RAM-LFE verification mode: {value}") from exc


def _identifier_optional_u64(value: Any, context: str) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + _identifier_sized_field(_identifier_u64(value, context))


def _identifier_program_id_payload(raw: Any, context: str) -> bytes:
    return _identifier_sized_field(_identifier_exact_string(raw, context))


def _identifier_prefixed_hash_payload(raw: Any, prefix: str, context: str) -> bytes:
    value = _require_exact_non_empty_string(raw, context)
    body = value[len(prefix) :] if value.lower().startswith(prefix) else value
    digest = _identifier_hash_bytes(body, context)
    return _identifier_compact_length(len(digest)) + digest


def _identifier_uaid_payload(raw: Any, context: str) -> bytes:
    value = _require_exact_non_empty_string(raw, context)
    prefix = "uaid:"
    body = value[len(prefix) :] if value.startswith(prefix) else ""
    if (
        len(body) != 64
        or any(character not in "0123456789abcdef" for character in body)
    ):
        raise ValueError(
            f"{context} must be an exact canonical uaid:<64 lowercase hex> literal"
        )
    if int(body[-1], 16) % 2 == 0:
        raise ValueError(f"{context} must have least significant bit set to 1")
    digest = bytes.fromhex(body)
    return _identifier_compact_length(len(digest)) + digest


def _identifier_execution_payload(execution: Any) -> bytes:
    record = _require_mapping(execution, "payload.execution")
    return b"".join(
        (
            _identifier_sized_field(
                _identifier_program_id_payload(
                    record.get("program_id"), "payload.execution.program_id"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("program_digest"), "payload.execution.program_digest"
                )
            ),
            _identifier_sized_field(
                _identifier_u32(
                    _identifier_backend_tag(record.get("backend")), "payload.execution.backend"
                )
            ),
            _identifier_sized_field(
                _identifier_u32(
                    _identifier_verification_mode_tag(record.get("verification_mode")),
                    "payload.execution.verification_mode",
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("input_ciphertext_hash"), "payload.execution.input_ciphertext_hash"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("output_ciphertext_hash"), "payload.execution.output_ciphertext_hash"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("parameter_digest"), "payload.execution.parameter_digest"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("evaluation_key_digest"), "payload.execution.evaluation_key_digest"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(record.get("output_hash"), "payload.execution.output_hash")
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("associated_data_hash"), "payload.execution.associated_data_hash"
                )
            ),
            _identifier_sized_field(
                _identifier_u64(record.get("executed_at_ms"), "payload.execution.executed_at_ms")
            ),
            _identifier_sized_field(
                _identifier_optional_u64(
                    record.get("expires_at_ms"), "payload.execution.expires_at_ms"
                )
            ),
        )
    )


def _identifier_output_opening_payload(payload: Any) -> bytes:
    record = _require_mapping(payload, "payload.opening.payload")
    return b"".join(
        (
            _identifier_sized_field(
                _identifier_program_id_payload(
                    record.get("program_id"), "payload.opening.payload.program_id"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("input_ciphertext_hash"),
                    "payload.opening.payload.input_ciphertext_hash",
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("output_ciphertext_hash"),
                    "payload.opening.payload.output_ciphertext_hash",
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("parameter_digest"), "payload.opening.payload.parameter_digest"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("evaluation_key_digest"),
                    "payload.opening.payload.evaluation_key_digest",
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(
                    record.get("opened_output_hash"), "payload.opening.payload.opened_output_hash"
                )
            ),
            _identifier_sized_field(
                _identifier_u64(record.get("opened_at_ms"), "payload.opening.payload.opened_at_ms")
            ),
            _identifier_sized_field(
                _identifier_optional_u64(
                    record.get("expires_at_ms"), "payload.opening.payload.expires_at_ms"
                )
            ),
        )
    )


def _identifier_output_opening(opening: Any) -> bytes:
    record = _require_mapping(opening, "payload.opening")
    return b"".join(
        (
            _identifier_sized_field(_identifier_output_opening_payload(record.get("payload"))),
            _identifier_sized_field(
                _identifier_byte_vec(
                    _identifier_exact_hex_bytes(
                        record.get("signature"), "payload.opening.signature"
                    )
                )
            ),
        )
    )


def _identifier_account_id_payload(
    account_id: Any,
    decode_i105: Callable[[str], bytes],
) -> bytes:
    literal = _require_exact_non_empty_string(account_id, "payload.account_id")
    if "@" in literal:
        raise ValueError("payload.account_id must be a canonical I105 account id")
    canonical = decode_i105(literal)
    if len(canonical) < 4:
        raise ValueError("payload.account_id contains an invalid account address payload")
    controller_tag = canonical[1]
    if controller_tag != 0:
        raise ValueError(
            "payload.account_id multisig controllers are not supported by this verifier"
        )
    curve_id = canonical[2]
    key_len = canonical[3]
    public_key = canonical[4:]
    if len(public_key) != key_len:
        raise ValueError("payload.account_id contains an invalid single-key controller")
    try:
        compact_tag = _IDENTIFIER_COMPACT_ALGORITHM_TAGS[curve_id]
    except KeyError as exc:
        raise ValueError(
            f"payload.account_id uses unsupported public-key curve {curve_id}"
        ) from exc
    public_key_payload = _identifier_byte_vec(bytes((compact_tag,)) + public_key)
    return _identifier_u32(0, "payload.account_id.controller") + _identifier_sized_field(
        public_key_payload
    )


def _identifier_normalize_attestation(attestation: Any) -> Dict[str, Any]:
    record = _require_mapping(attestation, "identifier receipt attestation")
    kind = _require_exact_non_empty_string(
        record.get("kind"), "identifier receipt attestation.kind"
    )
    if kind == "signed":
        if record.get("proof_backend") is not None or record.get("proof_b64") is not None:
            raise ValueError(
                "identifier receipt attestation signed attestation must not include proof fields"
            )
        signature = _identifier_exact_hex_bytes(
            record.get("signature"), "identifier receipt attestation.signature"
        )
        return {"kind": "signed", "signature": signature.hex().upper()}
    if kind == "proof":
        if record.get("signature") is not None:
            raise ValueError(
                "identifier receipt attestation proof attestation must not include signature"
            )
        proof_backend = _require_exact_non_empty_string(
            record.get("proof_backend"),
            "identifier receipt attestation.proof_backend",
        )
        proof_b64 = _require_exact_non_empty_string(
            record.get("proof_b64"), "identifier receipt attestation.proof_b64"
        )
        return {"kind": "proof", "proof_backend": proof_backend, "proof_b64": proof_b64}
    raise ValueError("identifier receipt attestation.kind must be signed or proof")


def _identifier_proof_box_payload(attestation: Mapping[str, Any]) -> bytes:
    proof_backend = _require_exact_non_empty_string(
        attestation.get("proof_backend"), "attestation.proof_backend"
    )
    try:
        proof = base64.b64decode(
            _require_exact_non_empty_string(attestation.get("proof_b64"), "attestation.proof_b64"),
            validate=True,
        )
    except binascii.Error as exc:
        raise ValueError("attestation.proof_b64 must be valid base64") from exc
    return b"".join(
        (
            _identifier_sized_field(_identifier_string(proof_backend, "attestation.proof_backend")),
            _identifier_sized_field(_identifier_raw_byte_vec(proof)),
        )
    )


def _identifier_decode_varint(data: bytes, offset: int, context: str) -> Tuple[int, int]:
    value = 0
    shift = 0
    index = offset
    while index < len(data):
        byte = data[index]
        value |= (byte & 0x7F) << shift
        index += 1
        if (byte & 0x80) == 0:
            return value, index
        shift += 7
        if shift > 63:
            raise ValueError(f"{context} contains an invalid multihash varint")
    raise ValueError(f"{context} contains a truncated multihash varint")


def _identifier_decode_public_key(value: Any, context: str) -> Tuple[str, bytes]:
    literal = _require_exact_non_empty_string(value, context)
    prefixed_algorithm: Optional[str] = None
    multihash_literal = literal
    if ":" in literal:
        prefix, multihash_literal = literal.split(":", 1)
        prefixed_algorithm = prefix.lower()
    if multihash_literal.startswith(("0x", "0X")):
        raise ValueError(f"{context} must be a bare multihash hex literal")
    if len(multihash_literal) % 2 != 0:
        raise ValueError(f"{context} must contain an even number of hex characters")
    try:
        data = bytes.fromhex(multihash_literal)
    except ValueError as exc:
        raise ValueError(f"{context} contains non-hex characters") from exc
    code, offset = _identifier_decode_varint(data, 0, context)
    digest_len, offset = _identifier_decode_varint(data, offset, context)
    payload = data[offset:]
    if len(payload) != digest_len:
        raise ValueError(f"{context} multihash payload length does not match its digest header")
    try:
        algorithm = _IDENTIFIER_PUBLIC_KEY_MULTICODEC[code]
    except KeyError as exc:
        raise ValueError(f"{context} uses unsupported multihash code 0x{code:x}") from exc
    if (
        prefixed_algorithm
        and prefixed_algorithm != algorithm
        and not (prefixed_algorithm == "mldsa" and algorithm == "ml-dsa")
    ):
        raise ValueError(f"{context} algorithm prefix does not match the multihash payload")
    return algorithm, payload


def _identifier_iroha_prehash(message: bytes) -> bytes:
    digest = bytearray(hashlib.blake2b(message, digest_size=32).digest())
    digest[-1] |= 1
    return bytes(digest)


def _identifier_verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        return False
    return True


def _require_mapping(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{context} must be an object")
    return value


def _require_non_empty_string(value: Any, context: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{context} must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError(f"{context} must be a non-empty string")
    return stripped


def encode_identifier_resolution_receipt_payload(
    payload: Mapping[str, Any],
    *,
    decode_i105: Callable[[str], bytes],
) -> bytes:
    """Encode the current receipt layout, including its signed network identity.

    ``network_id`` is the marked genesis hash as exactly 64 lowercase hexadecimal
    characters. It is the first Norito field, as in the shared Rust/SDK vectors.
    """

    record = _require_mapping(payload, "identifier resolution payload")
    return b"".join(
        (
            _identifier_sized_field(_identifier_network_id_payload(record.get("network_id"))),
            _identifier_sized_field(_identifier_policy_id_payload(record.get("policy_id"))),
            _identifier_sized_field(_identifier_execution_payload(record.get("execution"))),
            _identifier_sized_field(_identifier_output_opening(record.get("opening"))),
            _identifier_sized_field(
                _identifier_prefixed_hash_payload(
                    record.get("opaque_id"), "opaque:", "payload.opaque_id"
                )
            ),
            _identifier_sized_field(
                _identifier_hash_bytes(record.get("receipt_hash"), "payload.receipt_hash")
            ),
            _identifier_sized_field(
                _identifier_uaid_payload(record.get("uaid"), "payload.uaid")
            ),
            _identifier_sized_field(
                _identifier_account_id_payload(record.get("account_id"), decode_i105)
            ),
        )
    )


def encode_identifier_resolution_receipt_attestation(attestation: Mapping[str, Any]) -> bytes:
    """Encode an identifier-resolution receipt attestation with the shared canonical layout."""

    normalized = _identifier_normalize_attestation(attestation)
    if normalized["kind"] == "signed":
        return _identifier_u32(0, "attestation.kind") + _identifier_sized_field(
            _identifier_byte_vec(
                _identifier_hex_bytes(normalized["signature"], "attestation.signature")
            )
        )
    return _identifier_u32(1, "attestation.kind") + _identifier_sized_field(
        _identifier_proof_box_payload(normalized)
    )


def verify_identifier_resolution_receipt(
    receipt: Mapping[str, Any],
    policy_summary: Mapping[str, Any],
    *,
    decode_i105: Callable[[str], bytes],
) -> bool:
    """Verify a signed identifier-resolution receipt against a policy summary.

    Proof attestations are intentionally not accepted here; they require an
    external verifier bound to the declared proof backend.
    """

    receipt_record = _require_mapping(receipt, "identifier resolution receipt")
    payload = _require_mapping(
        receipt_record.get("payload"), "identifier resolution receipt.payload"
    )
    attestation = _identifier_normalize_attestation(receipt_record.get("attestation"))
    policy = _require_mapping(policy_summary, "identifier policy summary")
    _identifier_policy_id_payload(payload.get("policy_id"))
    receipt_policy_id = _require_exact_non_empty_string(
        payload.get("policy_id"), "receipt.payload.policy_id"
    )
    policy_id = _require_exact_non_empty_string(policy.get("policy_id"), "policy.policy_id")
    _identifier_policy_id_payload(policy_id)
    if receipt_policy_id != policy_id:
        raise ValueError(
            f"verify_identifier_resolution_receipt: receipt policy {receipt_policy_id} does not match policy {policy_id}"
        )
    if attestation["kind"] != "signed":
        raise RuntimeError(
            "verify_identifier_resolution_receipt: proof attestations require an external verifier"
        )
    algorithm, public_key = _identifier_decode_public_key(
        policy.get("resolver_public_key"),
        "policy.resolver_public_key",
    )
    if algorithm != "ed25519":
        raise RuntimeError(
            f"verify_identifier_resolution_receipt: {algorithm} verification is not available in the Python SDK"
        )
    signed_payload = encode_identifier_resolution_receipt_payload(
        payload,
        decode_i105=decode_i105,
    )
    prehash = _identifier_iroha_prehash(signed_payload)
    signature = _identifier_hex_bytes(attestation["signature"], "receipt.attestation.signature")
    return _identifier_verify_ed25519(public_key, prehash, signature)
