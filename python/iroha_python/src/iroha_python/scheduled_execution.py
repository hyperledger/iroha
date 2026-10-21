"""Native authentication of Time outputs from original registration through retries.

This API does not authenticate an application's choice of original operation or
replace its fee, artifact, account, and event policies. It has no Python crypto
or business-execution fallback.
"""
from __future__ import annotations

import json
from typing import Any

from .crypto import _crypto, _require_chain_discriminant, _require_network_id


def verify_scheduled_trigger_execution_v1(
    original_signed_registration: bytes,
    trigger_id: str,
    *,
    native_finality_proof_chain_json: str,
    expected_network_id: Any,
    expected_chain: str,
    trusted_checkpoint: bytes,
    expected_chain_discriminant: int,
) -> dict[str, Any]:
    """Authenticate the complete consecutive prefix including registration.

    The result contains Time execution-call identities, never synthetic
    transaction hashes. Its internal route is the authenticated Global root
    with no Network lane assignment. Keep the registration's external route
    receipt separately. Persist original wires and replay them on recovery.
    """
    network = _require_network_id(expected_network_id, "expected_network_id")
    prefix = _require_chain_discriminant(expected_chain_discriminant, "expected_chain_discriminant")
    for name, value, maximum in (
        ("original_signed_registration", original_signed_registration, 32 * 1024 * 1024),
        ("trusted_checkpoint", trusted_checkpoint, 68 * 1024 * 1024),
    ):
        if type(value) is not bytes or not 0 < len(value) <= maximum:
            raise ValueError(f"{name} must be bounded exact immutable bytes")
    for name, value, maximum in (
        ("trigger_id", trigger_id, 255),
        ("expected_chain", expected_chain, 1024),
        ("native_finality_proof_chain_json", native_finality_proof_chain_json, 16 * 1024 * 1024),
    ):
        if type(value) is not str or not 0 < len(value.encode("utf-8")) <= maximum:
            raise ValueError(f"{name} must be bounded exact UTF-8 text")
    verify = getattr(_crypto, "verify_scheduled_trigger_execution_v1", None)
    if not callable(verify):
        raise RuntimeError("selected native SDK lacks scheduled Time authentication")
    result = verify(
        original_signed_registration, trigger_id, native_finality_proof_chain_json,
        network, expected_chain, trusted_checkpoint,
        expected_chain_discriminant=prefix,
    )
    if type(result) is not tuple or len(result) != 2:
        raise RuntimeError("native Time verifier returned a malformed result")
    projection, checkpoint = result
    if (type(projection) is not str or type(checkpoint) is not bytes
            or not 0 < len(checkpoint) <= 68 * 1024 * 1024):
        raise RuntimeError("native Time verifier returned a malformed checkpoint")
    payload = json.loads(projection)
    if type(payload) is not dict or "promoted_checkpoint" in payload:
        raise RuntimeError("native Time verifier returned a malformed projection")
    return {**payload, "promoted_checkpoint": checkpoint}
