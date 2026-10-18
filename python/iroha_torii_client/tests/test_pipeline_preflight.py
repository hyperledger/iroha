"""`GET /v1/pipeline/preflight` parsing against the Rust-produced Torii body.

`fixtures/torii/pipeline_preflight.json` is generated from Torii's `PipelinePreflightResponse`
by `cargo test -p iroha_torii --lib pipeline_preflight_fixture` and is never hand-edited, so
these tests pin the client to exactly the fields the node serves.
"""

from __future__ import annotations

import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import pytest
from client_test_support import canonical_hash
from sumeragi_exact_json_test_support import RecordingSession, StubResponse

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from iroha_torii_client import (  # noqa: E402  (import depends on sys.path mutation)
    PIPELINE_STALL_BLOCK_CADENCES,
    PipelinePreflight,
    PipelinePreflightSumeragi,
    ToriiClient,
    ToriiOperatorSigningContext,
)
from iroha_torii_client._account_id import decode_canonical_i105_account_id  # noqa: E402
from iroha_torii_client.client import StatusPayload  # noqa: E402
from iroha_torii_client.mock import _MockState  # noqa: E402


def _fixture_text() -> str:
    for directory in Path(__file__).resolve().parents:
        path = directory / "fixtures" / "torii" / "pipeline_preflight.json"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError("fixtures/torii/pipeline_preflight.json")


FIXTURE_TEXT = _fixture_text()


def _served() -> Dict[str, Any]:
    return json.loads(FIXTURE_TEXT)


def _operator_context() -> ToriiOperatorSigningContext:
    return ToriiOperatorSigningContext(
        network_id=canonical_hash(0xA5),
        public_key="ed0120" + "66" * 32,
        signer=lambda _message: b"\x55" * 64,
    )


def _fetch(payload: Dict[str, Any]) -> PipelinePreflight:
    session = RecordingSession()
    session.queue(StubResponse(payload=payload))
    client = ToriiClient(
        "https://node.test",
        session=session,
        operator_signing_context=_operator_context(),
    )
    preflight = client.get_pipeline_preflight()
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["url"].endswith("/v1/pipeline/preflight")
    return preflight


def _parse(payload: Dict[str, Any]) -> PipelinePreflight:
    client = ToriiClient("https://node.test", session=RecordingSession())
    return client._parse_pipeline_preflight(payload, context="pipeline preflight")


@dataclass(frozen=True)
class _LivenessStatus:
    """The `/status` facts the stall classifier reads, judged by `StatusPayload`'s own code."""

    queue_size: int
    time_since_last_non_empty_block_ms: int
    time_since_last_block_ms: int = 0

    liveness_elapsed_ms = StatusPayload.liveness_elapsed_ms
    is_queue_stalled = StatusPayload.is_queue_stalled


def _status(queue_size: int, non_empty_elapsed_ms: int, block_elapsed_ms: int = 0) -> Any:
    return _LivenessStatus(queue_size, non_empty_elapsed_ms, block_elapsed_ms)


def test_fixture_carries_exactly_the_served_sections() -> None:
    served = _served()
    assert list(served) == [
        "schema_version",
        "chain_height",
        "sumeragi",
        "admission",
        "block",
        "pipeline",
        "queue",
        "fees",
    ]
    assert list(served["sumeragi"]) == ["block_cadence_ms"]


def test_get_pipeline_preflight_parses_every_served_field_of_the_rust_sample() -> None:
    served = _served()
    preflight = _fetch(served)

    assert preflight.schema_version == 1
    assert preflight.chain_height == 42
    assert preflight.sumeragi == PipelinePreflightSumeragi(block_cadence_ms=1_000)
    assert vars(preflight.admission) == {
        "max_signatures": 16,
        "max_instructions": 4_096,
        "max_tx_bytes": 1_048_576,
        "max_decompressed_bytes": 4_194_304,
        "max_metadata_depth": 8,
    }
    assert preflight.block.max_transactions == 512
    assert vars(preflight.pipeline) == {
        "signature_batch_max_ed25519": 64,
        "signature_batch_max_secp256k1": 32,
        "signature_batch_max_pqc": 12,
        "signature_batch_max_bls": 24,
        "overlay_max_instructions": 2_048,
        "ivm_max_cycles_upper_bound": 2_000_000,
        "ivm_admission_cycle_limit": 1_000_000,
        "ivm_max_decoded_instructions": 131_072,
    }
    assert vars(preflight.queue) == {"size": 3, "queued": 2, "inflight": 1}
    assert vars(preflight.fees) == {
        **served["fees"],
        "base_fee": "0.1",
        "per_byte_fee": "0.0002",
        "per_instruction_fee": "0.001",
        "per_gas_unit_fee": "0.00005",
    }
    assert len(preflight.fees.successful_claim_fee_exempt_authorities) == 1
    assert preflight.fees.fee_sink_account_id != preflight.fees.sponsor_vault_custody_account_id
    assert preflight.raw == served


def test_stall_threshold_is_twenty_served_block_cadences() -> None:
    preflight = _fetch(_served())
    threshold = 20 * 1_000

    assert PIPELINE_STALL_BLOCK_CADENCES == 20
    assert preflight.stall_threshold_ms == threshold
    assert preflight.is_status_stalled(_status(1, threshold)) is False
    assert preflight.is_status_stalled(_status(1, threshold + 1)) is True
    assert preflight.is_status_stalled(_status(0, threshold + 1)) is False
    # Before the first non-empty block the elapsed time since any block is used.
    assert preflight.is_status_stalled(_status(1, 0, threshold + 1)) is True
    assert preflight.is_status_stalled(_status(1, 0, threshold)) is False

    slow = _served()
    slow["sumeragi"]["block_cadence_ms"] = 5_000
    assert _parse(slow).stall_threshold_ms == 100_000


@pytest.mark.parametrize("field", ["block_time_ms", "commit_time_ms", "stall_threshold_ms"])
def test_pipeline_preflight_rejects_the_retired_sumeragi_timing_fields(field: str) -> None:
    payload = _served()
    payload["sumeragi"][field] = 6_000
    with pytest.raises(
        RuntimeError,
        match=rf"pipeline preflight\.sumeragi contains unsupported fields: {field}",
    ):
        _parse(payload)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        (None, r"sumeragi\.block_cadence_ms must be an integer"),
        (0, r"sumeragi\.block_cadence_ms must be positive"),
        ("1000", r"sumeragi\.block_cadence_ms must be an integer"),
        (True, r"sumeragi\.block_cadence_ms must be an integer"),
    ],
)
def test_pipeline_preflight_requires_a_positive_integer_block_cadence(
    value: Any, message: str
) -> None:
    payload = _served()
    if value is None:
        del payload["sumeragi"]["block_cadence_ms"]
    else:
        payload["sumeragi"]["block_cadence_ms"] = value
    with pytest.raises(RuntimeError, match=message):
        _parse(payload)


@pytest.mark.parametrize(
    "section", [None, "admission", "block", "pipeline", "queue", "fees"]
)
def test_pipeline_preflight_rejects_fields_torii_does_not_serve(section: Any) -> None:
    payload = _served()
    target = payload if section is None else payload[section]
    target["unserved_field"] = 1
    with pytest.raises(RuntimeError, match=r"contains unsupported fields: unserved_field"):
        _parse(payload)


def test_get_pipeline_preflight_rejects_retired_signature_batch_alias() -> None:
    payload = _served()
    payload["pipeline"]["signature_batch_max"] = 0
    with pytest.raises(
        RuntimeError,
        match=r"pipeline contains unsupported fields: signature_batch_max",
    ):
        _fetch(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("ivm_max_cycles_upper_bound", None, r"pipeline\.ivm_max_cycles_upper_bound must be an integer"),
        ("ivm_admission_cycle_limit", 0, r"pipeline\.ivm_admission_cycle_limit must be positive"),
    ],
)
def test_pipeline_preflight_requires_positive_current_cycle_limits(
    field: str, value: Any, message: str
) -> None:
    payload = _served()
    if value is None:
        del payload["pipeline"][field]
    else:
        payload["pipeline"][field] = value
    with pytest.raises(RuntimeError, match=message):
        _parse(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fee_sink_account_id", "fees@system"),
        ("sponsor_vault_custody_account_id", "vault@system"),
        ("successful_claim_fee_exempt_authorities", ["authority@system"]),
    ],
)
def test_pipeline_preflight_rejects_alias_fee_accounts(field: str, value: Any) -> None:
    payload = _served()
    payload["fees"][field] = value
    with pytest.raises(ValueError, match="exact canonical I105 account id"):
        _parse(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("fee_asset_id", None, r"fees\.fee_asset_id must be a non-empty string"),
        ("base_fee", 0, r"fees\.base_fee must be a non-empty string"),
        (
            "successful_claim_fee_exempt_authorities",
            None,
            r"successful_claim_fee_exempt_authorities must be a list",
        ),
    ],
)
def test_pipeline_preflight_requires_the_served_fee_values(
    field: str, value: Any, message: str
) -> None:
    payload = _served()
    if value is None:
        del payload["fees"][field]
    else:
        payload["fees"][field] = value
    with pytest.raises(RuntimeError, match=message):
        _parse(payload)

    relay = _served()
    relay["fees"]["settlement_mode"] = "lane_relay_burn"
    with pytest.raises(RuntimeError, match="unsupported fields: settlement_mode"):
        _parse(relay)


def test_mock_preflight_matches_the_served_field_sets() -> None:
    state = _MockState()
    mock = copy.deepcopy(state.pipeline_preflight)
    served = _served()
    assert list(mock) == list(served)
    for section in ("sumeragi", "admission", "block", "pipeline", "queue", "fees"):
        assert list(mock[section]) == list(served[section]), section
    parsed = _parse(mock)
    assert parsed.stall_threshold_ms == PIPELINE_STALL_BLOCK_CADENCES * parsed.sumeragi.block_cadence_ms


def test_mock_preflight_fee_accounts_have_a_valid_seeded_controller() -> None:
    fees = _MockState().pipeline_preflight["fees"]
    # Pin the independently specified RFC 8032 key, not a second address literal.
    canonical = b"\x02\x00\x01\x20" + bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    for field in ("fee_sink_account_id", "sponsor_vault_custody_account_id"):
        assert decode_canonical_i105_account_id(
            fees[field], expected_discriminant=0x02F1
        ) == canonical
