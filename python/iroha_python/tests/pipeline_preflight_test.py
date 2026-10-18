"""`GET /v1/pipeline/preflight` parsing against the Rust-produced Torii body.

`fixtures/torii/pipeline_preflight.json` is generated from Torii's `PipelinePreflightResponse`
by `cargo test -p iroha_torii --lib pipeline_preflight_fixture` and is never hand-edited, so
these tests pin the SDK to exactly the fields the node serves.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from iroha_python import ToriiPipelinePreflight, ToriiStatusPayload
from iroha_python.client import PIPELINE_STALL_BLOCK_CADENCES


def _fixture_text() -> str:
    for directory in Path(__file__).resolve().parents:
        path = directory / "fixtures" / "torii" / "pipeline_preflight.json"
        if path.is_file():
            return path.read_text(encoding="utf-8")
    raise FileNotFoundError("fixtures/torii/pipeline_preflight.json")


FIXTURE_TEXT = _fixture_text()


def served() -> dict[str, Any]:
    """Return a fresh copy of the exact body Torii serves."""

    return json.loads(FIXTURE_TEXT)


@dataclass(frozen=True)
class _LivenessStatus:
    """The `/status` facts the stall classifier reads, judged by `ToriiStatusPayload`'s code."""

    queue_size: int
    time_since_last_non_empty_block_ms: int
    time_since_last_block_ms: int = 0

    liveness_elapsed_ms = ToriiStatusPayload.liveness_elapsed_ms
    is_queue_stalled = ToriiStatusPayload.is_queue_stalled


def test_fixture_carries_exactly_the_served_sections() -> None:
    payload = served()
    assert list(payload) == [
        "schema_version",
        "chain_height",
        "sumeragi",
        "admission",
        "block",
        "pipeline",
        "queue",
        "fees",
    ]
    assert list(payload["sumeragi"]) == ["block_cadence_ms"]


def test_pipeline_preflight_parses_every_served_field_of_the_rust_sample() -> None:
    payload = served()
    preflight = ToriiPipelinePreflight.from_payload(payload)

    assert preflight.schema_version == 1
    assert preflight.chain_height == 42
    assert dict(preflight.sumeragi) == {"block_cadence_ms": 1_000}
    assert preflight.block_cadence_ms == 1_000
    assert dict(preflight.admission) == {
        "max_signatures": 16,
        "max_instructions": 4_096,
        "max_tx_bytes": 1_048_576,
        "max_decompressed_bytes": 4_194_304,
        "max_metadata_depth": 8,
    }
    assert dict(preflight.block) == {"max_transactions": 512}
    assert dict(preflight.pipeline) == {
        "signature_batch_max_ed25519": 64,
        "signature_batch_max_secp256k1": 32,
        "signature_batch_max_pqc": 12,
        "signature_batch_max_bls": 24,
        "overlay_max_instructions": 2_048,
        "ivm_max_cycles_upper_bound": 2_000_000,
        "ivm_admission_cycle_limit": 1_000_000,
        "ivm_max_decoded_instructions": 131_072,
    }
    assert dict(preflight.queue) == {"size": 3, "queued": 2, "inflight": 1}
    assert dict(preflight.fees) == payload["fees"]
    assert preflight.fees["base_fee"] == "0.1"
    assert preflight.fees["per_gas_unit_fee"] == "0.00005"
    assert len(preflight.fees["successful_claim_fee_exempt_authorities"]) == 1
    assert dict(preflight.raw) == payload


def test_stall_threshold_is_twenty_served_block_cadences() -> None:
    preflight = ToriiPipelinePreflight.from_payload(served())
    threshold = 20 * 1_000

    assert PIPELINE_STALL_BLOCK_CADENCES == 20
    assert preflight.stall_threshold_ms == threshold
    assert preflight.is_status_stalled(_LivenessStatus(1, threshold)) is False
    assert preflight.is_status_stalled(_LivenessStatus(1, threshold + 1)) is True
    assert preflight.is_status_stalled(_LivenessStatus(0, threshold + 1)) is False
    # Before the first non-empty block the elapsed time since any block is used.
    assert preflight.is_status_stalled(_LivenessStatus(1, 0, threshold + 1)) is True
    assert preflight.is_status_stalled(_LivenessStatus(1, 0, threshold)) is False

    slow = served()
    slow["sumeragi"]["block_cadence_ms"] = 5_000
    assert ToriiPipelinePreflight.from_payload(slow).stall_threshold_ms == 100_000


@pytest.mark.parametrize("field", ["block_time_ms", "commit_time_ms", "stall_threshold_ms"])
def test_pipeline_preflight_rejects_the_retired_sumeragi_timing_fields(field: str) -> None:
    payload = served()
    payload["sumeragi"][field] = 6_000
    with pytest.raises(ValueError, match=rf"`sumeragi` fields are not canonical: unsupported {field}"):
        ToriiPipelinePreflight.from_payload(payload)


@pytest.mark.parametrize(
    ("value", "error", "message"),
    [
        (None, ValueError, r"`sumeragi` fields are not canonical: missing block_cadence_ms"),
        (0, ValueError, r"sumeragi\.block_cadence_ms must be positive"),
        ("1000", TypeError, r"sumeragi\.block_cadence_ms must be an integer"),
        (True, TypeError, r"sumeragi\.block_cadence_ms must be an integer"),
    ],
)
def test_pipeline_preflight_requires_a_positive_integer_block_cadence(
    value: Any, error: type[Exception], message: str
) -> None:
    payload = served()
    if value is None:
        del payload["sumeragi"]["block_cadence_ms"]
    else:
        payload["sumeragi"]["block_cadence_ms"] = value
    with pytest.raises(error, match=message):
        ToriiPipelinePreflight.from_payload(payload)


@pytest.mark.parametrize("section", [None, "admission", "block", "pipeline", "queue", "fees"])
def test_pipeline_preflight_rejects_fields_torii_does_not_serve(section: Any) -> None:
    payload = served()
    target = payload if section is None else payload[section]
    target["unserved_field"] = 1
    with pytest.raises(ValueError, match=r"fields are not canonical: unsupported unserved_field"):
        ToriiPipelinePreflight.from_payload(payload)


def test_pipeline_preflight_rejects_missing_current_cycle_limit() -> None:
    payload = served()
    del payload["pipeline"]["ivm_admission_cycle_limit"]

    with pytest.raises(ValueError, match="missing ivm_admission_cycle_limit"):
        ToriiPipelinePreflight.from_payload(payload)


def test_pipeline_preflight_requires_positive_current_cycle_limits() -> None:
    payload = served()
    payload["pipeline"]["ivm_max_cycles_upper_bound"] = 0

    with pytest.raises(ValueError, match=r"pipeline\.ivm_max_cycles_upper_bound must be positive"):
        ToriiPipelinePreflight.from_payload(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fee_sink_account_id", "fees@system"),
        ("sponsor_vault_custody_account_id", "vault@system"),
        ("successful_claim_fee_exempt_authorities", ["authority@system"]),
    ],
)
def test_pipeline_preflight_rejects_alias_shaped_fee_accounts(field: str, value: Any) -> None:
    payload = served()
    payload["fees"][field] = value

    with pytest.raises(ValueError, match="exact canonical I105 account id"):
        ToriiPipelinePreflight.from_payload(payload)


@pytest.mark.parametrize(
    ("field", "value", "error", "message"),
    [
        ("fee_asset_id", "", TypeError, r"fees\.fee_asset_id must be a non-empty string"),
        ("base_fee", 0, TypeError, r"fees\.base_fee must be a non-empty string"),
        (
            "successful_claim_fee_exempt_authorities",
            None,
            TypeError,
            r"successful_claim_fee_exempt_authorities must be an array",
        ),
    ],
)
def test_pipeline_preflight_requires_the_served_fee_values(
    field: str, value: Any, error: type[Exception], message: str
) -> None:
    payload = served()
    payload["fees"][field] = value
    with pytest.raises(error, match=message):
        ToriiPipelinePreflight.from_payload(payload)

    relay = served()
    relay["fees"]["settlement_mode"] = "lane_relay_burn"
    with pytest.raises(ValueError, match="unsupported settlement_mode"):
        ToriiPipelinePreflight.from_payload(relay)
