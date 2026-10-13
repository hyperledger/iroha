"""The high-level SDK exposes the sole native Sumeragi observation contract."""
from __future__ import annotations

from copy import deepcopy

import pytest

from iroha_python import SumeragiParamsSnapshot, SumeragiStatus, ToriiClient


def _native_status():
    return {
        "protocol_version": 1,
        "config_fingerprint": "hash:0101010101010101010101010101010101010101010101010101010101010101#B86C",
        "beacon_horizon": None, "instance": "00" * 32,
        "height": 1, "view": 0, "stage": 0, "leader": None, "proxy_tail": None,
        "high_qc_view": None, "level": 0, "start_level": 0, "t_retx_ms": 1,
        "committed_height": 0, "applied_height": 0, "awaiting": False,
        "signer": None, "unanchored": True, "abstaining": True, "halted": None,
        "footprint": {name: 0 for name in (
            "votes", "timeouts", "blocks", "exec_entries", "wants", "pending_apply",
            "sync_entries", "sync_bytes", "peers", "recent_headers", "configs",
            "cert_cache", "evidence_keys", "probe",
        )},
    }


def test_sumeragi_native_status_owns_nested_values():
    payload = _native_status()
    parsed = SumeragiStatus.from_payload(payload)
    payload["footprint"]["votes"] = 10
    assert parsed.protocol_version == 1
    assert parsed.footprint.votes == 0


@pytest.mark.parametrize("field", list(_native_status()))
def test_sumeragi_native_status_requires_every_field(field):
    payload = deepcopy(_native_status())
    del payload[field]
    with pytest.raises((TypeError, ValueError)):
        SumeragiStatus.from_payload(payload)


def test_retired_consensus_queries_are_absent():
    client = ToriiClient("http://127.0.0.1:8080")
    assert not hasattr(client, "get_sumeragi_qc")
    assert not hasattr(client, "get_sumeragi_commit_qc_typed")
    assert not hasattr(client, "get_sumeragi_phases_typed")


def test_sumeragi_params_snapshot_accepts_exactly_the_served_fields():
    served = {"block_cadence_ms": 1_000, "max_clock_drift_ms": 50, "chain_height": (1 << 64) - 1}
    params = SumeragiParamsSnapshot.from_payload(served)
    assert (params.block_cadence_ms, params.max_clock_drift_ms, params.chain_height) == (
        1_000, 50, (1 << 64) - 1,
    )
    for payload in [
        {**served, "collectors_k": 3},
        {"block_time_ms": 1_000, "max_clock_drift_ms": 50, "chain_height": 1},
        {"block_cadence_ms": 1_000, "max_clock_drift_ms": 50},
        {**served, "block_cadence_ms": 0},
        {**served, "chain_height": 1 << 64},
        {**served, "max_clock_drift_ms": True},
        {**served, "max_clock_drift_ms": "50"},
    ]:
        with pytest.raises(TypeError):
            SumeragiParamsSnapshot.from_payload(payload)
