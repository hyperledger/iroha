from __future__ import annotations

import json

import pytest

from iroha_python.client import RuntimeUpgradeManifest, ToriiClient

from .helpers import RecordingSession, StubResponse


def test_runtime_upgrade_manifest_rejects_non_v1_abi() -> None:
    with pytest.raises(ValueError, match="abi_version` must be 1"):
        RuntimeUpgradeManifest.from_payload(
            {
                "name": "upgrade-1",
                "description": "invalid",
                "abi_version": 2,
                "abi_hash": "00" * 32,
                "added_syscalls": [],
                "added_pointer_types": [],
                "start_height": 10,
                "end_height": 20,
            }
        )


def test_propose_runtime_upgrade_serializes_v1_manifest() -> None:
    session = RecordingSession(StubResponse(payload={"ok": True, "tx_instructions": []}))
    client = ToriiClient("http://node.test", session=session, chain_discriminant=753)

    client.propose_runtime_upgrade(
        {
            "name": "ABI v1 maintenance",
            "description": "no ABI change",
            "abi_version": 1,
            "abi_hash": "aa" * 32,
            "added_syscalls": [],
            "added_pointer_types": [],
            "start_height": 100,
            "end_height": 120,
        }
    )

    payload = json.loads(session.calls[0]["data"].decode("utf-8"))
    assert payload["abi_version"] == 1
    assert payload["added_syscalls"] == []
    assert payload["added_pointer_types"] == []
