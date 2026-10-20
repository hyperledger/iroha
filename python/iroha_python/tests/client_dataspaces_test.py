from __future__ import annotations

import base64
import json
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import requests
from iroha_torii_client.client import canonical_request_message

from iroha_python import DataspaceSpec, NetworkId, ToriiClient, plan_dataspace, write_dataspace_plan
from iroha_python.address import AccountAddress
from iroha_python.crypto import Ed25519KeyPair

FEE_PAYMENT = {
    "payer": "authority",
    "value": {"charge_limits": [], "gas_limit": None},
}
CANONICAL_GENESIS_HASH = bytes([0xA5]) * 32
NETWORK_ID = NetworkId.from_bytes(CANONICAL_GENESIS_HASH)
SETTLEMENT_PUBLIC_KEY = Ed25519KeyPair.from_private_key(bytes([0xA5]) * 32).public_key
SETTLEMENT_ACCOUNT_ID = AccountAddress.from_account(public_key=SETTLEMENT_PUBLIC_KEY).to_i105()
SETTLEMENT_ASSET_DEFINITION_ID = "61CtjvNd9T3THAR65GsMVHr82Bjc"


class FakeSession(requests.Session):
    def __init__(self, responses: list[requests.Response]):
        super().__init__()
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def request(self, method: str, url: str, **kwargs: object) -> requests.Response:
        self.calls.append(
            {
                "method": method,
                "path": urlsplit(url).path,
                "params": kwargs.get("params"),
                "data": kwargs.get("data"),
                "headers": dict(kwargs.get("headers") or {}),
                "timeout": kwargs.get("timeout"),
            }
        )
        if not self.responses:
            raise AssertionError(f"unexpected request {method} {url}")
        response = self.responses.pop(0)
        response.url = url
        return response


def response(status: int, payload: object | None = None) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    if payload is None:
        result._content = b""
    else:
        result._content = json.dumps(payload).encode("utf-8")
        result.headers["Content-Type"] = "application/json"
    return result


def canonical_hash(fill: int) -> str:
    """Build one canonical Norito ``Hash`` JSON literal for fixtures."""

    assert 0 <= fill <= 0xFF and fill & 1 == 1
    body = f"{fill:02X}" * 32
    crc = 0xFFFF
    for byte in f"hash:{body}".encode("ascii"):
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return f"hash:{body}#{crc:04X}"


def lane_config(
    *,
    lane_id: int = 0,
    shard_id: int | None = None,
    dataspace_id: int = 0,
    alias: str = "universal",
) -> dict[str, object]:
    """Return the complete canonical V1 ``LaneConfig`` JSON surface."""

    return {
        "id": lane_id,
        "shard_id": shard_id,
        "dataspace_id": dataspace_id,
        "alias": alias,
        "description": None,
        "visibility": "public",
        "lane_type": None,
        "governance": None,
        "settlement": None,
        "storage": "full_replica",
        "proof_scheme": "merkle_sha256",
        "manifest_policy": "strict",
        "confidential_compute": None,
        "scheduler": None,
        "settlement_buffer": None,
        "metadata": {},
    }


def test_plan_dataspace_generates_manifest_catalog_and_summary(tmp_path: Path) -> None:
    spec = DataspaceSpec(
        dataspace_alias="boi",
        dataspace_id=42,
        lane_alias="boi-payments",
        lane_id=7,
        governance_module="parliament",
        settlement_handle="xor_global",
        validators=["validator01"],
        route_instructions=["TransferAsset"],
    )

    plan = plan_dataspace(spec)

    assert plan.manifest["lane"] == "boi-payments"
    assert plan.manifest["quorum"] == 1
    assert 'alias = "boi"' in plan.catalog_snippet
    assert "dataspace:42" not in plan.catalog_snippet
    assert plan.summary["dataspace_id"] == 42

    outputs = write_dataspace_plan(plan, tmp_path)
    assert outputs["manifest"].read_text(encoding="utf-8").startswith("{\n")
    assert outputs["catalog"].read_text(encoding="utf-8") == plan.catalog_snippet


def test_plan_dataspace_escapes_toml_strings() -> None:
    spec = DataspaceSpec(
        dataspace_alias='boi"retail',
        dataspace_id=42,
        lane_alias='lane\none',
        lane_id=7,
        governance_module="parliament",
        settlement_handle="xor_global",
        validators=["validator01"],
        metadata={'owner"team': "payments\nops"},
        route_accounts=['alice"retail'],
        route_instructions=['Transfer"Asset'],
    )

    plan = plan_dataspace(spec)

    assert 'alias = "lane\\none"' in plan.catalog_snippet
    assert 'dataspace = "boi\\"retail"' in plan.catalog_snippet
    assert '"owner\\"team" = "payments\\nops"' in plan.catalog_snippet


@pytest.mark.parametrize(
    ("patch", "match"),
    [
        ({"dataspace_alias": ""}, "dataspace_alias"),
        ({"lane_alias": ""}, "lane_alias"),
        ({"lane_id": -1}, "lane_id"),
        ({"validators": []}, "validators"),
        ({"validators": ["validator 01"]}, "whitespace"),
        ({"validators": ["validator@is"]}, "encoded account identifier"),
        ({"quorum": 0}, "quorum"),
        ({"quorum": 3}, "quorum"),
        ({"dataspace_id": -1}, "dataspace_id"),
        ({"dataspace_hash": "not-hex"}, "dataspace_hash"),
    ],
)
def test_plan_dataspace_rejects_invalid_inputs(
    patch: dict[str, object],
    match: str,
) -> None:
    fields: dict[str, object] = {
        "dataspace_alias": "boi",
        "lane_alias": "boi-payments",
        "lane_id": 7,
        "governance_module": "parliament",
        "settlement_handle": "xor_global",
        "validators": ["validator01", "validator02"],
        "quorum": 2,
    }
    fields.update(patch)
    spec = DataspaceSpec(**fields)

    with pytest.raises(ValueError, match=match):
        plan_dataspace(spec)


@pytest.mark.parametrize(
    "name_patch",
    [
        {"manifest_name": "../escape.json"},
        {"catalog_name": "/tmp/escape.toml"},
        {"summary_name": "nested/summary.json"},
        {"space_directory_name": r"nested\\manifest.to"},
    ],
)
def test_plan_dataspace_rejects_artifact_path_traversal(
    name_patch: dict[str, str],
) -> None:
    spec = DataspaceSpec(
        dataspace_alias="boi",
        dataspace_id=42,
        lane_alias="boi-payments",
        lane_id=7,
        governance_module="parliament",
        settlement_handle="xor_global",
        validators=["validator01"],
        **name_patch,
    )

    with pytest.raises(ValueError, match="file name"):
        plan_dataspace(spec)


def test_write_dataspace_plan_rejects_tampered_artifact_path(
    tmp_path: Path,
) -> None:
    plan = plan_dataspace(
        DataspaceSpec(
            dataspace_alias="boi",
            dataspace_id=42,
            lane_alias="boi-payments",
            lane_id=7,
            governance_module="parliament",
            settlement_handle="xor_global",
            validators=["validator01"],
        )
    )
    tampered = replace(plan, manifest_name="../escape.json")

    with pytest.raises(ValueError, match="file name"):
        write_dataspace_plan(tampered, tmp_path)

    assert not (tmp_path.parent / "escape.json").exists()


def test_client_dataspace_readiness_accepts_lane_governance_status() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)
    status = {
        "lane_governance": [
            {
                "lane_id": 3,
                "alias": "boi",
                "dataspace_id": 42,
                "manifest_required": True,
                "manifest_ready": True,
            }
        ],
        "lane_governance_sealed_aliases": [],
    }

    assert client.get_dataspace("boi", status=status)["dataspace_id"] == 42
    assert client.dataspace_ready(42, status=status)
    assert client.smoke_dataspace("boi", status=status).ready


def test_client_dataspace_smoke_rejects_missing_or_sealed_status() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)

    missing = client.dataspace_status("boi", status={"lane_governance": []})
    assert missing.found is False
    assert missing.ready is False

    sealed_status = {
        "lane_governance": [
            {
                "lane_id": 1,
                "alias": "boi",
                "dataspace_id": 9,
                "manifest_required": False,
                "manifest_ready": True,
            }
        ],
        "lane_governance_sealed_aliases": ["boi"],
    }
    sealed = client.dataspace_status("boi", status=sealed_status)
    assert sealed.found is True
    assert sealed.ready is False


def test_client_dataspace_smoke_counts_dataspace_catalog_lanes() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)
    status = {
        "dataspace_catalog": [
            {
                "alias": "universal",
                "dataspace_id": 0,
                "lane_id": 0,
                "manifest_required": False,
            },
            {
                "alias": "is",
                "dataspace_id": 42,
                "lane_id": 1,
                "manifest_required": False,
            },
        ],
    }

    smoke = client.smoke_dataspace("is", expected_lane_count=2, status=status)

    assert smoke.ready
    assert smoke.dataspace_id == 42


def test_client_dataspace_catalog_metadata_survives_backlog_entries() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)
    status = {
        "dataspace_catalog": [
            {
                "alias": "is",
                "dataspace_id": 6647857470246403404,
                "lane_alias": "is",
                "lane_id": 5,
                "manifest_required": False,
                "manifest_ready": False,
                "sealed": False,
                "storage_profile": "full_replica",
                "visibility": "restricted",
            }
        ],
        "teu_dataspace_backlog": [
            {"alias": "is", "dataspace_id": 6647857470246403404, "lane_id": lane_id}
            for lane_id in range(6)
        ],
    }

    route = client.get_dataspace("is", status=status)
    smoke = client.smoke_dataspace(
        "is",
        expected_dataspace_id=6647857470246403404,
        status=status,
    )

    assert route is not None
    assert route["visibility"] == "restricted"
    assert route["lane_id"] == 5
    assert smoke.ready is True
    assert smoke.lane["visibility"] == "restricted"
    assert smoke.lane["lane_id"] == 5


def test_client_dataspace_smoke_rejects_wrong_expected_dataspace_id() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)
    status = {
        "dataspace_catalog": [
            {
                "alias": "is",
                "dataspace_id": 41,
                "lane_id": 5,
                "manifest_required": False,
            }
        ],
    }

    with pytest.raises(AssertionError, match="expected 42"):
        client.smoke_dataspace("is", expected_dataspace_id=42, status=status)


def test_get_status_rejects_missing_canonical_route_without_fallback() -> None:
    session = FakeSession([response(404)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(RuntimeError, match="unexpected status 404"):
        client.get_status()

    assert [call["path"] for call in session.calls] == ["/status"]
    assert session.calls[0]["headers"]["Accept"] == "application/json"


def test_get_status_does_not_fallback_on_non_404_failure() -> None:
    session = FakeSession([response(500, {"message": "temporary failure"})])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(RuntimeError, match="temporary failure"):
        client.get_status()

    assert [call["path"] for call in session.calls] == ["/status"]


def test_get_status_snapshot_typed_uses_canonical_route() -> None:
    session = FakeSession(
        [response(200, {"peers": 1, "queue_size": 0, "commit_time_ms": 1})]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    snapshot = client.get_status_snapshot_typed()

    assert snapshot.status.peers == 1
    assert [call["path"] for call in session.calls] == ["/status"]


def test_operator_signature_headers_sign_canonical_request() -> None:
    key_pair = Ed25519KeyPair.from_private_key(bytes([7] * 32))

    headers = ToriiClient.build_operator_signature_headers(
        network_id=NETWORK_ID,
        method="POST",
        path="/v1/configuration?b=2&a=1",
        body=b'{"retire":[]}',
        key_pair=key_pair,
        timestamp_ms=123456,
        nonce="nonce-1",
    )

    message = b"".join(
        (
            b"iroha.operator.http-request.network.v1\0",
            CANONICAL_GENESIS_HASH,
            canonical_request_message(
                "POST", "/v1/configuration?b=2&a=1", b'{"retire":[]}'
            ),
            b"\n123456\nnonce-1",
        )
    )
    assert headers["x-iroha-operator-public-key"] == key_pair.public_key_multihash
    assert headers["x-iroha-operator-timestamp-ms"] == "123456"
    assert headers["x-iroha-operator-nonce"] == "nonce-1"
    assert key_pair.verify(
        message,
        base64.b64decode(headers["x-iroha-operator-signature"]),
    )
    foreign_message = message.replace(
        CANONICAL_GENESIS_HASH,
        bytes([0xA6]) * 32,
        1,
    )
    assert not key_pair.verify(
        foreign_message,
        base64.b64decode(headers["x-iroha-operator-signature"]),
    )


def test_operator_signature_headers_rejects_ambiguous_or_bad_signers() -> None:
    key_pair = Ed25519KeyPair.from_private_key(bytes([8] * 32))

    with pytest.raises(TypeError, match="NetworkId"):
        ToriiClient.build_operator_signature_headers(
            network_id="same-label",  # type: ignore[arg-type]
            method="POST",
            path="/v1/configuration",
            key_pair=key_pair,
        )

    with pytest.raises(ValueError, match="exactly one"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            key_pair=key_pair,
            private_key_hex="11" * 32,
        )

    with pytest.raises(ValueError, match="nonce"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            key_pair=key_pair,
            nonce="",
        )

    with pytest.raises(ValueError, match="nonce"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            key_pair=key_pair,
            nonce="   ",
        )

    with pytest.raises(ValueError, match="timestamp_ms"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            key_pair=key_pair,
            timestamp_ms=-1,
        )

    class MissingPublicKey:
        def sign(self, message: bytes) -> bytes:
            return b"signature"

    with pytest.raises(TypeError, match="public_key_multihash"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            key_pair=MissingPublicKey(),
        )

    class BadSignature:
        public_key_multihash = "ed0120abc"

        def sign(self, message: bytes) -> str:
            return "not-bytes"

    with pytest.raises(TypeError, match="return bytes"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            key_pair=BadSignature(),
        )


def test_operator_signature_headers_accept_raw_private_key_inputs() -> None:
    raw_private_key = bytes([13] * 32)
    key_pair = Ed25519KeyPair.from_private_key(raw_private_key)

    hex_headers = ToriiClient.build_operator_signature_headers(
        network_id=NETWORK_ID,
        method="POST",
        path="/v1/configuration",
        body=b"{}",
        private_key_hex=raw_private_key.hex(),
        timestamp_ms=123,
        nonce="hex-nonce",
    )
    bytes_headers = ToriiClient.build_operator_signature_headers(
        network_id=NETWORK_ID,
        method="POST",
        path="/v1/configuration",
        body=b"{}",
        private_key=raw_private_key,
        timestamp_ms=123,
        nonce="bytes-nonce",
    )

    assert hex_headers["x-iroha-operator-public-key"] == key_pair.public_key_multihash
    assert bytes_headers["x-iroha-operator-public-key"] == key_pair.public_key_multihash
    with pytest.raises(ValueError, match="private-key multihash or raw Ed25519 hex"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            private_key="not-hex-or-multihash",
        )
    with pytest.raises(ValueError, match="32 bytes"):
        ToriiClient.build_operator_signature_headers(
            network_id=NETWORK_ID,
            method="POST",
            path="/v1/configuration",
            private_key="00" * 31,
        )


def lifecycle_status() -> dict[str, object]:
    return {
        "version": 1,
        "lane_count": 1,
        "lanes": [lane_config()],
        "catalog_hash": canonical_hash(0xA1),
        "runtime_catalog_hash": None,
        "incarnations": [{"lane_id": 0, "incarnation": canonical_hash(0xB3)}],
        "incarnation_root": canonical_hash(0xC3),
    }


@pytest.mark.parametrize("runtime_catalog_hash", (None, canonical_hash(0xD5)))
def test_nexus_lane_lifecycle_status_fetches_exact_json_snapshot(
    runtime_catalog_hash: str | None,
) -> None:
    status = lifecycle_status()
    status["runtime_catalog_hash"] = runtime_catalog_hash
    session = FakeSession([response(200, status)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    assert client.nexus_lane_lifecycle_status() == status
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["path"] == "/v1/nexus/lifecycle"
    assert session.calls[0]["headers"]["Accept"] == "application/json"


def test_nexus_lane_lifecycle_status_requires_explicit_runtime_catalog_hash() -> None:
    status = lifecycle_status()
    del status["runtime_catalog_hash"]
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, status)]),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(TypeError, match="missing required `runtime_catalog_hash`"):
        client.nexus_lane_lifecycle_status()


@pytest.mark.parametrize("first", (None, canonical_hash(0xD5)))
@pytest.mark.parametrize("second", (None, canonical_hash(0xD7)))
def test_nexus_lane_lifecycle_status_rejects_duplicate_runtime_catalog_hash(
    first: str | None, second: str | None,
) -> None:
    status = lifecycle_status()
    status["runtime_catalog_hash"] = first
    duplicate = response(200, status)
    duplicate._content = (
        duplicate.content[:-1]
        + b', "runtime_catalog_hash": '
        + json.dumps(second).encode("utf-8")
        + b"}"
    )
    client = ToriiClient(
        "http://torii.example", session=FakeSession([duplicate]), max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="duplicate field `runtime_catalog_hash`"):
        client.nexus_lane_lifecycle_status()


@pytest.mark.parametrize("value", (False, True, 0, 1, [], {}))
def test_nexus_lane_lifecycle_status_rejects_nonstring_runtime_catalog_hash(
    value: object,
) -> None:
    status = lifecycle_status()
    status["runtime_catalog_hash"] = value
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, status)]),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(TypeError, match="`runtime_catalog_hash` must be a canonical hash"):
        client.nexus_lane_lifecycle_status()


def test_nexus_lane_lifecycle_status_rejects_removed_enablement_field() -> None:
    status = lifecycle_status()
    status["nexus_enabled"] = True
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, status)]),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="unknown field `nexus_enabled`"):
        client.nexus_lane_lifecycle_status()


@pytest.mark.parametrize("runtime_catalog_hash", (None, canonical_hash(0xD5)))
def test_nexus_lane_lifecycle_submits_native_signed_set_parameter(
    monkeypatch: pytest.MonkeyPatch, runtime_catalog_hash: str | None,
) -> None:
    import iroha_python.client as client_module

    status = lifecycle_status()
    status["runtime_catalog_hash"] = runtime_catalog_hash
    session = FakeSession([response(200, status)])
    client = ToriiClient("http://torii.example", session=session, max_retries=3, chain_discriminant=753)
    addition = lane_config(lane_id=5, shard_id=9, dataspace_id=42, alias="is")
    addition.update(
        {
            "visibility": "restricted",
            "lane_type": "cbdc_private",
            "governance": "is_governance",
            "settlement": "boi_rtgs",
            "metadata": {"owner": "boi-poc"},
        }
    )
    additions = [addition]
    captured: dict[str, object] = {}

    class FakeInstruction:
        @staticmethod
        def nexus_lane_lifecycle(status_json: str, plan_json: str) -> object:
            captured["status"] = json.loads(status_json)
            captured["plan"] = json.loads(plan_json)
            return "set-parameter-instruction"

    class FakeCrypto:
        Instruction = FakeInstruction

    def fake_submit(
        network_id: NetworkId,
        authority: str,
        private_key: bytes,
        **kwargs: object,
    ) -> tuple[str, dict[str, object]]:
        captured["network_id"] = network_id
        captured["authority"] = authority
        captured["private_key"] = private_key
        captured.update(kwargs)
        return "envelope", {"kind": "Applied"}

    monkeypatch.setattr(client_module, "_require_crypto", lambda: FakeCrypto)
    monkeypatch.setattr(client, "build_and_submit_transaction", fake_submit)
    result = client.nexus_lane_lifecycle(
        additions,
        retire=[1],
        network_id=NETWORK_ID,
        authority="alice@wonderland",
        private_key=bytes([9] * 32),
        fee_payment=FEE_PAYMENT,
    )

    assert result == ("envelope", {"kind": "Applied"})
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "GET"
    assert captured["status"] == status
    assert captured["plan"] == {"additions": additions, "retire": [1]}
    assert captured["network_id"] == NETWORK_ID
    assert captured["authority"] == "alice@wonderland"
    assert captured["private_key"] == bytes([9] * 32)
    assert captured["instructions"] == ["set-parameter-instruction"]
    assert captured["wait"] is True
    assert "scope" not in captured
    assert "success_statuses" not in captured


def test_nexus_lane_lifecycle_rejects_malformed_inputs() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)
    auth = {
        "network_id": NETWORK_ID,
        "authority": "alice@wonderland",
        "private_key": bytes([10] * 32),
        "fee_payment": FEE_PAYMENT,
    }

    with pytest.raises(TypeError, match="additions"):
        client.nexus_lane_lifecycle("not-a-list", **auth)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"additions\[0\]"):
        client.nexus_lane_lifecycle([object()], **auth)  # type: ignore[list-item]

    with pytest.raises(ValueError, match=r"retire\[0\]"):
        client.nexus_lane_lifecycle([], retire=[-1], **auth)

    with pytest.raises(TypeError, match="retire"):
        client.nexus_lane_lifecycle([], retire="12", **auth)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="retire"):
        client.nexus_lane_lifecycle([], retire=object(), **auth)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"retire\[0\]"):
        client.nexus_lane_lifecycle([], retire=[object()], **auth)  # type: ignore[list-item]

    with pytest.raises(ValueError, match=r"retire\[0\]"):
        client.nexus_lane_lifecycle([], retire=[True], **auth)  # type: ignore[list-item]

    for invalid in (1.5, "1", 0x1_0000_0000):
        with pytest.raises(ValueError, match=r"retire\[0\].*u32"):
            client.nexus_lane_lifecycle([], retire=[invalid], **auth)  # type: ignore[list-item]

    with pytest.raises(ValueError, match="duplicates lane"):
        client.nexus_lane_lifecycle([], retire=[1, 1], **auth)

    lane = lane_config(lane_id=1, alias="lane-one")
    with pytest.raises(ValueError, match=r"additions\[1\].id duplicates"):
        client.nexus_lane_lifecycle([lane, lane], **auth)

    invalid_lane = lane_config(lane_id=1, alias="bad")
    invalid_lane["id"] = 1.5
    with pytest.raises(TypeError, match=r"additions\[0\].*id.*unsigned integer"):
        client.nexus_lane_lifecycle([invalid_lane], **auth)

    with pytest.raises(ValueError, match="must add or retire"):
        client.nexus_lane_lifecycle([], **auth)


@pytest.mark.parametrize(
    "missing_field",
    (
        "id",
        "shard_id",
        "dataspace_id",
        "alias",
        "description",
        "visibility",
        "lane_type",
        "governance",
        "settlement",
        "storage",
        "proof_scheme",
        "manifest_policy",
        "confidential_compute",
        "scheduler",
        "settlement_buffer",
        "metadata",
    ),
)
def test_nexus_lane_lifecycle_rejects_incomplete_lane_before_status_fetch(
    missing_field: str,
) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    addition = lane_config(lane_id=3, shard_id=7, dataspace_id=42, alias="payments")
    del addition[missing_field]

    with pytest.raises(TypeError, match=rf"missing required `{missing_field}`"):
        client.nexus_lane_lifecycle(
            [addition],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([13] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("shard_id", True, "shard_id.*unsigned integer"),
        ("dataspace_id", -1, "dataspace_id.*between 0"),
        ("description", 7, "description.*string or null"),
        ("visibility", "Public", "visibility.*public.*restricted"),
        ("storage", "full-replica", "storage.*full_replica"),
        ("proof_scheme", "merkle", "proof_scheme.*merkle_sha256"),
        ("manifest_policy", "Strict", "manifest_policy.*strict.*audit"),
        ("confidential_compute", True, "confidential_compute.*object or null"),
        (
            "confidential_compute",
            {
                "mechanism": "sealed_box",
                "key_version": 1,
                "allowed_audiences": [],
            },
            "mechanism.*encryption.*secret_sharing",
        ),
        (
            "confidential_compute",
            {
                "mechanism": "encryption",
                "key_version": 0,
                "allowed_audiences": [],
            },
            "key_version.*positive u32",
        ),
        (
            "confidential_compute",
            {
                "mechanism": "secret_sharing",
                "key_version": 1,
                "allowed_audiences": [" auditor"],
            },
            "allowed_audiences.*surrounding whitespace",
        ),
        ("scheduler", {}, "scheduler.*missing required"),
        (
            "scheduler",
            {"teu_capacity": None, "starvation_bound_slots": None},
            "scheduler.*at least one override",
        ),
        (
            "scheduler",
            {"teu_capacity": 0, "starvation_bound_slots": None},
            "teu_capacity.*positive u64",
        ),
        (
            "scheduler",
            {
                "teu_capacity": 1,
                "starvation_bound_slots": None,
                "unexpected": 1,
            },
            "scheduler.*unknown field `unexpected`",
        ),
        ("settlement_buffer", {}, "settlement_buffer.*missing required"),
        (
            "settlement_buffer",
            {
                "account_id": "alice@wonderland",
                "asset_definition_id": SETTLEMENT_ASSET_DEFINITION_ID,
                "capacity": "1000",
            },
            "account_id.*canonical I105",
        ),
        (
            "settlement_buffer",
            {
                "account_id": SETTLEMENT_ACCOUNT_ID,
                "asset_definition_id": "not-an-asset-address",
                "capacity": "1000",
            },
            "asset_definition_id.*canonical asset definition",
        ),
        (
            "settlement_buffer",
            {
                "account_id": SETTLEMENT_ACCOUNT_ID,
                "asset_definition_id": SETTLEMENT_ASSET_DEFINITION_ID,
                "capacity": "0",
            },
            "capacity.*positive XOR quantity",
        ),
        (
            "settlement_buffer",
            {
                "account_id": SETTLEMENT_ACCOUNT_ID,
                "asset_definition_id": SETTLEMENT_ASSET_DEFINITION_ID,
                "capacity": "0.0000000001",
            },
            "capacity.*nine fractional digits",
        ),
        ("metadata", [], "metadata.*object"),
        ("metadata", {"owner": 7}, "metadata.owner.*string"),
        ("metadata", {"da_shard_id": "7"}, "retired.*shard_id"),
    ),
)
def test_nexus_lane_lifecycle_rejects_noncanonical_lane_fields_before_status_fetch(
    field: str,
    value: object,
    match: str,
) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    addition = lane_config(lane_id=3, shard_id=7, dataspace_id=42, alias="payments")
    addition[field] = value

    with pytest.raises((TypeError, ValueError), match=match):
        client.nexus_lane_lifecycle(
            [addition],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([14] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "retired_key",
    (
        "da_manifest_policy",
        "confidential_compute",
        "confidential_mechanism",
        "confidential_key_version",
        "confidential_access",
        "confidential_future_policy",
        "scheduler.teu_capacity",
        "scheduler.future_policy",
        "settlement.buffer_account",
        "settlement.buffer_asset",
        "settlement.buffer_capacity",
        "settlement.buffer_future_policy",
    ),
)
def test_nexus_lane_lifecycle_rejects_retired_functional_metadata_before_status_fetch(
    retired_key: str,
) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    addition = lane_config(lane_id=3, shard_id=7, dataspace_id=42, alias="payments")
    addition["metadata"] = {retired_key: "retired"}

    with pytest.raises(ValueError, match=rf"metadata.{retired_key}.*retired"):
        client.nexus_lane_lifecycle(
            [addition],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([14] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert session.calls == []


def test_nexus_lane_lifecycle_requires_nonreplicated_confidential_storage() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    addition = lane_config(lane_id=3, shard_id=7, dataspace_id=42, alias="payments")
    addition["confidential_compute"] = {
        "mechanism": "encryption",
        "key_version": 1,
        "allowed_audiences": [],
    }

    with pytest.raises(ValueError, match="requires.*commitment_only.*split_replica"):
        client.nexus_lane_lifecycle(
            [addition],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([14] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert session.calls == []


def test_nexus_lane_lifecycle_canonicalizes_typed_confidential_audiences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import iroha_python.client as client_module

    session = FakeSession([response(200, lifecycle_status())])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    default_lane = lane_config(lane_id=3, dataspace_id=42, alias="payments")
    default_lane["metadata"] = {"owner": "payments"}
    default_lane["scheduler"] = {
        "teu_capacity": 4096,
        "starvation_bound_slots": None,
    }
    default_lane["settlement_buffer"] = {
        "account_id": SETTLEMENT_ACCOUNT_ID,
        "asset_definition_id": SETTLEMENT_ASSET_DEFINITION_ID,
        "capacity": "1500.25",
    }
    confidential_lane = lane_config(lane_id=4, dataspace_id=43, alias="private")
    confidential_lane["storage"] = "split_replica"
    confidential_lane["manifest_policy"] = "audit"
    confidential_lane["confidential_compute"] = {
        "mechanism": "secret_sharing",
        "key_version": 7,
        "allowed_audiences": ["operator", "auditor", "operator"],
    }
    captured: dict[str, object] = {}

    class FakeInstruction:
        @staticmethod
        def nexus_lane_lifecycle(_status_json: str, plan_json: str) -> object:
            captured["plan"] = json.loads(plan_json)
            return "set-parameter-instruction"

    class FakeCrypto:
        Instruction = FakeInstruction

    def fake_submit(*_args: object, **_kwargs: object) -> tuple[str, dict[str, object]]:
        return "envelope", {"kind": "Applied"}

    monkeypatch.setattr(client_module, "_require_crypto", lambda: FakeCrypto)
    monkeypatch.setattr(client, "build_and_submit_transaction", fake_submit)

    client.nexus_lane_lifecycle(
        [default_lane, confidential_lane],
        network_id=NETWORK_ID,
        authority="alice@wonderland",
        private_key=bytes([15] * 32),
        fee_payment=FEE_PAYMENT,
    )

    additions = captured["plan"]["additions"]  # type: ignore[index]
    assert additions[0]["metadata"] == {"owner": "payments"}
    assert additions[0]["scheduler"] == {
        "teu_capacity": 4096,
        "starvation_bound_slots": None,
    }
    assert additions[0]["settlement_buffer"] == {
        "account_id": SETTLEMENT_ACCOUNT_ID,
        "asset_definition_id": SETTLEMENT_ASSET_DEFINITION_ID,
        "capacity": "1500.25",
    }
    assert additions[1]["manifest_policy"] == "audit"
    assert additions[1]["confidential_compute"] == {
        "mechanism": "secret_sharing",
        "key_version": 7,
        "allowed_audiences": ["auditor", "operator"],
    }
    assert confidential_lane["confidential_compute"]["allowed_audiences"] == [  # type: ignore[index]
        "operator",
        "auditor",
        "operator",
    ]
    assert default_lane["scheduler"] == {
        "teu_capacity": 4096,
        "starvation_bound_slots": None,
    }


def test_nexus_lane_lifecycle_rejects_unknown_lane_field_before_status_fetch() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    addition = lane_config(lane_id=3, shard_id=7, dataspace_id=42, alias="payments")
    addition["shard"] = 7

    with pytest.raises(ValueError, match="unknown field `shard`"):
        client.nexus_lane_lifecycle(
            [addition],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([15] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert session.calls == []


def test_nexus_lane_lifecycle_requires_full_transaction_signing_context() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)
    with pytest.raises(TypeError, match="network_id"):
        client.nexus_lane_lifecycle(
            [],
            authority="alice@wonderland",
            private_key=bytes([1] * 32),
            fee_payment=FEE_PAYMENT,
        )
    with pytest.raises(TypeError, match="network_id must be a NetworkId"):
        client.nexus_lane_lifecycle(
            [],
            network_id=CANONICAL_GENESIS_HASH,  # type: ignore[arg-type]
            authority="alice@wonderland",
            private_key=bytes([1] * 32),
            fee_payment=FEE_PAYMENT,
        )
    with pytest.raises(TypeError, match="authority"):
        client.nexus_lane_lifecycle(
            [],
            network_id=NETWORK_ID,
            private_key=bytes([1] * 32),
            fee_payment=FEE_PAYMENT,
        )
    with pytest.raises(TypeError, match="private_key"):
        client.nexus_lane_lifecycle(
            [],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            fee_payment=FEE_PAYMENT,
        )


def test_nexus_lane_lifecycle_rejects_malformed_status() -> None:
    malformed = lifecycle_status()
    malformed["catalog_hash"] = ""
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, malformed)]),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="catalog_hash"):
        client.nexus_lane_lifecycle_status()

    wrong_incarnation = lifecycle_status()
    wrong_incarnation["incarnations"] = [
        {"lane_id": 1, "incarnation": canonical_hash(0xB3)}
    ]
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, wrong_incarnation)]),
        max_retries=0,
        chain_discriminant=753,
    )
    with pytest.raises(ValueError, match="exactly match"):
        client.nexus_lane_lifecycle_status()

    missing_root = lifecycle_status()
    missing_root["incarnation_root"] = ""
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, missing_root)]),
        max_retries=0,
        chain_discriminant=753,
    )
    with pytest.raises(ValueError, match="incarnation_root"):
        client.nexus_lane_lifecycle_status()


def test_nexus_lane_lifecycle_status_requires_explicit_shard_id() -> None:
    malformed_lane = lane_config()
    del malformed_lane["shard_id"]
    malformed = lifecycle_status()
    malformed["lanes"] = [malformed_lane]
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, malformed)]),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(TypeError, match="missing required `shard_id`"):
        client.nexus_lane_lifecycle_status()


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("catalog_hash", "A1" * 32, "canonical.*uppercase hex.*CRC16"),
        ("catalog_hash", canonical_hash(0xA1).lower(), "canonical.*uppercase hex.*CRC16"),
        ("catalog_hash", "hash:" + "A1" * 32 + "#0000", "checksum mismatch"),
        ("runtime_catalog_hash", "", "canonical.*uppercase hex.*CRC16"),
        ("runtime_catalog_hash", "D5" * 32, "canonical.*uppercase hex.*CRC16"),
        ("runtime_catalog_hash", canonical_hash(0xD5).lower(), "canonical.*uppercase hex.*CRC16"),
        ("runtime_catalog_hash", "hash:" + "D5" * 32 + "#0000", "checksum mismatch"),
        ("runtime_catalog_hash", "hash:" + "00" * 32 + "#D52F", "invalid Iroha hash marker bit"),
        ("runtime_catalog_hash", "hash:" + "A2" * 32 + "#873F", "invalid Iroha hash marker bit"),
        ("runtime_catalog_hash", "hash:" + "00" * 31 + "01#C50E", "empty Iroha hash"),
        ("incarnation", "B3" * 32, "canonical.*uppercase hex.*CRC16"),
        ("incarnation_root", "C3" * 32, "canonical.*uppercase hex.*CRC16"),
    ),
)
def test_nexus_lane_lifecycle_rejects_noncanonical_hash_before_native_bridge(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
    match: str,
) -> None:
    import iroha_python.client as client_module

    malformed = lifecycle_status()
    if field == "incarnation":
        malformed["incarnations"] = [{"lane_id": 0, "incarnation": value}]
    else:
        malformed[field] = value
    session = FakeSession([response(200, malformed)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    def unexpected_bridge() -> object:
        raise AssertionError("native bridge must not observe malformed lifecycle JSON")

    monkeypatch.setattr(client_module, "_require_crypto", unexpected_bridge)
    with pytest.raises(ValueError, match=match):
        client.nexus_lane_lifecycle(
            [],
            retire=[0],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([16] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert len(session.calls) == 1


def test_nexus_lane_lifecycle_surfaces_stale_transaction_without_refetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import iroha_python.client as client_module

    session = FakeSession([response(200, lifecycle_status())])
    client = ToriiClient("http://torii.example", session=session, max_retries=3, chain_discriminant=753)

    class FakeInstruction:
        @staticmethod
        def nexus_lane_lifecycle(_status: str, _plan: str) -> object:
            return object()

    class FakeCrypto:
        Instruction = FakeInstruction

    monkeypatch.setattr(client_module, "_require_crypto", lambda: FakeCrypto)

    def stale(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("stale Nexus lane lifecycle catalog commitment")

    monkeypatch.setattr(client, "build_and_submit_transaction", stale)
    with pytest.raises(RuntimeError, match="stale Nexus"):
        client.nexus_lane_lifecycle(
            [],
            retire=[0],
            network_id=NETWORK_ID,
            authority="alice@wonderland",
            private_key=bytes([12] * 32),
            fee_payment=FEE_PAYMENT,
        )

    assert len(session.calls) == 1
    assert session.calls[0]["path"] == "/v1/nexus/lifecycle"


def test_compose_asset_id_accepts_dataspace_scope_shortcut() -> None:
    assert (
        ToriiClient.compose_asset_id("abc", "alice@boi", scope="42")
        == "abc#alice@boi#dataspace:42"
    )
