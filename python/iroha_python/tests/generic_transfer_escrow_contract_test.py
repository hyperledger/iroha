from __future__ import annotations

import base64
import importlib
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest
import requests
from blake3 import blake3

# These source-level request tests use a separate package name to isolate Python
# helpers. Native SDK imports still require the installed iroha-native wheel.
PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "src" / "iroha_python"
PURE_PACKAGE = "_iroha_python_source_test"
TX_PURE_PACKAGE = "_iroha_python_tx_network_id_test"
if PURE_PACKAGE not in sys.modules:
    package = types.ModuleType(PURE_PACKAGE)
    package.__path__ = [str(PACKAGE_ROOT)]
    package.__package__ = PURE_PACKAGE
    sys.modules[PURE_PACKAGE] = package
if f"{PURE_PACKAGE}.sorafs" not in sys.modules:
    sorafs = types.ModuleType(f"{PURE_PACKAGE}.sorafs")
    sorafs.SorafsAliasError = type("SorafsAliasError", (Exception,), {})
    for name in ("SorafsAliasEvaluation", "SorafsAliasWarning"):
        setattr(sorafs, name, type(name, (), {}))

    class SorafsAliasPolicy:
        @classmethod
        def defaults(cls) -> "SorafsAliasPolicy":
            return cls()

    sorafs.SorafsAliasPolicy = SorafsAliasPolicy
    sorafs.enforce_alias_policy = lambda *args, **kwargs: None
    sys.modules[f"{PURE_PACKAGE}.sorafs"] = sorafs

client_module = importlib.import_module(f"{PURE_PACKAGE}.client")
settlement_module = importlib.import_module(f"{PURE_PACKAGE}.settlement")

BatchMode = settlement_module.BatchMode
DeadlineCondition = settlement_module.DeadlineCondition
EscrowValue = settlement_module.EscrowValue
OracleCondition = settlement_module.OracleCondition
Payment = settlement_module.Payment
ContractCallIntent = client_module.ContractCallIntent
ToriiClient = client_module.ToriiClient
VerifiedCommittedTransaction = client_module.VerifiedCommittedTransaction


class FakeNetworkId:
    def __init__(self, value: bytes) -> None:
        self._value = value

    def to_bytes(self) -> bytes:
        return self._value


NETWORK_ID = FakeNetworkId(b"\x77" * 32)
RETIRED_NETWORK_KEYWORDS = (
    "chain",
    "chainId",
    "chain_id",
    "canonicalGenesisHash",
    "canonical_genesis_hash",
    "genesisHash",
    "genesis_hash",
)


def _install_network_id_contract(module: types.ModuleType) -> None:
    module.NetworkId = FakeNetworkId

    def require(value: object, context: str = "network_id") -> FakeNetworkId:
        if not isinstance(value, FakeNetworkId):
            raise TypeError(f"{context} must be a NetworkId")
        return value

    module._require_network_id = require


def _load_native_free_tx_module() -> types.ModuleType:
    if TX_PURE_PACKAGE not in sys.modules:
        package = types.ModuleType(TX_PURE_PACKAGE)
        package.__path__ = [str(PACKAGE_ROOT)]
        package.__package__ = TX_PURE_PACKAGE
        sys.modules[TX_PURE_PACKAGE] = package

        crypto = types.ModuleType(f"{TX_PURE_PACKAGE}.crypto")
        _install_network_id_contract(crypto)

        class NativePlaceholder:
            pass

        crypto._LANE_PRIVACY_MAX_MERKLE_DEPTH_V1 = 255
        crypto._is_native_crypto_instance = lambda value, _type_name: isinstance(
            value, NativePlaceholder
        )
        for name in (
            "ContractCall",
            "Ed25519KeyPair",
            "Instruction",
            "PrivacyExact12CapabilityManifestV1",
            "PrivacyNativeActionBuildResultV1",
            "SignedTransactionEnvelope",
            "TransactionBuilder",
            "TransactionExecutableEntry",
        ):
            setattr(crypto, name, NativePlaceholder)
        crypto._normalize_lane_privacy_attachment = lambda value: value
        crypto.build_signed_transaction = lambda *_args, **_kwargs: None
        sys.modules[f"{TX_PURE_PACKAGE}.crypto"] = crypto
    return importlib.import_module(f"{TX_PURE_PACKAGE}.tx")


def _response(payload: Any, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(payload).encode("utf-8")
    return response


def _norito_response(payload: bytes, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = "application/x-norito"
    response._content = payload
    return response


class FakeSession(requests.Session):
    def __init__(self, responses: list[requests.Response]) -> None:
        super().__init__()
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


def test_typed_batch_and_conditional_escrow_payloads_are_canonical() -> None:
    payment = Payment("leg-1", "recipient@payments", "7.5")
    assert payment.to_payload() == {
        "id": "leg-1",
        "to": "recipient@payments",
        "amount": "7.5",
    }
    assert BatchMode.INDEPENDENT.value == "Independent"

    approved = OracleCondition.equals(
        "approved",
        EscrowValue.boolean(True),
        "oracle@payments",
        order=1,
    )
    maximum = OracleCondition.quantity_at_most(
        "amount",
        "100",
        "oracle@payments",
        order=2,
    )
    deadline = DeadlineCondition.within(hours=1, minutes=30)

    assert approved.to_payload()["value"]["predicate"] == {
        "kind": "Equals",
        "value": {"kind": "Bool", "value": True},
    }
    assert maximum.to_payload()["value"]["predicate"] == {
        "kind": "QuantityAtMost",
        "value": "100",
    }
    assert deadline.to_payload() == {
        "kind": "Within",
        "value": {"id": "deadline", "duration_ms": 5_400_000},
    }
    with pytest.raises(ValueError, match="payment id"):
        Payment(" leg-1", "recipient@payments", "1")
    with pytest.raises(ValueError, match="positive integer"):
        OracleCondition.equals(
            "approved",
            EscrowValue.boolean(True),
            "oracle@payments",
            order=0,
        )


@pytest.mark.parametrize(
    "raw_network_id",
    [b"\x77" * 32, bytearray(b"\x77" * 32), memoryview(b"\x77" * 32)],
)
def test_transaction_config_rejects_raw_network_bytes_at_construction(
    raw_network_id: bytes | bytearray | memoryview,
) -> None:
    tx = _load_native_free_tx_module()
    with pytest.raises(
        TypeError,
        match="TransactionConfig.network_id must be a NetworkId",
    ):
        tx.TransactionConfig(
            network_id=raw_network_id,
            authority="authority@payments",
            fee_payment={},
        )


@pytest.mark.parametrize("retired_key", RETIRED_NETWORK_KEYWORDS)
def test_transaction_draft_sign_rejects_legacy_network_keyword_aliases(
    retired_key: str,
) -> None:
    tx = _load_native_free_tx_module()
    draft = tx.TransactionDraft(
        tx.TransactionConfig(
            network_id=NETWORK_ID,
            authority="authority@payments",
            fee_payment={},
        )
    )
    with pytest.raises(TypeError, match=f"unexpected keyword argument '{retired_key}'"):
        draft.sign(b"private-key", **{retired_key: "retired"})


def test_public_status_rejects_native_batch_outcomes() -> None:
    payload = {
        "hash": "ab" * 32,
        "status": {"kind": "Rejected"},
        "scope": "global",
        "resolved_from": "state",
        "batch_transfer_outcomes": [
            {
                "leg_index": 0,
                "leg_id": "first",
                "destination": "first@payments",
                "amount": "20",
                "status": {"status": "Applied", "value": None},
            },
            {
                "leg_index": 1,
                "leg_id": "second",
                "destination": "second@payments",
                "amount": "60",
                "status": {
                    "status": "Rejected",
                    "value": {
                        "code": {
                            "code": "HoldingLimitExceeded",
                            "value": None,
                        },
                        "message": "destination holding limit exceeded",
                    },
                },
            },
        ],
    }

    with pytest.raises(ValueError, match="retired or unsupported fields"):
        client_module._normalize_public_pipeline_status(payload, "ab" * 32)


@pytest.mark.parametrize(
    "embedded_hash",
    [
        "AB" * 32,
        "0x" + "ab" * 32,
        " " + "ab" * 32,
        "ab" * 31,
        "aa" * 32,
        b"\xab" * 32,
    ],
)
def test_contract_wait_rejects_noncanonical_embedded_transaction_hash(
    embedded_hash: object,
) -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0)
    response = {
        "tx_hash_hex": embedded_hash,
        "pipeline_status": {
            "hash": "ab" * 32,
            "status": {"kind": "Applied", "block_height": 1},
            "scope": "global",
            "resolved_from": "state",
        },
    }

    with pytest.raises(
        ValueError,
        match=(
            r"^contract response\.tx_hash_hex must match \[0-9a-f\]\{63\}\[13579bdf\] "
            r"with the canonical Iroha HashOf marker$"
        ),
    ):
        client._wait_for_contract_response(
            response,
            timeout_ms=1_000,
            interval=0,
        )


def test_contract_wait_requires_exact_hash_field_and_pipeline_binding() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0)
    tx_hash = "ab" * 32
    exact_status = {
        "hash": tx_hash,
        "status": {"kind": "Applied", "block_height": 1},
        "scope": "global",
        "resolved_from": "state",
    }
    with pytest.raises(ValueError, match="canonical tx_hash_hex"):
        client._wait_for_contract_response(
            {"transaction_hash": tx_hash, "pipeline_status": exact_status},
            timeout_ms=1_000,
            interval=0,
        )
    with pytest.raises(ValueError, match="does not match tx_hash_hex"):
        client._wait_for_contract_response(
            {
                "tx_hash_hex": tx_hash,
                "pipeline_status": {**exact_status, "hash": "cd" * 32},
            },
            timeout_ms=1_000,
            interval=0,
        )


def test_contract_wait_uses_only_exact_authoritative_applied_embedded_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0)
    tx_hash = "ab" * 32
    queued = {
        "hash": tx_hash,
        "status": {"kind": "Queued"},
        "scope": "local",
        "resolved_from": "queue",
    }
    applied = {
        "hash": tx_hash,
        "status": {"kind": "Applied", "block_height": 9},
        "scope": "global",
        "resolved_from": "state",
    }
    waits: list[tuple[str, dict[str, object]]] = []

    def wait(hash_hex: str, **kwargs: object) -> dict[str, object]:
        waits.append((hash_hex, kwargs))
        return applied

    monkeypatch.setattr(client, "wait_for_transaction_status", wait)
    result = client._wait_for_contract_response(
        {"tx_hash_hex": tx_hash, "pipeline_status": queued},
        timeout_ms=1_000,
        interval=0.25,
    )

    assert result["r#final"] == applied
    assert waits == [
        (
            tx_hash,
            {
                "interval": 0.25,
                "timeout": 1.0,
            },
        )
    ]

    monkeypatch.setattr(
        client,
        "wait_for_transaction_status",
        lambda *_args, **_kwargs: pytest.fail("exact Applied status must not poll"),
    )
    embedded = client._wait_for_contract_response(
        {"tx_hash_hex": tx_hash, "pipeline_status": applied},
        timeout_ms=1_000,
        interval=0.25,
    )
    assert embedded["r#final"] == applied


def test_signed_role_scoped_escrow_queries_use_native_query_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    crypto = types.ModuleType(f"{PURE_PACKAGE}.crypto")
    _install_network_id_contract(crypto)
    query_network_ids: list[FakeNetworkId] = []

    def seller_query(
        authority: str,
        private_key: bytes,
        network_id: FakeNetworkId,
        seller: str,
    ) -> bytes:
        query_network_ids.append(network_id)
        return b"seller-query"

    def buyer_query(
        authority: str,
        private_key: bytes,
        network_id: FakeNetworkId,
        buyer: str,
    ) -> bytes:
        query_network_ids.append(network_id)
        return b"buyer-query"

    crypto.build_find_asset_escrows_by_seller_query = seller_query
    crypto.build_find_asset_escrows_by_buyer_query = buyer_query
    monkeypatch.setitem(sys.modules, f"{PURE_PACKAGE}.crypto", crypto)
    records = [
        {
            "id": "escrow-locked",
            "seller": "seller@payments",
            "buyer": "buyer@payments",
            "status": {"status": "Locked", "value": None},
        },
        {
            "id": "escrow-released",
            "seller": "seller@payments",
            "buyer": "buyer@payments",
            "status": {"status": "Released", "value": None},
        },
    ]
    response_payload = {
        "kind": "Iterable",
        "content": {
            "kind": "AssetEscrowRecord",
            "content": records,
        },
    }
    session = FakeSession([_response(response_payload), _response(response_payload)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    seller_records = client.list_asset_escrows_by_seller(
        seller="seller@payments",
        authority="authority@payments",
        network_id=NETWORK_ID,
        private_key_hex="11" * 32,
        status="Locked",
    )
    buyer_records = client.list_asset_escrows_by_buyer(
        buyer="buyer@payments",
        authority="authority@payments",
        network_id=NETWORK_ID,
        private_key=b"\x11" * 32,
        escrow_id="escrow-released",
    )

    assert [record["id"] for record in seller_records] == ["escrow-locked"]
    assert [record["id"] for record in buyer_records] == ["escrow-released"]
    assert [call["data"] for call in session.calls] == [
        b"seller-query",
        b"buyer-query",
    ]
    assert query_network_ids == [NETWORK_ID, NETWORK_ID]
    assert [call["url"] for call in session.calls] == ["http://torii.example/v1/query"] * 2


@pytest.mark.parametrize(
    "raw_network_id",
    [b"\x77" * 32, bytearray(b"\x77" * 32), memoryview(b"\x77" * 32)],
)
def test_public_query_helpers_reject_raw_network_bytes_before_native_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    raw_network_id: bytes | bytearray | memoryview,
) -> None:
    crypto = types.ModuleType(f"{PURE_PACKAGE}.crypto")
    _install_network_id_contract(crypto)

    def unexpected_native_dispatch(*_args: object, **_kwargs: object) -> bytes:
        raise AssertionError("raw NetworkId reached the native query boundary")

    for name in (
        "build_find_asset_escrow_query",
        "build_find_asset_escrows_by_seller_query",
        "build_find_asset_escrows_by_buyer_query",
        "build_find_committed_transaction_query",
        "build_find_block_by_hash_query",
        "committed_transaction_carrier_block_hash",
        "verify_committed_transaction_inclusion",
    ):
        setattr(crypto, name, unexpected_native_dispatch)
    monkeypatch.setitem(sys.modules, f"{PURE_PACKAGE}.crypto", crypto)

    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    calls = (
        lambda: client.get_asset_escrow(
            escrow_id="escrow",
            authority="authority@payments",
            network_id=raw_network_id,
            private_key=b"\x11" * 32,
        ),
        lambda: client.list_asset_escrows_by_seller(
            seller="seller@payments",
            authority="authority@payments",
            network_id=raw_network_id,
            private_key=b"\x11" * 32,
        ),
        lambda: client.list_asset_escrows_by_buyer(
            buyer="buyer@payments",
            authority="authority@payments",
            network_id=raw_network_id,
            private_key=b"\x11" * 32,
        ),
        lambda: client.get_verified_committed_transaction(
            transaction_hash="11" * 32,
            authority="authority@payments",
            network_id=raw_network_id,
            native_finality_proof_chain_json="[]",
            expected_chain="trusted-chain", trusted_checkpoint=b"trusted-checkpoint",
            private_key=b"\x11" * 32,
        ),
    )
    for call in calls:
        with pytest.raises(TypeError, match="network_id must be a NetworkId"):
            call()
    assert session.calls == []


@pytest.mark.parametrize("retired_key", RETIRED_NETWORK_KEYWORDS)
def test_public_query_helpers_reject_legacy_network_keyword_aliases(
    retired_key: str,
) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    calls = (
        lambda: client.get_asset_escrow(
            escrow_id="escrow",
            authority="authority@payments",
            network_id=NETWORK_ID,
            private_key=b"\x11" * 32,
            **{retired_key: "retired"},
        ),
        lambda: client.list_asset_escrows_by_seller(
            seller="seller@payments",
            authority="authority@payments",
            network_id=NETWORK_ID,
            private_key=b"\x11" * 32,
            **{retired_key: "retired"},
        ),
        lambda: client.list_asset_escrows_by_buyer(
            buyer="buyer@payments",
            authority="authority@payments",
            network_id=NETWORK_ID,
            private_key=b"\x11" * 32,
            **{retired_key: "retired"},
        ),
        lambda: client.get_verified_committed_transaction(
            transaction_hash="11" * 32,
            authority="authority@payments",
            network_id=NETWORK_ID,
            native_finality_proof_chain_json="[native-proof]",
            expected_chain="trusted-chain", trusted_checkpoint=b"trusted-checkpoint",
            private_key=b"\x11" * 32,
            **{retired_key: "retired"},
        ),
    )
    for call in calls:
        with pytest.raises(TypeError, match=f"unexpected keyword argument '{retired_key}'"):
            call()
    assert session.calls == []


def test_verified_committed_transaction_joins_signed_query_to_required_finality_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction_hash = "11" * 32
    block_hash = "22" * 32
    output_hash = "33" * 32
    crypto = types.ModuleType(f"{PURE_PACKAGE}.crypto")
    _install_network_id_contract(crypto)
    query_network_ids: list[FakeNetworkId] = []

    def transaction_query(
        authority: str,
        private_key: bytes,
        network_id: FakeNetworkId,
        requested_hash: str,
    ) -> bytes:
        query_network_ids.append(network_id)
        return b"transaction-query"

    crypto.build_find_committed_transaction_query = transaction_query
    verification_inputs = []
    def verify(requested_hash, transaction_response, **trust):
        verification_inputs.append((requested_hash, transaction_response, trust))
        return {
            "proof_kind": "selective-v1",
            "transaction_hash": transaction_hash,
            "block_hash": block_hash,
            "block_height": 7,
            "output_hash": output_hash,
            "network_id": "trusted-network",
            "context_id": "trusted-context",
            "promoted_checkpoint": b"promoted-checkpoint",
            "execution_commitment": {"executed_block_wire_len": 123},
            "executed_block_wire_hash": "55" * 32,
            "executed_block_wire_len": 123,
            "entrypoint_kind": "External",
            "authority": "authority@payments",
            "signer_public_key_hex": "44" * 32,
            "metadata": {"walkthrough": "availability"},
            "executable": {"Instructions": []},
            "result_ok": True,
            "rejection_code": None,
            "rejection_message": None,
            "contract_rejection": None,
            "ivm_fault": None,
            "batch_outcomes": [],
            "committed_transaction": {
                "entrypoint_hash": transaction_hash,
                "block_hash": block_hash,
            },
        }

    crypto.verify_committed_transaction_inclusion = verify
    monkeypatch.setitem(sys.modules, f"{PURE_PACKAGE}.crypto", crypto)
    session = FakeSession(
        [
            _norito_response(b"transaction-response"),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    verified = client.get_verified_committed_transaction(
        transaction_hash=transaction_hash,
        authority="authority@payments",
        network_id=NETWORK_ID,
        native_finality_proof_chain_json="[native-proof]",
        expected_chain="trusted-chain", trusted_checkpoint=b"trusted-checkpoint",
        private_key_hex="44" * 32,
    )

    assert verified.transaction_hash == transaction_hash
    assert verified.block_hash == block_hash
    assert verified.block_height == 7
    assert verified.output_hash == output_hash
    assert verified.entrypoint_kind == "External"
    assert verified.authority == "authority@payments"
    assert verified.signer_public_key_hex == "44" * 32
    assert verified.metadata == {"walkthrough": "availability"}
    assert verified.executable == {"Instructions": []}
    assert verified.result_ok
    assert verified.rejection_code is None
    assert verified.batch_outcomes == ()
    assert [call["data"] for call in session.calls] == [
        b"transaction-query",
    ]
    assert query_network_ids == [NETWORK_ID]
    assert verification_inputs == [(transaction_hash, b"transaction-response", {
        "native_finality_proof_chain_json": "[native-proof]",
        "expected_network_id": NETWORK_ID,
        "expected_chain": "trusted-chain",
        "trusted_checkpoint": b"trusted-checkpoint",
    })]
    assert verified.executed_block_wire_hash == "55" * 32
    assert verified.executed_block_wire_len == 123
    assert verified.context_id == "trusted-context"
    assert verified.promoted_checkpoint == b"promoted-checkpoint"
    assert all(
        call["headers"]["Accept"] == "application/x-norito"
        for call in session.calls
    )


def test_verified_contract_rejection_is_manifest_typed_and_fail_closed() -> None:
    payload = {
        "proof_kind": "selective-v1",
        "transaction_hash": "11" * 32,
        "block_hash": "22" * 32,
        "block_height": 7,
        "output_hash": "33" * 32,
        "network_id": "trusted-network",
        "context_id": "trusted-context",
            "promoted_checkpoint": b"promoted-checkpoint",
        "execution_commitment": {"executed_block_wire_len": 123},
        "executed_block_wire_hash": "55" * 32,
        "executed_block_wire_len": 123,
        "entrypoint_kind": "External",
        "authority": "authority@payments",
        "signer_public_key_hex": "44" * 32,
        "metadata": {},
        "executable": {"Instructions": []},
        "result_ok": False,
        "rejection_code": "BelowMinimum",
        "rejection_message": "contract rejection",
        "ivm_fault": None,
        "contract_rejection": {
            "contract": "BoiFiLiquidity",
            "error_type": "example/boifi@1::BoiFiLiquidity::FiLiquidityError",
            "schema_hash": "AB" * 32,
            "name": "BelowMinimum",
            "code": 18,
            "message": "  支払額が不足しています。  ",
        },
        "batch_outcomes": [],
        "committed_transaction": {},
    }
    verified = VerifiedCommittedTransaction.from_payload(payload)
    assert verified.rejection_code == "BelowMinimum"
    assert verified.contract_rejection == {
        "contract": "BoiFiLiquidity",
        "error_type": "example/boifi@1::BoiFiLiquidity::FiLiquidityError",
        "schema_hash": "AB" * 32,
        "name": "BelowMinimum",
        "code": 18,
        "message": "  支払額が不足しています。  ",
    }

    without_message = {**payload, "contract_rejection": {**payload["contract_rejection"], "message": None}}
    assert VerifiedCommittedTransaction.from_payload(without_message).contract_rejection["message"] is None
    missing_message = {**payload["contract_rejection"]}
    del missing_message["message"]
    with pytest.raises(ValueError, match="must contain exactly"):
        VerifiedCommittedTransaction.from_payload({**payload, "contract_rejection": missing_message})

    digit_hash_payload = {
        **payload,
        "ivm_fault": None,
        "contract_rejection": {**payload["contract_rejection"], "schema_hash": "07" * 32},
    }
    assert VerifiedCommittedTransaction.from_payload(
        digit_hash_payload
    ).contract_rejection == {
        **verified.contract_rejection,
        "schema_hash": "07" * 32,
    }

    unknown_field = {**payload, "unverified_hint": "ignored"}
    with pytest.raises(ValueError, match="must contain exactly"):
        VerifiedCommittedTransaction.from_payload(unknown_field)

    with pytest.raises(ValueError, match="must contain exactly"):
        VerifiedCommittedTransaction.from_payload(
            {**payload, "result_hash": payload["output_hash"]}
        )
    for retired_kind in ("ordinary", "certified_merge"):
        with pytest.raises(ValueError, match="current selective proof_kind required"):
            VerifiedCommittedTransaction.from_payload(
                {**payload, "proof_kind": retired_kind}
            )
    with pytest.raises(ValueError, match="entrypoint_kind is not recognized"):
        VerifiedCommittedTransaction.from_payload({**payload, "entrypoint_kind": "Time"})

    missing_field = dict(payload)
    del missing_field["committed_transaction"]
    with pytest.raises(ValueError, match="must contain exactly"):
        VerifiedCommittedTransaction.from_payload(missing_field)

    mismatched = dict(payload)
    mismatched["rejection_code"] = "NotPermitted"
    with pytest.raises(ValueError, match="manifest-authenticated"):
        VerifiedCommittedTransaction.from_payload(mismatched)

    for invalid_code in (True, "18", 0, 0x1_0000_0000):
        malformed = dict(payload)
        malformed["contract_rejection"] = {
            **payload["contract_rejection"],
            "code": invalid_code,
        }
        with pytest.raises((TypeError, ValueError), match="contract rejection code"):
            VerifiedCommittedTransaction.from_payload(malformed)

    for field, invalid_value in (
        ("error_type", "bad identity"),
        ("error_type", "__kotodama_link_hidden"),
        ("schema_hash", "AB" * 31),
        ("schema_hash", "AB" * 33),
        ("schema_hash", True),
        ("schema_hash", "AB" * 31 + "100"),
        ("schema_hash", "AB" * 31 + "A8"),
        ("schema_hash", [7] * 32),
        ("schema_hash", "ab" * 32),
        ("schema_hash", "Ab" * 32),
        ("schema_hash", "AB" * 31 + "AG"),
        ("schema_hash", "AB" * 31 + "A "),
        ("name", "bad name"),
        ("message", True),
        ("message", ""),
        ("message", "\u3000\n"),
        ("message", "あ" * 1366),
        ("message", "\ud800"),
    ):
        malformed = dict(payload)
        malformed["contract_rejection"] = {
            **payload["contract_rejection"],
            field: invalid_value,
        }
        with pytest.raises((TypeError, ValueError), match="contract rejection"):
            VerifiedCommittedTransaction.from_payload(malformed)


class FakeInstruction:
    def __init__(self, payload: bytes, wire_id: str) -> None:
        self.payload = payload
        self._wire_id = wire_id

    def to_norito_bytes(self) -> bytes:
        return self.payload

    def wire_id(self) -> str:
        return self._wire_id


class FakeDraft:
    def __init__(self) -> None:
        self.entries: list[tuple[Any, ...]] = []
        self.explicit_batch = False

    def use_executable_batch(self) -> "FakeDraft":
        self.explicit_batch = True
        return self

    def add_contract_call(self, *entry: Any) -> None:
        self.entries.append(("contract_call", *entry))

    def add_instruction(self, instruction: FakeInstruction) -> None:
        self.entries.append(("instruction", instruction))


def _prepared_batch_response(
    calls: list[ContractCallIntent],
    instruction: FakeInstruction,
) -> dict[str, Any]:
    arguments = [b"first-arguments", b"second-arguments"]
    binding_items: list[dict[str, Any]] = []
    prepared_entries: list[dict[str, Any]] = []
    for index, (call, encoded_arguments) in enumerate(zip(calls, arguments, strict=True)):
        address = call.expected_contract_address or call.contract_address
        code_hash = call.expected_code_hash_hex
        abi_hash = call.expected_abi_hash_hex
        binding_items.append(
            {
                "index": index,
                "kind": "contract_call",
                "contract_alias": call.contract_alias,
                "contract_address": address,
                "dataspace": "payments",
                "code_hash_hex": code_hash,
                "abi_hash_hex": abi_hash,
                "entrypoint": call.entrypoint,
                "payload_digest_hex": f"{index + 1:064x}",
                "arguments_digest_hex": blake3(
                    client_module._CONTRACT_CALL_BATCH_ARGUMENTS_DOMAIN_V1
                    + b"\x01"
                    + encoded_arguments
                ).hexdigest(),
            }
        )
        prepared_entries.append(
            {
                "index": index,
                "kind": "contract_call",
                "contract_address": address,
                "code_hash_hex": code_hash,
                "abi_hash_hex": abi_hash,
                "entrypoint": call.entrypoint,
                "arguments_b64": base64.b64encode(encoded_arguments).decode(
                    "ascii"
                ),
            }
        )
    instruction_index = len(calls)
    instruction_bytes = instruction.to_norito_bytes()
    binding_items.append(
        {
            "index": instruction_index,
            "kind": "instruction",
            "wire_id": instruction.wire_id(),
            "instruction_digest_hex": blake3(
                client_module._CONTRACT_CALL_BATCH_INSTRUCTION_DOMAIN_V1
                + instruction_bytes
            ).hexdigest(),
        }
    )
    prepared_entries.append(
        {
            "index": instruction_index,
            "kind": "instruction",
            "wire_id": instruction.wire_id(),
            "instruction_b64": base64.b64encode(instruction_bytes).decode(
                "ascii"
            ),
        }
    )
    binding = {"version": 1, "items": binding_items}
    binding_bytes = json.dumps(
        binding,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return {
        "ok": True,
        "binding": binding,
        "binding_digest_hex": blake3(
            client_module._CONTRACT_CALL_BATCH_BINDING_DOMAIN_V1 + binding_bytes
        ).hexdigest(),
        "prepared_entries": prepared_entries,
    }


def test_contract_intents_prepare_ordered_batch_and_keep_signing_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    crypto = types.ModuleType(f"{PURE_PACKAGE}.crypto")
    crypto.Instruction = FakeInstruction
    monkeypatch.setitem(sys.modules, f"{PURE_PACKAGE}.crypto", crypto)
    first = ContractCallIntent(
        "pay",
        contract_alias="wallet::payments",
        payload={"amount": "10"},
        expected_contract_address="contract:wallet",
        expected_code_hash_hex="a" * 64,
        expected_abi_hash_hex="b" * 64,
    )
    second = ContractCallIntent(
        "record",
        contract_address="contract:audit",
        payload={"reference": "r-1"},
        expected_code_hash_hex="c" * 64,
        expected_abi_hash_hex="d" * 64,
    )
    instruction = FakeInstruction(b"native-instruction", "transfer_asset")
    session = FakeSession(
        [_response(_prepared_batch_response([first, second], instruction))]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    draft = FakeDraft()
    submitted: dict[str, Any] = {}
    client._transaction_draft = lambda **kwargs: draft

    def submit(prepared_draft: FakeDraft, **kwargs: Any) -> dict[str, Any]:
        submitted.update(kwargs)
        return {
            "hash": "ef" * 32,
            "submission": {"accepted": True},
        }

    client._submit_transaction_draft_result = submit

    result = client.call_contract_batch_and_wait(
        authority="authority@payments",
        private_key_hex="11" * 32,
        entries=[first, second, instruction],
        metadata={"case_reference": "r-1"},
        wait=False,
    )

    assert draft.explicit_batch is True
    assert [entry[0] for entry in draft.entries] == [
        "contract_call",
        "contract_call",
        "instruction",
    ]
    assert submitted["private_key_hex"] == "11" * 32
    request_body = session.calls[0]["data"]
    assert b"11" * 32 not in request_body
    assert result["tx_hash_hex"] == "ef" * 32


def test_single_contract_call_is_the_local_batch_convenience_form() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([]),
        max_retries=0,
    )
    captured: dict[str, Any] = {}

    def call_batch(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "hash": "ab" * 32,
            "submission": {"accepted": True},
        }

    client.call_contract_batch_and_wait = call_batch
    result = client.call_contract_and_wait(
        authority="authority@payments",
        private_key=b"\x22" * 32,
        contract_alias="wallet::payments",
        entrypoint="pay",
        payload={"amount": "10"},
        metadata={"case_reference": "r-1"},
        wait=False,
    )

    assert len(captured["entries"]) == 1
    assert isinstance(captured["entries"][0], ContractCallIntent)
    assert captured["private_key"] == b"\x22" * 32
    assert captured["private_key_hex"] is None
    assert "chain_id" not in captured
    assert result["tx_hashes"] == ["ab" * 32]


def test_verified_committed_transaction_requires_explicit_trust_before_request() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0)
    with pytest.raises(TypeError, match="required keyword-only"):
        client.get_verified_committed_transaction(
            transaction_hash="11" * 32, authority="authority@payments",
            network_id=NETWORK_ID, private_key=b"\x11" * 32,
        )


def test_committed_output_crypto_wrapper_requires_and_forwards_exact_trust_inputs() -> None:
    # Exercise the actual source wrapper without loading an older installed native ABI.
    # Cryptographic acceptance is covered by the real-BLS native boundary tests.
    import ast
    from typing import Mapping

    source = (PACKAGE_ROOT / "crypto.py").read_text()
    node = next(item for item in ast.parse(source).body
                if isinstance(item, ast.FunctionDef)
                and item.name == "verify_committed_transaction_inclusion")
    calls = []
    native = types.SimpleNamespace(verify_committed_transaction_inclusion=
        lambda *args: calls.append(args) or ('{"output_hash":"verified"}', b"promoted-checkpoint"))
    contract = types.ModuleType("contract")
    _install_network_id_contract(contract)
    namespace = {"_crypto": native, "_require_network_id": contract._require_network_id,
                 "NetworkId": FakeNetworkId, "Mapping": Mapping, "Any": Any, "json": json}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "crypto.py", "exec"), namespace)
    verify = namespace["verify_committed_transaction_inclusion"]
    trust = dict(native_finality_proof_chain_json="[exact-native-proof]", expected_network_id=NETWORK_ID,
                 expected_chain="trusted-chain", trusted_checkpoint=b"trusted-checkpoint")
    assert verify("transaction", b"response", **trust) == {"output_hash": "verified", "promoted_checkpoint": b"promoted-checkpoint"}
    assert calls == [("transaction", b"response", "[exact-native-proof]", NETWORK_ID, "trusted-chain", b"trusted-checkpoint")]
    for response in [bytearray(b"response"), memoryview(b"response")]:
        with pytest.raises(TypeError, match="exact immutable bytes"):
            verify("transaction", response, **trust)
    with pytest.raises(TypeError, match="expected_network_id must be a NetworkId"):
        verify("transaction", b"response", **{**trust, "expected_network_id": b"untrusted"})
    with pytest.raises(ValueError, match="16 MiB"):
        verify("transaction", b"response", **{**trust, "native_finality_proof_chain_json": " " * (16 * 1024 * 1024 + 1)})
    with pytest.raises(TypeError, match="required keyword-only"):
        verify("transaction", b"response")
    assert len(calls) == 1


def test_committed_verifier_rejects_mutable_or_empty_checkpoint_before_native_call() -> None:
    import ast
    from typing import Mapping
    node = next(item for item in ast.parse((PACKAGE_ROOT / "crypto.py").read_text()).body
                if isinstance(item, ast.FunctionDef) and item.name == "verify_committed_transaction_inclusion")
    calls = []
    native = types.SimpleNamespace(verify_committed_transaction_inclusion=lambda *args: calls.append(args))
    contract = types.ModuleType("contract")
    _install_network_id_contract(contract)
    namespace = {"_crypto": native, "_require_network_id": contract._require_network_id,
                 "NetworkId": FakeNetworkId, "Mapping": Mapping, "Any": Any, "json": json}
    exec(compile(ast.Module(body=[node], type_ignores=[]), "crypto.py", "exec"), namespace)
    verify = namespace["verify_committed_transaction_inclusion"]
    trust = dict(native_finality_proof_chain_json="[]", expected_network_id=NETWORK_ID,
                 expected_chain="chain", trusted_checkpoint=b"checkpoint")
    for checkpoint in (bytearray(b"checkpoint"), memoryview(b"checkpoint")):
        with pytest.raises(TypeError, match="exact immutable bytes"):
            verify("transaction", b"response", **{**trust, "trusted_checkpoint": checkpoint})
    for checkpoint in (b"", b"x" * (68 * 1024 * 1024 + 1)):
        with pytest.raises(ValueError, match="68 MiB"):
            verify("transaction", b"response", **{**trust, "trusted_checkpoint": checkpoint})
    for chain in ("", "x" * 1025):
        with pytest.raises(ValueError, match="1024 UTF-8"):
            verify("transaction", b"response", **{**trust, "expected_chain": chain})
    assert calls == []
