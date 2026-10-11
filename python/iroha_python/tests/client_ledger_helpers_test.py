from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
from decimal import Decimal
from pathlib import Path
from typing import Callable
from urllib.parse import quote, urlsplit

import pytest
import requests

import iroha_python.client as client_module
import iroha_python.crypto as crypto_module
from client_expensive_query_test_support import authenticated_query_client
from iroha_python import (
    AccountAsset,
    AssetHolder,
    CommittedTransaction,
    ContractCallIntent,
    Ed25519KeyPair,
    ExplorerRwaRecord,
    F,
    FilterError,
    Instruction,
    KotodamaQuantity,
    ListQuery,
    ListQueryError,
    LocalSigningContext,
    NetworkId,
    RwaLot,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    ToriiError,
    ToriiQueryError,
    TransactionConfig,
    TransactionDraft,
    UaidPortfolioAsset,
    authority_fee_payment,
)
from iroha_python._privacy_backends import (
    _VERIFIER_BACKEND_REGISTRY_LABELS_V1,
    _is_verifier_backend_registry_label_v1,
    _require_verifier_backend_registry_label_v1,
    _verifier_backend_registry_tag_v1,
)
from iroha_python.client import ACCOUNT_ONBOARDING_TOKEN_HEADER, DATA_MODEL_VERSION
from iroha_python.repo import (
    RepoAgreementRecord,
    RepoCashLeg,
    RepoCollateralLeg,
)
from iroha_python.settlement import SettlementLeg
from iroha_python.tx import (
    _normalize_quantity,
    _normalize_rwa_quantity_fields,
    _normalize_u128_quantity,
)

CANONICAL_GENESIS_HASH = bytes([0xA5]) * 32
NETWORK_ID = NetworkId.from_bytes(CANONICAL_GENESIS_HASH)
FEE_PAYMENT = authority_fee_payment(charge_limits=[])
FAUCET_ASSET_DEFINITION_ID = "4rPeAP6jAjiLVZThZYwwPRBuQagt"
ALTERNATE_FAUCET_ASSET_DEFINITION_ID = "61CtjvNd9T3THAR65GsMVHr82Bjc"
FAUCET_AMOUNT = "100"
VK_LOCAL_SIGNING_CONTEXT = LocalSigningContext(NETWORK_ID)
TRANSACTION_LOCAL_SIGNING_CONTEXT = LocalSigningContext(NETWORK_ID)

def canonical_proof_attachment(
    *,
    backend: str = "pipa-r/pasta",
    proof_bytes: bytes = b"proof-bytes",
    vk_backend: str | None = None,
    vk_name: str = "vk_transfer",
) -> dict[str, object]:
    return {
        "backend": backend,
        "proof": {"backend": backend, "bytes": proof_bytes},
        "vk_ref": {"backend": vk_backend or backend, "name": vk_name},
    }


def iroha_hash_bytes(payload: bytes) -> bytes:
    digest = bytearray(hashlib.blake2b(payload, digest_size=32).digest())
    digest[-1] |= 1
    return bytes(digest)


def test_data_model_version_matches_current_wire_contract() -> None:
    assert DATA_MODEL_VERSION == 4


def test_signed_pipeline_details_is_exact_network_bound_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction_hash = "ab" * 32
    captured: dict[str, object] = {}

    def build_query(
        authority: str,
        private_key: bytes,
        network_id: NetworkId,
        entrypoint_hash: str,
    ) -> bytes:
        captured.update(
            authority=authority,
            private_key=private_key,
            network_id=network_id,
            entrypoint_hash=entrypoint_hash,
        )
        return b"signed-find-transactions"

    monkeypatch.setattr(
        crypto_module,
        "build_find_committed_transaction_query",
        build_query,
    )
    session = FakeSession(
        [
            response(
                200,
                {
                    "hash": transaction_hash,
                    "transaction": {"entrypoint_hash": transaction_hash},
                    "trigger_completions": [],
                },
            )
        ]
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        max_retries=4,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
    )

    details = client.get_pipeline_transaction_details(
        transaction_hash,
        authority="alice@wonderland",
        private_key=bytes([0x51]) * 32,
    )

    assert details["hash"] == transaction_hash
    assert captured == {
        "authority": "alice@wonderland",
        "private_key": bytes([0x51]) * 32,
        "network_id": NETWORK_ID,
        "entrypoint_hash": transaction_hash,
    }
    assert len(session.calls) == 1
    assert session.calls[0]["path"] == "/v1/pipeline/transactions/details"
    assert session.calls[0]["data"] == b"signed-find-transactions"
    assert session.calls[0]["allow_redirects"] is False
    assert session.calls[0]["headers"] == {
        "Content-Type": "application/x-norito",
        "Accept": "application/json",
    }


@pytest.mark.parametrize("redirect_status", [307, 308])
def test_signed_pipeline_details_never_replays_redirects(
    monkeypatch: pytest.MonkeyPatch,
    redirect_status: int,
) -> None:
    monkeypatch.setattr(
        crypto_module,
        "build_find_committed_transaction_query",
        lambda *_args: b"signed-find-transactions",
    )
    session = FakeSession([response(redirect_status, {"redirect": True})])
    client = ToriiClient(
        "https://torii.example",
        session=session,
        max_retries=4,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
    )

    with pytest.raises(RuntimeError, match=f"unexpected status {redirect_status}"):
        client.get_pipeline_transaction_details(
            "cd" * 32,
            authority="alice@wonderland",
            private_key=bytes([0x51]) * 32,
        )

    assert len(session.calls) == 1
    assert session.calls[0]["allow_redirects"] is False


def test_confidential_gas_schedule_has_no_runtime_setter() -> None:
    assert not hasattr(ToriiClient, "set_confidential_gas_schedule")


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
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self.responses:
            raise AssertionError(f"unexpected request {method} {url}")
        response = self.responses.pop(0)
        response.url = url
        return response

    def send(
        self, request: requests.PreparedRequest, **kwargs: object
    ) -> requests.Response:
        url = request.url or ""
        self.calls.append(
            {
                "method": request.method,
                "path": urlsplit(url).path,
                "params": None,
                "data": request.body,
                "headers": dict(request.headers),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self.responses:
            raise AssertionError(f"unexpected prepared request {request.method} {url}")
        response = self.responses.pop(0)
        response.url = url
        return response


class OnboardingSession(requests.Session):
    def __init__(self, responses: list[requests.Response]):
        super().__init__()
        self.responses = responses
        self.calls: list[dict[str, object]] = []
        self.adapter = requests.adapters.HTTPAdapter(max_retries=0)

    def get_adapter(self, _url: str) -> requests.adapters.HTTPAdapter:
        return self.adapter

    def request(self, method: str, url: str, **kwargs: object) -> requests.Response:
        self.calls.append(
            {
                "method": method,
                "path": urlsplit(url).path,
                "headers": dict(kwargs.get("headers") or {}),
                "data": kwargs.get("data"),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        if not self.responses:
            raise AssertionError(f"unexpected request {method} {url}")
        response = self.responses.pop(0)
        response.url = url
        return response


def response(
    status: int,
    payload: object | None = None,
    *,
    text: str = "",
    headers: dict[str, str] | None = None,
) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result.headers.update(headers or {})
    if payload is None:
        result._content = text.encode("utf-8")
    else:
        result._content = json.dumps(payload).encode("utf-8")
        result.headers["Content-Type"] = "application/json"
    result._content_consumed = True
    return result


ONBOARDING_TOKEN = "0123456789abcdef0123456789ABCDEF"
ONBOARDING_KEY_PAIR = Ed25519KeyPair.from_private_key(bytes(range(1, 33)))
ONBOARDING_ACCOUNT_ID = client_module.AccountAddress.from_account(
    public_key=ONBOARDING_KEY_PAIR.public_key,
).to_i105(client_module.DEFAULT_I105_DISCRIMINANT)


def onboarding_canonical_auth(
    *,
    network_id: NetworkId = NETWORK_ID,
    signer: Callable[[bytes], bytes] | None = None,
) -> ToriiCanonicalRequestAuth:
    return ToriiCanonicalRequestAuth(
        network_id=network_id.literal,
        account_id=ONBOARDING_ACCOUNT_ID,
        signer=signer or (lambda _message: b"\x55" * 64),
    )


def prepared_binding(kind: str) -> dict[str, object]:
    return {
        "schema": "iroha.prepared-operation.binding.v1",
        "semantic_hash_hex": ("11" if kind == "onboarding" else "55") * 32,
        "kind": kind,
        "request_id": "cd" * 32,
        "execution_expires_at_unix_ms": 4_000_000_000_000,
    }


def canonical_hash_literal(hex_value: str) -> str:
    body = hex_value.upper()
    checksum = client_module._crc16_ccitt_false(f"hash:{body}".encode("ascii"))
    return f"hash:{body}#{checksum:04X}"


def onboarding_request(*, permissions: list[str] | None = None) -> dict[str, object]:
    return {
        "version": 1,
        "alias": "merchant@universal",
        "account_id": ONBOARDING_ACCOUNT_ID,
        "permissions": [] if permissions is None else permissions,
    }


def onboarding_receipt() -> dict[str, object]:
    return {
        "body": {
            "version": 1,
            "valid_until_ms": 4_000_000_000_000,
            "request": onboarding_request(),
            "resource": {
                "disposition": {"kind": "create", "value": None},
            },
        },
        "plan_hash": canonical_hash_literal("11" * 32),
        "signature": "02",
    }


def atomic_onboarding_state(
    *,
    account_id: str = ONBOARDING_ACCOUNT_ID,
    alias: str = "merchant@universal",
    network_id: str = NETWORK_ID.literal,
    account_exists: bool = True,
    alias_target_account_id: str | None = ONBOARDING_ACCOUNT_ID,
    observed_block_height: int = 19,
    observed_block_hash: str = canonical_hash_literal("ab" * 32),
) -> dict[str, object]:
    return {
        "version": 1,
        "network_id": network_id,
        "account_id": account_id,
        "alias": alias,
        "account_exists": account_exists,
        "alias_target_account_id": alias_target_account_id,
        "observed_block_height": observed_block_height,
        "observed_block_hash": observed_block_hash,
    }


def prepared_onboarding() -> dict[str, object]:
    return {
        "schema": "iroha.prepared-transaction.v1",
        "binding": prepared_binding("onboarding"),
        "operation": "onboarding",
        "receipt": onboarding_receipt(),
        "semantic_hash_hex": "11" * 32,
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
        "disposition": {"kind": "create", "value": None},
        "transaction_hash_hex": "23" * 32,
        "signed_transaction_wire_hex": "0102",
        "signed_transaction_wire_sha256": "33" * 32,
        "fee_payment": copy.deepcopy(FEE_PAYMENT),
        "server_signature": "44" * 64,
    }


def prepared_faucet() -> dict[str, object]:
    claim = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "pow_anchor_height": 7,
        "pow_nonce_hex": "0000000000000000",
    }
    return {
        "schema": "iroha.prepared-transaction.v1",
        "binding": prepared_binding("faucet"),
        "operation": "faucet",
        "claim": claim,
        "semantic_hash_hex": "55" * 32,
        "account_id": ONBOARDING_ACCOUNT_ID,
        "asset_definition_id": FAUCET_ASSET_DEFINITION_ID,
        "asset_id": f"{FAUCET_ASSET_DEFINITION_ID}#{ONBOARDING_ACCOUNT_ID}",
        "amount": FAUCET_AMOUNT,
        "transaction_hash_hex": "67" * 32,
        "signed_transaction_wire_hex": "0304",
        "signed_transaction_wire_sha256": "77" * 32,
        "fee_payment": copy.deepcopy(FEE_PAYMENT),
        "server_signature": "88" * 64,
    }


def test_faucet_prepared_transcript_uses_direct_required_pow_values() -> None:
    prepared = prepared_faucet()
    transcript = client_module._prepared_signature_transcript(
        prepared,
        "prepared faucet transcript",
    )

    assert client_module._prepared_signature_field("claim.pow_anchor_height", "7") in transcript
    assert (
        client_module._prepared_signature_field(
            "claim.pow_nonce_hex",
            "0000000000000000",
        )
        in transcript
    )
    assert b"some:7" not in transcript
    assert b"some:0000000000000000" not in transcript
    assert b"none" not in transcript


def test_prepared_transaction_rejects_hash_without_iroha_marker() -> None:
    prepared = prepared_onboarding()
    prepared["transaction_hash_hex"] = "22" * 32

    with pytest.raises(ValueError, match="canonical Iroha HashOf marker"):
        client_module._copy_prepared_transaction(
            prepared,
            expected_operation="onboarding",
            context="prepared transaction",
        )


def test_prepared_transaction_signature_v1_shared_golden_is_exact() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "prepared_transactions"
        / "prepared_transaction_signature_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert fixture["schema"] == "iroha.prepared-transaction-signature-fixture.v1"
    assert fixture["transcript_schema"] == client_module.PREPARED_SIGNATURE_TRANSCRIPT_SCHEMA
    assert (
        bytes.fromhex(fixture["signature_domain_hex"])
        == client_module.PREPARED_SIGNATURE_DOMAIN
    )
    assert fixture["frame_length_encoding"] == "u64_be"
    assert fixture["digest_algorithm"] == "iroha_blake2b_256"
    assert [vector["name"] for vector in fixture["vectors"]] == [
        "onboarding_prepared",
        "onboarding_proof_required",
        "faucet_prepared",
    ]
    for vector in fixture["vectors"]:
        response_payload = vector["response"]
        if vector["name"] == "onboarding_proof_required":
            binding = response_payload["binding"]
            transcript = client_module._prepared_binding_transcript(
                response_payload["schema"], "onboarding", binding
            )
            for label in (
                "outcome",
                "proof_kind",
                "semantic_hash_hex",
                "account_id",
                "alias",
            ):
                transcript.extend(
                    client_module._prepared_signature_field(label, str(response_payload[label]))
                )
            transcript.extend(client_module._prepared_signature_field("disposition", "no_op"))
            transcript_bytes = bytes(transcript)
        else:
            operation = "onboarding" if vector["name"] == "onboarding_prepared" else "faucet"
            exact_payload = client_module._copy_prepared_transaction(
                response_payload,
                expected_operation=operation,
                context=f"shared golden {vector['name']}",
            )
            transcript_bytes = client_module._prepared_signature_transcript(
                exact_payload, f"shared golden {vector['name']}"
            )
        assert transcript_bytes.hex() == vector["transcript_hex"]
        digest = crypto_module.hash_blake2b_32(transcript_bytes)
        assert digest.hex() == vector["digest_hex"]
        public_key = bytes.fromhex(
            crypto_module.AccountId(vector["signer_account_id"]).public_key_hex
        )
        signature = bytes.fromhex(vector["server_signature_hex"])
        assert response_payload["server_signature"] == vector["server_signature_hex"].upper()
        assert crypto_module.verify_ed25519(public_key, digest, signature)


def test_prepared_transaction_v1_shared_golden_authenticates_inner_context() -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "prepared_transactions"
        / "prepared_transaction_signature_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    for vector in fixture["vectors"]:
        if vector["name"] == "onboarding_proof_required":
            continue
        prepared = vector["response"]
        network_id = NetworkId.parse(vector["network_id"])
        operation_context = (
            {
                "receipt": prepared["receipt"],
                "account_id": prepared["account_id"],
                "alias": prepared["alias"],
                "disposition": prepared["disposition"],
            }
            if vector["name"] == "onboarding_prepared"
            else {
                "claim": prepared["claim"],
                "account_id": prepared["account_id"],
                "asset_definition_id": prepared["asset_definition_id"],
                "asset_id": prepared["asset_id"],
                "amount": prepared["amount"],
            }
        )
        envelope = crypto_module.verify_prepared_transaction_context_v1(
            bytes.fromhex(prepared["signed_transaction_wire_hex"]),
            network_id,
            vector["signer_account_id"],
            json.dumps(prepared["binding"], sort_keys=True, separators=(",", ":")),
            prepared["operation"],
            prepared["semantic_hash_hex"],
            json.dumps(prepared["fee_payment"], sort_keys=True, separators=(",", ":")),
            json.dumps(operation_context, sort_keys=True, separators=(",", ":")),
        )
        assert envelope.hash_hex() == prepared["transaction_hash_hex"]
        substituted_context = copy.deepcopy(operation_context)
        if vector["name"] == "onboarding_prepared":
            substituted_context["disposition"] = {"kind": "conflict", "value": None}
        else:
            substituted_context["amount"] = "6"
        with pytest.raises(ValueError, match="invalid prepared transaction context"):
            crypto_module.verify_prepared_transaction_context_v1(
                bytes.fromhex(prepared["signed_transaction_wire_hex"]),
                network_id,
                vector["signer_account_id"],
                json.dumps(prepared["binding"], sort_keys=True, separators=(",", ":")),
                prepared["operation"],
                prepared["semantic_hash_hex"],
                json.dumps(prepared["fee_payment"], sort_keys=True, separators=(",", ":")),
                json.dumps(substituted_context, sort_keys=True, separators=(",", ":")),
            )
        if vector["name"] == "onboarding_prepared":
            receipt = prepared["receipt"]
            request = receipt["body"]["request"]
            assert (
                crypto_module.verify_account_onboarding_receipt_v1(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                    network_id,
                    vector["signer_account_id"],
                    request["account_id"],
                    request["alias"],
                    json.dumps(request["permissions"], separators=(",", ":")),
                )
                == prepared["semantic_hash_hex"]
            )
            with pytest.raises(ValueError, match="invalid account onboarding receipt"):
                crypto_module.verify_account_onboarding_receipt_v1(
                    json.dumps(receipt, sort_keys=True, separators=(",", ":")),
                    network_id,
                    vector["signer_account_id"],
                    request["account_id"],
                    request["alias"],
                    '["CanGrantAccountPermission"]',
                )


@pytest.mark.parametrize("name", ["onboarding_prepared", "faucet_prepared"])
def test_prepared_transaction_v1_rejects_validly_signed_missing_operation_binding(name: str) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "prepared_transactions"
        / "prepared_transaction_signature_v1.json"
    )
    vector = next(
        vector
        for vector in json.loads(fixture_path.read_text(encoding="utf-8"))["vectors"]
        if vector["name"] == name
    )
    prepared = vector["response"]

    def compact_length(value: int) -> bytes:
        encoded = bytearray()
        while value >= 128:
            encoded.append((value & 127) | 128)
            value >>= 7
        encoded.append(value)
        return bytes(encoded)

    def field(value: bytes) -> bytes:
        return compact_length(len(value)) + value

    def read_field(wire: bytes, offset: int) -> tuple[bytes, int]:
        length = 0
        shift = 0
        while True:
            byte = wire[offset]
            offset += 1
            length |= (byte & 127) << shift
            if byte < 128:
                break
            shift += 7
        return wire[offset : offset + length], offset + length

    original_wire = bytes.fromhex(prepared["signed_transaction_wire_hex"])
    _, offset = read_field(original_wire, 1)  # authority signature
    payload, _ = read_field(original_wire, offset)
    fields = []
    offset = 0
    for _ in range(9):
        value, offset = read_field(payload, offset)
        fields.append(value)
    assert offset == len(payload)
    # Metadata is the eighth field in the sole current payload layout. Remove the
    # signed prepared-operation binding, then sign that otherwise valid transaction.
    assert b"prepared_semantic_hash" in fields[7]
    # Metadata's canonical element sequence has a fixed u64 zero count.
    fields[7] = bytes(8)
    unbound_payload = b"".join(field(value) for value in fields)
    seed = bytes([0x51 if name == "onboarding_prepared" else 0x61]) * 32
    signer = crypto_module.derive_ed25519_keypair_from_seed(seed)
    signature = crypto_module.sign_ed25519(
        signer.private_key, crypto_module.hash_blake2b_32(unbound_payload)
    )
    signature_wire = len(signature).to_bytes(8, "little") + b"".join(
        field(bytes([byte])) for byte in signature
    )
    unbound_wire = b"\x01" + field(field(signature_wire)) + field(unbound_payload) + field(b"\x00")
    network_id = NetworkId.parse(vector["network_id"])
    # The negative case must reach the prepared verifier with a valid signature.
    crypto_module.signed_transaction_envelope_from_versioned_v1(unbound_wire, network_id)
    operation_context = (
        {
            "receipt": prepared["receipt"],
            "account_id": prepared["account_id"],
            "alias": prepared["alias"],
            "disposition": prepared["disposition"],
        }
        if name == "onboarding_prepared"
        else {
            "claim": prepared["claim"],
            "account_id": prepared["account_id"],
            "asset_definition_id": prepared["asset_definition_id"],
            "asset_id": prepared["asset_id"],
            "amount": prepared["amount"],
        }
    )
    with pytest.raises(ValueError, match="invalid prepared transaction context"):
        crypto_module.verify_prepared_transaction_context_v1(
            unbound_wire,
            network_id,
            vector["signer_account_id"],
            json.dumps(prepared["binding"], sort_keys=True, separators=(",", ":")),
            prepared["operation"],
            prepared["semantic_hash_hex"],
            json.dumps(prepared["fee_payment"], sort_keys=True, separators=(",", ":")),
            json.dumps(operation_context, sort_keys=True, separators=(",", ":")),
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("pow_anchor_height", None),
        ("pow_anchor_height", 0),
        ("pow_nonce_hex", None),
        ("pow_nonce_hex", ""),
        ("pow_nonce_hex", "AA"),
    ],
)
def test_prepared_faucet_native_context_rejects_optional_pow_claim(
    field: str,
    invalid: object,
) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[3]
        / "fixtures"
        / "prepared_transactions"
        / "prepared_transaction_signature_v1.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    vector = next(
        vector for vector in fixture["vectors"] if vector["name"] == "faucet_prepared"
    )
    prepared = vector["response"]
    claim = copy.deepcopy(prepared["claim"])
    assert isinstance(claim, dict)
    claim[field] = invalid
    operation_context = {
        "claim": claim,
        "account_id": prepared["account_id"],
        "asset_definition_id": prepared["asset_definition_id"],
        "asset_id": prepared["asset_id"],
        "amount": prepared["amount"],
    }

    with pytest.raises(ValueError):
        crypto_module.verify_prepared_transaction_context_v1(
            bytes.fromhex(prepared["signed_transaction_wire_hex"]),
            NetworkId.parse(vector["network_id"]),
            vector["signer_account_id"],
            json.dumps(prepared["binding"], sort_keys=True, separators=(",", ":")),
            prepared["operation"],
            prepared["semantic_hash_hex"],
            json.dumps(prepared["fee_payment"], sort_keys=True, separators=(",", ":")),
            json.dumps(operation_context, sort_keys=True, separators=(",", ":")),
        )


def test_account_onboarding_is_explicit_plan_prepare_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = onboarding_receipt()
    prepared = prepared_onboarding()
    session = OnboardingSession(
        [
            response(200, receipt),
            response(200, prepared),
            response(
                200,
                {
                    "schema": "iroha.prepared-transaction-submit.v1",
                    "binding": prepared["binding"],
                    "operation": "onboarding",
                    "transaction_hash_hex": prepared["transaction_hash_hex"],
                    "outcome": "Pending",
                },
            ),
        ]
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_verify_prepared_transaction_authentication_v1",
        lambda *_, **__: None,
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        api_token="global-api-token",
    )

    plan = client.plan_account_onboarding(
        onboarding_token=ONBOARDING_TOKEN,
        alias="merchant@universal",
        account_id=ONBOARDING_ACCOUNT_ID,
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
        permissions=["CanFoo", "CanFoo", "CanBar"],
    )
    prepare = client.prepare_account_onboarding(
        onboarding_token=ONBOARDING_TOKEN,
        binding=prepared_binding("onboarding"),
        fee_payment=FEE_PAYMENT,
        receipt=receipt,
        expected_request=onboarding_request(),
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
    )
    submit = client.submit_prepared_account_onboarding(
        onboarding_token=ONBOARDING_TOKEN,
        prepared=prepared,
        expected_fee_payment=FEE_PAYMENT,
        expected_request=onboarding_request(),
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
    )

    assert [plan.status_code, prepare.status_code, submit.status_code] == [200, 200, 200]
    assert [call["path"] for call in session.calls] == [
        "/v1/accounts/onboard/plan",
        "/v1/accounts/onboard/prepare",
        "/v1/accounts/onboard",
    ]
    assert json.loads(session.calls[0]["data"]) == {
        "version": 1,
        "alias": "merchant@universal",
        "account_id": ONBOARDING_ACCOUNT_ID,
        "permissions": ["CanBar", "CanFoo"],
    }
    assert json.loads(session.calls[1]["data"]) == {
        "schema": "iroha.accounts.onboard.prepare.v1",
        "binding": prepared_binding("onboarding"),
        "receipt": receipt,
        "fee_payment": FEE_PAYMENT,
    }
    assert json.loads(session.calls[2]["data"]) == prepared
    for call in session.calls:
        assert call["method"] == "POST"
        assert call["allow_redirects"] is False
        headers = call["headers"]
        assert isinstance(headers, dict)
        assert headers[ACCOUNT_ONBOARDING_TOKEN_HEADER] == ONBOARDING_TOKEN
        assert headers["X-API-Token"] == "global-api-token"
        assert ONBOARDING_TOKEN.encode() not in call["data"]


def test_onboarding_receipt_permissions_must_match_complete_original_request() -> None:
    receipt = onboarding_receipt()
    body = receipt["body"]
    assert isinstance(body, dict)
    body.update(
        {
            "authority": ONBOARDING_ACCOUNT_ID,
            "network_id": NETWORK_ID.literal,
            "anchor": {},
            "acquisition": {},
            "quote_guard": {},
            "instructions": [],
            "owner_auto_renew_instruction": None,
            "valid_until_ms": 4_000_000_000_000,
        }
    )
    request = body["request"]
    assert isinstance(request, dict)
    request["permissions"] = ["CanGrantAccountPermission"]

    with pytest.raises(ValueError, match="complete request"):
        client_module._copy_account_onboarding_receipt_v1(
            receipt,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            expected_request=onboarding_request(),
            context="permission substitution",
        )


def test_proof_required_onboarding_uses_one_exact_atomic_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    session = OnboardingSession([response(200, atomic_onboarding_state())])
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    client = ToriiClient("https://torii.example", session=session)
    durable_binding = prepared_binding("onboarding")
    durable_binding["execution_expires_at_unix_ms"] = 1

    result = client.prove_account_onboarding_current_state(
        proof_required=proof_required,
        binding=durable_binding,
        receipt=onboarding_receipt(),
        expected_request=onboarding_request(),
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
        canonical_auth=onboarding_canonical_auth(),
    )
    assert result.kind == "Applied"
    assert result.block_height == 19
    assert result.block_hash == canonical_hash_literal("ab" * 32)
    assert [(call["method"], call["path"]) for call in session.calls] == [
        ("POST", "/v1/accounts/onboarding/current-state"),
    ]
    assert all(call["allow_redirects"] is False for call in session.calls)
    assert session.calls[0]["headers"]["Content-Type"] == "application/json"
    assert session.calls[0]["headers"]["Cache-Control"] == "no-cache"
    assert session.calls[0]["headers"]["X-Iroha-Account"]
    assert session.calls[0]["headers"]["X-Iroha-Signature"]
    assert session.calls[0]["headers"]["X-Iroha-Timestamp-Ms"]
    assert session.calls[0]["headers"]["X-Iroha-Nonce"]
    assert json.loads(session.calls[0]["data"]) == {
        "version": 1,
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }


def test_proof_required_onboarding_never_retries_atomic_post(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    session = OnboardingSession(
        [
            response(503, {"message": "retryable only for ordinary requests"}),
            response(200, atomic_onboarding_state()),
        ]
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        max_retries=4,
        backoff_initial=0,
        retry_on_methods=["POST"],
    )

    with pytest.raises(RuntimeError, match="unexpected status 503"):
        client.prove_account_onboarding_current_state(
            proof_required=proof_required,
            binding=prepared_binding("onboarding"),
            receipt=onboarding_receipt(),
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            canonical_auth=onboarding_canonical_auth(),
        )

    assert [(call["method"], call["path"]) for call in session.calls] == [
        ("POST", "/v1/accounts/onboarding/current-state"),
    ]


def test_proof_required_onboarding_rejects_adapter_retries_before_signing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    session = OnboardingSession([])
    session.adapter = requests.adapters.HTTPAdapter(max_retries=1)
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match="transport retries to be disabled"):
        client.prove_account_onboarding_current_state(
            proof_required=proof_required,
            binding=prepared_binding("onboarding"),
            receipt=onboarding_receipt(),
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            canonical_auth=onboarding_canonical_auth(),
        )

    assert session.calls == []


def test_proof_required_onboarding_rejects_missing_or_foreign_canonical_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    session = OnboardingSession([])
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    client = ToriiClient("https://torii.example", session=session)
    common = {
        "proof_required": proof_required,
        "binding": prepared_binding("onboarding"),
        "receipt": onboarding_receipt(),
        "expected_request": onboarding_request(),
        "expected_authority": ONBOARDING_ACCOUNT_ID,
        "network_id": NETWORK_ID,
    }

    with pytest.raises(ValueError, match="canonical_auth is required"):
        client.prove_account_onboarding_current_state(
            **common,
            canonical_auth=None,  # type: ignore[arg-type]
        )
    with pytest.raises(ValueError, match="must match network_id"):
        client.prove_account_onboarding_current_state(
            **common,
            canonical_auth=onboarding_canonical_auth(
                network_id=NetworkId.from_bytes(bytes([0xA7]) * 32)
            ),
        )

    assert session.calls == []


def test_proof_required_onboarding_classifies_absent_and_conflicting_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    substituted_key_pair = Ed25519KeyPair.from_private_key(bytes(range(33, 65)))
    substituted_account = client_module.AccountAddress.from_account(
        public_key=substituted_key_pair.public_key,
    ).to_i105(client_module.DEFAULT_I105_DISCRIMINANT)
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )

    for target, expected_kind in (
        (None, "AliasAbsent"),
        (substituted_account, "AliasConflict"),
    ):
        session = OnboardingSession(
            [
                response(
                    200,
                    atomic_onboarding_state(alias_target_account_id=target),
                )
            ]
        )
        client = ToriiClient("https://torii.example", session=session)
        result = client.prove_account_onboarding_current_state(
            proof_required=proof_required,
            binding=prepared_binding("onboarding"),
            receipt=onboarding_receipt(),
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            canonical_auth=onboarding_canonical_auth(),
        )
        assert result.kind == expected_kind
        assert len(session.calls) == 1


def test_proof_required_onboarding_rejects_open_substituted_or_unanchored_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    substituted_key_pair = Ed25519KeyPair.from_private_key(bytes(range(33, 65)))
    substituted_account = client_module.AccountAddress.from_account(
        public_key=substituted_key_pair.public_key,
    ).to_i105(client_module.DEFAULT_I105_DISCRIMINANT)
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    foreign_network_id = NetworkId.from_bytes(bytes([0xA7]) * 32).literal
    exact = atomic_onboarding_state()
    candidates: list[dict[str, object]] = []
    for field, value in (
        ("version", 2),
        ("network_id", foreign_network_id),
        ("account_id", substituted_account),
        ("alias", "other@universal"),
        ("account_exists", False),
        ("observed_block_height", 0),
        ("observed_block_hash", "not-a-typed-hash"),
        (
            "observed_block_hash",
            canonical_hash_literal("ab" * 32).lower(),
        ),
        ("alias_target_account_id", f" {ONBOARDING_ACCOUNT_ID}"),
    ):
        candidate = copy.deepcopy(exact)
        candidate[field] = value
        candidates.append(candidate)
    open_response = copy.deepcopy(exact)
    open_response["legacy_account_state"] = "applied"
    candidates.append(open_response)

    for candidate in candidates:
        session = OnboardingSession([response(200, candidate)])
        client = ToriiClient("https://torii.example", session=session)
        with pytest.raises((TypeError, ValueError)):
            client.prove_account_onboarding_current_state(
                proof_required=proof_required,
                binding=prepared_binding("onboarding"),
                receipt=onboarding_receipt(),
                expected_request=onboarding_request(),
                expected_authority=ONBOARDING_ACCOUNT_ID,
                network_id=NETWORK_ID,
                canonical_auth=onboarding_canonical_auth(),
            )
        assert [(call["method"], call["path"]) for call in session.calls] == [
            ("POST", "/v1/accounts/onboarding/current-state"),
        ]


def test_proof_required_onboarding_rejects_response_over_four_kib_before_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    oversized = atomic_onboarding_state()
    oversized["padding"] = "x" * (4 * 1024)
    session = OnboardingSession([response(200, oversized)])
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match="4096-byte limit"):
        client.prove_account_onboarding_current_state(
            proof_required=proof_required,
            binding=prepared_binding("onboarding"),
            receipt=onboarding_receipt(),
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            canonical_auth=onboarding_canonical_auth(),
        )

    assert [(call["method"], call["path"]) for call in session.calls] == [
        ("POST", "/v1/accounts/onboarding/current-state"),
    ]


def test_proof_required_onboarding_rejects_duplicate_response_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof_required = {
        "account_id": ONBOARDING_ACCOUNT_ID,
        "alias": "merchant@universal",
    }
    exact_body = json.dumps(atomic_onboarding_state(), separators=(",", ":"))
    duplicate_body = exact_body.replace(
        '"version":1',
        '"version":1,"version":1',
        1,
    )
    duplicate_response = response(200)
    duplicate_response._content = duplicate_body.encode("utf-8")
    duplicate_response.headers["Content-Type"] = "application/json"
    session = OnboardingSession([duplicate_response])
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_receipt_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    monkeypatch.setattr(
        client_module,
        "_copy_account_onboarding_proof_required_v1",
        lambda value, **_: copy.deepcopy(value),
    )
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match="duplicate object key 'version'"):
        client.prove_account_onboarding_current_state(
            proof_required=proof_required,
            binding=prepared_binding("onboarding"),
            receipt=onboarding_receipt(),
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            canonical_auth=onboarding_canonical_auth(),
        )

    assert [(call["method"], call["path"]) for call in session.calls] == [
        ("POST", "/v1/accounts/onboarding/current-state"),
    ]


@pytest.mark.parametrize(
    "token",
    [
        None,
        "",
        "T" * 31,
        "T" * 257,
        "T" * 31 + " ",
        "T" * 31 + "é",
    ],
)
def test_onboarding_prepare_rejects_malformed_route_token_before_dispatch(
    token: object,
) -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises((TypeError, ValueError)) as error:
        client.prepare_account_onboarding(
            onboarding_token=token,  # type: ignore[arg-type]
            binding=prepared_binding("onboarding"),
            fee_payment=FEE_PAYMENT,
            receipt={"body": {}},
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )

    if token:
        assert str(token) not in str(error.value)
    assert session.calls == []


def test_onboarding_requests_require_explicit_token_and_reject_global_default() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(TypeError, match="onboarding_token"):
        client.plan_account_onboarding(  # type: ignore[call-arg]
            alias="merchant@universal",
            account_id=ONBOARDING_ACCOUNT_ID,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    with pytest.raises(ValueError, match="pass onboarding_token explicitly"):
        ToriiClient(
            "https://torii.example",
            session=session,
            default_headers={ACCOUNT_ONBOARDING_TOKEN_HEADER.lower(): ONBOARDING_TOKEN},
        )
    assert session.calls == []


@pytest.mark.parametrize(
    "header_name",
    [
        "Authorization",
        "Proxy-Authorization",
        "Cookie",
        "Cookie2",
        "X-API-Token",
        "X-API-Key",
        "X-Auth-Token",
        ACCOUNT_ONBOARDING_TOKEN_HEADER,
        "X-Iroha-Account",
        "X-Iroha-Signature",
        "X-Iroha-Timestamp-Ms",
        "X-Iroha-Nonce",
        "X-Iroha-Witness",
        "X-Iroha-Operator-Public-Key",
        "X-Iroha-Operator-Signature",
        "X-Iroha-Operator-Timestamp-Ms",
        "X-Iroha-Operator-Nonce",
    ],
)
def test_client_rejects_session_route_secret_headers_at_construction(
    header_name: str,
) -> None:
    session = requests.Session()
    session.headers[header_name.swapcase()] = "must-not-leak"

    with pytest.raises(ValueError, match="session.headers") as error:
        ToriiClient("https://torii.example", session=session)

    assert "must-not-leak" not in str(error.value)


@pytest.mark.parametrize(
    ("header_name", "explicit_kwargs"),
    [
        ("Authorization", {"auth_token": "explicit-bearer"}),
        ("X-API-Token", {"api_token": "explicit-api-token"}),
        (
            "X-Iroha-Signature",
            {"canonical_request_auth": onboarding_canonical_auth()},
        ),
    ],
)
def test_client_rejects_session_route_secret_conflicts(
    header_name: str,
    explicit_kwargs: dict[str, object],
) -> None:
    session = requests.Session()
    session.headers[header_name] = "must-not-conflict"

    with pytest.raises(ValueError, match="session.headers") as error:
        ToriiClient("https://torii.example", session=session, **explicit_kwargs)

    assert "must-not-conflict" not in str(error.value)


def test_client_rejects_session_auth_and_cookies_but_keeps_harmless_headers() -> None:
    auth_session = requests.Session()
    auth_session.auth = ("retired-user", "must-not-leak")
    with pytest.raises(ValueError, match="session.auth") as auth_error:
        ToriiClient("https://torii.example", session=auth_session)
    assert "must-not-leak" not in str(auth_error.value)

    cookie_session = requests.Session()
    cookie_session.cookies.set("route_secret", "must-not-leak")
    with pytest.raises(ValueError, match="session.cookies") as cookie_error:
        ToriiClient("https://torii.example", session=cookie_session)
    assert "must-not-leak" not in str(cookie_error.value)

    harmless_session = requests.Session()
    harmless_session.headers["X-Trace-Id"] = "trace-only"
    client = ToriiClient("https://torii.example", session=harmless_session)
    assert client._session.headers["X-Trace-Id"] == "trace-only"


def test_prepared_account_mutations_require_explicit_trust_pins() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(TypeError, match="expected_authority"):
        client.submit_prepared_account_faucet(prepared_faucet())  # type: ignore[call-arg]
    with pytest.raises(TypeError, match="expected_authority"):
        client.submit_prepared_account_onboarding(  # type: ignore[call-arg]
            onboarding_token=ONBOARDING_TOKEN,
            prepared=prepared_onboarding(),
        )
    with pytest.raises(TypeError, match="expected_authority"):
        client.plan_account_onboarding(  # type: ignore[call-arg]
            onboarding_token=ONBOARDING_TOKEN,
            alias="merchant@universal",
            account_id=ONBOARDING_ACCOUNT_ID,
        )
    assert session.calls == []


def test_faucet_policy_pins_have_no_defaults() -> None:
    for method in (
        ToriiClient.prepare_account_faucet_registration,
        ToriiClient.prepare_account_faucet,
        ToriiClient.submit_prepared_account_faucet,
    ):
        parameters = inspect.signature(method).parameters
        for name in ("expected_asset_definition_id", "expected_amount"):
            assert parameters[name].default is inspect.Parameter.empty


def test_prepared_account_submissions_reject_expired_forward_binding() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)
    onboarding = prepared_onboarding()
    onboarding_binding = onboarding["binding"]
    assert isinstance(onboarding_binding, dict)
    onboarding_binding["execution_expires_at_unix_ms"] = 1
    faucet = prepared_faucet()
    faucet_binding = faucet["binding"]
    assert isinstance(faucet_binding, dict)
    faucet_binding["execution_expires_at_unix_ms"] = 1

    with pytest.raises(ValueError, match="expired"):
        client.submit_prepared_account_onboarding(
            onboarding_token=ONBOARDING_TOKEN,
            prepared=onboarding,
            expected_fee_payment=FEE_PAYMENT,
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    with pytest.raises(ValueError, match="expired"):
        client.submit_prepared_account_faucet(
            faucet,
            expected_fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    assert session.calls == []


def test_prepared_account_submissions_reject_independent_fee_substitution() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)
    substituted = authority_fee_payment(charge_limits=[], gas_limit=1)

    with pytest.raises(ValueError, match="independent selection"):
        client.submit_prepared_account_onboarding(
            onboarding_token=ONBOARDING_TOKEN,
            prepared=prepared_onboarding(),
            expected_fee_payment=substituted,
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    with pytest.raises(ValueError, match="independent selection"):
        client.submit_prepared_account_faucet(
            prepared_faucet(),
            expected_fee_payment=substituted,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    assert session.calls == []


def test_onboarding_plan_does_not_follow_redirect_or_accept_retired_fields() -> None:
    session = OnboardingSession([response(307, text="redirect")])
    client = ToriiClient("https://torii.example", session=session)

    result = client.plan_account_onboarding(
        onboarding_token=ONBOARDING_TOKEN,
        alias="merchant@universal",
        account_id=ONBOARDING_ACCOUNT_ID,
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
    )

    assert result.status_code == 307
    assert len(session.calls) == 1
    assert session.calls[0]["allow_redirects"] is False
    with pytest.raises(TypeError, match="uaid"):
        client.plan_account_onboarding(  # type: ignore[call-arg]
            onboarding_token=ONBOARDING_TOKEN,
            alias="merchant@universal",
            account_id=ONBOARDING_ACCOUNT_ID,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            uaid="retired",
        )


def test_prepared_submit_rejects_legacy_or_aggregate_envelopes_before_dispatch() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    legacy = prepared_onboarding()
    legacy["receipt_only"] = legacy.pop("signed_transaction_wire_hex")
    with pytest.raises(TypeError, match="exactly the onboarding V1 fields"):
        client.submit_prepared_account_onboarding(
            onboarding_token=ONBOARDING_TOKEN,
            prepared=legacy,
            expected_fee_payment=FEE_PAYMENT,
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    aggregate = {"operations": [prepared_onboarding()]}
    with pytest.raises(TypeError, match="exactly the onboarding V1 fields"):
        client.submit_prepared_account_onboarding(
            onboarding_token=ONBOARDING_TOKEN,
            prepared=aggregate,
            expected_fee_payment=FEE_PAYMENT,
            expected_request=onboarding_request(),
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    assert session.calls == []


def test_account_faucet_is_explicit_prepare_then_exact_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared = prepared_faucet()
    session = OnboardingSession(
        [
            response(200, prepared),
            response(
                200,
                {
                    "schema": "iroha.prepared-transaction-submit.v1",
                    "binding": prepared["binding"],
                    "operation": "faucet",
                    "transaction_hash_hex": prepared["transaction_hash_hex"],
                    "outcome": "Pending",
                },
            ),
        ]
    )
    authentication_contexts: list[str] = []

    def authenticate(*_: object, **kwargs: object) -> None:
        authentication_contexts.append(str(kwargs["context"]))

    monkeypatch.setattr(
        client_module,
        "_verify_prepared_transaction_authentication_v1",
        authenticate,
    )
    client = ToriiClient("https://torii.example", session=session)

    prepare = client.prepare_account_faucet(
        ONBOARDING_ACCOUNT_ID,
        binding=prepared_binding("faucet"),
        fee_payment=FEE_PAYMENT,
        expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
        expected_amount=FAUCET_AMOUNT,
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
        pow_anchor_height=7,
        pow_nonce_hex="0000000000000000",
    )
    submit = client.submit_prepared_account_faucet(
        prepared,
        expected_fee_payment=FEE_PAYMENT,
        expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
        expected_amount=FAUCET_AMOUNT,
        expected_authority=ONBOARDING_ACCOUNT_ID,
        network_id=NETWORK_ID,
    )

    assert [prepare.status_code, submit.status_code] == [200, 200]
    assert [call["path"] for call in session.calls] == [
        "/v1/accounts/faucet/prepare",
        "/v1/accounts/faucet",
    ]
    assert json.loads(session.calls[0]["data"]) == {
        "schema": "iroha.accounts.faucet.prepare.v1",
        "binding": prepared_binding("faucet"),
        "claim": prepared["claim"],
        "fee_payment": FEE_PAYMENT,
    }
    assert json.loads(session.calls[1]["data"]) == prepared
    assert all(call["allow_redirects"] is False for call in session.calls)
    assert authentication_contexts == [
        "prepare_account_faucet.response",
        "submit_prepared_account_faucet.prepared",
    ]


@pytest.mark.parametrize(
    ("field", "substituted", "message"),
    [
        ("asset_definition_id", ALTERNATE_FAUCET_ASSET_DEFINITION_ID, "asset_definition_id differs"),
        ("amount", "101", "amount differs"),
    ],
)
def test_faucet_prepare_rejects_independent_policy_substitution(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    substituted: str,
    message: str,
) -> None:
    prepared = prepared_faucet()
    prepared[field] = substituted
    if field == "asset_definition_id":
        prepared["asset_id"] = f"{substituted}#{ONBOARDING_ACCOUNT_ID}"
    session = OnboardingSession([response(200, prepared)])
    monkeypatch.setattr(
        client_module,
        "_verify_prepared_transaction_authentication_v1",
        lambda *_, **__: None,
    )
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match=message):
        client.prepare_account_faucet(
            ONBOARDING_ACCOUNT_ID,
            binding=prepared_binding("faucet"),
            fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            pow_anchor_height=7,
            pow_nonce_hex="0000000000000000",
        )

    assert [call["path"] for call in session.calls] == ["/v1/accounts/faucet/prepare"]


@pytest.mark.parametrize(
    ("field", "substituted", "message"),
    [
        ("asset_definition_id", ALTERNATE_FAUCET_ASSET_DEFINITION_ID, "asset_definition_id differs"),
        ("amount", "101", "amount differs"),
    ],
)
def test_faucet_submit_rejects_independent_policy_substitution_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    substituted: str,
    message: str,
) -> None:
    prepared = prepared_faucet()
    prepared[field] = substituted
    if field == "asset_definition_id":
        prepared["asset_id"] = f"{substituted}#{ONBOARDING_ACCOUNT_ID}"
    session = OnboardingSession([])
    monkeypatch.setattr(
        client_module,
        "_verify_prepared_transaction_authentication_v1",
        lambda *_, **__: None,
    )
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match=message):
        client.submit_prepared_account_faucet(
            prepared,
            expected_fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    ("expected_asset_definition_id", "expected_amount"),
    [
        ("", FAUCET_AMOUNT),
        (f" {FAUCET_ASSET_DEFINITION_ID}", FAUCET_AMOUNT),
        ("xor#sora", FAUCET_AMOUNT),
        ("4rPeAP6jAjiLVZThZYwwPRBuQagu", FAUCET_AMOUNT),
        (FAUCET_ASSET_DEFINITION_ID, "0"),
        (FAUCET_ASSET_DEFINITION_ID, "-1"),
        (FAUCET_ASSET_DEFINITION_ID, "01"),
        (FAUCET_ASSET_DEFINITION_ID, 100),
    ],
)
def test_faucet_prepare_rejects_invalid_independent_policy_before_dispatch(
    expected_asset_definition_id: object,
    expected_amount: object,
) -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises((TypeError, ValueError)):
        client.prepare_account_faucet(
            ONBOARDING_ACCOUNT_ID,
            binding=prepared_binding("faucet"),
            fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=expected_asset_definition_id,  # type: ignore[arg-type]
            expected_amount=expected_amount,  # type: ignore[arg-type]
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            pow_anchor_height=7,
            pow_nonce_hex="0000000000000000",
        )

    assert session.calls == []


def test_faucet_registration_rejects_invalid_policy_before_puzzle_dispatch() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match="positive exact quantity"):
        client.prepare_account_faucet_registration(
            ONBOARDING_ACCOUNT_ID,
            binding=prepared_binding("faucet"),
            fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount="0",
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )

    assert session.calls == []


def test_faucet_registration_rejects_explicit_empty_puzzle_without_dispatch() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(TypeError, match="exactly the V1 fields"):
        client.prepare_account_faucet_registration(
            ONBOARDING_ACCOUNT_ID,
            binding=prepared_binding("faucet"),
            fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            puzzle={},
        )

    assert session.calls == []


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("pow_anchor_height", None),
        ("pow_anchor_height", 0),
        ("pow_nonce_hex", None),
        ("pow_nonce_hex", ""),
        ("pow_nonce_hex", "0"),
        ("pow_nonce_hex", "AA"),
        ("pow_nonce_hex", "00" * 33),
    ],
)
def test_faucet_submit_rejects_optional_or_noncanonical_pow_before_dispatch(
    field: str,
    invalid: object,
) -> None:
    prepared = prepared_faucet()
    claim = prepared["claim"]
    assert isinstance(claim, dict)
    claim[field] = invalid
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises((TypeError, ValueError)):
        client.submit_prepared_account_faucet(
            prepared,
            expected_fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )

    assert session.calls == []


@pytest.mark.parametrize(
    ("account_id", "anchor", "nonce"),
    [
        ("merchant@universal", 7, "00"),
        (ONBOARDING_ACCOUNT_ID, True, "00"),
        (ONBOARDING_ACCOUNT_ID, None, "00"),
        (ONBOARDING_ACCOUNT_ID, 0, "00"),
        (ONBOARDING_ACCOUNT_ID, 1 << 64, "00"),
        (ONBOARDING_ACCOUNT_ID, 7, None),
        (ONBOARDING_ACCOUNT_ID, 7, ""),
        (ONBOARDING_ACCOUNT_ID, 7, "0"),
        (ONBOARDING_ACCOUNT_ID, 7, "AA"),
        (ONBOARDING_ACCOUNT_ID, 7, "00" * 33),
    ],
)
def test_faucet_prepare_rejects_noncanonical_claim_before_dispatch(
    account_id: object,
    anchor: object,
    nonce: object,
) -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises((TypeError, ValueError)):
        client.prepare_account_faucet(
            account_id,  # type: ignore[arg-type]
            binding=prepared_binding("faucet"),
            fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            pow_anchor_height=anchor,  # type: ignore[arg-type]
            pow_nonce_hex=nonce,  # type: ignore[arg-type]
        )

    assert session.calls == []


@pytest.mark.parametrize(
    "fee_payment",
    [
        {},
        {"payer": "authority"},
        {"payer": "legacy", "value": {"charge_limits": [], "gas_limit": None}},
        {
            "payer": "authority",
            "value": {"charge_limits": [], "gas_limit": 0},
        },
    ],
)
def test_faucet_prepare_rejects_noncanonical_fee_intent_before_dispatch(
    fee_payment: object,
) -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises((TypeError, ValueError)):
        client.prepare_account_faucet(
            ONBOARDING_ACCOUNT_ID,
            binding=prepared_binding("faucet"),
            fee_payment=fee_payment,  # type: ignore[arg-type]
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            pow_anchor_height=7,
            pow_nonce_hex="0000000000000000",
        )
    assert session.calls == []


def test_fee_intent_v1_requires_canonical_asset_addresses_and_exact_quantities() -> None:
    intent = authority_fee_payment(
        charge_limits=[
            {
                "kind": "nexus",
                "asset_definition_id": FAUCET_ASSET_DEFINITION_ID,
                "max_amount": "1.25",
            }
        ]
    )
    copied = client_module._copy_fee_payment_intent_v1(intent, "fixture.fee_payment")
    assert copied["value"]["charge_limits"][0]["max_amount"] == "1.25"

    for invalid in ("xor#sora", FAUCET_ASSET_DEFINITION_ID[:-1] + "A"):
        with pytest.raises(ValueError, match="canonical asset definition address"):
            authority_fee_payment(
                charge_limits=[
                    {
                        "kind": "nexus",
                        "asset_definition_id": invalid,
                        "max_amount": "1.25",
                    }
                ]
            )


def test_fee_intent_v1_requires_canonical_sponsor_account() -> None:
    sponsored = {
        "payer": "sponsor",
        "value": {
            "program_id": {"sponsor": ONBOARDING_ACCOUNT_ID, "name": "reset"},
            "program_revision": 1,
            "charge_limits": [],
            "gas_limit": None,
        },
    }
    assert (
        client_module._copy_fee_payment_intent_v1(sponsored, "fixture.fee_payment")
        == sponsored
    )
    sponsored["value"]["program_id"]["sponsor"] = "merchant@universal"
    with pytest.raises(ValueError, match="canonical I105 account id"):
        client_module._copy_fee_payment_intent_v1(sponsored, "fixture.fee_payment")


def test_faucet_submit_rejects_claim_body_and_wrong_binding_kind() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(TypeError, match="exactly the faucet V1 fields"):
        client.submit_prepared_account_faucet(
            {
                "account_id": ONBOARDING_ACCOUNT_ID,
                "pow_anchor_height": 7,
                "pow_nonce_hex": "0000000000000000",
            },
            expected_fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    wrong_kind = prepared_faucet()
    wrong_kind["binding"] = prepared_binding("onboarding")
    with pytest.raises(ValueError, match="kind must be 'faucet'"):
        client.submit_prepared_account_faucet(
            wrong_kind,
            expected_fee_payment=FEE_PAYMENT,
            expected_asset_definition_id=FAUCET_ASSET_DEFINITION_ID,
            expected_amount=FAUCET_AMOUNT,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    assert session.calls == []


def test_onboarding_plan_rejects_normalizing_alias_and_permission() -> None:
    session = OnboardingSession([])
    client = ToriiClient("https://torii.example", session=session)

    with pytest.raises(ValueError, match="surrounding whitespace"):
        client.plan_account_onboarding(
            onboarding_token=ONBOARDING_TOKEN,
            alias=" merchant@universal",
            account_id=ONBOARDING_ACCOUNT_ID,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
        )
    with pytest.raises(ValueError, match="surrounding whitespace"):
        client.plan_account_onboarding(
            onboarding_token=ONBOARDING_TOKEN,
            alias="merchant@universal",
            account_id=ONBOARDING_ACCOUNT_ID,
            expected_authority=ONBOARDING_ACCOUNT_ID,
            network_id=NETWORK_ID,
            permissions=["CanFoo "],
        )

    assert session.calls == []


def test_privacy_verifier_registry_is_closed_exact_and_engine_typed() -> None:
    expected = frozenset(
        {
            "pipa-r/pasta",
            "pipa-r/pasta/kaigi-authorization-v1",
            "pipa-r/pasta/kaigi-usage-v1",
            "pipa-r/pasta/confidential-transfer-v1",
            "pipa-r/pasta/confidential-unshield-full-v1",
            "pipa-r/pasta/confidential-unshield-change-v1",
            "stark/fri/poseidon-x7-goldilocks-6x64-v1",
        }
    )
    assert len(expected) == 7
    assert _VERIFIER_BACKEND_REGISTRY_LABELS_V1 == expected
    for backend in expected:
        expected_tag = ("native-pipa-r-pasta" if backend.startswith("pipa-r/") else "stark")
        assert _verifier_backend_registry_tag_v1(backend) == expected_tag
        assert _is_verifier_backend_registry_label_v1(backend)
        assert _require_verifier_backend_registry_label_v1(backend, "backend") == backend


def test_privacy_verifier_registry_rejects_aliases_retired_and_hostile_labels() -> None:
    unsupported = (
        "",
        "halo2/ipa",
        "halo2/pasta/ivm-execution-v1",
        "halo2/pasta/kaigi-authorization-v1",
        "halo2/pasta/kaigi-usage-v1",
        "pipa-r/ipa/pasta/kaigi-usage-v1",
        "halo2/pasta/kaigi-roster-v1",
        "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
        "unknown/privacy/backend",
        "halo2/unknown-native-v1",
        "halo2/ipa:unknown-native-v1",
        "stark/unknown-native-v1",
        "halo2/bn254",
        "groth16",
        "groth16/bls12-377",
        " halo2/ipa",
        "halo2/ipa ",
        "\thalo2/ipa",
        "halo2/ipa\n",
        "halo2\uff0fipa",
        "halo2/\u200bipa",
        "h\u0430lo2/ipa",
        "halo2/ipa\0",
        "HALO2/IPA",
        "stark/FRI",
        "stark/fri",
        "stark/fri/poseidon2-goldilocks",
        "stark/fri/sha256_goldilocks.v1",
        "halo2/ipa::ivm-replay-binding-v1",
        "halo2//ipa",
        "halo2/ipa:",
        "halo2/ipa.",
        "halo2/ipa/.ivm-replay-binding-v1",
        "halo2/ipa:ivm..execution-v1",
        "halo2/pasta/ipa-pasta-cycle-v1",
        "halo2/ipa-pasta-cycle-v1",
        "../halo2/ipa",
        "halo2/ipa/orchard",
        "halo2-ipa-orchard",
        "halo2/ipa/penumbra",
        "halo2/ipa/masp",
        "halo2/ipa/monero",
        "halo2/ipa/curve-tree",
        "halo2/pasta/tiny-add",
        "halo2/ipa/tiny-add",
        "halo2/ipa:tiny-add",
        "stark/fri/miden",
        "stark/fri/miden/claimed-production",
        "stark/fri/latest",
        "stark/fri/random-profile",
        "stark/fri/sha512-goldilocks",
        "stark/fri/audit-proof-v1",
        "stark/fri/sha256 goldilocks",
        "stark/fri/sha256+goldilocks",
        "fcmp++",
        "halo2/ipa+mock",
        "halo2/ipa:production-ready",
        "halo2/ipa:claimed-production",
        "halo2/ipa:mainnet-ready",
        "halo2/ipa:release-ready",
        "halo2/ipa:certified-mainnet",
        "halo2/ipa:third-party-audited",
        "halo2/ipa/orchard:production-ready",
        "orchard:mainnet-ready",
        "penumbra-masp:external-security-review",
        "jindo-lattice-pcs-zk:release-ready",
        "miden-stark:dev-fixture",
        "sis-hints-anoncred-pq-v0",
        "sis-with-hints",
        "sis-with-hints:s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        "halo2/ipa/orchard:kzg",
        "orchard:universal-srs",
        "penumbra-masp:kzg",
        "jindo-lattice-pcs-zk:trusted-setup",
        "miden-stark:ptau",
        "sis-with-hints:groth16",
        "pq-masp-stark-fri:kzg",
        "stark/fri/audit-signoff",
        "stark/fri/externally-audited",
        "stark/fri/boi-audited",
        "stark/fri/external-security-review",
        "stark/fri/security-review-passed",
        "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
        "stark/fri/s-e-c-u-r-i-t-y-a-u-d-i-t-e-d",
        "stark/fri/a-u-d-i-t-c-l-a-i-m",
        "stark/fri/dev-fixture",
        "stark/fri/d-e-v-f-i-x-t-u-r-e",
        "stark/fri/test",
        "stark/fri/t-e-s-t",
        "stark/fri/todo",
        "stark/fri/t-o-d-o",
        "stark/fri/draft-only",
        "stark/fri/d-r-a-f-t",
        "stark/fri/pending-audit",
        "stark/fri/replace-before-mainnet",
        "stark/fri/not-production-ready",
        "halo2/ipa:dev-fixture",
        "halo2/ipa:todo-proof",
        "halo2/ipa:t-o-d-o-proof",
        "halo2/ipa:draft-proof",
        "halo2/ipa:d-r-a-f-t-proof",
        "halo2/ipa:pending-audit",
        "halo2/ipa:replace-before-production",
        "halo2/ipa:not-for-production",
        "halo2/ipa:dummy",
        "halo2/ipa:f-a-k-e",
        "halo2/ipa:stub",
        "halo2/kzg",
        "halo2/pasta/mock",
        "kzg/powersoftau",
    )
    for backend in unsupported:
        assert _verifier_backend_registry_tag_v1(backend) is None, backend
        assert not _is_verifier_backend_registry_label_v1(backend), backend
        with pytest.raises(ValueError, match="unsupported verifier-registry label"):
            _require_verifier_backend_registry_label_v1(backend, "backend")
    for backend in (None, b"pipa-r/pasta", 1, object()):
        assert _verifier_backend_registry_tag_v1(backend) is None
        assert not _is_verifier_backend_registry_label_v1(backend)
        with pytest.raises(TypeError, match="must be a string"):
            _require_verifier_backend_registry_label_v1(backend, "backend")


def test_each_privacy_verifier_registry_label_rejects_structural_mutations() -> None:
    for label in _VERIFIER_BACKEND_REGISTRY_LABELS_V1:
        replacement = "y" if label.endswith("x") else "x"
        mutations = {
            f" {label}",
            f"{label} ",
            label.upper(),
            f"{label}/",
            f"{label}\0",
            f"{label}\u200b",
            label.replace("/", "//", 1),
            f"{label[:-1]}{replacement}",
        }
        mutations.discard(label)
        for mutation in mutations:
            assert not _is_verifier_backend_registry_label_v1(mutation), (
                mutation,
                label,
            )
def zk_verifying_key_commitment(backend: str, vk_bytes: bytes) -> str:
    backend_bytes = backend.encode("utf-8")
    preimage = (
        b"iroha:zk:v1:vk"
        + len(backend_bytes).to_bytes(8, "big")
        + backend_bytes
        + len(vk_bytes).to_bytes(8, "big")
        + vk_bytes
    )
    return hashlib.sha256(preimage).hexdigest()


def zk_verifying_key_transaction_draft(
    **overrides: object,
) -> dict[str, object]:
    transaction_payload = b"vk transaction payload"
    signing_message = bytearray(
        hashlib.blake2b(transaction_payload, digest_size=32).digest()
    )
    signing_message[-1] |= 1
    draft: dict[str, object] = {
        "submitted": False,
        "transaction_payload_b64": base64.b64encode(transaction_payload).decode("ascii"),
        "signing_message_b64": base64.b64encode(signing_message).decode("ascii"),
    }
    draft.update(overrides)
    return draft


def zk_verifying_key_draft_for_payload(
    transaction_payload: bytes,
) -> dict[str, object]:
    signing_message = bytearray(
        hashlib.blake2b(transaction_payload, digest_size=32).digest()
    )
    signing_message[-1] |= 1
    return zk_verifying_key_transaction_draft(
        transaction_payload_b64=base64.b64encode(transaction_payload).decode("ascii"),
        signing_message_b64=base64.b64encode(signing_message).decode("ascii"),
    )


class FakeVkDraftCrypto:
    def __init__(
        self,
        decoded: dict[str, object] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.decoded = decoded
        self.error = error
        self.calls: list[tuple[bytes, NetworkId, str, str]] = []

    def decode_zk_vk_transaction_payload(
        self,
        payload: bytes,
        network_id: NetworkId,
        expected_authority: str,
        operation: str,
    ) -> dict[str, object]:
        self.calls.append((payload, network_id, expected_authority, operation))
        if self.error is not None:
            raise self.error
        if self.decoded is None:
            raise AssertionError("fake VK decoder has no result")
        return self.decoded


def expected_zk_verifying_key_instruction(
    payload: dict[str, object],
    authority: str,
    *,
    update: bool,
) -> dict[str, object]:
    normalized = (
        client_module._normalize_zk_verifying_key_update_payload(payload)
        if update
        else client_module._normalize_zk_verifying_key_registration_payload(payload)
    )
    normalized["authority"] = authority
    return client_module._expected_zk_verifying_key_instruction(normalized)


def account_address(seed: int, discriminant: int = 0x02F1) -> str:
    return Ed25519KeyPair.from_private_key(bytes([seed] * 32)).account_id(
        discriminant=discriminant,
    )


def test_submit_transaction_draft_result_wait_false_preserves_hash_after_submit_timeout() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)

    class FakeEnvelope:
        hash = bytes.fromhex("ab" * 32)

    envelope = FakeEnvelope()
    client._sign_transaction_draft = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: envelope
    )

    def fake_submit(_envelope: object) -> object:
        raise requests.Timeout("submit timed out")

    client.submit_transaction_envelope = fake_submit  # type: ignore[method-assign]
    client.wait_for_transaction_status = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: pytest.fail("wait=False must not poll status")
    )

    result = client._submit_transaction_draft_result(
        object(),  # type: ignore[arg-type]
        private_key_hex="11" * 32,
        wait=False,
    )

    assert result["hash"] == "ab" * 32
    assert result["envelope"] is envelope
    assert result["submission"] == {
        "ok": False,
        "status": "submission_timeout_pending_status",
        "error": "submit timed out",
    }
    assert "terminal" not in result


def test_submit_transaction_draft_result_wait_true_raises_submit_timeout() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)

    class FakeEnvelope:
        hash = bytes.fromhex("cd" * 32)

    client._sign_transaction_draft = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: FakeEnvelope()
    )

    def fake_submit(_envelope: object) -> object:
        raise requests.Timeout("submit timed out")

    client.submit_transaction_envelope = fake_submit  # type: ignore[method-assign]

    with pytest.raises(requests.Timeout, match="submit timed out"):
        client._submit_transaction_draft_result(
            object(),  # type: ignore[arg-type]
            private_key_hex="11" * 32,
            wait=True,
        )


def test_submit_transaction_draft_result_wait_false_does_not_hide_rejection() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)

    class FakeEnvelope:
        hash = bytes.fromhex("ef" * 32)

    client._sign_transaction_draft = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: FakeEnvelope()
    )

    def fake_submit(_envelope: object) -> object:
        raise RuntimeError("signature rejected")

    client.submit_transaction_envelope = fake_submit  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="signature rejected"):
        client._submit_transaction_draft_result(
            object(),  # type: ignore[arg-type]
            private_key_hex="11" * 32,
            wait=False,
        )


def test_account_exists_rejects_route_unavailable_without_listing_fallback() -> None:
    session = FakeSession(
        [
            response(
                503,
                text="route unavailable",
                headers={"x-iroha-reject-code": "route_unavailable"},
            ),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(RuntimeError, match="unexpected status 503"):
        client.account_exists("adult@is")
    assert [(call["method"], call["path"]) for call in session.calls] == [
        ("GET", "/v1/accounts/adult%40is"),
    ]


def test_asset_balance_rejects_wrong_network_prefix_without_retry() -> None:
    taira_account = account_address(0x6A, discriminant=369)
    session = FakeSession([response(400, text="ERR_UNEXPECTED_NETWORK_PREFIX")])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(RuntimeError, match="unexpected status 400"):
        client.asset_balance(taira_account, "ds#wonderland.is")
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert call["path"] == f"/v1/accounts/{quote(taira_account, safe='')}/assets/query"
    assert json.loads(call["data"]) == {
        "filter": {"op": "eq", "args": ["asset_alias", "ds#wonderland.is"]}
    }
    assert call["allow_redirects"] is False


def test_asset_balance_sums_every_matching_bucket_across_pages() -> None:
    account = account_address(0x6B)
    alias = "ds#wonderland.is"
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {
                            "asset": "DEF",
                            "asset_alias": alias,
                            "scope": "global",
                            "account_id": account,
                            "quantity": "1.5",
                        }
                    ],
                    "next_cursor": "c2",
                },
            ),
            response(
                200,
                {
                    "items": [
                        {
                            "asset": "DEF",
                            "asset_alias": alias,
                            "scope": "dataspace:7",
                            "account_id": account,
                            "quantity": "2",
                        },
                        {
                            "asset": "OTHER",
                            "asset_alias": "other#wonderland.is",
                            "scope": "global",
                            "account_id": account,
                            "quantity": "100",
                        },
                    ],
                    "next_cursor": None,
                },
            ),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert client.asset_balance(account, alias) == Decimal("3.5")
    expected_filter = {"op": "eq", "args": ["asset_alias", alias]}
    assert [json.loads(call["data"]) for call in session.calls] == [
        {"filter": expected_filter},
        {"filter": expected_filter, "cursor": "c2"},
    ]


def test_asset_balance_reads_one_scope_by_base58_definition() -> None:
    account = account_address(0x6C)
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {
                            "asset": "5Ff9",
                            "scope": "global",
                            "account_id": account,
                            "quantity": "4",
                        }
                    ],
                    "next_cursor": None,
                },
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert client.asset_balance(account, "5Ff9", scope="global") == Decimal("4")
    assert json.loads(session.calls[0]["data"]) == {
        "filter": {
            "op": "and",
            "args": [
                {"op": "eq", "args": ["asset", "5Ff9"]},
                {"op": "eq", "args": ["scope", "global"]},
            ],
        }
    }


def test_asset_balance_returns_zero_when_account_has_no_matching_asset() -> None:
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {
                            "asset": "other",
                            "scope": "global",
                            "account_id": "adult@is",
                            "quantity": "3",
                        }
                    ],
                    "next_cursor": None,
                },
            )
        ]
    )
    client = authenticated_query_client(session)

    assert client.asset_balance("adult@is", "ds#wonderland.is") == Decimal("0")


def test_asset_quantity_builder_boundary_is_exact_and_canonical() -> None:
    assert _normalize_quantity(KotodamaQuantity("12.5")) == "12.5"
    assert _normalize_quantity("12.5") == "12.5"
    assert _normalize_quantity(12) == "12"
    assert _normalize_quantity(Decimal("12.500")) == "12.5"
    assert _normalize_quantity((1 << 511) - 1) == str((1 << 511) - 1)

    for alternate in ("+1", "01", "1.0", "1.2300", "1e0", "-0", "-1", " 1"):
        with pytest.raises(ValueError):
            _normalize_quantity(alternate)
    for lossy in (1.0, True, None, object()):
        with pytest.raises(TypeError):
            _normalize_quantity(lossy)  # type: ignore[arg-type]
    for out_of_domain in (Decimal("1e1000000"), Decimal("1e-1000000")):
        with pytest.raises(ValueError):
            _normalize_quantity(out_of_domain)
    with pytest.raises(ValueError, match="canonical V1 bound"):
        _normalize_quantity("1." + "0" * 10_000)
    with pytest.raises(ValueError):
        _normalize_quantity(1 << 511)


def test_u128_quantity_boundary_rejects_out_of_range_values() -> None:
    assert _normalize_u128_quantity((1 << 128) - 1, "amount") == str((1 << 128) - 1)
    with pytest.raises(ValueError, match="within u128"):
        _normalize_u128_quantity(1 << 128, "amount")


@pytest.mark.parametrize(
    "quantity",
    [1.5, True, "+1", "01", "1.0", "1.500", "1e0", "-1", " 1"],
)
def test_repo_and_settlement_quantity_builders_reject_alternate_inputs(
    quantity: object,
) -> None:
    builders = (
        RepoCashLeg("cash#is", quantity),  # type: ignore[arg-type]
        RepoCollateralLeg("bond#is", quantity),  # type: ignore[arg-type]
        SettlementLeg(
            "cash#is", quantity, "alice@is", "bob@is"  # type: ignore[arg-type]
        ),
    )
    for builder in builders:
        with pytest.raises((TypeError, ValueError)):
            builder.to_payload()


def test_rwa_nested_quantity_fields_are_normalized_without_float_coercion() -> None:
    normalized = _normalize_rwa_quantity_fields(
        {
            "quantity": Decimal("10.500"),
            "parents": [{"rwa": "parent", "quantity": Decimal("1.2500")}],
        },
        "rwa",
        top_level_quantity=True,
    )
    assert normalized["quantity"] == "10.5"
    assert normalized["parents"][0]["quantity"] == "1.25"

    for quantity in (1.5, "1.0", "01", "-1"):
        with pytest.raises((TypeError, ValueError)):
            _normalize_rwa_quantity_fields(
                {"quantity": quantity},
                "rwa",
                top_level_quantity=True,
            )
        with pytest.raises((TypeError, ValueError)):
            _normalize_rwa_quantity_fields(
                {"parents": [{"rwa": "parent", "quantity": quantity}]},
                "merge",
                top_level_quantity=False,
            )


def _quantity_readback_factories(
    quantity: object,
) -> tuple[Callable[[], object], ...]:
    # Balances require their quantity; an RWA lot's quantity may be null or
    # absent (only a row's identity fields are always present).
    optional_quantity = () if quantity is None else (
        lambda: RwaLot.from_json({"id": "rwa", "quantity": quantity}),
    )
    return (
        lambda: AccountAsset.from_json(
            {"asset": "asset", "scope": "global", "account_id": "account", "quantity": quantity}
        ),
        lambda: AssetHolder.from_json(
            {"account_id": "account", "asset": "asset", "scope": "global", "quantity": quantity}
        ),
        lambda: UaidPortfolioAsset.from_payload(
            {
                "asset_id": "asset#account",
                "asset_definition_id": "asset",
                "quantity": quantity,
            }
        ),
        lambda: ExplorerRwaRecord.from_payload(
            {
                "id": "rwa",
                "owned_by": "account",
                "quantity": quantity,
                "held_quantity": "0",
                "primary_reference": "reference",
                "is_frozen": False,
            }
        ),
        *optional_quantity,
    )


@pytest.mark.parametrize("quantity", ["1.0", "01", "+1", "-1", 1, 1.0, None])
def test_typed_quantity_readbacks_reject_noncanonical_or_untyped_values(
    quantity: object,
) -> None:
    for factory in _quantity_readback_factories(quantity):
        with pytest.raises((TypeError, ValueError)):
            factory()


def test_rwa_lot_quantity_may_be_null_or_absent() -> None:
    assert RwaLot.from_json({"id": "rwa", "quantity": None}).quantity is None
    assert RwaLot.from_json({"id": "rwa"}).quantity is None
    assert RwaLot.from_json({"id": "rwa", "quantity": "0.5"}).quantity == Decimal("0.5")


def test_typed_quantity_readback_rejects_oversized_alternate_before_bigint_parsing() -> None:
    with pytest.raises(ValueError, match="canonical V1 text bound"):
        AccountAsset.from_json(
            {
                "asset": "asset",
                "scope": "global",
                "account_id": "account",
                "quantity": "1." + "0" * 10_000,
            }
        )


@pytest.mark.parametrize("quantity", ["1.0", "01", "+1", "-1", 1, None])
def test_asset_balance_rejects_noncanonical_or_untyped_quantities(quantity: object) -> None:
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {
                            "asset": "canonical-ds-id",
                            "asset_alias": "ds#wonderland.is",
                            "scope": "global",
                            "account_id": "adult@is",
                            "quantity": quantity,
                        }
                    ],
                    "next_cursor": None,
                },
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises((TypeError, ValueError)):
        client.asset_balance("adult@is", "ds#wonderland.is")


def test_get_asset_definition_returns_none_for_missing_definition() -> None:
    session = FakeSession([response(404, text="missing")])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert client.get_asset_definition("ds#wonderland.is") is None


def test_data_model_validation_uses_typed_node_capabilities() -> None:
    session = FakeSession(
        [response(200, {"abi_version": 1, "data_model_version": DATA_MODEL_VERSION})]
    )
    client = authenticated_query_client(session)

    client._ensure_data_model_validation()

    assert client._data_model_validation == "matched"
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "GET"
    assert session.calls[0]["path"] == "/v1/node/capabilities"
    assert session.calls[0]["allow_redirects"] is False
    assert "X-Iroha-Account" in session.calls[0]["headers"]


def test_accounts_list_returns_a_typed_cursor_page() -> None:
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {
                            "id": "adult@is",
                            "label": "Adult",
                            "uaid": None,
                            "metadata": {"tier": 1},
                            "added_later": True,
                        }
                    ],
                    "next_cursor": "q1_next",
                    "total": 7,
                },
            )
        ]
    )
    client = authenticated_query_client(session)

    page = client.accounts.list(
        filter=F.label.is_not_null(), sort="-label", limit=1, include_total=True
    )

    assert (page.next_cursor, page.has_more, page.total) == ("q1_next", True, 7)
    account = page.items[0]
    assert (account.id, account.label, account.uaid, account.metadata) == (
        "adult@is",
        "Adult",
        None,
        {"tier": 1},
    )
    assert account.raw["added_later"] is True
    call = session.calls[0]
    assert (call["method"], call["path"]) == ("POST", "/v1/accounts/query")
    assert json.loads(call["data"]) == {
        "filter": {"op": "not", "args": [{"op": "is_null", "args": ["label"]}]},
        "sort": ["-label"],
        "limit": 1,
        "include_total": True,
    }
    assert "X-Iroha-Signature" in call["headers"]


def test_collection_controls_are_validated_before_any_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    for call, code in (
        (lambda: client.accounts.list(limit=0), "invalid_limit"),
        (lambda: client.domains.list(sort="id:desc"), "invalid_sort"),
        (lambda: client.domains.list(filter=F.id.in_()), "invalid_filter"),
        (lambda: client.domains.list(cursor="has space"), "invalid_cursor"),
        (lambda: client.nfts.rows(select=[]), "invalid_select"),
    ):
        with pytest.raises(ListQueryError) as raised:
            call()
        assert raised.value.code == code
    assert session.calls == []


def test_collection_page_envelope_is_strict() -> None:
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {"asset": "a", "scope": "global", "account_id": "x", "quantity": "1"}
                    ],
                    "next_cursor": 5,
                },
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(ValueError, match="next_cursor"):
        client.accounts.assets("x").list()


def test_domains_iter_follows_next_cursor_until_the_last_page() -> None:
    session = FakeSession(
        [
            response(200, {"items": [{"id": "a"}, {"id": "b"}], "next_cursor": "c1"}),
            response(200, {"items": [{"id": "c"}], "next_cursor": None}),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert [domain.id for domain in client.domains.iter(limit=2)] == ["a", "b", "c"]
    assert [json.loads(call["data"]) for call in session.calls] == [
        {"limit": 2},
        {"limit": 2, "cursor": "c1"},
    ]
    assert all("X-Iroha-Signature" not in call["headers"] for call in session.calls)


def test_rwa_lots_decode_exact_quantities() -> None:
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [
                        {
                            "id": "rwa$bond",
                            "quantity": "10.25",
                            "is_frozen": False,
                            "status": "active",
                        }
                    ],
                    "next_cursor": None,
                },
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    lot = client.rwas.list(filter=F.quantity > Decimal("10")).items[0]

    assert (lot.id, lot.quantity, lot.is_frozen, lot.status) == (
        "rwa$bond",
        Decimal("10.25"),
        False,
        "active",
    )
    assert json.loads(session.calls[0]["data"]) == {
        "filter": {"op": "gt", "args": ["quantity", 10]}
    }


def test_account_transaction_rows_carry_projections() -> None:
    account = account_address(0x31)
    session = FakeSession(
        [
            response(
                200,
                {
                    "items": [{"authority": "adult@is", "timestamp_ms": 5, "asset_ids": ["a#b"]}],
                    "next_cursor": None,
                },
            )
        ]
    )
    client = authenticated_query_client(session)

    page = client.accounts.transactions(account).rows(
        filter=F.asset_definition_ids == "a",
        select=["authority", "timestamp_ms", "asset_ids"],
        limit=25,
    )

    assert page.items == ({"authority": "adult@is", "timestamp_ms": 5, "asset_ids": ["a#b"]},)
    call = session.calls[0]
    assert call["path"] == f"/v1/accounts/{quote(account, safe='')}/transactions/query"
    assert json.loads(call["data"]) == {
        "filter": {"op": "eq", "args": ["asset_definition_ids", "a"]},
        "select": ["authority", "timestamp_ms", "asset_ids"],
        "limit": 25,
    }


def test_global_transactions_are_a_history_collection() -> None:
    row = {
        "entrypoint_hash": "ab" * 32,
        "block_height": 9,
        "block_index": 1,
        "block_hash": "cd" * 32,
        "authority": None,
        "timestamp_ms": None,
        "entrypoint_kind": "time_trigger",
        "result_ok": False,
        "asset_ids": [],
        "asset_definition_ids": [],
        "metadata": {},
    }
    session = FakeSession(
        [
            response(200, {"items": [], "next_cursor": "h1"}),
            response(200, {"items": [row], "next_cursor": None}),
        ]
    )
    client = authenticated_query_client(session)

    history = list(client.transactions.iter(filter=F.block_height <= 9))

    assert [(tx.block_height, tx.block_index, tx.authority) for tx in history] == [(9, 1, None)]
    assert isinstance(history[0], CommittedTransaction)
    assert [call["path"] for call in session.calls] == ["/v1/transactions/query"] * 2
    assert [json.loads(call["data"]) for call in session.calls] == [
        {"filter": {"op": "lte", "args": ["block_height", 9]}},
        {"filter": {"op": "lte", "args": ["block_height", 9]}, "cursor": "h1"},
    ]
    with pytest.raises(ListQueryError) as raised:
        client.transactions.list(sort="-block_height")
    assert raised.value.code == "invalid_sort"
    assert not hasattr(ToriiClient, "query_transactions")


def test_typed_collection_calls_reject_projections_and_bad_select() -> None:
    account = account_address(0x32)
    transactions = ToriiClient(
        "http://torii.example", session=FakeSession([]), max_retries=0
    ).accounts.transactions(account)

    with pytest.raises(ListQueryError, match="rows"):
        transactions.list(ListQuery(select=["authority"]))
    with pytest.raises(TypeError, match="select"):
        transactions.rows(select="authority")
    with pytest.raises(ListQueryError) as raised:
        transactions.rows(select=["authority", "authority"])
    assert raised.value.code == "invalid_select"


def test_collection_query_errors_are_typed_and_text_filters_pass_through() -> None:
    session = FakeSession(
        [
            response(
                400,
                {
                    "code": "invalid_filter",
                    "message": "invalid `filter`: use the keyword `and` instead of `&` or `&&` (column 17)",
                    "details": {"field": "filter", "hint": "use `and`"},
                },
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    text_filter = 'owned_by == "x" && quantity > 1'

    with pytest.raises(ToriiQueryError) as raised:
        client.accounts.list(filter=text_filter)

    error = raised.value
    assert (error.status, error.code, error.parameter) == (400, "invalid_filter", "filter")
    assert error.details["hint"] == "use `and`"
    assert isinstance(error, ListQueryError) and isinstance(error, ToriiError)
    assert json.loads(session.calls[0]["data"]) == {"filter": text_filter}


_REPO_ROW = {
    "id": "repo-1",
    "initiator": "alice@is",
    "counterparty": "bob@is",
    "custodian": None,
    "cash_leg": {"asset_definition_id": "cash#is", "quantity": "100"},
    "cash_source": "cash#is::bob@is",
    "collateral_leg": {"asset_definition_id": "bond#is", "quantity": "120"},
    "collateral_custody_asset": "bond#is::bob@is",
    "rate_bps": 250,
    "maturity_timestamp_ms": 2_000,
    "initiated_timestamp_ms": 1_000,
    "last_margin_check_timestamp_ms": 1_000,
    "governance": {"haircut_bps": 500, "margin_frequency_secs": 3600},
    "settlement_timestamp_ms": None,
    "status": "active",
}


def test_repo_agreements_collection_decodes_typed_records_anonymously() -> None:
    session = FakeSession(
        [response(200, {"items": [_REPO_ROW], "next_cursor": None, "total": 1})]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    page = client.repo_agreements.list(filter=F.status == "active", include_total=True)

    record = page.items[0]
    assert isinstance(record, RepoAgreementRecord)
    assert record.cash_source == "cash#is::bob@is"
    assert record.collateral_custody_asset == "bond#is::bob@is"
    assert record.settlement_timestamp_ms is None
    assert record.status == "active"
    assert page.total == 1
    call = session.calls[0]
    assert call["path"] == "/v1/repo/agreements/query"
    assert json.loads(call["data"]) == {
        "filter": {"op": "eq", "args": ["status", "active"]},
        "include_total": True,
    }
    assert "X-Iroha-Signature" not in call["headers"]

    inconsistent = dict(_REPO_ROW)
    inconsistent["status"] = "settled"
    with pytest.raises(ValueError, match="status must agree"):
        RepoAgreementRecord.from_payload(inconsistent)


@pytest.mark.parametrize("quantity", ["1.0", "01", "+1", "-1", 1, 1.0, None])
def test_repo_agreement_readback_rejects_noncanonical_quantities(quantity: object) -> None:
    row = copy.deepcopy(_REPO_ROW)
    row["cash_leg"]["quantity"] = quantity

    with pytest.raises((TypeError, ValueError)):
        RepoAgreementRecord.from_payload(row)


def test_repo_agreement_readback_requires_quantity_fields() -> None:
    row = copy.deepcopy(_REPO_ROW)
    del row["cash_leg"]["quantity"]

    with pytest.raises(KeyError, match="quantity"):
        RepoAgreementRecord.from_payload(row)


def test_sns_helpers_read_policy_and_name() -> None:
    session = FakeSession(
        [
            response(200, {"payment_asset_id": "fee", "pricing": []}),
            response(200, {"literal": "merchant@paynet"}),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert client.get_sns_policy(2)["payment_asset_id"] == "fee"
    registration = client.get_sns_name("account-alias", "merchant@paynet")

    assert registration == {"literal": "merchant@paynet"}
    assert [call["path"] for call in session.calls] == [
        "/v1/sns/policies/2",
        "/v1/sns/names/account-alias/merchant%40paynet",
    ]


def test_zk_verifying_key_helpers_detect_active_status_and_return_registration_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_draft = zk_verifying_key_transaction_draft()
    authority = account_address(31)
    registration_payload: dict[str, object] = {
        "authority": authority,
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 1,
        "circuit_id": "vk-transfer-v1",
        "public_inputs_schema_hash_hex": "11" * 32,
        "gas_schedule_id": "zk.verify.default",
        "vk_bytes": "dms=",
    }
    native = FakeVkDraftCrypto(
        expected_zk_verifying_key_instruction(
            registration_payload,
            authority,
            update=False,
        )
    )
    monkeypatch.setattr(client_module, "_require_crypto", lambda: native)
    session = FakeSession(
        [
            response(200, {"record": {"status": "Active"}}),
            response(200, expected_draft),
        ]
    )
    client = ToriiClient(
        "http://torii.example",
        session=session,
        local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
        max_retries=0,
    )
    assert client.local_signing_context is VK_LOCAL_SIGNING_CONTEXT

    assert client.zk_verifying_key_active("pipa-r/pasta", "vk_transfer")
    draft = client.register_zk_verifying_key(registration_payload)

    assert draft == expected_draft
    assert [call["path"] for call in session.calls] == [
        "/v1/zk/vk/pipa-r%2Fpasta/vk_transfer",
        "/v1/zk/vk/register",
    ]
    body = json.loads(session.calls[1]["data"])
    assert "private_key" not in body
    assert native.calls == [
        (
            b"vk transaction payload",
            NETWORK_ID,
            authority,
            "register",
        )
    ]


def test_zk_verifying_key_helpers_reject_labels_outside_exact_registry() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    for backend in ("stark/fri/latest", "stark/fri/attestation", "stark/fri/contest"):
        with pytest.raises(
            ValueError,
            match=(
                "must be a non-empty string|surrounding whitespace|"
                "unsupported production verifier backend"
            ),
        ):
            client.submit_zk_verifying_key_registration(
                {"backend": backend, "name": "vk_false_positive_guard"}
            )

    assert session.calls == []


def test_zk_verifying_key_registration_rejects_unsupported_backends_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    for backend in (
        "halo2/pasta/kaigi-authorization-v1",
        "halo2/pasta/kaigi-usage-v1",
        "pipa-r/ipa/pasta/kaigi-usage-v1",
        "halo2/pasta/kaigi-roster-v1",
        "halo2/pasta/kagemusha-v1-mint-fold-merkle16-axiom-poseidon-v1",
        "halo2/unknown-native-v1",
        "halo2/ipa:unknown-native-v1",
        "stark/unknown-native-v1",
        " halo2/ipa",
        "halo2/ipa ",
        "\thalo2/ipa",
        "halo2/ipa\n",
        "halo2\uFF0Fipa",
        "halo2/\u200Bipa",
        "h\u0430lo2/ipa",
        "stark/fri/miden",
        "stark/fri/latest",
        "stark/fri/attestation",
        "stark/fri/contest",
        "stark/fri/random-profile",
        "stark/fri/sha512-goldilocks",
        "stark/fri/audit-proof-v1",
        "halo2/ipa:production-ready",
        "halo2/ipa:claimed-production",
        "halo2/ipa:mainnet-ready",
        "stark/fri/audit-signoff",
        "stark/fri/externally-audited",
        "stark/fri/security-review-passed",
        "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
        "stark/fri/a-u-d-i-t-c-l-a-i-m",
        "halo2/ipa/penumbra",
        "halo2/ipa/masp",
        "halo2/ipa/monero",
        "halo2/ipa/curve-tree",
        "halo2/pasta/tiny-add",
        "halo2/ipa/tiny-add",
        "halo2/ipa:tiny-add",
        "halo2/pasta/tiny-commit-open",
        "halo2/pasta/anon-transfer-2x2",
        "halo2/ipa/anon-transfer-2x2",
        "halo2/ipa:anon-transfer-2x2",
        "halo2/pasta/anon-transfer-2x2-merkle2",
        "halo2/ipa/anon-transfer-2x2-merkle8",
        "halo2/ipa:anon-transfer-2x2-merkle16",
        "halo2/pasta/vote-bool-commit",
        "halo2/ipa/vote-bool-commit",
        "halo2/ipa:vote-bool-commit",
        "halo2/pasta/vote-bool-commit-merkle2",
        "halo2/ipa/vote-bool-commit-merkle8",
        "halo2/ipa:vote-bool-commit-merkle16",
        "stark/fri/dev-fixture",
        "stark/fri/d-e-v-f-i-x-t-u-r-e",
        "stark/fri/dev",
        "stark/fri/d-e-v",
        "stark/fri/test",
        "stark/fri/t-e-s-t",
        "stark/fri/todo",
        "stark/fri/t-o-d-o",
        "stark/fri/draft-only",
        "stark/fri/d-r-a-f-t",
        "stark/fri/pending-audit",
        "stark/fri/replace-before-mainnet",
        "stark/fri/not-production-ready",
        "stark/fri/placeholder",
        " stark/fri/poseidon-x7-goldilocks-6x64-v1",
        "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
        "halo2/ipa/orchard",
        "halo2/kzg",
        "halo2/ipa\0",
        "halo2/ipa:dev-fixture",
        "halo2/ipa:dev",
        "halo2/ipa:d-e-v",
        "halo2/ipa:todo-proof",
        "halo2/ipa:t-o-d-o-proof",
        "halo2/ipa:draft-proof",
        "halo2/ipa:d-r-a-f-t-proof",
        "halo2/ipa:pending-audit",
        "halo2/ipa:replace-before-production",
        "halo2/ipa:not-for-production",
        "halo2/ipa:dummy",
        "halo2/ipa:f-a-k-e",
        "halo2/ipa:stub",
        "halo2/ipa:s-a-m-p-l-e",
        "mock/dev",
    ):
        with pytest.raises(
            ValueError,
            match=(
                "must be a non-empty string|surrounding whitespace|"
                "unsupported production verifier backend"
            ),
        ):
            client.submit_zk_verifying_key_registration(
                {"backend": backend, "name": "vk_transfer"}
            )
    assert session.calls == []


def test_zk_verifying_key_registration_rejects_bad_names_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    for bad_name in ("", "   ", "\t", " vk_transfer", "vk_transfer ", None, 7):
        with pytest.raises((TypeError, ValueError), match="register_zk_verifying_key.name"):
            client.submit_zk_verifying_key_registration(
                {"backend": "pipa-r/pasta", "name": bad_name}
            )

    assert session.calls == []


def test_zk_verifying_key_registration_rejects_padded_selector_metadata_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    base = {
        "authority": "alice",
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 1,
        "circuit_id": "halo2/ipa::transfer_v1",
        "public_inputs_schema_hash_hex": "aa" * 32,
        "gas_schedule_id": "halo2_default",
        "vk_bytes": "dms=",
    }

    for field, value in (
        ("name", " vk_transfer"),
        ("name", "vk_transfer "),
        ("circuit_id", " halo2/ipa::transfer_v1"),
        ("circuit_id", "halo2/ipa::transfer_v1 "),
        ("gas_schedule_id", " halo2_default"),
        ("gas_schedule_id", "halo2_default "),
    ):
        with pytest.raises(
            ValueError,
            match=rf"register_zk_verifying_key\.{field}.*surrounding whitespace",
        ):
            client.submit_zk_verifying_key_registration({**base, field: value})

    assert session.calls == []


def test_zk_verifying_key_registration_rejects_missing_authority_and_private_keys() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    for authority in (None, "", "   ", 7):
        with pytest.raises((TypeError, ValueError), match="register_zk_verifying_key.authority"):
            client.submit_zk_verifying_key_registration(
                {
                    "authority": authority,
                    "backend": "pipa-r/pasta",
                    "name": "vk_transfer",
                }
            )

    for field, private_key in (
        ("private_key", None),
        ("private_key", "ed25519:deadbeef"),
        ("privateKey", "ed25519:deadbeef"),
        ("private_key_hex", "11" * 32),
        ("privateKeyBytes", bytes([0x11]) * 32),
    ):
        with pytest.raises(
            ValueError,
            match="does not accept private-key fields.*sign the returned transaction draft locally",
        ):
            client.submit_zk_verifying_key_registration(
                {
                    "authority": "alice",
                    "backend": "pipa-r/pasta",
                    "name": "vk_transfer",
                    field: private_key,
                }
            )

    assert session.calls == []


def test_zk_verifying_key_registration_rejects_mismatched_inline_commitment() -> None:
    session = FakeSession([response(200, zk_verifying_key_transaction_draft())])
    client = ToriiClient(
        "http://torii.example",
        session=session,
        local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
        max_retries=0,
    )
    vk_bytes = b"abc"
    matching_commitment = zk_verifying_key_commitment("pipa-r/pasta", vk_bytes)

    with pytest.raises(ValueError, match="commitment_hex must match domain-separated SHA-256"):
        client.submit_zk_verifying_key_registration(
            {
                "authority": "alice",
                "backend": "pipa-r/pasta",
                "name": "vk_transfer",
                "version": 1,
                "circuit_id": "halo2/ipa::transfer_v1",
                "public_inputs_schema_hash_hex": "aa" * 32,
                "gas_schedule_id": "halo2_default",
                "vk_bytes": base64.b64encode(vk_bytes).decode("ascii"),
                "commitment_hex": "00" * 32,
            }
        )

    assert session.calls == []
    response_obj = client.submit_zk_verifying_key_registration(
        {
            "authority": "alice",
            "backend": "pipa-r/pasta",
            "name": "vk_transfer",
            "version": 1,
            "circuit_id": "halo2/ipa::transfer_v1",
            "public_inputs_schema_hash_hex": "aa" * 32,
            "gas_schedule_id": "halo2_default",
            "vk_bytes": vk_bytes,
            "commitment_hex": matching_commitment,
        }
    )

    assert response_obj.status_code == 200
    assert [call["path"] for call in session.calls] == ["/v1/zk/vk/register"]


def test_zk_verifying_key_registration_rejects_withdraw_height_before_activation_height() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(ValueError, match="withdraw_height"):
        client.submit_zk_verifying_key_registration(
            {
                "authority": "alice",
                "backend": "pipa-r/pasta",
                "name": "vk_transfer",
                "version": 1,
                "circuit_id": "halo2/ipa::transfer_v1",
                "public_inputs_schema_hash_hex": "aa" * 32,
                "gas_schedule_id": "halo2_default",
                "activation_height": 10,
                "withdraw_height": 9,
            }
        )
    with pytest.raises(ValueError, match="activation_height"):
        client.submit_zk_verifying_key_registration(
            {
                "authority": "alice",
                "backend": "pipa-r/pasta",
                "name": "vk_transfer",
                "version": 1,
                "circuit_id": "halo2/ipa::transfer_v1",
                "public_inputs_schema_hash_hex": "aa" * 32,
                "gas_schedule_id": "halo2_default",
                "activation_height": -1,
            }
        )
    assert session.calls == []


def test_zk_verifying_key_update_helper_returns_unsigned_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_draft = zk_verifying_key_transaction_draft()
    session = FakeSession([response(200, expected_draft)])
    vk_bytes = b"abc"
    matching_commitment = zk_verifying_key_commitment("pipa-r/pasta", vk_bytes)
    authority = account_address(32)
    update_payload: dict[str, object] = {
        "authority": authority,
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 2,
        "circuit_id": "halo2/ipa::transfer_v2",
        "public_inputs_schema_hash_hex": "aa" * 32,
        "gas_schedule_id": "halo2_default",
        "vk_bytes": vk_bytes,
        "commitment_hex": matching_commitment,
        "activation_height": "10",
        "withdraw_height": "10",
    }
    native = FakeVkDraftCrypto(
        expected_zk_verifying_key_instruction(
            update_payload,
            authority,
            update=True,
        )
    )
    monkeypatch.setattr(client_module, "_require_crypto", lambda: native)
    client = ToriiClient(
        "http://torii.example",
        session=session,
        local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
        max_retries=0,
    )

    decoded = client.update_zk_verifying_key(update_payload)

    assert decoded == expected_draft
    assert [call["path"] for call in session.calls] == ["/v1/zk/vk/update"]
    call = session.calls[0]
    assert call["method"] == "POST"
    body = json.loads(call["data"])
    assert body["authority"] == authority
    assert "private_key" not in body
    assert body["backend"] == "pipa-r/pasta"
    assert body["name"] == "vk_transfer"
    assert body["vk_bytes"] == base64.b64encode(vk_bytes).decode("ascii")
    assert body["commitment_hex"] == matching_commitment
    assert body["activation_height"] == 10
    assert body["withdraw_height"] == 10


def test_zk_verifying_key_mutation_helpers_enforce_unsigned_draft_contract() -> None:
    payload = {
        "authority": account_address(33),
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 1,
        "circuit_id": "halo2/ipa::transfer_v1",
        "public_inputs_schema_hash_hex": "aa" * 32,
        "gas_schedule_id": "halo2_default",
        "vk_bytes": "dms=",
    }

    for malformed, pattern in (
        (
            zk_verifying_key_transaction_draft(submitted=True),
            r"submitted must be false",
        ),
        (
            zk_verifying_key_transaction_draft(transaction_payload_b64="AQ"),
            r"transaction_payload_b64 must be canonical padded base64",
        ),
        (
            zk_verifying_key_transaction_draft(signing_message_b64=None),
            r"signing_message_b64 must be canonical padded base64",
        ),
        (
            zk_verifying_key_transaction_draft(
                transaction_payload_b64=base64.b64encode(
                    bytes(16 * 1024 * 1024 + 1)
                ).decode("ascii")
            ),
            r"transaction_payload_b64 exceeds the 16777216-byte transaction payload limit",
        ),
        (
            zk_verifying_key_transaction_draft(
                signing_message_b64=base64.b64encode(bytes(31)).decode("ascii")
            ),
            r"signing_message_b64 must decode to exactly 32 bytes",
        ),
        (
            zk_verifying_key_transaction_draft(
                signing_message_b64=base64.b64encode(bytes(32)).decode("ascii")
            ),
            r"signing_message_b64 must equal the canonical Iroha HashOf",
        ),
        (
            zk_verifying_key_transaction_draft(accepted=True),
            r"contains unsupported fields: accepted",
        ),
    ):
        client = ToriiClient(
            "http://torii.example",
            session=FakeSession([response(200, malformed)]),
            local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
            max_retries=0,
        )
        with pytest.raises((TypeError, ValueError), match=pattern):
            client.register_zk_verifying_key(payload)

    legacy_status_client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(202, zk_verifying_key_transaction_draft())]),
        local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
        max_retries=0,
    )
    with pytest.raises(RuntimeError, match=r"unexpected status 202; expected \[200\]"):
        legacy_status_client.update_zk_verifying_key(payload)


def test_zk_verifying_key_drafts_reject_substitution_extra_wrong_context_and_noncanonical(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = account_address(34)
    payload: dict[str, object] = {
        "authority": authority,
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 1,
        "circuit_id": "halo2/ipa::transfer_v1",
        "public_inputs_schema_hash_hex": "aa" * 32,
        "gas_schedule_id": "halo2_default",
        "vk_bytes": "dms=",
    }
    for label, error, pattern in (
        (
            "operation substitution",
            ValueError(
                "verifying-key transaction payload must contain RegisterVerifyingKey"
            ),
            r"must contain RegisterVerifyingKey",
        ),
        (
            "extra instruction",
            ValueError(
                "verifying-key transaction payload must contain exactly one instruction"
            ),
            r"exactly one instruction",
        ),
        (
            "wrong chain",
            ValueError("transaction payload changed the configured network ID"),
            r"changed the configured network ID",
        ),
        (
            "wrong authority",
            ValueError("transaction payload changed the requested authority"),
            r"changed the requested authority",
        ),
        (
            "noncanonical",
            ValueError("invalid canonical transaction payload"),
            r"invalid canonical transaction payload",
        ),
    ):
        native = FakeVkDraftCrypto(error=error)
        monkeypatch.setattr(client_module, "_require_crypto", lambda native=native: native)
        transaction_payload = f"vk-{label}".encode()
        client = ToriiClient(
            "http://torii.example",
            session=FakeSession(
                [response(200, zk_verifying_key_draft_for_payload(transaction_payload))]
            ),
            local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
            max_retries=0,
        )
        with pytest.raises(ValueError, match=pattern):
            client.register_zk_verifying_key(payload)
        assert native.calls[0][1:] == (
            NETWORK_ID,
            authority,
            "register",
        ), label


def test_zk_verifying_key_draft_rejects_any_record_field_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = account_address(35)
    payload: dict[str, object] = {
        "authority": authority,
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 1,
        "circuit_id": "halo2/ipa::transfer_v1",
        "public_inputs_schema_hash_hex": "aa" * 32,
        "gas_schedule_id": "halo2_default",
        "vk_bytes": "dms=",
    }
    decoded = copy.deepcopy(
        expected_zk_verifying_key_instruction(payload, authority, update=False)
    )
    record = decoded["record"]
    assert isinstance(record, dict)
    record["max_proof_bytes"] = 1
    native = FakeVkDraftCrypto(decoded)
    monkeypatch.setattr(client_module, "_require_crypto", lambda: native)
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([response(200, zk_verifying_key_transaction_draft())]),
        local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
        max_retries=0,
    )
    with pytest.raises(
        ValueError,
        match="does not contain the exact requested verifying-key registry record",
    ):
        client.register_zk_verifying_key(payload)


def test_zk_verifying_key_local_signing_fails_closed_without_network_context() -> None:
    session = FakeSession([response(200, zk_verifying_key_transaction_draft())])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    payload = {
        "authority": account_address(36),
        "backend": "pipa-r/pasta",
        "name": "vk_transfer",
        "version": 1,
        "circuit_id": "halo2/ipa::transfer_v1",
        "public_inputs_schema_hash_hex": "aa" * 32,
        "gas_schedule_id": "halo2_default",
        "vk_bytes": "dms=",
    }
    with pytest.raises(
        ValueError,
        match="requires immutable ToriiClient local_signing_context",
    ):
        client.register_zk_verifying_key(payload)
    with pytest.raises(
        ValueError,
        match="requires immutable ToriiClient local_signing_context",
    ):
        client.update_zk_verifying_key(payload)
    with pytest.raises(
        ValueError,
        match="requires immutable ToriiClient local_signing_context",
    ):
        client.submit_zk_verifying_key_registration(payload)
    with pytest.raises(
        ValueError,
        match="requires immutable ToriiClient local_signing_context",
    ):
        client.submit_zk_verifying_key_update(payload)
    assert session.calls == []
    with pytest.raises(AttributeError):
        client.local_signing_context = LocalSigningContext(  # type: ignore[misc]
            NetworkId.from_bytes(bytes([0xA7]) * 32)
        )
    with pytest.raises(AttributeError):
        VK_LOCAL_SIGNING_CONTEXT.network_id = NetworkId.from_bytes(  # type: ignore[misc]
            bytes([0xA7]) * 32
        )
    for retired_value in ("vk-test", CANONICAL_GENESIS_HASH, object()):
        with pytest.raises(TypeError, match="LocalSigningContext.network_id must be a NetworkId"):
            LocalSigningContext(retired_value)  # type: ignore[arg-type]
    for retired_key in (
        "chain",
        "chainId",
        "chain_id",
        "canonicalGenesisHash",
        "canonical_genesis_hash",
        "genesisHash",
        "genesis_hash",
    ):
        with pytest.raises(TypeError, match=f"unexpected keyword argument '{retired_key}'"):
            LocalSigningContext(**{retired_key: "vk-test"})  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="unexpected keyword argument 'signing_chain_id'"):
        ToriiClient(
            "http://torii.example",
            **{"signing_chain_id": "vk-test"},  # type: ignore[arg-type]
        )

    signing_client = ToriiClient(
        "http://torii.example",
        session=session,
        local_signing_context=VK_LOCAL_SIGNING_CONTEXT,
        max_retries=0,
    )
    with pytest.raises(ValueError, match="must be an exact canonical I105 account id"):
        signing_client.register_zk_verifying_key(
            {**payload, "authority": "merchant@paynet"}
        )
    assert session.calls == []


def test_zk_verifying_key_update_rejects_bad_inputs_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    vk_bytes = b"abc"
    matching_commitment = zk_verifying_key_commitment("pipa-r/pasta", vk_bytes)

    def payload(**overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "authority": "alice",
            "backend": "pipa-r/pasta",
            "name": "vk_transfer",
            "version": 2,
            "circuit_id": "halo2/ipa::transfer_v2",
            "public_inputs_schema_hash_hex": "aa" * 32,
            "vk_bytes": base64.b64encode(vk_bytes).decode("ascii"),
            "commitment_hex": matching_commitment,
        }
        base.update(overrides)
        return base

    for backend in (
        " halo2/ipa",
        "halo2/ipa ",
        "halo2/ipa\n",
        "halo2\uFF0Fipa",
        "halo2/\u200Bipa",
        "h\u0430lo2/ipa",
        "stark/fri/miden",
        "stark/fri/latest",
        "halo2/kzg",
        "mock/dev",
    ):
        with pytest.raises(ValueError, match="update_zk_verifying_key.backend"):
            client.submit_zk_verifying_key_update(payload(backend=backend))

    for bad_name in ("", "   ", "\t", " vk_transfer", "vk_transfer ", None, 7):
        with pytest.raises((TypeError, ValueError), match="update_zk_verifying_key.name"):
            client.submit_zk_verifying_key_update(payload(name=bad_name))

    for field, value in (
        ("circuit_id", " halo2/ipa::transfer_v2"),
        ("circuit_id", "halo2/ipa::transfer_v2 "),
        ("gas_schedule_id", " halo2_default"),
        ("gas_schedule_id", "halo2_default "),
    ):
        with pytest.raises(
            ValueError,
            match=rf"update_zk_verifying_key\.{field}.*surrounding whitespace",
        ):
            client.submit_zk_verifying_key_update(payload(**{field: value}))

    for authority in (None, "", "   ", 7):
        with pytest.raises((TypeError, ValueError), match="update_zk_verifying_key.authority"):
            client.submit_zk_verifying_key_update(payload(authority=authority))

    for field, private_key in (
        ("private_key", None),
        ("private_key", "ed25519:deadbeef"),
        ("privateKey", "ed25519:deadbeef"),
        ("private_key_hex", "11" * 32),
        ("privateKeyBytes", bytes([0x11]) * 32),
    ):
        with pytest.raises(
            ValueError,
            match="does not accept private-key fields.*sign the returned transaction draft locally",
        ):
            client.submit_zk_verifying_key_update(payload(**{field: private_key}))

    with pytest.raises(TypeError, match="update_zk_verifying_key.vk_bytes"):
        client.submit_zk_verifying_key_update(payload(vk_bytes=7))

    with pytest.raises(ValueError, match="update_zk_verifying_key.vk_bytes"):
        client.submit_zk_verifying_key_update(payload(vk_bytes="not base64!"))

    with pytest.raises(ValueError, match="commitment_hex must match domain-separated SHA-256"):
        client.submit_zk_verifying_key_update(payload(commitment_hex="00" * 32))

    with pytest.raises(ValueError, match="commitment_hex"):
        client.submit_zk_verifying_key_update(
            payload(vk_bytes=None, vk_len=3, commitment_hex=None)
        )

    with pytest.raises(ValueError, match="withdraw_height"):
        client.submit_zk_verifying_key_update(payload(activation_height=10, withdraw_height=9))

    with pytest.raises(ValueError, match="activation_height"):
        client.submit_zk_verifying_key_update(payload(activation_height=-1))

    assert session.calls == []


def test_zk_verifying_key_read_helpers_reject_unsupported_backends_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    for backend in (
        " halo2/ipa",
        "halo2/ipa ",
        "\thalo2/ipa",
        "halo2/ipa\n",
        "halo2\uFF0Fipa",
        "halo2/\u200Bipa",
        "h\u0430lo2/ipa",
        "stark/fri/miden",
        "stark/fri/latest",
        "stark/fri/attestation",
        "stark/fri/contest",
        "stark/fri/random-profile",
        "stark/fri/sha512-goldilocks",
        "stark/fri/audit-proof-v1",
        "halo2/ipa:production-ready",
        "halo2/ipa:claimed-production",
        "halo2/ipa:mainnet-ready",
        "stark/fri/audit-signoff",
        "stark/fri/externally-audited",
        "stark/fri/security-review-passed",
        "stark/fri/S.e.c.u.r.i.t.yReviewPassed",
        "stark/fri/a-u-d-i-t-c-l-a-i-m",
        "halo2/ipa/penumbra",
        "halo2/ipa/masp",
        "halo2/ipa/monero",
        "halo2/ipa/curve-tree",
        "halo2/pasta/tiny-add",
        "halo2/ipa/tiny-add",
        "halo2/ipa:tiny-add",
        "halo2/pasta/tiny-commit-open",
        "halo2/pasta/anon-transfer-2x2",
        "halo2/ipa/anon-transfer-2x2",
        "halo2/ipa:anon-transfer-2x2",
        "halo2/pasta/anon-transfer-2x2-merkle2",
        "halo2/ipa/anon-transfer-2x2-merkle8",
        "halo2/ipa:anon-transfer-2x2-merkle16",
        "halo2/pasta/vote-bool-commit",
        "halo2/ipa/vote-bool-commit",
        "halo2/ipa:vote-bool-commit",
        "halo2/pasta/vote-bool-commit-merkle2",
        "halo2/ipa/vote-bool-commit-merkle8",
        "halo2/ipa:vote-bool-commit-merkle16",
        "stark/fri/dev-fixture",
        "stark/fri/d-e-v-f-i-x-t-u-r-e",
        "stark/fri/dev",
        "stark/fri/d-e-v",
        "stark/fri/test",
        "stark/fri/t-e-s-t",
        "stark/fri/todo",
        "stark/fri/t-o-d-o",
        "stark/fri/draft-only",
        "stark/fri/d-r-a-f-t",
        "stark/fri/pending-audit",
        "stark/fri/replace-before-mainnet",
        "stark/fri/not-production-ready",
        "stark/fri/placeholder",
        " stark/fri/poseidon-x7-goldilocks-6x64-v1",
        "stark/fri/poseidon-x7-goldilocks-6x64-v1 ",
        "halo2/ipa/orchard",
        "halo2/kzg",
        "halo2/ipa\0",
        "halo2/ipa:dev-fixture",
        "halo2/ipa:dev",
        "halo2/ipa:d-e-v",
        "halo2/ipa:todo-proof",
        "halo2/ipa:t-o-d-o-proof",
        "halo2/ipa:draft-proof",
        "halo2/ipa:d-r-a-f-t-proof",
        "halo2/ipa:pending-audit",
        "halo2/ipa:replace-before-production",
        "halo2/ipa:not-for-production",
        "halo2/ipa:dummy",
        "halo2/ipa:f-a-k-e",
        "halo2/ipa:stub",
        "halo2/ipa:s-a-m-p-l-e",
        "mock/dev",
    ):
        with pytest.raises(
            ValueError,
            match=(
                "must be a non-empty string|surrounding whitespace|"
                "unsupported production verifier backend"
            ),
        ):
            client.request_zk_verifying_key(backend, "vk_transfer")
        with pytest.raises(
            ValueError,
            match=(
                "must be a non-empty string|surrounding whitespace|"
                "unsupported production verifier backend"
            ),
        ):
            client.zk_verifying_key_active(backend, "vk_transfer")
    assert session.calls == []


def test_zk_verifying_key_read_helpers_reject_padded_names_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    for name in (" vk_transfer", "vk_transfer "):
        with pytest.raises(ValueError, match="name.*surrounding whitespace"):
            client.request_zk_verifying_key("pipa-r/pasta", name)
        with pytest.raises(ValueError, match="name.*surrounding whitespace"):
            client.zk_verifying_key_active("pipa-r/pasta", name)

    assert session.calls == []


def test_event_stream_filters_use_the_collection_text_grammar() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0)
    captured = []

    def capture_stream(path, **kwargs):
        captured.append((path, kwargs.get("params")))
        return iter(())

    client._stream_sse = capture_stream
    tx_hash = "ab" * 31 + "a1"

    list(client.stream_events(filter=(F.tx_hash == tx_hash) & F.tx_status.in_("Approved", "Rejected")))
    list(client.stream_events(filter='proof_backend = "pipa-r/pasta"'))
    list(client.stream_events())

    assert captured == [
        (
            "/v1/events/sse",
            {"filter": f'tx_hash = "{tx_hash}" and tx_status in ["Approved", "Rejected"]'},
        ),
        ("/v1/events/sse", {"filter": 'proof_backend = "pipa-r/pasta"'}),
        ("/v1/events/sse", None),
    ]


@pytest.mark.parametrize(
    "retired",
    [
        {"Pipeline": {"Transaction": {"status": "Queued"}}},
        {"VerifyingKey": {"id_matcher": None, "event_set": {"Registered": True}}},
        {"op": "eq", "args": ["tx_status", "Queued"]},
    ],
)
def test_event_stream_rejects_retired_and_json_filter_shapes(retired: object) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(TypeError):
        client.stream_events(filter=retired)  # type: ignore[arg-type]
    assert session.calls == []


def test_event_stream_filters_reject_object_and_array_literals_before_request() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(FilterError, match="no text form"):
        client.stream_events(filter=F.metadata.tags == ["a"])
    assert session.calls == []


def test_account_has_permission_follows_effective_permission_collection() -> None:
    session = FakeSession(
        [
            response(200, {"items": [], "next_cursor": "more"}),
            response(
                200,
                {
                    "items": [
                        {
                            "name": "register_zk_asset",
                            "payload": {"asset_definition_id": "ds#wonderland.is"},
                        }
                    ],
                    "next_cursor": None,
                },
            )
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert client.account_has_permission(
        "asset-owner@is",
        "register_zk_asset",
        expected_payload={"asset_definition_id": "ds#wonderland.is"},
    )


def test_account_permission_listing_accepts_configured_chain_discriminant() -> None:
    taira_account = account_address(5, 0x0171)
    session = FakeSession([response(200, {"items": [], "next_cursor": None})])
    client = ToriiClient(
        "http://torii.example",
        session=session,
        max_retries=0,
        chain_discriminant=0x0171,
    )

    assert client.accounts.permissions(taira_account).list().items == ()
    assert session.calls == [
        {
            "method": "POST",
            "path": f"/v1/accounts/{quote(taira_account, safe='')}/permissions/query",
            "params": None,
            "data": b"{}",
            "headers": {"Accept": "application/json", "Content-Type": "application/json"},
            "allow_redirects": False,
        }
    ]


def _empty_page() -> requests.Response:
    return response(200, {"items": [], "next_cursor": None})


def test_dataspace_visible_account_reads_use_configured_canonical_signer() -> None:
    account = account_address(0x46)
    session = FakeSession(
        [
            response(200, {"id": account}),
            _empty_page(),
            _empty_page(),
            response(200, {"items": [], "next_cursor": None}),
        ]
    )
    client = authenticated_query_client(session)

    assert client.find_account(account) == {"id": account}
    assert client.accounts.assets(account).list(filter=F.asset_alias == "ds#boi.is2").items == ()
    assert client.accounts.transactions(account).list().items == ()
    assert client.accounts.permissions(account).list().items == ()

    assert len(session.calls) == 4
    assert json.loads(session.calls[1]["data"]) == {
        "filter": {"op": "eq", "args": ["asset_alias", "ds#boi.is2"]}
    }
    for call in session.calls:
        assert call["allow_redirects"] is False
        headers = call["headers"]
        assert isinstance(headers, dict)
        for header in (
            "X-Iroha-Account",
            "X-Iroha-Signature",
            "X-Iroha-Timestamp-Ms",
            "X-Iroha-Nonce",
        ):
            assert header in headers


def test_dataspace_visible_account_reads_remain_anonymous_without_signer() -> None:
    account = account_address(0x47)
    session = FakeSession(
        [
            response(200, {"id": account}),
            _empty_page(),
            _empty_page(),
            response(200, {"items": [], "next_cursor": None}),
        ]
    )
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    assert client.find_account(account) == {"id": account}
    assert client.accounts.assets(account).list().items == ()
    assert client.accounts.transactions(account).list().items == ()
    assert client.accounts.permissions(account).list().items == ()

    assert len(session.calls) == 4
    for call in session.calls:
        assert call["allow_redirects"] is False
        headers = call["headers"]
        assert isinstance(headers, dict)
        for header in (
            "X-Iroha-Account",
            "X-Iroha-Signature",
            "X-Iroha-Timestamp-Ms",
            "X-Iroha-Nonce",
        ):
            assert header not in headers


def test_account_permission_listing_rejects_foreign_chain_discriminant() -> None:
    taira_account = account_address(6, 0x0171)
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)

    with pytest.raises(
        ValueError,
        match="account_id must be a canonical I105 account id or on-chain account alias",
    ):
        client.accounts.permissions(taira_account).list()
    assert session.calls == []



def test_call_contract_and_wait_delegates_to_caller_signed_batch() -> None:
    tx_hash = "d" * 64
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    captured: dict[str, object] = {}

    def call_batch(**kwargs: object) -> dict[str, object]:
        captured.update(kwargs)
        return {
            "hash": tx_hash,
            "submission": {"accepted": True},
        }

    client.call_contract_batch_and_wait = call_batch  # type: ignore[method-assign]

    result = client.call_contract_and_wait(
        authority="authority@is",
        private_key_hex="11" * 32,
        contract_alias="contract::is",
        entrypoint="main",
        payload={"amount": 7},
        fee_payment=authority_fee_payment(charge_limits=[], gas_limit=5000),
        wait=True,
        timeout_ms=1000,
        interval=0,
    )

    assert "chain_id" not in captured
    assert captured["authority"] == "authority@is"
    assert captured["private_key"] is None
    assert captured["private_key_hex"] == "11" * 32
    entries = captured["entries"]
    assert isinstance(entries, list) and len(entries) == 1
    intent = entries[0]
    assert isinstance(intent, ContractCallIntent)
    assert intent.to_payload() == {
        "entrypoint": "main",
        "contract_alias": "contract::is",
        "payload": {"amount": 7},
    }
    assert result["submit"] == {"accepted": True}
    assert result["tx_hashes"] == [tx_hash]
    assert session.calls == []


def test_call_contract_and_wait_rejects_retired_chain_id_before_dispatch() -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0)
    client.call_contract_batch_and_wait = (  # type: ignore[method-assign]
        lambda **_kwargs: pytest.fail("retired chain_id must fail before dispatch")
    )

    with pytest.raises(TypeError, match="chain_id"):
        client.call_contract_and_wait(  # type: ignore[call-arg]
            authority="authority@is",
            private_key_hex="11" * 32,
            contract_alias="contract::is",
            entrypoint="main",
            payload={"amount": 7},
            fee_payment=authority_fee_payment(charge_limits=[], gas_limit=5000),
            **{"chain_id": "chain"},
        )
    assert session.calls == []


def test_mint_assets_quantity_and_wait_batches_records_in_one_transaction() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    captured: dict[str, object] = {}
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    adult = account_address(0x11)
    business = account_address(0x22)

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured["draft"] = draft
        captured["kwargs"] = kwargs
        return {"hash": "mint-batch"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    result = client.mint_assets_quantity_and_wait(
        authority="authority@is",
        fee_payment=FEE_PAYMENT,
        private_key_hex="11" * 32,
        mints=[
            {"asset_id": f"{asset_definition_id}#{adult}", "quantity": "1.25"},
            {"asset_id": f"{asset_definition_id}#{business}", "quantity": 2},
        ],
        transaction_metadata={"purpose": "batch"},
        wait=False,
    )

    draft = captured["draft"]
    assert result == {"hash": "mint-batch"}
    assert len(draft) == 2
    assert draft.config.metadata == {"purpose": "batch"}
    assert captured["kwargs"]["private_key_hex"] == "11" * 32
    assert captured["kwargs"]["wait"] is False


def test_transaction_draft_rejects_retired_chain_and_padded_authority_before_signing() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)

    with pytest.raises(
        TypeError,
        match="unexpected keyword argument 'chain_id'",
    ):
        client._transaction_draft(
            authority="authority@is",
            fee_payment=FEE_PAYMENT,
            **{"chain_id": "chain"},
        )

    with pytest.raises(
        ValueError,
        match="authority must not contain surrounding whitespace",
    ):
        client._transaction_draft(
            authority=" authority@is ",
            fee_payment=FEE_PAYMENT,
        )


def test_transfer_assets_quantity_and_wait_batches_records_in_one_transaction() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    captured: dict[str, object] = {}
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    source = account_address(0x11)
    dest = account_address(0x22)
    fees = account_address(0x33)

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured["draft"] = draft
        captured["kwargs"] = kwargs
        return {"hash": "transfer-batch"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    result = client.transfer_assets_quantity_and_wait(
        authority="source@is",
        fee_payment=FEE_PAYMENT,
        private_key_hex="22" * 32,
        transfers=[
            {
                "asset_id": f"{asset_definition_id}#{source}",
                "quantity": Decimal("3"),
                "destination": dest,
            },
            {
                "asset_id": f"{asset_definition_id}#{source}",
                "quantity": "0.1",
                "destination": fees,
            },
        ],
        wait=True,
    )

    draft = captured["draft"]
    assert result == {"hash": "transfer-batch"}
    assert len(draft) == 2
    assert draft.config.authority == "source@is"
    assert captured["kwargs"]["private_key_hex"] == "22" * 32
    assert captured["kwargs"]["wait"] is True


def test_permission_grant_and_revoke_helpers_build_one_instruction() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    captured: list[tuple[object, dict[str, object]]] = []
    account = account_address(0x44)

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured.append((draft, kwargs))
        return {"hash": f"permission-{len(captured)}"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    grant = client.grant_account_permission_and_wait(
        authority="authority@is",
        fee_payment=FEE_PAYMENT,
        private_key_hex="11" * 32,
        account_id=account,
        permission_name="CanEnrollFeeSponsorProgram",
        permission_payload={"program_id": "sponsor@is/retail"},
        transaction_metadata={"purpose": "fee-sponsor-program"},
        wait=False,
    )
    revoke = client.revoke_account_permission_and_wait(
        authority="authority@is",
        fee_payment=FEE_PAYMENT,
        private_key_hex="22" * 32,
        account_id=account,
        permission_name="CanEnrollFeeSponsorProgram",
        permission_payload={"program_id": "sponsor@is/retail"},
        wait=True,
    )

    assert grant == {"hash": "permission-1"}
    assert revoke == {"hash": "permission-2"}
    grant_draft, grant_kwargs = captured[0]
    revoke_draft, revoke_kwargs = captured[1]
    assert len(grant_draft) == 1
    assert len(revoke_draft) == 1
    assert grant_draft.config.metadata == {"purpose": "fee-sponsor-program"}
    assert grant_kwargs["private_key_hex"] == "11" * 32
    assert grant_kwargs["wait"] is False
    assert revoke_kwargs["private_key_hex"] == "22" * 32
    assert revoke_kwargs["wait"] is True


def test_permission_grant_normalizes_configured_chain_discriminant_for_transaction_draft() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([]),
        max_retries=0,
        chain_discriminant=0x0171,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
    )
    captured: dict[str, object] = {}
    account = account_address(0x45, 0x0171)
    fixed_account = account_address(0x45)

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured["draft"] = draft
        captured["kwargs"] = kwargs
        return {"hash": "permission-taira"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    assert client.grant_account_permission_and_wait(
        authority=account,
        fee_payment=FEE_PAYMENT,
        private_key_hex="11" * 32,
        account_id=account,
        permission_name="CanEnrollFeeSponsorProgram",
        permission_payload={"program_id": "sponsor@is/retail"},
        wait=False,
    ) == {"hash": "permission-taira"}

    draft = captured["draft"]
    assert draft.config.authority == fixed_account
    assert len(draft) == 1
    assert captured["kwargs"]["private_key_hex"] == "11" * 32


def test_transfer_helper_normalizes_configured_chain_discriminant_for_transaction_draft() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([]),
        max_retries=0,
        chain_discriminant=0x0171,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
    )
    captured: dict[str, object] = {}
    source = account_address(0x46, 0x0171)
    destination = account_address(0x47, 0x0171)
    fixed_source = account_address(0x46)
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured["draft"] = draft
        captured["kwargs"] = kwargs
        return {"hash": "transfer-taira"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    assert client.transfer_asset_quantity_and_wait(
        authority=source,
        fee_payment=FEE_PAYMENT,
        private_key_hex="22" * 32,
        asset_id=f"{asset_definition_id}#{source}",
        destination=destination,
        quantity=Decimal("3"),
        wait=False,
    ) == {"hash": "transfer-taira"}

    draft = captured["draft"]
    assert draft.config.authority == fixed_source
    assert len(draft) == 1
    assert captured["kwargs"]["private_key_hex"] == "22" * 32


def test_transfer_helper_normalizes_scoped_asset_id_account_segment() -> None:
    client = ToriiClient(
        "http://torii.example",
        session=FakeSession([]),
        max_retries=0,
        chain_discriminant=0x0171,
        local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT,
    )
    captured: dict[str, object] = {}
    source = account_address(0x48, 0x0171)
    destination = account_address(0x49, 0x0171)
    fixed_source = account_address(0x48)
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    scope = "dataspace:6647857470246403404"

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured["draft"] = draft
        captured["kwargs"] = kwargs
        return {"hash": "transfer-taira-scoped"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    assert client.transfer_asset_quantity_and_wait(
        authority=source,
        fee_payment=FEE_PAYMENT,
        private_key_hex="23" * 32,
        asset_id=f"{asset_definition_id}#{source}#{scope}",
        destination=destination,
        quantity=Decimal("3"),
        wait=False,
    ) == {"hash": "transfer-taira-scoped"}

    draft = captured["draft"]
    assert draft.config.authority == fixed_source
    assert len(draft) == 1
    assert captured["kwargs"]["private_key_hex"] == "23" * 32


def test_zk_instruction_helpers_serialize_full_surface() -> None:
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    proof = canonical_proof_attachment()
    proof["vk_commitment"] = b"\x44" * 32
    proof["envelope_hash"] = iroha_hash_bytes(b"proof-bytes")

    instructions = [
        Instruction.register_zk_asset(
            asset_definition_id,
            vk_unshield={"backend": "pipa-r/pasta", "name": "vk_unshield"},
        ),
        Instruction.verify_proof(proof),
    ]

    encoded = [instruction.to_json() for instruction in instructions]
    assert all(payload for payload in encoded)
    assert "\"vk_shield\"" not in encoded[0]
    assert [Instruction.from_json(payload).to_json() for payload in encoded] == encoded


def test_legacy_zk_ace_instruction_and_client_surfaces_are_absent() -> None:
    for name in (
        "register_zk_ace_identity_commitment",
        "rotate_zk_ace_identity_commitment",
        "revoke_zk_ace_identity_commitment",
        "zk_ace_authorized_transfer",
    ):
        assert not hasattr(Instruction, name)
        assert not hasattr(TransactionDraft, name)


def test_retired_generic_confidential_instruction_and_client_surfaces_are_absent() -> None:
    assert not hasattr(Instruction, "shield_asset")
    assert not hasattr(TransactionDraft, "shield_asset")
    assert not hasattr(ToriiClient, "shield_asset_and_wait")

    for name in ("zk_transfer_prepared", "unshield_prepared"):
        assert not hasattr(Instruction, name)
        assert not hasattr(TransactionDraft, name)
    for name in ("zk_transfer_prepared_and_wait", "unshield_prepared_and_wait"):
        assert not hasattr(ToriiClient, name)

    for name in (
        "register_zk_ace_identity_commitment_and_wait",
        "rotate_zk_ace_identity_commitment_and_wait",
        "revoke_zk_ace_identity_commitment_and_wait",
        "zk_ace_authorized_transfer_and_wait",
    ):
        assert not hasattr(ToriiClient, name)

    for name in (
        "sign_privacy_zk_ace_transfer_action_v1",
        "sign_privacy_jindo_action_v1",
        "sign_privacy_verange_action_v1",
        "prepare_privacy_vega_action_v1",
        "sign_privacy_zk_ams_batch_admission_action_v1",
        "sign_privacy_zk_ams_provision_account_action_v1",
        "sign_privacy_bootle_lantern_presentation_action_v1",
        "sign_privacy_anonymous_pgc_payment_action_v1",
        "sign_privacy_orchard_note_action_v1",
        "sign_privacy_fcmp_membership_payment_action_v1",
        "sign_privacy_ivm_private_note_action_v1",
        "sign_privacy_pq_masp_note_action_v1",
    ):
        assert not hasattr(TransactionDraft, name)


@pytest.mark.parametrize(
    "entry_surface",
    ("instruction", "transaction_draft", "torii_client"),
)
@pytest.mark.parametrize(
    ("unexpected_kwarg", "hostile_value"),
    (
        pytest.param("mode", "Hybrid", id="mode-hybrid"),
        pytest.param("mode", "ZkNative", id="mode-zk-native"),
        pytest.param(
            "vk_transfer",
            "halo2/ipa:vk_transfer",
            id="vk-transfer",
        ),
        pytest.param("allow_shield", True, id="allow-shield"),
        pytest.param("vk_shield", "halo2/ipa:vk_shield", id="retired-shield-role"),
        pytest.param("allow_unshield", True, id="allow-unshield"),
    ),
)
def test_register_zk_asset_entry_surfaces_reject_transitional_keywords(
    entry_surface: str,
    unexpected_kwarg: str,
    hostile_value: object,
) -> None:
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    unexpected = {unexpected_kwarg: hostile_value}

    with pytest.raises(
        TypeError,
        match=rf"unexpected keyword argument '{unexpected_kwarg}'",
    ):
        if entry_surface == "instruction":
            Instruction.register_zk_asset(asset_definition_id, **unexpected)
        elif entry_surface == "transaction_draft":
            TransactionDraft(
                TransactionConfig(
                    network_id=NETWORK_ID,
                    authority=account_address(0x75),
                    fee_payment=FEE_PAYMENT,
                )
            ).register_zk_asset(asset_definition_id, **unexpected)
        else:
            assert entry_surface == "torii_client"
            ToriiClient(
                "http://torii.example",
                session=FakeSession([]),
                max_retries=0,
            ).register_zk_asset_and_wait(
                authority="authority@is",
                fee_payment=FEE_PAYMENT,
                private_key_hex="11" * 32,
                asset_definition_id=asset_definition_id,
                wait=False,
                **unexpected,
            )


def test_zk_registration_helper_rejects_adversarial_inputs() -> None:
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"

    with pytest.raises(ValueError, match="backend:name"):
        Instruction.register_zk_asset(asset_definition_id, vk_unshield="pipa-r/pasta")


def test_zk_client_helpers_build_transaction_drafts() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    captured: list[tuple[object, dict[str, object]]] = []
    asset_definition_id = "7MBRDd8cGFBZkFGdDMwV7S6FPwbw"
    source = account_address(0x63)
    proof = canonical_proof_attachment()

    def fake_submit(draft: object, **kwargs: object) -> dict[str, object]:
        captured.append((draft, kwargs))
        return {"hash": f"zk-{len(captured)}"}

    client._submit_transaction_draft_result = fake_submit  # type: ignore[method-assign]

    assert client.register_zk_asset_and_wait(
        authority="authority@is",
        fee_payment=FEE_PAYMENT,
        private_key_hex="11" * 32,
        asset_definition_id=asset_definition_id,
        vk_unshield="halo2/ipa:vk_unshield",
        transaction_metadata={"purpose": "zk-register"},
        wait=False,
    ) == {"hash": "zk-1"}
    assert client.verify_proof_and_wait(
        authority=source,
        fee_payment=FEE_PAYMENT,
        private_key_hex="bb" * 32,
        proof=proof,
        wait=False,
    ) == {"hash": "zk-2"}

    assert [len(draft) for draft, _kwargs in captured] == [1, 1]
    assert captured[0][0].config.metadata == {"purpose": "zk-register"}
    assert captured[0][1]["wait"] is False
    assert captured[1][1]["private_key_hex"] == "bb" * 32


def test_verify_proof_client_helper_rejects_non_mapping_before_submission() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    client._submit_transaction_draft_result = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: pytest.fail("invalid ZK helper should not submit")
    )

    with pytest.raises(TypeError, match="proof must be a mapping"):
        client.verify_proof_and_wait(
            authority=account_address(0x6B),
            fee_payment=FEE_PAYMENT,
            private_key_hex="11" * 32,
            proof=object(),
        )


@pytest.mark.parametrize(
    ("method_name", "kwargs", "error_type", "match"),
    [
        (
            "mint_assets_quantity_and_wait",
            {"mints": []},
            ValueError,
            "at least one mint record",
        ),
        (
            "mint_assets_quantity_and_wait",
            {"mints": [object()]},
            TypeError,
            r"mints\[0\] must be a mapping",
        ),
        (
            "mint_assets_quantity_and_wait",
            {"mints": [{"quantity": "1"}]},
            TypeError,
            r"mints\[0\]\.asset_id",
        ),
        (
            "mint_assets_quantity_and_wait",
            {"mints": [{"asset_id": "asset#account"}]},
            TypeError,
            r"mints\[0\]\.quantity is required",
        ),
        (
            "transfer_assets_quantity_and_wait",
            {"transfers": []},
            ValueError,
            "at least one transfer record",
        ),
        (
            "transfer_assets_quantity_and_wait",
            {"transfers": [object()]},
            TypeError,
            r"transfers\[0\] must be a mapping",
        ),
        (
            "transfer_assets_quantity_and_wait",
            {"transfers": [{"quantity": "1", "destination": account_address(0x45)}]},
            TypeError,
            r"transfers\[0\]\.asset_id",
        ),
        (
            "transfer_assets_quantity_and_wait",
            {"transfers": [{"asset_id": f'asset#{account_address(0x46)}', "quantity": "1"}]},
            TypeError,
            r"transfers\[0\]\.destination",
        ),
        (
            "transfer_assets_quantity_and_wait",
            {
                "transfers": [
                    {
                        "asset_id": f"asset#{account_address(0x47)}",
                        "destination": account_address(0x48),
                    }
                ]
            },
            TypeError,
            r"transfers\[0\]\.quantity is required",
        ),
    ],
)
def test_batch_helpers_reject_invalid_records(
    method_name: str,
    kwargs: dict[str, object],
    error_type: type[Exception],
    match: str,
) -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    client._submit_transaction_draft_result = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: pytest.fail("invalid batch should not submit")
    )
    method = getattr(client, method_name)

    with pytest.raises(error_type, match=match):
        method(
            authority="authority@is",
            fee_payment=FEE_PAYMENT,
            private_key_hex="11" * 32,
            **kwargs,
        )


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        (
            {
                "account_id": "adult@is",
                "permission_name": "CanEnrollFeeSponsorProgram",
            },
            "exact canonical I105 account id",
        ),
        (
            {"account_id": account_address(0x49), "permission_name": ""},
            "permission name",
        ),
        (
            {
                "account_id": account_address(0x4A),
                "permission_name": "CanEnrollFeeSponsorProgram",
                "permission_payload": object(),
            },
            "JSON",
        ),
    ],
)
def test_permission_helpers_reject_invalid_inputs(
    kwargs: dict[str, object],
    match: str,
) -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, local_signing_context=TRANSACTION_LOCAL_SIGNING_CONTEXT)
    client._submit_transaction_draft_result = (  # type: ignore[method-assign]
        lambda *_args, **_kwargs: pytest.fail("invalid permission should not submit")
    )

    with pytest.raises(ValueError, match=match):
        client.grant_account_permission_and_wait(
            authority="authority@is",
            fee_payment=FEE_PAYMENT,
            private_key_hex="11" * 32,
            **kwargs,
        )


@pytest.mark.parametrize(
    "field", ["authorization_sha256", "authorization_nonce", "phase", "idempotency_key"]
)
def test_prepared_operation_binding_rejects_private_custody_fields(field: str) -> None:
    binding = prepared_binding("onboarding")
    binding[field] = "operator-private"
    with pytest.raises(TypeError, match="exactly the V1"):
        client_module._copy_prepared_operation_binding(
            binding, expected_kind="onboarding", context="binding", require_active=False
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("schema", "iroha.taira.public-reset.mutation-binding.v1"),
        ("kind", "reset"),
        ("request_id", "AA" * 32),
        ("request_id", "a" * 63),
        ("semantic_hash_hex", "GG" * 32),
        ("execution_expires_at_unix_ms", 0),
        ("execution_expires_at_unix_ms", True),
        ("execution_expires_at_unix_ms", 1 << 64),
    ],
)
def test_prepared_operation_binding_rejects_noncanonical_identity(
    field: str, invalid: object
) -> None:
    binding = prepared_binding("onboarding")
    binding[field] = invalid
    with pytest.raises(ValueError):
        client_module._copy_prepared_operation_binding(
            binding, expected_kind="onboarding", context="binding", require_active=False
        )


def test_prepared_operation_binding_pins_receipt_hash_and_validity() -> None:
    binding = prepared_binding("onboarding")
    receipt = onboarding_receipt()
    client_module._require_onboarding_binding_receipt(binding, receipt, "receipt")
    substituted = dict(binding, semantic_hash_hex="22" * 32)
    with pytest.raises(ValueError, match="semantic_hash_hex differs"):
        client_module._require_onboarding_binding_receipt(substituted, receipt, "receipt")
    late = dict(binding, execution_expires_at_unix_ms=binding["execution_expires_at_unix_ms"] + 1)
    with pytest.raises(ValueError, match="deadline exceeds"):
        client_module._require_onboarding_binding_receipt(late, receipt, "receipt")


def test_prepared_operation_transcript_authenticates_public_request_identity() -> None:
    binding = prepared_binding("onboarding")
    transcript = client_module._prepared_binding_transcript(
        client_module.PREPARED_TRANSACTION_SCHEMA, "onboarding", binding
    )
    for field in ("authorization_sha256", "authorization_nonce", "phase", "idempotency_key"):
        assert f"binding.{field}".encode() not in transcript
    assert b"iroha:prepared-transaction:v1\0" in transcript
    assert b"binding.semantic_hash_hex" in transcript
    assert b"binding.request_id" in transcript
    substituted = dict(binding, request_id="ef" * 32)
    assert transcript != client_module._prepared_binding_transcript(
        client_module.PREPARED_TRANSACTION_SCHEMA, "onboarding", substituted
    )
