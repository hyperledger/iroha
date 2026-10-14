from __future__ import annotations

import json
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

import pytest

from iroha_python import NetworkId
from iroha_python.address import AccountAddress, CurveId, MultisigMember
from iroha_python.connect import ConnectUri, build_connect_uri, generate_connect_sid
from iroha_python.nexus_app import (
    DefaultNexusTransactionCodec,
    NexusAppClient,
    NexusAppConfig,
    NexusAppError,
    NexusApprovedAccount,
    NexusConnectOptions,
    NexusConnectSession,
    NexusTransferInput,
    NexusWalletSignature,
)

FIXTURE = json.loads(
    (Path(__file__).parents[3] / "fixtures" / "sdk" / "nexus_connect_transfer_v1.json").read_text(
        encoding="utf-8"
    )
)
FIXTURE_PAYLOAD = bytes.fromhex(FIXTURE["expected"]["payload_bytes_hex"])
FIXTURE_PUBLIC_KEY = bytes.fromhex(FIXTURE["connect"]["approval_frame"]["signing_public_key_hex"])
FIXTURE_SIGNATURE = bytes.fromhex(FIXTURE["expected"]["wallet_signature_hex"])
FIXTURE_ACCOUNT_ID = FIXTURE["connect"]["approval_frame"]["account_id"]
FIXTURE_DESTINATION_ACCOUNT_ID = FIXTURE["transfer_input"]["destination_account_id"]
FIXTURE_SOURCE_ASSET_ID = FIXTURE["transfer_input"]["source_asset_id"]
FIXTURE_CHAIN_DISCRIMINANT = FIXTURE["transfer_input"]["account_chain_discriminant"]
FIXTURE_NETWORK_ID = NetworkId.parse(FIXTURE["transfer_input"]["network_id"])
FEE_PAYMENT = {
    "payer": "authority",
    "value": {"charge_limits": [], "gas_limit": None},
}
CANONICAL_GENESIS_HASH = bytes([0xA5]) * 32
NETWORK_ID = NetworkId.from_bytes(CANONICAL_GENESIS_HASH)
UNSUPPORTED_SIGNATURE_ALGORITHMS = (
    "secp256k1",
    "",
    " ",
    " Ed25519",
    "Ed25519 ",
    "\tEd25519",
    "Ed25519\n",
    "ed25519 ",
    " ed25519",
    "\ted25519",
    "ed25519\u00a0",
    "0 ",
    "0",
    " 0",
    "\t0",
    "00",
    "\uff10",
    "ED25519",
    "Ed25519",
    "ed\t25519",
    "ed\00025519",
    "ed\u001f25519",
    "ed\u007f25519",
    "\u00a0Ed25519",
    "Ed25519\u00a0",
    "ed\u200b25519",
    "\u0435d25519",
    "ed\uff0d25519",
    0,
    False,
    b"ed25519",
    ["ed25519"],
)


def _nexus_connect_session(
    *,
    network_id: NetworkId = NETWORK_ID,
    approved_account: str | None = None,
    signing_public_key: bytes | None = None,
) -> NexusConnectSession:
    app_public_key = bytes([0x41]) * 32
    nonce = bytes([0x51]) * 16
    sid = generate_connect_sid(
        network_id=network_id,
        app_public_key=app_public_key,
        nonce=nonce,
    )
    wallet_uri = build_connect_uri(
        ConnectUri(
            sid=sid.sid_base64url,
            network_id=network_id,
            app_public_key=app_public_key,
            nonce=nonce,
        )
    )
    return NexusConnectSession(
        sid=sid.sid_base64url,
        network_id=network_id,
        app_public_key=app_public_key,
        nonce=nonce,
        wallet_launch_uri=wallet_uri,
        token_app="app-token",
        approved_account=approved_account,
        signing_public_key=signing_public_key,
    )


class FakeConnect:
    def __init__(
        self,
        signature: bytes,
        approval=None,
        *,
        signing_public_key: bytes = FIXTURE_PUBLIC_KEY,
        account_id: str = FIXTURE_ACCOUNT_ID,
        session_network_id: NetworkId | None = None,
    ):
        self.signature = signature
        self.approval = approval
        self.signing_public_key = signing_public_key
        self.account_id = account_id
        self.session_network_id = session_network_id
        self.requested_payloads: list[bytes] = []

    def start_connect(self, options: NexusConnectOptions, _config: NexusAppConfig) -> NexusConnectSession:
        _ = options
        return _nexus_connect_session(
            network_id=self.session_network_id or _config.network_id
        )

    def await_approval(self, _session: NexusConnectSession, _config: NexusAppConfig):
        if self.approval is not None:
            return self.approval
        return {
            "account_id": self.account_id,
            "signing_public_key": self.signing_public_key,
        }

    def request_signature(self, _session, signable, _config):
        self.requested_payloads.append(signable.payload_bytes)
        return NexusWalletSignature(self.signature)


class FakeCodec:
    def __init__(
        self,
        payload: bytes,
        signed: bytes,
        hash_hex: str,
        *,
        expected_authority: str = FIXTURE_ACCOUNT_ID,
        expected_signature: bytes = bytes([7]) * 64,
        expected_signing_public_key: bytes = FIXTURE_PUBLIC_KEY,
    ):
        self.payload = payload
        self.signed = signed
        self.hash_hex = hash_hex
        self.expected_authority = expected_authority
        self.expected_signature = expected_signature
        self.expected_signing_public_key = expected_signing_public_key
        self.finalized: list[tuple[object, object]] = []
        self.built: list[dict[str, object]] = []

    def build_transfer_payload(self, payload_input):
        assert payload_input["network_id"] == NETWORK_ID
        assert payload_input["authority"] == self.expected_authority
        assert payload_input["destination_account_id"] == FIXTURE_DESTINATION_ACCOUNT_ID
        self.built.append(dict(payload_input))
        return self.payload

    def finalize_signed_transaction(self, signable, signature, signing_public_key):
        assert signable.payload_bytes == self.payload
        assert signature.signature == self.expected_signature
        assert signing_public_key == self.expected_signing_public_key
        self.finalized.append((signable, signature))
        return {"signed_transaction": self.signed, "hash_hex": self.hash_hex}


class FinalizedResultCodec(FakeCodec):
    def __init__(self, result):
        super().__init__(
            FIXTURE_PAYLOAD,
            b"signed",
            "c" * 64,
            expected_authority=FIXTURE_ACCOUNT_ID,
            expected_signature=FIXTURE_SIGNATURE,
            expected_signing_public_key=FIXTURE_PUBLIC_KEY,
        )
        self.result = result

    def finalize_signed_transaction(self, signable, signature, signing_public_key):
        super().finalize_signed_transaction(signable, signature, signing_public_key)
        return self.result


class PayloadResultCodec(FakeCodec):
    def __init__(self, result):
        super().__init__(FIXTURE_PAYLOAD, b"signed", "c" * 64)
        self.result = result

    def build_transfer_payload(self, payload_input):
        assert payload_input["network_id"] == NETWORK_ID
        assert payload_input["authority"] == FIXTURE_ACCOUNT_ID
        assert payload_input["destination_account_id"] == FIXTURE_DESTINATION_ACCOUNT_ID
        return self.result


class FakeTorii:
    def __init__(
        self,
        *,
        submit_hash_hex=None,
        submit_result=None,
        submit_error=None,
        wait_error=None,
    ):
        self.submitted = []
        self.waited = []
        self.wait_options = []
        self.submit_hash_hex = submit_hash_hex
        self.submit_result = submit_result
        self.submit_error = submit_error
        self.wait_error = wait_error

    def submit_transaction(self, payload):
        if self.submit_error is not None:
            raise self.submit_error
        self.submitted.append(payload)
        if self.submit_result is not None:
            return self.submit_result
        return (
            {
                "accepted": True,
                "payload": {"entrypoint_hash": self.submit_hash_hex},
            }
            if self.submit_hash_hex
            else {"accepted": True}
        )

    def wait_for_transaction_status(self, hash_hex, **_options):
        if self.wait_error is not None:
            raise self.wait_error
        self.waited.append(hash_hex)
        self.wait_options.append(dict(_options))
        return {"status": "Applied"}


def test_nexus_app_builds_transfer_draft_and_computes_payload_hash():
    payload = b"canonical-transfer-payload"
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(payload, b"signed", "a" * 64),
    )

    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity="1.25",
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )

    assert draft.signable.payload_bytes == payload
    assert len(draft.signable.payload_hash_hex) == 64


def test_nexus_app_normalizes_lossless_quantity_before_custom_codec():
    codec = FakeCodec(
        b"canonical-transfer-payload",
        b"signed",
        "a" * 64,
    )
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=codec,
    )

    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=Decimal("1.2500"),
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )

    assert codec.built[0]["quantity"] == "1.25"
    assert draft.input.quantity == "1.25"


@pytest.mark.parametrize(
    "quantity",
    [1.25, True, "+1", "01", "1.0", "1.2500", "1e0", "-1", " 1"],
)
def test_nexus_app_rejects_lossy_or_noncanonical_quantity_before_codec(quantity):
    codec = FakeCodec(
        b"canonical-transfer-payload",
        b"signed",
        "a" * 64,
    )
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=codec,
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.build_transfer_draft(
            NexusTransferInput(
                source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
                quantity=quantity,
                destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
                fee_payment=FEE_PAYMENT,
            )
        )

    assert excinfo.value.code == "invalid_quantity"
    assert codec.built == []


@pytest.mark.parametrize("hash_field", ["payload_hash_hex", "payloadHashHex"])
def test_nexus_app_accepts_exact_custom_payload_hash(hash_field):
    expected_hash = FIXTURE["expected"]["payload_hash_hex"]
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=PayloadResultCodec(
            {"payload_bytes": FIXTURE_PAYLOAD, hash_field: expected_hash}
        ),
    )

    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )

    assert draft.signable.payload_hash_hex == expected_hash


@pytest.mark.parametrize(
    "hash_hex",
    [
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "A" * 64,
        "0x" + "a" * 64,
        " " + "a" * 64,
        bytes.fromhex("aa" * 32),
    ],
    ids=[
        "short",
        "long",
        "non-hex",
        "uppercase",
        "prefixed",
        "whitespace",
        "raw-bytes",
    ],
)
def test_nexus_app_rejects_noncanonical_custom_payload_hash(hash_hex):
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=PayloadResultCodec(
            {"payload_bytes": FIXTURE_PAYLOAD, "payload_hash_hex": hash_hex}
        ),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.build_transfer_draft(
            NexusTransferInput(
                source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
                quantity=1,
                destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
                fee_payment=FEE_PAYMENT,
            )
        )

    assert excinfo.value.code == "invalid_payload_hash"


def test_nexus_app_rejects_mismatched_custom_payload_hash():
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=PayloadResultCodec(
            {"payload_bytes": FIXTURE_PAYLOAD, "payload_hash_hex": "d" * 64}
        ),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.build_transfer_draft(
            NexusTransferInput(
                source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
                quantity=1,
                destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
                fee_payment=FEE_PAYMENT,
            )
        )

    assert excinfo.value.code == "payload_hash_mismatch"


def test_nexus_app_rejects_conflicting_custom_payload_hash_aliases():
    expected_hash = FIXTURE["expected"]["payload_hash_hex"]
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=PayloadResultCodec(
            {
                "payload_bytes": FIXTURE_PAYLOAD,
                "payload_hash_hex": expected_hash,
                "payloadHashHex": "d" * 64,
            }
        ),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.build_transfer_draft(
            NexusTransferInput(
                source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
                quantity=1,
                destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
                fee_payment=FEE_PAYMENT,
            )
        )

    assert excinfo.value.code == "invalid_payload_hash"


def test_nexus_app_default_codec_matches_shared_fixture():
    transfer = FIXTURE["transfer_input"]
    expected = FIXTURE["expected"]
    approval = FIXTURE["connect"]["approval_frame"]
    for account in (
        transfer["authority"],
        transfer["destination_account_id"],
        transfer["source_asset_id"].split("#")[1],
    ):
        parsed = AccountAddress.from_i105(
            account,
            expected_discriminant=transfer["account_chain_discriminant"],
        )
        assert parsed.to_i105(transfer["account_chain_discriminant"]) == account
    client = NexusAppClient(
        NexusAppConfig(
            network_id=FIXTURE_NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=transfer["authority"],
            signing_public_key=bytes.fromhex(approval["signing_public_key_hex"]),
        ),
        transaction_codec=DefaultNexusTransactionCodec(),
    )

    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=transfer["source_asset_id"],
            quantity=transfer["quantity"],
            destination_account_id=transfer["destination_account_id"],
            fee_payment=FEE_PAYMENT,
            metadata=transfer["metadata"],
            creation_time_ms=transfer["creation_time_ms"],
            ttl_ms=transfer["ttl_ms"],
            nonce=transfer["nonce"],
        )
    )

    assert draft.signable.payload_bytes.hex() == expected["payload_bytes_hex"]
    assert draft.signable.payload_hash_hex == expected["payload_hash_hex"]


def test_nexus_app_rejects_wrong_chain_transfer_and_approval_accounts():
    transfer = FIXTURE["transfer_input"]
    wrong_chain_destination = AccountAddress.from_i105(
        transfer["destination_account_id"],
        expected_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
    ).to_i105(FIXTURE_CHAIN_DISCRIMINANT + 1)
    client = NexusAppClient(
        NexusAppConfig(
            network_id=FIXTURE_NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=transfer["authority"],
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=DefaultNexusTransactionCodec(),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.build_transfer_draft(
            NexusTransferInput(
                source_asset_id=transfer["source_asset_id"],
                quantity=transfer["quantity"],
                destination_account_id=wrong_chain_destination,
                fee_payment=FEE_PAYMENT,
            )
        )

    assert excinfo.value.code == "invalid_account_id"

    with pytest.raises(NexusAppError) as scope_excinfo:
        client.build_transfer_draft(
            NexusTransferInput(
                source_asset_id=f'{transfer["source_asset_id"]}#dataspace:01',
                quantity=transfer["quantity"],
                destination_account_id=transfer["destination_account_id"],
                fee_payment=FEE_PAYMENT,
            )
        )
    assert scope_excinfo.value.code == "invalid_account_id"

    wrong_chain_authority = AccountAddress.from_i105(
        transfer["authority"],
        expected_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
    ).to_i105(FIXTURE_CHAIN_DISCRIMINANT + 1)
    approval_client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(
            FIXTURE_SIGNATURE,
            account_id=wrong_chain_authority,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
    )
    with pytest.raises(NexusAppError) as approval_excinfo:
        approval_client.await_approval(_nexus_connect_session())
    assert approval_excinfo.value.code == "invalid_account_id"


def test_nexus_app_runs_wallet_transfer_flow():
    payload = FIXTURE_PAYLOAD
    signed = b"signed-transaction"
    hash_hex = "b" * 64
    connect = FakeConnect(
        FIXTURE_SIGNATURE,
        signing_public_key=FIXTURE_PUBLIC_KEY,
        account_id=FIXTURE_ACCOUNT_ID,
    )
    codec = FakeCodec(
        payload,
        signed,
        hash_hex,
        expected_signature=FIXTURE_SIGNATURE,
        expected_signing_public_key=FIXTURE_PUBLIC_KEY,
        expected_authority=FIXTURE_ACCOUNT_ID,
    )
    torii = FakeTorii()
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        connect_transport=connect,
        transaction_codec=codec,
        torii_client=torii,
    )

    session = client.start_connect()
    approval = client.await_approval(session)
    assert isinstance(approval, NexusApprovedAccount)
    with pytest.raises(TypeError):
        iter(approval)
    receipt = client.transfer_with_wallet(
        approval.session,
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        ),
    )

    assert receipt.signed_transaction == signed
    assert receipt.signed_transaction_hash_hex == hash_hex
    assert connect.requested_payloads == [payload]
    assert torii.submitted == [signed]
    assert torii.waited == [hash_hex]


def test_nexus_app_rejects_approved_account_key_substitution():
    error_case = next(
        case
        for case in FIXTURE["error_cases"]
        if case["name"] == "approval signing key mismatch"
    )
    approval_frame = error_case["approval_frame"]
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(
            FIXTURE_SIGNATURE,
            account_id=approval_frame["account_id"],
            signing_public_key=bytes.fromhex(
                approval_frame["signing_public_key_hex"]
            ),
        ),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.await_approval(_nexus_connect_session())

    assert excinfo.value.code == error_case["expected_code"]


def test_nexus_app_rejects_approval_session_substitution():
    error_case = next(
        case
        for case in FIXTURE["error_cases"]
        if case["name"] == "approval session substitution"
    )
    approval_frame = error_case["approval_frame"]
    caller_session = _nexus_connect_session()
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(
            FIXTURE_SIGNATURE,
            approval={
                "account_id": approval_frame["account_id"],
                "signing_public_key": bytes.fromhex(
                    approval_frame["signing_public_key_hex"]
                ),
                "session": approval_frame["session"],
            },
        ),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.await_approval(caller_session)

    assert excinfo.value.code == error_case["expected_code"]
    assert caller_session.sid == _nexus_connect_session().sid


def test_nexus_app_rejects_transport_network_substitution():
    other_network = NetworkId.from_bytes(bytes([0xA7]) * 32)
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(
            FIXTURE_SIGNATURE,
            session_network_id=other_network,
        ),
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.start_connect()

    assert excinfo.value.code == "connect_identity_substituted"


def test_nexus_connect_session_rejects_sid_substitution():
    exact = _nexus_connect_session()
    substituted_sid = ("A" if exact.sid[0] != "A" else "B") + exact.sid[1:]

    with pytest.raises(ValueError, match="sid does not match"):
        NexusConnectSession(
            sid=substituted_sid,
            network_id=exact.network_id,
            app_public_key=exact.app_public_key,
            nonce=exact.nonce,
            wallet_launch_uri=exact.wallet_launch_uri,
        )


@pytest.mark.parametrize(
    "algorithm",
    UNSUPPORTED_SIGNATURE_ALGORITHMS,
)
def test_nexus_app_rejects_unsupported_signature_algorithm(algorithm):
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(
            b"payload", b"signed", "c" * 64, expected_authority=FIXTURE_ACCOUNT_ID
        ),
    )
    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            {"algorithm": algorithm, "signature": bytes([0]) * 64},
            wait=False,
        )

    assert excinfo.value.code == "unsupported_signature_algorithm"


@pytest.mark.parametrize(
    "algorithm",
    UNSUPPORTED_SIGNATURE_ALGORITHMS,
)
def test_nexus_app_rejects_unsupported_signable_signature_algorithm(algorithm):
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(
            b"payload", b"signed", "c" * 64, expected_authority=FIXTURE_ACCOUNT_ID
        ),
    )
    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )
    signable = replace(draft.signable, signature_algorithm=algorithm)

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            signable,
            {"algorithm": "ed25519", "signature": bytes([7]) * 64},
            wait=False,
        )

    assert excinfo.value.code == "unsupported_signature_algorithm"


def _client_for_finalized_result(result, *, submit_result=None):
    torii = FakeTorii(submit_result=submit_result)
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FinalizedResultCodec(result),
        torii_client=torii,
    )
    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )
    return client, draft, torii


@pytest.mark.parametrize(
    "retired_option",
    ["scope", "success_statuses", "additional_failure_statuses"],
)
def test_nexus_app_rejects_retired_transaction_wait_options_before_submission(
    retired_option,
):
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": "c" * 64}
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
            wait_options={retired_option: "local"},
        )

    assert excinfo.value.code == "invalid_wait_options"
    assert torii.submitted == []
    assert torii.waited == []


def test_nexus_app_forwards_only_current_transaction_wait_options():
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": "d" * 64}
    )
    def callback(*_args):
        return None

    options = {
        "interval": 0.25,
        "timeout": 5.0,
        "max_attempts": 4,
        "on_status": callback,
    }

    client.finalize_and_submit(
        draft.signable,
        NexusWalletSignature(FIXTURE_SIGNATURE),
        wait_options=options,
    )

    assert torii.wait_options == [options]


@pytest.mark.parametrize(
    "finalized",
    [
        b"signed",
        {"signed_transaction": b"signed"},
        {"signedTransaction": b"signed", "hashHex": None},
    ],
    ids=["bytes-only", "missing-hash", "null-hash"],
)
def test_nexus_app_requires_custom_finalizer_transaction_hash(finalized):
    client, draft, torii = _client_for_finalized_result(finalized)

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
            wait=False,
        )

    assert excinfo.value.code == "invalid_transaction_hash"
    assert torii.submitted == []


@pytest.mark.parametrize(
    "hash_hex",
    [
        "a" * 63,
        "a" * 65,
        "a" * 64,
        "g" * 64,
        "A" * 64,
        "0x" + "a" * 64,
        " " + "a" * 64,
        bytes.fromhex("aa" * 32),
    ],
    ids=[
        "short",
        "long",
        "missing-marker",
        "non-hex",
        "uppercase",
        "prefixed",
        "whitespace",
        "raw-bytes",
    ],
)
def test_nexus_app_rejects_noncanonical_custom_finalizer_hash(hash_hex):
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": hash_hex}
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
            wait=False,
        )

    assert excinfo.value.code == "invalid_transaction_hash"
    assert torii.submitted == []


def test_nexus_app_rejects_retired_custom_finalizer_camel_case_fields():
    hash_hex = "d" * 64
    client, draft, torii = _client_for_finalized_result(
        {"signedTransaction": b"signed", "hashHex": hash_hex}
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
            wait=False,
        )

    assert excinfo.value.code == "invalid_transaction_hash"
    assert torii.submitted == []


def test_nexus_app_separates_canonical_and_signed_wire_submission_hashes():
    canonical_hash = "b" * 64
    signed_wire_hash = "d" * 64
    submission = {
        "payload": {
            "entrypoint_hash": canonical_hash,
            "signed_transaction_hash": signed_wire_hash,
        }
    }
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": canonical_hash},
        submit_result=submission,
    )

    receipt = client.finalize_and_submit(
        draft.signable,
        NexusWalletSignature(FIXTURE_SIGNATURE),
    )

    assert receipt.submission is submission
    assert receipt.submission["payload"]["signed_transaction_hash"] == signed_wire_hash
    assert receipt.signed_transaction_hash_hex == canonical_hash
    assert torii.waited == [canonical_hash]


@pytest.mark.parametrize(
    "entrypoint_alias",
    ("entrypoint_hash_hex", "entrypointHashHex", "entrypointHash"),
)
def test_nexus_app_rejects_retired_submission_hash_aliases(entrypoint_alias):
    canonical_hash = "b" * 64
    submission = {"payload": {entrypoint_alias: canonical_hash}}
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": canonical_hash},
        submit_result=submission,
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
        )

    assert excinfo.value.code == "invalid_transaction_hash"
    assert torii.waited == []


def test_nexus_app_ignores_signed_wire_only_submission_hash_and_uses_local_hash():
    canonical_hash = "b" * 64
    signed_wire_hash = "d" * 64
    submission = {"payload": {"signed_transaction_hash": signed_wire_hash}}
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": canonical_hash},
        submit_result=submission,
    )

    receipt = client.finalize_and_submit(
        draft.signable,
        NexusWalletSignature(FIXTURE_SIGNATURE),
    )

    assert receipt.submission is submission
    assert receipt.signed_transaction_hash_hex == canonical_hash
    assert torii.waited == [canonical_hash]


def test_nexus_app_rejects_noncanonical_signed_wire_receipt_hash():
    canonical_hash = "b" * 64
    submission = {"payload": {"signed_transaction_hash": "c" * 64}}
    client, draft, torii = _client_for_finalized_result(
        {"signed_transaction": b"signed", "hash_hex": canonical_hash},
        submit_result=submission,
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
        )

    assert excinfo.value.code == "invalid_transaction_hash"
    assert torii.waited == []


def test_nexus_app_rejects_conflicting_custom_finalizer_hash_aliases():
    client, draft, torii = _client_for_finalized_result(
        {
            "signed_transaction": b"signed",
            "hash_hex": "c" * 64,
            "hashHex": "d" * 64,
        }
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(
            draft.signable,
            NexusWalletSignature(FIXTURE_SIGNATURE),
            wait=False,
        )

    assert excinfo.value.code == "invalid_transaction_hash"
    assert torii.submitted == []


def test_nexus_app_rejects_missing_approval_fields():
    missing_account = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(bytes([7]) * 64, approval={}),
        transaction_codec=FakeCodec(b"payload", b"signed", "a" * 64),
    )

    with pytest.raises(NexusAppError) as account_exc:
        missing_account.await_approval(_nexus_connect_session())
    assert account_exc.value.code == "approval_missing_account"

    missing_key = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(bytes([7]) * 64, approval={"account_id": "not-an-i105-account"}),
        transaction_codec=FakeCodec(b"payload", b"signed", "a" * 64),
    )

    with pytest.raises(NexusAppError) as key_exc:
        missing_key.await_approval(_nexus_connect_session())
    assert key_exc.value.code == "invalid_account_id"


def test_nexus_app_rejects_authority_mismatch_before_wallet_signature():
    connect = FakeConnect(bytes([7]) * 64)
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        connect_transport=connect,
        transaction_codec=FakeCodec(b"payload", b"signed", "a" * 64),
        torii_client=FakeTorii(),
    )
    session = _nexus_connect_session(
        approved_account=FIXTURE_ACCOUNT_ID,
        signing_public_key=FIXTURE_PUBLIC_KEY,
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.transfer_with_wallet(
            session,
            NexusTransferInput(
                source_asset_id=f"asset#{FIXTURE_DESTINATION_ACCOUNT_ID}",
                quantity=1,
                destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
                fee_payment=FEE_PAYMENT,
                authority=FIXTURE_DESTINATION_ACCOUNT_ID,
            ),
        )

    assert excinfo.value.code == "approval_account_mismatch"
    assert connect.requested_payloads == []


def test_nexus_app_rejects_invalid_signature_length():
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(
            FIXTURE_PAYLOAD,
            b"signed",
            "c" * 64,
            expected_authority=FIXTURE_ACCOUNT_ID,
            expected_signature=FIXTURE_SIGNATURE,
            expected_signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        torii_client=FakeTorii(),
    )
    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )

    with pytest.raises(NexusAppError) as excinfo:
        client.finalize_and_submit(draft.signable, bytes([0]) * 63, wait=False)

    assert excinfo.value.code == "invalid_signature"

    with pytest.raises(NexusAppError) as bad_signature:
        client.finalize_and_submit(draft.signable, bytes([7]) * 64, wait=False)

    assert bad_signature.value.code == "invalid_signature"


def test_nexus_app_rejects_torii_hash_mismatch_and_maps_failures():
    hash_hex = "d" * 64
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(
            FIXTURE_PAYLOAD,
            b"signed",
            hash_hex,
            expected_authority=FIXTURE_ACCOUNT_ID,
            expected_signature=FIXTURE_SIGNATURE,
            expected_signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        torii_client=FakeTorii(submit_hash_hex="f" * 64),
    )
    draft = client.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )

    with pytest.raises(NexusAppError) as mismatch_exc:
        client.finalize_and_submit(draft.signable, NexusWalletSignature(FIXTURE_SIGNATURE), wait=False)
    assert mismatch_exc.value.code == "transaction_hash_mismatch"

    submit_failure = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(
            FIXTURE_PAYLOAD,
            b"signed",
            hash_hex,
            expected_authority=FIXTURE_ACCOUNT_ID,
            expected_signature=FIXTURE_SIGNATURE,
            expected_signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        torii_client=FakeTorii(submit_error=RuntimeError("down")),
    )
    draft = submit_failure.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )
    with pytest.raises(NexusAppError) as submit_exc:
        submit_failure.finalize_and_submit(draft.signable, NexusWalletSignature(FIXTURE_SIGNATURE), wait=False)
    assert submit_exc.value.code == "submit_failed"

    status_failure = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
            authority=FIXTURE_ACCOUNT_ID,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        transaction_codec=FakeCodec(
            FIXTURE_PAYLOAD,
            b"signed",
            hash_hex,
            expected_authority=FIXTURE_ACCOUNT_ID,
            expected_signature=FIXTURE_SIGNATURE,
            expected_signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
        torii_client=FakeTorii(submit_hash_hex=hash_hex, wait_error=RuntimeError("timeout")),
    )
    draft = status_failure.build_transfer_draft(
        NexusTransferInput(
            source_asset_id=f"asset#{FIXTURE_ACCOUNT_ID}",
            quantity=1,
            destination_account_id=FIXTURE_DESTINATION_ACCOUNT_ID,
            fee_payment=FEE_PAYMENT,
        )
    )
    with pytest.raises(NexusAppError) as status_exc:
        status_failure.finalize_and_submit(draft.signable, NexusWalletSignature(FIXTURE_SIGNATURE))
    assert status_exc.value.code == "status_wait_failed"


def test_nexus_app_fixture_error_codes_are_stable():
    expected_codes = {case["name"]: case["expected_code"] for case in FIXTURE["error_cases"]}
    assert expected_codes["unsupported signature algorithm"] == "unsupported_signature_algorithm"
    assert expected_codes["approval without signing key"] == "missing_signing_public_key"
    assert expected_codes["authority mismatch"] == "approval_account_mismatch"
    assert expected_codes["approval signing key mismatch"] == "approval_account_mismatch"
    assert expected_codes["approval session substitution"] == "approval_session_mismatch"


def test_nexus_app_multisig_approval_requires_a_supported_signing_controller():
    account = AccountAddress.from_multisig_policy(
        threshold=1,
        members=(MultisigMember(CurveId.ED25519, FIXTURE_PUBLIC_KEY, 1),),
    ).to_i105(FIXTURE_CHAIN_DISCRIMINANT)
    client = NexusAppClient(
        NexusAppConfig(
            network_id=NETWORK_ID,
            account_chain_discriminant=FIXTURE_CHAIN_DISCRIMINANT,
        ),
        connect_transport=FakeConnect(
            FIXTURE_SIGNATURE,
            account_id=account,
            signing_public_key=FIXTURE_PUBLIC_KEY,
        ),
    )
    with pytest.raises(NexusAppError) as failure:
        client.await_approval(_nexus_connect_session())
    assert failure.value.code == "missing_signing_public_key"
