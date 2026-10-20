"""Fail-closed Python SDK tests for the native ZK-X509 action transport."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import iroha_python
import iroha_python.client as client_module
import iroha_python.crypto as crypto_module
from iroha_python import (
    AccountAddress,
    Ed25519KeyPair,
    NetworkId,
    SorafsAliasPolicy,
    ToriiCanonicalRequestAuth,
    TransactionConfig,
    TransactionDraft,
)
from iroha_python.client import LocalSigningContext, ToriiClient

X509_PROTOCOL = "iroha-zk-x509-stark-p256-v1"
SIGNED_X509_WIRE = b"canonical-signed-x509-wire"
SIGNED_OTHER_WIRE = b"canonical-signed-other-protocol-wire"
CANONICAL_GENESIS_HASH = bytes([0xA5]) * 32
NETWORK_ID = NetworkId.from_bytes(CANONICAL_GENESIS_HASH)
FOREIGN_NETWORK_ID = NetworkId.from_bytes(bytes([0xA7]) * 32)
CANONICAL_AUTH_PUBLIC_KEY = Ed25519KeyPair.from_private_key(bytes([0x11]) * 32).public_key
CANONICAL_AUTH = ToriiCanonicalRequestAuth(
    network_id=NETWORK_ID.literal,
    account_id=AccountAddress.from_account(public_key=CANONICAL_AUTH_PUBLIC_KEY).to_i105(0x02F1),
    signer=lambda _message: bytes([0x44]) * 64,
    timestamp_ms=4_102_444_801_000,
    nonce="privacy-capability-test",
)
class _FakeCrypto:
    PRIVACY_EXACT12_CAPABILITY_MANIFEST_ARCHIVE_MAX_BYTES_V1 = 256 * 1024
    NetworkId = NetworkId

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.envelope = SimpleNamespace(
            signed_transaction_versioned=SIGNED_X509_WIRE,
            hash=bytes([7]) * 32,
        )

    def privacy_exact12_capability_manifest_v1(
        self,
        archive: object,
    ) -> "_FakeManifest":
        self.events.append("decode-capabilities")
        if archive != b"canonical-exact12-manifest":
            raise ValueError("wrong manifest bytes")
        return _FakeManifest()

    def _fetch_privacy_exact12_capability_manifest_v1(
        self, client: ToriiClient, canonical_auth: ToriiCanonicalRequestAuth
    ) -> "_FakeManifest":
        # Transport control-flow test double; cryptographic acceptance is covered by Rust tests.
        archive = client_module._fetch_authenticated_privacy_capabilities_archive_v1(
            client, canonical_auth
        )
        return self.privacy_exact12_capability_manifest_v1(archive)

    def inspect_signed_privacy_zk_x509_identity_presentation_action_v1(
        self,
        wire: object,
        network_id: object,
    ) -> dict[str, object]:
        self.events.append("inspect")
        if wire != SIGNED_X509_WIRE:
            raise ValueError("wrong privacy protocol")
        if network_id != NETWORK_ID:
            raise ValueError("wrong NetworkId")
        return {"protocol_id": X509_PROTOCOL}

    def signed_transaction_envelope_from_versioned_v1(
        self,
        wire: object,
        network_id: object,
        *,
        chain_discriminant: int,
    ) -> SimpleNamespace:
        assert chain_discriminant == 753
        self.events.append("reconstruct")
        assert wire == SIGNED_X509_WIRE
        assert network_id == NETWORK_ID
        return self.envelope


class _FakeManifest:
    def __init__(self, error: str | None = None) -> None:
        self.error = error

    def require_network_capability(self, protocol_id: str) -> dict[str, object]:
        if self.error is not None:
            raise RuntimeError(self.error)
        if protocol_id != X509_PROTOCOL:
            raise RuntimeError("wrong selected protocol")
        return {
            "protocol_id": X509_PROTOCOL,
            "operation_schema": "zk_x509_identity_presentation_v1",
            "execution_mode": "presentation_action",
            "privacy_feature_mask": 2,
            "readiness": "available",
            "activation_state": "active",
            "network_available": True,
        }


def _client_with_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[ToriiClient, _FakeCrypto, list[str]]:
    events: list[str] = []
    fake_crypto = _FakeCrypto(events)
    monkeypatch.setattr(client_module, "_CRYPTO_MODULE", fake_crypto)
    alias_policy = SorafsAliasPolicy(
        positive_ttl_secs=1,
        refresh_window_secs=1,
        hard_expiry_secs=1,
        negative_ttl_secs=1,
        revocation_ttl_secs=1,
        rotation_max_age_secs=1,
        successor_grace_secs=0,
        governance_grace_secs=0,
    )
    return (
        ToriiClient(
            "https://torii.invalid",
            sorafs_alias_policy=alias_policy,
            local_signing_context=LocalSigningContext(NETWORK_ID),
            chain_discriminant=753,
        ),
        fake_crypto,
        events,
    )


def test_privacy_capabilities_fetches_and_preserves_exact_norito_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    response = SimpleNamespace(
        status_code=200,
        headers={"Content-Type": "application/x-norito"},
        content=b"canonical-exact12-manifest",
        text="",
        url="https://torii.invalid/v1/privacy/capabilities",
        history=[],
        close=lambda: None,
        iter_content=lambda **_kwargs: [b"canonical-exact12-manifest"],
    )
    requests: list[tuple[str, str, object, object, object]] = []

    def request(method: str, path: str, **kwargs: object) -> object:
        requests.append(
            (
                method,
                path,
                kwargs.get("headers"),
                kwargs.get("allow_retry"),
                kwargs.get("allow_redirects"),
            )
        )
        return response

    monkeypatch.setattr(client, "_request", request)
    manifest = client.privacy_capabilities_v1(canonical_auth=CANONICAL_AUTH)

    assert isinstance(manifest, _FakeManifest)
    assert requests[0][:2] == ("GET", "/v1/privacy/capabilities")
    header_plan = requests[0][2]
    assert header_plan["Accept"] == "application/x-norito"
    assert header_plan["Accept-Encoding"] == "identity"
    assert header_plan["Cache-Control"] == "no-store"
    assert header_plan.canonical_auth is CANONICAL_AUTH
    assert "X-Iroha-Account" not in header_plan
    assert requests[0][3:] == (False, False)
    assert events == ["decode-capabilities"]


def test_privacy_capabilities_rejects_json_and_never_invokes_native_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    response = SimpleNamespace(
        status_code=200,
        headers={"Content-Type": "application/json"},
        content=b"{}",
        text="",
        url="https://torii.invalid/v1/privacy/capabilities",
        history=[],
        close=lambda: None,
    )
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: response)

    with pytest.raises(ValueError, match="application/x-norito"):
        client.privacy_capabilities_v1(canonical_auth=CANONICAL_AUTH)
    assert events == []


@pytest.mark.parametrize("change", ["origin", "redirect", "encoding", "empty", "oversized", "length", "media-parameters"])
def test_capability_fetch_rejects_response_provenance_and_body_drift(
    monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    body = b"canonical-exact12-manifest"
    headers = {"Content-Type": "application/x-norito"}
    url = "https://torii.invalid/v1/privacy/capabilities"
    history: list[object] = []
    if change == "origin":
        url = "https://other.invalid/v1/privacy/capabilities"
    elif change == "redirect":
        history = [object()]
    elif change == "encoding":
        headers["Content-Encoding"] = "gzip"
    elif change == "empty":
        body = b""
    elif change == "oversized":
        body = b"x" * (256 * 1024 + 1)
    elif change == "length":
        headers["Content-Length"] = str(len(body) + 1)
    elif change == "media-parameters":
        headers["Content-Type"] = "application/x-norito; charset=utf-8"
    closed: list[bool] = []
    response = SimpleNamespace(
        status_code=200, headers=headers, url=url, history=history,
        close=lambda: closed.append(True),
        iter_content=lambda **_kwargs: [body],
    )
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: response)
    with pytest.raises(ValueError):
        client.privacy_capabilities_v1(canonical_auth=CANONICAL_AUTH)
    assert closed
    assert events == []


def test_capability_fetch_rejects_wrong_network_and_http_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    monkeypatch.setattr(client, "_request", lambda *_args, **_kwargs: pytest.fail("must not dispatch"))
    auth = ToriiCanonicalRequestAuth(
        network_id=FOREIGN_NETWORK_ID.literal,
        account_id=CANONICAL_AUTH.account_id,
        signer=CANONICAL_AUTH.signer,
        timestamp_ms=CANONICAL_AUTH.timestamp_ms,
        nonce=CANONICAL_AUTH.nonce,
    )
    with pytest.raises(ValueError, match="different network"):
        client.privacy_capabilities_v1(canonical_auth=auth)
    client._base_url = "http://torii.invalid"
    with pytest.raises(ValueError, match="HTTPS"):
        client.privacy_capabilities_v1(canonical_auth=CANONICAL_AUTH)
    assert events == []


def test_capability_fetch_rejects_duck_typed_archive_owners() -> None:
    with pytest.raises(TypeError, match="configured SDK ToriiClient"):
        client_module._fetch_authenticated_privacy_capabilities_archive_v1(
            SimpleNamespace(canonical_archive=b"replayed"), CANONICAL_AUTH
        )


def test_crypto_x509_inspector_is_public_and_forwards_exact_network_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, object]] = []

    def inspect(wire: bytes, network_id: object) -> dict[str, object]:
        calls.append((wire, network_id))
        return {"protocol_id": X509_PROTOCOL}

    monkeypatch.setattr(
        crypto_module,
        "_crypto",
        SimpleNamespace(
            inspect_signed_privacy_zk_x509_identity_presentation_action_v1=inspect
        ),
    )
    result = crypto_module.inspect_signed_privacy_zk_x509_identity_presentation_action_v1(
        bytearray(SIGNED_X509_WIRE),
        NETWORK_ID,
    )

    assert result == {"protocol_id": X509_PROTOCOL}
    assert calls == [(SIGNED_X509_WIRE, NETWORK_ID)]
    assert (
        iroha_python.inspect_signed_privacy_zk_x509_identity_presentation_action_v1
        is crypto_module.inspect_signed_privacy_zk_x509_identity_presentation_action_v1
    )
    assert "inspect_signed_privacy_zk_x509_identity_presentation_action_v1" in (
        iroha_python.__all__
    )


def test_crypto_x509_inspector_rejects_bad_inputs_and_native_contract_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspect = crypto_module.inspect_signed_privacy_zk_x509_identity_presentation_action_v1
    with pytest.raises(TypeError, match="signed_transaction_versioned"):
        inspect("not-bytes", NETWORK_ID)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="network_id must be a NetworkId"):
        inspect(SIGNED_X509_WIRE, CANONICAL_GENESIS_HASH)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="network_id must be a NetworkId"):
        inspect(SIGNED_X509_WIRE, "chain/dev")  # type: ignore[arg-type]

    monkeypatch.setattr(crypto_module, "_crypto", SimpleNamespace())
    with pytest.raises(RuntimeError, match="rebuild the extension"):
        inspect(SIGNED_X509_WIRE, NETWORK_ID)

    monkeypatch.setattr(
        crypto_module,
        "_crypto",
        SimpleNamespace(
            inspect_signed_privacy_zk_x509_identity_presentation_action_v1=lambda *_: []
        ),
    )
    with pytest.raises(RuntimeError, match="invalid result"):
        inspect(SIGNED_X509_WIRE, NETWORK_ID)

    def reject(*_: object) -> None:
        raise RuntimeError("native detail must not escape")

    monkeypatch.setattr(
        crypto_module,
        "_crypto",
        SimpleNamespace(
            inspect_signed_privacy_zk_x509_identity_presentation_action_v1=reject
        ),
    )
    with pytest.raises(ValueError, match="invalid canonical signed ZK-X509"):
        inspect(SIGNED_X509_WIRE, NETWORK_ID)


def test_transaction_draft_delegates_exact_x509_prepare_and_sign_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    signed_result = object()

    class Builder:
        def prepare_privacy_zk_x509_identity_presentation_action_v1(
            self, statement: bytes
        ) -> bytes:
            calls.append(("prepare", statement))
            return bytes([9]) * 32

        def sign_privacy_zk_x509_identity_presentation_action_v1(
            self,
            private_key: bytes,
            statement: bytes,
            proof: bytes,
        ) -> object:
            calls.append(("sign", private_key, statement, proof))
            return signed_result

    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority="ed0120" + "11" * 32,
            fee_payment={
                "payer": "authority",
                "value": {"charge_limits": [], "gas_limit": 1000},
            },
            creation_time_ms=42,
            chain_discriminant=753,
        )
    )
    monkeypatch.setattr(draft, "to_builder", lambda: Builder())

    statement = b"canonical-typed-statement"
    proof = b"X5S1-proof"
    assert draft.prepare_privacy_zk_x509_identity_presentation_action_v1(
        canonical_statement_archive=statement
    ) == bytes([9]) * 32
    assert (
        draft.sign_privacy_zk_x509_identity_presentation_action_v1(
            b"private-key",
            canonical_statement_archive=statement,
            credential_proof=proof,
        )
        is signed_result
    )
    assert calls == [
        ("prepare", statement),
        ("sign", b"private-key", statement, proof),
    ]


def test_transaction_draft_rejects_x509_action_mixing_before_native_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    draft = TransactionDraft(
        TransactionConfig(
            network_id=NETWORK_ID,
            authority="ed0120" + "11" * 32,
            fee_payment={
                "payer": "authority",
                "value": {"charge_limits": [], "gas_limit": 1000},
            },
            creation_time_ms=42,
            chain_discriminant=753,
        )
    )
    draft.add_instruction(object())  # type: ignore[arg-type]
    monkeypatch.setattr(
        draft,
        "to_builder",
        lambda: pytest.fail("mixed X509 draft reached native builder"),
    )

    with pytest.raises(ValueError, match="otherwise empty"):
        draft.prepare_privacy_zk_x509_identity_presentation_action_v1(
            canonical_statement_archive=b"statement"
        )
    with pytest.raises(ValueError, match="otherwise empty"):
        draft.sign_privacy_zk_x509_identity_presentation_action_v1(
            b"private-key",
            canonical_statement_archive=b"statement",
            credential_proof=b"proof",
        )


def test_x509_transport_authenticates_live_gates_and_submits_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, fake_crypto, events = _client_with_crypto(monkeypatch)
    capability_calls = 0

    def capabilities(*, canonical_auth: object) -> _FakeManifest:
        assert canonical_auth is CANONICAL_AUTH
        nonlocal capability_calls
        capability_calls += 1
        events.append("capabilities")
        return _FakeManifest()

    submissions: list[object] = []

    def submit(envelope: object) -> dict[str, str]:
        events.append("submit")
        submissions.append(envelope)
        return {"status": "queued"}

    monkeypatch.setattr(client, "privacy_capabilities_v1", capabilities)
    monkeypatch.setattr(client, "submit_transaction_envelope", submit)

    envelope, result = (
        client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
            SIGNED_X509_WIRE,
            canonical_auth=CANONICAL_AUTH,
            network_id=NETWORK_ID,
            wait=False,
        )
    )

    assert envelope is fake_crypto.envelope
    assert result == {"status": "queued"}
    assert submissions == [fake_crypto.envelope]
    assert capability_calls == 1
    assert events == ["inspect", "capabilities", "reconstruct", "submit"]


def test_x509_transport_wait_path_submits_through_wait_helper_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, fake_crypto, events = _client_with_crypto(monkeypatch)

    def capabilities(*, canonical_auth: object) -> _FakeManifest:
        assert canonical_auth is CANONICAL_AUTH
        events.append("capabilities")
        return _FakeManifest()

    waits: list[tuple[object, dict[str, object]]] = []

    def submit_and_wait(envelope: object, **kwargs: object) -> dict[str, str]:
        events.append("wait")
        waits.append((envelope, kwargs))
        return {"status": "Committed"}

    monkeypatch.setattr(client, "privacy_capabilities_v1", capabilities)
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope",
        lambda _: pytest.fail("wait path performed a separate direct submission"),
    )
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope_and_wait",
        submit_and_wait,
    )

    envelope, result = (
        client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
            SIGNED_X509_WIRE,
            canonical_auth=CANONICAL_AUTH,
            network_id=NETWORK_ID,
            interval=0.25,
            timeout=5.0,
            max_attempts=3,
        )
    )

    assert envelope is fake_crypto.envelope
    assert result == {"status": "Committed"}
    assert len(waits) == 1
    assert waits[0][0] is fake_crypto.envelope
    assert waits[0][1]["interval"] == 0.25
    assert waits[0][1]["timeout"] == 5.0
    assert waits[0][1]["max_attempts"] == 3
    assert "scope" not in waits[0][1]
    assert "success_statuses" not in waits[0][1]
    assert events == ["inspect", "capabilities", "reconstruct", "wait"]


def test_x509_transport_rejects_raw_aliases_and_foreign_network_before_inspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    monkeypatch.setattr(
        client,
        "privacy_capabilities_v1",
        lambda **_kwargs: pytest.fail("invalid network reached capability fetch"),
    )
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope",
        lambda _: pytest.fail("invalid network was submitted"),
    )

    for retired in (CANONICAL_GENESIS_HASH, "chain/dev", "genesis"):
        with pytest.raises(TypeError, match="network_id must be a NetworkId"):
            client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
                SIGNED_X509_WIRE,
                canonical_auth=CANONICAL_AUTH,
                network_id=retired,  # type: ignore[arg-type]
                wait=False,
            )
    with pytest.raises(ValueError, match="does not match"):
        client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
            SIGNED_X509_WIRE,
            canonical_auth=CANONICAL_AUTH,
            network_id=FOREIGN_NETWORK_ID,
            wait=False,
        )
    assert events == []


def test_x509_transport_rejects_wrong_protocol_before_capability_fetch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    monkeypatch.setattr(
        client,
        "privacy_capabilities_v1",
        lambda **_kwargs: pytest.fail("wrong protocol reached capability fetch"),
    )
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope",
        lambda _: pytest.fail("wrong protocol was submitted"),
    )

    with pytest.raises(ValueError, match="wrong privacy protocol"):
        client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
            SIGNED_OTHER_WIRE,
            canonical_auth=CANONICAL_AUTH,
            network_id=NETWORK_ID,
            wait=False,
        )
    assert events == ["inspect"]


@pytest.mark.parametrize(
    "message",
    (
        "manifest row ordering mismatch",
        "compiled profile tuple mismatch",
        "activation projection mismatch",
    ),
    ids=("duplicate-row", "compiled-binding", "activation-binding"),
)
def test_x509_transport_rejects_malformed_capability_bindings_before_submission(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    monkeypatch.setattr(
        client,
        "privacy_capabilities_v1",
        lambda **_kwargs: _FakeManifest(message),
    )
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope",
        lambda _: pytest.fail("malformed capability row permitted submission"),
    )

    with pytest.raises(RuntimeError, match=message):
        client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
            SIGNED_X509_WIRE,
            canonical_auth=CANONICAL_AUTH,
            network_id=NETWORK_ID,
            wait=False,
        )
    assert events == ["inspect"]


@pytest.mark.parametrize(
    "message",
    (
        "compiled profile unavailable",
        "no governed activation",
        "not active: proposed",
        "not active: suspended",
        "not active: retired",
    ),
    ids=("unavailable", "no-activation", "proposed", "suspended", "retired"),
)
def test_x509_transport_fails_closed_for_unavailable_or_inactive_capability(
    monkeypatch: pytest.MonkeyPatch,
    message: str,
) -> None:
    client, _, events = _client_with_crypto(monkeypatch)
    monkeypatch.setattr(
        client,
        "privacy_capabilities_v1",
        lambda **_kwargs: _FakeManifest(message),
    )
    monkeypatch.setattr(
        client,
        "submit_transaction_envelope",
        lambda _: pytest.fail("inactive X509 protocol was submitted"),
    )

    with pytest.raises(RuntimeError, match=message):
        client.submit_signed_privacy_zk_x509_identity_presentation_action_v1(
            SIGNED_X509_WIRE,
            canonical_auth=CANONICAL_AUTH,
            network_id=NETWORK_ID,
            wait=False,
        )
    assert events == ["inspect"]
