from __future__ import annotations

from types import SimpleNamespace

import pytest

from iroha_python import SorafsPinRegisterResponse, ToriiClient

from .helpers import RecordingSession, StubResponse


def test_pin_register_posts_only_versioned_signed_transaction() -> None:
    signed_transaction = b"\x01signed-pin-transaction"
    response = {
        "status": "submitted",
        "tx_hash_hex": "b" * 64,
        "manifest_digest_hex": "b" * 64,
    }
    session = RecordingSession(StubResponse(202, response))
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    admission = client.register_sorafs_pin_manifest(
        SimpleNamespace(signed_transaction_versioned=signed_transaction)
    )

    assert admission == SorafsPinRegisterResponse(**response)
    assert len(session.calls) == 1
    call = session.calls[0]
    assert str(call["url"]).endswith("/v1/sorafs/pin/register")
    assert call["data"] == signed_transaction
    assert call["headers"] == {
        "Content-Type": "application/x-norito",
        "Accept": "application/json",
    }


def test_pin_register_rejects_pre_finality_fee_claim() -> None:
    response = {
        "status": "submitted",
        "tx_hash_hex": "b" * 64,
        "manifest_digest_hex": "b" * 64,
        "pin_fee": "1",
    }
    client = ToriiClient(
        "http://torii.example",
        session=RecordingSession(StubResponse(202, response)),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(TypeError, match="must contain only"):
        client.register_sorafs_pin_manifest(
            SimpleNamespace(signed_transaction_versioned=b"\x01signed")
        )


def test_pin_register_rejects_transaction_hash_without_iroha_marker() -> None:
    response = {
        "status": "submitted",
        "tx_hash_hex": "a" * 64,
        "manifest_digest_hex": "b" * 64,
    }
    client = ToriiClient(
        "http://torii.example",
        session=RecordingSession(StubResponse(202, response)),
        max_retries=0,
        chain_discriminant=753,
    )

    with pytest.raises(ValueError, match="must match .*canonical Iroha HashOf marker"):
        client.register_sorafs_pin_manifest(
            SimpleNamespace(signed_transaction_versioned=b"\x01signed")
        )


def test_generic_signed_transaction_submission_remains_available() -> None:
    signed_transaction = b"\x01signed-transaction"
    session = RecordingSession(StubResponse(202, None))
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)
    client._ensure_data_model_validation = lambda: None  # type: ignore[method-assign]

    client.submit_transaction(signed_transaction)

    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "POST"
    assert str(call["url"]).endswith("/v1/pipeline/transactions")
    assert call["data"] == signed_transaction
    assert call["headers"]["Content-Type"] == "application/x-norito"
