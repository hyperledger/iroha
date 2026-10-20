"""Optional exact-network authentication for collection queries.

Collection routes are public: a canonical account signature only widens
visibility into restricted dataspaces, so the SDK signs when credentials are
configured and never requires them.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlsplit

import pytest
import requests

from iroha_python import ToriiUnavailableError
from iroha_python.address import AccountAddress
from iroha_python.client import (
    LocalSigningContext,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
)
from iroha_python.crypto import Ed25519KeyPair, NetworkId

NETWORK_ID = NetworkId.from_bytes(bytes([0xA5]) * 32)
ACCOUNT_PUBLIC_KEY = Ed25519KeyPair.from_private_key(bytes([0x31]) * 32).public_key
ACCOUNT_ID = AccountAddress.from_account(
    public_key=ACCOUNT_PUBLIC_KEY,
).to_i105(0x02F1)
ACCOUNT_HEADER = AccountAddress.parse_encoded(
    ACCOUNT_ID, expected_discriminant=0x02F1
).canonical_hex()
_SIGNED_HEADERS = ("X-Iroha-Account", "X-Iroha-Signature", "X-Iroha-Timestamp-Ms", "X-Iroha-Nonce")


def _response(status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps({"items": [], "next_cursor": None}).encode()
    response._content_consumed = True
    response.encoding = "utf-8"
    return response


class _Session(requests.Session):
    def __init__(self, statuses: list[int]) -> None:
        super().__init__()
        self.responses = [_response(status) for status in statuses]
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.calls.append(
            {
                "method": method,
                "path": urlsplit(url).path,
                "headers": dict(kwargs.get("headers") or {}),
                "data": kwargs.get("data"),
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        return self._next(method, url)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        url = request.url or ""
        self.calls.append(
            {
                "method": request.method,
                "path": urlsplit(url).path,
                "headers": dict(request.headers),
                "data": request.body,
                "allow_redirects": kwargs.get("allow_redirects"),
            }
        )
        return self._next(request.method, url)

    def _next(self, method: Any, url: str) -> requests.Response:
        if not self.responses:
            raise AssertionError(f"unexpected request {method} {url}")
        response = self.responses.pop(0)
        response.url = url
        return response


def _signed_client(
    session: _Session,
    captured: list[bytes] | None = None,
    *,
    api_token: str | None = None,
) -> ToriiClient:
    """A client with exact-network canonical credentials (shared by other read tests)."""

    def signer(message: bytes) -> bytes:
        if captured is not None:
            captured.append(message)
        return bytes([0x44]) * 64

    return ToriiClient(
        "https://torii.example",
        session=session,
        max_retries=4,
        api_token=api_token,
        local_signing_context=LocalSigningContext(NETWORK_ID),
        canonical_request_auth=ToriiCanonicalRequestAuth(
            network_id=NETWORK_ID.literal,
            account_id=ACCOUNT_ID,
            signer=signer,
            timestamp_ms=4_102_444_801_000,
            nonce="python-collection-query-auth",
        ),
        chain_discriminant=753,
    )


def _query_every_collection(client: ToriiClient) -> None:
    client.accounts.transactions(ACCOUNT_ID).list(limit=1)
    client.accounts.assets(ACCOUNT_ID).list(limit=1)
    client.domains.list(limit=1)
    client.accounts.list(limit=1)
    client.repo_agreements.list(limit=1)
    client.asset_definitions.holders("rose#wonderland").list(limit=1)
    client.asset_definitions.list(limit=1)
    client.rwas.list(limit=1)
    client.nfts.list(limit=1)
    client.transactions.list(limit=1)


_EXPECTED_PATHS = [
    f"/v1/accounts/{quote(ACCOUNT_ID, safe='')}/transactions/query",
    f"/v1/accounts/{quote(ACCOUNT_ID, safe='')}/assets/query",
    "/v1/domains/query",
    "/v1/accounts/query",
    "/v1/repo/agreements/query",
    "/v1/assets/rose%23wonderland/holders/query",
    "/v1/assets/definitions/query",
    "/v1/rwas/query",
    "/v1/nfts/query",
    "/v1/transactions/query",
]


def test_configured_credentials_sign_the_exact_one_shot_target_of_every_query() -> None:
    session = _Session([200] * len(_EXPECTED_PATHS))
    captured: list[bytes] = []

    _query_every_collection(_signed_client(session, captured))

    assert [call["path"] for call in session.calls] == _EXPECTED_PATHS
    assert len(captured) == len(session.calls)
    for call, message in zip(session.calls, captured, strict=True):
        assert call["method"] == "POST"
        assert call["allow_redirects"] is False
        assert call["headers"]["X-Iroha-Account"] == ACCOUNT_HEADER
        assert message == canonical_network_request_signature_message(
            NETWORK_ID.literal,
            "POST",
            call["path"],
            call["data"],
            timestamp_ms=4_102_444_801_000,
            nonce="python-collection-query-auth",
        )
    assert captured[0] != captured[1], "the substituted account route must be signed"


def test_queries_never_require_credentials() -> None:
    session = _Session([200] * len(_EXPECTED_PATHS))
    client = ToriiClient("https://torii.example", session=session, max_retries=0, chain_discriminant=753)

    _query_every_collection(client)

    assert [call["path"] for call in session.calls] == _EXPECTED_PATHS
    for call in session.calls:
        assert call["method"] == "POST"
        assert call["allow_redirects"] is False
        assert not any(header in call["headers"] for header in _SIGNED_HEADERS)


def test_inline_secrets_and_precomputed_signatures_are_rejected_before_dispatch() -> None:
    session = _Session([])
    client = ToriiClient("https://torii.example", session=session, chain_discriminant=753)
    with pytest.raises(TypeError, match="private_key"):
        client.accounts.list(limit=1, private_key="inline-secret")  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="canonical authentication headers"):
        ToriiClient(
            "https://torii.example",
            session=_Session([]),
            default_headers={"X-Iroha-Signature": "precomputed"},
            chain_discriminant=753,
        )
    assert session.calls == []


@pytest.mark.parametrize("signed", [True, False])
def test_query_dispatch_is_not_retried_after_a_503(signed: bool) -> None:
    session = _Session([503])
    client = (
        _signed_client(session)
        if signed
        else ToriiClient("https://torii.example", session=session, max_retries=4, chain_discriminant=753)
    )
    with pytest.raises(ToriiUnavailableError, match="unexpected status 503"):
        client.accounts.list(limit=1)
    assert len(session.calls) == 1
