from __future__ import annotations

import base64
import json
from urllib.parse import urlsplit

import pytest
import requests

from iroha_python import (
    F,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    canonical_network_request_signature_message,
)

from .helpers import RecordingSession, StubResponse

_CANONICAL_ACCOUNT_ID = (
    "sorauﾛ1PｺfMﾇﾘｾﾄoﾂﾊﾔH7ZdﾘhﾚmAｸdnｳu1ｱﾄ1ｺﾋuSﾑﾀﾇﾐuHEB5DP"
)
_CANONICAL_NETWORK_ID = (
    "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"
)


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
            }
        )
        if not self.responses:
            raise AssertionError(f"unexpected request {method} {url}")
        response = self.responses.pop(0)
        response.url = url
        return response


def response(status: int, payload: object) -> requests.Response:
    result = requests.Response()
    result.status_code = status
    result._content = json.dumps(payload).encode("utf-8")
    result._content_consumed = True
    result.headers["Content-Type"] = "application/json"
    return result


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
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises((TypeError, ValueError)):
        client.asset_balance("adult@is", "ds#wonderland.is")


def test_explorer_rwa_list_uses_strict_cursor_contract() -> None:
    cursor = base64.urlsafe_b64encode(b"canonical explorer cursor").rstrip(b"=").decode()
    payload = {
        "next_cursor": cursor,
        "items": [
            {
                "id": "lot-001$commodities",
                "owned_by": "account",
                "quantity": "10",
                "held_quantity": "2",
                "primary_reference": "warehouse-1",
                "status": None,
                "is_frozen": False,
                "metadata": {},
            }
        ],
    }
    session = FakeSession([response(200, payload)])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    page = client.explorer_rwas.list(
        cursor=cursor,
        limit=2,
        filter=(F.owned_by == "account") & (F.domain == "commodities"),
    )

    assert page.next_cursor == cursor
    assert page.has_more
    assert [item.id for item in page.items] == ["lot-001$commodities"]
    assert json.loads(session.calls[0]["data"]) == {
        "cursor": cursor,
        "limit": 2,
        "filter": {"op": "and", "args": [
            {"op": "eq", "args": ["owned_by", "account"]},
            {"op": "eq", "args": ["domain", "commodities"]},
        ]},
    }
    assert not any(
        str(name).lower().startswith("x-iroha-")
        for name in session.calls[0]["headers"]
    )


def test_explorer_rwa_list_optionally_signs_exact_final_uri() -> None:
    cursor = base64.urlsafe_b64encode(b"signed explorer cursor").rstrip(b"=").decode()
    payload = {
        "next_cursor": None,
        "items": [],
    }
    session = RecordingSession(StubResponse(payload=payload))
    captured: list[bytes] = []
    auth = ToriiCanonicalRequestAuth(
        network_id=_CANONICAL_NETWORK_ID,
        account_id=_CANONICAL_ACCOUNT_ID,
        signer=lambda message: captured.append(message) or b"\x5a" * 64,
        timestamp_ms=4_102_444_801_000,
        nonce="python-explorer-final-uri",
    )
    client = ToriiClient(
        "https://torii.example",
        session=session,
        canonical_request_auth=auth,
        max_retries=3,
        chain_discriminant=753,
    )

    page = client.explorer_rwas.list(
        cursor=cursor,
        limit=2,
        filter=F.domain == "commodities",
    )

    assert page.items == ()
    call = session.calls[0]
    prepared_url = str(call["url"])
    prepared = urlsplit(prepared_url)
    exact_target = prepared.path + (f"?{prepared.query}" if prepared.query else "")
    assert prepared.query == ""
    assert prepared.path == "/v1/explorer/rwas/query"
    assert captured == [
        canonical_network_request_signature_message(
            auth.network_id,
            "POST",
            exact_target,
            call["data"],
            timestamp_ms=auth.timestamp_ms or 0,
            nonce=auth.nonce or "",
        )
    ]
    assert "X-Iroha-Account" in call["headers"]
    assert "X-Iroha-Signature" in call["headers"]


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_explorer_rwa_list_rejects_invalid_limit_before_dispatch(limit: object) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises((TypeError, ValueError)):
        client.explorer_rwas.list(limit=limit)  # type: ignore[arg-type]
    assert session.calls == []


@pytest.mark.parametrize("cursor", ["", "a" * 4097])
def test_explorer_rwa_list_rejects_invalid_cursor_before_dispatch(cursor: str) -> None:
    session = FakeSession([])
    client = ToriiClient("http://torii.example", session=session, max_retries=0, chain_discriminant=753)

    with pytest.raises(ValueError, match="cursor"):
        client.explorer_rwas.list(cursor=cursor)
    assert session.calls == []


@pytest.mark.parametrize("payload", [
    {"items": [], "pagination": {"limit": 25, "next_cursor": None, "has_more": False}},
    {"items": [], "next_cursor": None, "total": 0},
    {"items": [], "next_cursor": None, "sampled_at": "today"},
    {"items": []},
    {"items": [{}, {}], "next_cursor": None},
])
def test_explorer_collection_response_rejects_retired_or_inconsistent_fields(payload: dict) -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([response(200, payload)]), max_retries=0, chain_discriminant=753)
    with pytest.raises(ValueError, match="malformed page"):
        client.explorer_rwas.list(limit=1)


def test_explorer_rwa_list_hard_cuts_retired_page_arguments() -> None:
    client = ToriiClient("http://torii.example", session=FakeSession([]), max_retries=0, chain_discriminant=753)

    with pytest.raises(TypeError, match="unexpected keyword argument"):
        client.explorer_rwas.list(page=1, per_page=25)  # type: ignore[call-arg]
