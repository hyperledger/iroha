"""Collection API tests for the lightweight client with a recording transport."""

from __future__ import annotations

import json
import pickle
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any, List, Optional
from urllib.parse import quote, urlsplit

import pytest
import requests

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from client_test_support import CANONICAL_OWNER  # noqa: E402
from iroha_torii_client import (  # noqa: E402  (import depends on sys.path mutation)
    Account,
    AccountAsset,
    AggregateMetric,
    AggregateSpec,
    AssetDefinition,
    AssetHolder,
    CommittedTransaction,
    F,
    HistoryCollection,
    ListQuery,
    ListQueryError,
    Nft,
    RwaLot,
    ToriiCanonicalRequestAuth,
    ToriiClient,
    ToriiError,
    ToriiNotFoundError,
    ToriiQueryError,
    ToriiRateLimitedError,
    ToriiServerError,
    ToriiUnavailableError,
    error_for_status,
)

NETWORK_ID = "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0"


def _response(
    status: int = 200,
    payload: Any = None,
    *,
    text: Optional[str] = None,
    content_type: str = "application/json",
    headers: Optional[dict] = None,
) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.headers["Content-Type"] = content_type
    response.headers.update(headers or {})
    body = text if text is not None else json.dumps(payload if payload is not None else {"items": [], "next_cursor": None})
    response._content = body.encode("utf-8")
    response._content_consumed = True
    response.encoding = "utf-8"
    return response


class _Session(requests.Session):
    def __init__(self, responses: List[requests.Response]) -> None:
        super().__init__()
        self.responses = responses
        self.calls: List[dict] = []

    def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        self.calls.append(
            {
                "method": method,
                "path": urlsplit(url).path,
                "headers": dict(kwargs.get("headers") or {}),
                "body": kwargs.get("data"),
                "timeout": kwargs.get("timeout"),
                "allow_redirects": kwargs.get("allow_redirects"),
                "stream": kwargs.get("stream"),
            }
        )
        return self._next(url)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        self.calls.append(
            {
                "method": request.method,
                "path": urlsplit(request.url or "").path,
                "headers": dict(request.headers),
                "body": request.body,
                "timeout": kwargs.get("timeout"),
                "allow_redirects": kwargs.get("allow_redirects"),
                "stream": kwargs.get("stream"),
            }
        )
        return self._next(request.url or "")

    def _next(self, url: str) -> requests.Response:
        if not self.responses:
            raise AssertionError(f"unexpected request to {url}")
        response = self.responses.pop(0)
        response.url = url
        return response


def _client(*responses: requests.Response, **options: Any) -> "tuple[ToriiClient, _Session]":
    session = _Session(list(responses))
    return ToriiClient("https://torii.example", session=session, **options), session


def _body(call: dict) -> Any:
    return json.loads(call["body"].decode("utf-8"))


def test_every_collection_posts_its_query_route() -> None:
    client, session = _client(*[_response() for _ in range(17)])

    client.domains.list()
    client.accounts.list()
    client.asset_definitions.list()
    client.nfts.list()
    client.rwas.list()
    client.repo_agreements.list()
    client.accounts.assets(CANONICAL_OWNER).list()
    client.accounts.transactions(CANONICAL_OWNER).list()
    client.asset_definitions.holders("62Fk4FPcMuLvW5QjDGNF2a4jAmjM").list()
    client.transactions.list()
    client.accounts.permissions(CANONICAL_OWNER).list()
    client.accounts.history(CANONICAL_OWNER).list()
    client.subscription_plans.list()
    client.subscriptions.list()
    client.contract_activity.list()
    client.contract_events.list()
    client.uaid_manifests("uaid:" + "01" * 32).list()

    owner = quote(CANONICAL_OWNER, safe="")
    assert [(call["method"], call["path"]) for call in session.calls] == [
        ("POST", "/v1/domains/query"),
        ("POST", "/v1/accounts/query"),
        ("POST", "/v1/assets/definitions/query"),
        ("POST", "/v1/nfts/query"),
        ("POST", "/v1/rwas/query"),
        ("POST", "/v1/repo/agreements/query"),
        ("POST", f"/v1/accounts/{owner}/assets/query"),
        ("POST", f"/v1/accounts/{owner}/transactions/query"),
        ("POST", "/v1/assets/62Fk4FPcMuLvW5QjDGNF2a4jAmjM/holders/query"),
        ("POST", "/v1/transactions/query"),
        ("POST", f"/v1/accounts/{owner}/permissions/query"),
        ("POST", f"/v1/accounts/{owner}/history/query"),
        ("POST", "/v1/subscriptions/plans/query"),
        ("POST", "/v1/subscriptions/query"),
        ("POST", "/v1/contracts/activity/query"),
        ("POST", "/v1/contracts/events/query"),
        ("POST", "/v1/space-directory/uaids/uaid%3A" + "01" * 32 + "/manifests/query"),
    ]
    for call in session.calls:
        assert _body(call) == {}
        assert call["headers"]["Content-Type"] == "application/json"
        assert call["headers"]["Accept"] == "application/json"
        assert call["allow_redirects"] is False
        assert call["timeout"] == 30.0
        assert not any(name.lower().startswith("x-iroha-") for name in call["headers"])


def test_list_sends_the_canonical_body_and_decodes_typed_rows() -> None:
    row = {
        "id": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
        "name": "rose",
        "alias": "rose#wonderland.universal",
        "owned_by": CANONICAL_OWNER,
        "owning_domain": "wonderland",
        "mintable": "Infinitely",
        "alias_binding": {"alias": "rose#wonderland.universal", "status": "active", "bound_at_ms": 5},
        "metadata": {"tier": 2},
        "description": "kept in raw",
    }
    client, session = _client(_response(payload={"items": [row], "next_cursor": "q1_next", "total": 9}))

    page = client.asset_definitions.list(
        filter=(F.owned_by == CANONICAL_OWNER) & F.metadata.tier.in_(1, 2),
        sort=[-F.alias_binding.bound_at_ms, "id"],
        limit=50,
        include_total=True,
    )

    assert _body(session.calls[0]) == {
        "filter": {
            "op": "and",
            "args": [
                {"op": "eq", "args": ["owned_by", CANONICAL_OWNER]},
                {"op": "in", "args": ["metadata.tier", [1, 2]]},
            ],
        },
        "sort": ["-alias_binding.bound_at_ms", "id"],
        "limit": 50,
        "include_total": True,
    }
    assert (page.next_cursor, page.total, page.has_more) == ("q1_next", 9, True)
    definition = page.items[0]
    assert isinstance(definition, AssetDefinition)
    assert (definition.name, definition.alias, definition.mintable) == (
        "rose",
        "rose#wonderland.universal",
        "Infinitely",
    )
    assert definition.alias_binding is not None and definition.alias_binding.bound_at_ms == 5
    assert definition.raw["description"] == "kept in raw"


def test_iter_follows_cursors_lazily_and_pages_reuse_the_query() -> None:
    client, session = _client(
        _response(payload={"items": [{"id": "a"}], "next_cursor": "c1"}),
        _response(payload={"items": [{"id": "b"}], "next_cursor": "c2"}),
        _response(payload={"items": [{"id": "c"}], "next_cursor": None}),
    )

    iterator = client.accounts.iter(filter="label is not null", limit=1)
    assert isinstance(next(iterator), Account)
    assert len(session.calls) == 1
    assert [account.id for account in iterator] == ["b", "c"]
    assert [_body(call) for call in session.calls] == [
        {"filter": "label is not null", "limit": 1},
        {"filter": "label is not null", "limit": 1, "cursor": "c1"},
        {"filter": "label is not null", "limit": 1, "cursor": "c2"},
    ]


def test_pages_accept_a_query_value_and_stop_on_the_last_page() -> None:
    client, _ = _client(
        _response(payload={"items": [{"id": "n1", "owned_by": "x", "metadata": {"k": 1}}], "next_cursor": "c"}),
        _response(payload={"items": [], "next_cursor": None}),
    )

    pages = list(client.nfts.pages(ListQuery(filter=F.owned_by == "x"), limit=1))

    assert [len(page) for page in pages] == [1, 0]
    assert isinstance(pages[0].items[0], Nft)
    assert pages[0].items[0].metadata == {"k": 1}


def test_quantities_are_exact_decimals_and_reject_floats() -> None:
    client, _ = _client(
        _response(
            payload={
                "items": [
                    {
                        "asset": "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
                        "asset_name": "rose",
                        "asset_alias": None,
                        "scope": "dataspace:3",
                        "account_id": CANONICAL_OWNER,
                        "quantity": "123456789012345678901234567890.000000001",
                    }
                ],
                "next_cursor": None,
            }
        ),
        _response(text='{"items": [{"account_id": "a", "asset": "b", "scope": "global", "quantity": 1.5}], "next_cursor": null}'),
        _response(payload={"items": [{"id": "lot", "quantity": "1.50"}], "next_cursor": None}),
    )

    bucket = client.accounts.assets(CANONICAL_OWNER).list().items[0]
    assert isinstance(bucket, AccountAsset)
    assert bucket.quantity == Decimal("123456789012345678901234567890.000000001")
    assert bucket.scope == "dataspace:3"
    with pytest.raises(TypeError, match="canonical decimal string"):
        client.asset_definitions.holders("b").list()
    with pytest.raises(ValueError, match="trailing fractional zeros"):
        client.rwas.list()


def test_rows_return_json_objects_for_projections_and_aggregates() -> None:
    client, session = _client(
        _response(payload={"items": [{"id": "a"}], "next_cursor": None}),
        _response(payload={"items": [{"asset": "x", "holders": 12, "supply": "10.5"}], "next_cursor": None}),
    )

    projected = client.domains.rows(select=["id"], limit=10)
    aggregated = client.accounts.assets(CANONICAL_OWNER).rows(
        filter=F.quantity > 0,
        aggregate=AggregateSpec(
            group_by=["asset"],
            metrics=[AggregateMetric("holders", "count"), AggregateMetric("supply", "sum", "quantity")],
            having="holders >= 10",
        ),
        sort="-supply",
    )

    assert projected.items == ({"id": "a"},)
    assert aggregated.items == ({"asset": "x", "holders": 12, "supply": "10.5"},)
    assert _body(session.calls[0]) == {"select": ["id"], "limit": 10}
    assert _body(session.calls[1])["aggregate"] == {
        "group_by": ["asset"],
        "metrics": [
            {"alias": "holders", "fn": "count"},
            {"alias": "supply", "fn": "sum", "field": "quantity"},
        ],
        "having": "holders >= 10",
    }


def test_typed_calls_point_projections_to_rows() -> None:
    client, session = _client()
    with pytest.raises(ListQueryError, match="rows"):
        client.domains.list(ListQuery(select=["id"]))
    with pytest.raises(ListQueryError, match="rows"):
        client.domains.list(ListQuery(aggregate=AggregateSpec(metrics=[AggregateMetric("n", "count")])))
    assert session.calls == []


def test_count_uses_include_total_with_the_smallest_page() -> None:
    client, session = _client(
        _response(payload={"items": [{"id": "x"}], "next_cursor": "c", "total": 42}),
        _response(payload={"items": [], "next_cursor": None}),
    )

    assert client.domains.count(F.owned_by == "alice") == 42
    assert _body(session.calls[0]) == {
        "filter": {"op": "eq", "args": ["owned_by", "alice"]},
        "limit": 1,
        "include_total": True,
    }
    with pytest.raises(ValueError, match="omitted `total`"):
        client.domains.count()


def test_configured_credentials_sign_queries_once_without_redirects() -> None:
    captured: List[bytes] = []
    auth = ToriiCanonicalRequestAuth(
        network_id=NETWORK_ID,
        account_id=CANONICAL_OWNER,
        signer=lambda message: captured.append(message) or b"\x5a" * 64,
    )
    client, session = _client(_response(), canonical_request_auth=auth)

    client.accounts.list(limit=5)

    call = session.calls[0]
    assert {"X-Iroha-Account", "X-Iroha-Signature", "X-Iroha-Timestamp-Ms", "X-Iroha-Nonce"} <= set(call["headers"])
    assert call["allow_redirects"] is False
    assert len(captured) == 1 and _body(call) == {"limit": 5}


@pytest.mark.parametrize(
    ("status", "payload", "headers", "error_type", "code"),
    [
        (
            400,
            {"code": "invalid_sort", "message": "invalid `sort`: ...", "details": {"field": "sort"}},
            {},
            ToriiQueryError,
            "invalid_sort",
        ),
        (404, {"code": "not_found", "message": "account not found"}, {}, ToriiNotFoundError, "not_found"),
        (429, {"code": "rate_limited", "message": "slow down"}, {"Retry-After": "3"}, ToriiRateLimitedError, "rate_limited"),
        (503, None, {}, ToriiUnavailableError, None),
        (500, {"code": "internal_error", "message": "boom"}, {}, ToriiServerError, "internal_error"),
    ],
)
def test_error_envelopes_raise_typed_errors(
    status: int, payload: Any, headers: dict, error_type: type, code: Optional[str]
) -> None:
    response = _response(status, payload, headers=headers) if payload is not None else _response(status, text="")
    client, _ = _client(response)

    with pytest.raises(error_type) as raised:
        client.accounts.list()

    error = raised.value
    assert isinstance(error, ToriiError) and isinstance(error, RuntimeError)
    assert (error.status, error.code) == (status, code)
    assert f"unexpected status {status}" in str(error)
    if error_type is ToriiQueryError:
        assert error.parameter == "sort"
        assert isinstance(error, ListQueryError)
    if error_type is ToriiRateLimitedError:
        assert error.retry_after == 3


@pytest.mark.parametrize("field", [None, [], {}, 1, "unknown"])
def test_query_error_with_malformed_field_retains_typed_error(field: Any) -> None:
    details = {"field": field}
    response = _response(
        400,
        {"code": "invalid_filter", "message": "invalid filter", "details": details},
    )
    client, _ = _client(response)

    with pytest.raises(ToriiQueryError) as raised:
        client.accounts.list()

    assert raised.value.parameter == "filter"
    assert raised.value.details == details
    assert raised.value.code == "invalid_filter"


def test_reject_code_header_is_exposed() -> None:
    response = _response(
        400,
        {"code": "transaction_rejected", "message": "denied", "details": {"reject_code": "inner"}},
        headers={"x-iroha-reject-code": "PRTRY:TX_SIGNATURE_INVALID"},
    )
    client, _ = _client(response)
    with pytest.raises(ToriiError) as raised:
        client.domains.list()
    assert raised.value.reject_code == "PRTRY:TX_SIGNATURE_INVALID"
    assert "reject_code=PRTRY:TX_SIGNATURE_INVALID" in str(raised.value)


def test_torii_errors_survive_pickling() -> None:
    error = error_for_status(
        400,
        code="invalid_filter",
        message="bad",
        details={"field": "filter"},
        expected=[200],
    )
    restored = pickle.loads(pickle.dumps(error))
    assert type(restored) is ToriiQueryError
    assert (restored.status, restored.code, restored.parameter, str(restored)) == (
        400,
        "invalid_filter",
        "filter",
        str(error),
    )


@pytest.mark.parametrize(
    ("response", "needle"),
    [
        (_response(text="[]"), "JSON object"),
        (_response(text='{"items": [], "items": []}'), "repeats the JSON key"),
        (_response(text='{"items": [NaN]}'), "non-finite"),
        (_response(text="{}", content_type="text/plain"), "application/json"),
        (_response(text=""), "empty body"),
    ],
)
def test_malformed_pages_fail_closed(response: requests.Response, needle: str) -> None:
    client, _ = _client(response)
    with pytest.raises(ValueError, match=needle):
        client.domains.list()


def test_path_segments_are_validated_and_encoded() -> None:
    client, _ = _client()
    for bad in ("", " padded", 7):
        with pytest.raises(ValueError):
            client.accounts.assets(bad)  # type: ignore[arg-type]
    assert client.asset_definitions.holders("rose#wonderland.universal").path == (
        "/v1/assets/rose%23wonderland.universal/holders"
    )


_TRANSACTION_ROW = {
    "entrypoint_hash": "ab" * 32,
    "block_height": 1_500,
    "block_index": 3,
    "block_hash": "cd" * 32,
    "authority": "a",
    "timestamp_ms": 1_700,
    "entrypoint_kind": "transaction",
    "result_ok": True,
    "asset_ids": ["62Fk4FPcMuLvW5QjDGNF2a4jAmjM#a"],
    "asset_definition_ids": ["62Fk4FPcMuLvW5QjDGNF2a4jAmjM"],
    "metadata": {"memo": "rent"},
}


def test_holders_and_transactions_rows_are_typed() -> None:
    client, _ = _client(
        _response(payload={"items": [{"account_id": "a", "asset": "d", "scope": "global", "quantity": "7"}], "next_cursor": None}),
        _response(payload={"items": [_TRANSACTION_ROW], "next_cursor": None}),
    )
    holder = client.asset_definitions.holders("d").list().items[0]
    assert isinstance(holder, AssetHolder) and holder.quantity == Decimal(7)
    transaction = client.accounts.transactions("a").list().items[0]
    assert transaction == CommittedTransaction(
        entrypoint_hash="ab" * 32,
        block_height=1_500,
        block_index=3,
        block_hash="cd" * 32,
        authority="a",
        timestamp_ms=1_700,
        entrypoint_kind="transaction",
        result_ok=True,
        asset_ids=("62Fk4FPcMuLvW5QjDGNF2a4jAmjM#a",),
        asset_definition_ids=("62Fk4FPcMuLvW5QjDGNF2a4jAmjM",),
        metadata={"memo": "rent"},
    )
    assert transaction.raw == _TRANSACTION_ROW
    assert not hasattr(transaction, "asset_id")


def test_transaction_rows_require_only_their_identity_fields() -> None:
    minimal = CommittedTransaction.from_json(
        {"entrypoint_hash": "ab", "block_height": 2, "block_index": 0, "authority": None, "timestamp_ms": None}
    )
    assert (minimal.authority, minimal.timestamp_ms, minimal.result_ok) == (None, None, None)
    assert (minimal.asset_ids, minimal.asset_definition_ids, minimal.metadata) == ((), (), {})
    for missing in ("entrypoint_hash", "block_height", "block_index"):
        row = {key: value for key, value in _TRANSACTION_ROW.items() if key != missing}
        with pytest.raises(ValueError, match=missing):
            CommittedTransaction.from_json(row)
    for name, value in (("block_height", -1), ("block_index", True), ("asset_ids", "x"), ("asset_definition_ids", [1])):
        with pytest.raises(ValueError, match=name):
            CommittedTransaction.from_json({**_TRANSACTION_ROW, name: value})


@pytest.mark.parametrize(
    ("controls", "parameter", "message"),
    [
        (
            {"sort": "-block_height"},
            "sort",
            "rows use a fixed server order and cannot be re-sorted",
        ),
        ({"include_total": True}, "include_total", "counting would scan the whole history"),
        (
            {"aggregate": AggregateSpec(metrics=[AggregateMetric("n", "count")])},
            "aggregate",
            "they would scan the whole history",
        ),
    ],
)
def test_history_collections_reject_sort_totals_and_aggregates_before_any_request(
    controls: dict, parameter: str, message: str
) -> None:
    client, session = _client()
    for collection, collection_id in (
        (client.transactions, "transactions"),
        (client.accounts.transactions(CANONICAL_OWNER), "account_transactions"),
        (client.accounts.history(CANONICAL_OWNER), "account_history"),
        (client.contract_activity, "contract_activity"),
        (client.contract_events, "contract_events"),
    ):
        assert isinstance(collection, HistoryCollection)
        calls = [
            (collection.rows, None),
            (collection.iter_rows, ListQuery(**controls)),
            (collection.list, ListQuery(**controls)),
            (collection.pages, ListQuery(**controls)),
            (collection.iter, ListQuery(**controls)),
        ]
        if parameter != "aggregate":
            calls.append((collection.list, None))
        for method, query in calls:
            with pytest.raises(ListQueryError) as raised:
                method(**controls) if query is None else method(query)
            assert raised.value.parameter == parameter
            assert raised.value.code == f"invalid_{parameter}"
            assert f"`{collection_id}`" in str(raised.value) and message in str(raised.value)
    assert session.calls == []


def test_history_iteration_follows_short_and_empty_pages() -> None:
    row = dict(_TRANSACTION_ROW)
    client, session = _client(
        _response(payload={"items": [], "next_cursor": "h1"}),
        _response(payload={"items": [row], "next_cursor": "h2"}),
        _response(payload={"items": [], "next_cursor": "h3"}),
        _response(payload={"items": [row], "next_cursor": None}),
    )

    history = client.transactions.iter(filter=(F.block_height >= 1_200) & (F.result_ok == True), limit=50)  # noqa: E712

    assert [tx.block_height for tx in history] == [1_500, 1_500]
    assert [_body(call).get("cursor") for call in session.calls] == [None, "h1", "h2", "h3"]
    assert _body(session.calls[0]) == {
        "filter": {
            "op": "and",
            "args": [
                {"op": "gte", "args": ["block_height", 1_200]},
                {"op": "eq", "args": ["result_ok", True]},
            ],
        },
        "limit": 50,
    }


def test_history_count_pages_through_matching_rows() -> None:
    client, session = _client(
        _response(payload={"items": [{"entrypoint_hash": "a"}], "next_cursor": "h1"}),
        _response(payload={"items": [], "next_cursor": "h2"}),
        _response(payload={"items": [{"entrypoint_hash": "b"}, {"entrypoint_hash": "c"}], "next_cursor": None}),
    )

    assert client.accounts.transactions(CANONICAL_OWNER).count(F.asset_definition_ids == "d") == 3
    assert [_body(call) for call in session.calls] == [
        {"filter": {"op": "eq", "args": ["asset_definition_ids", "d"]}},
        {"filter": {"op": "eq", "args": ["asset_definition_ids", "d"]}, "cursor": "h1"},
        {"filter": {"op": "eq", "args": ["asset_definition_ids", "d"]}, "cursor": "h2"},
    ]


def test_rwa_rows_require_only_their_id() -> None:
    client, _ = _client(_response(payload={"items": [{"id": "lot"}, {"id": "lot2", "quantity": None}], "next_cursor": None}))
    assert [lot.quantity for lot in client.rwas.list().items] == [None, None]
    assert RwaLot.from_json({"id": "lot", "quantity": "0"}).quantity == Decimal(0)
    with pytest.raises(TypeError, match="quantity"):
        RwaLot.from_json({"id": "lot", "quantity": 1})
    with pytest.raises(ValueError, match="`id`"):
        RwaLot.from_json({"quantity": "1"})


def test_client_owns_and_closes_only_its_own_session() -> None:
    closed: List[str] = []

    class Tracking(requests.Session):
        def close(self) -> None:
            closed.append("caller")

    caller_session = Tracking()
    with ToriiClient("https://torii.example", session=caller_session):
        pass
    assert closed == []

    with ToriiClient("https://torii.example") as owned:
        assert owned._session.trust_env is False
    with pytest.raises(ValueError, match="timeout"):
        ToriiClient("https://torii.example", timeout=0)


def test_iteration_resumes_from_a_cursor() -> None:
    client, session = _client(
        _response(payload={"items": [{"id": "c"}], "next_cursor": None}),
    )

    assert [domain.id for domain in client.domains.iter(sort="id", cursor="c2")] == ["c"]
    assert _body(session.calls[0]) == {"sort": ["id"], "cursor": "c2"}


@pytest.mark.parametrize(("name", "path"), [
    ("explorer_accounts", "accounts"),
    ("explorer_domains", "domains"),
    ("explorer_asset_definitions", "asset-definitions"),
    ("explorer_assets", "assets"),
    ("explorer_nfts", "nfts"),
    ("explorer_rwas", "rwas"),
    ("explorer_blocks", "blocks"),
    ("explorer_transactions", "transactions"),
    ("explorer_latest_transactions", "transactions/latest"),
    ("explorer_instructions", "instructions"),
    ("explorer_latest_instructions", "instructions/latest"),
])
def test_explorer_collections_share_bounded_queries_and_pages(name: str, path: str) -> None:
    client, session = _client(
        _response(payload={"items": [], "next_cursor": "older"}),
        _response(payload={"items": [{"id": "one"}], "next_cursor": None}),
    )
    collection = getattr(client, name)
    assert list(collection.iter_rows(filter='status = "active"', limit=5)) == [{"id": "one"}]
    assert [call["path"] for call in session.calls] == [f"/v1/explorer/{path}/query"] * 2
    assert _body(session.calls[0]) == {"filter": 'status = "active"', "limit": 5}
    assert _body(session.calls[1])["cursor"] == "older"
    for controls in [{"sort": "id"}, {"include_total": True}, {"aggregate": AggregateSpec(metrics=[AggregateMetric("n", "count")])}]:
        with pytest.raises(ListQueryError):
            collection.rows(**controls)
    assert len(session.calls) == 2


@pytest.mark.parametrize("payload", [
    {"items": [], "pagination": {"next_cursor": None, "has_more": False}},
    {"items": [], "next_cursor": None, "sampled_at": "today"},
    {"items": [], "next_cursor": None, "total": 0},
    {"items": [{}, {}], "next_cursor": None},
])
def test_explorer_collection_rejects_retired_or_oversized_pages(payload: dict) -> None:
    client, _ = _client(_response(payload=payload))
    with pytest.raises(ValueError, match="malformed page"):
        client.explorer_accounts.list(limit=1)
