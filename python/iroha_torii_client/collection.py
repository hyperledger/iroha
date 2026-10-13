"""Typed access to Torii's collection endpoints.

Every collection exposes the same calls, each issuing
``POST /v1/<collection>/query`` with a :class:`~iroha_torii_client.list_query.ListQuery`
body::

    page = client.asset_definitions.list(filter=F.owned_by == alice, sort="-id", limit=50)
    for definition in client.asset_definitions.iter(filter=F.owned_by == alice):
        ...                                   # follows next_cursor until the last page
    rows = client.accounts.assets(alice).rows(select=["asset", "quantity"])
    n = client.domains.count(F.owned_by == alice)

``list``/``pages``/``iter`` return typed rows; ``rows``/``iter_rows`` return
plain JSON objects and are the calls that accept ``select`` and ``aggregate``.
Transaction collections (``client.transactions`` and
``client.accounts.transactions(id)``) are :class:`HistoryCollection` values:
newest first, without ``sort``, ``include_total`` or ``aggregate``, and with
pages that can be short or empty while ``next_cursor`` continues. Requests are
signed with the client's canonical account credentials when they are
configured (a signature only widens visibility into restricted dataspaces) and
are anonymous otherwise.

Rows decode the fields that identify them strictly (``id``; ``account_id``,
``asset``, ``scope`` and ``quantity`` for balances; ``entrypoint_hash``,
``block_height`` and ``block_index`` for transactions). Every other field may
be null or absent and decodes as ``None`` (``{}`` for ``metadata``, ``()`` for
lists); ``raw`` keeps the row exactly as Torii sent it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from decimal import Decimal
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterator,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)
from urllib.parse import quote

from .list_query import (
    AggregateSpec,
    FilterLike,
    ListQuery,
    ListQueryError,
    Page,
    SortLike,
    iter_items,
    iter_pages,
)

__all__ = [
    "Account",
    "AccountAsset",
    "AccountsCollection",
    "AliasBinding",
    "AssetDefinition",
    "AssetDefinitionsCollection",
    "AssetHolder",
    "Collection",
    "CollectionsMixin",
    "CommittedTransaction",
    "Domain",
    "HistoryCollection",
    "JsonObject",
    "Nft",
    "RwaLot",
]

JsonObject = Dict[str, Any]
T = TypeVar("T")
SortArgument = Union[None, SortLike, Sequence[SortLike]]


class _QueryTransport:
    """The client hook used by collections (implemented by ``ToriiClient``)."""

    def _query_collection(self, path: str, body: Mapping[str, Any], *, context: str) -> Any:
        raise NotImplementedError  # pragma: no cover - protocol


# ---------------------------------------------------------------------------
# Row decoding helpers
# ---------------------------------------------------------------------------


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be a JSON object")
    return value


def _string(row: Mapping[str, Any], name: str, context: str) -> str:
    value = row.get(name)
    if not isinstance(value, str):
        raise ValueError(f"{context} `{name}` must be a string")
    return value


def _optional_string(row: Mapping[str, Any], name: str, context: str) -> Optional[str]:
    value = row.get(name)
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{context} `{name}` must be a string or null")
    return value


def _optional_int(row: Mapping[str, Any], name: str, context: str) -> Optional[int]:
    value = row.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{context} `{name}` must be an integer")
    return value


def _optional_bool(row: Mapping[str, Any], name: str, context: str) -> Optional[bool]:
    value = row.get(name)
    if value is not None and not isinstance(value, bool):
        raise ValueError(f"{context} `{name}` must be a boolean")
    return value


_U64_MAX = (1 << 64) - 1


def _u64(row: Mapping[str, Any], name: str, context: str) -> int:
    value = row.get(name)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _U64_MAX:
        raise ValueError(f"{context} `{name}` must be an unsigned 64-bit integer")
    return value


def _optional_u64(row: Mapping[str, Any], name: str, context: str) -> Optional[int]:
    return None if row.get(name) is None else _u64(row, name, context)


def _string_list(row: Mapping[str, Any], name: str, context: str) -> Tuple[str, ...]:
    value = row.get(name)
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{context} `{name}` must be an array of strings")
    return tuple(value)


_QUANTITY_TEXT = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?")
_QUANTITY_TEXT_MAX_CHARS = 155
_QUANTITY_MAX_SCALE = 28
_QUANTITY_MANTISSA_LIMIT = 1 << 511


def _quantity(value: Any, context: str) -> Decimal:
    """Exact quantity from its canonical Numeric V1 string (never a float or JSON number).

    Canonical quantities are non-negative, have no sign, no leading zeros and
    no trailing fractional zeros, at most 28 fractional digits and a mantissa
    below ``2**511``.
    """

    if not isinstance(value, str):
        raise TypeError(f'{context} must be a canonical decimal string such as "10.5"')
    if len(value) > _QUANTITY_TEXT_MAX_CHARS:
        raise ValueError(f"{context} exceeds the canonical V1 text bound of 155 characters")
    if _QUANTITY_TEXT.fullmatch(value) is None:
        raise ValueError(
            f"{context} must be a canonical non-negative decimal without sign, "
            f"leading zeros or trailing fractional zeros, got {value!r}"
        )
    integer, _, fraction = value.partition(".")
    if len(fraction) > _QUANTITY_MAX_SCALE:
        raise ValueError(f"{context} has more than {_QUANTITY_MAX_SCALE} fractional digits")
    if int(integer + fraction) >= _QUANTITY_MANTISSA_LIMIT:
        raise ValueError(f"{context} exceeds the Numeric V1 mantissa range")
    return Decimal(value)


def _optional_quantity(value: Any, context: str) -> Optional[Decimal]:
    return None if value is None else _quantity(value, context)


def _metadata(row: Mapping[str, Any], context: str) -> Dict[str, Any]:
    value = row.get("metadata")
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} `metadata` must be a JSON object")
    return dict(value)


def _raw() -> Any:
    return dataclass_field(default_factory=dict, repr=False, compare=False)


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Domain:
    """A ``/v1/domains`` row. ``raw`` keeps every field Torii sent."""

    id: str
    owned_by: Optional[str] = None
    logo: Optional[str] = None
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "Domain":
        row = _object(value, "domain row")
        return cls(
            id=_string(row, "id", "domain row"),
            owned_by=_optional_string(row, "owned_by", "domain row"),
            logo=_optional_string(row, "logo", "domain row"),
            metadata=_metadata(row, "domain row"),
            raw=dict(row),
        )


@dataclass(frozen=True)
class Account:
    """A ``/v1/accounts`` row: canonical I105 ``id`` plus optional ``label``/``uaid``."""

    id: str
    label: Optional[str] = None
    uaid: Optional[str] = None
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "Account":
        row = _object(value, "account row")
        return cls(
            id=_string(row, "id", "account row"),
            label=_optional_string(row, "label", "account row"),
            uaid=_optional_string(row, "uaid", "account row"),
            metadata=_metadata(row, "account row"),
            raw=dict(row),
        )


@dataclass(frozen=True)
class AliasBinding:
    """Alias bound to an asset definition, with its lease timeline (milliseconds)."""

    alias: Optional[str] = None
    status: Optional[str] = None
    lease_expiry_ms: Optional[int] = None
    grace_until_ms: Optional[int] = None
    bound_at_ms: Optional[int] = None

    @classmethod
    def from_json(cls, value: Any) -> "AliasBinding":
        row = _object(value, "asset definition `alias_binding`")
        context = "asset definition `alias_binding`"
        return cls(
            alias=_optional_string(row, "alias", context),
            status=_optional_string(row, "status", context),
            lease_expiry_ms=_optional_int(row, "lease_expiry_ms", context),
            grace_until_ms=_optional_int(row, "grace_until_ms", context),
            bound_at_ms=_optional_int(row, "bound_at_ms", context),
        )


@dataclass(frozen=True)
class AssetDefinition:
    """A ``/v1/assets/definitions`` row (Base58 ``id``).

    The complete definition record (``description``, ``spec``, ``logo``,
    ``balance_scope_policy``, ...) stays available in ``raw``.
    """

    id: str
    name: Optional[str] = None
    alias: Optional[str] = None
    owned_by: Optional[str] = None
    owning_domain: Optional[str] = None
    mintable: Optional[str] = None
    alias_binding: Optional[AliasBinding] = None
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "AssetDefinition":
        context = "asset definition row"
        row = _object(value, context)
        binding = row.get("alias_binding")
        return cls(
            id=_string(row, "id", context),
            name=_optional_string(row, "name", context),
            alias=_optional_string(row, "alias", context),
            owned_by=_optional_string(row, "owned_by", context),
            owning_domain=_optional_string(row, "owning_domain", context),
            mintable=_optional_string(row, "mintable", context),
            alias_binding=None if binding is None else AliasBinding.from_json(binding),
            metadata=_metadata(row, context),
            raw=dict(row),
        )


@dataclass(frozen=True)
class Nft:
    """A ``/v1/nfts`` row; ``metadata`` is the NFT content."""

    id: str
    owned_by: Optional[str] = None
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "Nft":
        row = _object(value, "NFT row")
        return cls(
            id=_string(row, "id", "NFT row"),
            owned_by=_optional_string(row, "owned_by", "NFT row"),
            metadata=_metadata(row, "NFT row"),
            raw=dict(row),
        )


@dataclass(frozen=True)
class RwaLot:
    """A ``/v1/rwas`` row; ``quantity`` is exact (``None`` when Torii omits it)."""

    id: str
    quantity: Optional[Decimal] = None
    owned_by: Optional[str] = None
    primary_reference: Optional[str] = None
    status: Optional[str] = None
    is_frozen: Optional[bool] = None
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "RwaLot":
        context = "RWA lot row"
        row = _object(value, context)
        return cls(
            id=_string(row, "id", context),
            quantity=_optional_quantity(row.get("quantity"), f"{context} `quantity`"),
            owned_by=_optional_string(row, "owned_by", context),
            primary_reference=_optional_string(row, "primary_reference", context),
            status=_optional_string(row, "status", context),
            is_frozen=_optional_bool(row, "is_frozen", context),
            metadata=_metadata(row, context),
            raw=dict(row),
        )


@dataclass(frozen=True)
class AccountAsset:
    """One balance bucket of an account: ``asset`` definition id, ``scope`` and exact ``quantity``."""

    asset: str
    scope: str
    account_id: str
    quantity: Decimal
    asset_name: Optional[str] = None
    asset_alias: Optional[str] = None
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "AccountAsset":
        context = "account asset row"
        row = _object(value, context)
        return cls(
            asset=_string(row, "asset", context),
            scope=_string(row, "scope", context),
            account_id=_string(row, "account_id", context),
            quantity=_quantity(row.get("quantity"), f"{context} `quantity`"),
            asset_name=_optional_string(row, "asset_name", context),
            asset_alias=_optional_string(row, "asset_alias", context),
            raw=dict(row),
        )


@dataclass(frozen=True)
class AssetHolder:
    """One holder of an asset definition: ``account_id``, ``scope`` and exact ``quantity``."""

    account_id: str
    asset: str
    scope: str
    quantity: Decimal
    asset_alias: Optional[str] = None
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "AssetHolder":
        context = "asset holder row"
        row = _object(value, context)
        return cls(
            account_id=_string(row, "account_id", context),
            asset=_string(row, "asset", context),
            scope=_string(row, "scope", context),
            quantity=_quantity(row.get("quantity"), f"{context} `quantity`"),
            asset_alias=_optional_string(row, "asset_alias", context),
            raw=dict(row),
        )


@dataclass(frozen=True)
class CommittedTransaction:
    """A committed transaction (``client.transactions``, ``client.accounts.transactions(id)``).

    ``block_height`` and ``block_index`` (the position in its block) locate the
    transaction; history is read newest first by those coordinates.
    ``asset_ids`` and ``asset_definition_ids`` list the asset buckets and
    definitions it touched; filters match these lists element-wise
    (``F.asset_definition_ids == definition`` selects transactions touching
    ``definition``).
    """

    entrypoint_hash: str
    block_height: int
    block_index: int
    block_hash: Optional[str] = None
    authority: Optional[str] = None
    timestamp_ms: Optional[int] = None
    entrypoint_kind: Optional[str] = None
    result_ok: Optional[bool] = None
    asset_ids: Tuple[str, ...] = ()
    asset_definition_ids: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = dataclass_field(default_factory=dict)
    raw: Dict[str, Any] = _raw()

    @classmethod
    def from_json(cls, value: Any) -> "CommittedTransaction":
        context = "transaction row"
        row = _object(value, context)
        return cls(
            entrypoint_hash=_string(row, "entrypoint_hash", context),
            block_height=_u64(row, "block_height", context),
            block_index=_u64(row, "block_index", context),
            block_hash=_optional_string(row, "block_hash", context),
            authority=_optional_string(row, "authority", context),
            timestamp_ms=_optional_u64(row, "timestamp_ms", context),
            entrypoint_kind=_optional_string(row, "entrypoint_kind", context),
            result_ok=_optional_bool(row, "result_ok", context),
            asset_ids=_string_list(row, "asset_ids", context),
            asset_definition_ids=_string_list(row, "asset_definition_ids", context),
            metadata=_metadata(row, context),
            raw=dict(row),
        )


def _json_object_row(value: Any) -> JsonObject:
    return dict(_object(value, "collection row"))


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------


class Collection(Generic[T]):
    """One Torii collection; obtain it from a client attribute such as ``client.domains``."""

    __slots__ = ("_transport", "_path", "_parse", "_name")

    def __init__(
        self,
        transport: _QueryTransport,
        path: str,
        parse: Callable[[Any], T],
        name: str,
    ) -> None:
        self._transport = transport
        self._path = path
        self._parse = parse
        self._name = name

    def __repr__(self) -> str:
        return f"<Collection {self._name} {self._path}>"

    @property
    def path(self) -> str:
        """The collection path: queries go to ``POST <path>/query``."""

        return self._path

    # -- query assembly ------------------------------------------------------
    def _query(self, query: Optional[ListQuery], controls: Mapping[str, Any]) -> ListQuery:
        given = {name: value for name, value in controls.items() if value is not None}
        if query is None:
            built = ListQuery(**given)
        elif not isinstance(query, ListQuery):
            raise TypeError("query must be a ListQuery")
        else:
            built = query.replace(**given) if given else query
        self._check(built)
        return built

    def _check(self, query: ListQuery) -> None:
        """Reject ``query`` before any request when Torii would reject it."""

        query.validate()

    def _typed_query(self, query: Optional[ListQuery], controls: Mapping[str, Any]) -> ListQuery:
        built = self._query(query, controls)
        if built.select is not None:
            raise ListQueryError("select", "projected rows are JSON objects; use .rows() or .iter_rows()")
        if built.aggregate is not None:
            raise ListQueryError("aggregate", "aggregate rows are JSON objects; use .rows() or .iter_rows()")
        return built

    def _fetch(self, query: ListQuery) -> Page[Any]:
        self._check(query)
        payload = self._transport._query_collection(
            f"{self._path}/query",
            query.to_json(),
            context=f"{self._name} query",
        )
        try:
            page: Page[Any] = Page.from_json(payload)
            if query.limit is not None and len(page.items) > query.limit:
                raise ValueError("items exceed the requested limit")
            if isinstance(self, HistoryCollection) and page.total is not None:
                raise ValueError("bounded collections must omit total")
            return page
        except ValueError as error:
            raise ValueError(f"{self._name} query returned a malformed page: {error}") from None

    def _fetch_typed(self, query: ListQuery) -> Page[T]:
        page = self._fetch(query)
        return page.map(self._parse)

    def _fetch_rows(self, query: ListQuery) -> Page[JsonObject]:
        return self._fetch(query).map(_json_object_row)

    # -- typed rows ----------------------------------------------------------
    def list(
        self,
        query: Optional[ListQuery] = None,
        /,
        *,
        filter: Optional[FilterLike] = None,
        sort: SortArgument = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        include_total: Optional[bool] = None,
    ) -> Page[T]:
        """Fetch one page of typed rows; pass ``cursor=page.next_cursor`` to continue."""

        controls = {"filter": filter, "sort": sort, "limit": limit, "cursor": cursor, "include_total": include_total}
        return self._fetch_typed(self._typed_query(query, controls))

    def pages(
        self,
        query: Optional[ListQuery] = None,
        /,
        *,
        filter: Optional[FilterLike] = None,
        sort: SortArgument = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        include_total: Optional[bool] = None,
    ) -> Iterator[Page[T]]:
        """Lazily fetch every page, following ``next_cursor`` until the last page.

        Pass ``cursor`` to resume after a page fetched earlier with the same query.
        """

        controls = {
            "filter": filter,
            "sort": sort,
            "limit": limit,
            "cursor": cursor,
            "include_total": include_total,
        }
        return iter_pages(self._fetch_typed, self._typed_query(query, controls))

    def iter(
        self,
        query: Optional[ListQuery] = None,
        /,
        *,
        filter: Optional[FilterLike] = None,
        sort: SortArgument = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Iterator[T]:
        """Lazily yield every matching row across pages (``limit`` is the page size).

        Breaking out of the loop stops issuing requests; ``cursor`` resumes a query.
        """

        controls = {"filter": filter, "sort": sort, "limit": limit, "cursor": cursor}
        return iter_items(self._fetch_typed, self._typed_query(query, controls))

    # -- JSON rows (projections and aggregates) -------------------------------
    def rows(
        self,
        query: Optional[ListQuery] = None,
        /,
        *,
        filter: Optional[FilterLike] = None,
        sort: SortArgument = None,
        select: Optional[Any] = None,
        aggregate: Optional[AggregateSpec] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
        include_total: Optional[bool] = None,
    ) -> Page[JsonObject]:
        """Fetch one page of JSON objects; supports ``select`` and ``aggregate``."""

        controls = {
            "filter": filter,
            "sort": sort,
            "select": select,
            "aggregate": aggregate,
            "limit": limit,
            "cursor": cursor,
            "include_total": include_total,
        }
        return self._fetch_rows(self._query(query, controls))

    def iter_rows(
        self,
        query: Optional[ListQuery] = None,
        /,
        *,
        filter: Optional[FilterLike] = None,
        sort: SortArgument = None,
        select: Optional[Any] = None,
        aggregate: Optional[AggregateSpec] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Iterator[JsonObject]:
        """Lazily yield every JSON row across pages; supports ``select`` and ``aggregate``."""

        controls = {
            "filter": filter,
            "sort": sort,
            "select": select,
            "aggregate": aggregate,
            "limit": limit,
            "cursor": cursor,
        }
        return iter_items(self._fetch_rows, self._query(query, controls))

    def count(self, filter: Optional[FilterLike] = None) -> int:
        """Exact number of rows matching ``filter`` (costs a full scan on the server)."""

        page = self._fetch(ListQuery(filter=filter, limit=1, include_total=True))
        if page.total is None:
            raise ValueError(f"{self._name} query omitted `total` although include_total was set")
        return page.total


class HistoryCollection(Collection[T]):
    """A bounded collection with fixed server ordering.

    Chain history rows come by ``block_height`` then ``block_index``
    descending; Explorer world rows use the collection key. History cursors
    hold the block coordinates of the last row,
    so transactions committed while paging never shift later pages. ``sort``,
    ``include_total`` and ``aggregate`` would need a scan of the whole history
    and are rejected before any request with Torii's codes (``invalid_sort``,
    ``invalid_include_total``, ``invalid_aggregate``).

    Each page has a bounded history-scan budget, so a selective filter can
    return a page with fewer than ``limit`` rows, even none, together with a
    ``next_cursor``. :meth:`pages`, :meth:`iter`, :meth:`iter_rows` and
    :meth:`count` keep following ``next_cursor`` until it is null. Bounds on
    ``block_height`` in the filter's top-level ``and`` also bound the scan:
    ``(F.block_height >= 1200) & (F.result_ok == True)`` reads only heights
    from 1200 up.
    """

    __slots__ = ("_collection_id",)

    def __init__(
        self,
        transport: _QueryTransport,
        path: str,
        parse: Callable[[Any], T],
        name: str,
        collection_id: str,
    ) -> None:
        super().__init__(transport, path, parse, name)
        self._collection_id = collection_id

    def _check(self, query: ListQuery) -> None:
        query.validate()
        collection = self._collection_id
        if query.sort:
            raise ListQueryError(
                "sort",
                f"`{collection}` rows use a fixed server order and cannot be re-sorted; "
                "omit `sort` and use `filter` to select a range",
            )
        if query.include_total:
            raise ListQueryError(
                "include_total",
                f"totals are not available for `{collection}`: counting would scan the whole history",
            )
        if query.aggregate is not None:
            raise ListQueryError(
                "aggregate",
                f"aggregates are not available for `{collection}`: they would scan the whole history",
            )

    def count(self, filter: Optional[FilterLike] = None) -> int:
        """Number of rows matching ``filter``, counted page by page.

        History has no ``include_total``: this follows ``next_cursor`` through
        every matching row, so bound large reads with a selective filter.
        """

        query = ListQuery(filter=filter)
        self._check(query)
        return sum(len(page.items) for page in iter_pages(self._fetch, query))


def _path_segment(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty string without surrounding whitespace")
    return quote(value, safe="")


class AccountsCollection(Collection[Account]):
    """``/v1/accounts`` plus per-account assets, permissions, movements and transactions."""

    __slots__ = ()

    def history(self, account_id: str) -> HistoryCollection[JsonObject]:
        """Indexed account movements, newest first by block and movement position."""

        return HistoryCollection(
            self._transport,
            f"/v1/accounts/{_path_segment(account_id, 'account_id')}/history",
            _json_object_row,
            "account history",
            "account_history",
        )

    def permissions(self, account_id: str) -> Collection[JsonObject]:
        """Effective direct and role-inherited permission tokens, with ``name`` and ``payload``."""

        return Collection(
            self._transport,
            f"/v1/accounts/{_path_segment(account_id, 'account_id')}/permissions",
            _json_object_row,
            "account permissions",
        )

    def assets(self, account_id: str) -> Collection[AccountAsset]:
        """Balance buckets held by ``account_id`` (``/v1/accounts/{account_id}/assets``)."""

        return Collection(
            self._transport,
            f"/v1/accounts/{_path_segment(account_id, 'account_id')}/assets",
            AccountAsset.from_json,
            "account assets",
        )

    def transactions(self, account_id: str) -> HistoryCollection[CommittedTransaction]:
        """Transactions ``account_id`` signed or that reference it, newest first.

        ``/v1/accounts/{account_id}/transactions``; see :class:`HistoryCollection`.
        """

        return HistoryCollection(
            self._transport,
            f"/v1/accounts/{_path_segment(account_id, 'account_id')}/transactions",
            CommittedTransaction.from_json,
            "account transactions",
            "account_transactions",
        )


class AssetDefinitionsCollection(Collection[AssetDefinition]):
    """``/v1/assets/definitions`` plus the per-definition ``holders`` collection."""

    __slots__ = ()

    def holders(self, definition_id: str) -> Collection[AssetHolder]:
        """Accounts holding ``definition_id`` (``/v1/assets/{definition_id}/holders``)."""

        return Collection(
            self._transport,
            f"/v1/assets/{_path_segment(definition_id, 'definition_id')}/holders",
            AssetHolder.from_json,
            "asset holders",
        )


class CollectionsMixin:
    """Collection attributes shared by every Torii client."""

    @property
    def explorer_accounts(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``accounts`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/accounts",
            _json_object_row,
            "Explorer accounts",
            "explorer_accounts",
        )

    @property
    def explorer_domains(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``domains`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/domains",
            _json_object_row,
            "Explorer domains",
            "explorer_domains",
        )

    @property
    def explorer_asset_definitions(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``asset-definitions`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/asset-definitions",
            _json_object_row,
            "Explorer asset-definitions",
            "explorer_asset_definitions",
        )

    @property
    def explorer_assets(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``assets`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/assets",
            _json_object_row,
            "Explorer assets",
            "explorer_assets",
        )

    @property
    def explorer_nfts(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``nfts`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/nfts",
            _json_object_row,
            "Explorer nfts",
            "explorer_nfts",
        )

    @property
    def explorer_rwas(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``rwas`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/rwas",
            _json_object_row,
            "Explorer rwas",
            "explorer_rwas",
        )

    @property
    def explorer_blocks(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``blocks`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/blocks",
            _json_object_row,
            "Explorer blocks",
            "explorer_blocks",
        )

    @property
    def explorer_transactions(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``transactions`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/transactions",
            _json_object_row,
            "Explorer transactions",
            "explorer_transactions",
        )

    @property
    def explorer_latest_transactions(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``transactions/latest`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/transactions/latest",
            _json_object_row,
            "Explorer transactions/latest",
            "explorer_latest_transactions",
        )

    @property
    def explorer_instructions(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``instructions`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/instructions",
            _json_object_row,
            "Explorer instructions",
            "explorer_instructions",
        )

    @property
    def explorer_latest_instructions(self) -> HistoryCollection[JsonObject]:
        """Bounded Explorer ``instructions/latest`` rows with shared query controls."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/explorer/instructions/latest",
            _json_object_row,
            "Explorer instructions/latest",
            "explorer_latest_instructions",
        )

    @property
    def contract_activity(self) -> HistoryCollection[JsonObject]:
        """Committed contract calls in block order, with history cursors."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/contracts/activity",
            _json_object_row,
            "contract activity",
            "contract_activity",
        )

    @property
    def contract_events(self) -> HistoryCollection[JsonObject]:
        """Committed contract events in block order, with history cursors."""

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/contracts/events",
            _json_object_row,
            "contract events",
            "contract_events",
        )

    @property
    def subscription_plans(self) -> Collection[JsonObject]:
        """Subscription plans with ``id``, ``provider``, ``billing`` and ``pricing`` fields."""

        return Collection(
            self,  # type: ignore[arg-type]
            "/v1/subscriptions/plans",
            _json_object_row,
            "subscription plans",
        )

    @property
    def subscriptions(self) -> Collection[JsonObject]:
        """Subscription state rows with ``id``, ``owned_by``, ``invoice`` and ``plan`` fields."""

        return Collection(
            self,  # type: ignore[arg-type]
            "/v1/subscriptions",
            _json_object_row,
            "subscriptions",
        )

    @property
    def domains(self) -> Collection[Domain]:
        """``/v1/domains``"""

        return Collection(self, "/v1/domains", Domain.from_json, "domains")  # type: ignore[arg-type]

    @property
    def accounts(self) -> AccountsCollection:
        """``/v1/accounts``; ``.assets(id)`` and ``.transactions(id)`` reach per-account collections."""

        return AccountsCollection(self, "/v1/accounts", Account.from_json, "accounts")  # type: ignore[arg-type]

    @property
    def asset_definitions(self) -> AssetDefinitionsCollection:
        """``/v1/assets/definitions``; ``.holders(definition_id)`` reaches the holders collection."""

        return AssetDefinitionsCollection(
            self,  # type: ignore[arg-type]
            "/v1/assets/definitions",
            AssetDefinition.from_json,
            "asset definitions",
        )

    @property
    def nfts(self) -> Collection[Nft]:
        """``/v1/nfts``"""

        return Collection(self, "/v1/nfts", Nft.from_json, "NFTs")  # type: ignore[arg-type]

    @property
    def rwas(self) -> Collection[RwaLot]:
        """``/v1/rwas`` (RWA lots)"""

        return Collection(self, "/v1/rwas", RwaLot.from_json, "RWA lots")  # type: ignore[arg-type]

    @property
    def transactions(self) -> HistoryCollection[CommittedTransaction]:
        """Every committed transaction, newest first (``POST /v1/transactions/query`` only).

        See :class:`HistoryCollection`; per-account history is
        ``accounts.transactions(account_id)``.
        """

        return HistoryCollection(
            self,  # type: ignore[arg-type]
            "/v1/transactions",
            CommittedTransaction.from_json,
            "transactions",
            "transactions",
        )

    @property
    def repo_agreements(self) -> Collection[Any]:
        """``/v1/repo/agreements`` (JSON objects; ``iroha_python`` decodes typed records)."""

        return Collection(
            self,  # type: ignore[arg-type]
            "/v1/repo/agreements",
            _json_object_row,
            "repo agreements",
        )
