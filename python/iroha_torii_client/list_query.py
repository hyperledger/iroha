"""Torii collection-query language: filters, sort keys, list queries and pages.

This is the single Python implementation of the wire contract in
``specs/torii/collection_queries.md``; the Rust reference is
``iroha_torii_shared::list_query`` and both are checked against
``fixtures/torii/list_query/vectors.json``. ``iroha_python`` re-exports this
module instead of carrying its own copy.

Build filters with :data:`F` and Python operators::

    from iroha_torii_client.list_query import F, ListQuery

    flt = (F.owned_by == "alice") & (F.quantity >= Decimal("10.5"))
    str(flt)        # 'owned_by = "alice" and quantity >= "10.5"'
    flt.to_json()   # {"op": "and", "args": [...]}

Comparisons bind more loosely than ``&``/``|`` in Python, so parenthesize each
comparison. Integers that fit ``u64``/``i64`` become JSON numbers; decimals and
wider integers become exact decimal strings. ``float`` is rejected because it
is not exact. A raw text filter (``str``) is accepted wherever a filter is and
is sent unchanged; :func:`parse_filter` turns text into a :class:`Filter`.
Object and array literals (``F.metadata.tags == ["a", "b"]``) exist only in
the JSON form: ``POST`` query bodies carry them, while :meth:`Filter.to_text`
(used for ``GET`` parameters and event streams) rejects them.
"""

from __future__ import annotations

import json
import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
from decimal import Decimal
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

__all__ = [
    "AGGREGATE_MAX_GROUP_BY",
    "AGGREGATE_MAX_METRICS",
    "CURSOR_MAX_BYTES",
    "F",
    "FIELD_PATH_MAX_BYTES",
    "FILTER_MAX_DEPTH",
    "FILTER_MAX_MEMBERSHIP_VALUES",
    "FILTER_MAX_NODES",
    "FILTER_MAX_TOTAL_MEMBERSHIP_VALUES",
    "FILTER_TEXT_MAX_BYTES",
    "LIST_QUERY_MEMBERS",
    "LIST_QUERY_PARAMETERS",
    "QUERY_ERROR_CODES",
    "SELECT_MAX_FIELDS",
    "SORT_MAX_KEYS",
    "AggregateFn",
    "AggregateMetric",
    "AggregateSpec",
    "And",
    "Comparison",
    "Exists",
    "Field",
    "Filter",
    "FilterError",
    "FilterLike",
    "FilterSyntaxError",
    "IsNull",
    "ListQuery",
    "ListQueryError",
    "Membership",
    "Not",
    "Or",
    "Page",
    "SortKey",
    "SortLike",
    "field",
    "filter_text",
    "is_decimal_text",
    "iter_items",
    "iter_pages",
    "parse_filter",
    "parse_sort",
]

#: Maximum accepted length (UTF-8 bytes) of a text filter.
FILTER_TEXT_MAX_BYTES = 32 * 1024
#: Maximum nesting depth of a filter expression (a single leaf has depth 0).
FILTER_MAX_DEPTH = 10
#: Maximum operator nodes in one filter expression.
FILTER_MAX_NODES = 1_024
#: Maximum literals accepted by one ``in`` / ``not in`` operator.
FILTER_MAX_MEMBERSHIP_VALUES = 1_024
#: Maximum membership literals across one filter expression.
FILTER_MAX_TOTAL_MEMBERSHIP_VALUES = 4_096
#: Maximum UTF-8 length of one field path.
FIELD_PATH_MAX_BYTES = 256
#: Maximum number of keys in one sort specification.
SORT_MAX_KEYS = 8
#: Maximum number of fields in one projection.
SELECT_MAX_FIELDS = 64
#: Maximum encoded length of a pagination cursor.
CURSOR_MAX_BYTES = 4096
#: Maximum number of ``group_by`` fields in one aggregate.
AGGREGATE_MAX_GROUP_BY = 8
#: Maximum number of metrics in one aggregate.
AGGREGATE_MAX_METRICS = 16
#: JSON members accepted in a ``POST /query`` body, in canonical order.
LIST_QUERY_MEMBERS = (
    "filter",
    "sort",
    "select",
    "aggregate",
    "limit",
    "cursor",
    "include_total",
)
#: URL parameters accepted by ``GET`` collection endpoints, in canonical order.
LIST_QUERY_PARAMETERS = ("filter", "sort", "select", "limit", "cursor", "include_total")
#: Torii error code for each rejected control.
QUERY_ERROR_CODES: Mapping[str, str] = {
    "query": "invalid_query",
    "filter": "invalid_filter",
    "sort": "invalid_sort",
    "select": "invalid_select",
    "aggregate": "invalid_aggregate",
    "limit": "invalid_limit",
    "cursor": "invalid_cursor",
    "include_total": "invalid_include_total",
}

_PARSE_MAX_NESTING = 64
_KEYWORDS = ("and", "or", "not", "in", "is", "null", "true", "false", "exists")
_U64_MAX = (1 << 64) - 1
_U32_MAX = (1 << 32) - 1
_I64_MIN = -(1 << 63)
_DECIMAL_TEXT = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?")
_BARE_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_CURSOR = re.compile(r"[A-Za-z0-9_-]+")
_UNSIGNED = re.compile(r"\+?[0-9]+")
_OPERATORS = "and, or, not, eq, ne, lt, lte, gt, gte, in, nin, exists, is_null"
_COMPARISON_SYMBOLS = {"eq": "=", "ne": "!=", "lt": "<", "lte": "<=", "gt": ">", "gte": ">="}
_RANGE_OPS = frozenset({"lt", "lte", "gt", "gte"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class FilterError(ValueError):
    """A filter is malformed, names an invalid field, has a bad operand or exceeds a limit."""

    def __init__(self, message: str, *, field: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.field = field

    @classmethod
    def _malformed(cls, location: str, reason: str) -> "FilterError":
        return cls(reason if not location else f"{reason} (at `{location}`)")

    @classmethod
    def _invalid_field(cls, path: str, reason: str) -> "FilterError":
        return cls(f"invalid field `{path}`: {reason}", field=path)

    @classmethod
    def _invalid_operand(cls, path: str, reason: str) -> "FilterError":
        return cls(f"invalid operand for `{path}`: {reason}", field=path)

    @classmethod
    def _limit(cls, limit: str, maximum: int) -> "FilterError":
        return cls(f"filter exceeds the {limit} limit of {maximum}")


class FilterSyntaxError(FilterError):
    """A text filter or sort specification does not parse.

    ``line`` and ``column`` are 1-based (``column`` counts characters);
    ``offset`` is the UTF-8 byte offset of the offending token.
    """

    def __init__(
        self,
        message: str,
        *,
        offset: int = 0,
        line: int = 1,
        column: int = 1,
        multiline: bool = False,
    ) -> None:
        self.offset = offset
        self.line = line
        self.column = column
        self.multiline = multiline
        super().__init__(message)
        self.message = message

    @classmethod
    def _at(cls, text: str, index: int, message: str) -> "FilterSyntaxError":
        index = max(0, min(index, len(text)))
        before = text[:index]
        line_start = before.rfind("\n") + 1
        return cls(
            message,
            offset=len(before.encode("utf-8")),
            line=before.count("\n") + 1,
            column=index - line_start + 1,
            multiline="\n" in text,
        )

    def __str__(self) -> str:
        if self.multiline:
            return f"{self.message} (line {self.line}, column {self.column})"
        return f"{self.message} (column {self.column})"


class ListQueryError(ValueError):
    """A list-query control is invalid.

    ``parameter`` is one of :data:`LIST_QUERY_MEMBERS` or ``"query"`` for the
    request as a whole; ``code`` is the matching Torii error code such as
    ``invalid_filter``.
    """

    def __init__(self, parameter: str, message: str) -> None:
        super().__init__(f"invalid `{parameter}`: {message}")
        self.parameter = parameter
        self.message = message
        #: Stable Torii error code for :attr:`parameter`.
        self.code: Optional[str] = QUERY_ERROR_CODES.get(parameter, "invalid_query")


# ---------------------------------------------------------------------------
# Literals and field paths
# ---------------------------------------------------------------------------


class _ObjectLiteral(tuple):
    """Frozen JSON object literal: ordered ``(key, value)`` pairs."""

    __slots__ = ()


Literal = Union[None, bool, int, str, Tuple[Any, ...], _ObjectLiteral]


def is_decimal_text(text: str) -> bool:
    """Whether ``text`` is a canonical decimal literal ``-?(0|[1-9][0-9]*)(\\.[0-9]+)?``."""

    return isinstance(text, str) and _DECIMAL_TEXT.fullmatch(text) is not None


def _integer_literal(value: int) -> Union[int, str]:
    return value if _I64_MIN <= value <= _U64_MAX else str(value)


def _number_text_literal(raw: str) -> Union[int, str]:
    if "." not in raw:
        return _integer_literal(int(raw))
    return raw


def _decimal_literal(value: Decimal) -> Union[int, str]:
    if not value.is_finite():
        raise TypeError("filter literals must be finite; NaN and infinity have no exact form")
    return _number_text_literal(format(value, "f"))


def _literal(value: Any) -> Literal:
    """Normalize a Python value into the exact JSON literal stored in a filter."""

    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return _integer_literal(value)
    if isinstance(value, Decimal):
        return _decimal_literal(value)
    if isinstance(value, float):
        raise TypeError(
            "float literals are inexact; pass decimal.Decimal or a decimal string such as '10.5'"
        )
    if isinstance(value, _ObjectLiteral):
        return value
    if isinstance(value, Mapping):
        pairs = []
        for key, nested in value.items():
            if not isinstance(key, str):
                raise TypeError("JSON object literal keys must be strings")
            pairs.append((key, _literal(nested)))
        return _ObjectLiteral(pairs)
    if isinstance(value, (list, tuple)):
        return tuple(_literal(item) for item in value)
    raise TypeError(
        "filter literals must be str, int, decimal.Decimal, bool, None, or JSON lists/objects; "
        f"got {type(value).__name__}"
    )


def _literal_from_json(value: Any, path: str) -> Literal:
    """Decode a literal for ``path`` from parsed JSON exactly like Torii.

    Fractional JSON numbers are rejected, also inside object and array
    literals: decimals are written as strings (``"1.5"``). JSON parsed with
    ``parse_float=decimal.Decimal`` reports them as ``Decimal``, the default
    parser as ``float``; both are refused.
    """

    if isinstance(value, (float, Decimal)):
        raise FilterError._invalid_operand(
            path, 'fractional JSON numbers are not exact; write decimals as strings such as "1.5"'
        )
    if isinstance(value, Mapping):
        return _ObjectLiteral(
            (key, _literal_from_json(nested, path)) for key, nested in value.items()
        )
    if isinstance(value, list):
        return tuple(_literal_from_json(item, path) for item in value)
    return _literal(value)


def _structured_field(expr: "Filter") -> Optional[str]:
    """Field of the first comparison against an object or array literal, if any."""

    if isinstance(expr, _Group):
        for operand in expr.operands:
            found = _structured_field(operand)
            if found is not None:
                return found
        return None
    if isinstance(expr, Not):
        return _structured_field(expr.operand)
    if isinstance(expr, Comparison):
        return expr.field if isinstance(expr.value, tuple) else None
    if isinstance(expr, Membership):
        return expr.field if any(isinstance(value, tuple) for value in expr.values) else None
    return None


def _literal_to_json(value: Literal) -> Any:
    if isinstance(value, _ObjectLiteral):
        return {key: _literal_to_json(nested) for key, nested in value}
    if isinstance(value, tuple):
        return [_literal_to_json(item) for item in value]
    return value


def _literal_key(value: Literal) -> Tuple[Any, ...]:
    """Exact identity of a literal; ``True`` and ``1`` are different literals."""

    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, int):
        return ("number", value)
    if isinstance(value, str):
        return ("string", value)
    if isinstance(value, _ObjectLiteral):
        return ("object", tuple((key, _literal_key(nested)) for key, nested in value))
    return ("array", tuple(_literal_key(item) for item in value))


def _is_numeric_literal(value: Literal) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, str) and is_decimal_text(value)


def _render_literal(value: Literal) -> str:
    return json.dumps(_literal_to_json(value), ensure_ascii=False, separators=(",", ":"))


def _validate_field_path(path: str) -> None:
    if not path:
        raise FilterError._invalid_field(path, "field paths must not be empty")
    if len(path.encode("utf-8")) > FIELD_PATH_MAX_BYTES:
        raise FilterError._invalid_field(path, "field paths must not exceed 256 bytes")
    if any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in path):
        raise FilterError._invalid_field(
            path, "field paths must not contain whitespace or control characters"
        )
    if any(not segment for segment in path.split(".")):
        raise FilterError._invalid_field(path, "field path segments must not be empty")
    # The text form quotes segments with backticks and has no escape.
    if "`" in path:
        raise FilterError._invalid_field(path, "field paths must not contain backticks")


def _is_bare_segment(segment: str, first: bool) -> bool:
    if not segment.isascii() or _BARE_SEGMENT.fullmatch(segment) is None:
        return False
    return not (first and segment.lower() in _KEYWORDS)


def _render_path(path: str) -> str:
    """Canonical text spelling of a dotted field path (backticks where needed)."""

    return ".".join(
        segment if _is_bare_segment(segment, index == 0) else f"`{segment}`"
        for index, segment in enumerate(path.split("."))
    )


def _require_path(path: Any) -> str:
    if not isinstance(path, str):
        raise TypeError(f"field paths must be strings, got {type(path).__name__}")
    return path


# ---------------------------------------------------------------------------
# Filter AST
# ---------------------------------------------------------------------------

FilterLike = Union["Filter", str]


class Filter(ABC):
    """A filter expression; build with :data:`F`, :func:`parse_filter` or the node classes.

    Combine with ``&`` (and), ``|`` (or) and ``~`` (not). Python's ``and``,
    ``or`` and ``not`` keywords cannot be overloaded, so using a filter as a
    boolean raises :class:`TypeError`.
    """

    __slots__ = ()
    op: str = ""

    # -- composition -------------------------------------------------------
    def __and__(self, other: FilterLike) -> "Filter":
        return _join(And, self, _coerce(other))

    def __rand__(self, other: FilterLike) -> "Filter":
        return _join(And, _coerce(other), self)

    def __or__(self, other: FilterLike) -> "Filter":
        return _join(Or, self, _coerce(other))

    def __ror__(self, other: FilterLike) -> "Filter":
        return _join(Or, _coerce(other), self)

    def __invert__(self) -> "Filter":
        return Not(self)

    def __bool__(self) -> bool:
        raise TypeError(
            "a filter has no truth value; combine filters with &, | and ~ "
            "(and parenthesize comparisons: (F.a == 1) & (F.b == 2))"
        )

    # -- identity ----------------------------------------------------------
    @abstractmethod
    def _key(self) -> Tuple[Any, ...]:  # pragma: no cover - overridden
        raise NotImplementedError

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Filter):
            return NotImplemented
        return type(self) is type(other) and self._key() == other._key()

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._key()))

    def __repr__(self) -> str:
        return f"Filter({str(self)!r})"

    # -- forms -------------------------------------------------------------
    def __str__(self) -> str:
        """Canonical text rendering, for display.

        :func:`parse_filter` reads it back to the same tree unless the filter
        compares against an object or array literal; :meth:`to_text` is the
        checked form for ``GET`` parameters and event streams.
        """

        out: List[str] = []
        _write_expr(self, _ROOT, out)
        return "".join(out)

    def to_text(self) -> str:
        """Canonical text form, as sent in ``GET`` parameters and event-stream filters.

        Object and array literals (valid against ``metadata.<key>`` only) exist
        only in the JSON form, so a filter containing one raises
        :class:`FilterError`; collection queries send every :class:`Filter` as
        JSON (:meth:`to_json`) and accept them.
        """

        path = _structured_field(self)
        if path is not None:
            raise FilterError._invalid_operand(
                path,
                "object and array literals have no text form; "
                "they exist only in the JSON form of a POST /query body",
            )
        return str(self)

    @abstractmethod
    def to_json(self) -> Dict[str, Any]:
        """Canonical JSON form: ``{"op": ..., "args": [...]}``."""

        raise NotImplementedError  # pragma: no cover - overridden

    @property
    def depth(self) -> int:
        """Nesting depth (a single leaf has depth 0)."""

        return 0

    def validate(self) -> None:
        """Check structural limits and operand shapes exactly like Torii.

        Raises :class:`FilterError` for the first problem in evaluation order.
        """

        _validate_rec(self, 0, _Budget())

    # -- constructors -------------------------------------------------------
    @staticmethod
    def parse(text: str) -> "Filter":
        """Parse the text form; see :func:`parse_filter`."""

        return parse_filter(text)

    @staticmethod
    def from_json(value: Any) -> "Filter":
        """Decode and validate the JSON form (or text, when ``value`` is a string)."""

        if isinstance(value, str):
            return parse_filter(value)
        return _from_json_rec(value, 0, _Budget(), [])

    @staticmethod
    def all(filters: Iterable[FilterLike]) -> Optional["Filter"]:
        """Conjunction of ``filters``, or ``None`` when there are none."""

        result: Optional[Filter] = None
        for item in filters:
            current = _coerce(item)
            result = current if result is None else result & current
        return result

    @staticmethod
    def any(filters: Iterable[FilterLike]) -> Optional["Filter"]:
        """Disjunction of ``filters``, or ``None`` when there are none."""

        result: Optional[Filter] = None
        for item in filters:
            current = _coerce(item)
            result = current if result is None else result | current
        return result


class _Group(Filter):
    __slots__ = ("operands",)
    operands: Tuple[Filter, ...]

    def __init__(self, operands: Iterable[Filter]) -> None:
        items = tuple(operands)
        for item in items:
            if not isinstance(item, Filter):
                raise TypeError(f"{self.op} operands must be Filter nodes, got {type(item).__name__}")
        object.__setattr__(self, "operands", items)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("filters are immutable")

    def __reduce__(self) -> Tuple[Any, ...]:
        return (type(self), (self.operands,))

    def _key(self) -> Tuple[Any, ...]:
        return self.operands

    def to_json(self) -> Dict[str, Any]:
        return {"op": self.op, "args": [operand.to_json() for operand in self.operands]}

    @property
    def depth(self) -> int:
        return 1 + max((operand.depth for operand in self.operands), default=0)


class And(_Group):
    """All operands match (``a and b``)."""

    __slots__ = ()
    op = "and"


class Or(_Group):
    """At least one operand matches (``a or b``)."""

    __slots__ = ()
    op = "or"


class Not(Filter):
    """The operand does not match (``not a``)."""

    __slots__ = ("operand",)
    op = "not"
    operand: Filter

    def __init__(self, operand: Filter) -> None:
        if not isinstance(operand, Filter):
            raise TypeError(f"not takes a Filter node, got {type(operand).__name__}")
        object.__setattr__(self, "operand", operand)

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("filters are immutable")

    def __reduce__(self) -> Tuple[Any, ...]:
        return (Not, (self.operand,))

    def _key(self) -> Tuple[Any, ...]:
        return (self.operand,)

    def to_json(self) -> Dict[str, Any]:
        return {"op": "not", "args": [self.operand.to_json()]}

    @property
    def depth(self) -> int:
        return 1 + self.operand.depth


class Comparison(Filter):
    """``field <op> value`` for ``op`` in ``eq``, ``ne``, ``lt``, ``lte``, ``gt``, ``gte``.

    ``ne`` also matches rows where the field is absent.
    """

    __slots__ = ("op", "field", "value")
    op: str
    field: str
    value: Literal

    def __init__(self, op: str, field: str, value: Any) -> None:
        if op not in _COMPARISON_SYMBOLS:
            raise ValueError(f"unknown comparison operator {op!r}; expected one of: {', '.join(_COMPARISON_SYMBOLS)}")
        object.__setattr__(self, "op", op)
        object.__setattr__(self, "field", _require_path(field))
        object.__setattr__(self, "value", _literal(value))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("filters are immutable")

    def __reduce__(self) -> Tuple[Any, ...]:
        return (Comparison, (self.op, self.field, _literal_to_json(self.value)))

    def _key(self) -> Tuple[Any, ...]:
        return (self.op, self.field, _literal_key(self.value))

    def to_json(self) -> Dict[str, Any]:
        return {"op": self.op, "args": [self.field, _literal_to_json(self.value)]}


class Membership(Filter):
    """``field in [values]`` (``op="in"``) or ``field not in [values]`` (``op="nin"``).

    ``nin`` also matches rows where the field is absent.
    """

    __slots__ = ("op", "field", "values")
    op: str
    field: str
    values: Tuple[Literal, ...]

    def __init__(self, op: str, field: str, values: Iterable[Any]) -> None:
        if op not in ("in", "nin"):
            raise ValueError(f"unknown membership operator {op!r}; expected 'in' or 'nin'")
        if isinstance(values, (str, bytes, bytearray, Mapping)):
            raise TypeError("membership values must be a list or tuple of literals")
        if isinstance(values, (set, frozenset)):
            raise TypeError("membership values must be ordered; pass a list or tuple, not a set")
        object.__setattr__(self, "op", op)
        object.__setattr__(self, "field", _require_path(field))
        object.__setattr__(self, "values", tuple(_literal(value) for value in values))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("filters are immutable")

    def __reduce__(self) -> Tuple[Any, ...]:
        return (
            Membership,
            (self.op, self.field, [_literal_to_json(value) for value in self.values]),
        )

    def _key(self) -> Tuple[Any, ...]:
        return (self.op, self.field, tuple(_literal_key(value) for value in self.values))

    def to_json(self) -> Dict[str, Any]:
        return {
            "op": self.op,
            "args": [self.field, [_literal_to_json(value) for value in self.values]],
        }


class _FieldPredicate(Filter):
    __slots__ = ("field",)
    field: str

    def __init__(self, field: str) -> None:
        object.__setattr__(self, "field", _require_path(field))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("filters are immutable")

    def __reduce__(self) -> Tuple[Any, ...]:
        return (type(self), (self.field,))

    def _key(self) -> Tuple[Any, ...]:
        return (self.field,)

    def to_json(self) -> Dict[str, Any]:
        return {"op": self.op, "args": [self.field]}


class Exists(_FieldPredicate):
    """The field is present (``exists(field)``)."""

    __slots__ = ()
    op = "exists"


class IsNull(_FieldPredicate):
    """The field is absent or null (``field is null``)."""

    __slots__ = ()
    op = "is_null"


def _coerce(value: Any) -> Filter:
    if isinstance(value, Filter):
        return value
    if isinstance(value, str):
        return parse_filter(value)
    if isinstance(value, Field):
        raise TypeError(
            "a bare field is not a filter; compare it, e.g. (F.a == 1), and parenthesize comparisons"
        )
    raise TypeError(f"expected a Filter or text filter, got {type(value).__name__}")


def _join(kind: type, left: Filter, right: Filter) -> Filter:
    left_items = left.operands if type(left) is kind else (left,)  # type: ignore[attr-defined]
    right_items = right.operands if type(right) is kind else (right,)  # type: ignore[attr-defined]
    return kind(left_items + right_items)


# ---------------------------------------------------------------------------
# Fluent builder
# ---------------------------------------------------------------------------


class Field:
    """A field path awaiting an operator; obtain one from :data:`F` or :func:`field`.

    ``F.metadata.tier`` and ``F["metadata.tier"]`` name the same path;
    ``F.metadata["display-name"]`` appends a segment that needs quoting in
    text. Use item access for segments that clash with method names such as
    ``exists``.
    """

    __slots__ = ("_path",)
    _path: str

    def __init__(self, path: str) -> None:
        object.__setattr__(self, "_path", _require_path(path))

    def __setattr__(self, name: str, value: Any) -> None:
        raise AttributeError("fields are immutable")

    def __reduce__(self) -> Tuple[Any, ...]:
        return (Field, (self._path,))

    @property
    def path(self) -> str:
        """The dotted path (no backticks), as used in JSON and ``select``."""

        return self._path

    def __getattr__(self, name: str) -> "Field":
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return Field(f"{self._path}.{name}")

    def __getitem__(self, segment: str) -> "Field":
        segment = _require_path(segment)
        if "." in segment:
            raise ValueError("a single path segment cannot contain `.`; index once per segment")
        return Field(f"{self._path}.{segment}")

    def __repr__(self) -> str:
        return f"F[{self._path!r}]"

    def __str__(self) -> str:
        return _render_path(self._path)

    def __bool__(self) -> bool:
        raise TypeError("a field has no truth value; compare it, e.g. (F.a == 1)")

    # Python evaluates `F.a == 1 & F.b == 2` as a chained comparison of
    # `1 & F.b`; fail loudly instead of building a wrong filter.
    def _operator_misuse(self, other: Any) -> Any:
        raise TypeError("parenthesize each comparison: (F.a == 1) & (F.b == 2)")

    __and__ = __rand__ = __or__ = __ror__ = _operator_misuse

    def __eq__(self, value: Any) -> Comparison:  # type: ignore[override]
        return Comparison("eq", self._path, value)

    def __ne__(self, value: Any) -> Comparison:  # type: ignore[override]
        return Comparison("ne", self._path, value)

    def __lt__(self, value: Any) -> Comparison:
        return Comparison("lt", self._path, value)

    def __le__(self, value: Any) -> Comparison:
        return Comparison("lte", self._path, value)

    def __gt__(self, value: Any) -> Comparison:
        return Comparison("gt", self._path, value)

    def __ge__(self, value: Any) -> Comparison:
        return Comparison("gte", self._path, value)

    __hash__ = None  # type: ignore[assignment]

    def eq(self, value: Any) -> Comparison:
        """``field = value``"""

        return Comparison("eq", self._path, value)

    def ne(self, value: Any) -> Comparison:
        """``field != value`` (also matches rows where the field is absent)."""

        return Comparison("ne", self._path, value)

    def lt(self, value: Any) -> Comparison:
        """``field < value``"""

        return Comparison("lt", self._path, value)

    def lte(self, value: Any) -> Comparison:
        """``field <= value``"""

        return Comparison("lte", self._path, value)

    def gt(self, value: Any) -> Comparison:
        """``field > value``"""

        return Comparison("gt", self._path, value)

    def gte(self, value: Any) -> Comparison:
        """``field >= value``"""

        return Comparison("gte", self._path, value)

    def in_(self, *values: Any) -> Membership:
        """``field in [values]``; pass values or one list/tuple of values."""

        return Membership("in", self._path, _membership_values(values))

    def not_in(self, *values: Any) -> Membership:
        """``field not in [values]`` (also matches rows where the field is absent)."""

        return Membership("nin", self._path, _membership_values(values))

    def exists(self) -> Exists:
        """``exists(field)``"""

        return Exists(self._path)

    def is_null(self) -> IsNull:
        """``field is null`` (absent or null)."""

        return IsNull(self._path)

    def is_not_null(self) -> Not:
        """``field is not null`` (present and not null)."""

        return Not(IsNull(self._path))

    def asc(self) -> "SortKey":
        """Ascending sort key on this field."""

        return SortKey(self._path)

    def desc(self) -> "SortKey":
        """Descending sort key on this field."""

        return SortKey(self._path, descending=True)

    def __neg__(self) -> "SortKey":
        return self.desc()

    def __pos__(self) -> "SortKey":
        return self.asc()


def _membership_values(values: Tuple[Any, ...]) -> Sequence[Any]:
    if len(values) == 1 and isinstance(values[0], (list, tuple, set, frozenset)):
        if isinstance(values[0], (set, frozenset)):
            raise TypeError("membership values must be ordered; pass a list or tuple, not a set")
        return values[0]
    return values


class _FieldNamespace:
    """Attribute-style entry point for field paths: ``F.owned_by``, ``F["metadata.x"]``."""

    __slots__ = ()

    def __getattr__(self, name: str) -> Field:
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return Field(name)

    def __getitem__(self, path: str) -> Field:
        return Field(path)

    def __call__(self, path: str) -> Field:
        return Field(path)

    def __repr__(self) -> str:
        return "F"


#: Field-path builder: ``(F.owned_by == "alice") & F.metadata.tier.in_(1, 2)``.
F = _FieldNamespace()


def field(path: str) -> Field:
    """Start a predicate or sort key on a dotted path such as ``metadata.tier``."""

    return Field(path)


def filter_text(value: FilterLike) -> str:
    """Text form of a filter: :meth:`Filter.to_text` for a tree, unchanged for raw text.

    Raises :class:`FilterError` for a tree with object or array literals,
    which have no text form.
    """

    if isinstance(value, Filter):
        return value.to_text()
    if isinstance(value, str):
        return value
    raise TypeError(f"expected a Filter or text filter, got {type(value).__name__}")


# ---------------------------------------------------------------------------
# Canonical text rendering
# ---------------------------------------------------------------------------

_ROOT, _OR, _AND, _NOT = range(4)


def _write_expr(expr: Filter, parent: int, out: List[str]) -> None:
    if isinstance(expr, _Group):
        if isinstance(expr, Or):
            keyword, me, parens = "or", _OR, parent != _ROOT
        else:
            keyword, me, parens = "and", _AND, parent in (_AND, _NOT)
        if parens:
            out.append("(")
        for index, operand in enumerate(expr.operands):
            if index:
                out.append(f" {keyword} ")
            _write_expr(operand, me, out)
        if parens:
            out.append(")")
    elif isinstance(expr, Not):
        if isinstance(expr.operand, IsNull):
            out.append(f"{_render_path(expr.operand.field)} is not null")
            return
        out.append("not ")
        _write_expr(expr.operand, _NOT, out)
    elif isinstance(expr, Comparison):
        out.append(
            f"{_render_path(expr.field)} {_COMPARISON_SYMBOLS[expr.op]} {_render_literal(expr.value)}"
        )
    elif isinstance(expr, Membership):
        keyword = "in" if expr.op == "in" else "not in"
        rendered = ", ".join(_render_literal(value) for value in expr.values)
        out.append(f"{_render_path(expr.field)} {keyword} [{rendered}]")
    elif isinstance(expr, Exists):
        out.append(f"exists({_render_path(expr.field)})")
    elif isinstance(expr, IsNull):
        out.append(f"{_render_path(expr.field)} is null")
    else:  # pragma: no cover - closed hierarchy
        raise TypeError(f"unsupported filter node {type(expr).__name__}")


# ---------------------------------------------------------------------------
# Validation and the JSON form
# ---------------------------------------------------------------------------


class _Budget:
    __slots__ = ("nodes", "membership_values")

    def __init__(self) -> None:
        self.nodes = 0
        self.membership_values = 0

    def enter(self, depth: int) -> None:
        if depth > FILTER_MAX_DEPTH:
            raise FilterError._limit("nesting depth", FILTER_MAX_DEPTH)
        self.nodes += 1
        if self.nodes > FILTER_MAX_NODES:
            raise FilterError._limit("node count", FILTER_MAX_NODES)

    def membership(self, path: str, values: Sequence[Literal]) -> None:
        if not values:
            raise FilterError._invalid_operand(path, "membership lists must not be empty")
        if len(values) > FILTER_MAX_MEMBERSHIP_VALUES:
            raise FilterError._limit("membership list size", FILTER_MAX_MEMBERSHIP_VALUES)
        self.membership_values += len(values)
        if self.membership_values > FILTER_MAX_TOTAL_MEMBERSHIP_VALUES:
            raise FilterError._limit(
                "total membership values", FILTER_MAX_TOTAL_MEMBERSHIP_VALUES
            )
        keys = [_literal_key(value) for value in values]
        if len(set(keys)) != len(keys):
            raise FilterError._invalid_operand(path, "membership list values must be unique")
        homogeneous = (
            all(isinstance(value, str) for value in values)
            or all(_is_numeric_literal(value) for value in values)
            or all(isinstance(value, bool) for value in values)
        )
        if not homogeneous and not path.startswith("metadata."):
            raise FilterError._invalid_operand(
                path, "membership list values must all be strings, numbers or booleans"
            )


def _validate_rec(expr: Filter, depth: int, budget: _Budget) -> None:
    budget.enter(depth)
    if isinstance(expr, _Group):
        if not expr.operands:
            raise FilterError(f"`{expr.op}` needs at least one operand")
        for operand in expr.operands:
            _validate_rec(operand, depth + 1, budget)
    elif isinstance(expr, Not):
        _validate_rec(expr.operand, depth + 1, budget)
    elif isinstance(expr, Comparison):
        _validate_field_path(expr.field)
        if expr.op in _RANGE_OPS:
            if not (_is_numeric_literal(expr.value) or isinstance(expr.value, str)):
                raise FilterError._invalid_operand(
                    expr.field, "range comparisons need a number, decimal or string literal"
                )
        elif isinstance(expr.value, tuple) and not expr.field.startswith("metadata."):
            raise FilterError._invalid_operand(
                expr.field, "comparison literals must be strings, numbers, booleans or null"
            )
    elif isinstance(expr, Membership):
        _validate_field_path(expr.field)
        budget.membership(expr.field, expr.values)
    elif isinstance(expr, _FieldPredicate):
        _validate_field_path(expr.field)
    else:
        raise TypeError(f"unsupported filter node {type(expr).__name__}")


def _render_location(location: List[Union[str, int]]) -> str:
    out = ""
    for segment in location:
        if isinstance(segment, int):
            out += f"[{segment}]"
        else:
            out += f".{segment}" if out else segment
    return out


def _from_json_rec(value: Any, depth: int, budget: _Budget, location: List[Union[str, int]]) -> Filter:
    def malformed(reason: str) -> FilterError:
        return FilterError._malformed(_render_location(location), reason)

    budget.enter(depth)
    if not isinstance(value, Mapping):
        raise malformed(
            'a filter node must be an object such as {"op": "eq", "args": ["field", value]}'
        )
    if "op" not in value:
        raise malformed("a filter node needs an `op` member")
    op = value["op"]
    if not isinstance(op, str):
        raise malformed("`op` must be a string")
    args = value.get("args")
    for key in value:
        if key not in ("op", "args"):
            raise malformed(f"unknown member `{key}`; a filter node has only `op` and `args`")
    location.append("args")
    parsed: Filter
    if op in ("and", "or"):
        if not isinstance(args, list):
            raise malformed(f"`{op}` takes an array of filter nodes")
        if not args:
            raise malformed(f"`{op}` needs at least one operand")
        if len(args) > max(FILTER_MAX_NODES - budget.nodes, 0):
            raise FilterError._limit("node count", FILTER_MAX_NODES)
        operands = []
        for index, nested in enumerate(args):
            location.append(index)
            operands.append(_from_json_rec(nested, depth + 1, budget, location))
            location.pop()
        # A one-operand `and`/`or` is its operand: the text form cannot spell
        # it, and both forms must decode to the same tree.
        if len(operands) == 1:
            parsed = operands[0]
        else:
            parsed = And(operands) if op == "and" else Or(operands)
    elif op == "not":
        if not isinstance(args, list) or len(args) != 1:
            raise malformed("`not` takes an array with exactly one filter node")
        location.append(0)
        inner = _from_json_rec(args[0], depth + 1, budget, location)
        location.pop()
        parsed = Not(inner)
    elif op in _COMPARISON_SYMBOLS:
        path, operand = _binary_args(args, op, malformed)
        _validate_field_path(path)
        parsed = Comparison(op, path, _literal_from_json(operand, path))
        _validate_rec(parsed, 0, _Budget())
    elif op in ("in", "nin"):
        path, operand = _binary_args(args, op, malformed)
        if not isinstance(operand, list):
            raise malformed(f'`{op}` takes ["field", [value, ...]]')
        _validate_field_path(path)
        values = tuple(_literal_from_json(item, path) for item in operand)
        budget.membership(path, values)
        parsed = Membership(op, path, values)
    elif op in ("exists", "is_null"):
        if not isinstance(args, list) or len(args) != 1:
            raise malformed(f'`{op}` takes ["field"]')
        if not isinstance(args[0], str):
            raise malformed("the field must be a string")
        _validate_field_path(args[0])
        parsed = Exists(args[0]) if op == "exists" else IsNull(args[0])
    else:
        location.pop()
        raise malformed(f"unknown operator `{op}`; expected one of: {_OPERATORS}")
    location.pop()
    return parsed


def _binary_args(args: Any, op: str, malformed: Callable[[str], FilterError]) -> Tuple[str, Any]:
    if not isinstance(args, list) or len(args) != 2:
        raise malformed(f'`{op}` takes ["field", value]')
    if not isinstance(args[0], str):
        raise malformed("the first argument must be the field name")
    return args[0], args[1]


# ---------------------------------------------------------------------------
# Text grammar
# ---------------------------------------------------------------------------
#
#   filter     := or
#   or         := and ("or" and)*
#   and        := unary ("and" unary)*
#   unary      := "not" unary | primary
#   primary    := "(" filter ")" | "exists" "(" path ")" | path predicate
#   predicate  := compare literal | ["not"] "in" list | "is" ["not"] "null"
#   compare    := "=" | "==" | "!=" | "<>" | "<" | "<=" | ">" | ">="
#   list       := "[" literal ("," literal)* [","] "]" | "(" ... ")"
#   literal    := string | number | "true" | "false" | "null"
#   path       := segment ("." segment)*
#   segment    := [A-Za-z_][A-Za-z0-9_]* | "`" any character except "`" "`"
#   number     := "-"? ("0" | [1-9][0-9]*) ("." [0-9]+)?
#   sort       := key ("," key)*        key := ["-"] path

_WORD, _QUOTED, _STR, _NUMBER, _COMPARE = "word", "quoted", "str", "number", "compare"
_MINUS, _LPAREN, _RPAREN, _LBRACKET, _RBRACKET = "-", "(", ")", "[", "]"
_COMMA, _DOT, _END = ",", ".", "end"
_ASCII_DIGITS = frozenset("0123456789")
_ASCII_LETTERS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
_WORD_START = _ASCII_LETTERS | {"_"}
_WORD_CHARS = _WORD_START | _ASCII_DIGITS
_HEX = frozenset("0123456789abcdefABCDEF")


@dataclass(frozen=True)
class _Token:
    kind: str
    start: int
    text: str = ""

    def describe(self) -> str:
        if self.kind in (_WORD, _QUOTED):
            return f"`{self.text}`"
        if self.kind == _STR:
            return "a string literal"
        if self.kind == _NUMBER:
            return f"the number `{self.text}`"
        if self.kind == _COMPARE:
            return "a comparison operator"
        if self.kind == _END:
            return "the end of the input"
        return f"`{self.kind}`"

    def keyword(self) -> Optional[str]:
        if self.kind != _WORD:
            return None
        lowered = self.text.lower()
        return lowered if lowered in _KEYWORDS else None

    def is_keyword(self, keyword: str) -> bool:
        return self.kind == _WORD and self.text.lower() == keyword


class _Lexer:
    def __init__(self, text: str, allow_minus: bool) -> None:
        self.text = text
        self.position = 0
        self.allow_minus = allow_minus

    def error(self, index: int, message: str) -> FilterSyntaxError:
        return FilterSyntaxError._at(self.text, index, message)

    def peek(self, ahead: int = 0) -> str:
        index = self.position + ahead
        return self.text[index] if index < len(self.text) else ""

    def tokens(self) -> List[_Token]:
        out = []
        while True:
            token = self.next_token()
            out.append(token)
            if token.kind == _END:
                return out

    def next_token(self) -> _Token:
        text = self.text
        while self.position < len(text) and text[self.position] in " \t\r\n":
            self.position += 1
        start = self.position
        if start >= len(text):
            return _Token(_END, start)
        ch = text[start]
        if ch in "()[],":
            self.position += 1
            return _Token(ch, start)
        if ch == ".":
            if self.peek(1) in _ASCII_DIGITS and self.peek(1):
                raise self.error(start, "decimal literals need a leading digit, e.g. `0.5`")
            self.position += 1
            return _Token(_DOT, start)
        if ch == "=":
            self.position += 2 if self.peek(1) == "=" else 1
            return _Token(_COMPARE, start, "eq")
        if ch == "!":
            if self.peek(1) == "=":
                self.position += 2
                return _Token(_COMPARE, start, "ne")
            raise self.error(start, "use the keyword `not` instead of `!`")
        if ch == "<":
            following = self.peek(1)
            if following == "=":
                self.position += 2
                return _Token(_COMPARE, start, "lte")
            if following == ">":
                self.position += 2
                return _Token(_COMPARE, start, "ne")
            self.position += 1
            return _Token(_COMPARE, start, "lt")
        if ch == ">":
            if self.peek(1) == "=":
                self.position += 2
                return _Token(_COMPARE, start, "gte")
            self.position += 1
            return _Token(_COMPARE, start, "gt")
        if ch == "&":
            raise self.error(start, "use the keyword `and` instead of `&` or `&&`")
        if ch == "|":
            raise self.error(start, "use the keyword `or` instead of `|` or `||`")
        if ch in "\"'":
            return self.string(ch)
        if ch == "`":
            return self.quoted_segment()
        if ch == "-":
            if self.peek(1) and self.peek(1) in _ASCII_DIGITS:
                return self.number()
            if self.allow_minus:
                self.position += 1
                return _Token(_MINUS, start)
            raise self.error(
                start,
                "unexpected `-`; quote field names that contain `-` with backticks, e.g. `display-name`",
            )
        if ch in _ASCII_DIGITS:
            return self.number()
        if ch in _WORD_START:
            end = start + 1
            while end < len(text) and text[end] in _WORD_CHARS:
                end += 1
            self.position = end
            if self.peek() == "-" and self.peek(1) and self.peek(1) in _ASCII_LETTERS:
                word_end = end
                while word_end < len(text) and (text[word_end] in _WORD_CHARS or text[word_end] == "-"):
                    word_end += 1
                raise self.error(
                    start,
                    f"wrap field names containing `-` in backticks, e.g. `{text[start:word_end]}`",
                )
            return _Token(_WORD, start, text[start:end])
        if ch == ":":
            if self.allow_minus:
                raise self.error(
                    start,
                    "unexpected `:`; write `field` for ascending and `-field` for descending order",
                )
            raise self.error(start, 'unexpected `:`; compare values with `=`, e.g. `status = "active"`')
        raise self.error(start, f"unexpected character `{ch}`")

    def number(self) -> _Token:
        text = self.text
        start = self.position
        end = start
        if end < len(text) and text[end] == "-":
            end += 1
        integer_start = end
        while end < len(text) and text[end] in _ASCII_DIGITS:
            end += 1
        if end - integer_start > 1 and text[integer_start] == "0":
            raise self.error(start, "numbers must not have leading zeros")
        if end < len(text) and text[end] == ".":
            end += 1
            fraction_start = end
            while end < len(text) and text[end] in _ASCII_DIGITS:
                end += 1
            if end == fraction_start:
                raise self.error(start, "decimal literals need digits after `.`")
        following = text[end] if end < len(text) else ""
        if following in ("e", "E"):
            raise self.error(
                start, "exponent notation is not supported; write the full decimal value"
            )
        if following and (following in _ASCII_LETTERS or following == "_"):
            raise self.error(
                start, "a number cannot be followed directly by letters; quote text values"
            )
        self.position = end
        return _Token(_NUMBER, start, text[start:end])

    def string(self, quote: str) -> _Token:
        text = self.text
        start = self.position
        out: List[str] = []
        index = start + 1
        while True:
            if index >= len(text):
                raise self.error(start, "unterminated string literal")
            ch = text[index]
            if ch == quote:
                self.position = index + 1
                return _Token(_STR, start, "".join(out))
            if ch == "\\":
                escape_at = index
                if index + 1 >= len(text):
                    raise self.error(escape_at, "unterminated escape sequence")
                escaped = text[index + 1]
                index += 2
                simple = {
                    '"': '"',
                    "'": "'",
                    "\\": "\\",
                    "/": "/",
                    "b": "\b",
                    "f": "\f",
                    "n": "\n",
                    "r": "\r",
                    "t": "\t",
                }
                if escaped in simple:
                    out.append(simple[escaped])
                elif escaped == "u":
                    decoded, index = self.unicode_escape(index, escape_at)
                    out.append(decoded)
                else:
                    raise self.error(escape_at, f"unknown escape sequence `\\{escaped}`")
                continue
            # As in JSON, only U+0000..U+001F must be escaped; DEL and C1
            # characters stay literal, so every rendered literal parses.
            if ch < "\x20":
                raise self.error(index, "control characters must be escaped inside string literals")
            out.append(ch)
            index += 1

    def unicode_escape(self, index: int, at: int) -> Tuple[str, int]:
        text = self.text

        def invalid() -> FilterSyntaxError:
            return self.error(at, "invalid `\\u` escape; expected four hexadecimal digits")

        def unpaired() -> FilterSyntaxError:
            return self.error(at, "unpaired UTF-16 surrogate in `\\u` escape")

        def read_unit(position: int) -> Tuple[Optional[int], int]:
            digits = text[position : position + 4]
            if len(digits) != 4 or any(digit not in _HEX for digit in digits):
                return None, position
            return int(digits, 16), position + 4

        first, index = read_unit(index)
        if first is None:
            raise invalid()
        if 0xD800 <= first < 0xDC00:
            if text[index : index + 2] != "\\u":
                raise unpaired()
            second, index = read_unit(index + 2)
            if second is None:
                raise invalid()
            if not 0xDC00 <= second < 0xE000:
                raise unpaired()
            return chr(0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00)), index
        if 0xDC00 <= first < 0xE000:
            raise unpaired()
        return chr(first), index

    def quoted_segment(self) -> _Token:
        text = self.text
        start = self.position
        end = text.find("`", start + 1)
        if end < 0:
            raise self.error(start, "unterminated backtick-quoted field name")
        segment = text[start + 1 : end]
        if not segment:
            raise self.error(start, "backtick-quoted field names must not be empty")
        if "." in segment:
            raise self.error(
                start,
                "a backtick-quoted segment must not contain `.`; quote each segment separately",
            )
        self.position = end + 1
        return _Token(_QUOTED, start, segment)


class _Parser:
    def __init__(self, text: str, allow_minus: bool) -> None:
        self.text = text
        self.tokens = _Lexer(text, allow_minus).tokens()
        self.position = 0
        self.nesting = 0

    def peek(self, ahead: int = 0) -> _Token:
        return self.tokens[min(self.position + ahead, len(self.tokens) - 1)]

    def advance(self) -> _Token:
        token = self.peek()
        if token.kind != _END:
            self.position += 1
        return token

    def error_at(self, token: _Token, message: str) -> FilterSyntaxError:
        return FilterSyntaxError._at(self.text, token.start, message)

    def enter(self, token: _Token) -> None:
        self.nesting += 1
        if self.nesting > _PARSE_MAX_NESTING:
            raise self.error_at(token, "filter nests too deeply")

    def filter(self) -> Filter:
        first = self.conjunction()
        if not self.peek().is_keyword("or"):
            return first
        operands = [first]
        while self.peek().is_keyword("or"):
            self.advance()
            operands.append(self.conjunction())
        return Or(operands)

    def conjunction(self) -> Filter:
        first = self.unary()
        if not self.peek().is_keyword("and"):
            return first
        operands = [first]
        while self.peek().is_keyword("and"):
            self.advance()
            operands.append(self.unary())
        return And(operands)

    def unary(self) -> Filter:
        if self.peek().is_keyword("not"):
            token = self.advance()
            self.enter(token)
            inner = self.unary()
            self.nesting -= 1
            return Not(inner)
        return self.primary()

    def primary(self) -> Filter:
        token = self.peek()
        if token.kind == _LPAREN:
            self.advance()
            self.enter(token)
            inner = self.filter()
            self.nesting -= 1
            self.expect_close(_RPAREN, token)
            return inner
        if token.is_keyword("exists") and self.peek(1).kind == _LPAREN:
            self.advance()
            opening = self.advance()
            path = self.path()
            self.expect_close(_RPAREN, opening)
            return Exists(path)
        if token.kind in (_WORD, _QUOTED):
            return self.predicate(self.path())
        if token.kind in (_STR, _NUMBER):
            raise self.error_at(
                token, "expected a field name on the left-hand side, e.g. `quantity > 5`"
            )
        if token.kind == _END:
            raise self.error_at(token, "expected a filter expression")
        raise self.error_at(token, f"expected a field name, found {token.describe()}")

    def expect_close(self, close: str, opening: _Token) -> None:
        token = self.advance()
        if token.kind == close:
            return
        symbol, opened = ("`)`", "`(`") if close == _RPAREN else ("`]`", "`[`")
        column = FilterSyntaxError._at(self.text, opening.start, "").column
        raise self.error_at(
            token,
            f"expected {symbol} to close the {opened} at column {column}, found {token.describe()}",
        )

    def path(self) -> str:
        first = self.advance()
        if first.kind == _WORD:
            keyword = first.keyword()
            if keyword is not None:
                raise self.error_at(
                    first,
                    f"expected a field name, found the keyword `{keyword}`; "
                    f"quote a field with this name as `{first.text}` in backticks",
                )
            path = first.text
        elif first.kind == _QUOTED:
            path = first.text
        else:
            raise self.error_at(first, f"expected a field name, found {first.describe()}")
        while self.peek().kind == _DOT:
            self.advance()
            segment = self.advance()
            if segment.kind not in (_WORD, _QUOTED):
                raise self.error_at(
                    segment, f"expected a field name after `.`, found {segment.describe()}"
                )
            path = f"{path}.{segment.text}"
        try:
            _validate_field_path(path)
        except FilterError as error:
            raise self.error_at(first, error.message) from None
        return path

    def predicate(self, path: str) -> Filter:
        token = self.advance()
        if token.kind == _COMPARE:
            return Comparison(token.text, path, self.literal())
        if token.is_keyword("in"):
            return Membership("in", path, self.value_list())
        if token.is_keyword("not"):
            following = self.advance()
            if following.is_keyword("in"):
                return Membership("nin", path, self.value_list())
            raise self.error_at(following, "expected `in` after `not` (as in `field not in [...]`)")
        if token.is_keyword("is"):
            following = self.advance()
            if following.is_keyword("null"):
                return IsNull(path)
            if following.is_keyword("not"):
                null = self.advance()
                if null.is_keyword("null"):
                    return Not(IsNull(path))
                raise self.error_at(null, "expected `null` after `is not`")
            raise self.error_at(
                following, "expected `null` or `not null` after `is`; compare values with `=`"
            )
        expected = (
            f"expected an operator after `{_render_path(path)}` "
            "(=, !=, <, <=, >, >=, in, not in, is null)"
        )
        if token.kind == _END:
            raise self.error_at(token, expected)
        raise self.error_at(token, f"{expected}, found {token.describe()}")

    def value_list(self) -> List[Literal]:
        opening = self.advance()
        if opening.kind == _LBRACKET:
            close = _RBRACKET
        elif opening.kind == _LPAREN:
            close = _RPAREN
        else:
            raise self.error_at(
                opening, f"expected `[` to start a value list, found {opening.describe()}"
            )
        values: List[Literal] = []
        while True:
            if self.peek().kind == close:
                if not values:
                    raise self.error_at(self.peek(), "value lists must not be empty")
                self.advance()
                return values
            values.append(self.literal())
            separator = self.peek()
            if separator.kind == _COMMA:
                self.advance()
            elif separator.kind != close:
                self.expect_close(close, opening)
                return values  # pragma: no cover - expect_close always raises here

    def literal(self) -> Literal:
        token = self.advance()
        if token.kind == _STR:
            return token.text
        if token.kind == _NUMBER:
            return _number_text_literal(token.text)
        if token.is_keyword("true"):
            return True
        if token.is_keyword("false"):
            return False
        if token.is_keyword("null"):
            return None
        if token.kind == _WORD:
            raise self.error_at(
                token,
                f'expected a literal value, found `{token.text}`; quote text values, e.g. "{token.text}"',
            )
        raise self.error_at(token, f"expected a literal value, found {token.describe()}")

    def finish(self) -> None:
        token = self.peek()
        if token.kind == _END:
            return
        hint = "; combine conditions with `and` or `or`" if token.kind in (_WORD, _QUOTED) else ""
        raise self.error_at(token, f"unexpected {token.describe()} after a complete filter{hint}")


def _index_of_byte_offset(text: str, offset: int) -> int:
    return len(text.encode("utf-8")[:offset].decode("utf-8", "ignore"))


def parse_filter(text: str) -> Filter:
    """Parse the text form, e.g. ``owned_by = "alice" and quantity >= 10``.

    Raises :class:`FilterSyntaxError` with the line and column of the
    offending token and a suggested fix when one is obvious.
    """

    if not isinstance(text, str):
        raise TypeError(f"text filters must be strings, got {type(text).__name__}")
    if len(text.encode("utf-8")) > FILTER_TEXT_MAX_BYTES:
        raise FilterSyntaxError._at(
            text,
            _index_of_byte_offset(text, FILTER_TEXT_MAX_BYTES),
            f"filters must not exceed {FILTER_TEXT_MAX_BYTES} bytes",
        )
    if not text.strip():
        raise FilterSyntaxError._at(text, 0, "expected a filter expression")
    parser = _Parser(text, allow_minus=False)
    expr = parser.filter()
    parser.finish()
    try:
        expr.validate()
    except FilterError as error:
        raise FilterSyntaxError(error.message) from None
    return expr


# ---------------------------------------------------------------------------
# Sort keys
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SortKey:
    """One sort key: ``SortKey("quantity", descending=True)`` renders ``-quantity``."""

    field: str
    descending: bool = False

    def __post_init__(self) -> None:
        _require_path(self.field)
        if not isinstance(self.descending, bool):
            raise TypeError("SortKey.descending must be a bool")

    def __str__(self) -> str:
        return ("-" if self.descending else "") + _render_path(self.field)

    @classmethod
    def parse(cls, text: str) -> "SortKey":
        """Parse exactly one key such as ``-quantity``."""

        keys = parse_sort(text)
        if len(keys) != 1:
            raise FilterSyntaxError._at(
                text, 0, "expected exactly one sort key; pass each key as its own array element"
            )
        return keys[0]


SortLike = Union[SortKey, Field, str]


def parse_sort(text: str) -> Tuple[SortKey, ...]:
    """Parse a sort specification such as ``-quantity,id``."""

    if not isinstance(text, str):
        raise TypeError(f"sort specifications must be strings, got {type(text).__name__}")
    if not text.strip():
        raise FilterSyntaxError._at(text, 0, "expected at least one sort key")
    parser = _Parser(text, allow_minus=True)
    keys: List[SortKey] = []
    while True:
        token = parser.peek()
        descending = token.kind == _MINUS
        if descending:
            parser.advance()
        path = parser.path()
        if any(existing.field == path for existing in keys):
            raise parser.error_at(token, f"sort key `{_render_path(path)}` appears more than once")
        keys.append(SortKey(path, descending))
        if len(keys) > SORT_MAX_KEYS:
            raise parser.error_at(token, f"sort specifications accept at most {SORT_MAX_KEYS} keys")
        following = parser.advance()
        if following.kind == _END:
            return tuple(keys)
        if following.kind == _COMMA:
            continue
        if following.kind == _WORD and following.text.lower() in ("asc", "desc"):
            raise parser.error_at(
                following, "write `field` for ascending and `-field` for descending order"
            )
        raise parser.error_at(following, f"expected `,` between sort keys, found {following.describe()}")


def _sort_keys(value: Union[None, SortLike, Iterable[SortLike]]) -> Tuple[SortKey, ...]:
    if value is None:
        return ()
    if isinstance(value, (SortKey, Field)):
        value = (value,)
    elif isinstance(value, str):
        return parse_sort(value)
    keys: List[SortKey] = []
    for item in value:
        if isinstance(item, SortKey):
            keys.append(item)
        elif isinstance(item, Field):
            keys.append(item.asc())
        elif isinstance(item, str):
            keys.append(SortKey.parse(item))
        else:
            raise TypeError(
                f"sort keys must be SortKey, Field or strings such as '-quantity', got {type(item).__name__}"
            )
    return tuple(keys)


# ---------------------------------------------------------------------------
# Aggregates
# ---------------------------------------------------------------------------


class AggregateFn(str, Enum):
    """Aggregate function applied to each group."""

    COUNT = "count"
    SUM = "sum"
    MIN = "min"
    MAX = "max"
    AVG = "avg"
    DISTINCT_COUNT = "distinct_count"


@dataclass(frozen=True)
class AggregateMetric:
    """One metric per group; ``alias`` names the output column (usable in ``having``/``sort``)."""

    alias: str
    fn: AggregateFn
    field: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.alias, str):
            raise TypeError("AggregateMetric.alias must be a string")
        if isinstance(self.fn, str) and not isinstance(self.fn, AggregateFn):
            try:
                object.__setattr__(self, "fn", AggregateFn(self.fn))
            except ValueError:
                raise ValueError(
                    f"unknown aggregate function `{self.fn}`; expected one of: "
                    + ", ".join(item.value for item in AggregateFn)
                ) from None
        elif not isinstance(self.fn, AggregateFn):
            raise TypeError("AggregateMetric.fn must be an AggregateFn")
        if isinstance(self.field, Field):
            object.__setattr__(self, "field", self.field.path)
        elif self.field is not None:
            _require_path(self.field)

    def to_json(self) -> Dict[str, Any]:
        """JSON form used inside ``aggregate.metrics``."""

        payload: Dict[str, Any] = {"alias": self.alias, "fn": self.fn.value}
        if self.field is not None:
            payload["field"] = self.field
        return payload

    @classmethod
    def from_json(cls, value: Any) -> "AggregateMetric":
        """Decode one metric object."""

        if not isinstance(value, Mapping):
            raise ValueError('a metric must be an object such as {"alias": "n", "fn": "count"}')
        unknown = [key for key in value if key not in ("alias", "fn", "field")]
        if unknown:
            raise ValueError(f"unknown metric member `{unknown[0]}`; expected alias, fn, field")
        alias, fn, path = value.get("alias"), value.get("fn"), value.get("field")
        if not isinstance(alias, str):
            raise ValueError("metric `alias` must be a string")
        if not isinstance(fn, str):
            raise ValueError("metric `fn` must be a string")
        if path is not None and not isinstance(path, str):
            raise ValueError("metric `field` must be a string")
        return cls(alias, fn, path)  # type: ignore[arg-type]


@dataclass(frozen=True)
class AggregateSpec:
    """``group_by`` dimensions, ``metrics`` and an optional ``having`` filter (POST only).

    Aggregates are computed where the rows live: Torii rejects a read whose
    visible rows span several dataspace routes with ``invalid_aggregate``
    (overlapping routes cannot be summed exactly); page through the rows
    without ``aggregate`` instead. History collections (transactions) reject
    aggregates outright.
    """

    metrics: Tuple[AggregateMetric, ...]
    group_by: Tuple[str, ...] = ()
    having: Optional[FilterLike] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "metrics", tuple(self.metrics))
        for metric in self.metrics:
            if not isinstance(metric, AggregateMetric):
                raise TypeError("AggregateSpec.metrics must contain AggregateMetric values")
        if isinstance(self.group_by, (str, Field)):
            raise TypeError("AggregateSpec.group_by must be a sequence of field paths")
        object.__setattr__(
            self,
            "group_by",
            tuple(item.path if isinstance(item, Field) else _require_path(item) for item in self.group_by),
        )
        if self.having is not None and not isinstance(self.having, (Filter, str)):
            raise TypeError("AggregateSpec.having must be a Filter or text filter")

    def to_json(self) -> Dict[str, Any]:
        """JSON form of the ``aggregate`` member."""

        payload: Dict[str, Any] = {
            "group_by": list(self.group_by),
            "metrics": [metric.to_json() for metric in self.metrics],
        }
        if self.having is not None:
            payload["having"] = (
                self.having.to_json() if isinstance(self.having, Filter) else self.having
            )
        return payload

    @classmethod
    def from_json(cls, value: Any) -> "AggregateSpec":
        """Decode the ``aggregate`` member; text ``having`` filters are parsed."""

        if not isinstance(value, Mapping):
            raise ValueError("`aggregate` must be an object with `group_by`, `metrics` and `having`")
        unknown = [key for key in value if key not in ("group_by", "metrics", "having")]
        if unknown:
            raise ValueError(
                f"unknown aggregate member `{unknown[0]}`; expected group_by, metrics, having"
            )
        group_by = value.get("group_by") or []
        metrics = value.get("metrics") or []
        if not isinstance(group_by, list) or not all(isinstance(item, str) for item in group_by):
            raise ValueError("`group_by` must be an array of field names")
        if not isinstance(metrics, list):
            raise ValueError("`metrics` must be an array of metric objects")
        having_value = value.get("having")
        having = None if having_value is None else Filter.from_json(having_value)
        return cls(
            tuple(AggregateMetric.from_json(metric) for metric in metrics),
            tuple(group_by),
            having,
        )


# ---------------------------------------------------------------------------
# List queries
# ---------------------------------------------------------------------------


def _select_fields(value: Any) -> Optional[Tuple[str, ...]]:
    if value is None:
        return None
    if isinstance(value, (str, Field)):
        raise TypeError("select must be a sequence of field paths such as ['id', 'quantity']")
    return tuple(item.path if isinstance(item, Field) else _require_path(item) for item in value)


@dataclass(frozen=True)
class ListQuery:
    """Filter, ordering, projection and page controls for one collection read.

    ``sort`` accepts :class:`SortKey`/:class:`Field` values or key strings such
    as ``"-quantity"``; ``select`` accepts paths or fields. Instances are
    immutable; derive variants with :meth:`replace` or :meth:`with_cursor`.
    """

    filter: Optional[FilterLike] = None
    sort: Tuple[SortKey, ...] = ()
    select: Optional[Tuple[str, ...]] = None
    aggregate: Optional[AggregateSpec] = None
    limit: Optional[int] = None
    cursor: Optional[str] = None
    include_total: bool = False

    def __post_init__(self) -> None:
        if self.filter is not None and not isinstance(self.filter, (Filter, str)):
            raise TypeError("ListQuery.filter must be a Filter, a text filter or None")
        try:
            sort_keys = _sort_keys(self.sort)
        except FilterError as error:
            raise ListQueryError("sort", str(error)) from None
        object.__setattr__(self, "sort", sort_keys)
        object.__setattr__(self, "select", _select_fields(self.select))
        if self.aggregate is not None and not isinstance(self.aggregate, AggregateSpec):
            raise TypeError("ListQuery.aggregate must be an AggregateSpec")
        if self.limit is not None and (isinstance(self.limit, bool) or not isinstance(self.limit, int)):
            raise TypeError("ListQuery.limit must be an integer")
        if self.cursor is not None and not isinstance(self.cursor, str):
            raise TypeError("ListQuery.cursor must be a string")
        if not isinstance(self.include_total, bool):
            raise TypeError("ListQuery.include_total must be a bool")

    def replace(self, **changes: Any) -> "ListQuery":
        """Copy with some controls changed."""

        return replace(self, **changes)

    def with_cursor(self, cursor: Optional[str]) -> "ListQuery":
        """The same query positioned at ``cursor``."""

        return replace(self, cursor=cursor)

    def next_page(self, page: "Page[Any]") -> Optional["ListQuery"]:
        """The same query positioned after ``page``, or ``None`` on the last page."""

        return None if page.next_cursor is None else self.with_cursor(page.next_cursor)

    def validate(self) -> None:
        """Check every control without contacting a server; raises :class:`ListQueryError`."""

        if isinstance(self.filter, Filter):
            try:
                self.filter.validate()
            except FilterError as error:
                raise ListQueryError("filter", str(error)) from None
        _validate_sort(self.sort)
        if self.select is not None:
            _validate_select(self.select)
        if self.select is not None and self.aggregate is not None:
            raise ListQueryError(
                "select",
                "`select` and `aggregate` cannot be combined; aggregates define their own columns",
            )
        if self.aggregate is not None:
            if not self.aggregate.metrics:
                raise ListQueryError("aggregate", "`metrics` must list at least one metric")
            if len(self.aggregate.group_by) > AGGREGATE_MAX_GROUP_BY:
                raise ListQueryError(
                    "aggregate", f"`group_by` lists at most {AGGREGATE_MAX_GROUP_BY} fields"
                )
            if len(self.aggregate.metrics) > AGGREGATE_MAX_METRICS:
                raise ListQueryError(
                    "aggregate", f"`metrics` lists at most {AGGREGATE_MAX_METRICS} metrics"
                )
            metric_fields = [m.field for m in self.aggregate.metrics if m.field is not None]
            for path in (*self.aggregate.group_by, *metric_fields):
                try:
                    _validate_field_path(path)
                except FilterError as error:
                    raise ListQueryError("aggregate", str(error)) from None
            if isinstance(self.aggregate.having, Filter):
                try:
                    self.aggregate.having.validate()
                except FilterError as error:
                    raise ListQueryError("aggregate", f"having: {error}") from None
        if self.limit is not None:
            _limit_value(self.limit)
        if self.cursor is not None:
            _validate_cursor(self.cursor)

    def to_json(self) -> Dict[str, Any]:
        """Canonical ``POST /v1/<collection>/query`` body (absent controls omitted)."""

        body: Dict[str, Any] = {}
        if self.filter is not None:
            body["filter"] = self.filter.to_json() if isinstance(self.filter, Filter) else self.filter
        if self.sort:
            body["sort"] = [str(key) for key in self.sort]
        if self.select is not None:
            body["select"] = list(self.select)
        if self.aggregate is not None:
            body["aggregate"] = self.aggregate.to_json()
        if self.limit is not None:
            body["limit"] = self.limit
        if self.cursor is not None:
            body["cursor"] = self.cursor
        if self.include_total:
            body["include_total"] = True
        return body

    def to_query_pairs(self) -> List[Tuple[str, str]]:
        """``GET`` parameters in canonical order (not yet percent-encoded).

        Aggregates and filters with object or array literals exist only in the
        ``POST`` body and raise :class:`ListQueryError`.
        """

        if self.aggregate is not None:
            raise ListQueryError("aggregate", "aggregates are only available through POST /query")
        pairs: List[Tuple[str, str]] = []
        if self.filter is not None:
            try:
                pairs.append(("filter", filter_text(self.filter)))
            except FilterError as error:
                raise ListQueryError("filter", str(error)) from None
        if self.sort:
            pairs.append(("sort", ",".join(str(key) for key in self.sort)))
        if self.select is not None:
            pairs.append(("select", ",".join(self.select)))
        if self.limit is not None:
            pairs.append(("limit", str(self.limit)))
        if self.cursor is not None:
            pairs.append(("cursor", self.cursor))
        if self.include_total:
            pairs.append(("include_total", "true"))
        return pairs

    @classmethod
    def from_json(cls, value: Any) -> "ListQuery":
        """Decode and validate a ``POST /query`` body exactly like Torii.

        Text filters are parsed, so the result always carries :class:`Filter`
        trees. Raises :class:`ListQueryError` naming the offending member.
        """

        if not isinstance(value, Mapping):
            raise ListQueryError(
                "query",
                'the request body must be a JSON object such as {"filter": "...", "limit": 50}',
            )
        changes: Dict[str, Any] = {}
        for key, member in value.items():
            if key == "filter":
                if member is not None:
                    try:
                        changes["filter"] = Filter.from_json(member)
                    except (FilterError, TypeError) as error:
                        raise ListQueryError("filter", str(error)) from None
            elif key == "sort":
                changes["sort"] = _sort_from_json(member)
            elif key == "select":
                if member is not None:
                    if not isinstance(member, list):
                        raise ListQueryError(
                            "select",
                            '`select` must be an array of field names such as ["id", "quantity"]',
                        )
                    if not all(isinstance(item, str) for item in member):
                        raise ListQueryError("select", "`select` must be an array of field names")
                    changes["select"] = tuple(member)
            elif key == "aggregate":
                if member is not None:
                    try:
                        changes["aggregate"] = AggregateSpec.from_json(member)
                    except (FilterError, TypeError, ValueError) as error:
                        raise ListQueryError("aggregate", str(error)) from None
            elif key == "limit":
                if member is not None:
                    if isinstance(member, bool) or not isinstance(member, int) or member < 0:
                        raise ListQueryError("limit", "`limit` must be a positive integer")
                    changes["limit"] = _limit_value(member)
            elif key == "cursor":
                if member is not None:
                    if not isinstance(member, str):
                        raise ListQueryError(
                            "cursor", "`cursor` must be the string returned as `next_cursor`"
                        )
                    changes["cursor"] = member
            elif key == "include_total":
                if member is not None:
                    if not isinstance(member, bool):
                        raise ListQueryError(
                            "include_total", "`include_total` must be true or false"
                        )
                    changes["include_total"] = member
            else:
                raise ListQueryError(
                    "query",
                    f"unknown member `{key}`; expected one of: {', '.join(LIST_QUERY_MEMBERS)}",
                )
        query = cls(**changes)
        query.validate()
        return query

    @classmethod
    def from_query_pairs(cls, pairs: Iterable[Tuple[str, str]]) -> "ListQuery":
        """Decode already percent-decoded ``GET`` parameters exactly like Torii."""

        changes: Dict[str, Any] = {}
        seen = set()
        for key, value in pairs:
            if key not in LIST_QUERY_PARAMETERS:
                hint = "; aggregates are only available through POST /query" if key == "aggregate" else ""
                raise ListQueryError(
                    "query",
                    f"unknown parameter `{key}`; expected one of: {', '.join(LIST_QUERY_PARAMETERS)}{hint}",
                )
            if key in seen:
                raise ListQueryError(key, f"`{key}` must appear at most once")
            seen.add(key)
            if key == "filter":
                try:
                    changes["filter"] = parse_filter(value)
                except FilterError as error:
                    raise ListQueryError("filter", str(error)) from None
            elif key == "sort":
                try:
                    changes["sort"] = parse_sort(value)
                except FilterError as error:
                    raise ListQueryError("sort", str(error)) from None
            elif key == "select":
                changes["select"] = tuple(item.strip() for item in value.split(","))
            elif key == "limit":
                if _UNSIGNED.fullmatch(value) is None or int(value) > _U64_MAX:
                    raise ListQueryError("limit", f"`limit` must be a positive integer, got `{value}`")
                changes["limit"] = _limit_value(int(value))
            elif key == "cursor":
                changes["cursor"] = value
            elif value in ("true", "false"):
                changes["include_total"] = value == "true"
            else:
                raise ListQueryError(
                    "include_total", f"`include_total` must be `true` or `false`, got `{value}`"
                )
        query = cls(**changes)
        query.validate()
        return query


def _limit_value(limit: int) -> int:
    if limit == 0:
        raise ListQueryError("limit", "`limit` must be at least 1")
    if limit < 0:
        raise ListQueryError("limit", "`limit` must be a positive integer")
    if limit > _U32_MAX:
        raise ListQueryError("limit", "`limit` is too large")
    return limit


def _sort_from_json(value: Any) -> Tuple[SortKey, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ListQueryError("sort", '`sort` must be an array of keys such as ["-quantity", "id"]')
    keys = []
    for item in value:
        if not isinstance(item, str):
            raise ListQueryError("sort", 'sort keys are strings such as "-quantity" or "id"')
        try:
            keys.append(SortKey.parse(item))
        except FilterError as error:
            raise ListQueryError("sort", str(error)) from None
    return tuple(keys)


def _validate_sort(keys: Sequence[SortKey]) -> None:
    if len(keys) > SORT_MAX_KEYS:
        raise ListQueryError("sort", f"at most {SORT_MAX_KEYS} sort keys are allowed")
    for index, key in enumerate(keys):
        try:
            _validate_field_path(key.field)
        except FilterError as error:
            raise ListQueryError("sort", str(error)) from None
        if any(earlier.field == key.field for earlier in keys[:index]):
            raise ListQueryError(
                "sort", f"sort key `{_render_path(key.field)}` appears more than once"
            )


def _validate_select(fields: Sequence[str]) -> None:
    if not fields:
        raise ListQueryError("select", "`select` must list at least one field")
    if len(fields) > SELECT_MAX_FIELDS:
        raise ListQueryError("select", f"at most {SELECT_MAX_FIELDS} fields can be selected")
    for index, path in enumerate(fields):
        try:
            _validate_field_path(path)
        except FilterError as error:
            raise ListQueryError("select", str(error)) from None
        if path in fields[:index]:
            raise ListQueryError(
                "select", f"field `{_render_path(path)}` is selected more than once"
            )


def _validate_cursor(cursor: str) -> None:
    if (
        not cursor
        or len(cursor) > CURSOR_MAX_BYTES
        or not cursor.isascii()
        or _CURSOR.fullmatch(cursor) is None
    ):
        raise ListQueryError(
            "cursor", "`cursor` must be a `next_cursor` value returned by a previous page"
        )


# ---------------------------------------------------------------------------
# Pages and iteration
# ---------------------------------------------------------------------------

T = TypeVar("T")
U = TypeVar("U")


@dataclass(frozen=True)
class Page(Generic[T]):
    """One page of a collection read: ``{"items": [...], "next_cursor": ..., "total": ...}``."""

    items: Tuple[T, ...]
    next_cursor: Optional[str] = None
    total: Optional[int] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))

    @property
    def has_more(self) -> bool:
        """Whether another page follows."""

        return self.next_cursor is not None

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

    def __len__(self) -> int:
        return len(self.items)

    def map(self, convert: Callable[[T], U]) -> "Page[U]":
        """Convert every item, keeping the cursor and total."""

        return Page(tuple(convert(item) for item in self.items), self.next_cursor, self.total)

    def to_json(self) -> Dict[str, Any]:
        """Envelope form (``total`` only when present)."""

        payload: Dict[str, Any] = {"items": list(self.items), "next_cursor": self.next_cursor}
        if self.total is not None:
            payload["total"] = self.total
        return payload

    @classmethod
    def from_json(
        cls,
        payload: Any,
        item: Optional[Callable[[Any], T]] = None,
    ) -> "Page[T]":
        """Decode a page envelope, converting items with ``item``.

        The envelope contains only ``items``, mandatory ``next_cursor`` and
        optional ``total``. Totals cannot be smaller than the current page.
        """

        if not isinstance(payload, Mapping):
            raise ValueError("a page must be a JSON object")
        if set(payload) - {"items", "next_cursor", "total"}:
            raise ValueError("a page contains an unknown envelope field")
        items = payload.get("items")
        if not isinstance(items, list):
            raise ValueError("a page must contain an `items` array")
        if "next_cursor" not in payload:
            raise ValueError("a page must contain `next_cursor`")
        next_cursor = payload["next_cursor"]
        if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor):
            raise ValueError("`next_cursor` must be a non-empty string or null")
        total = payload.get("total")
        if total is not None and (isinstance(total, bool) or not isinstance(total, int) or total < 0):
            raise ValueError("`total` must be a non-negative integer")
        if "total" in payload and (total is None or total < len(items)):
            raise ValueError("`total` must be an integer at least as large as the current page")
        converted = tuple(items) if item is None else tuple(item(entry) for entry in items)
        return cls(converted, next_cursor, total)


def iter_pages(fetch: Callable[[ListQuery], Page[T]], query: ListQuery) -> Iterator[Page[T]]:
    """Fetch ``query`` and every following page until ``next_cursor`` is null.

    Only a null ``next_cursor`` ends the read: a page may hold fewer than
    ``limit`` items, or none, and still continue (history collections bound
    the scan behind each page). The generator is lazy: breaking out of the
    loop (or calling ``close()``) stops issuing requests. A ``next_cursor``
    equal to the cursor just sent would never advance, so it raises
    :class:`RuntimeError`.
    """

    current = query
    while True:
        page = fetch(current)
        yield page
        cursor = page.next_cursor
        if cursor is None:
            return
        if cursor == current.cursor:
            raise RuntimeError(
                f"Torii answered cursor `{cursor}` with the same `next_cursor`; refusing to loop"
            )
        current = current.with_cursor(cursor)


def iter_items(fetch: Callable[[ListQuery], Page[T]], query: ListQuery) -> Iterator[T]:
    """Every item of ``query`` across all pages, fetched lazily page by page."""

    for page in iter_pages(fetch, query):
        yield from page.items
