"""Typed Torii HTTP errors shared by ``iroha_torii_client`` and ``iroha_python``.

Torii reports failures with the envelope ``{"code", "message", "details"}``
and, for transaction admission, an ``x-iroha-reject-code`` header. Every
unexpected status is raised as a :class:`ToriiError` (a ``RuntimeError``)
carrying those fields; HTTP-status subclasses let callers catch the cases
they handle::

    try:
        page = client.accounts.list(filter="label = 'treasury'")
    except ToriiQueryError as error:      # 400 invalid_filter, invalid_sort, ...
        print(error.code, error.parameter, error.message)
    except ToriiNotFoundError:
        ...
    except ToriiError as error:           # any other non-success status
        print(error.status, error.code)
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, Mapping, Optional, Tuple, Type

from .list_query import QUERY_ERROR_CODES, ListQueryError

__all__ = [
    "ERROR_BODY_PREVIEW_BYTES",
    "ToriiBadRequestError",
    "ToriiConflictError",
    "ToriiError",
    "ToriiForbiddenError",
    "ToriiNotFoundError",
    "ToriiPayloadTooLargeError",
    "ToriiQueryError",
    "ToriiRateLimitedError",
    "ToriiServerError",
    "ToriiUnauthorizedError",
    "ToriiUnavailableError",
    "error_for_response",
    "error_for_status",
]

#: Error bodies are read up to this many bytes when no stricter bound applies.
ERROR_BODY_PREVIEW_BYTES = 64 * 1024

_REJECT_CODE_HEADER = "x-iroha-reject-code"
_QUERY_CODES = frozenset(QUERY_ERROR_CODES.values())
_PARAMETER_FOR_CODE = {code: parameter for parameter, code in QUERY_ERROR_CODES.items()}
_RETRY_AFTER = re.compile(r"[0-9]{1,9}")


class ToriiError(RuntimeError):
    """Torii answered with an unexpected HTTP status.

    ``code``, ``message`` and ``details`` come from Torii's error envelope;
    ``code`` is ``None`` when the body was not an envelope. ``reject_code`` is
    the ``x-iroha-reject-code`` header (or ``details.reject_code``).
    ``retry_after`` is the ``Retry-After`` delay in seconds when Torii sent one.
    """

    def __init__(
        self,
        status: int,
        *,
        code: Optional[str] = None,
        message: str = "",
        details: Optional[Mapping[str, Any]] = None,
        reject_code: Optional[str] = None,
        retry_after: Optional[int] = None,
        expected: Iterable[int] = (),
        context: Optional[str] = None,
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.details: Dict[str, Any] = dict(details or {})
        self.reject_code = reject_code
        self.retry_after = retry_after
        self.expected: Tuple[int, ...] = tuple(sorted(set(expected)))
        self.context = context
        # Call the exception base directly: ToriiQueryError's MRO also contains
        # ListQueryError, whose initializer takes different arguments.
        RuntimeError.__init__(self, self._render())

    def _render(self) -> str:
        head = f"unexpected status {self.status}"
        if self.code:
            head += f" ({self.code})"
        if self.expected:
            head += f"; expected {list(self.expected)}"
        if self.context:
            head = f"{self.context}: {head}"
        body = self.message
        if self.reject_code and self.reject_code not in body:
            body = f"{body}; reject_code={self.reject_code}" if body else f"reject_code={self.reject_code}"
        return f"{head}; body={body}" if body else head

    def __reduce__(self) -> Tuple[Any, ...]:
        return (
            _rebuild,
            (
                type(self),
                self.status,
                self.code,
                self.message,
                self.details,
                self.reject_code,
                self.retry_after,
                self.expected,
                self.context,
            ),
        )


def _rebuild(cls: Type[ToriiError], *fields: Any) -> ToriiError:
    status, code, message, details, reject_code, retry_after, expected, context = fields
    return cls(
        status,
        code=code,
        message=message,
        details=details,
        reject_code=reject_code,
        retry_after=retry_after,
        expected=expected,
        context=context,
    )


class ToriiBadRequestError(ToriiError):
    """HTTP 400: the request was malformed or violated a validation rule."""


class ToriiQueryError(ToriiBadRequestError, ListQueryError):
    """HTTP 400 rejecting a collection-query control (``invalid_filter``, ``invalid_sort``, ...).

    ``parameter`` names the rejected control (``details.field``); the class is
    also a :class:`~iroha_torii_client.list_query.ListQueryError`, so one
    ``except ListQueryError`` handles client-side and server-side rejections.
    """

    def __init__(self, status: int, **fields: Any) -> None:
        ToriiBadRequestError.__init__(self, status, **fields)
        field = self.details.get("field")
        parameter = (
            field if isinstance(field, str) and field in QUERY_ERROR_CODES
            else _PARAMETER_FOR_CODE.get(self.code or "", "query")
        )
        self.parameter = parameter


class ToriiUnauthorizedError(ToriiError):
    """HTTP 401: credentials are missing or invalid."""


class ToriiForbiddenError(ToriiError):
    """HTTP 403: the authenticated principal may not perform the request."""


class ToriiNotFoundError(ToriiError):
    """HTTP 404: the addressed resource does not exist (or is not visible)."""


class ToriiConflictError(ToriiError):
    """HTTP 409: the request conflicts with current state."""


class ToriiPayloadTooLargeError(ToriiError):
    """HTTP 413: the request body exceeds Torii's limit."""


class ToriiRateLimitedError(ToriiError):
    """HTTP 429: retry after :attr:`retry_after` seconds when present."""


class ToriiServerError(ToriiError):
    """HTTP 5xx: Torii failed to process a valid request."""


class ToriiUnavailableError(ToriiServerError):
    """HTTP 503: Torii is temporarily unable to serve; retry later."""


_STATUS_CLASSES: Mapping[int, Type[ToriiError]] = {
    400: ToriiBadRequestError,
    401: ToriiUnauthorizedError,
    403: ToriiForbiddenError,
    404: ToriiNotFoundError,
    409: ToriiConflictError,
    413: ToriiPayloadTooLargeError,
    429: ToriiRateLimitedError,
    503: ToriiUnavailableError,
}


def _error_class(status: int, code: Optional[str]) -> Type[ToriiError]:
    if status == 400 and code in _QUERY_CODES:
        return ToriiQueryError
    if status in _STATUS_CLASSES:
        return _STATUS_CLASSES[status]
    if 500 <= status <= 599:
        return ToriiServerError
    return ToriiError


def _header(response: Any, name: str) -> Optional[str]:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        value = headers.get(name)
    except AttributeError:
        return None
    return value if isinstance(value, str) else None


def _retry_after(response: Any) -> Optional[int]:
    value = _header(response, "Retry-After")
    if value is None or _RETRY_AFTER.fullmatch(value.strip()) is None:
        return None
    return int(value.strip())


def _read_preview(response: Any, limit: int) -> bytes:
    """Read at most ``limit`` bytes of an error body and release the response."""

    try:
        content = getattr(response, "_content", False)
        if isinstance(content, (bytes, bytearray)):
            return bytes(content[:limit])
        iter_content = getattr(response, "iter_content", None)
        if callable(iter_content) and content is False:
            buffer = bytearray()
            for chunk in iter_content(chunk_size=8_192):
                if not chunk:
                    continue
                if not isinstance(chunk, (bytes, bytearray)):
                    break
                buffer.extend(chunk[: limit - len(buffer)])
                if len(buffer) >= limit:
                    break
            return bytes(buffer)
        text = getattr(response, "text", "")
        if isinstance(text, str):
            return text.encode("utf-8")[:limit]
        return b""
    finally:
        # Release the connection; a response without a transport (``raw is None``)
        # has nothing to release.
        close = getattr(response, "close", None)
        if callable(close) and getattr(response, "raw", True) is not None:
            close()


def _message_from(payload: Any) -> Optional[str]:
    if isinstance(payload, str):
        return payload.strip() or None
    if isinstance(payload, Mapping):
        for key in ("message", "error", "detail", "reason", "description"):
            value = _message_from(payload.get(key))
            if value:
                return value
    if isinstance(payload, list):
        for entry in payload:
            value = _message_from(entry)
            if value:
                return value
    return None


def _envelope_fields(body: bytes) -> Tuple[Optional[str], str, Dict[str, Any]]:
    """Return ``(code, message, details)`` from an error body."""

    text = body.decode("utf-8", "replace").strip()
    if not text:
        return None, "", {}
    try:
        payload = json.loads(text)
    except ValueError:
        return None, text, {}
    if isinstance(payload, Mapping):
        code = payload.get("code") if isinstance(payload.get("code"), str) else None
        raw_details = payload.get("details")
        details = raw_details if isinstance(raw_details, Mapping) else {}
        message = _message_from(payload) or ""
        if not message:
            message = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return code, message, dict(details)
    return None, _message_from(payload) or json.dumps(payload, separators=(",", ":")), {}


def error_for_status(
    status: int,
    *,
    expected: Iterable[int] = (),
    context: Optional[str] = None,
    code: Optional[str] = None,
    message: str = "",
    details: Optional[Mapping[str, Any]] = None,
    reject_code: Optional[str] = None,
    retry_after: Optional[int] = None,
) -> ToriiError:
    """Build the :class:`ToriiError` subclass for ``status``/``code``."""

    return _error_class(status, code)(
        status,
        code=code,
        message=message,
        details=details,
        reject_code=reject_code,
        retry_after=retry_after,
        expected=expected,
        context=context,
    )


def error_for_response(
    response: Any,
    *,
    expected: Iterable[int] = (),
    context: Optional[str] = None,
    body: Optional[bytes] = None,
) -> ToriiError:
    """Parse Torii's error envelope from ``response`` into a :class:`ToriiError`.

    ``body`` supplies already-read bytes; otherwise at most
    :data:`ERROR_BODY_PREVIEW_BYTES` are read and the response is closed.
    """

    raw = _read_preview(response, ERROR_BODY_PREVIEW_BYTES) if body is None else body
    code, message, details = _envelope_fields(raw)
    reject_code = _header(response, _REJECT_CODE_HEADER)
    if reject_code is None and isinstance(details.get("reject_code"), str):
        reject_code = details["reject_code"]
    return error_for_status(
        int(getattr(response, "status_code", 0)),
        expected=expected,
        context=context,
        code=code,
        message=message,
        details=details,
        reject_code=reject_code,
        retry_after=_retry_after(response),
    )
