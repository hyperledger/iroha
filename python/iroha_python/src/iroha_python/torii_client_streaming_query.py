"""Server-Sent Event streaming helpers shared by the high-level Torii client."""

from __future__ import annotations

import json
import math
import time
from typing import Any, Callable, Dict, Iterable, Iterator, List, Mapping, Optional

import requests
from iroha_torii_client.canonical_transport import (
    CanonicalRequestHeaderPlan as _CanonicalRequestHeaderPlan,
)
from iroha_torii_client.canonical_transport import (
    OperatorRequestHeaderPlan as _OperatorRequestHeaderPlan,
)

from .stream_events import EventCursor, SseEvent, SseStreamError

_DEFAULT_SSE_EVENT_MAX_BYTES = 1024 * 1024
_SSE_READ_CHUNK_BYTES = 64 * 1024
_SSE_MAX_BACKOFF_SECONDS = 30.0


def _set_header(headers: Dict[str, str], name: str, value: str) -> None:
    for existing in tuple(headers):
        if existing.lower() == name.lower():
            del headers[existing]
    headers[name] = value


def _remove_header(headers: Dict[str, str], name: str) -> None:
    for existing in tuple(headers):
        if existing.lower() == name.lower():
            del headers[existing]


def _iter_bounded_sse_lines(
    response: requests.Response,
    *,
    path: str,
    maximum_event_bytes: int,
) -> Iterator[tuple[bytes, int]]:
    def next_line_ending(*, at_eof: bool) -> Optional[tuple[int, int]]:
        for index, byte in enumerate(pending):
            if byte == 0x0A:
                return index, 1
            if byte != 0x0D:
                continue
            if index + 1 == len(pending) and not at_eof:
                return None
            width = 2 if pending[index + 1 : index + 2] == b"\n" else 1
            return index, width
        return None

    def drain_lines(*, at_eof: bool) -> Iterator[tuple[bytes, int]]:
        while (ending := next_line_ending(at_eof=at_eof)) is not None:
            line_end, ending_width = ending
            wire_bytes = line_end + ending_width
            if wire_bytes > maximum_event_bytes:
                raise ValueError(
                    f"{path} SSE event exceeds its "
                    f"{maximum_event_bytes}-byte size bound"
                )
            raw_line = bytes(pending[:line_end])
            del pending[:wire_bytes]
            yield raw_line, wire_bytes

    pending = bytearray()
    chunk_size = min(_SSE_READ_CHUNK_BYTES, maximum_event_bytes + 1)
    for chunk in response.iter_content(chunk_size=chunk_size):
        if not isinstance(chunk, bytes):
            raise ValueError(f"{path} SSE body yielded a non-byte chunk")
        pending.extend(chunk)
        yield from drain_lines(at_eof=False)
        if len(pending) > maximum_event_bytes:
            raise ValueError(
                f"{path} SSE event exceeds its {maximum_event_bytes}-byte size bound"
            )
    yield from drain_lines(at_eof=True)
    if pending:
        raw_line = bytes(pending)
        yield raw_line, len(raw_line)


def create_torii_client_streaming_query_mixin(
    *,
    require_crypto: Callable[[], Any],
    expect_sorafs_reputation_status: Callable[..., None],
) -> Any:
    """Bind client-local hooks to the reusable streaming/query implementation."""

    _require_crypto = require_crypto
    _expect_sorafs_reputation_status = expect_sorafs_reputation_status

    class ToriiClientStreamingQueryMixin:
        _base_url: str
        _default_headers: Mapping[str, str]
        _session: requests.Session
        _request: Callable[..., requests.Response]
        _expect_status: Callable[..., None]

        @staticmethod
        def _maybe_transaction_receipt(response: requests.Response) -> Optional[Any]:
            content_type = response.headers.get("Content-Type", "")
            if "application/x-norito" not in content_type.lower():
                return None
            if not response.content:
                return None
            try:
                crypto = _require_crypto()
            except RuntimeError:
                return None
            if not hasattr(crypto, "decode_transaction_receipt_json"):
                return None
            try:
                receipt_json = crypto.decode_transaction_receipt_json(response.content)
            except Exception:
                return None
            try:
                return json.loads(receipt_json)
            except json.JSONDecodeError:
                return None

        @staticmethod
        def _parse_sse_event(
            lines: Iterable[str],
            *,
            decode_json: bool = True,
            json_loader: Optional[Callable[[str], Any]] = None,
        ) -> Optional[SseEvent]:
            raw_lines = list(lines)
            data_chunks: List[str] = []
            event_name: Optional[str] = None
            event_id: Optional[str] = None
            retry_value: Optional[int] = None
            for entry in raw_lines:
                if entry.startswith(":"):
                    continue
                field, sep, value = entry.partition(":")
                value = value.lstrip() if sep else ""
                if field == "data":
                    data_chunks.append(value)
                elif field == "id":
                    event_id = value or None
                elif field == "event":
                    event_name = value or None
                elif field == "retry":
                    try:
                        retry_value = int(value)
                    except ValueError:
                        retry_value = None
            if not data_chunks and event_name is None and event_id is None and retry_value is None:
                return None
            payload: Any
            if data_chunks:
                joined = "\n".join(data_chunks)
                if decode_json:
                    if json_loader is not None:
                        payload = json_loader(joined)
                    else:
                        try:
                            payload = json.loads(joined)
                        except json.JSONDecodeError:
                            payload = joined
                else:
                    payload = joined
            else:
                payload = None
            return SseEvent(
                event=event_name,
                data=payload,
                id=event_id,
                retry=retry_value,
                raw="\n".join(raw_lines),
            )

        def _stream_sse(
            self,
            path: str,
            *,
            params: Optional[Mapping[str, Any]] = None,
            headers: Optional[Mapping[str, str]] = None,
            headers_factory: Optional[Callable[[], Mapping[str, str]]] = None,
            timeout: Optional[float] = None,
            max_retries: int = 3,
            backoff_base: float = 0.5,
            last_event_id: Optional[str] = None,
            resume: bool = False,
            decode_json: bool = True,
            cursor: Optional[EventCursor] = None,
            allow_resume: bool = False,
            maximum_event_bytes: int = _DEFAULT_SSE_EVENT_MAX_BYTES,
            json_loader: Optional[Callable[[str], Any]] = None,
            on_event: Optional[Callable[[SseEvent], None]] = None,
            expected_content_type: Optional[str] = None,
            require_identity_encoding: bool = False,
            payload_free_errors: bool = False,
        ):
            if headers is not None and headers_factory is not None:
                raise ValueError("_stream_sse accepts only one of headers or headers_factory")
            if not allow_resume and (last_event_id is not None or resume or cursor is not None):
                raise ValueError(f"{path} does not support SSE replay")
            if isinstance(max_retries, bool) or not isinstance(max_retries, int):
                raise TypeError("max_retries must be a non-negative integer")
            if max_retries < 0:
                raise ValueError("max_retries must be a non-negative integer")
            if (
                isinstance(backoff_base, bool)
                or not isinstance(backoff_base, (int, float))
                or not math.isfinite(backoff_base)
                or backoff_base < 0
            ):
                raise ValueError("backoff_base must be a finite non-negative number")
            if isinstance(maximum_event_bytes, bool) or not isinstance(
                maximum_event_bytes,
                int,
            ):
                raise TypeError("maximum_event_bytes must be a positive integer")
            if maximum_event_bytes <= 0:
                raise ValueError("maximum_event_bytes must be a positive integer")
            active_last_id = (
                last_event_id
                if last_event_id is not None
                else (cursor.last_event_id if cursor is not None else None)
            )
            should_resume = allow_resume and (resume or last_event_id is not None or cursor is not None)

            def iterator() -> Iterator[SseEvent]:
                nonlocal active_last_id
                attempt = 0
                backoff = float(backoff_base)

                def process_event(event: SseEvent) -> SseEvent:
                    nonlocal active_last_id, attempt, backoff
                    if event.event == "stream_error":
                        raise SseStreamError.from_event(event)
                    if on_event is not None:
                        on_event(event)
                    if event.id is not None and allow_resume:
                        active_last_id = event.id
                        if cursor is not None:
                            cursor.advance(event)
                    attempt = 0
                    backoff = float(backoff_base)
                    return event

                def prepare_retry(error: requests.RequestException) -> None:
                    nonlocal attempt, backoff
                    attempt += 1
                    if attempt > max_retries:
                        raise error
                    if backoff > 0.0:
                        time.sleep(backoff)
                        backoff = min(backoff * 2, _SSE_MAX_BACKOFF_SECONDS)

                while True:
                    final_headers: Dict[str, str] = dict(self._default_headers)
                    _remove_header(final_headers, "Accept")
                    attempt_headers = headers_factory() if headers_factory is not None else headers
                    if attempt_headers is not None and not isinstance(
                        attempt_headers,
                        Mapping,
                    ):
                        raise TypeError("SSE headers must be a mapping")
                    if attempt_headers:
                        for name, value in attempt_headers.items():
                            _set_header(final_headers, name, value)
                    if not allow_resume:
                        _remove_header(final_headers, "Last-Event-ID")
                        session_headers = getattr(self._session, "headers", {})
                        if not isinstance(session_headers, Mapping):
                            raise TypeError("SSE Session.headers must be a mapping")
                        if any(
                            str(name).lower() == "last-event-id"
                            for name in session_headers
                        ):
                            raise ValueError(
                                f"{path} rejects ambient Session.headers Last-Event-ID"
                            )
                    _set_header(final_headers, "Accept", "text/event-stream")
                    if should_resume and active_last_id:
                        _set_header(final_headers, "Last-Event-ID", active_last_id)
                    request_headers: Mapping[str, str]
                    if isinstance(attempt_headers, _CanonicalRequestHeaderPlan):
                        request_headers = _CanonicalRequestHeaderPlan(
                            final_headers,
                            attempt_headers.canonical_auth,
                            reject_ambient_auth=attempt_headers.reject_ambient_auth,
                        )
                    elif isinstance(attempt_headers, _OperatorRequestHeaderPlan):
                        request_headers = _OperatorRequestHeaderPlan(
                            final_headers,
                            attempt_headers.context,
                        )
                    else:
                        request_headers = final_headers
                    try:
                        response_context = self._request(
                            "GET",
                            path,
                            params=params,
                            headers=request_headers,
                            stream=True,
                            timeout=timeout,
                            allow_retry=False,
                            allow_redirects=False,
                            _headers_are_final=True,
                        )
                    except requests.RequestException as exc:
                        prepare_retry(exc)
                        continue

                    transport_failure: Optional[requests.RequestException] = None
                    with response_context as response:
                        if payload_free_errors:
                            _expect_sorafs_reputation_status(
                                response,
                                {200},
                                path,
                            )
                        else:
                            self._expect_status(response, {200})
                        if require_identity_encoding:
                            content_encoding = response.headers.get("Content-Encoding")
                            if (
                                content_encoding is not None
                                and content_encoding.lower() != "identity"
                            ):
                                raise ValueError(
                                    f"{path} Content-Encoding must be identity"
                                )
                        if expected_content_type is not None:
                            content_type = response.headers.get("Content-Type")
                            if (
                                content_type is None
                                or content_type.split(";", 1)[0].strip().lower()
                                != expected_content_type
                            ):
                                raise ValueError(
                                    f"{path} Content-Type must be "
                                    f"{expected_content_type}"
                                )
                        buffer: list[str] = []
                        buffered_bytes = 0
                        first_line = True
                        lines = iter(
                            _iter_bounded_sse_lines(
                                response,
                                path=path,
                                maximum_event_bytes=maximum_event_bytes,
                            )
                        )
                        while True:
                            try:
                                raw_bytes, line_bytes = next(lines)
                            except StopIteration:
                                break
                            except requests.RequestException as exc:
                                transport_failure = exc
                                break
                            if first_line and raw_bytes.startswith(b"\xef\xbb\xbf"):
                                raise ValueError(
                                    f"{path} SSE body must not contain a UTF-8 BOM"
                                )
                            try:
                                decoded_line = raw_bytes.decode("utf-8", "strict")
                            except UnicodeDecodeError as exc:
                                raise ValueError(
                                    f"{path} SSE body must be strict UTF-8"
                                ) from exc
                            first_line = False
                            buffered_bytes += line_bytes
                            if buffered_bytes > maximum_event_bytes:
                                raise ValueError(
                                    f"{path} SSE event exceeds its "
                                    f"{maximum_event_bytes}-byte size bound"
                                )
                            if not decoded_line:
                                if buffer:
                                    event = self._parse_sse_event(
                                        buffer,
                                        decode_json=decode_json,
                                        json_loader=json_loader,
                                    )
                                    buffer.clear()
                                    if event is None:
                                        buffered_bytes = 0
                                        continue
                                    yield process_event(event)
                                buffered_bytes = 0
                                continue
                            buffer.append(decoded_line)
                        if transport_failure is None and buffer:
                            event = self._parse_sse_event(
                                buffer,
                                decode_json=decode_json,
                                json_loader=json_loader,
                            )
                            buffer.clear()
                            if event is not None:
                                yield process_event(event)
                    if transport_failure is not None:
                        prepare_retry(transport_failure)
                        continue
                    break

            return iterator()

    return ToriiClientStreamingQueryMixin
