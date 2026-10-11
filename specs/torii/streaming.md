# Torii `/v1` streaming contract

This document is normative for Torii's first-release canonical event and block
streams. These transports are deliberately small: live event feeds do not
pretend to provide replay, while the block stream uses a committed block height
as its explicit replay position.

| Route | Transport | Resume model |
| --- | --- | --- |
| `GET /v1/events/sse` | UTF-8 JSON Server-Sent Events | none; live events after subscription only |
| `GET /v1/contracts/events/sse` | UTF-8 JSON Server-Sent Events | none; payload `event_id` is for deduplication only |
| `GET /v1/events/ws` | framed Norito WebSocket | none; live events after subscription only |
| `GET /v1/blocks/stream` | framed Norito WebSocket | required non-zero start height in `BlockSubscriptionRequest` |

## Establishment and authorization

Torii applies ingress limits, API-token policy, CIDR policy, and the route rate
limit before returning an SSE `200` or WebSocket `101`. A failed check does not
create a subscriber. The event routes accept either no canonical account
authentication or one complete canonical account signature. Supplying any
partial, malformed, stale, replayed, or otherwise invalid authentication tuple
fails with `401`; it never degrades to anonymous access.

An anonymous event subscriber sees only active public dataspaces. A verified
account additionally sees dataspaces bound to its UAID and exact
`CanReadRestrictedDataspace` grants. `CanReadAllLedgerData` sees every active
dataspace. Transaction events are scoped to the union of every coordinator and
participant dataspace in their committed routing plan and are emitted only when
the caller can see every leg. Unknown, stale, or malformed provenance and event
families without committed route provenance are global-reader-only. Scope is
applied before subscriber filters and JSON/Norito projection.

The native `/v1/blocks/stream` carries complete `SignedBlock` values and cannot
be safely redacted. It therefore requires a canonical account signature from a
caller that currently holds `CanReadAllLedgerData`. Event and Explorer streams
retain the admitted principal and route scope, re-evaluate account existence and
permissions while open, and close with a generic authorization-revoked terminal
error when that authority is removed. Static API-token rotation remains an
establishment policy; account and dataspace authorization is the live,
re-evaluated boundary.

SSE clients send `Accept: text/event-stream`. Successful responses use
`Content-Type: text/event-stream` and `Cache-Control: no-cache`. WebSocket
clients use the ordinary HTTP Upgrade handshake and must offer exactly one
case-sensitive subprotocol:

```http
Sec-WebSocket-Protocol: iroha-norito-v1
```

Before a stream is established, router, authentication, authorization,
rate-limit, capacity, and service-availability failures are ordinary finite
HTTP responses. Torii returns the shared JSON `ErrorEnvelope` for those
failures even when the client advertised only `text/event-stream`; it does not
replace the actionable failure with `406 Not Acceptable`. Such responses carry
`Vary: Accept`. Once an SSE response has started, errors use the terminal
`stream_error` event described below because the HTTP status and headers can no
longer be changed.

Ingress and authentication checks precede subscription-syntax, resume, and
subprotocol validation. A request that is both unauthorized and malformed is
therefore rejected as `401` without revealing whether its stream parameters
would otherwise be accepted. After ingress succeeds, malformed or unsupported
handshake input fails before a subscriber or WebSocket upgrade is created.

Missing, duplicated, comma-combined, or different subprotocols fail the HTTP
handshake. The two canonical WebSocket routes accept no query parameters and
reject `Last-Event-ID`. Incoming subscription messages and frames are capped at
256 KiB.

## SSE framing

`/v1/events/sse` emits one `data:` field containing the canonical Norito JSON
mapping of an `EventBox`. A broadcast `PipelineBatch` is expanded in its stored
batch order. No SSE `id:` field is emitted.

`/v1/contracts/events/sse` emits `event: contract_event` plus one JSON `data:`
field carrying the same call-derived row as the contract events collection
(see [Call-derived contract activity and events](collection_queries.md#call-derived-contract-activity-and-events)):
rows are projected from committed `ContractCall` transactions, never from
contract-emitted events, and `provenance` is always `derived`. The JSON
payload's `event_id` remains stable enough for consumer-side
deduplication, but Torii does not interpret it as an SSE replay cursor and does
not emit it as an SSE `id:` field. Duplicate committed/applied notifications for
the same block height are suppressed within a connection; projected events are
emitted in committed block/transaction order.

An idle SSE connection receives this comment at most every 15 seconds:

```text
: heartbeat
```

Comments do not advance stream ordering and must not be persisted as cursors.

The live broadcast channel is bounded. If a receiver falls behind, continuing
would conceal a gap. Torii instead emits exactly one terminal event and closes
the response body:

```text
event: stream_error
data: {"code":"stream_lagged","message":"...","dropped_messages":1,"replay_available":false}
```

`dropped_messages` counts skipped broadcast messages, not necessarily logical
events (one message can be a `PipelineBatch`). Encoding failure uses
`stream_encode_error`; shutdown of the source uses `stream_source_closed`.
Both are terminal and set `dropped_messages` to `null`.

## SSE resume and reconnect

Neither canonical SSE route retains a replay log. Any presence of
`Last-Event-ID`, including an empty or repeated field, fails establishment with
HTTP `400`, `X-Iroha-Stream-Error: stream_resume_unsupported`, and a native
`text/event-stream` `stream_error` body. This is intentional: silently ignoring
the field would falsely claim a lossless reconnect.

A reconnect without `Last-Event-ID` starts a new live subscription and can have
a gap. There is no atomic snapshot-to-SSE handoff in `/v1`. Authorized global
readers that need complete, ordered ledger history may use
`/v1/blocks/stream` from a known height and derive the relevant committed
events. Other callers use the dataspace-filtered Explorer summaries.

Explorer block, transaction, and instruction streams suppress repeated or
stale block heights within one connection, so paired committed/applied
notifications cannot duplicate a block projection. If their bounded receiver
lags, they emit a terminal `stream_lagged` event and close instead of silently
skipping blocks.

## Norito WebSocket framing

After the `101` response selects `iroha-norito-v1`, the client sends exactly one
binary, header-bearing Norito message:

- `/v1/events/ws`: `EventSubscriptionRequest`;
- `/v1/blocks/stream`: `BlockSubscriptionRequest`.

The server then sends only binary, header-bearing Norito `EventMessage` or
`BlockMessage` values, plus WebSocket ping/close control frames. Text as the
subscription, malformed Norito, or any second client data frame is a protocol
error. The subscription must arrive before one fixed configured deadline;
ping and pong control frames remain valid but do not restart that deadline.
Torii sends an empty ping at most every 15 seconds while idle; clients must
permit the WebSocket stack to answer with pong.

The event WebSocket preserves receiver order and expands `PipelineBatch` in
batch order, but it does not impose a new global ledger order across independent
event producers. It has no replay cursor. The block WebSocket reads committed
blocks from Kura in strictly increasing height order, beginning with the
requested height. Reconnecting at the last fully processed height can repeat
that block; clients deduplicate by height and block hash. Reconnecting at the
next height avoids that duplicate.

## Backpressure and terminal errors

HTTP status/error envelopes are no longer possible after an SSE response or
WebSocket upgrade has started. SSE uses the terminal `stream_error` event above.
WebSocket uses these stable RFC 6455 close codes and ASCII reasons:

| Code | Reason | Meaning |
| --- | --- | --- |
| `1000` | peer/default reason | normal close handshake |
| `1007` | `invalid_subscription_payload` | malformed Norito, wrong frame type, or extra data frame |
| `1008` | `subscription_timeout` | first request did not arrive in time |
| `1008` | `invalid_event_subscription` | event subscription contains no event filters |
| `1008` | `invalid_block_subscription` | block height violates the request contract |
| `1009` | implementation close reason | subscription message or frame exceeds 256 KiB |
| `1011` | `event_source_closed` | event source stopped unexpectedly |
| `1011` | `stream_internal_error` | encoding or server transport failure |
| `1013` | `event_stream_lagged:<N>` | the event receiver skipped `N` broadcast messages; no replay is available |
| `1013` | `stream_backpressure` | a bounded send timed out because the consumer was too slow |

On `1007` or `1008`, clients must correct the request before reconnecting. On
`1013`, reconnect with randomized backoff. For `/v1/events/ws`, reconnect is a
new live stream and cannot repair the reported gap. For `/v1/blocks/stream`,
reconnect from the first block height that was not fully processed. A client
must surface non-`1000` close code and reason to its caller rather than treating
the stream as a clean end-of-file.
