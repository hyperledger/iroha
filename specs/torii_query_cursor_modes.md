## Torii Query Cursor Modes (Snapshot Lane)

This page documents how server-side queries select cursor behavior when executing over a snapshot of state, and how clients can override it per request.

### Overview

Iroha runs read-only queries against a captured `StateView` snapshot for determinism. Iterable queries can operate in two modes:

- ephemeral: returns only the first batch. The server does not keep a cursor;
  signed-query admission requires zero offset, so this mode cannot page through
  a larger result set.
- stored: returns the first batch and a server cursor. Clients can continue the same snapshot using the cursor.

Mode selection is configurable and can be overridden per request.

### Configuration

- `pipeline.query_default_cursor_mode`: default cursor mode for server-facing iterable queries. Values: `ephemeral` (default) or `stored`.
- `query_stored_min_gas_units` (a field of the committed chain parameter `pipeline_validity_policy_v1`, not node configuration): minimum gas units required to use stored mode (0 disables the requirement). When > 0, stored mode requires the client to provide sufficient `gas_units` in the request.

### Per-request Overrides

The `/v1/query` endpoint accepts optional query-string parameters (reserved for mode control):

- `cursor_mode`: `ephemeral` | `stored`
- `gas_units`: integer; required when the committed `query_stored_min_gas_units > 0` and `cursor_mode=stored`. When insufficient, the server rejects the request with a validation error.
- Stored `Continue` requests embed the gas budget in the Norito payload via `ForwardCursor.gas_budget` so the server can re-validate stored cursors.
- Transaction history is read through the [collection query
  endpoints](torii/collection_queries.md), with their own cursor contract.
- The normative storage, authorization, expiry, and count rules are defined in
  [Cursor pagination](torii/cursor_pagination.md).

Notes:
- If `cursor_mode` is omitted, the server uses the default from `pipeline.query_default_cursor_mode`.
- In ephemeral mode, the server always returns `cursor=null`. Continue requests are rejected.

### Telemetry

When telemetry is enabled (`telemetry_profile` is not `disabled`):

- `torii_query_snapshot_requests_total{mode}`: total count of snapshot-lane queries by mode.
- `torii_query_snapshot_first_batch_ms{mode}`: first-batch latency histogram by mode (ms).
- `torii_query_snapshot_gas_consumed_units_total{mode}`: cumulative gas units reported by clients for stored mode (when a minimum is configured).
- Core telemetry publishes complementary lane metrics such as `query_snapshot_lane_first_batch_ms{mode}` and `query_snapshot_lane_remaining_items{mode}` for operators who monitor the pipeline directly.

### Determinism and Snapshot Semantics

- The initial request executes against a captured `StateView`. Admitted stored
  queries retain their initial snapshot tail for continuation. See
  [Cursor pagination](torii/cursor_pagination.md) for the precise lifecycle.
- Ephemeral mode returns only the first batch. Use stored mode for admitted
  iterable queries that need continuation, or collection cursors for listings.

### Examples (Conceptual)

1) Ephemeral default, no override:

POST /v1/query
Body: Norito-encoded Start request (predicate/selector/params)
Response: first batch; `cursor=null`

2) Override to stored with gas units:

POST /v1/query?cursor_mode=stored&gas_units=100
Body: Norito-encoded Start request
Response: first batch; `cursor` present for continuation

If the committed `query_stored_min_gas_units` is 200, the above is rejected with NotPermitted.

---

For the canonical list of Torii endpoints, see the Reference section. This page covers only mode selection and behavior for snapshot-lane query execution.


## Bounded ordinary account identities

Ordinary `FindAccountIds` admits a pass predicate, default selector, bounded
counting and unsorted zero-offset pagination. The immutable world adapter owns
at most `min(limit, F + 1)` rows for ephemeral queries and
`min(limit, F + T + 1)` rows for stored queries. The extra row detects retained
item overflow only when the requested range exceeds the cursor ceiling. The
source uses exact fallible row slots and compact key/member copies charged to
both the per-row and aggregate graph allowances. Multisig member order and the
canonical account identity are preserved.

Stored Start carries both source-pass statistics into retained-tail sizing and
reserves the configured response-byte ceiling from the same work budget before
publishing a cursor. Continuations retain only the initial snapshot tail, form
each page through exact fallible storage, and charge a fresh page/response
budget. Response charges are conservative ceiling reservations, not measured
encoded lengths. Each returned response still passes the existing wire-byte
ceiling. Source and page storage fit the combined fresh and retained admission
leases; neither a live-State replay nor a generic producer fallback is used.
Peers support the bounded ephemeral adapter, and `FindTriggers` and
`FindActiveTriggerIds` follow the same unfiltered, unsorted, zero-offset shape.
Every other iterable query, and these with a predicate, offset or sorting, is
refused before execution with the stable reason
`signed_query_shape_not_admitted`; the refusal names the query and lists the
Torii collection endpoints (`/v1/domains`, `/v1/accounts`,
`/v1/assets/definitions`, `/v1/nfts`, `/v1/rwas`, `/v1/accounts/{id}/assets`,
`/v1/assets/{definition}/holders`, `/v1/transactions/query`,
`/v1/repo/agreements`) that serve listing reads. See
[Query JSON envelope](query_json.md#admission-on-signed-v1query) and
[Torii collection queries](torii/collection_queries.md).
