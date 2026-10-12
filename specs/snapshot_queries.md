# Snapshot Query Operations

Snapshot queries execute against a consistent `StateView` so operators can service
read-only workloads without affecting consensus state. This note collects the
operational guardrails that now ship with the snapshot lane.

## Resource Budgets and Quotas

- `query_stored_min_gas_units` of the committed `pipeline_validity_policy_v1`
  chain parameter (not node configuration) gates server-side cursor storage. When
  the value is greater than zero:
  - `Start` requests that opt into stored mode must provide at least this many
    `gas_units` via the Torii query-string override.
  - `Continue` requests must echo a budget in the Norito payload via
    `ForwardCursor.gas_budget`. Budgets lower than the configured minimum are
    rejected with a `NotPermitted` validation error.
  - Stored transaction-history scans debit certified-carrier projection work
    against the actual validated request budget. Compact entrypoint counts are
    precharged before full merge sidecars are resolved, so false predicates and
    underfunded continuations cannot force unaccounted sidecar decoding or
    Merkle-proof reconstruction.
- `live_query_store.capacity` limits the total number of stored cursors.
- `live_query_store.capacity_per_user` enforces per-authority quotas. When the
  quota is exceeded the server returns the `AuthorityQuotaExceeded` error.

## Cursor TTL and Garbage Collection

Stored cursors inherit `live_query_store.idle_time`. A background pruning task
removes cursors whose `last_access_time` exceeds this TTL. Subsequent `Continue`
requests for evicted cursors surface `QueryExecutionFail::Expired` so clients can
recover gracefully.

## Telemetry

Two families of metrics are exposed when telemetry is enabled:

- Torii front-end metrics:
  - `torii_query_snapshot_requests_total{mode}` – request counter.
  - `torii_query_snapshot_first_batch_ms{mode}` – first-batch latency histogram.
  - `torii_query_snapshot_gas_consumed_units_total{mode}` – cumulative gas budget
    values provided by clients (query-string or cursor payloads).
- Core snapshot lane metrics:
  - `query_snapshot_lane_first_batch_ms{mode}` – execution time inside the lane.
  - `query_snapshot_lane_first_batch_items{mode}` – item counts per batch.
  - `query_snapshot_lane_remaining_items{mode}` – remaining items gauge.
  - `query_snapshot_lane_cursors_total{mode}` – stored cursor issuance counter.

All counters are labeled by cursor mode (`ephemeral` or `stored`) so operators can
track adoption and verify budget compliance.

## Operator Checklist

1. Tune `pipeline.query_default_cursor_mode` to select ephemeral vs stored mode
   for the default case.
2. When enabling stored cursors, the chain sets `query_stored_min_gas_units` in
   its committed `pipeline_validity_policy_v1` parameter (an authorized
   `SetParameter`); monitor `torii_query_snapshot_gas_consumed_units_total` to ensure clients
   honour budgets.
3. Size `live_query_store.capacity` and `capacity_per_user` according to expected
   workloads, watching `query_snapshot_lane_cursors_total` to understand how many
   cursors are being issued.
4. Review `query_snapshot_lane_remaining_items` to detect long-lived cursors and
   adjust `idle_time` if pruning becomes too aggressive or too lax.

These guardrails keep snapshot queries predictable while providing visibility
into operator-facing resource usage.
