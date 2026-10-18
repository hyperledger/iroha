# Query Benchmark Suite

This page documents the query benchmarks added for Iroha, how they are
constructed, and how to interpret the results. The suite covers core
iterator-based execution, client-path builder overhead, and Torii handler-path
load through in-process HTTP requests.

## Where the benches live

- Core query benches: `crates/iroha_core/benches/queries.rs`
- Client-path builder benches (mocked executor): `crates/iroha_core/benches/queries_client.rs`
- Torii hot-path benches: `crates/iroha_torii/benches/torii_hot_paths.rs`

All are Criterion benches with a manual entrypoint (`fn main`) to comply with
workspace lints.

## Methodology

- The benches construct an in-memory `State` and `World` directly (no network),
  then use `ValidQuery::execute` to obtain iterators over items.
- Result counts are consumed (with `count()` or by collecting then sorting) to
  ensure side effects are not optimized away; `criterion::black_box` prevents
  dead-code elimination.
- For client-path overhead, a `MockExec` implements `QueryExecutor` and feeds
  batches to `QueryBuilder`/`QueryBuilderExt` without network I/O, isolating the
  builder cost and typed downcasting path.
- Torii sustained-load benches build Axum routers around the same signed-query
  and app-query handlers used by the server, then drive cloned in-process HTTP
  services from multiple Tokio tasks. This includes request body decoding,
  handler execution, response construction, and response body consumption while
  avoiding kernel/socket noise.
- Torii socket-load benches reuse those routers behind ephemeral localhost TCP
  listeners and drive them with pooled `reqwest` clients. They add real HTTP
  transport, connection-pool, and socket body IO costs while keeping the same
  deterministic fixtures and validated profile shapes.

## Datasets

- Accounts: `build_state_with_accounts(n)` creates a single domain and `n`
  accounts (authority-only ownership).
- Assets: `build_state_with_assets(n_accounts, assets_per_account)` creates the
  above plus one or two assets per account.
- Domains: `build_state_with_domains(n)` creates `n` standalone domains.
- Asset Definitions: `build_state_with_asset_definitions(n)` creates a domain,
  an owner account, and `n` asset definitions.
- Torii sustained profiles use `query_load_profiles` to validate synthetic
  fixture sizes before building a state with primary account aliases and asset
  balances for app-query and holder workloads, plus committed contract-metadata
  transactions for contract-activity workloads.

## What’s measured

Core benches (`queries.rs`):
- FindAccounts
  - Iterate and count (1k, 10k)
  - Sort by ID (10k)
  - Simulated pagination over a full result vector (page = 100)
- FindAssets
  - Iterate and count (~10k assets)
  - Filter by a specific account
  - Filter by quantity threshold
- FindDomains
  - Iterate and count (5k)
  - Sort by ID (10k)
  - First-batch snapshot query count-mode comparison:
    `snapshot_find_domains_count_mode_first_batch/{ephemeral,stored}/{exact,bounded}`
  - Stored bounded continuations in Torii use the Arc-backed snapshot runner,
    so the first response reads only the first page plus a probe and later
    continuations replay one page at a time instead of retaining a materialized
    tail.
- FindAssetDefinitions
  - Iterate and count (10k)

Client-path benches (`queries_client.rs`):
- `QueryBuilder` + `execute_all()` with mocked `QueryExecutor`
  - 1k total, fetch_size = 100
  - 10k total, fetch_size = 500

These mimic end-user paths in the client SDK without network effects.

Torii hot-path benches (`torii_hot_paths.rs`):
- Signed iterable `/query`
  - Stored cursor mode
  - Bounded count mode
  - Concurrent in-process HTTP clients
  - Deep continuation chains over the Arc-backed snapshot replay path
- `/v1/accounts/query`
  - Primary alias projection fields
  - Bounded pagination under concurrent clients
- `/v1/accounts/{account_id}/assets/query`
  - Account-local asset predicates over quantity, scope, and owner alias fields
  - Bounded pagination and sorting under concurrent clients
- `/v1/assets/{definition_id}/holders/query`
  - Asset-holder scans with quantity filtering and sorting
- `/v1/contracts/activity`
  - Committed transaction metadata projected through the contract-activity index
  - Authority, contract-alias, entrypoint, result, and timestamp predicates
    under bounded pagination
- Generic aggregate mode
  - Account rows grouped by primary alias domain with count and distinct-count
    metrics
- Socket transport mode
  - The same sustained profile set over ephemeral localhost listeners
  - Useful for comparing handler-only measurements with realistic HTTP client
    and socket overhead

## Running

Build benches:

```
cargo build -p iroha_core --benches --features bench,iroha-core-tests
cargo check -p iroha_torii --bench torii_hot_paths --features app_api
```

Run specific benches:

```
# All query benches in iroha_core
cargo bench -p iroha_core --features bench,iroha-core-tests --bench queries

# Client-path builder benches (mock executor)
cargo bench -p iroha_core --bench queries_client

# Torii signed/app handler-path benches
cargo bench -p iroha_torii --bench torii_hot_paths --features app_api

# Torii socket transport profiles only
cargo bench -p iroha_torii --bench torii_hot_paths --features app_api torii_query_http_socket_sustained
```

Note: Criterion manages output under `target/criterion`. For stable comparisons,
fix CPU governor and isolate noisy background processes. Use multiple runs and
inspect the report variance.

## Interpreting Results

- Iterator cost scales with the number of items scanned; most benches expose
  linear behavior. Sorting adds `O(n log n)` cost; values are sensitive to key
  size and comparison complexity.
- Filtering on the iterator side demonstrates upper bounds for server-side
  filters. In practice, server-side predicates should prefer pre-filtering to
  reduce downstream processing.
- Pagination simulation over full vectors is a proxy to client-side chunking.
  Real systems should rely on server-side pagination (fetch_size) to avoid
  loading entire datasets.
- Client-path builder benches isolate the overhead of constructing and
  downcasting typed batches from `QueryOutputBatchBoxTuple`.
- Torii sustained profiles measure handler-path wall time for fixed operation
  counts and concurrency. They are useful for comparing code changes in routing,
  bounded-count pagination, alias projection, account-asset predicates,
  asset-holder scans, committed-history contract activity, and aggregate
  execution, but they intentionally do not replace socket-level soak tests.
- Torii socket profiles exercise the same workloads through localhost HTTP.
  Compare them against the in-process group to estimate transport overhead
  before running longer node-level or multi-process soak tests.

## Next Steps

- Add selection (projection) once server-side projections are reintroduced.
- Expand to triggers and blocks with synthetic state builders.
- Run the full Torii socket profile suite under production-like datasets and
  longer measurement windows to decide whether the existing account-asset,
  asset-holder, and contract-activity predicates need additional indexes or
  materialized views.
