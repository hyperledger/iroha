# Torii Router Composition

Torii exposes its HTTP surface through a staged, crate-internal builder that
groups related routes and wires shared state exactly once. `RouterBuilder`
wraps `axum::Router<SharedAppState>` and accepts only catalog-backed route
registrations. Each `Torii::add_*_routes` helper receives the same mutable
builder.

## Builder Pattern

The builder API removes the old "return a new `Router`" pattern. Instead of
reassigning a router after every helper, callers invoke the helpers in sequence:

```rust
let mut builder = RouterBuilder::new(
    app_state.clone(),
    RouteCatalog::new(route_catalog::CATALOGED_ROUTES),
    compiled_route_features(),
)?;

// Feature-neutral groups
torii.add_sumeragi_routes(&mut builder);
torii.add_telemetry_routes(&mut builder);
torii.add_core_info_routes(&mut builder);

// Optional feature groups
#[cfg(feature = "connect")]
torii.add_connect_routes(&mut builder);
#[cfg(feature = "app_api")]
torii.add_app_api_routes(&mut builder);

let (router, mounted_manifest) = builder.finish()?;
```

Construction validates the catalog once and indexes its stable route IDs.
Each mount then performs a direct catalog lookup instead of scanning or
cloning the growing registration manifest. This approach guarantees that:

- Every descriptor and every mounted, OpenAPI, SDK, or MCP projection carries
  route-auth metadata schema V1. Catalog validation rejects an absent/legacy
  version instead of inferring authentication or admission semantics. OpenAPI
  operations publish the descriptor-derived contract under
  `x-iroha-route-auth`; MCP `tools/list` publishes the identical four fields
  under `_meta["iroha/routeAuth"]`. OpenAPI also projects standard header
  security schemes for canonical account, optional canonical account,
  onboarding-token, and exact operator-signature policies; protocol-specific
  bearer or handshake schemes remain owned by their operation definitions.
- A route's method, authentication policy, path, feature gate, and stable ID
  agree with its canonical descriptor.
- Duplicate registrations are rejected by stable ID, while finalization
  rejects both missing and unexpected mounts.
- Feature-gated helpers compose deterministically regardless of compile-time
  configuration.
- Tests can exercise different combinations without juggling intermediate
  `Router` values.

## Regression Tests

The integration test `crates/iroha_torii/tests/router_feature_matrix.rs`
constructs Torii with a minimal in-memory stack and ensures the router builds
under the active feature set. Torii embeds the package-local mirror at
`crates/iroha_torii/assets/openapi/torii.json`, parses it once with Norito JSON,
and caches both the document and response. The complete release feature profile
serves those exact bytes; reduced profiles remove only path/method operations
disabled by the compiled route catalog and serialize the pruned document once.

When the schema/OpenAPI endpoint is compiled in, the test can compare the
served static authority against an expected file:

- Set `IROHA_TORII_OPENAPI_EXPECTED=/path/to/openapi.json` to assert the
  served document matches the expected authority.
- Optionally set `IROHA_TORII_OPENAPI_ACTUAL=/tmp/iroha-openapi.json` to write
  the current output for manual inspection or diff tooling.

If the OpenAPI endpoint is unavailable the diff is skipped automatically. The
test also performs feature-gated smoke requests (e.g., `/v1/domains` under
`app_api`, strict management-token `/v1/connect/status?sid=...`, and unsigned
rejection at `/v1/connect/status/aggregate`) to verify the staged builder covers
every route group.

## Routed Request Diagnostics

An exact signed `FindAssetById` for a locally known `Global` asset definition
and a `Global` balance bucket routes to the universal ledger. The holder's
other dataspace bindings and the definition's owning domain do not expand that
read. Account-scoped route authorization and the executor's exact-holder read
permissions still apply. Unknown definitions and explicit dataspace buckets
do not inherit this shortcut.

Cross-dataspace Torii proxy failures return structured headers in addition to
the normal reject-code body. A `503` with `x-iroha-reject-code:
route_unavailable` should be triaged from these headers before treating the
request payload as invalid:

- `x-iroha-route-lane-id` and `x-iroha-route-dataspace-id` identify the
  resolved target lane/dataspace.
- `x-iroha-route-unavailable-reason` is one of
  `missing_authoritative_binding`, `authoritative_peers_offline`, or
  `loop_prevention_exhausted`.
- `x-iroha-route-authoritative-total`,
  `x-iroha-route-authoritative-offline`, and
  `x-iroha-route-loop-prevention-drops` distinguish catalog drift, offline
  authoritative peers, and proxy-hop loop prevention.

Configured public-dataspace HTTP upstreams may forward only one
`x-iroha-reject-code` on a `4xx`/`5xx` response, and it must satisfy Torii's
bounded grammar: 1–128 ASCII letters, digits, `_`, `.`, `:`, or `-`. This
preserves `route_unavailable` skip semantics without reflecting contradictory,
arbitrary, or ambiguous upstream headers. Peer proxy snapshots, including local
`502` fallbacks for header/body overflow, cap diagnostic bodies at the
request-specific response limit so receiver-side bounds validation cannot
discard the fallback. Body-read errors use fixed local diagnostic text and
never reflect or format an upstream body's error value.

Signed-query fanout admits singular queries only. It retains the first successful
output and compares each later output sequentially; conflicting results fail.
Iterable signed queries execute on their selected authoritative route. Core has no
canonical top-K fanout accumulator or alternate canonical-output query mode.
The signed-fanout working set charges request decoding, retained and current
singular outputs, bounded canonical frames, response encoding, and transport
copies. Application collection reads retain separate row and merge accounting
within the same phase ceilings.

Application read fanout visits dataspace routes in sequence under its bounded
working set and merges the routes that answer successfully. Candidate-peer
hedging within a routed proxy request is separate from this dataspace traversal.
Skipped not-found, unavailable, and alias-permission replies release their
upstream bodies, headers, extensions, and memory reservations before the next
route. The aggregate retains fixed local error text and failure counters;
capacity and other non-skippable failures still stop collection. Responses include
aggregate fanout headers:

- `x-iroha-fanout-routes-attempted`
- `x-iroha-fanout-routes-succeeded`
- `x-iroha-fanout-routes-failed`
- `x-iroha-fanout-routes-unavailable`
- `x-iroha-fanout-routes-not-found`
- `x-iroha-fanout-first-failure`

Successful fanout responses keep these counters so operators can see partial
route degradation even when another dataspace supplied the requested result.
Typed singleton reads such as `GET /v1/proofs/{id}` now use the same routed
fanout path, but they preserve the canonical Norito payload after merging
matching dataspace results. When every candidate dataspace misses the same
proof id, the routed path now normalizes that miss back to `404 Not Found`
instead of surfacing the executor's internal
`QueryExecutionFail::Conversion("ProofRecord not found")` shape as `400`.

`RouterBuilder` is not a compatibility surface for external route injection.
The first release has one catalog-enforced composition path and carries no
adapter for older builder shapes.

## Further Reading

- `specs/torii/app_api_parity_audit.md` — parity matrix covering the `app_api` and `connect` route groups, their DTOs, and existing test coverage.
- `crates/iroha_torii/docs/mcp_api.md` — canonical Torii MCP JSON-RPC contract (`/v1/mcp`) for agent/tool integrations.
