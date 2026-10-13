# Deterministic settlement pricing

The [`settlement_router` crate](../crates/settlement_router/src/lib.rs) implements
exact XOR pricing, receipt construction and buffer-policy evaluation. Core exposes
these helpers through [`SettlementEngine`](../crates/iroha_core/src/settlement/mod.rs)
and retains an engine derived from the State-owned router configuration.

`SettlementEngine::quote` accepts canonical `Quantity` and `Numeric` values,
applies volatility margins and liquidity haircuts, and returns exact XOR
quantities. Both pricing stages round toward positive infinity at XOR's
nine-digit precision boundary. Non-positive TWAPs, haircuts above 100% and
out-of-domain arithmetic fail explicitly. A quote is pricing data: it does not
authorize a balance or reserve mutation.

`SettlementEngine::evaluate_buffer` classifies exact remaining capacity using the
configured thresholds. The optional typed lane `settlement_buffer` descriptor
contains a canonical account, canonical asset-definition ID and positive exact
XOR capacity. Configuration validates these fields together; aliases, partial
descriptors and retired metadata fields are rejected. See the
[configuration implementation](../crates/iroha_config/src/parameters/user.rs).

The current block execution path has no pending-settlement accumulator or buffer
snapshot publisher. Settlement metric definitions and the
[Grafana dashboard](../dashboards/grafana/settlement_router_overview.json) remain
available, but their presence does not establish automatic reserve sampling or
per-block settlement telemetry.

Lane transactions pay fees during merge execution. The current lane protocol has
no per-lane settlement receipts; see
[Sumeragi lanes §7](../specs/sumeragi_lanes.md#7-fees-and-settlement) and the
[Nexus fee model](../specs/nexus_fee_model.md).

Pricing and buffer-policy coverage lives in `cargo test -p settlement_router`;
the Core facade has unit tests in `crates/iroha_core/src/settlement/mod.rs`.
Public documentation is maintained at [docs.iroha.tech](https://docs.iroha.tech/).
