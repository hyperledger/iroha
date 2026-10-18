---
title: SoraFS XOR Hedging & Billing
summary: SFM-5 target architecture and current gap status for XOR price feeds, hedging, billing statements, risk controls, and rollout.
---

# SoraFS XOR Hedging & Billing

## Status
SFM-5 now has a local deterministic SoraFS hedging/billing payload foundation in
`crates/sorafs_manifest::hedging`. The workspace ships canonical Norito/JSON
schemas for normalized XOR/USD feed samples, reference-price decisions, billing
line items, and billing statements. Pure helpers replay weighted fixed-point
reference-price aggregation, stale/rejected-feed refusal, divergence degradation
flags, exact XOR-to-USD multiplication, billing
totals, and BLAKE3 digest ids for statements and line items.
The first-release payload validators now also enforce bounded canonical text,
at most 64 uniquely identified and uniquely sourced feeds, an exact 10,000 bps
weight budget, sorted feed/reason inventories, and checked weighted arithmetic.
Statements cap account and line cardinality, sort line IDs canonically, reject
duplicate source events, bind category to debit/credit direction and metered
quantity, require the reference decision to be effective exactly at the period
end, and expose an exact predecessor/account/contiguous-period transition
validator. Digest preimages include their canonical Norito byte length. The
generated positive and adversarial fixture set was regenerated against these
rules and passes the full fixture validator.
The reference validator also accepts those payloads through
`validate_hedging_payload_bytes`, and `iroha app sorafs toolkit validate hedging` can
validate feed, decision, line-item, and statement files with deterministic
operator outcomes.
The source bridge surface also exposes the same reference validator through
`sorafs_reference_validate_hedging_json`, Connect C/JNI
`connect_norito_sorafs_reference_validate_hedging_json`, and Kotlin/JVM, Java
Android, and Swift SDK wrappers. The bridge source and checked C header both
declare the sole first-release ABI, version 30; packaged
native artifacts still need to be regenerated before SDK release consumption.
`scripts/check_sorafs_hedging_rollout_evidence.py` now provides the SFM-5
promotion gate for staged rollout evidence. It requires feed-collector,
reference-price, billing-cycle, statement-publication, reconciliation,
metrics/alert, native-bridge-release, and governance-approval artifacts, rejects
payload-bearing evidence including common camel-case or hyphenated secret-key
spellings, and requires at least two distinct successful staged billing cycles
before reporting `ready`. Feed-collector and reference-price artifacts also
bind `feed_count` to the unique canonical `feeds[].name` inventory, require
`accepted_feed_count` to equal `feed_count`, require coverage for the reviewed
`feed-primary`, `feed-secondary`, and `feed-tertiary` price feeds, and reject
duplicate or unknown feed entries before promotion can report ready.
Feed-collector `feed_lag_seconds` and reference-price `divergence_bps` and
`decision_lag_seconds` must be non-negative integer-unit evidence before they
can satisfy rollout ceilings; `divergence_bps` and the operator
`--max-divergence-bps` threshold are also capped at `10000`, so impossible
basis-point rates cannot satisfy promotion. Billing-cycle evidence must bind each cycle
to a valid reference-price decision id from the same rollout bundle and carry only
payload-free line-item roots, statement-bundle digests,
reconciliation digests, and per-statement digest arrays whose length matches
the signed statement count, plus `policy_digest_hex` for the billing policy
that priced the staged cycle. Billing-cycle artifacts also require `cycle_id`
to match a reviewed lowercase `billing-cycle-*` label without non-production markers,
bind `statement_count` to the unique canonical `statements[].name` inventory
using reviewed `billing-statement-*` labels without non-production markers,
and bind `line_item_count` to the unique canonical `line_items[].name`
inventory using reviewed `billing-line-item-*` labels without non-production
markers, rejecting duplicate statement or line-item entries before promotion
can report ready.
Statement-publication, reconciliation,
metrics/alert, and governance-approval evidence must also carry the same
`statement_bundle_digest_hex`/`reconciliation_digest_hex` tuple as a valid
staged billing cycle in the same rollout bundle, and governance approval
`policy_digest_hex` must match a valid billing-cycle policy digest. The
aggregate production-readiness gate now derives cycle tuple and policy digest
sets from `valid_billing_cycles`: `valid_cycle_bindings` must match those cycle
tuples, `valid_policy_digests` must match those cycle policies, and every
billing-cycle `reference_decision_id_hex` must appear in
`valid_reference_decision_ids` before final promotion can report ready. It also
rechecks the lane-proven bound artifacts before final promotion:
cycle-bound artifact fingerprints must match `valid_cycle_bindings`, and
policy-bound artifact fingerprints must match `valid_policy_digests`. The
hedging gate fail-closes when more than one valid cycle tuple or policy anchor
appears, and clears the mixed `valid_cycle_bindings` or
`valid_policy_digests` set before aggregate promotion can report ready.
Statement-publication artifacts also bind `route_count` to the unique canonical
`routes[].name` inventory and reject duplicate or unknown route entries before promotion
can report ready, require every route response to carry a lowercase
`body_blake3_hex` digest, and bind `acknowledgement_probe_count` to the
unique canonical `acknowledgement_probes` inventory using reviewed
`billing-ack-probe-*` labels without non-production markers. Reconciliation
artifacts also bind `source_count` to the
    unique canonical `sources[].name` inventory and `line_item_count` to the
    unique canonical `line_items[].name` inventory using reviewed
    `billing-line-item-*` labels without non-production markers, rejecting
    duplicate or unknown source entries and duplicate line-item entries before
    promotion can report ready. Native-bridge release
    artifacts also bind
`artifact_count` to the unique canonical `artifacts[].id` inventory, require
reviewed `hedging-native-artifact-*` labels without non-production markers, and
reject duplicate artifact entries before promotion can report ready. They also
require artifact IDs to start with reviewed native bridge family prefixes and
at least one Swift-family plus one JNI-family artifact before promotion can
report ready, matching the Swift XCFramework plus JNI bridge release evidence
shape used by the checked-in canary fixtures. Metrics/alert
artifacts also bind `metric_count` to the unique canonical `metrics` inventory
and reject duplicate or unknown metric entries before promotion can report ready.
The summary exports the sorted reviewed `metrics` inventory plus
`metric_count_values`, and the aggregate production-readiness gate requires
those fields to match the metrics/alert artifact fingerprint before final
promotion can report ready. This
prevents promotion packets from mixing statement publication, reconciliation,
dashboard, approval, or policy artifacts from different billing runs.
Reference-price, cycle-tuple, and policy-digest binding failures are recorded
on the offending artifact before required-kind validity is computed, so the
JSON summary matches the fail-closed rollout decision. The
checker supports shell-style
`@ARGFILE` inputs
so reviewed operator evidence paths can be replayed without embedding secrets
or raw billing payloads. The checker exports its required top-level payload
fields as `EVIDENCE_REQUIRED_FIELDS`, and the collection planner dry-run JSON
includes the checker-backed `evidence_contract` map for selected required
kinds.
`scripts/run_sorafs_hedging_rollout_evidence.py` now provides the matching
collection planner/runner for reviewed staged evidence. It accepts explicit
payload-free canary artifacts, supports shell-style `@ARGFILE` inputs, forwards
the gate thresholds, preflights the verifier script and output targets before
printing dry-run plans, and invokes the checker with a reproducible summary
path. The planner does not replace live feed acquisition, the deployment-owned
finalized-query/journal-verifier/signer/publisher/acknowledgement/witness
adapters, governance approval, or genuine deployment evidence; operators must
still capture those canary artifacts before promotion can pass.
`scripts/build_sorafs_hedging_canary.py` is a payload-free SFM-5 hedging/billing canary builder
for feed collector, reference price, billing
cycle, statement publication, reconciliation, metrics/alerts, native-bridge
release, and governance approval evidence. It takes reviewed deployment facts,
requires every positive proof claim and required
feed/line-item/route/source/metric coverage explicitly, rejects duplicate or
unknown `--verified-claim`, feed, route, source, and metric closed-set inputs
before writing, forces raw feed, statement, financial-record, response-body, and
debug-artifact inclusion flags to `false`, rejects malformed,
non-production, or duplicate `--artifact` ids for native-bridge release
canaries, rejects native-bridge release canaries with fewer than two distinct
artifact ids, requires statement-publication canaries to take explicit
`--route-body-blake3-hex` response digest evidence, emits `metric_count` matching the canonical
`metrics` inventory, rejects ungoverned hedge-execution enablement, validates
each generated artifact through the hedging/billing rollout gate, and writes
atomically without following output symlinks. Billing-cycle canaries require
reviewed `--cycle-id` labels to match the same `billing-cycle-*` production shape
enforced by the gate. Billing-cycle and governance-approval canaries require
reviewed `--policy-digest-hex` input, and billing-cycle canaries require
reviewed `--statement` labels in the `billing-statement-*` family whose unique
inventory matches `--statement-digest-hex`, and billing-cycle plus
reconciliation canaries require reviewed `--line-item` labels in the
`billing-line-item-*` family whose unique inventory matches `--line-item-count`
before locally generated evidence exercises the same policy-bound promotion
path. The builder is an evidence
packaging aid; it does not replace live feed acquisition, deployment-owned
finalized-query and journal-verifier adapters, the external software signer, immutable
publisher, acknowledgement authority, sealed witness store, deployment of the
authenticated runtime API, or native bridge release process.

This is not yet a complete production hedging and billing stack. There is still no
price-feed collector, concrete production finalized-query/journal-verifier
adapter, independently administered external software signer, immutable publication service,
acknowledgement authority, sealed epoch-witness store, released native bridge
artifacts, deployed instance of the shipped API, or captured staged rollout
evidence that passes the SFM-5 gate. The supervised projector/delivery worker,
its authenticated Torii API, the Rust client, and the standard `iroha_cli`
commands are shipped as source modules. Lifecycle management remains the
responsibility of the standard `irohad` supervisor and deployment service
manager; there is deliberately no separate `hedgingd` or `billingd` binary and
no process-local daemon-control API.
The checked-in fixture generator,
fixture manifest, README, and generated `.to`/`.json` byte suite define the
canonical SFM-5 feed, reference-price, line-item, statement, and negative
fixture set. A checked-in Grafana dashboard plus Prometheus alert/test fixtures
and runtime telemetry define the local hedging/billing alert contract; live
scrapes, alert routing, and response evidence remain deployment work.
`HedgingPriceFeedV1.evidence_digest` remains an intrinsic evidence binding only;
the raw payload by itself does not authenticate an external feed signer. The
manifest crate now ships `SignedHedgingPriceFeedV1` and an external
`HedgingFeedTrustPolicyV1` that binds strong Ed25519 keys to exact
`(feed_id, source)` pairs, validity/freshness/skew limits, and explicit
revocations. `GovernedHedgingReferencePriceDecisionV1` retains and replays all
signed inputs, while `GovernedBillingStatementV1` prevents a statement from
downgrading its reference price to unauthenticated raw feeds. Their canonical
decoders are byte/allocation bounded and reject trailing or compressed
noncanonical Norito. `SignedHedgingFeedLedgerV1` now supplies the deterministic
collector-side high-water state: it keeps one latest signed sample per feed,
binds the external policy digest, rejects global admission-clock rollback,
per-feed observation rollback, exact replay, same-time equivocation, reused
evidence digests, malformed ordering, and tampered restart checkpoints. Updates
replace the prior per-feed high-water mark, so the checkpoint stays bounded for
an indefinitely running collector; every governed decision still retains its
complete signed input set for immutable audit history. Deployment admission
must remain disabled until the live collector and every deployment-owned
runtime adapter load the reviewed policy and accept only these governed
wrappers at their trust boundaries.

The pre-release embedded economics authority has been hard-cut. `sorafs_node`
does not admit or query an independent governed-pricing series or signed-feed
ledger, and Torii does not mount the former `/v1/sorafs/economics/*` mutation or
read family. The `sorafs_economics_operator` role is retired. The non-secret
`hedging_feed_trust_policy_path` remains only as a configuration-pinned input to
the committed hedging/billing runtime, which validates signed feeds while
reconciling finalized ledger pages. It is not a second source of pricing,
billing, or feed truth.

Development state created by the retired implementation is deliberately not
migrated. Before starting a V1 node on a reused development data directory,
operators must archive or delete `economics/governed-pricing.to` and
`economics/signed-hedging-feeds.to`, then reseed through the canonical ledger
and committed-service path. Production backups and restore procedures must not
classify either retired file as authoritative state.

The separate `sorafs_node::hedging_billing_service` and supervised
`irohad::sorafs_hedging_billing_runtime` now implement the local committed
service pipeline. The bounded finalized-query and consensus-journal-verifier
interfaces ingest contiguous typed event pages and authenticated period closes.
The service policy and every finalized page or close, journal commitment,
replay identity, checkpoint or compacted archive, signed statement,
acknowledgement, epoch witness, and hedge intent carry the mandatory
genesis-derived `NetworkId`. Digest and signature preimages bind its exact raw
bytes; a human-readable chain label is display-only and is never accepted as a
security domain or compatibility fallback. Stock `irohad` derives the runtime
identity from mandatory `genesis.expected_hash` before opening durable state.
The durable projector deterministically derives open accruals, per-account
governed statements, aggregate XOR exposure, and never-automatic hedge intents;
it retains exact finalized cursors, replay receipts, delivery state, dead
letters, acknowledgements, and sealed epoch-transition witnesses. The
supervised worker signs through a runtime-only external software-signer interface, publishes
through an identity-pinned immutable sink, reconciles ambiguous publications
and authoritative acknowledgements, and emits payload-free readiness, cursor,
delivery, dead-letter, and hedge-intent metrics. `iroha_config` contains only
the public policy path/digest, bounded work cadence, private state directory,
and each adapter's opaque handle, non-zero revision, and public-policy digest;
missing, test-marked, unready, substituted, stale, or identity-drifting
dependencies fail before durable state opens and are requalified around every
external operation. No worker or timer accepts a hedge-execution adapter.
Every generated intent sets `automatic_execution=false`, and the separate
explicitly authorized submission helper rejects adapters that claim automatic
execution.

These source boundaries do not supply live market feeds or concrete production
implementations of the finalized query, journal verifier, signer, publisher,
acknowledgement authority, sealed witness store, or governed venue adapter.
Those independently administered providers, software-key custody, and deployment
evidence remain external release inputs.

## Goals & Scope
- Maintain a resilient XOR/USD reference price for SoraFS billing and economic reporting.
- Generate dual-quoted billing statements in XOR and USD for providers and buyers.
- Provide APIs, CLI tooling, and alerts for escrow runway, exposure, invoice reconciliation, and statement acknowledgement.
- Keep decisions auditable through signed Norito payloads, deterministic logs, and governance evidence.

## Target Architecture
| Component | Responsibility | Current workspace status |
|-----------|----------------|--------------------------|
| Hedging engine | Aggregate price feeds, derive the reference XOR/USD rate, track exposure, and optionally execute hedges. | Local pure reference-price helpers and the supervised finalized-ledger projector ship deterministic exposure totals and bounded hedge intents. There is no competing embedded feed ledger. Live collector automation and a production venue adapter remain external. Automatic execution is absent; only an explicitly authorized, idempotent helper may call an adapter that reports automatic execution disabled. |
| Price feed collectors | Fetch primary/secondary/tertiary feeds and normalize them into signed price payloads. | Not shipped for SoraFS hedging. |
| Billing aggregator | Consume settlement, rent, egress, fee, and penalty events and produce account accruals. | The local service consumes typed finalized storage, orderbook-settlement, reserve/rent, egress, orchestrator-fee, incentive, penalty, and governance-adjustment events; it durably projects accruals and deterministic fixed-period governed statements. The production finalized-query and journal-verifier implementations remain external. |
| Statement publisher | Store, sign, publish, notify, and track acknowledgements for statements. | The local delivery state machine persists signing claims, signed statements, ambiguous publication state, immutable receipts, acknowledgements, retry limits, and dead letters. Private-key-free runtime interfaces and opaque identity bindings are shipped; the external software signer, immutable publisher, and acknowledgement service are deployment-owned. |
| Alerting service | Monitor committed runtime health and finalized projection freshness. | Checked-in Grafana/Prometheus alert fixtures cover successful-tick freshness plus finalized projection availability and lag. The runtime also exposes bounded dependency, delivery, dead-letter, and hedge-intent status for deployment-owned extensions. Production scrapes, alert routing, and response evidence remain open. |

## Target Price Feeds And Decisions
- Primary feed: governance-approved on-chain XOR/USD or XOR/stablecoin TWAP.
- Secondary feed: independent market feed or synthetic pair.
- Tertiary feed: internal market/orderbook-implied sanity check once SFM-2 exists.
- Implemented locally: reject stale/rejected feeds before decision construction
  and mark the decision degraded on feed divergence or degraded collector status.
- Implemented locally: use deterministic integer weighted-average math for
  aggregation and replay.
- Implemented locally: record every decision as a versioned Norito payload with
  feed inputs, weights, status, evidence digests, degradation reasons, and a
  BLAKE3 decision id.

Automated hedge execution must remain off until governance approves venues,
keys, limits, failover rules, and reconciliation evidence.

## Target Billing Pipeline
- Event sources: orderbook settlement receipts, reserve/rent ledgers, egress accounting, orchestrator fees, provider incentives, and governance penalties.
- Hourly accruals update account-level usage and projected escrow runway.
- Implemented locally: bounded contiguous finalized pages, authenticated journal
  commitments, and typed period closes drive the durable accrual projector; the
  configured finalized-query and journal-verifier implementations are injected
  external adapters.
- Implemented locally: weekly/ad-hoc statements finalize line items,
  adjustments, XOR totals, USD equivalents, reference-price binding, and due
  dates.
- Implemented locally: statement payloads are Norito-first; PDF/email delivery
  remains a presentation layer over the signed payload.
- Implemented locally: statement signing claims, immutable publication,
  ambiguous-write lookup, authenticated acknowledgement, reconciliation,
  retry/dead-letter state, and exposure-derived hedge intents are durable and
  idempotent. Signing and publication cross runtime-only adapter interfaces;
  their production services and credentials are not repository artifacts.
- Statement hashes should be publishable into governance evidence once the governance DAG pipeline is available.

## Target APIs And CLI
The five pre-release local economics routes are retired and must return 404;
there are no aliases or compatibility handlers. Public hedging and billing
views come from the committed runtime API and never from process-local pricing
or feed checkpoints. Torii now mounts exactly this V1 family:

- `GET /v1/sorafs/billing/status`
- `GET /v1/sorafs/billing/statements`
- `GET /v1/sorafs/billing/statements/{statement_id}`
- `POST /v1/sorafs/billing/statements/{statement_id}/acknowledgements`
- `GET /v1/sorafs/billing/reconciliation`
- `GET /v1/sorafs/hedging/exposure`
- `GET /v1/sorafs/hedging/intents`

Every route requires canonical account authentication, bounds
query/body/page inputs, and returns `Cache-Control: private, no-store`.
Authenticated `GET /v1/sorafs/billing/status` is the bootstrap-anchor route:
any canonically authenticated account may call it, it is not gated by the
`sorafs_billing_manager` role, and its payload-free response carries the exact
current projection anchor required by subsequent owner and finance reads.
Manager-only reconciliation and the owner/governed-finance boundaries remain
on their narrower routes. Every catalogued `GET` route also accepts its
implicit authenticated `HEAD` request.

The acknowledgement route accepts one exact canonical Norito body containing a
required non-zero client `request_nonce` plus the bounded
`authentication_proof`. The proof-independent acknowledgement digest binds the
statement, canonical owner account, and request nonce; proof bytes are
deliberately excluded from their own preimage. Native Norito JSON response
fields backed by `[u8; 32]` use exactly 64 uppercase hexadecimal characters,
while the separately documented HTTP query and path digest parameters remain
lowercase hexadecimal. Statement lookup collapses absent, unpublished, and
wrong-owner cases to the same response. The family exposes no feed-ingestion,
automatic-execution, or local-authority mutation route.

Implemented local validator CLI: `iroha app sorafs toolkit validate hedging` validates Norito
feed, reference-price decision, billing-line, and statement payloads. The
standard signed-client CLI also mirrors every shipped runtime route:
`sorafs billing status`, `statements`, `statement`, `acknowledge`, and
`reconciliation`, plus `sorafs hedging exposure` and `intents`. Exact-checkpoint
reads require canonical lowercase identifiers and bounded page sizes.
Acknowledgement reads a bounded direct regular proof file, and statement
download creates a new canonical Norito output without following a symlink or
replacing an existing path. No CLI command can ingest a feed, publish a
statement through local authority, control the daemon, or execute a hedge.

Implemented source SDK/FFI bridge: Rust C FFI, Connect C/JNI, Kotlin/JVM, Java
Android, and Swift callers can pass the same four hedging/billing payload
selectors and receive the canonical reference-validator JSON outcome.

## Target Observability
The checked-in SFM-5 observability pack includes
`dashboards/grafana/sorafs_hedging_billing.json`,
`dashboards/alerts/sorafs_hedging_billing_rules.yml`, and
`dashboards/alerts/tests/sorafs_hedging_billing_rules.test.yml`. The supervised
billing worker emits bounded status for readiness, external dependency health,
finalized height/sequence, statement signing/publication/acknowledgement state,
dead letters, retained hedge intents, automatic-execution state, and tick
results. Runtime status can report `ready=true` only when its latest successful
tick remains inside the fixed freshness window and the projection contains a
non-zero finalized cursor and height within the configured
`max_finalized_lag_blocks` distance from the authenticated query head; an
empty, lagging, or stale projection remains unready. The alert pack covers:

The node-owned statement, exposure, intent, anchor, and reconciliation APIs do
not trust that cached readiness summary. Each call holds the reconciliation
fence, live-probes the qualified finalized-query provider, applies the same
tick-freshness and maximum-lag bounds, and rechecks the exact observed head
before returning. Acknowledgement additionally rechecks that exact head before
the authoritative record and immediately before the local durable checkpoint
store write, so an in-flight head change cannot mutate the served projection.

- Successful runtime-tick freshness.
- Finalized projection availability and maximum accepted lag.
- Finalized ledger head and projected heights.

Price/feed, exposure, statement generation/failure, acknowledgement backlog,
escrow runway, decision result, statement latency, venue inventory, and billing
line-item metrics require deployment-owned collectors and publishers plus
deployed scrape and service integration.

The alert pack covers a stale successful tick, an unavailable finalized
projection, and finalized projection lag above the committed bound. The
Prometheus rule test pins firing and non-firing cases for those conditions.

The rollout evidence gate expects the deployed dashboard/alert canary to prove
the presence of successful-tick freshness, finalized-projection readiness and
lag, and finalized head/projected height metric families while reporting no
firing critical alerts.

## Security & Governance Requirements
- Price-feed and statement payloads must be signed and replayable.
- Hedge trades require governance-approved keys, venues, inventory limits, and manual override policy.
- Financial data storage needs encryption, retention, and audit-log policy before production use.
- API scopes should distinguish read-only hedging, billing read, billing management, and treasury operations.
- Production behavior must be configured through `iroha_config`, not environment variables.

## Testing Strategy
Required before rollout:
- Implemented locally: unit tests for feed validation, fixed-point aggregation,
  divergence degradation, billing line items, statement totals, digest replay,
  Norito/JSON roundtrips, reference-validator outcomes, and validator CLI
  parser aliases.
- Integration tests with stale/divergent feed simulations and synthetic settlement/rent inputs.
- End-to-end tests from usage events through statement finalization and acknowledgement.
- Serialization and fixture tests for all statement, feed, decision, and adjustment payloads.
- Implemented locally as a generated fixture suite:
  `cargo run -p sorafs_manifest --features dev-tools --bin generate_hedging_fixtures` emits the
  target positive and negative SFM-5 `.to`/`.json` fixture set documented in
  `fixtures/sorafs_manifest/hedging/README.md`. The target file inventory and
  validator commands are pinned in
  `fixtures/sorafs_manifest/hedging/fixture_manifest.json`, and
  `scripts/check_sorafs_hedging_fixture_manifest.py` validates the manifest in
  pre-generation mode, including accepted/rejected path and reviewed
  `negative_case` contracts, or fails closed on missing/mismatched generated
  bytes in full mode. Full mode also runs the pinned `iroha app sorafs toolkit validate hedging`
  command contract without shell execution and compares each generated payload
  against the manifest's accepted or rejected outcome, verifies the
  kind-specific top-level and nested JSON sidecar field set, checks V1
  versioning, duplicate nested ids, account-id hex binding, and statement
  timestamp ordering, enforces even-length lowercase hex payload mirrors,
  positive prices and timestamps, canonical signed-512 exact-decimal amount
  strings (at most 28 fractional digits generally and nine for XOR), canonical
  unsigned `u128` metered-quantity strings, and bounded basis-point fields, and rejects extra
  generated `.to` or `.json` files that are not pinned by the manifest. The
  generated positive and negative fixture byte suite is checked in under
  `fixtures/sorafs_manifest/hedging/`, and the rollout contract pins those
  files to the manifest inventory so future deletions or unmanifested fixture
  drift fail closed.
- Reconciliation tests comparing generated statements with underlying ledger and settlement sources.
- Rollout evidence collection with
  `scripts/run_sorafs_hedging_rollout_evidence.py
  @scripts/examples/sorafs_hedging_rollout_collection.args.example`, followed
  by validation with
  `scripts/check_sorafs_hedging_rollout_evidence.py
  @scripts/examples/sorafs_hedging_rollout_evidence.args.example`. Production
  promotion remains blocked unless the summary status is `ready`, including at
  least two distinct staged billing cycles whose reference-decision ids match a
  valid reference-price artifact in the same evidence bundle. The same
  promotion contract now requires staged billing-cycle `policy_digest_hex`
  values to anchor governance approval and binds `statement_count` to reviewed
  `statements[].name` inventory using `billing-statement-*` labels without
  non-production markers and `line_item_count` to reviewed `line_items[].name`
  inventory using `billing-line-item-*` labels without non-production markers.
  Feed canaries also bind `feed_count` to
  reviewed `feeds[].name` inventory, require `accepted_feed_count` to match,
  and require the reviewed `feed-primary`, `feed-secondary`, and `feed-tertiary`
  price feeds while rejecting unknown feed names.
  Hedging/billing payload-safety artifacts must explicitly set
  `payload_bytes_included`, `response_bodies_included`, `degraded`,
  `statement_bodies_included`, `raw_financial_records_included`,
  `critical_alerts_firing`, and `debug_artifacts` to `false` before promotion
  can report ready.
  Statement-publication canaries bind `route_count` to reviewed
  `routes[].name` inventory, reject unknown route names, and require each
  generated route record to carry the reviewed `--route-body-blake3-hex`
  response digest.
  Statement-publication canaries bind `acknowledgement_probe_count` to reviewed
  `billing-ack-probe-*` `acknowledgement_probes` inventory and reject duplicate
  or non-production acknowledgement probes.
  Reconciliation canaries bind both `source_count` to reviewed `sources[].name`
  inventory and `line_item_count` to reviewed `line_items[].name` inventory
  using `billing-line-item-*` labels without non-production markers, rejecting
  unknown source names. Metrics canaries reject unknown metric names outside the
  reviewed alert inventory.
  The collection
  planner's dry-run JSON includes the checker-backed `evidence_contract` map so operators can
  inspect the exact required fields for each requested evidence kind before
  collecting or submitting live billing artifacts. For reviewed local canary
  packaging, generate payload-free artifacts with
  `scripts/build_sorafs_hedging_canary.py
  @scripts/examples/sorafs_hedging_reference_price_canary.args.example` and
  `scripts/build_sorafs_hedging_canary.py
  @scripts/examples/sorafs_billing_cycle_canary.args.example` and
  `scripts/build_sorafs_hedging_canary.py
  @scripts/examples/sorafs_statement_publication_canary.args.example` before
  passing the generated evidence files to the rollout gate; production promotion still
  requires at least two distinct billing-cycle artifacts.

## Rollout Status
- Done: target requirements are documented; adjacent reserve, DA rent telemetry,
  and generic billing/oracle foundations exist; local SoraFS hedging/feed,
  reference-price decision, billing-line, and billing-statement Norito payloads
  plus deterministic math/tests and iroha-cli/CLI coverage are
  shipped; source-level Rust C FFI, Connect C/JNI, Kotlin/JVM, Java Android,
  and Swift bridge wrappers are shipped; the SFM-5 rollout evidence gate and
  collection planner with dry-run evidence-contract export plus operator
  argument-file examples are shipped; payload-free canary builder support for
  all SFM-5 evidence kinds is shipped; the
  deterministic hedging/billing fixture generator, fixture manifest, and
  fixture README are shipped; the fixture manifest checker and focused tests are
  shipped, including accepted/rejected validator outcome enforcement for full
  generated-byte checks, nested JSON sidecar shape/value validation, and exact
  generated-file inventory rejection; the generated fixture byte files are
  checked in and pinned by the rollout contract; the
  checked-in Grafana dashboard and Prometheus alert/test fixtures define the
  runtime observability contract, and
  `iroha_telemetry::Metrics` exposes helper methods for those metric families.
  The gate
  rejects staged billing cycles that omit digest roots, carry a statement
  digest count that does not match the signed statement count, or reference a
  missing/invalid reference-price decision; it also publishes valid
  billing-cycle policy digests as `valid_policy_digests` and rejects governance
  approval artifacts whose `policy_digest_hex` is not anchored to one of them.
  The aggregate production-readiness gate now derives cycle tuple and policy
  digest sets from `valid_billing_cycles`: `valid_cycle_bindings` must match
  those cycle tuples, `valid_policy_digests` must match those cycle policies,
  and every billing-cycle `reference_decision_id_hex` must appear in
  `valid_reference_decision_ids` before final promotion can report ready. It
  also rechecks cycle-bound and policy-bound artifact fingerprints against
  `valid_cycle_bindings` and `valid_policy_digests`. The hedging gate
  fail-closes when more than one valid cycle tuple or policy anchor appears,
	  and clears the mixed `valid_cycle_bindings` or `valid_policy_digests` set
	  before aggregate promotion can report ready.
- Done locally in source: the `sorafs_node` committed projector and supervised
  `irohad` worker provide bounded finalized ingest, deterministic
  accrual/exposure/statement/hedge-intent derivation, durable signing and
  publication state, acknowledgement and ambiguous-write reconciliation,
  retry/dead-letter handling, strict `iroha_config` policy/identity binding,
  private-key-free external signer/publisher interfaces, and payload-free
  health/alert metrics. Automatic hedge execution is unconditionally disabled
  in the worker.
- Done locally in source: the Rust client and standard `iroha_cli` expose the
  seven authenticated billing/reconciliation/exposure/intent routes. They
  enforce canonical lowercase identifiers, bounded pages and acknowledgement
  proofs, redact authentication material, use direct identity-bound proof-file
  reads on Unix and Windows, and create statement outputs without following or
  replacing existing paths. Focused client/CLI request, validation, filesystem,
  and exact-byte tests are green.
- Remaining: run focused Rust verification; deploy the live feed collector and
  genuine finalized-query, journal-verifier, external software signer, immutable
  publisher, acknowledgement-authority, sealed-witness, and any manually
  governed venue adapters; deploy and exercise the shipped authenticated API
  and CLI; validate production scrapes and alert routing; release native bridge
  artifacts; complete governance approval; and capture at least two successful
  staged billing cycles whose evidence passes the SFM-5 gate.

The runner validates the schema-closed collection-plan envelope before printing dry-run JSON or executing the verifier.
The shared runner plan guard also rejects non-canonical nested required-kind,
threshold, external-evidence, evidence-contract, and command-step shapes before
dry-run output or verifier execution.
