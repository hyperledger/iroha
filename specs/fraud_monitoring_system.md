# Fraud Monitoring System

This document captures the reference design for the shared fraud monitoring capability that will accompany the core ledger. The goal is to provide payment service providers (PSPs) with high-quality risk signals for every transaction while keeping custody, privacy, and policy decisions under the control of designated operators outside the settlement engine.

## Goals and Success Criteria
- Deliver real-time fraud risk assessments (<120 ms 95p, <40 ms median) for every payment touching the settlement engine.
- Preserve user privacy by ensuring the central service never processes personally identifiable information (PII) and only ingests pseudonymous identifiers and behavioral telemetry.
- Support multi-PSP environments where each provider keeps operational autonomy but can query shared intelligence.
- Adapt continuously to new attack patterns via supervised and unsupervised models without introducing non-deterministic ledger behavior.
- Provide auditable decision traces for regulators and independent reviewers without exposing sensitive wallets or counterparties.

## Scope
- **In-scope:** Transaction risk scoring, behavioral analytics, cross-PSP correlation, anomaly alerting, governance hooks, and PSP integration APIs.
- **Out-of-scope:** Direct enforcement (remain PSP responsibility), sanctions screening (handled by existing compliance pipelines), and identity proofing (alias management covers this).

## Functional Requirements
1. **Transaction Scoring API**: Synchronous API that PSPs call before forwarding a payment to the settlement engine, returning a risk score, categorical verdict, and reasoning features.
2. **Event Ingestion**: Stream of settlement outcomes, wallet lifecycle events, device fingerprints, and PSP-level fraud feedback for continuous learning.
3. **Model Lifecycle Management**: Versioned models with offline training, shadow deployment, staged rollout, and rollback support. Deterministic fallback heuristic must exist for every feature.
4. **Feedback Loop**: PSPs must be able to submit confirmed fraud cases, false positives, and remediation notes. System aligns feedback with risk features and updates analytics.
5. **Privacy Controls**: All data stored and transmitted must be alias-based. Any request containing raw identity metadata is rejected and logged.
6. **Governance Reporting**: Scheduled exports of aggregated metrics (detections per PSP, typologies, response latency) plus ad-hoc investigation APIs for authorized auditors.
7. **Resilience**: Active-active deployment across at least two facilities with automatic queue draining and replay. If the service is degraded, PSPs fall back to local rules without blocking the ledger.

## Non-Functional Requirements
- **Determinism & Consistency**: Risk scores guide PSP decisions but do not mutate ledger execution. Ledger commits remain deterministic across nodes.
- **Scalability**: Sustain ≥10k risk evaluations per second with horizontal scaling and message partitioning keyed by pseudo-wallet identifiers.
- **Observability**: Expose metrics (`fraud.scoring_latency_ms`, `fraud.risk_score_distribution`, `fraud.api_error_rate`, `fraud.model_version_active`) and structured logs for each scoring call.
- **Security**: Mutual TLS between PSPs and the central service, an authenticated
  purpose-separated signing service with rotation and revocation for response
  envelopes, and tamper-evident audit trails.
- **Compliance**: Align with AML/CFT requirements, provide configurable retention periods, and integrate with evidence preservation workflows.

## Architecture Overview
1. **API Gateway Layer**
  - Receives scoring and feedback requests over authenticated HTTP/JSON APIs.
   - Performs schema validation using Norito codecs and enforces rate limits per PSP id.

2. **Feature Aggregation Service**
   - Joins incoming requests with historical aggregates (velocity, geospatial patterns, device usage) stored in a time-series feature store.
   - Supports configurable feature windows (minutes, hours, days) using deterministic aggregation functions.

3. **Risk Engine**
   - Executes the active model pipeline (ensemble of gradient boosted trees, anomaly detectors, rules).
   - Includes a deterministic fallback rule-set to guarantee bounded responses when model scores are unavailable.
   - Emits `FraudAssessment` envelopes with score, band, contributing features, and model version.

## Scoring Models and Heuristics
- **Score Scale & Bands**: Risk scores are normalized to 0–1,000. Bands are defined as: `0–249` (low), `250–549` (medium), `550–749` (high), `750+` (critical). Bands map to recommended actions for PSPs (auto-approve, step-up, queue-for-review, auto-decline) but enforcement remains PSP-specific.
- **Model Ensemble**:
  - Gradient-boosted decision trees ingest structured features such as amount, alias/device velocity, merchant category, authentication strength, PSP trust tier, and cross-wallet graph features.
  - An autoencoder-based anomaly detector runs on time-windowed behavioural vectors (per-alias spend cadence, device switching, temporal entropy). Scores are calibrated against recent PSP activity to limit drift.
  - Deterministic policy rules execute first; their outputs feed the statistical models as binary/continuous features so the ensemble can learn interactions.
- **Fallback Heuristics**: When model execution fails, the deterministic layer still produces a bounded score by aggregating rule penalties. Each rule contributes a configurable weight, summed then clamped to the 0–1,000 scale, guaranteeing worst-case latency and explainability.
- **Latency Budgeting**: Scoring pipeline targets <20 ms for API gateway + validation, <30 ms for feature aggregation (served from in-memory caches with write-behind to persistent stores), and <40 ms for ensemble evaluation. Deterministic fallback returns within <10 ms if ML inference exceeds its budget, ensuring overall P95 stays under 120 ms.
 - **Latency Budgeting**: Scoring pipeline targets <20 ms for API gateway + validation, <30 ms for feature aggregation (served from in-memory caches with write-behind to persistent stores), and <40 ms for ensemble evaluation. Deterministic fallback returns within <10 ms if ML inference exceeds its budget, ensuring overall P95 stays under 120 ms.

## In-Memory Feature Cache Design
- **Shard Layout**: Feature stores are sharded by 64-bit alias hash into `N = 256` shards. Each shard owns:
  - A lock-free ring buffer for recent transaction deltas (5 min + 1 hr windows) stored as struct-of-arrays to maximise cache-line locality.
  - A compressed Fenwick tree (bit-packed 16-bit buckets) to maintain 24 hr / 7 day aggregates without full recomputation.
  - A hop-scotch hash map mapping counterparties → rolling stats (count, sum, variance, last timestamp) capped at 1,024 entries per alias.
- **Memory Residency**: Hot shards stay in RAM. For a 50 M alias universe with 1% active in the last hour, cache residency is ~500k aliases. At ~320 B per alias of active metadata, the working set is ~160 MB—small enough for L3 cache on modern servers.
- **Concurrency**: Readers borrow immutable references via epoch-based reclamation; writers append deltas and update aggregates using compare-and-swap. This avoids mutex contention and keeps hot paths to two atomic ops + bounded pointer chasing.
- **Prefetching**: The scoring worker issues manual `prefetch_read` hints for the next alias shard once request validation completes, hiding main-memory latency (~80 ns) behind feature aggregation.
- **Write-behind Log**: A per-shard WAL batches deltas every 50 ms (or 4 KB) and flushes to the durable store. Checkpoints run every 5 minutes to keep recovery bounds tight.

### Theoretical Latency Breakdown (Intel Ice Lake-class server, 3.1 GHz)
- **Shard lookup + prefetch**: 1 cache miss (~80 ns) plus hash calculation (<10 ns).
- **Ring buffer iteration (32 entries)**: 32 × 2 loads = 64 loads; with 32 B cache lines and sequential access this stays in L1 → ~20 ns.
- **Fenwick updates (log₂ 2048 ≈ 11 steps)**: 11 pointer hops; assuming half L1, half L2 hits → ~30 ns.
- **Hop-scotch map probe (load factor 0.75, 2 probes)**: 2 cache lines, ~2 × 15 ns.
- **Model feature assembly**: 150 scalar ops (<0.1 ns each) → ~15 ns.

Summing these gives ~160 ns of compute and ~120 ns of memory stalls per request (~0.28 µs). With four concurrent aggregation workers per core, the stage easily meets the 30 ms budget even under burst load; actual deployment should record histograms to validate (via `fraud.feature_cache_lookup_ms`).
- **Feature Windows & Aggregation**:
  - Short-term (rolling 5 min, 1 hr) and long-term (24 hr, 7 day) windows track spend velocity, device reuse, and alias graph degrees.
  - Graph features (e.g., shared devices across aliases, sudden fan-out, new counterparties in high-risk clusters) rely on regularly compacted summaries so queries stay sub-millisecond.
  - Location heuristics compare coarse geobuckets with historical behaviour, flagging improbable jumps (e.g., multiple distant locations within minutes) using a capped Haversine-based risk increment.
  - Flow-shape detectors maintain rolling histograms of inbound/outbound amounts and counterparties to spot mixing/tumbling signatures (rapid fan-in followed by similar fan-out, cyclical hop sequences, short-lived intermediaries).
- **Rule Catalogue (non-exhaustive)**:
  - **Velocity breach**: Rapid series of high-value transfers exceeding per-alias or per-device thresholds.
  - **Alias graph anomaly**: Alias interacts with a cluster linked to confirmed fraud cases or known mule patterns.
  - **Device reuse**: Shared device fingerprint across aliases belonging to different PSP user cohorts without prior linkage.
  - **First-time high-value**: New alias attempting amounts above the PSP’s typical onboarding corridor.
  - **Authentication downgrade**: Transaction uses weaker factors than the account’s baseline (e.g., fallback from biometric to PIN) without PSP-declared justification.
  - **Mixing/tumbling pattern**: Alias participates in high fan-in/fan-out chains with tightly coupled timing, repeating round-trip amounts, or circular flows across multiple aliases within short windows. Rule boosts score using graph centrality spikes and flow-shape detectors; severe cases clamp to the `high` band even before ML output.
  - **Transaction blacklist hit**: Alias or counterparty appears on the shared blacklist feed curated via on-chain governance voting or a delegated authority with `sudo` controls (e.g., regulatory orders, confirmed fraud). Score clamps to the `critical` band and emits `BLACKLIST_MATCH` reason code; PSPs must log overrides for audit.
  - **Sandbox signature mismatch**: PSP submits an assessment generated with an outdated model signature; score escalates to `critical` and audit hook triggers.
- **Reason Codes**: Every assessment includes machine-readable reason codes ranked by contribution weight (e.g., `VELOCITY_BREACH`, `NEW_DEVICE`, `GRAPH_HIGH_RISK`, `AUTH_DOWNGRADE`). PSPs can surface these to operators or wallets for user messaging.
- **Model Governance**: Calibration and threshold setting follow documented playbooks—ROC/PR curves reviewed quarterly, back-testing against labelled fraud, and challenger models run in shadow until stable. Any threshold update requires dual approval (fraud operations + independent risk).

## Governance-Sourced Blacklist Flow
- **On-chain authoring**: Blacklist entries are introduced through the governance subsystem (`iroha_core::smartcontracts::isi::governance`) as a `BlacklistProposal` ISI that lists aliases, PSP ids, or device fingerprints to block. Stakeholders vote using the standard ballot pipeline; once quorum is met, the chain emits a `GovernanceEvent::BlacklistUpdated` record carrying the approved additions/removals plus a monotonically increasing `blacklist_epoch`.
- **Delegated sudo path**: Emergency actions can be executed via the `sudo::Execute` instruction, which emits the same `BlacklistUpdated` event but flags the change as `origin = Sudo`. This mirrors on-chain history with explicit provenance so auditors can distinguish consensus votes from delegated interventions.
- **Distribution channel**: The FMS bridge service subscribes to the `LedgerEvent` stream (Norito-encoded) and watches for `BlacklistUpdated` events. Each event is validated against the governance Merkle proof and verified with the block signature before being applied. Events are idempotent; the FMS maintains the latest `blacklist_epoch` to avoid replays.
- **Application inside FMS**: Once an update is accepted, the entries are written to the deterministic rule store (backed by append-only storage with audit logs). The scoring engine hot-reloads the blacklist within 30 seconds, ensuring subsequent assessments trigger the `BLACKLIST_MATCH` rule and clamp to `critical`.
- **Audit & rollback**: Governance can vote to remove entries via the same pipeline. The FMS keeps historical snapshots tagged by `blacklist_epoch` so operators can answer forensic questions or replay past decisions during investigations.

4. **Learning & Analytics Platform**
   - Receives confirmed fraud events, settlement outcomes, and PSP feedback via an append-only ledger (e.g., Kafka + object storage).
   - Provides offline notebooks/jobs for data scientists to retrain models. Model artifacts are versioned and signed before promotion.

5. **Governance Portal**
   - Restricted interface for auditors to review trends, search historical assessments, and export incident reports.
   - Implements policy checks so investigators cannot drill down to PII without PSP cooperation.

6. **Integration Adapters**
   - Lightweight SDKs for PSPs (Rust, Kotlin, Swift, TypeScript) implementing the Norito requests/responses and local caching.
   - Settlement engine hook (within `iroha_core`) that records risk assessment references when PSPs forward transactions post-check.

## Data Flow
1. PSP authenticates to the API gateway and submits a `RiskQuery` containing:
   - Alias identifiers for payer/payee, hashed device id, transaction amount, category, geolocation coarse bucket, PSP confidence flags, and recent session metadata.
2. Gateway validates payload, enriches with PSP metadata (licence tier, SLA) and queues for feature aggregation.
3. Feature service pulls the latest aggregates, constructs the model vector, and sends it to the risk engine.
4. Risk engine evaluates the request, attaches deterministic reason codes, signs the `FraudAssessment`, and returns it to the PSP.
5. PSP combines the assessment with its local policies to approve, decline, or step-up authenticate the transaction.
6. Outcome (approved/declined, fraud confirmed/false positive) is pushed asynchronously to the learning platform for continuous improvement.
7. Daily batch processes roll up metrics for governance reporting and push policy alerts (e.g., rising social-engineering cases) to PSP dashboards.

## Integration with Iroha Components
- **Core Host Hooks**: Transaction admission reads the block's frozen `FraudAdmissionPolicyV1`. When `enabled` and `required_minimum_band` are set, it checks `fraud_assessment_band` against the committed minimum. Missing band metadata is accepted only when `missing_assessment_permitted` is true; this permission has no elapsed-time window. Supplied assessments must include a nonempty `fraud_assessment_tenant` and `fraud_assessment_score_bps`; the host cross-checks the score against the declared band (0–249 ➜ low, 250–549 ➜ medium, 550–749 ➜ high, 750+ ➜ critical, with values supported up to 10 000). When committed `attesters` are nonempty, transactions must attach a Norito-encoded `fraud_assessment_envelope` (base64) and matching `fraud_assessment_digest` (hex). Admission checks the original assessment signature against the exact engine key, recomputes its unsigned-payload digest, and rejects mismatches.
- **Committed admission**: The `fraud_admission_policy_v1` custom parameter owns the exact `FraudAdmissionPolicyV1` value. Signed genesis or an authorized `SetParameter` may set `version` (exactly 1), `enabled`, typed `required_minimum_band` (`Low`, `Medium`, `High`, `Critical`), `missing_assessment_permitted`, and strictly sorted unique `attesters`. The fixed absent-parameter default is disabled. Core validates replacements before publication and rebuilds the derived projection on restore. Every transaction in a block uses the predecessor's policy; a policy change applies to the next block. Empty attesters retain metadata-only assessment, while configured attesters require the original signed envelope and matching digest. An engine identifier contains neither ASCII uppercase letters nor whitespace, is nonempty and at most 128 UTF-8 bytes; a policy has at most 256 engines.
- **Local transport**: `[fraud_monitoring]` contains only `service_endpoints` (default `[]`), `connect_timeout_ms` (500) and `request_timeout_ms` (1500). Endpoints are deduplicated and zero deadlines select their defaults. Transport availability and elapsed local time do not choose ledger validity. There is no local admission-policy override or elapsed grace window.
- **Payment SDK boundary**: Native and private payment operations currently bind empty carrier metadata. A committed policy that requires an attached assessment therefore rejects such a carrier. Supporting assessments in these operations requires retained, request-bound assessment evidence; receipt verification must not silently relax metadata binding.

- **Validation**: Unit tests in `crates/iroha_core/tests/fraud_monitoring.rs` cover disabled, missing, and insufficient-band paths; `integration_tests::fraud_monitoring_requires_assessment_bands` exercises the mocked-assessment flow end-to-end.

- **Telemetry**: `iroha_telemetry` exports PSP-facing collectors capturing assessment counts (`fraud_psp_assessments_total{tenant,band,lane,subnet}`), missing metadata (`fraud_psp_missing_assessment_total{tenant,lane,subnet,cause}`), latency histograms (`fraud_psp_latency_ms{tenant,lane,subnet}`), score distributions (`fraud_psp_score_bps{tenant,band,lane,subnet}`), invalid payloads (`fraud_psp_invalid_metadata_total{tenant,field,lane,subnet}`), attestation outcomes (`fraud_psp_attestation_total{tenant,engine,lane,subnet,status}`), and outcome mismatches (`fraud_psp_outcome_mismatch_total{tenant,direction,lane,subnet}`). The assessment and telemetry metadata vocabulary includes `fraud_assessment_band`, `fraud_assessment_tenant`, `fraud_assessment_score_bps`, `fraud_assessment_latency_ms`, the attester envelope/digest pair (`fraud_assessment_envelope`, `fraud_assessment_digest`), and the post-incident `fraud_assessment_disposition` flag (values: `approved`, `declined`, `manual_review`, `confirmed_fraud`, `false_positive`, `chargeback`, `loss`).
- **Norito Schema**: Define Norito types for `RiskQuery`, `FraudAssessment`, and governance reports. Provide roundtrip tests to guarantee codec stability.

## Privacy & Data Minimization
- Aliases, hashed device IDs, and coarse geolocation buckets form the entire data plane shared with the central service.
- PSPs retain mapping from aliases to real identities; no such mapping leaves their perimeter.
- Risk models operate only on pseudonymous behavioral signals plus PSP-submitted context (merchant category, channel, authentication strength).
- Audit exports are aggregated (e.g., counts per PSP per day). Any drill-down requires dual control and PSP-side de-anonymization.

## Operations & Deployment
- Deploy the scoring platform as a dedicated subsystem managed by an appointed operator distinct from the central bank node operators.
- Provide blue/green environments: `fraud-scoring-prod`, `fraud-scoring-shadow`, `fraud-lab`.
- Implement automated health checks (API latency, message backlog, model load success). If health checks fail, PSP SDKs automatically switch to local-only mode and notify operators.
- Maintain retention buckets: hot storage (30 days in feature store), warm storage (1 year in object storage), cold archive (5 years compressed).

## Telemetry Collectors & Dashboards

### Required collectors

- **Prometheus scrape**: enable `/metrics` on every validator running the PSP integration profile so `fraud_psp_*` series are exported. Default labels include placeholder `subnet="global"` and `lane` IDs so dashboards can pivot once multi-subnet routing ships.
- **Assessment totals**: `fraud_psp_assessments_total{tenant,band}` counts accepted assessments per severity band; alerts fire if a tenant stops reporting for 5 minutes.
- **Missing metadata**: `fraud_psp_missing_assessment_total{tenant,cause}` distinguishes hard rejections (`cause="missing"`) from committed allowances (`cause="permitted"`). Gate transactions that repeatedly fall into the permitted bucket.
- **Latency histogram**: `fraud_psp_latency_ms_bucket` traces PSP-reported scoring latency. Target <120 ms P95 with alerts at 150 ms.
- **Score distribution**: `fraud_psp_score_bps_bucket{band}` snapshots risk-score drift; wire percentiles to the governance dashboard.
- **Outcome mismatches**: `fraud_psp_outcome_mismatch_total{direction}` splits false positives (`direction="false_positive"`) from missed fraud (`"missed_fraud"`). Escalate if either direction deviates >20% from trailing 30-day mean.
- **Invalid metadata**: `fraud_psp_invalid_metadata_total{field}` flags PSP payload regressions (e.g., missing tenant IDs, malformed dispositions) so SDK updates can be rolled out quickly.
- **Attestation status**: `fraud_psp_attestation_total{tenant,engine,status}` confirms that envelopes are being signed and digests match. Alert if `status!="verified"` spikes for any tenant or engine.

### Dashboard coverage

- **Executive overview**: stacked area chart of `fraud_psp_assessments_total` by band per tenant, coupled with a table summarising P95 latency and mismatch counts.
- **Operations**: histogram panels for `fraud_psp_latency_ms` and `fraud_psp_score_bps` with week-over-week comparison, plus single-stat counters for `fraud_psp_missing_assessment_total` split by `cause`.
- **Risk monitoring**: bar chart of `fraud_psp_outcome_mismatch_total` per tenant, drill-down table listing recent `fraud_assessment_disposition=confirmed_fraud` cases where `band` was `low` or `medium`.
- **Alert rules**:
  - `rate(fraud_psp_missing_assessment_total{cause="missing"}[5m]) > 0` → paging alert (admission rejecting PSP traffic).
  - `histogram_quantile(0.95, sum(rate(fraud_psp_latency_ms_bucket[10m])) by (le,tenant)) > 150` → latency SLO breach.
  - `sum by (tenant) (rate(fraud_psp_outcome_mismatch_total{direction="missed_fraud"}[1h])) > 0.01` → model drift / policy gap.

### Failover expectations

- Scoring clients may use multiple endpoints and local failover deadlines. A transport failure does not change committed admission: a request without assessment metadata is allowed only by the active `missing_assessment_permitted` policy. Local elapsed time cannot grant or revoke this permission.
- Validators record `fraud_psp_missing_assessment_total{cause="permitted"}` for missing assessments allowed by committed policy. Operators may alert or route cases to manual review using local monitoring windows; these windows do not alter consensus validity.
- Active-active deployments must demonstrate queue drain/replay during disaster recovery drills. Replay metrics should keep `fraud_psp_latency_ms` P99 under 400 ms for the replay window.

## PSP Data-Sharing Checklist

1. **Telemetry plumbing**: expose the metadata keys listed above for every transaction handed to the ledger; tenant identifiers must be pseudonymous and scoped to the PSP contract.
2. **Anonymisation**: confirm that device hashes, alias identifiers, and dispositions are pseudonymised before leaving the PSP perimeter; no PII can be embedded in Norito metadata.
3. **Latency reporting**: populate `fraud_assessment_latency_ms` with end-to-end timing (gateway to PSP) so SLA regressions surface immediately.
4. **Outcome reconciliation**: update `fraud_assessment_disposition` once fraud cases are confirmed (e.g., chargeback posted) to keep mismatch metrics accurate.
5. **Failover drills**: rehearse quarterly using the shared checklist—verify endpoint failover and the exact committed allowance/rejection metrics, and attach drill notes to the follow-up task filed by `scripts/ci/schedule_fraud_scoring.sh`.
6. **Dashboard validation**: PSP operations teams must review Prometheus dashboards after onboarding and after every red-team exercise to confirm metrics are flowing with expected tenant labels.

## Security Considerations
- All responses are signed through a qualified, purpose-separated custody
  provider; PSPs validate signatures before trusting scores. Provider
  implementation details remain deployment-owned.
- Rate-limit by alias/device to mitigate probing attacks aiming to learn model boundaries.
- Embed watermarking inside assessments to trace leaked responses without revealing PSP identity publicly.
- Run quarterly red-team exercises in coordination with the Security WG (Milestone 0) and feed findings into roadmap updates.

## Implementation Phases
1. **Phase 0 – Foundations**
   - Finalize Norito schemas, PSP SDK scaffolding, configuration wiring, and ledger-side verification stub.
   - Build deterministic rule engine covering mandatory risk checks (velocity, velocity per alias pair, device reuse).
2. **Phase 1 – Central Scoring MVP**
   - Deploy feature store, scoring service, and telemetry dashboards.
   - Integrate real-time scoring with a limited PSP cohort; capture latency and quality metrics.
3. **Phase 2 – Advanced Analytics**
   - Introduce anomaly detection, graph-based link analysis, and adaptive thresholds.
   - Launch governance portal and batch reporting pipelines.
4. **Phase 3 – Continuous Learning & Automation**
   - Automate model training/validation pipelines, add canary deployments, and expand SDK coverage.
   - Align with cross-jurisdiction data-sharing agreements and plug into future multi-subnet bridges.

## Open Questions
- What regulatory body will charter the operator of the fraud service, and how are oversight responsibilities shared?
- How do PSPs expose end-user challenge flows while maintaining consistent UX across providers?
- Which privacy-enhancing technologies (e.g., secure enclaves, homomorphic aggregation) should be prioritized once baseline service is stable?
