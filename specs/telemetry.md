# Telemetry & Metrics Overview

Iroha exports Prometheus-format metrics and a JSON status summary. This page lists key metrics and example PromQL queries you can use to build dashboards.

Endpoints
- `/metrics`: Prometheus exposition text. Hidden when telemetry is disabled or the profile does not allow expensive metrics.
- `/status`: JSON node status (hidden when telemetry is disabled). Includes peers, block and transaction gauges, crypto capabilities, governance, and the `sumeragi` node-wide queue and sealed-lane observations (`SumeragiConsensusStatus`). Per-instance consensus state comes from `/v1/sumeragi/status` and `/v1/sumeragi/lanes`.
- `/v1/sumeragi/status` (Norito by default, JSON with `Accept: application/json`): the authoritative `SumeragiStatus` of the global Sumeragi instance (protocol version, configuration fingerprint, instance id, height/view/stage, leader and proxy tail, lock view, pacemaker levels, committed and applied heights, signer, halt reason and footprint counters); `503` before consensus starts. `/v1/sumeragi/lanes` lists the node's lane instances.
- `/v1/sumeragi/status/sse` (SSE): operator-authenticated periodic stream (≈1s) emitting the same JSON payload as `/v1/sumeragi/status` for dashboards.
- Nexus lane/dataspace status is present for every first-release deployment,
  including the canonical one-lane topology.
- `/v1/soranet/privacy/{event,share}` (Norito): bounded privacy telemetry mutation ingress for relay/collector signals. Before decoding, Torii verifies the four exact NetworkId-bound `X-Iroha-Operator-*` headers over the method, target, body, timestamp, and fresh nonce, then requires `torii.soranet_privacy_ingest.enabled = true` and a CIDR allow-list entry (empty list denies). Rate limits come from `rate_per_sec`/`burst` and are keyed by authenticated operator public key. DTOs reject unknown fields and overlong/control-bearing labels; live bucket admission rejects future or expired timestamps, bounds incomplete windows, and rejects conflicting or already-finalized collector shares. The share route also derives a full 256-bit BLAKE3 collector ID from the authenticated operator key and rejects caller identity mismatches. Retired collector/API bearer headers are rejected; failures surface `400/401/403/429` plus `soranet_privacy_ingest_reject_total{endpoint,reason}`.
- `/v1/sumeragi/params` (JSON): read-only snapshot of governed NPoS parameter records. It does not replace authenticated per-instance consensus state or the shared configuration fingerprint exposed by `/v1/sumeragi/status`.

`/status` is an immutable reply from the Core telemetry actor. Its applied target
height, header hash and Nexus routing policy are copied under one stable State
publication generation. Torii does not compare it to an earlier or later live
height. Runtime gauges remain sampled observables, not a consensus snapshot or
transaction-finality assertion.

The actor classifies the captured finite prefix in quanta of at most 64 blocks.
Each quantum streams a domain-separated digest of its fixed-width range and
ordered `(height, header_hash)` rows from the State journal, then checks the
actual Kura sequence against it. The previously classified tip must also match.
Counters and commit timestamps are staged until the complete quantum verifies;
missing or substituted blocks cannot publish unverified progress. No State,
world, transaction or report guard is held during Kura access. State appends do
not extend the active target; a replaced target or checkpoint is refused.

The existing 1024-message mailbox and absolute 500 ms status service budget stay
unchanged. Expired queued requests do not start classification. Once started,
finite catch-up remains owned by the actor after HTTP cancellation or timeout,
yields between quanta, and retains verified progress for the next request. An
expired request never receives a successful late response. Missing actor,
mailbox capacity, inconsistent journal/counters or service timeout remains a
retriable unavailable result. This boundary does not change transaction wait
semantics or assert that `/status` failures cause slow transaction confirmation.

The authoritative `/v1/sumeragi/status` response carries canonical settlement,
relay, payload-ownership, committed-lane-block, and active-session evidence; it
does not infer governance readiness from retired operator snapshots. Use
`iroha --operator-private-key-file /absolute/runtime/operator.key app nexus lane-report --only-missing --fail-on-sealed` during
rollouts or CI to summarize lane-governance status and exit non-zero when a
required manifest remains sealed. Session and committed-block progress remains
observable through the dedicated metrics.

SM helper telemetry (Prometheus metrics)
- `iroha_sm_syscall_total{kind="hash|verify|seal|open",mode}` — cumulative SM helper syscall successes grouped by helper kind and mode (`gcm`/`ccm` for SM4 helpers).
- `iroha_sm_syscall_failures_total{kind,mode,reason}` — cumulative failure counts with reason labels (`permission_denied`, `norito_invalid`, `decode_error`, etc.).

Settlement telemetry

Consensus state contains only successful settlement receipts. Each
`SettlementId` keys one immutable, fixed two-leg receipt in
`settlement_receipts` and is consumed after the first successful DvP, PvP, or
governed FX settlement. Rejected attempts do not create receipt state and
therefore cannot retain account or asset-definition references. Operators can
still observe failures through the bounded counters and last-event snapshots
below; these diagnostics are local and do not participate in consensus.

- `iroha_settlement_events_total{kind="dvp|pvp",outcome="success|failure",reason}` — settlement lifecycle counters labelled by instruction kind and failure reason (`insufficient_funds`, `counterparty_mismatch`, `unsupported_policy`, `zero_quantity`, `missing_entity`, `math_error`, `other`; success uses `reason="-"`).
- `iroha_settlement_finality_events_total{kind="dvp|pvp",outcome="success|failure",final_state="none|delivery_only|payment_only|both|primary_only|counter_only"}` — finality counters grouped by settlement kind, execution outcome, and which legs remained committed. DvP reports `delivery_only|payment_only`, PvP reports `primary_only|counter_only`; `none` means both legs rolled back.
- `iroha_settlement_fx_window_ms{kind="pvp",order,atomicity}` — histogram of observed PvP FX windows (milliseconds between committed legs) labelled by execution order (`delivery_then_payment`/`payment_then_delivery`) and atomicity policy (`all_or_nothing|commit_first_leg|commit_second_leg`).

Subscription telemetry
- `iroha_subscription_billing_attempts_total{pricing="fixed|usage"}` — billing trigger invocations grouped by pricing kind.
- `iroha_subscription_billing_outcomes_total{pricing="fixed|usage",result="paid|failed|suspended|skipped"}` — billing outcomes grouped by pricing kind and result label.

Network time telemetry
- `nts_offset_ms` (gauge) — smoothed or raw offset vs local clock.
- `nts_confidence_ms` (gauge) — MAD confidence bound.
- `nts_peers_sampled` (gauge) — peers contributing recent samples.
- `nts_samples_used` (gauge) — samples used after RTT filtering.
- `nts_fallback` (gauge) — 1 when NTS falls back to local time.
- `nts_healthy` (gauge) — 1 when health thresholds pass and no fallback.
- `nts_min_samples_ok` / `nts_offset_ok` / `nts_confidence_ok` (gauges) — per-check health flags.
- `nts_rtt_ms_bucket{le="..."}` / `nts_rtt_ms_sum` / `nts_rtt_ms_count` — cumulative RTT histogram buckets (ms, including `+Inf`) and aggregates.
- `torii_nts_unhealthy_reject_total` (counter) — time-sensitive transactions rejected during admission because NTS is unhealthy.

NTS status gauges and RTT counters are captured under one service lock per scrape, so one export cannot mix sampler generations.

Runbook guidance
- Alert when `max_over_time(nts_healthy[5m]) == 0` or `max_over_time(nts_fallback[5m]) > 0`; these indicate the time service is unsynchronized or missing samples.
- Use `nts_min_samples_ok`, `nts_offset_ok`, and `nts_confidence_ok` to pinpoint root cause; an operator may check `/v1/time/status` for peer sample and RTT diagnostics using a fresh signature bound to the exact genesis `NetworkId`, `GET`, path, query, and empty body. The node rejects redirects/replays and does not accept token fallback for this node-local clock state.
- If `enforcement_mode = "reject"`, admission blocks time-sensitive instructions while unhealthy. Switch to `warn` only for temporary operational relief.

Configuration
- `telemetry_profile` (default: `operator`): The sole telemetry switch and capability bundle wiring both Torii routing and runtime sinks. `disabled` skips telemetry workers, exporters, and expensive hardware probes, hides `/metrics` and `/status`, and makes state-telemetry recording paths return without updating observations; a configured sink is rejected instead of being silently ignored. The other profiles select lightweight metrics, costly probes/timings, and developer outputs directly.
- `torii.peer_telemetry_urls` (default: empty): Optional list of canonical Torii HTTP(S) origins used to fetch peer telemetry metadata. Each value must contain only the scheme, host, optional non-default port, and root path (for example, `https://peer.example:8443/`); credentials, non-root paths, queries, and fragments are rejected. Torii derives `/v1/configuration`, `/v1/peers`, and `/status` from the validated origin. When unset, peer telemetry discovery is disabled to avoid probing P2P ports.
- Peer-monitor HTTP bodies are streamed under first-release caps before JSON decoding: 4 MiB for `/v1/configuration`, 1 MiB for `/v1/peers`, 64 KiB for `/status`, and 16 KiB for the fixed-field geo response. Both an oversized `Content-Length` and chunked/decompressed growth past the applicable cap fail closed without retaining the remainder.
- Telegram bot key and chat ID are an all-or-none pair of bounded ASCII identifiers. Alert settings without credentials are rejected, and the daemon rejects credentials when the binary/profile cannot run that sink. Telegram API requests use bounded connect/request deadlines, reject redirects and non-success statuses, and remove credential-bearing URLs from diagnostics. When `telegram_include_metrics = true`, each retained, rate-admitted alert requests the core telemetry actor's bounded checked refresh and then reads the four scalar values used by alert rendering from the shared in-process registry; a failed refresh omits the optional snapshot instead of publishing stale values. The first release has no Telegram HTTP metrics sampler: it performs no self-request to `/metrics`, cannot be blocked by Torii profile/auth policy, and rejects the retired `telegram_metrics_url` and `telegram_metrics_period_ms` settings.
- WebSocket collector URLs must use `ws` or `wss`, reconnect delays are clamped to at least 100 ms, the backoff exponent is capped at 16, and TLS support is part of the exporter feature itself. Exported records carry only the timestamp, tracing `target`, payload, and optional integrity chain; the retired constant `id: 0` field is not emitted. Collector input is control-only: Ping, Pong, and Close are accepted under a 1 KiB frame/message ceiling; Text, Binary, oversized, or malformed inbound frames disconnect the collector.
- `torii.peer_geo.enabled` (default: false): Enable peer geo lookups for Torii telemetry (opt-in; requires network access to the configured endpoint).
- `torii.peer_geo.endpoint` (default: unset): Required HTTPS ip-api compatible endpoint used for peer geo lookups when `torii.peer_geo.enabled = true`; when unset, Torii skips geo lookup and logs a warning.
- Build-time ISI instrumentation: `#[metrics]` counters (`isi{kind="total|success"}`) and timing histograms (`isi_times`) require building `irohad` with `--features expensive-telemetry` (or `iroha_core` `expensive-telemetry`). Runtime exposure still follows `telemetry_profile`.

Telemetry redaction and integrity
- Redaction is unconditional in every build and telemetry profile. The retired `[telemetry_redaction]` configuration section, runtime bypasses, and build-time redaction feature are rejected or absent.
- Field-name normalization is case-insensitive and splits punctuation/camelCase/acronyms into snake_case segments for taxonomy checks. Multi-segment keywords match at segment boundaries inside longer field names.
- Sensitive taxonomy is defined by explicit prefixes and keywords (kept in sync with guardrails below).
- Redacted values are replaced with `[REDACTED]`; sensitive debug values and error chains are classified before formatting, so their plaintext is not needlessly materialized. String payloads longer than 2048 bytes are truncated and suffixed with `...(truncated)` for deterministic export. Error source chains retain at most 16 linked errors and append `[error chain truncated]`, preventing cyclic or hostile `Error::source` implementations from blocking the logger.

Telemetry redaction prefixes:
<!-- TELEMETRY_REDACTION_PREFIXES_START -->
```text
redact
sensitive
secret
pii
```
<!-- TELEMETRY_REDACTION_PREFIXES_END -->

Telemetry redaction keywords:
<!-- TELEMETRY_REDACTION_KEYWORDS_START -->
```text
password
passwd
passphrase
secret
credential
token
access_token
refresh_token
session_token
session
authorization
cookie
jwt
bearer
api_key
api_key_hash
apikey
bot_key
private_key
privkey
signing_key
mnemonic
seed
```
<!-- TELEMETRY_REDACTION_KEYWORDS_END -->

- Tamper-evident exports: when `telemetry_integrity.enabled = true`, websocket telemetry and dev-telemetry JSON lines include a `chain` object (`seq`, `prev_hash`, `hash`, optional `signature`, `key_id`). `hash` is `blake3("iroha.telemetry.record.v1" || prev_hash || seq_be || payload_json)` where `payload_json` is the Norito JSON serialization of the record. `signature` is a keyed Blake3 hash when `telemetry_integrity.signing_key_hex` is set; the key must be exactly 64 hex characters with no prefix or surrounding whitespace. `signing_key_id` is bounded to 128 printable ASCII bytes and is invalid without that key. The exact serialized record is retained in memory before output and, when `state_dir` is configured, journaled before output. The checkpoint also stores a domain-separated BLAKE3 fingerprint of the sink kind and configured destination, so a pending record or established chain cannot silently move to another collector/output file. The development sink advances only after the file data and checkpoint are synced; the WebSocket sink advances after its local send operation succeeds and the checkpoint is synced. WebSocket has no application acknowledgement, so this does not prove remote collector acceptance: ambiguous local failures and restarts resend identical bytes, and collectors should deduplicate by `seq` plus `hash`. Development-file recovery deduplicates a complete tail or replaces a torn matching tail before advancing the chain.
- Persisted integrity state is supported only on Unix, where custody and directory sync can be enforced. `telemetry_integrity.state_dir` is created owner-only and must remain owned by the process user with no group/other access. Each sink holds an exclusive lock and writes mode-0600, single-link regular lock/state files (for example, `telemetry_integrity_ws.json` and `telemetry_integrity_dev.json`) through a bounded, atomically replaced, fsynced checkpoint. A second writer, unsafe permissions/links, destination mismatch, invalid schema, unreadable data, or oversized state refuses that optional exporter instead of silently replacing the chain; the daemon logs the error and continues serving consensus. Configuring persisted state on another platform fails closed. Without a state directory the in-memory chain restarts at sequence 1 after process restart.
- Developer telemetry output resolves its parent once, requires the directory to be owned by the process user and not group/other-writable, refuses symlink final components, requires an owner-held mode-0600 single-link regular file, and holds an exclusive file lock for the worker lifetime. This prevents two nodes from interleaving or crash-tail recovery from truncating an unrelated file.
- The bounded logger channel reserves capacity before formatting, normalizing, or redacting an event. When the channel is full the event is intentionally dropped without paying those allocations; downstream broadcast lag remains explicit in exporter diagnostics.

Build-time instrumentation
- `iroha_telemetry/event-exporter` compiles the WebSocket event sink and its durable integrity journal. The daemon's `telemetry` feature enables it; metrics/privacy-only consumers do not compile the exporter stack. `iroha_telemetry/dev-telemetry` is independent and compiles only the developer file sink plus the shared integrity primitives, without WebSocket or TLS dependencies.
- `iroha_core/expensive-telemetry` (enables `iroha_telemetry/metric-instrumentation`) compiles the `#[metrics]` attribute into Prometheus counters and timing histograms.
- Without it, `#[metrics(+"...")]` still parses but timing histograms are a no-op; runtime `telemetry_profile` still controls exposure.

Profile capability matrix

| Profile    | `/status` | `/metrics` | Developer routes (`/v1/sumeragi/*`, SSE) | Intended use |
|------------|-----------|------------|------------------------------------------|--------------|
| `disabled` | no        | no         | no                                       | Telemetry fully off |
| `operator` | yes       | no         | no                                       | Production nodes that only need JSON status |
| `extended` | yes       | yes        | no                                       | Operators scraping Prometheus |
| `developer`| yes       | no         | yes                                      | Local debugging and dashboards |
| `full`     | yes       | yes        | yes                                      | Combine operator + developer tooling |

## Platform-Specific Telemetry Profiles

### Android SDK (AND7)

Roadmap item **NRPC/AND7** requires the Android SDK to follow the same telemetry
and privacy guarantees as the Rust node. Use the artefacts below whenever you
need to brief operators or confirm governance readiness:

| Artefact | Purpose |
|----------|---------|
| [`sdk/android/telemetry_redaction.md`](./sdk/android/telemetry_redaction.md) | Canonical policy covering hashed authorities, device buckets, retention, and override governance. |
| [`android_runbook.md`](./android_runbook.md#2-telemetry--redaction) | Step-by-step operational workflow (config threading, exporter checks, override handling). |
| [`sdk/android/telemetry_chaos_checklist.md`](./sdk/android/telemetry_chaos_checklist.md) | Quarterly rehearsal scenarios referenced by SRE governance. |

**Key guardrails**

- Android exports hashed authorities (`android.torii.http.request` /
  `android.torii.http.retry`) using the same Blake2b-256 salt published through
  `iroha_config.telemetry.redaction_salt`; watch
  `android.telemetry.redaction.salt_version` for drift during salt rotations.
- Device metadata is limited to coarse `android.telemetry.device_profile`
  buckets (SDK major version + `emulator|consumer|enterprise`). Alert when
  bucket ratios diverge by more than 10 % from the Rust node baseline.
- Network context drops carrier names entirely; only `network_type` and
  `roaming` are exported. Any request for subscriber data should be rejected and
  handled through the override workflow.
- Overrides are logged via `android.telemetry.redaction.override` and must
  match the manifest + audit procedure documented in the Android Support
  Playbook; on-call engineers should update
  `specs/sdk/android/telemetry_override_log.md` immediately after apply
  and revoke operations.

**Operational validation**

- `scripts/telemetry/check_redaction_status.py` produces the status bundle
  attached to chaos drills and incident timelines; run it against staging before
  filing SRE readiness evidence.
- Chaos rehearsals record Grafana snapshots plus the latest
  `android.telemetry.redaction.failure` and `android.telemetry.redaction.override`
  counters; link those artefacts in `specs/sdk/android/readiness/labs/`.
- PromQL snippets:
  - `increase(android.telemetry.redaction.failure_total[5m]) > 0` should page
    immediately outside chaos windows.
  - `sum by (device_profile)(android.telemetry.device_profile)` compared against
    the Rust `node.hardware_profile` histogram verifies bucket alignment.
  - `clamp_min(rate(android.telemetry.redaction.override_total[1h]), 0)` feeds
    the monthly override audit.

Public operator guidance and escalation procedures are maintained at
[docs.iroha.tech](https://docs.iroha.tech/).

## Governance telemetry

Parliament transition and no-result counters publish only after the original
State journals become visible. The canonical native executor retains a typed
`CommitTelemetryOrigin` beside its move-only execution authorization: forward
execution emits those observations once, while authenticated startup replay
restores committed gauges without recounting historical transitions. The origin
cannot be replaced during preparation, publication refusal or archive retry.
Signed genesis derives the same distinction from its independently checked
stored certificate. This local observation owner does not relax source, witness,
finality, durable-frame or World publication authentication.

- `governance_parliament_transitions_total{transition}` (counter): accepted
  Parliament reducer transitions and automatic execution outcomes grouped by
  the closed `ParliamentLifecycleTransitionKindV1` vocabulary.
- `governance_parliament_no_result_total{class}` (counter): only Core-derived
  terminal no-result outcomes, grouped by the ten closed
  `ParliamentNoResultKindV1` classes. Public findings use
  `public_finding_quorum_unreachable` or `public_finding_deadline_expired`;
  private ballots use `ballot_registration_deadline_expired`,
  `ballot_survivor_deadline_expired`, `ballot_commitment_deadline_expired`,
  `ballot_release_pulse_unavailable`, or `ballot_opening_deadline_expired`.
  Exhausted deterministic body-election retries use
  `sortition_retries_exhausted`; a narrow Policy Jury result with fewer than three
  eligible fresh confirmers uses `confirmation_jury_capacity_unavailable`.
  A class attached to an incompatible transition kind is ignored by telemetry.
- `governance_parliament_attempts_by_status{status}` and
  `governance_parliament_attempts_by_stage{stage}` (gauges): aggregate committed
  attempt counts. The node recomputes them from persisted Parliament state at
  startup and after each committed attempt mutation, including automatic
  execution, so a rejected or dropped transaction cannot leave a gauge delta
  behind.
- These four families deliberately have one closed, low-cardinality label.
  They never use proposal, governance-attempt, body, ballot, assignment, pulse,
  session, certificate, or account identifiers as labels and never export
  roots, registration records, masked ballots, threshold shares, individual
  openings, or account labels. The lifecycle event retains its existing audit
  identifiers and digest, but the metrics projection consumes only the bounded
  transition kind and optional Core-derived no-result class.
- Import `dashboards/grafana/sora_parliament_observability.json` for aggregate
  status, stage, transition-rate, and deterministic no-result panels. The
  companion `dashboards/alerts/sora_parliament_rules.yml` pack warns only from
  those bounded aggregates: active/certified attempts with no progress after a
  complete 30-minute observation window plus 15-minute hold, phase-deadline
  expiry, unavailable release pulses, and isolated automatic-execution
  failures. Validate it with
  `promtool test rules dashboards/alerts/tests/sora_parliament_rules.test.yml`.
  Alert annotations likewise contain no attempt, proposal, body, account,
  pulse, session, certificate, root, ballot, share, or opening identifier.
- `governance_proposals_status{status}` (gauge): current proposal counts grouped by
  status (`proposed`, `rejected`, `enacted`, `superseded`, `execution_failed`).
  The `/status` JSON exposes the same closed set under `governance.proposals`,
  and the gauges are seeded from the
  recovered world state on startup so they reflect persisted proposals even
  before new transitions occur.
- `governance_protected_namespace_total{outcome}` (counter): admission enforcement
  for protected namespaces. Increments with `outcome="allowed"` when a deployment
  is backed by an enacted proposal and `outcome="rejected"` when the gate blocks it.
- `governance_manifest_admission_total{result}` (counter): queue admission outcomes
  driven by lane manifests. Each `result` label captures a distinct path:
  `allowed`, `missing_manifest`, `non_validator_authority`, `quorum_rejected`,
  `protected_namespace_rejected`, `runtime_hook_rejected`.
- `governance_manifest_quorum_total{outcome}` (counter): manifest quorum checks on
  the validator set. `outcome="satisfied"` records admits that met the quorum,
  while `outcome="rejected"` flags submissions missing the required validator approvals.
- `governance_manifest_hook_total{hook, outcome}` (counter): governance hook enforcement
  decisions. Currently `hook="runtime_upgrade"` is emitted with outcomes
  `allowed` / `rejected` whenever runtime upgrade submissions pass or fail manifest policy.
- `governance_manifest_activations_total{event}` (counter): manifest lifecycle
  events emitted when Core executes an exact-due Parliament certificate.
  `event="manifest_inserted"` counts new
  manifests keyed by `code_hash`; `event="instance_bound"` counts canonical
  contract activations.
- `/status` now includes a `governance` object with proposal counts, protected
  namespace totals, aggregated manifest admission outcomes, and a
  `recent_manifest_activations` array listing the most
  recent enactments (contract address, code/ABI hash, block height, and
  activation timestamp in milliseconds).

Example `governance` excerpt from `/status`:

```json
"governance": {
  "proposals": {
    "proposed": 2,
    "rejected": 0,
    "enacted": 1,
    "superseded": 1,
    "execution_failed": 0
  },
  "protected_namespace": {
    "total_checks": 5,
    "allowed": 4,
    "rejected": 1
  },
  "manifest_admission": {
    "allowed": 4,
    "missing_manifest": 1,
    "non_validator_authority": 0,
    "quorum_rejected": 1,
    "protected_namespace_rejected": 2,
    "runtime_hook_rejected": 0
  },
  "manifest_quorum": {
    "satisfied": 3,
    "rejected": 1
  },
"recent_manifest_activations": [
    {
      "contract_address": "xorc1qyqqqqqqqqqqqq9a5v7f58jgm40m0w7esnqg2pxj68d3f8a2l9ja3s",
      "code_hash_hex": "deadbeef",
      "abi_hash_hex": "cafebabe",
      "height": 42,
      "activated_at_ms": 1234567
    }
  ]
}
```

### Governance constraints validation runbook

The governance surface enforces that only enacted manifests may bind contract
instances inside protected namespaces. When rolling out runtime upgrades,
operators should validate that manifests were activated and that subsequent
deploys flowed through the protected gate.

**Key dashboards**
- Import `specs/grafana_governance_constraints.json` into Grafana (JSON
  dashboard). The template exposes the following panels:
  - `Proposal Status Counts` — shows the live values of
    `governance_proposals_status{status=…}` so proposal transitions can be
    reconciled with council decisions.
  - `Protected Namespace Enforcement (5m)` — plots
    `increase(governance_protected_namespace_total{outcome=…}[5m])` to detect
    deploy attempts that were allowed or rejected after the upgrade.
  - `Manifest Quorum Checks (5m)` — charts
    `increase(governance_manifest_quorum_total{outcome=…}[5m])` so missing
    quorum approvals surface quickly during incident response.
  - `Manifest Admission Outcomes (5m)` — visualises
    `increase(governance_manifest_admission_total{result=…}[5m])`, breaking down
    successful admits versus each rejection path (missing manifest, validator
    mismatch, quorum, namespace, runtime hook).
  - `Manifest Activations (5m)` — charts
    `increase(governance_manifest_activations_total{event=…}[5m])`, confirming
    that automatic certificate execution inserted manifests and bound
    namespaces to the new `code_hash`.
  - `Rejected Deploys (24h)` — a daily stat over
    `increase(governance_protected_namespace_total{outcome="rejected"}[24h])`
    highlighting unexpected admission failures.

**Alert thresholds**
- Protected namespaces: alert when
  `increase(governance_protected_namespace_total{outcome="rejected"}[15m]) > 0`
  outside of a planned rollback window.
- Manifest gate regressions: alert when
  `increase(governance_manifest_admission_total{result!="allowed"}[5m]) > 0`
  to catch sustained rejections (missing manifests, quorum failures, namespace
  or runtime-hook policy violations).

### Lane admission latency remediation

- **Metric to watch:** `torii_lane_admission_latency_seconds{lane_id,endpoint}`
  (histogram; 0.75 s P95 budget across transaction admission paths).
- **Alert snippet:** see `dashboards/alerts/soranet_lane_rules.yml` — the
  `SoranetLaneAdmissionLatencyDegraded` rule fires when the rolling 5 minute P95
  exceeds 750 ms.

When the alert triggers:
1. Inspect `histogram_quantile(0.5/0.95/0.99, sum by (lane_id,endpoint,le)(rate(torii_lane_admission_latency_seconds_bucket[5m])))`
   to confirm whether the regression is confined to a single endpoint (e.g.
   `/v1/pipeline/transactions` vs `/v1/contracts/call`).
2. Pull `/v1/sumeragi/status` and review `lane_activity` for the affected lane.
   A spike in `tx_vertices`, `overlay_bytes_total`, or `rbc_bytes_total` hints at
   admission pressure rather than infrastructure issues.
3. Check `rbc_lane_backlog` and `rbc_dataspace_backlog` in the same status
   payload. If backlog is accumulating, verify gossip health and DA fetch
   telemetry (`dashboards/grafana/soranet_pq_ratchet.json` covers PQ circuit
   status) before blaming the admission tier.
4. Confirm the authenticated `(height, view)` and TimeoutCertificate
   progress in `/v1/sumeragi/status`. Correlate repeated view changes with
   backpressure reasons and responsive committee membership; certified
   consensus progress is the authoritative deadline signal.
5. If latency remains elevated after clearing backlog, throttle the offending
   lane by raising `iroha_config.torii.transaction_lane.max_inflight` or
   redirecting traffic to a healthy lane using the orchestrator/CLI routing
   helpers. Document changes in the operations notebook and revert once metrics
   stabilise.

Always capture a snapshot of the Grafana panel and `/status` payload before and
after remediation; include them in the incident timeline for audit parity.

### Sumeragi consensus overview dashboard

Import `dashboards/grafana/sumeragi_consensus.json` for current per-instance
heights, views, pacemaker levels, halt reasons, queue drops and commit/apply
latencies. `dashboards/alerts/sumeragi_rules.yml` supplies tested alerts for
halts, stalled committed progress under queued work, delayed application and
unanchored keys.
The `lane` label is `global` or the decimal lane id; retiring a lane removes its
series. Idle instances need no commits and should not trigger a stalled-work
alert.

- Missing activations: alert when
  `increase(governance_manifest_activations_total{event="instance_bound"}[30m]) == 0`
  during an upgrade rollout window; a namespace binding never landed on-chain.
- Proposal drift: alert when `governance_proposals_status{status="proposed"}`
  remains non-zero for longer than the agreed SLA (e.g., 24 h) while the
  Parliament transition counters remain flat. Inspect the proposal's latest
  attempt; proposal records do not carry an intermediate approval state.

**Triage checklist**
1. Run `iroha_cli app gov deploy audit --namespace <ns>` (optionally filter by
   `--hash-prefix`) to compare stored manifests against the `code_hash` and
   `abi_hash` recorded in governance proposals. The command flags mismatches or
   missing manifests.
2. Fetch `/status` and inspect `governance.recent_manifest_activations` to
   confirm the latest activation contains the expected `code_hash_hex` and
   `abi_hash_hex` at the upgrade height.
3. Examine `increase(governance_protected_namespace_total{outcome="rejected"}[5m])`.
   If it spiked, grab Torii logs for the failing deploy and ensure the proposal
   was enacted; re-run `iroha_cli app gov protected get` to confirm the namespace
   list.
4. Verify that `governance_proposals_status{status="enacted"}` increased at the
   certificate's exact due height. If counts drift, inspect the retained
   Parliament attempt and its typed automatic outcome for `Superseded` or
   `ExecutionFailed`; there is no client enactment command to retry or accelerate.
5. Inspect `increase(governance_manifest_hook_total{hook="runtime_upgrade", outcome="rejected"}[5m])`
   to spot runtime upgrade submissions blocked by manifest policy. Correlate
   spikes with Torii admission logs and confirm the manifest allowlist /
   metadata requirements match the proposal that triggered the hook.

### Torii ZK attachments & prover runbook

Operators monitoring attachment throughput and the background prover should use
`specs/zk/prover_runbook.md` as their primary guide. It captures log
sources, alert thresholds, and mitigation steps for queue backlogs and budget
exhaustion.

**Dashboards**
- Import `specs/grafana_zk_prover.json` to get queue depth, latency, and
  budget panels. Update the Prometheus data source UID after import if your
  installation uses a custom name.
- Overlay `histogram_quantile(0.95, sum(rate(zk_verify_latency_ms_bucket[5m])) by (le, backend))`
  with `histogram_quantile(0.95, sum(rate(torii_zk_prover_latency_ms_bucket[5m])) by (le))`
  to spot systemic latency spikes.

**Alert hints**
- Backlog: `avg_over_time(torii_zk_prover_pending[10m]) > 0` (page).
- Budget hits: `increase(torii_zk_prover_budget_exhausted_total{reason="bytes"}[30m]) > 0`
  (ticket) and escalate if the rate persists across multiple windows.
- Latency: `histogram_quantile(0.95, sum(rate(torii_zk_prover_latency_ms_bucket[5m])) by (le))`
  exceeding `torii.zk_prover_max_scan_millis` for >15 minutes.
- Sanitizer rejects: `increase(torii_attachment_reject_total[10m]) > 0` to catch
  unsupported types, expansion limits, or malformed payloads; correlate with
  `histogram_quantile(0.95, sum(rate(torii_attachment_sanitize_ms_bucket[5m])) by (le))`.

**Triage outline**
1. Inspect `torii_zk_prover_pending`, `torii_zk_prover_inflight`, and
   `torii_zk_prover_last_scan_ms` to understand queue pressure.
2. Review Torii logs (target `torii::zk_prover`) for scan summaries and budget
   hits. Enable debug logging temporarily when attachment ids are required.
3. Confirm configuration values in `iroha_config` (`[torii] zk_prover_*`).
4. Prune or retry problematic attachments with `iroha_cli app zk attachments delete`
   when backlog cleanup is required.
5. Document any threshold changes in the ops notebook and update Grafana panel
   annotations.

Torii integration

- `Torii::new_with_handle` accepts a `routing::MaybeTelemetry` value that pairs the runtime `Telemetry` handle with the active `TelemetryProfile`. Use `routing::MaybeTelemetry::from_profile(runtime_handle, profile)` to construct it, or `routing::MaybeTelemetry::disabled()` when telemetry is unavailable.
- `Torii::new` has one feature-independent, telemetry-disabled signature. Embeddings that collect telemetry use `new_with_handle` explicitly. Tests can use `routing::MaybeTelemetry::for_tests()` to obtain an in-process telemetry handle.

- `torii_address_invalid_total{endpoint,reason}` increments whenever HTTP routes reject an account identifier (invalid I105 payloads, checksum failures, selector-prefixed bytes, and other strict-parser failures). Keep the `<0.1%` SLO by watching the dedicated Grafana board in `dashboards/grafana/address_ingest.json`.

Pipeline metrics
- pipeline_stage_ms: Histogram of per-stage durations with label `stage` in {"access","overlays","dag","schedule","apply","layers_prep","layers_exec","layers_merge"}.
- pipeline_dag_vertices, pipeline_dag_edges, pipeline_conflict_rate_bps: Latest validated block DAG shape and conflict rate in basis points.
- pipeline_access_set_source_total{source=manifest_hints|entrypoint_hints|prepass_merge|conservative_fallback}: Cumulative access-set derivation counts by source.
- pipeline_overlay_count, pipeline_overlay_instructions, pipeline_overlay_bytes: Overlay stats for latest block.
- pipeline_peak_layer_width, pipeline_layer_avg_width, pipeline_layer_median_width: Layer width summary.
- pipeline_layer_count: Number of scheduler layers for the latest block.
- pipeline_scheduler_utilization_pct: Average parallelism utilization (0..100) computed as `avg_width / peak_width * 100`.
- pipeline_detached_prepared, pipeline_detached_merged, pipeline_detached_fallback: Detached execution counters per latest block.

IVM cache metrics
- ivm_cache_hits, ivm_cache_misses, ivm_cache_evictions: Global pre-decode cache counters (cumulative).
- ivm_cache_decoded_streams, ivm_cache_decoded_ops_total: Cumulative decode workload counters (number of streams and total ops) reported by the IVM pre-decode cache.
- ivm_cache_decode_failures, ivm_cache_decode_time_ns_total: Cumulative decode failure count and wall-clock nanoseconds spent decoding.

IVM register pressure metrics (new)
- ivm_register_max_index (histogram): highest GPR index touched during a VM execution. Buckets cover 16 → 512 so you can alert when contracts spill beyond the hot register bank.
- ivm_register_unique_count (histogram): number of distinct GPRs accessed per execution. Useful to spot contracts with high register churn before Merkle tagging becomes expensive.
- Example PromQL:
  - `histogram_quantile(0.9, sum(rate(ivm_register_max_index_bucket[5m])) by (le))` — p90 of the highest register index over the last 5 minutes.
  - `histogram_quantile(0.95, sum(rate(ivm_register_unique_count_bucket[5m])) by (le))` — p95 of unique registers touched.
- Alert hint: page when `histogram_quantile(0.95, …)` holds above ~256 for >10m; this signals workloads exceeding the intended fast-register tier and justifies enabling the tiered register RFC.

Block/consensus metrics
- commit_time_ms (histogram), last_commit_time_ms (gauge), block_height, block_height_non_empty, txs{type in [accepted,rejected,total]}.
- Queue gauges: `queue_size` (active queue size, queued + in-flight), `queue_queued` (waiting in the hash queue), `queue_inflight` (selected but not yet committed).

P2P metrics (selected)
- connected_peers, `p2p_peer_churn_total{event="connected|disconnected"}`, p2p_* gauges/counters for queue depth/drops, throttling, DNS, handshake latencies (`p2p_handshake_ms_*`).
- `consensus_ingress_drop_total{topic,reason}` counts consensus ingress drops for payload topics (`topic` in `ConsensusPayload|ConsensusChunk|BlockSync`, `reason` in `rate|bytes|penalty`).

### Sumeragi consensus metrics

The native driver writes `iroha_core::sumeragi::metrics::InstanceMetrics` from
status snapshots and actual driver actions. Every instance series has a bounded
`lane` label (`global` or a live decimal lane id); `reason`, `kind` and `queue`
labels use closed enums. Telemetry never changes protocol decisions.

| Series | Meaning |
| --- | --- |
| `sumeragi_round_height`, `sumeragi_round_view`, `sumeragi_round_stage` | Current height, view and protocol stage. |
| `sumeragi_pacemaker_level`, `sumeragi_pacemaker_start_level`, `sumeragi_retransmit_interval_ms` | Current local pacemaker state. |
| `sumeragi_committed_height`, `sumeragi_applied_height` | Certified and durably applied heights. |
| `sumeragi_awaiting_configuration`, `sumeragi_signer_present`, `sumeragi_abstaining`, `sumeragi_unanchored` | Independent status flags. |
| `sumeragi_halted{reason}` | Halt flag by exact reason. |
| `sumeragi_commits_total`, `sumeragi_view_changes_total` | Progress since the first observed status snapshot. |
| `sumeragi_timeout_votes_total` | Locally signed timeout votes, counted once per height/view. |
| `sumeragi_fetch_requests_total{kind}` | Catch-up (`sync`) and payload (`body`) fetch requests. |
| `sumeragi_dropped_total{queue}` | Drops at the `ingress`, `held` and `serve` driver bounds. |
| `sumeragi_commit_latency_ms` | Histogram from first execution at a height to its CommitQC. |
| `sumeragi_apply_latency_ms` | Histogram from CommitQC to durable application. |

Latency samples use the driver's local monotonic clock and retain at most 64
pending heights per phase. Retries do not reset the first execution timestamp;
applying consumes the timestamp once. These measurements describe local node
progress, not client submission latency. The driver removes retired lane series.

The node-wide transaction queue retains `sumeragi_tx_queue_depth`,
`sumeragi_tx_queue_capacity`, `sumeragi_tx_queue_retained_bytes`,
`sumeragi_tx_queue_max_retained_bytes`, `sumeragi_tx_queue_oldest_queued_age_ms`,
and the `sumeragi_tx_queue_saturated` flags (aggregate, `_by_count`, `_by_bytes`,
`_by_age`). Correlate them with instance progress and P2P transport pressure.
Signed availability and quorum validity are protocol checks, not metric verdicts.

Example PromQL
- P50/P90 stage latency (ms):
  - histogram_quantile(0.5, sum(rate(pipeline_stage_ms_bucket[5m])) by (le,stage))
 - histogram_quantile(0.9, sum(rate(pipeline_stage_ms_bucket[5m])) by (le,stage))
- Commit time P95 (ms):
 - histogram_quantile(0.95, sum(rate(commit_time_ms_bucket[5m])) by (le))
- IVM cache hit rate (%):
  - 100 * (ivm_cache_hits - ivm_cache_hits offset 5m) / clamp_min((ivm_cache_hits - ivm_cache_hits offset 5m) + (ivm_cache_misses - ivm_cache_misses offset 5m), 1)
- Detached merge ratio:
 - pipeline_detached_merged / clamp_min(pipeline_detached_prepared, 1)
- View advances by instance: `rate(sumeragi_view_changes_total[5m])`
- Commit latency P95 by instance:
  `histogram_quantile(0.95, sum by (le,lane) (rate(sumeragi_commit_latency_ms_bucket[5m])))`
- Driver drops: `sum by (lane,queue) (rate(sumeragi_dropped_total[5m]))`

Alert expressions and their expected pending/firing behavior are maintained in
`dashboards/alerts/sumeragi_rules.yml` and its promtool test, alongside the
Grafana dashboard. Current leader/proxy-tail and lock details are fields of
`GET /v1/sumeragi/status`; certified finality comes from the bridge finality
proof, bundle and attestation routes.

## Fraud monitoring metrics

- `fraud_psp_assessments_total{tenant,band,lane,subnet}` — counter incremented whenever Torii admits a PSP assessment. Use it to monitor tenant activity and severity distribution.
- `fraud_psp_attestation_total{tenant,engine,lane,subnet,status}` — attestation verifier outcomes (`status="verified"` on success). Alerts should trigger on non-verified statuses to catch PSP regressions or key rotation issues.
- `fraud_psp_missing_assessment_total{tenant,lane,subnet,cause}` — counter for transactions missing metadata. `cause="missing"` means the host rejected the transaction; `cause="grace"` denotes temporary bypass via `missing_assessment_grace_secs`.
- `fraud_psp_invalid_metadata_total{tenant,field,lane,subnet}` — counter tracking malformed metadata fields (e.g., missing tenant, non-numeric latency).
- `fraud_psp_latency_ms{tenant,lane,subnet}` — histogram of PSP-reported scoring latency in milliseconds; buckets follow an exponential series (5 ms … ~1.3 s).
- `fraud_psp_score_bps{tenant,band,lane,subnet}` — histogram of risk scores (0–10 000 bps) recorded after admission.
- `fraud_psp_outcome_mismatch_total{tenant,direction,lane,subnet}` — counter capturing outcome drift: `direction="missed_fraud"` when a confirmed fraud cleared with `band∈{low,medium}`, `direction="false_positive"` when a `band∈{high,critical}` decision resolved as non-fraud.

PromQL starters:

- Tenant heartbeat: `sum by (tenant) (rate(fraud_psp_assessments_total[5m]))`
- Latency P95 per tenant: `histogram_quantile(0.95, sum(rate(fraud_psp_latency_ms_bucket[10m])) by (le,tenant))`
- Grace-window watchdog: `sum(rate(fraud_psp_missing_assessment_total{cause="grace"}[10m]))`
- Mismatch ratio: `sum(rate(fraud_psp_outcome_mismatch_total{direction="missed_fraud"}[1h])) / clamp_min(sum(rate(fraud_psp_assessments_total[1h])), 1)`

Telemetry expects the following transaction metadata to be present when fraud monitoring is enabled: `fraud_assessment_band`, `fraud_assessment_tenant`, `fraud_assessment_score_bps`, `fraud_assessment_latency_ms`, and, once PSPs complete post-incident triage, `fraud_assessment_disposition` (values documented in `specs/fraud_monitoring_system.md`).

Layer widths and utilization
- Peak width per block: max_over_time(pipeline_peak_layer_width[5m])
- Average width trend: avg_over_time(pipeline_layer_avg_width[5m])
- Median width trend: avg_over_time(pipeline_layer_median_width[5m])
- Layer count trend: avg_over_time(pipeline_layer_count[5m])
- Scheduler utilization (P50): quantile_over_time(0.5, pipeline_scheduler_utilization_pct[10m])
- Width histogram (e.g., layers <= 8): sum by (le) (increase(pipeline_layer_width_hist_bucket{le="8"}[5m]))
- Overlay volume (instructions/bytes):
  - rate(pipeline_overlay_instructions[5m])
  - rate(pipeline_overlay_bytes[5m])

Configuration
- Telemetry kill switch: when `telemetry_profile = "disabled"`, Torii hides `/metrics` and `/status`, no telemetry outputs are started, and all observations are skipped. Gauges/counters remain unchanged while disabled.
- Local diagnostic trace gauges (no proof or ledger authority):
  - `iroha_zk_trace_enabled`: whether local trace checking is enabled.
  - `iroha_zk_trace_max_batch`: maximum diagnostic tasks dispatched per batch.
  - `iroha_zk_trace_worker_threads`: effective worker count, zero when disabled.
  - `iroha_zk_trace_queue_cap`: effective ingress capacity, zero when disabled.
  - `/status` exposes these as `crypto.trace` with fields `enabled`, `max_batch`,
    `worker_threads`, and `queue_cap`.

Revision-4 Sumeragi context and diagnostics

- Consensus mode, cadence, committee/leader selection, quorum, and the mandatory
  Reed-Solomon-16 DA layout are authenticated by signed genesis/current-height
  context. There are no local DA, RBC, collector, or pacemaker switches.
- Node-local configuration only bounds candidate blocks and ingress/runtime
  resources under `sumeragi.block`, `sumeragi.queues`, and `sumeragi.limits`.
  Change these bounds consistently across validators; the shared projection is
  fingerprinted and a mismatch fails activation.
- The view-zero deadline is ten signed cadence intervals, critical-message
  retransmission is one fifth of that deadline, and view `v` uses a
  `min(v + 1, 10)` deadline multiplier. RTT samples, EMA values, jitter, and
  local wall clock tuning never change these deadlines.

Prometheus series whose names include `rbc` or `da` report node-local transport
and availability observations. They are not signed protocol evidence and do
not imply configurable V1 subprotocols.

### Troubleshooting consensus transport and backpressure

1. **Capture authenticated snapshots.** Use `iroha_cli --operator-private-key-file /absolute/runtime/operator.key --output-format text ops sumeragi status`; preserve the shared configuration fingerprint, signed height context, queue depths, and the active `(height, view)`. Capture `/metrics` separately for node-local transport observations.
2. **Check context agreement first.** A mode, cadence, roster, quorum, DA-layout, or shared-limit mismatch must be repaired through the signed genesis/height rollout or consistent validator configuration. Do not add a local bypass.
3. **Inspect finite queues.** Correlate transaction queue depth/capacity/saturation gauges, body/chunk ingress depth, and P2P queue/drop metrics. If a node-local limit is too small, change the corresponding current `sumeragi.block`, `sumeragi.queues`, or `sumeragi.limits` field consistently across validators.
4. **Inspect transport health.** Repeated retransmission, incomplete reconstruction, or block-sync recovery should be correlated with authenticated consensus-message logs and `consensus_ingress_drop_total`. Provision bandwidth or reduce admission load before changing finite limits.
5. **Escalate persistent stalls.** Freeze new client submissions, preserve status/telemetry and signed context evidence, and verify that at least `2f + 1` committee members remain responsive. A local RBC/DA/pacemaker knob is not a recovery mechanism in revision 4.

Notes
- All metrics have deterministic semantics across hardware. Parallel paths publish counters only after deterministic commit.
- Extend dashboards with Torii endpoint metrics (`torii_*`) once wired; see roadmap for status.

## Alerting — Threshold-Beacon Progress

First-release Sumeragi has no VRF commit/reveal messages or VRF penalty counters. Monitor the
authenticated height/view, view-change totals, consensus ingress drops, and committed-block
progress instead. A missing or invalid finalized threshold-beacon pulse fails the NPoS epoch
transition closed; preserve the signed height context and beacon validation logs when escalating an
epoch-boundary stall.
## Alerting — Consensus Membership Mismatch


### Alerting — Torii Pre-Auth Gating

Pre-auth connection gating exposes two metrics:
- `torii_pre_auth_reject_total{reason}` — counter of rejected connections. Reasons: `global_cap`, `ip_cap`, `rate`, `ban`.
- `torii_operator_auth_total{action,result,reason}` — operator auth events; `action` is `gate|register_options|register_verify|login_options|login_verify`, `result` is `allowed|denied|rate_limited|locked`, and `reason` mirrors the auth error labels.
- `torii_operator_auth_lockout_total{action,reason}` — operator auth lockouts per action and failure reason.
- `torii_contract_throttled_total{endpoint}` — contract API requests rejected by the deploy limiter (`endpoint` = `code`, `deploy`, `activate`).
- `torii_contract_errors_total{endpoint}` — contract API requests that failed for other reasons (missing token, queue error, etc.).
- `torii_active_connections_total{scheme}` — gauge tracking concurrent connections per scheme (`http`, `ws`).

Suggested alert for sustained rejections:
```
alert: ToriiPreAuthRejects
expr: increase(torii_pre_auth_reject_total[5m]) > 10
for: 10m
labels:
  severity: warning
annotations:
  summary: "Torii pre-auth gating is rejecting clients"
  description: |
    Instance {{ $labels.instance }} rejected {{ $value }} connections (reason={{ $labels.reason }}).
    Inspect Torii pre-auth configuration and recent traffic patterns. Check allowlists for trusted operators.
```

Operational guidance:
- Track `torii_active_connections_total` during incidents to confirm capacity pressure.
- Use CIDR allowlists for monitoring systems that should bypass gating.
- When bans trigger repeatedly, inspect the offending IP, update policies, and clear bans by restarting Torii if needed.

Refer to `sorafs/provider_advert_rollout.md` for the R0–R3 enforcement
timeline, Grafana export (`grafana_sorafs_admission.json`), checked-in dashboard (`dashboards/grafana/sorafs_provider_admission.json`), and canonical alert wiring (`dashboards/alerts/sorafs_provider_admission_rules.yml`) that Observability keeps in sync across environments.

### Musubi V1 Registry and Publication

The closed-label metric definitions live in
`iroha_telemetry::metrics::musubi`. The checked operator artifacts are
`dashboards/grafana/musubi_registry.json`,
`dashboards/alerts/musubi_registry_rules.yml`, and its rule-unit fixture
`dashboards/alerts/tests/musubi_registry_rules.test.yml`. The exact metric
contract, producer boundaries, and incident procedures are maintained beside
the implementation in `specs/musubi_operations_runbook.md`.

Core records typed governance rejections at the mutation boundary and updates
replication shortfall when an exact archive availability projection crosses
the selectable boundary. The count is a persisted universal consensus cell:
checked transition deltas are part of the Native AMX write set, snapshot load
validates it against exact archive reverse references, startup seeds the gauge
without an additional registry scan, and only a successful world-state commit
updates the process metric. It counts every release bound to a non-selectable
archive, including yanked and Parliament-taken-down releases, because it measures
replication exposure rather than fresh resolver eligibility.
Torii records structurally invalid cursors, while Core's public `Expired` query
error retains its canonical shape. For the six paged Musubi queries, an in-process
typed error preserves the exact failure through the Core boundary so Torii
exports `FinalizedAnchorMismatch` as `stale_anchor`, `IndexRevisionMismatch` as
`stale_revision`, `QueryMismatch` as `wrong_query`, `CallerMismatch` as
`wrong_caller`, and `LastKeyStale` as `boundary`. Structurally invalid supplied
cursors are rejected by Torii as `invalid` before Core execution; unrelated
query paths retain their existing public behavior.

The injected private publication service records authenticated terminal ingest
deadletters and integrity failures. Invalid or future-skewed staging receipts
use `receipt_invalid`; expired staging receipts use `receipt_expired`.
Publication phase age, cache corruption/capacity, selected-root storage usage,
and consumer-fetch integrity still require their authoritative long-lived host
producers. The one-shot Musubi CLI deliberately does not install a Prometheus
producer, and absent series for those signals mean unknown rather than healthy.
The private publication-service journal is not a phase-age source: it owns
route replay for seed ingress, storage coordination, and provider readback, not
the seven publisher-journal phases. Phase-age production additionally requires
an atomically persisted phase-entry time, a bounded complete active-journal
snapshot, a deployment-qualified non-regressing clock, and a long-lived owner
of both that publisher state root and the exporting metrics registry. The final
seven-value projection and withdrawal must be serialized with Prometheus
exposition; the existing reset/set calls are only label-level sinks. Partial
scans, clock rollback, or ownership loss must not initialize or reset the seven
series to zero. The exact integration and restart test contract is specified
in `specs/musubi_operations_runbook.md`.

### Torii Norito-RPC Observability

Norito-RPC transport telemetry requirements are captured in `specs/torii/norito_rpc_telemetry.md`. Key metrics:
- `torii_request_duration_seconds_bucket{scheme}` — scheme-level latency histogram; filter on `scheme="norito_rpc"` for burn-in dashboards.
- `torii_request_failures_total{scheme,code}` — error counter keyed by connection scheme and HTTP status.
- `torii_http_requests_total{route_id,route_template,surface,representation,error_code,content_type,method,status}` — request counter keyed only by catalog metadata and bounded outcome labels. `route_template` is the Axum template, never a concrete identifier, cursor, or raw URL.
- `torii_http_request_duration_seconds_bucket{route_id,route_template,surface,representation,content_type,method}` — latency histogram for per-operation and JSON/Norito parity dashboards.
- `torii_http_request_bytes_total{route_id,route_template,surface,representation,content_type,method}` — exact request-body bytes when the body size is known.
- `torii_http_response_bytes_total{route_id,route_template,surface,representation,error_code,content_type,method,status}` — exact response-body bytes when the body size is known.
- `torii_norito_decode_failures_total{payload_kind,reason}` — bucketed Norito RPC decode failures (invalid magic, checksum mismatch, unsupported feature, etc.).
- `torii_address_invalid_total{surface,reason}` — rejects grouped by Torii surface (e.g., `routing.source`, `iso_bridge.source`) and the stable address error code so SDK drift or malformed i105 literals are visible.
- Rely on `torii_address_invalid_total{surface,reason}` to monitor strict canonical address ingestion.
- Existing gauges (`torii_active_connections_total{scheme}`, `torii_pre_auth_reject_total{reason}`) must include `scheme="norito_rpc"` to track transport gating.

Alert rules live in `dashboards/alerts/torii_norito_rpc_rules.yml` (see companion test `dashboards/alerts/tests/torii_norito_rpc_rules.test.yml`). Highlights:
- `ToriiNoritoRpcErrorSpike` warns when Norito 5xx responses exceed allowable thresholds for five minutes.
- `ToriiNoritoRpcLatencyDegraded` fires when Norito P95 latency breaches 750 ms.
- `ToriiNoritoRpcSilentTraffic` detects 30 minutes without Norito requests, signalling misrouted traffic.

Use `scripts/telemetry/test_torii_norito_rpc_alerts.sh` to run `promtool test rules` locally or in CI so alert updates stay in sync with dashboards.

### SoraFS Data Availability Observability Pack (DA-9)

- **Dashboards.**
  - `dashboards/grafana/sorafs_fetch_observability.json` visualises ingestion latency (`histogram_quantile` over `sorafs_orchestrator_fetch_duration_ms` / `sorafs_orchestrator_chunk_latency_ms`), retry/backoff counters, and transport errors so DA fetch regressions are visible during burn-in.
  - `dashboards/grafana/sorafs_gateway_observability.json` focuses on PoR ingest queues (`torii_sorafs_por_ingest_backlog`, `torii_sorafs_por_ingest_failures_total`) and gateway refusal/throttle counters.
  - `dashboards/grafana/sorafs_capacity_penalties.json` tracks retention (`torii_sorafs_storage_bytes_{used,capacity}`), accumulated GiB·hours, disputes/slash proposals, and fee projections so finance/storage stakeholders review the same evidence bundle.
  - `dashboards/grafana/sorafs_capacity_health.json` graphs declared/effective/utilised GiB, outstanding reservations, and the consensus-maintained global pin totals (`torii_sorafs_pin_retained_manifests`, `torii_sorafs_pin_live_content_bytes`). Lifecycle and replication-order status require finalized registry queries; Torii does not scan the registry to synthesize Prometheus gauges.
  - `dashboards/grafana/sorafs_governance_dag.json` tracks Governance DAG publication attempts, failures, published bytes, backlog, head age, and last-success age via `sorafs_governance_dag_*` metrics. The filesystem publisher emits local publication outcomes today; public IPFS/IPNS head emission remains an SF-12 rollout gate.
  - `dashboards/grafana/sorafs_appeal_finance.json` tracks appeal-finance report, weekly-rollup, and settlement-receipt publication freshness, failures, payload bytes, rollup lag, receipt/report lag, and Governance DAG backlog via the same publication metrics.
- **Chunking cost.** `torii_da_chunking_seconds` tracks DA chunking + erasure coding CPU time; monitor p95 via `histogram_quantile(0.95, sum(rate(torii_da_chunking_seconds_bucket[5m])) by (le))`.
- **Proof health.** PDP/PoTR pass rates surface through `torii_sorafs_proof_stream_events_total{kind="pdp|potr",result}`; latency distributions are published via `torii_sorafs_proof_stream_latency_ms`. Pair them with `torii_sorafs_storage_por_samples_{success,failed}_total` to prove challenge coverage and link panels directly to provider alerts.
- **Retention digest.** `specs/status/sorafs_da_weekly_digest.md` is the weekly template mandated by DA-9. Populate it with snapshots exported from the dashboards above plus the PromQL snippets used to compute p95 ingestion latency and consensus-maintained pin totals; attach the Markdown to the Friday digest mail that SRE sends to Storage + Product.
- **Alerting.** Import `dashboards/alerts/sorafs_fetch_rules.yml`, `dashboards/alerts/sorafs_gateway_rules.yml`, `dashboards/alerts/sorafs_capacity_rules.yml`, `dashboards/alerts/sorafs_governance_dag_rules.yml`, and `dashboards/alerts/sorafs_appeal_finance_rules.yml` so ingestion, gateway, capacity saturation, local governance publication, and appeal-finance report/weekly-rollup/settlement-receipt signals stay covered. Validate each pack with its fixture (`dashboards/alerts/tests/sorafs_fetch_rules.test.yml`, `dashboards/alerts/tests/sorafs_capacity_rules.test.yml`, `dashboards/alerts/tests/sorafs_governance_dag_rules.test.yml`, `dashboards/alerts/tests/sorafs_appeal_finance_rules.test.yml`) via `promtool test rules …` (or `scripts/check_prometheus_rules.sh dashboards/alerts/sorafs_*`) before publishing changes.
- **Runbook integration.** Incident tickets tied to DA need three artefacts: (1) Grafana JSON exports (`sorafs_fetch_observability` and `sorafs_gateway_observability`), (2) the filled digest template, and (3) alert UUIDs from the rule groups above. This satisfies the DA-9 roadmap requirement that SRE/operator reviews include dashboards plus a narrative digest.

### Confidential Tree Telemetry (M2.2)

Roadmap item **M2.2 — Gas & Telemetry** now exposes per-asset gauges and eviction
counters for the confidential commitment tree so operators can prove tree depth,
root-history hygiene, and checkpoint behaviour:

- `iroha_confidential_tree_commitments{asset_id}` — current number of commitments (leaves).
- `iroha_confidential_tree_depth{asset_id}` — Merkle depth in levels (bounded by the verifier profile).
- `iroha_confidential_root_history_entries{asset_id}` — retained historical roots (should not exceed `confidential.tree_roots_history_len`).
- `iroha_confidential_frontier_checkpoints{asset_id}` — number of recorded frontier checkpoints.
- `iroha_confidential_frontier_last_checkpoint_height{asset_id}` — height of the last frontier checkpoint (0 when no checkpoint exists).
- `iroha_confidential_frontier_last_checkpoint_commitments{asset_id}` — commitment count captured alongside the last checkpoint.
- `iroha_confidential_root_evictions_total{asset_id}` — counter of root-history evictions after enforcing the cap.
- `iroha_confidential_frontier_evictions_total{asset_id}` — counter of frontier checkpoint evictions when the interval/depth window trims history.

Grafana panel `dashboards/grafana/confidential_assets.json` graphs the gauges
and pairs the eviction counters with alert rules that fire when roots or
checkpoints churn faster than expected. Capture evidence with a simple scrape:

```bash
curl -s http://127.0.0.1:8180/metrics \
  | rg 'iroha_confidential_(tree_(commitments|depth)|root_history_entries|frontier_(checkpoints|last_checkpoint_height|last_checkpoint_commitments)){asset_id="4cuvDVPuLBKJyN6dPbRQhmLh68sU"}'
```

Pair this with `rg 'iroha_confidential_(root|frontier)_evictions_total'` to prove
the eviction counters advanced after a maintenance window. The calibration doc
(`specs/confidential_assets_calibration.md`) records the signed baselines
and links to the corresponding governance acknowledgement.

#### Norito RPC degraded runbook

Use this checklist when the Norito transport fails SLOs or generates alerts:

- **Primary signals:** `ToriiNoritoRpcErrorSpike`, `ToriiNoritoRpcLatencyDegraded`, `ToriiNoritoRpcSilentTraffic`, `torii_norito_decode_failures_total`, and `torii_request_duration_seconds_bucket{scheme="norito_rpc"}` panels in `dashboards/grafana/torii_norito_rpc_observability.json`.
- **Client corroboration:** SDK CI and mock-harness jobs export `torii_mock_harness_retry_total`, `torii_mock_harness_duration_ms`, and `torii_mock_harness_fixture_version`; spikes in these client-side metrics usually indicate regressions before production traffic is impacted.
- **Support tooling:** `python/iroha_python/scripts/run_norito_rpc_smoke.sh` validates end-to-end request/response flows, and `scripts/telemetry/test_torii_norito_rpc_alerts.sh` confirms alert expressions continue to match the on-disk rules after remediation.

**Immediate triage**

1. Determine the failure mode:
   - Error spike: `torii_request_failures_total{scheme="norito_rpc"}` or decode counters rise.
   - Latency breach: `histogram_quantile(0.95, torii_request_duration_seconds_bucket{scheme="norito_rpc"})` exceeds 750 ms.
   - Silent traffic: `torii_request_duration_seconds_count{scheme="norito_rpc"}` flat-lines while HTTP/JSON remain healthy.
2. Scope the impact with dashboards, then inspect Torii logs filtered on `ConnScheme::NoritoRpc` for `schema_mismatch`, checksum, or TLS errors. Decode failures emit the exact `reason` tag shown in telemetry.
3. Verify edge ingress still forwards the binary payloads by running `curl -H 'Content-Type: application/x-norito' https://<torii-host>/rpc/ping` (or the mock harness) from multiple regions. A JSON-looking response indicates a proxy stripped the header.
4. Compare server metrics with SDK mock-harness counters. If retries spike in CI but production traffic is normal, halt the client rollout and coordinate with SDK owners instead of throttling Norito globally.

**Mitigation options**

- **Misbehaving clients:** Gate them via `torii.preauth_scheme_limits.norito_rpc` until parity is restored; the wire records live in `iroha_torii_shared::configuration`.
- **Decode or schema mismatches:** Ensure Torii and SDKs run the same fixture bundle by checking `fixtures/norito_rpc/schema_hashes.json` (the DTO→hash table). If hashes diverge, run `cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-fixtures --output-root <absent-absolute-external-root>` at two independent absent absolute external roots. Before any tracked update, require identical exact path sets, entry types, modes, completion manifests, and every file byte; apply the reviewed identity-relative patch from either sealed root, then run `cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-verify`.
- **Ingress/proxy issues:** Fix header forwarding or MTU settings, then rerun `python/iroha_python/scripts/run_norito_rpc_smoke.sh`.
- **Full brownout / rollback:** If service impact persists, flip `torii.transport.norito_rpc.stage` to `canary` or `disabled` (per `specs/torii/norito_rpc_rollout_plan.md`), reload Torii, and ensure `/rpc/capabilities` reports the downgraded stage so SDKs fall back to JSON without guessing. Record the change in the canary runbook (`specs/runbooks/torii_norito_rpc_canary.md`).

**Verification**

1. Watch `torii_request_failures_total` and the decode counter return to baseline; clear Alertmanager silences only after the metrics stay flat for one evaluation period.
2. Confirm `torii_active_connections_total{scheme="norito_rpc"}` stabilises and the `ToriiNoritoRpcSilentTraffic` alert stays green.
3. Re-run the Norito RPC smoke test (`python/iroha_python/scripts/run_norito_rpc_smoke.sh`) and alert tests (`scripts/telemetry/test_torii_norito_rpc_alerts.sh`).
4. Capture evidence (Grafana images, config patches, CLI outputs) and attach it to the NRPC-2 runbook ticket plus `status.md` so the roadmap artifact remains auditable.

## Nexus scheduler TEU metrics

The Nexus scheduler exports TEU-focused metrics once the lane router lands. All
series are exposed behind the `metrics` capability and default to `0` in
single-lane mode so dashboards can be provisioned early.

Key metrics:
- `nexus_scheduler_lane_teu_capacity{lane}` (gauge) — per-lane TEU cap.
- `nexus_scheduler_lane_teu_slot_committed{lane}` (gauge) — TEU used during
  the most recent slot.
- `nexus_scheduler_lane_teu_slot_breakdown{lane,bucket}` (gauge) — stacked
  view of floor/headroom/must-serve/circuit-breaker consumption.
- `nexus_scheduler_lane_teu_deferral_total{lane,reason}` (counter) — TEU
  deferred because the lane hit a cap, quota, or envelope limit.
- `nexus_scheduler_dataspace_teu_backlog{lane,dataspace}` (gauge) — queued
  TEU demand remaining after scheduling.
- `nexus_scheduler_dataspace_age_slots{lane,dataspace}` (gauge) — slots
  since the dataspace was last served.
- `nexus_scheduler_starvation_bound_slots{lane}` (gauge) — configured
  starvation bound applied to the lane.
- `nexus_scheduler_must_serve_truncations_total{lane}` (counter) — truncated
  must-serve slices.
- `nexus_scheduler_lane_trigger_level{lane}` (gauge) — current circuit-breaker tier.

The `/status` endpoint mirrors these gauges and now ships richer per-lane
pipeline summaries via `nexus_scheduler_lane_teu_status` responses. Each lane
snapshot includes the scheduler graph counters (`tx_vertices`, `tx_edges`,
`overlay_count`, `overlay_instr_total`, `overlay_bytes_total`, `rbc_chunks`,
`rbc_bytes_total`) plus:

The root `/status` payload also exposes a `build` object so operators can
verify what binary is actually serving traffic. The object includes:

- `version` — Cargo package version baked into the node binary.
- `git_commit_sha` — source revision baked into the node binary.
- `cargo_features` — enabled Cargo feature set used for the build.
- `target_triple` — compilation target triple for the running binary.
- `wire_schema_hash` — lowercase hex of
  `iroha_core::release_identity::wire_schema_hash()` over the compiled block
  wire (`SignedBlock`) and consensus wire (`iroha_sumeragi::message::WireMessage`)
  schemas plus the IVM ABI v1 hash; target independent but feature dependent,
  and pinned by release manifests.

Queue-aware liveness checks should use the raw `/status` facts together with
operator-authenticated `GET /v1/pipeline/preflight`. The preflight request must
carry a fresh signature over the exact genesis `NetworkId`, method, path,
query, and empty body; clients dispatch once without redirects or retries.
The status payload exposes `observed_at_ms`,
`queue_size`, `queue_queued`, `queue_inflight`,
`last_block_committed_at_ms`, `last_non_empty_block_committed_at_ms`,
`time_since_last_block_ms`, and `time_since_last_non_empty_block_ms`.
Treat `queue_size` as the primary gate: a peer is stalled only when queued work
exists and elapsed block time exceeds
`/v1/pipeline/preflight.sumeragi.stall_threshold_ms`. The preflight response
also reports current admission, block, pipeline, queue, and fee limits so SDKs
can explain rejected or delayed submissions before posting a transaction.

- `peak_layer_width`, `layer_count` — outer bounds of the scheduler layering
  that executed for the lane in the latest block.
- `avg_layer_width`, `median_layer_width`,
  `scheduler_utilization_pct` — basic moments for histogram dashboards.
- `layer_width_buckets[le]` — monotonically increasing buckets (`le =
  1,2,4,8,16,32,64,128`) matching the Prometheus histogram shown on Grafana.
- `manifest_required`, `manifest_ready` — whether the lane requires a manifest and if one is loaded.
- `manifest_path` — best-effort path of the active manifest (surfaced for operators).
- `manifest_validators`, `quorum` — validator roster and quorum declared by the manifest.
- `protected_namespaces` — namespaces gated by the lane’s governance policy.
- `runtime_upgrade` — snapshot of the runtime-upgrade hook (`allow`, `require_metadata`, `metadata_key`, `allowed_ids`).
- `dataspace_id`, `dataspace_alias` — identify which dataspace the lane services, matching the scheduler backlog gauges.
- `storage_profile` — lane storage strategy (`full_replica`, `commitment_only`, `split_replica`).
- `detached_prepared`, `detached_merged`, `detached_fallback` — detached overlay
  execution counters sized to the lane.
- `quarantine_executed` — quarantine fallbacks the lane had to drain during the
  block.

The sister collection `nexus_scheduler_dataspace_teu_status` mirrors the
per-dataspace backlog view and reports `tx_served` plus the dataspace
`fault_tolerance` (f) so operators can see the configured lane-relay committee
sizing (`3f+1`) in the same status payload.

The transaction queue now keeps these snapshots warm in between block commits.
Routing rules can specify dataspace aliases, so `ConfigLaneRouter` resolves both
lane and dataspace IDs before the queue updates telemetry.
Every time a transaction is enqueued or drained from consensus, the queue
recomputes pending TEU per lane/dataspace and updates the gauges. Operators can
therefore watch `nexus_scheduler_dataspace_teu_backlog` to understand backlog
pressure even before the next slot envelope is assembled. Lane headroom now
reflects remaining capacity (`capacity - min(pending_teu, capacity)`) instead of
mirroring backlog directly, so `nexus.scheduler.headroom` only fires when a lane
actually consumes most of its configured TEU budget rather than whenever the
queue is non-empty.

#### Nexus configuration drift

- `nexus_config_diff_total{knob,profile}` (counter) — increments whenever the active Nexus configuration diverges from the single-lane baseline. The `knob` label identifies the section that changed (for example `nexus.lane_catalog.count`, `nexus.routing.rules`, `nexus.da`), and `profile` is set to `active`.

Alert snippet:

```
increase(nexus_config_diff_total{profile="active"}[5m]) > 0
```

Page outside planned maintenance windows. Each increment also emits a `telemetry` log entry `nexus.config.diff` with a Norito JSON payload listing `baseline` and `current` values — review it during config rollouts and the `TRACE-TELEMETRY-BRIDGE` dry-run to confirm the expected knobs moved.

- `nexus_lane_configured_total` (gauge) — reports how many Nexus lane catalog entries the node has applied. Compare it against the expected lane count (for example, `1` for canonical single-lane bundles or `3` for Nexus multi-lane deployments) to catch misconfigured peers ahead of routed-trace audits. First-release nodes always expose the canonical lane/dataspace metrics; `nexus.enabled = false` is rejected during configuration parsing.

Alert snippet:

```
nexus_lane_configured_total != EXPECTED_LANE_COUNT
```

Example PromQL snippets:
- Lane headroom: `nexus_scheduler_lane_teu_capacity - nexus_scheduler_lane_teu_slot_committed`.
- Starvation bound: `max_over_time(nexus_scheduler_dataspace_age_slots[5m])` vs `max(nexus_scheduler_starvation_bound_slots)`.
- Deferrals per reason: `rate(nexus_scheduler_lane_teu_deferral_total{reason="cap_exceeded"}[10m])`.
- Truncated must-serve: `increase(nexus_scheduler_must_serve_truncations_total[30m])`.

Dashboard:
- Import `specs/grafana_scheduler_teu.json`. Panels include lane capacity
  stats, stacked bucket timeseries, backlog heatmap, starvation bound trend, and
  trigger status table. Set `$PROM_DS` to your Prometheus data source after import.

Alert thresholds:
- Cap exhaustion: trigger when `rate(nexus_scheduler_lane_teu_deferral_total{reason="cap_exceeded"}[5m]) > 0` for `15m`.
- Starvation bound: trigger when
  `max(nexus_scheduler_dataspace_age_slots) >= max(nexus_scheduler_starvation_bound_slots)` for `5m`.
- Must-serve truncation: ticket when
  `increase(nexus_scheduler_must_serve_truncations_total[1h]) > 0`.

Operator triage:
1. Run `iroha_cli --operator-private-key-file /absolute/runtime/operator.key app nexus lane-report --summary`
   to confirm lane-governance readiness, then inspect the lane-labelled metrics
   below for the exact cap, configured bound, and backlog.
2. Check `nexus_scheduler_lane_trigger_level` (tier `>0` implies a
   circuit-breaker is reducing caps); reference `specs/nexus_transition_notes.md`
   for trigger semantics.
3. Inspect Torii logs (`pipeline::scheduler`) for per-slot summaries including
   bucket breakdowns and queue diffs.
4. If starvation continues, verify `routing_policy` and dataspace quotas in
   configuration; confirm peers share identical catalog hashes.

##### Lane topology events

- Telemetry log `nexus.lane.topology` — emitted whenever a lane is provisioned, retired, or renamed. Each Norito JSON payload includes:
  - `action`: `provisioned`, `retired`, or `alias_migrated`.
  - `lane_id`, `alias`, `slug`, `dataspace_id`, `visibility`, and `storage_profile` for new lanes.
  - For migrations: `alias_before`, `alias_after`, `slug_before`, `slug_after`.

Operator workflow:
1. Tail `journalctl -u irohad -o json | jq 'select(.msg==\"nexus.lane.topology\")'` (or subscribe via the OTLP bridge) whenever the governance catalog changes so you capture an immutable record of the storage changes.
2. Store the JSON payloads with the change request; auditors cross-check them with `nexus_lane_configured_total` and Kura’s directory layout.
3. Add alert rules when unexpected events arrive (for example, `action="retired"` outside a maintenance window). A simple Loki/Grafana expression is `count_over_time({job="irohad"} |= "nexus.lane.topology" | json | action="retired" [5m]) > 0`.
4. Feed the events into automation such as `scripts/nexus_lane_smoke.py --telemetry-file telemetry.ndjson --require-alias-migration alpha:payments` so the smoke tests can assert that relabeling occurred after a rename. The helper rejects telemetry logs that do not contain the expected alias entries, making it safe to gate CI on the recorded `nexus.lane.topology` payloads.

##### Lane headroom telemetry log

- When per-lane headroom drops below 15 % of its configured capacity, hits zero,
  or `nexus_scheduler_lane_trigger_level > 0`, Iroha emits the structured log
  `nexus.scheduler.headroom`. Each Norito payload records `lane_id`,
  `capacity`, `committed`, `headroom_teu`, `headroom_pct`, bucket breakdown,
  `trigger_level`, `starvation_bound_slots`, and cumulative deferrals. Tail the
  log during drills with:

  ```sh
  journalctl -u irohad -o json | jq 'select(.msg=="nexus.scheduler.headroom")'
  ```

- Prometheus exposes `nexus_scheduler_lane_headroom_events_total{lane_id}` so you
  can alert when the log fires more than a handful of times per hour outside
  rehearsals. Combine it with `nexus_scheduler_lane_teu_slot_breakdown` to tune
  TEU alerts.
- After uploading the telemetry pack, run
  `scripts/telemetry/validate_nexus_telemetry_pack.py --pack-dir <dir>
  --workload-seed NEXUS-REH-2026Q1 --slot-range 820-860` to generate
  `telemetry_manifest.json` + `.sha256` for the evidence bucket and tracker.

#### OTLP capture batch sizing

The OTLP exporter used during rehearsals throttled when its batch queue capped
out. Configure your collector (for example `otelcol-contrib`) with a 256-sample
batch to keep `otlp.ndjson` captures within the rehearsal window:

```yaml
exporters:
  otlphttp:
    endpoint: https://telemetry.example.net/otlp
processors:
  batch:
    timeout: 5s
    send_batch_size: 256
    send_batch_max_size: 256
extensions:
  health_check: {}
service:
  extensions: [health_check]
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlphttp]
```

## Nexus finality, DA quorum, and oracle SLO telemetry (NX-18)

NX-18 introduces a dedicated metric set for the 1 s finality gate. The gauges
and histograms ship in every build (single-lane deployments simply emit steady
`0`/baseline values) so operators can configure dashboards and alerts ahead of
the Nexus cut-over. All metrics back the Grafana board stored in
`dashboards/grafana/nexus_lanes.json` and the runbook documented in
`specs/runbooks/nexus_lane_finality.md`.

### Metric cheat sheet

| Metric | Description | SLO / Action |
|--------|-------------|--------------|
| `histogram_quantile(0.95, iroha_slot_duration_ms)` | Slot-duration histogram derived from the end of every Sumeragi slot. | Keep p95 ≤ 1 000 ms (warning at 950 ms). Breaches must trigger the slot runbook and be recorded in the NX-18 drill log. |
| `iroha_slot_duration_ms_latest` | Gauge of the most recent slot duration. | Capture alongside the histogram whenever filing incidents; sustained spikes > 1 100 ms indicate an unhealthy validator even if quantiles remain green. |
| `iroha_da_quorum_ratio` | Rolling fraction of slots that satisfied the DA quorum window. | Target ≥ 0.95; capture authenticated Sumeragi status and queue/drop metrics to locate failing validators or transport paths. |
| `iroha_oracle_price_local_per_xor` | Latest TWAP reported by the lane-specific oracle. | Watch for spikes when swap lines are thin; tie haircuts to treasury reports. |
| `iroha_oracle_staleness_seconds` | Seconds since the last oracle refresh. | Alert at ≥ 75 s; fail the NX-18 gate at ≥ 90 s until the feed is restarted. |
| `iroha_oracle_twap_window_seconds` | Effective TWAP window length. | Should remain at 60 s ± 5 s; deviations mean the oracle config drifted. |
| `iroha_oracle_haircut_basis_points` | Applied haircut per lane/dataspace. | Compare against the liquidity tier table before approving router changes. |
| `iroha_settlement_buffer_xor` / `iroha_settlement_buffer_capacity_xor` | Remaining buffer headroom and configured capacity. | Soft alert at 25 %, hard alert at 10 %; below the hard threshold force XOR-only routing and log the incident. |

### Automation & evidence

- `scripts/telemetry/check_slot_duration.py --json-out artifacts/nx18/slot_summary.json` parses Prometheus dumps and enforces the p95/p99 gates. CI wires this via `ci/check_nexus_lane_smoke.sh` so every release candidate ships the JSON summary next to the metrics snapshot (`fixtures/nexus/lanes/metrics_ready.prom` provides the sample pack for local validation).
- `scripts/telemetry/bundle_slot_artifacts.py --metrics <metrics.prom> --summary artifacts/nx18/slot_summary.json --out-dir artifacts/nx18` emits `slot_bundle_manifest.json` and SHA-256 digests for the required artefacts. `scripts/run_release_pipeline.py` invokes it automatically (skip with `--skip-nexus-lane-smoke`) so NX-18 sign-offs include immutable evidence.
- The chaos/acceptance harness now runs `scripts/telemetry/nx18_acceptance.py --json-out artifacts/nx18/nx18_acceptance.json <metrics.prom>` inside `ci/check_nexus_lane_smoke.sh` to gate DA quorum, oracle staleness/TWAP/haircuts, settlement buffers, and slot quantiles in one place. Keep the thresholds in the script aligned with the dashboards/alert rules.
- Capture routed-trace telemetry with `scripts/telemetry/check_nexus_audit_outcome.py` and archive the resulting JSON under `fixtures/documentation/nexus_audit_outcomes/`. The tool enforces that every rehearsal produced a `nexus.audit.outcome` event and keeps the `TRACE-TELEMETRY-BRIDGE` checkpoints auditable.
- Record all drills with `scripts/telemetry/log_sorafs_drill.sh --log ops/drill-log.md --program NX-18 --status <status>` so quarter-end reports can enumerate slot, DA, oracle, and buffer rehearsals.

### Operator references

- Dashboards: import `dashboards/grafana/nexus_lanes.json` and keep it in sync with production panels, including quantile/ratio thresholds and Alertmanager annotations.
- Runbooks: use `specs/runbooks/nexus_lane_finality.md` for finality/oracle procedures and `ops/runbooks/da-quorum.md` for DA-specific mitigations. Both documents call out the metrics above plus evidence requirements.
- Release gates: ensure `status.md` entries link to the latest NX-18 slot bundle and Grafana captures whenever preparing a release candidate; the roadmap requires signed artefacts before multi-lane code paths are enabled by default.

#### Routed-trace audit outcomes

- `telemetry` log `nexus.audit.outcome` — produced by `Telemetry::record_audit_outcome`. The Norito payload includes `trace_id`, `slot_height`, `reviewer`, `status` (for example `pass`, `fail`, `mitigated`), and an optional `mitigation_url`. No node path calls the emitter yet, so it is compiled only for `iroha_core` unit tests until the routed-trace checkpoint wiring lands.
- Prometheus surfaces `nexus_audit_outcome_total{trace_id,status}` and `nexus_audit_outcome_last_timestamp_seconds{trace_id}` so dashboards and alert rules can track routed-trace health.

Operator workflow:
1. During `TRACE-*` rehearsals, tail the telemetry stream (`journalctl -u irohad -o json` or the bounded structured-event sink) and confirm an event appears for each scheduled audit window.
2. Archive the JSON payload alongside the audit artefacts so reviewers can trace the verdict and mitigation link.
3. Run `scripts/telemetry/check_nexus_audit_outcome.py` against the telemetry log (for example, `--trace-id TRACE-TELEMETRY-BRIDGE --window-start <ISO time> --window-minutes 30`). The helper enforces that a matching payload exists, fails the run if a disallowed status (default `fail`) is observed, and stores the JSON artefact under `fixtures/documentation/nexus_audit_outcomes/` for audit records.
4. Alert when `status="fail"` or if no event is observed within 30 minutes of the expected audit slot; the Prometheus rule `dashboards/alerts/nexus_audit_rules.yml` fires on failing statuses, while CI should integrate the script above to gate the “missing outcome” requirement.


## Norito Streaming Telemetry

Prometheus metrics exposed by the Norito streaming runtime:

- `streaming_encode_latency_ms`: histogram of publisher encode latency.
- `streaming_encode_audio_jitter_ms`: EWMA audio jitter observed at the publisher (ms).
- `streaming_encode_audio_max_jitter_ms`: gauge tracking the peak audio jitter observed (ms).
- `streaming_encode_dropped_layers_total`: counter of rendition layers dropped during encode.
- `streaming_decode_buffer_ms`: viewer buffer depth histogram.
- `streaming_decode_dropped_frames_total`: counter for decoder frame drops.
- `streaming_decode_max_queue_ms`: histogram of max decode queue depth.
- `streaming_decode_av_drift_ms`: histogram of absolute audio/video drift measured at viewers.
- `streaming_decode_max_drift_ms`: gauge for maximum audio/video drift observed (ms).
- `streaming_audio_jitter_ms`, `streaming_audio_max_jitter_ms`: viewer-reported audio jitter histogram + peak gauge derived from `ReceiverReport` diagnostics.
- `streaming_av_drift_ms`, `streaming_av_max_drift_ms`: viewer-reported audio/video drift histogram + peak gauge (absolute milliseconds).
- `streaming_av_drift_ewma_ms`: signed gauge tracking the viewer EWMA drift used for throttling decisions.
- `streaming_av_sync_window_ms`: gauge exposing the active aggregation window (ms) advertised by viewers.
- `streaming_av_sync_violation_total`: counter incremented when viewers flag segments beyond the ±10 ms sync budget.
- `streaming_network_rtt_ms`, `streaming_network_loss_percent_x100`, `streaming_network_fec_{repairs,failures}_total`, `streaming_network_datagram_reinjects_total`: network health metrics.
- `streaming_energy_encoder_mw`, `streaming_energy_decoder_mw`: power usage gauges from publishers/viewers.

Telemetry payloads emitted over Norito (`TelemetryEncodeStats`, `TelemetryDecodeStats`, and the new `SyncDiagnostics` bundle carried inside `ReceiverReport`) now include audio jitter and drift fields so dashboards can surface out-of-sync segments. See `specs/project_tracker/nsc28b_av_sync_telemetry.md` for the enforcement rollout plan.
