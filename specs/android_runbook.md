<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android SDK Operations Runbook

This runbook supports operators and support engineers managing Android SDK
deployments for AND7 and beyond. Pair with the Android Support Playbook for SLA
definitions and escalation paths.

> **Note:** When updating incident procedures, also refresh the shared
> troubleshooting matrix (`specs/sdk/android/troubleshooting.md`) so the
> scenario table, SLAs, and telemetry references stay aligned with this runbook.

## 0. Quickstart (when pagers fire)

Keep this sequence handy for Sev 1/Sev 2 alerts before diving into the detailed
sections below:

1. **Confirm the active config:** Capture the `ClientConfig` manifest checksum
   emitted at app startup and compare it to the pinned manifest in
   `configs/android_client_manifest.json`. If hashes diverge, halt releases and
   file a config drift ticket before touching telemetry/overrides (see §1).
2. **Run the schema diff gate:** Execute the `telemetry-schema-diff` CLI against
   the accepted snapshot
   (`specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json`).
   Treat any `policy_violations` output as Sev 2 and block exports until the
   discrepancy is understood (see §2.6).
3. **Check dashboards + status CLI:** Open the Android Telemetry Redaction and
   Exporter Health boards, then run
   `scripts/telemetry/check_redaction_status.py --status-url <collector>`. If
   authorities are under the floor or exports error, capture screenshots and
   CLI output for the incident doc (see §2.4–§2.5).
4. **Decide on overrides:** Only after the above steps and with incident/owner
   recorded, issue a limited override via `scripts/android_override_tool.sh`
   and log it in `telemetry_override_log.md` (see §3). Default expiry: <24 h.
5. **Escalate per contact list:** Page the Android on-call and Observability TL
   (contacts in §8), then follow the escalation tree in §4.1. If attestation or
   StrongBox signals are involved, pull the latest bundle and run the harness
   checks from §7 before re-enabling exports.

## 1. Configuration & Deployment

- **ClientConfig sourcing:** Ensure Android clients load Torii endpoint, TLS
  policies, and retry knobs from `iroha_config`-derived manifests. Validate
  values during app startup and log checksum of the active manifest.
  Implementation reference: `java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ClientConfig.java`
  threads `TelemetryOptions` from `java/iroha_android/src/main/java/org/hyperledger/iroha/android/telemetry/TelemetryOptions.java`
  (plus the generated `TelemetryObserver`) so hashed authorities are emitted automatically.
- **Hot reload:** Use the configuration watcher to pick up `iroha_config`
  updates without app restarts. Failed reloads should emit the
  `android.telemetry.config.reload` event and trigger retry with exponential
  backoff (max 5 attempts).
- **Fallback behaviour:** When configuration is missing or invalid, fall back to
  safe defaults (read-only mode, no pending queue submission) and surface a user
  prompt. Record the incident for follow-up.

### 1.1 Config reload diagnostics

- The config watcher emits `android.telemetry.config.reload` signals with
  `source`, `result`, `duration_ms`, and optional `digest`/`error` fields (see
  `configs/android_telemetry.json` and
  `java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ConfigWatcher.java`).
  Expect a single `result:"success"` event per applied manifest; repeated
  `result:"error"` records indicate the watcher exhausted its 5 backoff attempts
  starting at 50 ms.
- During an incident, capture the latest reload signal from the collector
  (OTLP/span store or the redaction status endpoint) and log the `digest` +
  `source` in the incident doc. Compare the digest to
  `configs/android_client_manifest.json` and the release manifest distributed to
  operators.
- If the watcher continues to emit errors, run the targeted harness to reproduce
  the parse failure with the suspect manifest:
  `ci/run_android_tests.sh org.hyperledger.iroha.android.client.ConfigWatcherTests`.
  Attach the test output and the failing manifest to the incident bundle so SRE
  can diff it against the baked configuration schema.
- When reload telemetry is missing, confirm the active `ClientConfig` carries a
  telemetry sink and that the OTLP collector still accepts the
  `android.telemetry.config.reload` ID; otherwise treat it as a Sev 2 telemetry
  regression (same path as §2.4) and pause releases until the signal returns.

### 1.2 Deterministic key export bundles
- Software exports now emit v3 bundles with per-export salt + nonce, `kdf_kind`, and `kdf_work_factor`.
  The exporter prefers Argon2id (64 MiB, 3 iterations, parallelism = 2) and falls back to
  PBKDF2-HMAC-SHA256 with a 350 k iteration floor when Argon2id is unavailable on the device. Bundle
  AAD still binds to the alias; passphrases must be at least 12 characters for v3 exports and the
  importer rejects all-zero salt/nonce seeds.
  `KeyExportBundle.decode(Base64|bytes)`, import with the original passphrase, and re-export to v3 to
  move to the memory-hard format. The importer rejects all-zero or reused salt/nonce pairs; always
  rotate bundles instead of reusing old exports between devices.
- Negative-path tests in `ci/run_android_tests.sh --tests org.hyperledger.iroha.android.crypto.export.DeterministicKeyExporterTests`
  rejection. Clear passphrase char arrays after use and capture both the bundle version and `kdf_kind`
  in incident notes when recovery fails.

## 2. Telemetry & Redaction

> Quick reference: see
> [`telemetry_redaction_quick_reference.md`](sdk/android/telemetry_redaction_quick_reference.md)
> for the condensed command/threshold checklist used during enablement
> sessions and incident bridges.

- **Signal inventory:** Refer to `specs/sdk/android/telemetry_redaction.md`
  for the full list of emitted spans/metrics/events and
  `specs/sdk/android/readiness/signal_inventory_worksheet.md`
  for owner/validation details and outstanding gaps.
- **Canonical schema diff:** The approved AND7 snapshot is
  `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json`.
  Every new CLI run must be compared against this artefact so reviewers can see
  that the accepted `intentional_differences` and `android_only_signals` still
  match the policy tables documented in
  `specs/sdk/android/telemetry_schema_diff.md` §3. The CLI now adds
  `policy_violations` when any intentional difference is missing a
  `status:"accepted"`/`"policy_allowlisted"` (or when Android-only records lose
  their accepted status), so treat non-empty violations as Sev 2 and stop
  exports. The `jq` snippets below remain as a manual sanity check on archived
  artefacts:
  ```bash
  jq '.intentional_differences[] | select(.status != "accepted" and .status != "policy_allowlisted")' "$OUT"
  jq '.android_only_signals[] | select(.status != "accepted")' "$OUT"
  jq '.field_mismatches[] | {signal, field, android, rust}' "$OUT"
  ```
  Treat any output from these commands as a schema regression that needs an
  AND7 readiness bug before telemetry exports continue; `field_mismatches`
  must stay empty per `telemetry_schema_diff.md` §5. The helper now writes
  `artifacts/android/telemetry/schema_diff.prom` automatically; pass
  `--textfile-dir /var/lib/node_exporter/textfile_collector` (or set
  `ANDROID_SCHEMA_DIFF_TEXTFILE_DIR`) when running on staging/production hosts
  so the `telemetry_schema_diff_run_status` gauge flips to `policy_violation`
  automatically if the CLI detects drift.
- **CLI helper:** `scripts/telemetry/check_redaction_status.py` inspects
  `artifacts/android/telemetry/status.json` by default; pass `--status-url` to
  query staging and `--write-cache` to refresh the local copy for offline
  drills. Use `--min-hashed 214` (or set
  `ANDROID_TELEMETRY_MIN_HASHED_AUTHORITIES=214`) to enforce the governance
  floor on hashed authorities during every status poll.
- **Authority hashing:** All authorities are hashed using Blake2b-256 with the
  quarterly rotation salt stored in the secure secrets vault. Rotations occur on
  the first Monday of each quarter at 00:00 UTC. Verify the exporter picks up
  the new salt by checking the `android.telemetry.redaction.salt_version` metric.
- **Device profile buckets:** Only `emulator`, `consumer`, and `enterprise`
  tiers are exported (alongside SDK major version). Dashboards compare these
  counts against Rust baselines; variance >10% raises alerts.
- **Network metadata:** Android exports `network_type` and `roaming` flags only.
  Carrier names are never emitted; operators should not request subscriber
  information in incident logs. The sanitised snapshot is emitted as the
  `android.telemetry.network_context` event, so ensure apps register a
  `NetworkContextProvider` (either via
  `ClientConfig.Builder.setNetworkContextProvider(...)` or the convenience
  `enableAndroidNetworkContext(...)` helper) before Torii calls are issued.
- **Grafana pointer:** The `Android Telemetry Redaction` dashboard is the
  canonical visual check for the CLI output above—confirm the
  `android.telemetry.redaction.salt_version` panel matches the current salt epoch
  and the `android_telemetry_override_tokens_active` widget stays at zero
  whenever no drills or incidents are running. Escalate if either panel drifts
  before the CLI scripts report a regression.

### 2.1 Export pipeline workflow

1. **Config distribution.** `ClientConfig.telemetry.redaction` is threaded from
   `iroha_config` and hot-reloaded by `ConfigWatcher`. Each reload logs the
   manifest digest plus salt epoch—capture that line in incidents and during
   rehearsals.
2. **Instrumentation.** SDK components emit spans/metrics/events into the
   `TelemetryBuffer`. The buffer tags every payload with the device profile and
   current salt epoch so the exporter can verify hashing inputs deterministically.
3. **Redaction filter.** `RedactionFilter` hashes `authority`, `alias`, and
   device identifiers before they leave the device. Failures emit
   `android.telemetry.redaction.failure` and block the export attempt.
4. **Exporter + collector.** Sanitised payloads are shipped through the Android
   OpenTelemetry exporter to the `android-otel-collector` deployment. The
   collector fans outputs to traces (Tempo), metrics (Prometheus), and Norito
   log sinks.
5. **Observability hooks.** `scripts/telemetry/check_redaction_status.py` reads
   collector counters (`android.telemetry.export.status`,
   `android.telemetry.redaction.salt_version`) and produces the status bundle
   referenced throughout this runbook.

### 2.2 Validation gates

- **Schema diff:** Run
  `scripts/telemetry/run_schema_diff.sh --android-config configs/android_telemetry.json --rust-config configs/rust_telemetry.json`
  whenever manifests change. After each run, confirm every
  `intentional_differences[*]` and `android_only_signals[*]` entry is stamped
  `status:"accepted"` (or `status:"policy_allowlisted"` for hashed/bucketed
  fields) as recommended in `telemetry_schema_diff.md` §3 before attaching the
  artefact to incidents and chaos lab reports. Use the approved snapshot
  (`android_vs_rust-20260305.json`) as a guardrail and lint the freshly emitted
  JSON before it is filed:
  ```bash
  LATEST=specs/sdk/android/readiness/schema_diffs/$(date -u +%Y%m%d).json
  jq '.intentional_differences[] | select(.status != "accepted" and .status != "policy_allowlisted") | {signal, field, status}' "$LATEST"
  jq '.android_only_signals[] | select(.status != "accepted") | {signal, status}' "$LATEST"
  ```
  Compare `$LATEST` against
  `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json`
  to prove that the allowlist stayed unchanged. Missing or blank `status`
  entries (for example on `android.telemetry.redaction.failure` or
  `android.telemetry.redaction.salt_version`) are now treated as regressions and
  must be resolved before the review can close; the CLI surfaces the accepted
  state directly, so the manual §3.4 cross-reference only applies when
  explaining why a non-`accepted` status appears.

  **Canonical AND7 signals (2026-03-05 snapshot)**

  | Signal | Channel | Status | Governance note | Validation hook |
  |--------|---------|--------|-----------------|-----------------|
  | `android.telemetry.redaction.override` | Event | `accepted` | Mirrors override manifests and must match `telemetry_override_log.md` entries. | Watch `android_telemetry_override_tokens_active` and archive manifests per §3. |
  | `android.telemetry.network_context` | Event | `accepted` | Android intentionally redacts carrier names; only `network_type` and `roaming` are exported. | Ensure apps register a `NetworkContextProvider` and confirm the event volume follows Torii traffic on `Android Telemetry Overview`. |
  | `android.telemetry.redaction.failure` | Counter | `accepted` | Emits whenever hashing fails; governance now requires explicit status metadata in the schema diff artefact. | The `Redaction Compliance` dashboard panel and CLI output from `check_redaction_status.py` must stay at zero except during drills. |
  | `android.telemetry.redaction.salt_version` | Gauge | `accepted` | Proves the exporter is using the current quarterly salt epoch. | Compare Grafana’s salt widget with the secrets-vault epoch and ensure schema diff runs retain the `status:"accepted"` annotation. |

  If any entry in the table above drops a `status`, the diff artefact must be
  regenerated **and** `telemetry_schema_diff.md` updated before the AND7
  governance packet is circulated. Include the refreshed JSON in
  `specs/sdk/android/readiness/schema_diffs/` and link it from the
  incident, chaos lab, or enablement report that triggered the rerun.
- **CI/unit coverage:** `ci/run_android_tests.sh` must pass before
  publishing builds; the suite enforces hashing/override behaviour by exercising
  the telemetry exporters with sample payloads.
- **Injector sanity checks:** Use
  `scripts/telemetry/inject_redaction_failure.sh --dry-run` ahead of rehearsals
  to confirm failure injection works and that alerts fire when hashing guards
  are tripped. Always clear the injector with `--clear` once validation
  completes.

### 2.3 Mobile ↔ Rust telemetry parity checklist

Keep the Android exporters and Rust node services aligned while respecting the
different redaction requirements documented in
`specs/sdk/android/telemetry_redaction.md`. The table below serves as the
dual allowlist referenced in the AND7 roadmap entry—update it whenever the
schema diff introduces or removes fields.

| Category | Android exporters | Rust services | Validation hook |
|----------|-------------------|---------------|-----------------|
| Authority / route context | Hash `authority`/`alias` via Blake2b-256 and drop raw Torii hostnames before export; emit `android.telemetry.redaction.salt_version` to prove salt rotation. | Emit full Torii hostnames and peer IDs for correlation. | Compare `android.torii.http.request` vs `torii.http.request` entries in the latest schema diff under `readiness/schema_diffs/`, then confirm `android.telemetry.redaction.salt_version` matches the cluster salt by running `scripts/telemetry/check_redaction_status.py`. |
| Device & signer identity | Bucket `hardware_tier`/`device_profile`, hash controller aliases, and never export serial numbers. | No device metadata; nodes emit validator `peer_id` and controller `public_key` verbatim. | Mirror the mappings in `specs/sdk/mobile_device_profile_alignment.md`, audit `PendingQueueInspector` outputs during labs, and ensure the alias hashing tests inside `ci/run_android_tests.sh` remain green. |
| Network metadata | Export only `network_type` + `roaming` booleans; `carrier_name` is dropped. | Rust retains peer hostnames plus full TLS endpoint metadata. | Store the latest diff JSON in `readiness/schema_diffs/` and confirm that the Android side still omits `carrier_name`. Alert if Grafana’s “Network Context” widget shows any carrier strings. |
| Override / chaos evidence | Emit `android.telemetry.redaction.override` and `android.telemetry.chaos.scenario` events with masked actor roles. | Rust services emit override approvals without role masking and no chaos-specific spans. | Cross-check `specs/sdk/android/readiness/and7_operator_enablement.md` after every drill to ensure override tokens and chaos artefacts are archived alongside the unmasked Rust events. |

Parity workflow:

1. After each manifest or exporter change, run
   `scripts/telemetry/run_schema_diff.sh --android-config configs/android_telemetry.json --rust-config configs/rust_telemetry.json --out specs/sdk/android/readiness/schema_diffs/$(date -u +%Y%m%d).json --textfile-dir /var/lib/node_exporter/textfile_collector`
   so the JSON artefact and the mirrored metrics both land in the evidence bundle
   (the helper still writes `artifacts/android/telemetry/schema_diff.prom` by default).
2. Review the diff against the table above; if Android now emits a field that is
   only allowed on Rust (or vice versa), file an AND7 readiness bug and update
   the redaction plan.
3. During weekly checks, run
   `scripts/telemetry/check_redaction_status.py --status-url https://android-telemetry-stg/api/redaction/status`
   to confirm salt epochs match the Grafana widget and note the epoch in the
   on-call journal.
4. Record any deltas in
   `specs/sdk/android/readiness/signal_inventory_worksheet.md` so
   governance can audit parity decisions.

### 2.4 Observability dashboards & alert thresholds

Keep dashboards and alerts aligned with the AND7 schema diff approvals when
reviewing `scripts/telemetry/check_redaction_status.py` output:

- `Android Telemetry Redaction` — Salt epoch widget, override token gauge.
- `Redaction Compliance` — `android.telemetry.redaction.failure` counter and
  injector trend panels.
- `Exporter Health` — `android.telemetry.export.status` rate breakdowns.
- `Android Telemetry Overview` — device profile buckets and network context volume.

The following thresholds mirror the quick-reference card and must be enforced
during incident response and rehearsals:

| Metric / panel | Threshold | Action |
|----------------|-----------|--------|
| `android.telemetry.redaction.failure` (`Redaction Compliance` board) | >0 over a rolling 15 min window | Investigate failing signal, run injector clear, log CLI output + Grafana screenshot. |
| `android.telemetry.redaction.salt_version` (`Android Telemetry Redaction` board) | Differs from secrets-vault salt epoch | Halt releases, coordinate with secrets rotation, file AND7 note. |
| `android.telemetry.export.status{status="error"}` (`Exporter Health` board) | >1 % of exports | Inspect collector health, capture CLI diagnostics, escalate to SRE. |
| `android.telemetry.device_profile{tier="enterprise"}` vs Rust parity (`Android Telemetry Overview`) | Variance >10 % from Rust baseline | File governance follow-up, verify fixture pools, annotate schema diff artefact. |
| `android.telemetry.network_context` volume (`Android Telemetry Overview`) | Drops to zero while Torii traffic exists | Confirm `NetworkContextProvider` registration, rerun schema diff to ensure fields unchanged. |
| `android.telemetry.redaction.override` / `android_telemetry_override_tokens_active` (`Android Telemetry Redaction`) | Non-zero outside approved override/drill window | Tie token to an incident, regenerate digest, revoke via workflow in §3. |

### 2.5 Operator readiness & enablement trail

Roadmap item AND7 calls out a dedicated operator curriculum so support, SRE, and
release stakeholders understand the parity tables above before the runbook goes
GA. Use the outline in
`specs/sdk/android/telemetry_readiness_outline.md` for canonical logistics
(agenda, presenters, timeline) and `specs/sdk/android/readiness/and7_operator_enablement.md`
for the detailed checklist, evidence links, and action log. Keep the following
phases in sync whenever the telemetry plan changes:

| Phase | Description | Evidence bundle | Primary owner |
|-------|-------------|-----------------|---------------|
| Pre-read distribution | Send the policy pre-read, `telemetry_redaction.md`, and the quick-reference card at least five business days before the briefing. Track acknowledgements in the outline’s comms log. | `specs/sdk/android/telemetry_readiness_outline.md` (Session Logistics + Communications Log) and the archived email in `specs/sdk/android/readiness/archive/<YYYY-MM>/`. | Docs/Support manager |
| Live readiness session | Deliver the 60-minute training (policy deep dive, runbook walkthrough, dashboards, chaos lab demo) and keep the recording running for asynchronous viewers. | Recording + slides stored under `specs/sdk/android/readiness/archive/<YYYY-MM>/` with references captured in §2 of the outline. | LLM (acting AND7 owner) |
| Chaos lab execution | Run at least C2 (override) + C6 (queue replay) from `specs/sdk/android/readiness/labs/telemetry_lab_01.md` immediately after the live session and attach logs/screenshots to the enablement kit. | Scenario reports and screenshots inside `specs/sdk/android/readiness/labs/reports/<YYYY-MM>/` and `/screenshots/<YYYY-MM>/`. | Android Observability TL + SRE on-call |
| Knowledge check & attendance | Collect quiz submissions, remediate anyone scoring <90 %, and record attendance/quiz statistics. Keep the quick-reference questions aligned with the parity checklist. | Quiz exports in `specs/sdk/android/readiness/forms/responses/`, summary Markdown/JSON produced via `scripts/telemetry/generate_and7_quiz_summary.py`, and the attendance table inside `and7_operator_enablement.md`. | Support engineering |
| Archive & follow-ups | Update the enablement kit’s action log, upload artefacts to the archive, and note the completion in `status.md`. Any remediation or override tokens issued during the session must be copied into `telemetry_override_log.md`. | `specs/sdk/android/readiness/and7_operator_enablement.md` §6 (action log), `.../archive/<YYYY-MM>/checklist.md`, and the override log referenced in §3. | LLM (acting AND7 owner) |

When the curriculum is rerun (quarterly or before major schema changes), refresh
the outline with the new session date, keep the attendee roster current, and
regenerate the quiz summary JSON/Markdown artefacts so governance packets can
reference consistent evidence. The `status.md` entry for AND7 should link to the
latest archive folder once each enablement sprint closes.

### 2.6 Schema diff allowlists & policy checks

The roadmap explicitly calls out a dual-allowlist policy (mobile redactions vs
Rust retention) that is enforced by the `telemetry-schema-diff` CLI housed under
`tools/telemetry-schema-diff`. Every diff artefact recorded in
`specs/sdk/android/readiness/schema_diffs/` must document which fields are
hashed/bucketed on Android, which fields remain unhashed on Rust, and whether
any non-allowlisted signal slipped into the build. Capture those decisions
directly in the JSON by running:

```bash
cargo run -p telemetry-schema-diff --features dev-tools -- \
  --android-config configs/android_telemetry.json \
  --rust-config configs/rust_telemetry.json \
  --format json \
  > "$LATEST"

if jq -e '.policy_violations | length > 0' "$LATEST" >/dev/null; then
  jq '.policy_violations[]' "$LATEST"
  exit 1
fi
```

The final `jq` evaluates to a no-op when the report is clean. Treat any output
from that command as a Sev 2 readiness bug: a populated `policy_violations`
array means the CLI discovered a signal that is neither on the Android-only list
nor on the Rust-only exemption list documented in
`specs/sdk/android/telemetry_schema_diff.md`. When this occurs, halt
exports, file an AND7 ticket, and rerun the diff only after the policy module
and manifest snapshots have been corrected. Store the resulting JSON in
`specs/sdk/android/readiness/schema_diffs/` with the date suffix and note
the path inside the incident or lab report so governance can replay the checks.

**Hashing & retention matrix**

| Signal.field | Android handling | Rust handling | Allowlist tag |
|--------------|-----------------|---------------|---------------|
| `torii.http.request.authority` | Blake2b-256 hashed (`representation: "blake2b_256"`) | Stored verbatim for traceability | `policy_allowlisted` (mobile hash) |
| `attestation.result.alias` | Blake2b-256 hashed | Plain text alias (attestation archives) | `policy_allowlisted` |
| `attestation.result.device_tier` | Bucketed (`representation: "bucketed"`) | Plain tier string | `policy_allowlisted` |
| `hardware.profile.hardware_tier` | Absent — Android exporters drop the field entirely | Present without redaction | `rust_only` (documented in §3 of `telemetry_schema_diff.md`) |
| `android.telemetry.redaction.override.*` | Android-only signal with masked actor roles | No equivalent signal emitted | `android_only` (must stay `status:"accepted"`) |

When new signals appear, add them to the schema diff policy module **and** the
table above so the runbook mirrors the enforcement logic shipped in the CLI.
Schema runs now fail if any Android-only signal omits an explicit `status` or if
the `policy_violations` array is non-empty, so keep this checklist in sync with
`telemetry_schema_diff.md` §3 and the latest JSON snapshots referenced in
`telemetry_redaction_minutes_*.md`.

## 3. Override Workflow

Overrides are the “break glass” option when hashing regressions or privacy
alerts block customers. Apply them only after recording the full decision trail
in the incident doc.

1. **Confirm drift and scope.** Wait for the PagerDuty alert or the schema diff
   gate to fire, then run
   `scripts/telemetry/check_redaction_status.py --status-url <collector>` to
   prove mismatched authorities. Attach the CLI output and Grafana screenshots
   to the incident record.
2. **Prepare a signed request.** Populate
   `fixtures/documentation/android_override_request.json` with the ticket id, requester,
   expiry, and justification. Store the file next to the incident artefacts so
   compliance can audit the inputs.
3. **Issue the override.** Invoke
   ```bash
   scripts/android_override_tool.sh apply \
     --request fixtures/documentation/android_override_request.json \
     --log specs/sdk/android/telemetry_override_log.md \
     --out artifacts/android/telemetry/override-$(date -u +%Y%m%dT%H%M%SZ).json \
     --event-log specs/sdk/android/readiness/override_logs/override_events.ndjson \
     --actor-role <support|sre|docs|compliance|program|other>
   ```
   The helper prints the override token, writes the manifest, and appends a row
   to the Markdown audit log. Never post the token in chat; deliver it directly
   to the Torii operators applying the override.
4. **Monitor the effect.** Within five minutes verify a single
   `android.telemetry.redaction.override` event was emitted, the collector
   status endpoint shows `override_active=true`, and the incident doc lists the
   expiry. Watch the Android Telemetry Overview dashboard’s “Override tokens
   active” panel (`android_telemetry_override_tokens_active`) for the same
   token count and continue running the status CLI every 10 minutes until
   hashing stabilises.
5. **Revoke and archive.** As soon as the mitigation lands, run
  `scripts/android_override_tool.sh revoke --token <token>` so the audit log
  captures the revocation time, then execute
  `scripts/android_override_tool.sh digest --out specs/sdk/android/readiness/override_logs/override_digest_$(date -u +%Y%m%dT%H%M%SZ).json`
  to refresh the sanitised snapshot that governance expects. Attach the
  manifest, digest JSON, CLI transcripts, Grafana snapshots, and the NDJSON log
  produced via `--event-log` to
  `specs/sdk/android/readiness/screenshots/<date>/` and cross-link the
  entry from `specs/sdk/android/telemetry_override_log.md`.

Overrides exceeding 24 hours require SRE Director and Compliance approval and
must be highlighted in the next weekly AND7 review.

### 3.1 Override escalation matrix

| Situation | Max duration | Approvers | Required notifications |
|-----------|--------------|-----------|------------------------|
| Single-tenant investigation (hashed authority mismatch, customer Sev 2) | 4 hours | Support engineer + SRE on-call | Ticket `SUP-OVR-<id>`, `android.telemetry.redaction.override` event, incident log |
| Fleet-wide telemetry outage or SRE-requested reproduction | 24 hours | SRE on-call + Program Lead | PagerDuty note, override log entry, update in `status.md` |
| Compliance/forensics request or any case exceeding 24 hours | Until explicitly revoked | SRE Director + Compliance lead | Governance mailing list, override log, AND7 weekly status |

#### Role responsibilities

| Role | Responsibilities | SLA / Notes |
|------|------------------|-------------|
| Android telemetry on-call (Incident Commander) | Drive detection, execute the override tooling, record approvals in the incident doc, and ensure revocation happens before expiry. | Acknowledge PagerDuty within 5 minutes and log progress every 15 minutes. |
| Android Observability TL (Haruka Yamamoto) | Validate the drift signal, confirm exporter/collector state, and sign off on the override manifest before it is handed to operators. | Join the bridge within 10 minutes; delegate to the staging cluster owner if unavailable. |
| SRE liaison (Liam O’Connor) | Apply the manifest to collectors, monitor backlog, and coordinate with Release Engineering for Torii-side mitigations. | Log every `kubectl` action in the change request and paste command transcripts in the incident doc. |
| Compliance (Sofia Martins / Daniel Park) | Approve overrides longer than 30 minutes, verify the audit log row, and advise on regulator/customer messaging. | Post acknowledgement in `#compliance-alerts`; for production events file a compliance note before the override is issued. |
| Docs/Support Manager (Priya Deshpande) | Archive manifests/CLI output under `specs/sdk/android/readiness/…`, keep the override log tidy, and schedule follow-up labs if gaps surface. | Confirms evidence retention (13 months) and files AND7 follow-ups before closing the incident. |

Escalate immediately if any override token approaches its expiry without a
documented revocation plan.

## 4. Incident Response

- **Alerts:** PagerDuty service `android-telemetry-primary` covers redaction
  failures, exporter outages, and bucket drift. Acknowledge within SLA windows
  (see support playbook).
- **Diagnostics:** Run `scripts/telemetry/check_redaction_status.py` to gather
  current exporter health, recent alerts, and hashed authority metrics. Include
  output in the incident timeline (`incident/YYYY-MM-DD-android-telemetry.md`).
- **Dashboards:** Monitor the Android Telemetry Redaction, Android Telemetry
  Overview, Redaction Compliance, and Exporter Health dashboards. Capture
  screenshots for incident records and annotate any salt-version or override
  token deviations before closing an incident.
- **Coordination:** Engage Release Engineering for exporter issues, Compliance
  for override/PII questions, and Program Lead for Sev 1 incidents.

### 4.1 Escalation flow

Android incidents are triaged using the same severity levels as the Android
Support Playbook (§2.1). The table below summarises who must be paged and how
quickly each responder is expected to join the bridge.

| Severity | Impact | Primary responder (≤5 min) | Secondary escalation (≤10 min) | Additional notifications | Notes |
|----------|--------|----------------------------|--------------------------------|--------------------------|-------|
| Sev 1 | Customer-facing outage, privacy breach, or data leak | Android telemetry on-call (`android-telemetry-primary`) | Torii on-call + Program Lead | Compliance + SRE Governance (`#sre-governance`), staging cluster owners (`#android-staging`) | Start war room immediately and open a shared doc for command logging. |
| Sev 2 | Fleet degradation, override misuse, or prolonged replay backlog | Android telemetry on-call | Android Foundations TL + Docs/Support Manager | Program Lead, Release Engineering liaison | Escalate to Compliance if overrides exceed 24 hours. |
| Sev 3 | Single-tenant issue, lab rehearsal, or advisory alert | Support engineer | Android on-call (optional) | Docs/Support for awareness | Convert to Sev 2 if scope expands or multiple tenants are affected. |

| Window | Action | Owner(s) | Evidence/Notes |
|--------|--------|----------|----------------|
| 0–5 min | Acknowledge PagerDuty, assign an incident commander (IC), and create `incident/YYYY-MM-DD-android-telemetry.md`. Drop the link plus one-line status in `#android-sdk-support`. | On-call SRE / Support engineer | Screenshot of PagerDuty ack + incident stub committed beside other incident logs. |
| 5–15 min | Run `scripts/telemetry/check_redaction_status.py --status-url https://android-telemetry-stg/api/redaction/status` and paste the summary in the incident doc. Ping Android Observability TL (Haruka Yamamoto) and Support lead (Priya Deshpande) for real-time hand-off. | IC + Android Observability TL | Attach CLI output JSON, note dashboard URLs opened, and mark who owns diagnostics. |
| 15–25 min | Engage staging cluster owners (Haruka Yamamoto for observability, Liam O’Connor for SRE) to reproduce on `android-telemetry-stg`. Seed load with `scripts/telemetry/generate_android_load.sh --cluster android-telemetry-stg` and capture queue dumps from the Pixel + emulator to confirm symptom parity. | Staging cluster owners | Upload sanitized `pending.queue` + `PendingQueueInspector` output to the incident folder. |
| 25–40 min | Decide on overrides, Torii throttling, or StrongBox fallback. If PII exposure or non-deterministic hashing is suspected, page Compliance (Sofia Martins, Daniel Park) via `#compliance-alerts` and notify the Program Lead in the same incident thread. | IC + Compliance + Program Lead | Link override tokens, Norito manifests, and approval comments. |
| ≥40 min | Provide 30-minute status updates (PagerDuty notes + `#android-sdk-support`). Schedule war-room bridge if not already active, document mitigation ETA, and ensure Release Engineering (Alexei Morozov) is on standby to roll collector/SDK artifacts. | IC | Time-stamped updates plus decision logs stored in the incident file and summarized in `status.md` during the next weekly refresh. |

- All escalations must stay mirrored in the incident doc using the “Owner / Next update time” table from the Android Support Playbook.
- If another incident is already open, join the existing war room and append Android context rather than spinning up a new one.
- When the incident touches runbook gaps, create follow-up tasks in the AND7 JIRA epic and tag `telemetry-runbook`.

## 5. Chaos & Readiness Exercises

- Execute the scenarios detailed in
  `specs/sdk/android/telemetry_chaos_checklist.md` quarterly and prior to
  major releases. Log outcomes with the lab report template.
- Store evidence (screenshots, logs) under
  `specs/sdk/android/readiness/screenshots/`.
- Track remediation tickets in the AND7 epic with label `telemetry-lab`.
- Scenario map: C1 (redaction fault), C2 (override), C3 (exporter brownout), C4
  (schema diff gate using `run_schema_diff.sh` with a drifted config), C5
  (device-profile skew seeded via `generate_android_load.sh`), C6 (Torii timeout
  + queue replay), C7 (attestation rejection). Keep this numbering aligned with
  `telemetry_lab_01.md` and the chaos checklist when adding drills.

### 5.1 Redaction drift & override drill (C1/C2)

1. Inject a hashing failure via
   `scripts/telemetry/inject_redaction_failure.sh` and wait for the PagerDuty
   alert (`android.telemetry.redaction.failure`). Capture the CLI output from
   `scripts/telemetry/check_redaction_status.py --status-url <collector>` for
   the incident record.
2. Clear the failure with `--clear` and confirm the alert resolves within
   10 minutes; attach Grafana screenshots of the salt/authority panels.
3. Create a signed override request using
   `fixtures/documentation/android_override_request.json`, apply it with
   `scripts/android_override_tool.sh apply`, and verify the unhashed sample by
   inspecting the exporter payload in staging (look for
   `android.telemetry.redaction.override`).
4. Revoke the override with `scripts/android_override_tool.sh revoke --token <token>`,
   append the override token hash plus ticket reference to
   `specs/sdk/android/telemetry_override_log.md`, and mint a digest JSON
   under `specs/sdk/android/readiness/override_logs/`. This closes the
   C2 scenario in the chaos checklist and keeps the governance evidence fresh.

### 5.2 Exporter brownout & queue replay drill (C3/C6)

1. Scale the staging collector down (`kubectl scale
   deploy/android-otel-collector --replicas=0`) to simulate an exporter
   brownout. Track buffer metrics via the status CLI and confirm alerts fire at
   the 15-minute mark.
2. Restore the collector, confirm backlog drain, and archive the collector log
   snippet showing replay completion.
3. On both the staging Pixel and emulator, follow Scenario C6: install
   `examples/android/operator-console`, toggle airplane mode, submit the demo
   transfers, then disable airplane mode and watch queue depth metrics.
4. Pull each pending queue (`adb shell run-as <app-id> cat files/pending.queue >
   /tmp/<serial>.queue`), compile the inspector (`gradle -p java/iroha_android
   :core:classes >/dev/null`), and run `java -cp build/classes
   org.hyperledger.iroha.android.tools.PendingQueueInspector --file
   /tmp/<serial>.queue --json > queue-replay-<serial>.json`. Attach decoded
   envelopes plus replay hashes to the lab log.
5. Update the chaos report with exporter outage duration, queue depth before/after,
   and confirmation that `android_sdk_offline_replay_errors` remained 0.

### 5.3 Staging cluster chaos script (android-telemetry-stg)

Staging cluster owners Haruka Yamamoto (Android Observability TL) and Liam O’Connor
(SRE) follow this script whenever a rehearsal run is scheduled. The sequence keeps
participants aligned with the telemetry chaos checklist while guaranteeing that
artefacts are captured for governance.

**Participants**

| Role | Responsibilities | Contact |
|------|------------------|---------|
| Android on-call IC | Drives the drill, coordinates PagerDuty notes, owns command log | PagerDuty `android-telemetry-primary`, `#android-sdk-support` |
| Staging cluster owners (Haruka, Liam) | Gate change windows, run `kubectl` actions, snapshot cluster telemetry | `#android-staging` |
| Docs/Support manager (Priya) | Record evidence, track labs checklist, publish follow-up tickets | `#docs-support` |

**Pre-flight coordination**

- 48 hours before the drill, file a change request that lists the planned
  scenarios (C1–C7) and paste the link in `#android-staging` so cluster owners
  can block clashing deployments.
- Collect the latest `ClientConfig` hash and `kubectl --context staging get pods
  -n android-telemetry-stg` output to establish the baseline state, then store
  both under `specs/sdk/android/readiness/labs/reports/<date>/`.
- Confirm device coverage (Pixel + emulator) and ensure
  `ci/run_android_tests.sh` compiled the tools used during the lab
  (`PendingQueueInspector`, telemetry injectors).

**Execution checkpoints**

- Announce “chaos start” in `#android-sdk-support`, begin the bridge recording,
  and keep `specs/sdk/android/telemetry_chaos_checklist.md` visible so
  every command is narrated for the scribe.
- Have a staging owner mirror each injector action (`kubectl scale`, exporter
  restarts, load generators) so both Observability and SRE confirm the step.
- Capture the output from `scripts/telemetry/check_redaction_status.py
  --status-url https://android-telemetry-stg/api/redaction/status` after each
  scenario and paste it into the incident doc.

**Recovery**

- Do not leave the bridge until all injectors are cleared (`inject_redaction_failure.sh --clear`,
  `kubectl scale ... --replicas=1`) and Grafana dashboards show green status.
- Docs/Support archives queue dumps, CLI logs, and screenshots under
  `specs/sdk/android/readiness/screenshots/<date>/` and ticks the archive
  checklist before the change request closes.
- Log follow-up tickets with the `telemetry-chaos` label for any scenario that
  failed or produced unexpected metrics, and reference them in `status.md`
  during the next weekly review.

| Time | Action | Owner(s) | Artefact |
|------|--------|----------|----------|
| T−30 min | Verify `android-telemetry-stg` health: `kubectl --context staging get pods -n android-telemetry-stg`, confirm no pending upgrades, and note collector versions. | Haruka | `specs/sdk/android/readiness/screenshots/<date>/cluster-health.png` |
| T−20 min | Seed baseline load (`scripts/telemetry/generate_android_load.sh --cluster android-telemetry-stg --duration 20m`) and capture stdout. | Liam | `readiness/labs/reports/<date>/load-generator.log` |
| T−15 min | Copy `specs/sdk/android/readiness/incident/telemetry_chaos_template.md` to `specs/sdk/android/readiness/incident/<date>-telemetry-chaos.md`, list scenarios to run (C1–C7), and assign scribes. | Priya Deshpande (Support) | Incident markdown committed before rehearsal starts. |
| T−10 min | Confirm Pixel + emulator online, latest SDK installed, and `ci/run_android_tests.sh` compiled the `PendingQueueInspector`. | Haruka, Liam | `readiness/screenshots/<date>/device-checklist.png` |
| T−5 min | Start Zoom bridge, begin screen recording, and announce “chaos start” in `#android-sdk-support`. | IC / Docs/Support | Recording saved under `readiness/archive/<month>/`. |
| +0 min | Execute the selected scenario from `specs/sdk/android/readiness/labs/telemetry_lab_01.md` (typically C2 + C6). Keep the lab guide visible and call out command invocations as they happen. | Haruka drives, Liam mirrors results | Logs attached to the incident file in real time. |
| +15 min | Pause to collect metrics (`scripts/telemetry/check_redaction_status.py --status-url https://android-telemetry-stg/api/redaction/status`) and grab Grafana screenshots. | Haruka | `readiness/screenshots/<date>/status-<scenario>.png` |
| +25 min | Restore any injected failures (`inject_redaction_failure.sh --clear`, `kubectl scale ... --replicas=1`), replay queues, and confirm alerts close. | Liam | `readiness/labs/reports/<date>/recovery.log` |
| +35 min | Debrief: update incident doc with pass/fail per scenario, list follow-ups, and push artefacts to git. Notify Docs/Support that the archive checklist can be completed. | IC | Incident doc updated, `readiness/archive/<month>/checklist.md` ticked. |

- Keep the staging owners on the bridge until exporters are healthy and all alerts have cleared.
- Store raw queue dumps in `specs/sdk/android/readiness/labs/reports/<date>/queues/` and reference their hashes in the incident log.
- If a scenario fails, immediately create a JIRA ticket labelled `telemetry-chaos` and cross-link it from `status.md`.
- Automation helper: `ci/run_android_telemetry_chaos_prep.sh` wraps the load generator, status snapshots, and queue export plumbing. Set `ANDROID_TELEMETRY_DRY_RUN=false` when staging access is available and `ANDROID_PENDING_QUEUE_EXPORTS=pixel8=/tmp/pixel.queue,emulator=/tmp/emulator.queue` (etc.) so the script copies each queue file, emits `<label>.sha256`, and runs `PendingQueueInspector` to produce `<label>.json`. Use `ANDROID_PENDING_QUEUE_INSPECTOR=false` only when JSON emission must be skipped (e.g., no JDK available). **Always export the expected salt identifiers before running the helper** by setting `ANDROID_TELEMETRY_EXPECTED_SALT_EPOCH=<YYYYQ#>` and `ANDROID_TELEMETRY_EXPECTED_SALT_ROTATION=<id>` so the embedded `check_redaction_status.py` calls fail fast if the captured telemetry diverges from the Rust baseline.

## 6. Documentation & Enablement

- **Operator enablement kit:** `specs/sdk/android/readiness/and7_operator_enablement.md`
  links the runbook, telemetry policy, lab guide, archive checklist, and knowledge
  checks into a single AND7-ready package. Reference it when preparing SRE
  governance pre-reads or scheduling the quarterly refresh.
- **Enablement sessions:** A 60-minute enablement recording runs on 2026-02-18
  with quarterly refreshes. Materials live under
  `specs/sdk/android/readiness/`.
- **Knowledge checks:** Staff must score ≥90% via the readiness form. Store
  results in `specs/sdk/android/readiness/forms/responses/`.
- **Updates:** Whenever telemetry schemas, dashboards, or override policies
  change, update this runbook, the support playbook, and `status.md` in the same
  PR.
- **Weekly review:** After each Rust release candidate (or at least weekly), verify
  `java/iroha_android/README.md` and this runbook still reflect current automation,
  fixture rotation procedures, and governance expectations. Capture the review in
  `status.md` so the Foundations milestone audit can trace documentation freshness.

## 7. StrongBox Attestation Harness

This is an optional hardware-integration qualification harness. It is strict
once selected, but physical hardware and attestation evidence are not required
for an ordinary software-backed build, deployment, governance flow, or release.

- **Purpose:** Validate hardware-backed attestation bundles before promoting devices into the
  StrongBox pool (AND2/AND6). The harness consumes captured certificate chains and verifies them
  against trusted roots using the same policy that production code executes.
- **Reference:** See `specs/sdk/android/strongbox_attestation_harness_plan.md` for the full
  capture API, alias lifecycle, CI/Buildkite wiring, and ownership matrix. Treat that plan as the
  source of truth when onboarding new lab technicians or updating finance/compliance artefacts.
- **Workflow:**
  1. Issue a challenge from the lab authority, provision a new unique alias with
     that challenge, and collect `chain.pem` in leaf→root order. Record the alias,
     challenge, and leaf-SPKI SHA-256 in a separately authenticated expectations tree.
  2. Capture the governed status with `scripts/capture_android_attestation_status.py`, passing each
     reviewed supplemental TBS digest through its repeatable `--revoked-tbs-sha256` option. Run
     `scripts/android_keystore_attestation.sh --bundle-dir <bundle> --trust-root <root.pem>
     --alias <trusted-alias> --challenge-file <trusted-challenge-file>
     --expected-leaf-spki-sha256 <trusted-leaf-spki-digest>
     --revocation-snapshot <capture>/android-sdk-revocation-snapshot-v1.txt
     --revocation-snapshot-sha256 <separately-trusted-governance-commitment>
     --evaluation-time-ms <ms> --require-strongbox --output <report.json>` using the appropriate
     Google/Samsung root. Obtain every expectation and the commitment from the
     authenticated governance record, never from the submitted bundle.
  3. Archive the JSON summary alongside raw attestation material in
     `artifacts/android/attestation/<device-tag>/`.
- **Bundle format:** Keep untrusted evidence (`chain.pem`, `result.json`, and
  optional notes) separate from the mirrored expectations tree (`alias.txt`,
  `challenge.hex`, and `leaf_spki_sha256.hex`).
- **Trusted roots:** Obtain vendor-supplied PEMs from the device lab secrets store; pass multiple
  `--trust-root` arguments or point `--trust-root-dir` to the directory that holds the anchors when
  the chain terminates in a non-Google anchor.
- **CI harness:** Use `scripts/android_strongbox_attestation_ci.sh --bundles-root
  <evidence> --expectations-root <trusted-expectations> --trust-root <root>` to
  batch-verify archived bundles. Missing or empty evidence roots fail closed.
- **CI lane:** After syncing new bundles, run the Buildkite step defined in
  `.buildkite/android-strongbox-attestation.yml` (`buildkite-agent pipeline upload --pipeline .buildkite/android-strongbox-attestation.yml`).
  The job executes `scripts/android_strongbox_attestation_ci.sh`, generates a summary with
  `scripts/android_strongbox_attestation_report.py`, uploads the report to `artifacts/android_strongbox_attestation_report.txt`,
  and annotates the build as `android-strongbox/report`. Investigate any failures immediately and
  link the build URL from the device-lab reservation ticket.
- **Reporting:** Attach the JSON output to governance reviews and record the attestation date in
  the device-lab reservation ticket (`specs/compliance/android/device_lab_reservation.md`).
- **Mock rehearsal:** When hardware is unavailable, run
  `scripts/android_generate_mock_attestation_bundles.sh` to mint test bundles,
  a separate expectations tree, and use the mock root from the separate
  attestation-authority directory.
- **In-code guardrails:** `ci/run_android_tests.sh --tests
  org.hyperledger.iroha.android.crypto.keystore.KeystoreKeyProviderTests` covers
  cached inspection, uncached recorded-chain verification, backend failures,
  alias binding, and explicit challenged re-attestation rejection.

## 8. Contacts

- **Support Engineering On-call:** `#android-sdk-support`
- **SRE Governance:** `#sre-governance`
- **Docs/Support:** `#docs-support`
- **Escalation Tree:** See Android Support Playbook §2.1

## 9. Troubleshooting Scenarios

Roadmap item AND7-P2 calls out three incident classes that repeatedly page the
Android on-call: Torii/network timeouts, StrongBox attestation failures, and
`iroha_config` manifest drift. Work through the relevant checklist before filing
Sev 1/2 follow-ups and archive the evidence in `incident/<date>-android-*.md`.

### 9.1 Torii & Network Timeouts

**Signals**

- Alerts on `android_sdk_submission_latency`, `android_sdk_pending_queue_depth`,
  `android_sdk_offline_replay_errors`, and the Torii `/v1/pipeline` error rate.
- `operator-console` widgets (examples/android) showing stalled queue drain or
  retries stuck in exponential backoff.

**Immediate response**

1. Acknowledge PagerDuty (`android-networking`) and start an incident log.
2. Capture Grafana snapshots (Submission Latency + Queue Depth) covering the
   last 30 minutes.
3. Record the active `ClientConfig` hash from the device logs (`ConfigWatcher`
   prints the manifest digest whenever a reload succeeds or fails).

**Diagnostics**

- **Queue health:** Pull the configured queue file from a staging device or the
  emulator (`adb shell run-as <app-id> cat files/pending.queue >
  /tmp/pending.queue`). Decode the envelopes with
  `OfflineSigningEnvelopeCodec` as described in
  `specs/sdk/android/offline_signing.md#4-queueing--replay` to confirm the
  backlog matches operator expectations. Attach the decoded hashes to the
  incident.
- **Hash inventory:** After downloading the queue file, run the inspector helper
  to capture canonical hashes/aliases for the incident artefacts:

  ```bash
  gradle -p java/iroha_android :core:classes >/dev/null  # compiles classes if needed
  java -cp build/classes org.hyperledger.iroha.android.tools.PendingQueueInspector \
    --file /tmp/pending.queue --json > queue-inspector.json
  ```

  Attach `queue-inspector.json` and the pretty-printed stdout to the incident
  and link it from the AND7 lab report for Scenario D.
- **Torii connectivity:** Run the HTTP transport harness locally to rule out SDK
  regressions: `ci/run_android_tests.sh` exercises
  `HttpClientTransportTests`, `HttpClientTransportHarnessTests`, and
  `ToriiMockServerTests`. Failures here indicate a client bug rather than a
  Torii outage.
- **Fault injection rehearsal:** On the staging Pixel (StrongBox) and the AOSP
  emulator, toggle connectivity to reproduce pending-queue growth:
  `adb shell cmd connectivity airplane-mode enable` → submit two demo
  transactions via operator-console → `adb shell cmd connectivity airplane-mode
  disable` → verify the queue drains and `android_sdk_offline_replay_errors`
  remains 0. Record hashes of the replayed transactions.
- **Alert parity:** When tuning thresholds or after Torii changes, execute
  `scripts/telemetry/test_torii_norito_rpc_alerts.sh` so Prometheus rules stay
  aligned with the dashboards.

**Recovery**

1. If Torii is degraded, engage the Torii on-call and continue replaying the
   queue once `/v1/pipeline` accepts traffic.
2. Reconfigure affected clients only via signed `iroha_config` manifests. The
   `ClientConfig` hot-reload watcher must emit a success log before the incident
   can close.
3. Update the incident with the queue size before/after replay plus hashes of
   any dropped transactions.

### 9.2 StrongBox & Attestation Failures

This incident class applies only to applications that explicitly selected a
StrongBox/TEE policy or claimed hardware qualification. It does not turn
optional hardware availability into a blocker for software-backed signing or
the general SDK release path.

**Signals**

- Alerts on `android_sdk_strongbox_success_rate` or
  `android.keystore.attestation.failure`.
- `android.keystore.keygen` telemetry now records the requested
  `KeySecurityPreference` and the route used (`strongbox`, `hardware`,
  `software`) with a `fallback=true` flag when a StrongBox preference lands in
  TEE/software. STRONGBOX_REQUIRED requests now fail fast instead of silently
  returning TEE keys.
- Support tickets referencing `KeySecurityPreference.STRONGBOX_ONLY` devices
  falling back to software keys.

**Immediate response**

1. Acknowledge PagerDuty (`android-crypto`) and capture the affected alias label
   (salted hash) plus device profile bucket.
2. Check the device's last attestation result in its device-lab reservation
   ticket (`specs/compliance/android/device_lab_reservation.md`) and record the
   last verified date.

**Diagnostics**

- **Bundle verification:** Run the harness with `--bundle-dir <bundle>`, the
  vendor trust root, current governed snapshot digest/date/max-age and deny
  lists, plus an explicit in-window `--evaluation-time-ms`
  on the archived attestation to confirm whether the failure is due to device
  misconfiguration or a policy change. Attach the generated `result.json`.
- **Challenge rotation:** Android cannot re-attest an existing alias. Provision a
  new unique alias with `setAttestationChallenge`, verify its recorded chain,
  and only then rotate application signing to it. Verification rereads the
  recorded chain and fails without a non-empty expected challenge.
- **CI sweep:** Execute `scripts/android_strongbox_attestation_ci.sh` with the
  same governed snapshot and explicit evaluation-time arguments so every
  stored bundle is revalidated; this guards against systemic issues introduced
  by new trust anchors.
- **Device drill:** On hardware without StrongBox (or by forcing the emulator),
  set the SDK to require StrongBox only, submit a demo transaction, and confirm
  the telemetry exporter emits the `android.keystore.attestation.failure` event
  with the expected reason. Repeat on a StrongBox-capable Pixel to ensure the
  happy path stays green.
- **SDK regression check:** Run `ci/run_android_tests.sh` and pay
  attention to the attestation-focused suites (`AndroidKeystoreBackendDetectionTests`,
  `AttestationVerifierTests`, `IrohaKeyManagerDeterministicExportTests`,
  `KeystoreKeyProviderTests` for cache/challenge separation). Failures here
  indicate a client-side regression.

**Recovery**

1. Regenerate attestation bundles if the vendor rotated certificates or if the
   device recently received a major OTA.
2. Upload the refreshed bundle to `artifacts/android/attestation/<device>/` and
   update the matrix entry with the new date.
3. If StrongBox is unavailable in production, follow the override workflow in
   Section 3 and document the fallback duration; long-term mitigation requires
   device replacement or a vendor fix.

### 9.2a Deterministic Export Recovery

- **Formats:** Current exports are v3 (per-export salt/nonce + Argon2id, recorded as
- **Passphrase policy:** v3 enforces ≥12 character passphrases. If users supply shorter
  passphrases, instruct them to re-export with a compliant passphrase; v0/v1 imports are
  exempt but should be rewrapped as v3 immediately after import.
- **Tamper/reuse guards:** Decoders reject zero/short salt or nonce lengths and repeated
  salt/nonce pairs surface as `salt/nonce reuse` errors. Regenerate the export to clear
  the guard; do not attempt to force reuse.
  `SoftwareKeyProvider.importDeterministic(...)` to rehydrate the key, then
  `exportDeterministic(...)` to emit a v3 bundle so desktop tooling records the new KDF
  parameters.

### 9.3 Manifest & Config Mismatches

**Signals**

- `ClientConfig` reload failures, mismatched Torii hostnames, or telemetry
  schema diffs flagged by the AND7 diff tool.
- Operators reporting different retry/backoff knobs across devices in the same
  fleet.

**Immediate response**

1. Capture the `ClientConfig` digest printed in the Android logs and the
   expected digest from the release manifest.
2. Dump the running node configuration for comparison:
   `iroha_cli config show --actual > /tmp/iroha_config.actual.json`.

**Diagnostics**

- **Schema diff:** Run `scripts/telemetry/run_schema_diff.sh --android-config
  <android.json> --rust-config <rust.json> --textfile-dir /var/lib/node_exporter/textfile_collector`
  to generate a Norito diff report, refresh the Prometheus textfile, and attach the
  JSON artefact plus metrics evidence to the incident and AND7 telemetry readiness log.
- **Manifest validation:** Use `iroha_cli runtime capabilities` (or the runtime
  audit command) to retrieve the node’s advertised crypto/ABI hashes and ensure
  they match the mobile manifest. A mismatch confirms the node was rolled back
  without reissuing the Android manifest.
- **SDK regression check:** `ci/run_android_tests.sh` covers
  `ClientConfigNoritoRpcTests`, `ClientConfig.ValidationTests`, and
  `HttpClientTransportStatusTests`. Failures signal that the shipped SDK cannot
  parse the manifest format currently deployed.

**Recovery**

1. Regenerate the manifest via the authorized pipeline (usually
   `iroha_cli runtime Capabilities` → signed Norito manifest → config bundle) and
   redeploy it through the operator channel. Never edit `ClientConfig`
   overrides on-device.
2. Once a corrected manifest lands, watch for the `ConfigWatcher` “reload ok”
   message on each fleet tier and close the incident only after the telemetry
   schema diff reports parity.
3. Record the manifest hash, schema diff artefact path, and incident link in
   `status.md` under the Android section for auditability.

## 10. Operator enablement curriculum

Roadmap item **AND7** requires a repeatable training package so operators,
support engineers, and SRE can adopt the telemetry/redaction updates without
guesswork. Pair this section with
`specs/sdk/android/readiness/and7_operator_enablement.md`, which contains
the detailed checklist and artefact links.

### 10.1 Session modules (60-minute briefing)

1. **Telemetry architecture (15 min).** Walk through the exporter buffer,
   redaction filter, and schema diff tooling. Demo
   `scripts/telemetry/run_schema_diff.sh --textfile-dir /var/lib/node_exporter/textfile_collector` plus
   `scripts/telemetry/check_redaction_status.py` so attendees see how parity is
   enforced.
2. **Runbook + chaos labs (20 min).** Highlight Sections 2–9 of this runbook,
   rehearse one scenario from `readiness/labs/telemetry_lab_01.md`, and show how
   to archive artefacts under `readiness/labs/reports/<stamp>/`.
3. **Override + compliance workflow (10 min).** Review Section 3 overrides,
   demonstrate `scripts/android_override_tool.sh` (apply/revoke/digest), and
   update `specs/sdk/android/telemetry_override_log.md` plus the latest
   digest JSON.
4. **Q&A / knowledge check (15 min).** Use the quick-reference card in
   `readiness/cards/telemetry_redaction_qrc.md` to anchor questions, then
   capture follow-ups in `readiness/and7_operator_enablement.md`.

### 10.2 Asset cadence & owners

| Asset | Cadence | Owner(s) | Archive location |
|-------|---------|----------|------------------|
| Recorded walkthrough (Zoom/Teams) | Quarterly or before every salt rotation | Android Observability TL + Docs/Support manager | `specs/sdk/android/readiness/archive/<YYYY-MM>/` (recording + checklist) |
| Slide deck & quick-reference card | Update whenever policy/runbook changes | Docs/Support manager | `specs/sdk/android/readiness/deck/` and `/cards/` (export PDF + Markdown) |
| Knowledge check + attendance sheet | After each live session | Support engineering | `specs/sdk/android/readiness/forms/responses/` and `and7_operator_enablement.md` attendance block |
| Q&A backlog / action log | Rolling; updated after every session | LLM (acting DRI) | `specs/sdk/android/readiness/and7_operator_enablement.md` §6 |

### 10.3 Evidence & feedback loop

- Store session artefacts (screenshots, incident drills, quiz exports) in the
  same dated directory used for chaos rehearsals so governance can audit both
  readiness tracks together.
- When a session completes, update `status.md` (Android section) with links to
  the archive directory and note any open follow-ups.
- Outstanding questions from the live Q&A must be turned into issues or doc
  pull requests within one week; reference the roadmap epics (AND7/AND8) in the
  ticket description so owners stay aligned.
- SRE syncs review the archive checklist plus the schema diff artefact listed in
  Section 2.3 before declaring the curriculum closed for the quarter.
