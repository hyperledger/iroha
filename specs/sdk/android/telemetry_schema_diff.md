<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android vs Rust Telemetry Schema Summary (Draft)

This appendix summarises the parity between Android SDK telemetry exports and
the Rust node observability schema. It accompanies the AND7 governance pre-read.
The latest comparison artefact from 2026-03-05 (config snapshot refresh of the
Android/Rust telemetry manifests) is stored at
`specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json`.
Earlier runs (2026-02-27, 2026-02-24, 2026-02-02, 2026-01-24, and 2025-11-15)
are retained for traceability.

## Governance Snapshot & Distribution

| Run date | Evidence | Location | Notes |
|----------|----------|----------|-------|
| 2026-03-05 | Schema diff artefact (March inventory refresh) | `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json` | Regenerated after governance feedback; worksheet, roadmap, and pre-read now reference this artefact for the April digest. |
| 2026-03-05 | Worksheet/pre-read sync | `specs/sdk/android/readiness/signal_inventory_worksheet.md`, `specs/sdk/android/telemetry_redaction_pre_read.md` | References updated to the March artefact so the AND7 packet links to the latest JSON evidence. |
| 2026-02-24 | Schema diff artefact (source of truth for the Feb SRE privacy gate) | `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260224.json` | Reviewed by the SRE privacy alias on 2026-02-24; hashes recorded in `artifacts/android/telemetry/and7_schema_diff/20260224/README.md`. |
| 2026-02-24 | Distribution log + PDF trail | `artifacts/android/telemetry/and7_schema_diff/20260224/README.md` | Documents the recipients, delivery channels, SHA256 values, and PDF export instructions so reviewers can confirm what was circulated. |
| 2025-11-17 | Schema diff + policy summary (CLI auto-generated) | `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20251117.json`, `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20251117-policy.json` | First run using the built-in `--policy-out` flag; CI/readiness pipelines should depend on the policy artefact instead of ad-hoc `jq` trimming. |

> The SRE privacy reviewers acknowledged the February packet in
> `specs/sdk/android/telemetry_redaction_minutes_20260212.md`, so the
> allowlists and approval checklist documented below are now the canonical
> governance baseline. Future schema diff runs must append to the distribution
> log instead of editing historical entries.

## 1. Metric & Span Coverage

| Channel | Rust Signal | Android Equivalent | Status | Notes |
|---------|-------------|--------------------|--------|-------|
| Trace | `torii.http.request` | `android.torii.http.request` | ✅ Field parity (authority hashed) |
| Trace | `torii.http.retry` | `android.torii.http.retry` | ✅ Field parity (authority hashed, matched to request) |
| Metric | `pipeline.pending_queue_depth` | `android.pending_queue.depth` | ✅ Units/labels match |
| Metric | `telemetry.export.status` | `android.telemetry.export.status` | ✅ Uses same label set |
| Metric | `streaming.privacy.redaction_fail_total` | `android.telemetry.redaction.failure` | ✅ Shared semantics |
| Metric | `attestation.success_total` | `android.keystore.attestation.result` | ⚠️ Alias hashed (documented) |
| Trace | `telemetry.config.reload` | `android.telemetry.config.reload` | ✅ |
| Event | N/A | `android.telemetry.redaction.override` | 🔸 Android-only (requires governance approval) |

Legend: ✅ parity confirmed, ⚠️ intentional divergence (documented), 🔸 new signal
requiring acceptance.

The 2026-03-05 CLI run (config-mode,
`telemetry-schema-diff 2.0.0-rc.2.0`) compared 7
signals, recorded 6 intentional differences, and detected 4 Android-only
signals; all four entries remain explicitly allowlisted (see Section 3).

## 2. Field Mapping Highlights

| Field (Rust) | Field (Android) | Parity | Comment |
|--------------|-----------------|--------|---------|
| `authority` (`torii.http.request`/`torii.http.retry`) | `authority_hash` | ⚠️ | Blake2b-256 hashed with rotating salt |
| `peer_host` | — | ✅ | Android drops this field; Rust retains |
| `device_profile` | `device_profile` | ⚠️ | Bucketed enums (`emulator`, `consumer`, `enterprise`) |
| `carrier_name` | — | ✅ | Dropped on Android |
| `override_actor` | `actor_role_masked` | 🔸 | Masked to role category (`support`, `sre`, `audit`) |

## 3. Policy Allowlists & Automated Checks

The schema diff CLI now enforces two privacy allowlists:

- **Android privacy allowlist.** Fields that must be redacted or bucketed on
  Android (e.g., `torii.http.request.authority`, `torii.http.retry.authority`,
  `attestation.result.alias`, `attestation.result.device_tier`, and
  `hardware.profile.profile_bucket`) are
  enumerated inside `telemetry-schema-diff` so the tool fails if a future schema
  forgets to hash/bucket them. When a diff run succeeds these entries are
  written into the `intentional_differences` array with
  `status: "accepted"` alongside the privacy-policy rationale recorded during
  the run.
- **Rust retention allowlist.** Fields that intentionally remain unredacted on
  Rust nodes (currently `hardware.profile.hardware_tier`) are codified in the
  same module. When Rust exports a field that Android omits for privacy reasons
  the diff reports it as an accepted, intentional difference and stores it in
  the same `intentional_differences` array.
- **Governance trail.** Every intentional difference must declare
  `status: "accepted"` or `status: "policy_allowlisted"`. The CLI surfaces a
  `policy_violation` when a status is missing or uses any other value so stale
  or unreviewed deviations cannot pass CI silently.

The 2026-03-05 refresh revalidated the explicit allowlist entries for the
Android-only guardrails introduced across AND7
(`android.telemetry.redaction.override`, `android.telemetry.network_context`,
`android.telemetry.redaction.failure`, and
`android.telemetry.redaction.salt_version`). These signals remain recorded
in `ANDROID_ONLY_SIGNALS` inside the diff CLI so the process fails fast and
records the violation whenever a future schema update drops or renames them
without policy approval.

Both allowlists are verified before the diff CLI emits JSON. `cargo run -p
telemetry-schema-diff` still writes the JSON artefact but exits non-zero if:

1. Android schemas omit the hashed/bucketed representation for a required field.
2. Android accidentally exports a field that must remain Rust-only.
3. A platform-exclusive signal is not explicitly allowlisted.
4. Any intentional difference lacks `status:"accepted"`/`"policy_allowlisted"`
   (the offending fields are listed under `policy_violations`).

When a guard fails the CLI exits with an error after writing the JSON so CI jobs
stop immediately while still preserving the evidence (`policy_violations`
carries the allowlist failures, and `recommendations` summarises follow-up
actions). Successful runs leave `policy_violations` empty and the JSON is
limited to the accepted deviations: `intentional_differences` lists
hashed/bucketed fields and `android_only_signals` records SDK-exclusive
telemetry.

### 3.1 Android Privacy Allowlist (Hash/Bucket Requirements)

| Signal.field | Representation enforced | Rationale | Enforcement hook |
|--------------|------------------------|-----------|------------------|
| `torii.http.request.authority` | `blake2b_256` hash | Prevents leaking operator endpoints from mobile traces while keeping the canonical I105 route observable on Rust. | `REQUIRED_ANDROID_REPRESENTATIONS` inside `tools/telemetry-schema-diff/src/main.rs` plus `telemetry-schema-diff` CLI gating; entries appear under `intentional_differences` when accepted. |
| `torii.http.retry.authority` | `blake2b_256` hash | Applies the same hashing to retry telemetry so backoff traces never expose Torii hosts. | `REQUIRED_ANDROID_REPRESENTATIONS` + schema validation; the accepted diff records the hashing under `intentional_differences`. |
| `attestation.result.alias` | `blake2b_256` hash | Keeps StrongBox alias handles private on devices that emit keystore telemetry. | Same `REQUIRED_ANDROID_REPRESENTATIONS` guard + schema validation in `scripts/telemetry/run_schema_diff.sh`; the accepted diff is recorded in `intentional_differences`. |
| `attestation.result.device_tier` | `bucketed` | Mobile builds only export tier buckets (`emulator`, `consumer`, `enterprise`) so vendor-specific metadata never leaves the device. | `REPRESENTATION_ALLOWANCES` in `tools/telemetry-schema-diff/src/main.rs` rejects non-bucketed representations and documents the acceptance inside `intentional_differences`. |

### 3.2 Platform-Exclusive Signals

- `android.telemetry.redaction.override` — Android-only override audit signal.
  - Intent: mirror override approvals that unblock exports when a redaction salt
    investigation is underway.
  - Guardrails: allowlisted by `ANDROID_ONLY_SIGNALS` in the diff CLI, logged in
    `specs/sdk/android/telemetry_override_log.md`, and automatically
    surfaced in the JSON artefact’s `android_only_signals` array so reviewers
    see every override recorded in telemetry.
- `android.telemetry.network_context` — sanitized network-type telemetry.
  - Intent: expose device network_type/roaming so OEM- or carrier-specific
    regressions can be triaged without leaking carrier metadata present on Rust
    nodes.
  - Guardrails: canonicalised as `network.context` and allowlisted; dropping or
    renaming it triggers a diff-tool failure so policy reviewers can re-approve
    the change.
- `android.telemetry.redaction.failure` — mobile-only streaming privacy counter.
  - Intent: alert SDK owners when client-side transforms fail before export so
    overrides/redaction fixes happen before telemetry is re-enabled.
  - Guardrails: canonical `streaming_privacy.redaction_fail_total`; operators
    correlate it with server-side dashboards during chaos drills. Allowlisted
    so the CLI enforces its presence and retains the Android-only classification.
- `android.telemetry.redaction.salt_version` — hash-salt rotation gauge.
  - Intent: prove which hashing salt epoch + rotation id are active on each
    client build so SRE can confirm parity with Rust nodes.
  - Guardrails: canonical `telemetry.redaction.salt_version`, surfaced in the
    JSON artefact and allowlisted; if future Android builds stop exporting it,
    the diff CLI aborts to force a governance review.

### 3.3 Rust Retention Allowlist & Raw-Field Requirements

| Signal.field | Rust requirement | Android expectation | Reason / notes |
|--------------|-----------------|---------------------|----------------|
| `hardware.profile.hardware_tier` | Must remain raw (no representation) | **Must not** surface on Android | Operators rely on the precise tier when correlating device classes; Android emits only coarse buckets via `android.telemetry.device_profile`. |
| `torii.http.request.authority` | Must remain raw | Hashed via `blake2b_256` | Rust nodes keep the original host/authority for debugging and GAR evidence, while Android hides it; enforced by `REQUIRED_RUST_RAW_FIELDS`. |
| `torii.http.retry.authority` | Must remain raw | Hashed via `blake2b_256` | Retry traces reuse the same host material; Rust keeps it for debugging/backoff analysis while Android redacts it. |
| `attestation.result.alias` | Must remain raw | Hashed via `blake2b_256` | Server-side attestation auditors require the literal alias; Android redacts it per §3.1. |

The allowlist above is what governance expects to see surfaced in the diff JSON
(`intentional_differences` entries). Any new signal/field combination must be
added to these tables and to `tools/telemetry-schema-diff/src/main.rs` before
SDK or Rust changes land.

### 3.4 Allowlist Reconciliation Snapshot (2026-03-05 run)

The 2026-03-05 schema diff produced the following reconciled allowlist. Each
row mirrors the JSON artefact stored at
`specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json`
so reviewers can see—at a glance—which differences were accepted, which ones
are policy-allowlisted, and where the evidence lives.

| Category | Signal.field | Handling | Status (2026-03-05) | Evidence |
|----------|--------------|----------|----------------------|----------|
| Intentional difference | `android.torii.http.request.authority` | `blake2b_256` hash | Accepted | `android_vs_rust-20260305.json:intentional_differences[0]` |
| Intentional difference | `android.torii.http.retry.authority` | `blake2b_256` hash | Accepted | `android_vs_rust-20260305.json:intentional_differences[1]` |
| Privacy bucket | `android.keystore.attestation.result.alias` | `blake2b_256` hash | Accepted | `android_vs_rust-20260305.json:intentional_differences[2]` |
| Privacy bucket | `android.keystore.attestation.result.device_tier` | Bucketed enum | Policy allowlisted | `android_vs_rust-20260305.json:intentional_differences[3]` |
| Platform gap | `android.telemetry.device_profile.profile_bucket` | Android-only bucket export | Accepted | `android_vs_rust-20260305.json:intentional_differences[4]` |
| Platform gap | `android.telemetry.device_profile.hardware_tier` | Rust-only raw export | Policy allowlisted | `android_vs_rust-20260305.json:intentional_differences[5]` |

#### Android-only telemetry guardrails

| Signal | Canonical name | Channel | Status | Evidence / notes |
|--------|----------------|---------|--------|------------------|
| `android.telemetry.redaction.override` | `android.telemetry.redaction.override` | Event | Accepted | Guarded by `ANDROID_ONLY_SIGNALS` and mirrored in `specs/sdk/android/telemetry_override_log.md`. |
| `android.telemetry.network_context` | `network.context` | Event | Accepted | Sanitised network context emitted only on Android; Rust retains richer carrier metadata. |
| `android.telemetry.redaction.failure` | `streaming_privacy.redaction_fail_total` | Counter | Accepted | Required for AND7 chaos drills; telemetry-schema-diff now surfaces `status:"accepted"` for this Android-only signal after resolving bug AND7-CLI-219. |
| `android.telemetry.redaction.salt_version` | `telemetry.redaction.salt_version` | Gauge | Accepted | Proves the active hash-salt epoch; telemetry-schema-diff now emits `status:"accepted"` for this Android-only signal so reviewers no longer need the manual cross-reference noted during the 2026-03-05 privacy briefing. |

Documenting the accepted allowlist in Markdown ensures downstream PDF exports
contain the same evidence bundle that the SRE governance review consumes, even
if the CLI output format changes.

> **2026-04-26 enforcement update:** `telemetry-schema-diff` now validates that
> every Android-only signal listed above is present **and** carries
> `status:"accepted"` (or `status:"policy_allowlisted"`). Missing entries or
> statuses cause the CLI to fail before generating a diff, eliminating the
> manual review step noted earlier in §3.4. The guardrail is implemented via the
> policy checks in `tools/telemetry-schema-diff/src/main.rs` and exercised by
> dedicated unit tests. The same flag set now emits the trimmed governance
> summary via `--policy-out`, so CI/pre-read binders should depend on the
> generated `*-policy.json` artefact instead of re-cutting summaries with `jq`.
>
> **2026-05-02 metrics update:** `scripts/telemetry/run_schema_diff.sh` now
> writes a Prometheus textfile by default
> (`artifacts/android/telemetry/schema_diff.prom`). Use `--metrics-out <path>`
> to override the output location and `--textfile-dir /var/lib/node_exporter/textfile_collector`
> (or set `ANDROID_SCHEMA_DIFF_TEXTFILE_DIR`) to atomically mirror the metrics
> into the node_exporter textfile collector. The exported gauges
> (`telemetry_schema_diff_signals_compared`,
> `telemetry_schema_diff_policy_violations`,
> `telemetry_schema_diff_run_status`, etc.) keep the AND7 dashboards and alerts
> green without manual uploads.

## 4. Pending Validation Items

1. **Schema diff tool run (`cargo run -p telemetry-schema-diff`)**
   - Output: `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json`
   - Owner: LLM (acting AND7 owner + SRE privacy lead) — refresh captured 2026-03-05 using the canonical config snapshots; the 2026-02-27, 2026-02-24, 2026-02-02, 2026-01-24, and 2025-11-15 artefacts remain archived for drift analysis ahead of GA.
- Status: Completed via [`scripts/telemetry/run_schema_diff.sh`](/scripts/telemetry/run_schema_diff.sh) with `--android-config configs/android_telemetry.json --rust-config configs/rust_telemetry.json --textfile-dir /var/lib/node_exporter/textfile_collector` and `telemetry_schema_diff 2.0.0-rc.2.0`. The script emitted the default `artifacts/android/telemetry/schema_diff.prom` snapshot and mirrored the metrics into the node_exporter textfile collector so Grafana proves the run timestamp, policy-violation count, and parity statistics. The run produced zero field mismatches, six `intentional_differences`, and four `android_only_signals` entries (`android.telemetry.redaction.override`, `android.telemetry.network_context`, `android.telemetry.redaction.failure`, `android.telemetry.redaction.salt_version`). As of the latest schema update, the CLI emits `status:"accepted"` for all four entries, so any future run that drops the field fails the review automatically instead of relying on §3.4 as a manual backstop.
2. **Unit tests for hashed authority round-trip** — ✅ Completed 2026-04-25
   - `AuthorityHashTest` now replays the recorded salt rotations and proves that replaying the
     manifests maps every hashed authority back to its canonical Torii host, covering trimming,
     case-folding, and multi-rotation lookups.【java/iroha_android/src/test/java/org/hyperledger/iroha/android/telemetry/AuthorityHashTest.java:1】
3. **Override event acceptance** — ✅ Completed 2026-02-12
   - Governance minutes (`telemetry_redaction_minutes_20260212.md`) confirm the
     `android.telemetry.redaction.override` signal is approved with masked actor
     roles and 365-day retention.
4. **Diff tool recommendations (2026-03-05 run)**
   - ✅ Completed 2026-03-05 — No new recommendations were emitted. We
     re-reviewed the StrongBox device-lab lanes
     (`specs/compliance/android/device_lab_reservation.md`) and
     telemetry redaction guidance (`specs/android_support_playbook.md`
     §8.1) to confirm the `consumer`/`enterprise` tier mapping and permitted
     hardware buckets remain accurate; no follow-up actions required.
5. **Diff tool recommendations (2026-02-02 run)**
   - Item A: publish the quarterly override digest using
     `specs/sdk/android/telemetry_override_log.md` (owner: Android
     Observability TL; status: 🈺 In Progress).
   - Item B: 🈴 Completed — `TelemetryObserverTests.emitsSaltVersionAfterConfigReload`
     (`java/iroha_android/src/test/java/org/hyperledger/iroha/android/telemetry/TelemetryObserverTests.java`)
     now proves `android.telemetry.redaction.salt_version` emits whenever a
     `ClientConfig` reload installs a new telemetry observer, satisfying the
     dashboard parity recommendation for automated coverage.

## 4. Markdown Snapshot for Readiness Packets

Roadmap item AND7 calls for a lightweight pre-read that spells out how the
Android telemetry payload differs from the Rust baseline. Run the schema diff
helper with the new `--markdown-out` flag to produce that hand-out alongside the
canonical JSON artefact:

```bash
scripts/telemetry/run_schema_diff.sh \
  --android-config configs/android_telemetry.json \
  --rust-config configs/rust_telemetry.json \
  --out specs/sdk/android/readiness/schema_diffs/android_vs_rust-$(date +%Y%m%d).json \
  --markdown-out specs/sdk/android/readiness/schema_diffs/android_vs_rust-$(date +%Y%m%d).md
```

The Markdown file mirrors the JSON summary counts, Android/Rust provenance, and
tables for intentional differences, platform-only signals, unexpected
mismatches, and policy violations. Drop the generated file into the AND7
enablement archive (see `telemetry_readiness_outline.md`) so SRE/support can
paste it into meeting agendas or share it with stakeholders who prefer a
human-readable delta instead of the raw JSON diff.

## 5. Acceptance Checklist

- [x] Diff artefact reviewed and signed off by SRE privacy lead (2026-03-05 refresh; older artefacts retained for regression analysis)
- [x] Divergences documented with justification (hashed authorities, bucketed
  profile, override events)
- [x] Dashboard parity tested (Android vs Rust) with `scripts/telemetry/compare_dashboards.py` (`specs/sdk/android/readiness/dashboard_parity/android_vs_rust-20260324.json`)
- [x] Schema version increment recorded in `status.md`

Dashboard parity evidence comes from running:

```bash
python3 scripts/telemetry/compare_dashboards.py \
  --android dashboards/grafana/android_telemetry_overview.json \
  --rust dashboards/grafana/rust_android_client_telemetry.json \
  --allow-file dashboards/data/android_rust_dashboard_allowances.json \
  --output specs/sdk/android/readiness/dashboard_parity/android_vs_rust-20260324.json
```

CI now runs `./ci/check_android_dashboard_parity.sh`, which regenerates
`specs/sdk/android/readiness/dashboard_parity/android_vs_rust-latest.json`
and compares it against the recorded artefact. When the check fails, rerun the
command above (updating the dated filename) and re-run the CI script to
re-establish parity.

The exported dashboards share the same `metric_id` catalog (`submission_latency_p95`,
`pending_queue_depth`, `offline_replay_errors`, `strongbox_success_rate`,
`redaction_failures`, `override_tokens_active`, `telemetry_export_backlog`), so
operators can prove coverage is identical even though the underlying Prometheus
expressions reference platform-specific metrics.

### 5.1 Reviewer Approval Matrix

| Reviewer | Role | Scope | Decision | Date (UTC) | Evidence |
|----------|------|-------|----------|------------|----------|
| LLM | SRE privacy lead / AND7 acting owner | Diff + allowlist snapshot (§§3–4) | ✅ Approved | 2026-03-05 | `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json` |
| Android Observability TL | Platform telemetry owner | Signal inventory refresh + hashed field verification | ✅ Approved | 2026-03-05 | `specs/sdk/android/readiness/signal_inventory_worksheet.md`, `specs/sdk/android/readiness/schema_diffs/android_vs_rust-20260305.json` |
| Docs/Support Manager | Enablement owner | Runbook (§§2–3) refresh + quick-reference + enablement assets | ✅ Approved | 2026-03-08 | `specs/android_runbook.md`, `specs/sdk/android/telemetry_redaction_quick_reference.md`, `specs/sdk/android/readiness/telemetry_redaction_v1.md` |

Reviewers should initial/date their row once the outstanding entry moves to
approved status; the AND7 governance hot list links back to this matrix for
telemetry-policy evidence.

### Governance Approval Checklist

1. **Regenerate the schema diff.** Run `scripts/telemetry/run_schema_diff.sh`
   with the current `configs/android/telemetry_schema.json` and
   `configs/rust/telemetry_schema.json`, then store the JSON under
   `specs/sdk/android/readiness/schema_diffs/<date>.json`.
2. **Review accepted deviations.** Confirm that every entry in
   `intentional_differences[*]` matches §3.1–§3.3 with `status == "accepted"`,
   that each `android_only_signals[*]` record is `status == "accepted"`, and
   that `field_mismatches` and `policy_violations` are empty (the CLI already
   exits non-zero when violations exist, but the artefact should still record
   the empty arrays). For quick spot checks:
   ```bash
   jq '.intentional_differences[] | select(.status!="accepted")' specs/sdk/android/readiness/schema_diffs/<date>.json
   jq '.android_only_signals[] | select(.status!="accepted")' specs/sdk/android/readiness/schema_diffs/<date>.json
   jq '.field_mismatches' specs/sdk/android/readiness/schema_diffs/<date>.json
   jq '.policy_violations' specs/sdk/android/readiness/schema_diffs/<date>.json
   ```
3. **Update artefact trail.** Link the refreshed JSON plus this Markdown file to
   the AND7 governance packet (pre-read, hot list, and knowledge-check folder).
   When distributing externally, export this document to PDF using the docs
   portal renderer and attach the PDF/JSON pair to the SRE privacy review email.
4. **Log reviewer sign-off.** Capture reviewer acknowledgements in
   `telemetry_redaction_minutes_YYYYMMDD.md` and tick the matching entry inside
   `specs/sdk/android/and7_governance_hotlist.md` so roadmap item AND7
   reflects the completed review.

## 6. References

- `specs/sdk/android/telemetry_redaction.md`
- `specs/sdk/android/telemetry_redaction_pre_read.md`
- `specs/android_support_playbook.md`
- `scripts/telemetry/run_schema_diff.sh`

Please update this document immediately after the schema diff tool completes to
avoid slipping the governance review.
