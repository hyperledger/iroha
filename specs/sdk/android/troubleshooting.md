<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android SDK Troubleshooting Matrix (AND5)

**Status:** Draft GA reference (updated 2026-03-24)  
**Scope:** Android SDK operator/support incidents tracked under roadmap milestone **AND5 – Developer Experience & Samples**

Use this matrix when triaging customer issues so diagnostics remain consistent
with the Android runbook (`specs/android_runbook.md`) and telemetry
policies (`specs/sdk/android/telemetry_redaction.md`). Each scenario lists
the primary signals, first-response actions, escalation triggers, and canonical
evidence bundles. Follow the linked runbook sections for deep dives.

## 1. Severity & SLA Reference

| Severity | SLA | Typical Triggers | Required Evidence |
|----------|-----|------------------|-------------------|
| **Sev 1** – Critical outage | Bridge up ≤10 min, mitigation ≤1 h | Ledger integrity risk, Torii submission halted globally, telemetry export fully stalled | Grafana screenshots (latency/queue/deck), manifest hash, queue dump, incident log |
| **Sev 2** – Degraded | Acknowledge ≤15 min, mitigation ≤4 h | Regional queue backlog, StrongBox regression on subset of devices, redaction alert flapping | Targeted dashboard snapshots, device profile list, PendingQueueInspector JSON |
| **Sev 3** – Limited impact | Response next business day | Single-partner config drift or documentation issue | Support ticket notes + config diff |

Escalate to Release Engineering and Compliance immediately for Sev 1, and loop
Program Lead if mitigation exceeds the SLA.

## 2. Troubleshooting Matrix

| Scenario | Signals & Telemetry | First Response | Escalation Criteria | Reference |
|----------|--------------------|----------------|---------------------|-----------|
| **Torii transport failures (HTTP/Norito RPC)** | `android_sdk_submission_latency`, `torii.request.duration`, `torii_rpc_retry_total`, app logs with `X-Iroha-Error-Code` | Run `ci/run_android_tests.sh -Ptransport` to verify client libraries, capture `scripts/telemetry/check_redaction_status.py --status-url <cluster>` output, attempt direct-mode fallback per runbook §9.1 | Latency >3× baseline for 15 min, sustained `schema_mismatch` or TLS errors, or retries exhausting queue budget | `specs/android_runbook.md#91-torii-transport--pending-queue` |
| **Pending queue backlog / replay stuck** | `android_sdk_pending_queue_depth`, `android_sdk_offline_replay_errors`, `PendingQueueInspector` hashes | Export queue (`adb shell run-as … cat files/pending.queue`), decode via `PendingQueueInspector --json`, compare against Torii ledger via `iroha_cli ledger query`. Trigger load generator dry-run if queue exceeds 500 tx | Replay >10 min with no drain, hashed payloads missing from Torii, or repeated replay errors | `specs/android_runbook.md#91-torii-transport--pending-queue`, `specs/sdk/android/readiness/labs/telemetry_lab_01.md#scenario-d` |
| **Telemetry redaction failures** | `android.telemetry.redaction.failure`, `android.telemetry.redaction.override`, dashboard drift alerts, governance diff artefacts | Run `scripts/telemetry/check_redaction_status.py`, confirm salt epoch/current override state, execute `scripts/telemetry/inject_redaction_failure.sh --dry-run` to validate alert path, verify schema diff artefact under `readiness/schema_diffs/` | Failure counter >0 for 15 min, drift >10 % vs Rust baseline, or overrides active >24 h | `specs/android_runbook.md#82-override-workflow`, `specs/sdk/android/telemetry_redaction.md#signal-inventory-draft` |
| **StrongBox / attestation rejection** | `android_sdk_strongbox_success_rate`, `android.keystore.attestation.failure`, support tickets referencing `KeySecurityPreference.STRONGBOX_ONLY` | Capture bundle via `scripts/android_keystore_attestation.sh`, rerun mock attestation CI (`scripts/android_strongbox_attestation_ci.sh`), consult the device-lab lanes (`specs/compliance/android/device_lab_reservation.md`), attach bundle + result JSON to incident | Success rate <98 % for >30 min, bundle invalid on multiple devices, or alias fallback required | `specs/android_runbook.md#92-strongbox--attestation-failures`, `specs/sdk/android/strongbox_attestation_harness_plan.md` |
| **Manifest/config drift** | `android.telemetry.config.reload` failures, `schema diff` CI alarms, `ConfigWatcher` log errors | Capture `ClientConfig` digest from device logcat, dump node config via `iroha_cli config show --actual`, compare using `scripts/telemetry/run_schema_diff.sh --android-config <a> --rust-config <b>`, record findings in incident | Drift affects >1 partner or involves ABI hash mismatch, or schema diff cannot reconcile within SLA | `specs/android_runbook.md#93-manifest--config-mismatches`, `specs/sdk/android/telemetry_schema_diff.md` |
| **Telemetry exporter outage / collector saturation** | `android.telemetry.export.status`, `android.telemetry.redaction.salt_version`, Grafana Exporter Health dashboard | Check collector pods (`kubectl --context staging get pods -n android-telemetry-*`), restart exporter if safe, replay backlog via runbook §5, snapshot status tool output for archive | Exporter unavailable >10 min, salt mismatch triggers compliance alert, or backlog drains slower than 500 events/5 min | `specs/android_runbook.md#22-telemetry--redaction`, `specs/sdk/android/telemetry_chaos_checklist.md` |
| **Norito schema mismatch / fixture drift** | HTTP 400 with `X-Iroha-Error-Code: schema_mismatch`, CI failing `run_tests.sh`, dashboards showing parity gaps | Render the canonical owner with `cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication`, repeat at a second absent root, and require identical exact path sets, entry types, modes, completion manifests, and every file byte before applying the reviewed identity-relative tracked patch; then run `norito-rpc-verify` and `make android-fixtures-check`, inspect `fixtures/norito_rpc/schema_hashes.json` (DTO→hash table), and regenerate docs via `scripts/android_codegen_docs.py` | Schema hash mismatch persists after regen, or discriminant change lacks matching manifest entry | `specs/sdk/android/generated/README.md`, `specs/android_fixture_changelog.md` |

## 3. Tooling Reference

| Tool / Script | Purpose | Notes |
|---------------|---------|-------|
| `scripts/telemetry/check_redaction_status.py` | Snapshot exporter counters, salt epoch, override status | Use `--write-cache` for offline evidence bundles. |
| `scripts/telemetry/run_schema_diff.sh` | Compare Android vs Rust telemetry manifests | Attach JSON diff output to incidents and labs. |
| Canonical `norito-rpc-fixtures --output-root <absent-absolute-external-root>` + `scripts/check_android_fixtures.py` | Render the complete create-only owner publication and verify tracked diffs | Record the sealed publication identity and operator in release evidence. |
| `scripts/android_keystore_attestation.sh` | Export StrongBox/TEE attestation bundles | Requires hardware lab access; use mock bundle generator when hardware unavailable. |
| `org.hyperledger.iroha.android.tools.PendingQueueInspector` | Generate queue hash/alias inventories | Built via `ci/run_android_tests.sh`; outputs JSON for governance archives. |

## 4. Evidence & Reporting Checklist

1. **Dashboards:** Capture the relevant Grafana panels (latency, queue depth,
   exporter health) and store images under
   `specs/sdk/android/readiness/screenshots/<date>/`.
2. **Logs:** Export CLI outputs (`telemetry/check_redaction_status`,
   `run_schema_diff`, queue inspector) into the incident folder under
   `specs/sdk/android/readiness/labs/reports/<date>/`.
3. **Incident doc:** Record severity, mitigation, and follow-ups using the
   template in `specs/sdk/android/readiness/labs/reports/<date>/incident.md`.
4. **Postmortem:** For Sev 1/2, update `status.md` and ensure the Android
   support playbook (#8) references any new mitigations or SLA adjustments.

## 5. Public documentation

Keep this repository-local matrix tied to the implementation. Public
troubleshooting guides and translations are maintained in the sibling
`iroha-docs` repository and published at <https://docs.iroha.tech/>.

Questions or edits should be filed via the Docs tracker and flagged during the
weekly Android DX sync.
