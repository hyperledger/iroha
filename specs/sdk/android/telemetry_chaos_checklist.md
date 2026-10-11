<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Telemetry Chaos Checklist (AND7)

This checklist enumerates the staging scenarios required to validate Android
telemetry redaction and exporter behaviour ahead of AND7 beta. Execute the full
suite quarterly and prior to major releases.

## Execution Overview

- **Environment:** AND7 staging cluster (`android-telemetry-stg`), seed with
  sample traffic using `scripts/telemetry/generate_android_load.sh`.
- **Salt guardrails:** Export `ANDROID_TELEMETRY_EXPECTED_SALT_EPOCH=<YYYYQ#>`
  and `ANDROID_TELEMETRY_EXPECTED_SALT_ROTATION=<id>` before running
  `scripts/telemetry/check_redaction_status.py` or
  `ci/run_android_telemetry_chaos_prep.sh` so the CLI fails fast if Android and
  Rust hash epochs diverge.
- **Participants:** Android Observability TL (Haruka Yamamoto), SRE on-call
  (Liam O’Connor), Support Engineer (Priya Deshpande), Release Engineering
  observer (Alexei Morozov).
- **Artifacts:** Log each run in `incident/YYYY-MM-DD-telemetry-chaos.md` and
  attach screenshots, exporter logs, and Norito override records.

## Scenarios

| ID | Scenario | Goal | Steps | Expected Outcome |
|----|----------|------|-------|------------------|
| C1 | Redaction failure injection | Validate alerting when hashing mismatches | 1. Run `scripts/telemetry/inject_redaction_failure.sh`\n2. Verify alert fires within 5 min\n3. Execute diagnostic script `check_redaction_status.py`\n4. Resolve failure (`scripts/telemetry/inject_redaction_failure.sh --clear`) and confirm alert clears | Alert triggers, diagnostic script highlights offending signal, alert clears within 10 min after fix. |
| C2 | Override lifecycle | Ensure override approvals, application, and revocation behave correctly | 1. Create signed override request (template in `fixtures/documentation/android_override_request.json`)\n2. Apply override via `scripts/android_override_tool.sh`\n3. Validate telemetry export includes unhashed authority sample\n4. Revoke override and confirm audit entry | Override applied ≤24 h, audit log updated, telemetry returns to hashed state within 5 min. |
| C3 | Exporter outage | Confirm buffering and alert thresholds | 1. Disable exporter (`kubectl scale deploy/android-otel-collector --replicas=0`)\n2. Observe buffer growth and alerting\n3. Re-enable exporter and ensure backlog drains\n4. Review logs for dropped spans | Alert at 15 min, backlog drains without data loss, metrics show sustained delivery. |
| C4 | Schema drift | Detect unexpected field addition/removal | 1. Create a drifted Android config: `DRIFT_CONFIG=$(mktemp /tmp/android_telemetry_drift.XXXXXX.json)` then `jq '.signals += [{\"name\":\"android.telemetry.test_dummy\",\"canonical_name\":\"telemetry.test_dummy\",\"channel\":\"metric\",\"fields\":[{\"name\":\"dummy\",\"canonical_name\":\"dummy\",\"data_type\":\"string\"}]}]' configs/android_telemetry.json >\"$DRIFT_CONFIG\"`.\n2. Run `scripts/telemetry/run_schema_diff.sh --android-config \"$DRIFT_CONFIG\" --rust-config configs/rust_telemetry.json --out specs/sdk/android/readiness/schema_diffs/android_vs_rust-$(date -u +%Y%m%d)-drift.json` (non-zero exit expected).\n3. Inspect the artefact for `policy_violations` and the injected signal, capture the output in the incident log.\n4. Delete the temp config (`rm \"$DRIFT_CONFIG\"`) after attaching the JSON to the lab report. | Schema diff blocks with the injected signal logged under `policy_violations`; evidence proves the gate catches drift. |
| C5 | Device profile mismatch | Validate bucket comparison | 1. Seed skewed traffic for five minutes: `scripts/telemetry/generate_android_load.sh --cluster android-telemetry-stg --device-profile enterprise --duration 5m --rps 6`.\n2. Observe `Android Telemetry Overview` device-profile variance/alerts.\n3. Run a balancing load to restore baseline: `scripts/telemetry/generate_android_load.sh --cluster android-telemetry-stg --device-profile emulator --device-profile consumer --device-profile enterprise --duration 5m --rps 6`.\n4. Capture before/after screenshots and log the variance percentage. | Variance alert triggers during skewed window, then clears once balanced load resumes; dashboard mix returns to baseline. |
| C6 | Torii timeout & queue replay | Ensure pending queues grow/drain predictably across device + emulator | 1. Build and install `examples/android/operator-console` on the staging Pixel and the AOSP emulator (`./gradlew :operator-console:installDebug`).\n2. Enable airplane mode for five minutes (`adb -s <serial> shell cmd connectivity airplane-mode enable`).\n3. Submit two demo transfers per device (operator-console > “Replay drill”).\n4. Disable airplane mode, watch queue drain, and export metrics via `scripts/telemetry/check_redaction_status.py`.\n5. Pull the queue file (`adb shell run-as <app-id> cat files/pending.queue > /tmp/<serial>.queue`). When available, rerun `ci/run_android_telemetry_chaos_prep.sh` with `ANDROID_PENDING_QUEUE_EXPORTS=pixel8=/tmp/pixel.queue,emulator=/tmp/emulator.queue` (etc.) so the helper copies each queue, writes `<label>.sha256`, and runs `PendingQueueInspector` automatically. Otherwise run `java -cp build/classes org.hyperledger.iroha.android.tools.PendingQueueInspector --file /tmp/<serial>.queue --json > queue-replay-<serial>.json` manually after `cd java/iroha_android && ./run_tests.sh` compiles the tool.\n6. Attach decoded envelopes/JSON summaries using `OfflineSigningEnvelopeCodec` + inspector output (helper emits `<label>.json`). | Queue depth increases during outage, drains cleanly after Torii recovers, and `android_sdk_offline_replay_errors` stays at 0. |
| C7 | Attestation rejection rehearsal | Validate alerting + audit flow when StrongBox attestation fails | 1. Capture a fresh bundle on the Pixel (`scripts/android_keystore_attestation.sh --bundle-dir artifacts/android/attestation/pixel8/$(date +%F) --trust-root vendor.pem`).\n2. On an emulator (or a device without StrongBox), run a debug build configured with `KeySecurityPreference.STRONGBOX_ONLY` and attempt to sign a sample transaction.\n3. Confirm `android.keystore.attestation.failure` fires and PagerDuty `android-crypto` notifies on-call.\n4. Run `scripts/android_strongbox_attestation_ci.sh` to prove the archived bundles still pass on StrongBox hardware.\n5. Record the rehearsal result in the device-lab reservation ticket (`specs/compliance/android/device_lab_reservation.md`). | Alert and metric fire once, audit log records hashed alias + bundle path, and CI confirms production StrongBox devices remain healthy. |

> **Note:** `ci/run_android_telemetry_chaos_prep.sh` compiles `PendingQueueInspector`
on demand; run `ci/run_android_tests.sh` manually only if you plan to
invoke the inspector outside the helper.

## Pre-Run Checklist

- [ ] Staging cluster healthy; no ongoing incidents.
- [ ] Latest Android SDK build deployed (`android-observability-stg` tag).
- [ ] Norito override templates up to date (run `cargo test -p sorafs_manifest` to verify).
- [ ] SRE and Support participants on call.
- [ ] Incident template prepared (`incident/<date>-telemetry-chaos.md`).

## Post-Run Checklist

- [ ] Incident log updated with scenario outcomes.
- [ ] Follow-up JIRA tickets filed for failures.
- [ ] Dashboard snapshots stored in `specs/sdk/android/readiness/screenshots/`.
- [ ] Schema diff artefact archived in `target/telemetry/schema_diffs/history/`.
- [ ] Roadmap/status updates captured if blockers identified.

## Metrics & Acceptance

- All scenarios completed within four hours.
- No Sev 1/2 incidents triggered during rehearsal.
- Alerts fire and clear within documented thresholds.
- Overrides audited and log entries verified.

Rehearsal artefacts are archived for reference:

- Command outputs and incident timelines:
  `specs/sdk/android/readiness/labs/reports/2026-02/telemetry_lab_01_report.md`
- Exporter recovery log:
  `specs/sdk/android/readiness/labs/reports/2026-02/android_otel_collector_recovery.log`
- Dashboard screenshots:
  `specs/sdk/android/readiness/screenshots/2026-02-10/`

Update these references and append new evidence after each subsequent rehearsal.
