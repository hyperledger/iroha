<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Device Lab Instrumentation Hooks (AND6)

This reference closes the roadmap action “stage the remaining device-lab /
instrumentation hooks ahead of AND6 kickoff”. It explains how every reserved
device-lab slot must capture telemetry, queue, and attestation artefacts so the
AND6 compliance checklist, evidence log, and governance packets share the same
deterministic workflow. Pair this note with the reservation procedure
(`device_lab_reservation.md`) and the failover runbook when planning rehearsals.

This document governs an optional physical-device qualification after a team
chooses to run it. No device-lab slot or hardware evidence is required for the
ordinary software-backed build, test, deployment, signing, or release path.

## Goals & Scope

- **Deterministic evidence** – all instrumentation outputs live under
  `artifacts/android/device_lab/<slot-id>/` with SHA-256 manifests so auditors
  can diff bundles without rerunning the probes.
- **Script-first workflow** – reuse the existing helpers
  (`ci/run_android_telemetry_chaos_prep.sh`,
  `scripts/android_keystore_attestation.sh`, `scripts/android_override_tool.sh`)
  instead of bespoke adb commands.
- **Checklists stay in sync** – every run references this document from the
  AND6 compliance checklist and appends the artefacts to
  `specs/compliance/android/evidence_log.csv`.

## Artifact Layout

1. Pick a unique slot identifier that matches the reservation ticket, e.g.
   `2026-05-12-slot-a`.
2. Seed the standard directories:

   ```bash
   export ANDROID_DEVICE_LAB_SLOT=2026-05-12-slot-a
   export ANDROID_DEVICE_LAB_ROOT="artifacts/android/device_lab/${ANDROID_DEVICE_LAB_SLOT}"
   mkdir -p "${ANDROID_DEVICE_LAB_ROOT}"/{telemetry,attestation,queue,logs}
   ```

3. Save every command log inside the matching folder (e.g.
   `telemetry/status.ndjson`, `attestation/pixel8pro.log`).
4. Capture SHA-256 manifests once the slot closes:

   ```bash
   find "${ANDROID_DEVICE_LAB_ROOT}" -type f -print0 | sort -z \
     | xargs -0 shasum -a 256 > "${ANDROID_DEVICE_LAB_ROOT}/sha256sum.txt"
   ```

## Instrumentation Matrix

| Flow | Command(s) | Output location | Notes |
|------|------------|-----------------|-------|
| Telemetry redaction + status bundle | `scripts/telemetry/check_redaction_status.py --status-url <collector> --json-out ${ANDROID_DEVICE_LAB_ROOT}/telemetry/status.ndjson` | `telemetry/status.ndjson`, `telemetry/status.log` | Run at the start and end of the slot; attach CLI stdout to `status.log`. |
| Pending queue + chaos prep | `ANDROID_PENDING_QUEUE_EXPORTS="pixel8=${ANDROID_DEVICE_LAB_ROOT}/queue/pixel8.bin" ci/run_android_telemetry_chaos_prep.sh --status-only` | `queue/*.bin`, `queue/*.json`, `queue/*.sha256` | Mirrors Scenario D from `readiness/labs/telemetry_lab_01.md`; extend the env var for every device in the slot. |
| Override ledger digest | `scripts/android_override_tool.sh digest --out ${ANDROID_DEVICE_LAB_ROOT}/telemetry/override_digest.json` | `telemetry/override_digest.json` | Required within a selected device-lab run even when no overrides are active; prove the zero state. |
| StrongBox / TEE attestation | `scripts/android_keystore_attestation.sh --device pixel8pro-strongbox-a --out "${ANDROID_DEVICE_LAB_ROOT}/attestation/pixel8pro"` | `attestation/<device>/*.{json,zip,log}` | Repeat for each reserved device (match lane names in `device_lab_reservation.md` §2). |
| CI harness attestation regression | `scripts/android_strongbox_attestation_ci.sh --output "${ANDROID_DEVICE_LAB_ROOT}/attestation/ci"` | `attestation/ci/*` | Captures the same evidence that CI uploads; include in manual runs for symmetry. |
| Lint / dependency baseline | `ANDROID_LINT_SUMMARY_OUT="${ANDROID_DEVICE_LAB_ROOT}/logs/jdeps-summary.txt" make android-lint` | `logs/jdeps-summary.txt`, `logs/lint.log` | Run once per freeze window; cite the summary in compliance packets. |

## Standard Slot Procedure

1. **Pre-flight (T-24 h)** – Confirm the reservation ticket references this
   document, update the device matrix entry, and seed the artifact root.
2. **During the slot**
   - Run the telemetry bundle + queue export commands first. Pass
     `--note <ticket>` to `ci/run_android_telemetry_chaos_prep.sh` so the log
     references the incident ID.
   - Trigger the attestation scripts per device. When the harness produces a
     `.zip`, copy it into the artefact root and record the Git SHA printed at
     the end of the script.
   - Execute `make android-lint` with the overridden summary path even if CI
     already ran; auditors expect a per-slot log.
3. **Post-run**
   - Generate `sha256sum.txt` and `README.md` (free-form notes) inside the slot
     folder summarising the executed commands.
   - Append a row to `specs/compliance/android/evidence_log.csv` with the
     slot ID, hash manifest path, Buildkite references (if any), and the latest
     device-lab capacity percentage from the reservation calendar export.
   - Link the slot folder in the `_android-device-lab` ticket, the AND6
     checklist, and `specs/android_support_playbook.md` release report.

## Failure Handling & Escalation

- If any command fails, capture the stderr output under `logs/` and follow the
  escalation ladder in `device_lab_reservation.md` §6.
- Queue or telemetry shortfalls should immediately note the override status in
  `specs/sdk/android/telemetry_override_log.md` and reference the slot ID
  so governance can trace the drill.
- Attestation regressions must be recorded in
  `specs/sdk/android/strongbox_attestation_harness_plan.md`
  with the failing device serials and the bundle paths recorded above.

## Reporting Checklist

Before marking the slot complete, verify the following references are updated:

- `specs/compliance/android/and6_compliance_checklist.md` — mark the
  instrumentation row complete and note the slot ID.
- `specs/compliance/android/evidence_log.csv` — add/update the entry with
  the slot hash and capacity reading.
- `_android-device-lab` ticket — attach artefact links and Buildkite job IDs.
- `status.md` — include a brief note in the next Android readiness digest so
  roadmap readers know which slot produced the latest evidence.

Following this process keeps AND6’s “device-lab + instrumentation hooks”
milestone auditable and prevents manual divergence between booking, execution,
and reporting.
