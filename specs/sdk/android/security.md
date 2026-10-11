<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Security & Compliance Evidence

This document defines the optional hardware-security acceptance criteria called
out in **AND2** (Secure Key Management & StrongBox) and **AND6** (CI smoke
harness & compliance) within `roadmap.md`. It consolidates the attestation
artefacts, device-matrix requirements, tamper-proof logging plan, and disclosure
playbooks required only when a release explicitly claims StrongBox or a
physical-device qualification. Software-backed signing and custody remain
valid for ordinary production, governance, build, test, deployment, and
release workflows; this hardware evidence does not gate preview, GA, or LTS
promotion.

- Use this file as the canonical reference when preparing audit packets,
  partner disclosures, and SRE readiness reviews.
- Keep the companion guides up to date:
  [`Android Key Management & Attestation Guide`](key_management.md),
  [`Android Networking & Telemetry Guide`](networking.md), and the
  [`Android Support Playbook`](../../android_support_playbook.md).

## 1. Scope & Ownership

| Item | Owner(s) | Coverage |
|------|----------|----------|
| Attestation capture & verification | Android Crypto TL · Hardware Lab Lead | `scripts/android_keystore_attestation.sh`, `scripts/android_strongbox_attestation_ci.sh`, and the readiness artefacts under `specs/sdk/android/readiness/`. |
| Device inventory & loaners | Hardware Lab · Partner Engineering | Device-lab lanes in `specs/compliance/android/device_lab_reservation.md`, `android_strongbox_capture_status.md`, loaner rotation in the support playbook. |
| Tamper-proof logs & telemetry | Telemetry/SRE · Support Engineering | `android_strongbox_attestation_run_log.md`, `telemetry_redaction.md`, associated Grafana dashboards. |
| Disclosure packs & retention | Program Lead · Compliance/Legal | `android_support_playbook.md` Sections 5–9, partner advisory templates, incident retros stored under `specs/compliance/android/`. |

All updates MUST be reflected in `status.md` within 24 hours and referenced in
the weekly AND2/AND6 governance sync.

## 2. Optional Hardware-Integration Evidence Matrix

This matrix qualifies the optional StrongBox integration when a deployment
selects it. It is not an Android SDK build, test, tag, or release gate, and
software-backed signing remains a fully supported release path without a
physical bundle.

| Stage | Attestation Reports | Device Matrix | Tamper-Proof Logs | Disclosure Pack |
|-------|--------------------|---------------|-------------------|-----------------|
| **Preview (Q2 2026)** | Fresh StrongBox bundle per device, mock bundles allowed only if tagged `mock=true`. | Pixels 6/7/8(+a/+Pro/Fold/Tablet) + Samsung S23/S24 allocated; capture status tracked in `android_strongbox_capture_status.md`. | Per-run JSONL in `readiness/android_strongbox_attestation_run_log.md`, hashes appended to `ops/drill-log.md`. | Draft comms + runbook delta filed in `android_support_playbook.md#7-release-readiness`. |
| **Beta (Q3 2026)** | Physical bundles only, verified by `scripts/android_strongbox_attestation_ci.sh` and archived under `artifacts/android/attestation/<fleet_tag>/YYYY-MM-DD/`. | Matrix signed off by Device Lab + Partner Eng; loaner rotation noted in the support playbook. | CI log digests plus Norito telemetry export stored under `specs/sdk/android/readiness/archive/`. | Disclosure outline translated (EN/JA) with attestation summary + opt-out instructions. |
| **GA/LTS (Q4 2026 →)** | Bundles + verification reports zipped into the release evidence pack referenced by `specs/compliance/android/`. | Same inventory, plus any partner-specific SKUs; deviations require Program Lead approval. | Signed SHA256 manifests for run logs retained 3 years, cross-linked in `status.md`. | Final playbook section published; incident contact + SLA tables validated. |

## 3. Attestation Report Pipeline

1. **Capture**
   - Run `scripts/android_keystore_attestation.sh --bundle-dir artifacts/android/attestation/<fleet_tag>/<date> --trust-root <governed-root.pem> --alias <trusted-alias> --challenge-hex <trusted-challenge> --expected-leaf-spki-sha256 <trusted-digest> --revocation-snapshot <capture>/android-sdk-revocation-snapshot-v1.txt --revocation-snapshot-sha256 <separately-trusted-governance-commitment> --evaluation-time-ms <ms>` on each device. Generate the canonical snapshot with `scripts/capture_android_attestation_status.py`, adding reviewed TBS digests there; do not reconstruct its fields at the harness boundary or obtain any expectation from the untrusted bundle.
   - Keep the submitted evidence (`chain.pem`, `result.json`, and optional notes)
     separate from the authenticated expectations inventory (alias, challenge,
     leaf-SPKI digest, trust roots, and snapshot commitment).
   - Note the device-lab lane (for example `pixel8pro-strongbox-a`) from
     `specs/compliance/android/device_lab_reservation.md`; this value is
     referenced by CI and partner playbooks.
2. **Verification**
   - `scripts/android_strongbox_attestation_ci.sh --bundles-root ... --expectations-root ... --trust-root ...` is the offline-friendly guard used in Buildkite. The expectations tree mirrors bundle paths and is authenticated independently. It validates:
     - Certificate chain rooted in the vendor trust anchor.
     - Mandatory challenge binding plus certificate validity at the explicit evaluation time.
     - Freshness of the governed offline status snapshot and serial/TBS-hash revocation for the full chain and configured anchors.
     - Security level (`STRONGBOX`, `TEE`, `SOFTWARE`) surfaced to telemetry.
   - Results feed into
     `readiness/android_strongbox_attestation_run_log.md` and the `torii_request`
     telemetry counters documented in `telemetry_redaction.md`.
3. **Publication**
   - Archive bundles beneath `artifacts/android/attestation/` and attach the
     directory SHA256 to the weekly AND2 update in `status.md`.
   - Include the most recent digest + link in
     `strongbox_attestation_harness_plan.md`.
   - During releases, copy the relevant bundles into the compliance evidence set
     tracked by `specs/compliance/android/and6_compliance_checklist.md`
     and record the digest inside `specs/compliance/android/evidence_log.csv`.

## 4. Device-Matrix Coverage

- Device-lab lanes and owners are listed in
  `specs/compliance/android/device_lab_reservation.md` §2; update that table
  whenever a device is provisioned, retired, or repurposed.
- `readiness/android_strongbox_capture_status.md` tracks per-device capture
  progress and is the checklist referenced during weekly readiness calls.
- Hardware additions/rotations require:
  1. Capture + verify attestation bundles as above.
  2. Log provisioning notes (firmware level, enrolment status) in the reservation ticket.
  3. Announce in the `#android-foundations` channel with a link to the diff.
- Partner loaners (AND8 dependency) must also appear in the `Loaner Rotation`
  table inside `android_support_playbook.md`.

## 5. Tamper-Proof Logs & Telemetry

- Every attestation capture (lab or CI) appends a JSONL entry to
  `readiness/android_strongbox_attestation_run_log.md` with the SHA256 of each
  artefact plus the Buildkite job URL.
- `scripts/android_strongbox_attestation_report.py` can emit signed manifests;
  store them under `readiness/archive/<year>/` and link the hash inside the run
  log so auditors can replay the evidence.
- Telemetry/SRE must export the following metrics (documented in
  `telemetry_redaction.md`):
  - `android_sdk_strongbox_success_rate`
  - `android_sdk_strongbox_attestation_age_seconds`
  - `android_sdk_strongbox_downgrade_total{reason}`
- Tamper-proof expectations:
  - CI jobs upload run logs to the immutable bucket managed by Ops, with server
    side encryption enabled and lifecycle rules set to ≥3 years.
  - Local captures sign the JSONL file via
    `scripts/android_strongbox_attestation_report.py manifest --input run_log.jsonl --signing-key <key>`
    before appending to `ops/drill-log.md`.

## 6. Disclosure Playbooks & Incident Flow

- Partner-facing procedures live in
  `../android_support_playbook.md` (Sections 4–8). This security doc summarises
  the specific hooks that must be updated when hardware issues occur:
  1. **Detection:** Alerts from `android_sdk_strongbox_success_rate` or manual
     capture failures trigger the Sev 2/Sev 1 paths defined in the playbook.
  2. **Containment:** Record the affected `fleet_tag`, disable automatic bundle
     promotion in `scripts/android_strongbox_attestation_ci.sh`, and file a
     redaction note per the override workflow in `telemetry_redaction.md`.
  3. **Disclosure:** Within 24 hours, publish a short advisory referencing the
     affected aliases, devices, and mitigation steps. Templates reside in
     `specs/sdk/android/readiness/cards/`.
  4. **Follow-up:** Append the incident summary to
     `specs/sdk/android/readiness/android_strongbox_capture_status.md`
     and record the remediation checklist in `status.md`.
- For regulatory filings, coordinate with Compliance to store the sealed report
  in `specs/compliance/android/` alongside the partner acknowledgement.

## 7. Evidence Review Cadence

- **Weekly (AND2/AND6 sync):**
  - Verify at least one attestation capture ran in the past seven days.
  - Confirm device matrix deltas and capture status checkboxes.
  - Update `status.md` with bundle hashes and outstanding risks.
- **Monthly (Governance review):**
  - Export redacted run logs + telemetry snapshots and attach to the meeting
    notes.
  - Reconcile disclosure templates with any new compliance findings.
  - Ensure the support playbook reflects the latest SLA, device rotation, and
    partner requirements.
- **Release (RC/GA):**
  - Snapshot this document (git tag) and freeze the evidence pack.
  - Attach the signed manifests + disclosure plan to the GA checklist referenced
    in `specs/sdk/android/developer_experience_plan.md`.

## 8. Related References

- `strongbox_attestation_harness_plan.md` — bundle layout and naming.
- `../../compliance/android/device_lab_reservation.md` — device-lab lanes + owners.
- `readiness/android_strongbox_attestation_run_log.md` — tamper-proof logbook.
- `readiness/android_strongbox_capture_status.md` — progress checklist + TODOs.
- `networking.md` Section 5 — Torii telemetry hooks referenced by AND4/AND7.
- `telemetry_redaction.md` — override flow and metric retention policies.
- `../android_support_playbook.md` — incident response, partner comms, SLAs.
- `key_management.md` — alias lifecycle, deterministic export, StrongBox policy.

> **Reminder:** Updating any evidence source without touching this document
> violates the roadmap guard rail. Always amend the relevant section (scope,
> pipeline, or cadence) when processes change.
