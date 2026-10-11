<!--
  SPDX-License-Identifier: Apache-2.0
-->

# FISC Security Controls Checklist — Android SDK

| Field | Value |
|-------|-------|
| Version | 0.1 (2026-02-12) |
| Scope | Android SDK + operator tooling used in Japanese financial deployments |
| Owners | Compliance & Legal (Daniel Park), Android Program Lead |

## Control Matrix

| FISC Control | Implementation Detail | Evidence / References | Status |
|--------------|-----------------------|-----------------------|--------|
| **System configuration integrity** | `ClientConfig` enforces manifest hashing, schema validation, and read-only runtime access. Configuration reload failures emit `android.telemetry.config.reload` events documented in the runbook. | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/client/ClientConfig.java`; `specs/android_runbook.md` §1–2. | ✅ Implemented |
| **Access control & authentication** | SDK honours Torii TLS policies and `/v1/pipeline` signed requests; operator workflows reference Support Playbook §4–5 for escalation plus override gating via signed Norito artefacts. | `specs/android_support_playbook.md`; `specs/sdk/android/telemetry_redaction.md` (override workflow). | ✅ Implemented |
| **Cryptographic key management** | Rotation and software-backed custody provide the baseline control. Caller-selected StrongBox providers, attestation validation, and device-lab coverage add optional hardware evidence without becoming a build, release, or deployment prerequisite. | `specs/sdk/android/key_management.md`; `specs/compliance/android/jp/strongbox_attestation.md`; `scripts/android_strongbox_attestation_ci.sh`. | ✅ Implemented |
| **Logging, monitoring, and retention** | Telemetry redaction policy hashes sensitive data, bucketises device attributes, and enforces retention (7/30/90/365-day windows). Support Playbook §8 describes dashboard thresholds; overrides recorded in `telemetry_override_log.md`. | `specs/sdk/android/telemetry_redaction.md`; `specs/android_support_playbook.md`; `specs/sdk/android/telemetry_override_log.md`. | ✅ Implemented |
| **Operations & change management** | GA cutover procedure (Support Playbook §7.2) plus `status.md` updates track release readiness. Release evidence (SBOM, Sigstore bundles) linked via `specs/compliance/android/eu/sbom_attestation.md`. | `specs/android_support_playbook.md`; `status.md`; `specs/compliance/android/eu/sbom_attestation.md`. | ✅ Implemented |
| **Incident response & reporting** | Playbook defines severity matrix, SLA response windows, and compliance notification steps; telemetry overrides + chaos rehearsals ensure reproducibility before pilots. | `specs/android_support_playbook.md` §§4–9; `specs/sdk/android/telemetry_chaos_checklist.md`. | ✅ Implemented |
| **Data residency / localisation** | Telemetry collectors for JP deployments run in approved Tokyo region; StrongBox attestation bundles stored in-region and referenced from partner tickets. Localization plan ensures docs available in Japanese before beta (AND5). | `specs/android_support_playbook.md` §9; `specs/sdk/android/developer_experience_plan.md` §5; `specs/compliance/android/jp/strongbox_attestation.md`. | 🈺 In Progress (localisation ongoing) |

## Reviewer Notes

- Verify device-matrix entries for Galaxy S23/S24 before regulated partner onboarding (see readiness doc rows `s23-strongbox-a`, `s24-strongbox-a`).
- Ensure telemetry collectors in JP deployments enforce the same retention/override logic defined in the DPIA (`specs/compliance/android/eu/gdpr_dpia_summary.md`).
- Capture confirmation from external auditors once banking partners review this checklist.
