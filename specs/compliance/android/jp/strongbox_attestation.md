<!--
  SPDX-License-Identifier: Apache-2.0
-->

# StrongBox Attestation Evidence — Japan Deployments

This evidence packet qualifies the optional StrongBox integration for a
deployment that explicitly selects it. Its strict capture and verification
steps do not apply to software-backed custody and do not gate ordinary SDK
builds, governance signing, deployments, or releases.

| Field | Value |
|-------|-------|
| Assessment Window | 2026-02-10 – 2026-02-12 |
| Artefact Location | `artifacts/android/attestation/<device-tag>/<date>/` (bundle format per `specs/sdk/android/strongbox_attestation_harness_plan.md`) |
| Capture Tooling | `scripts/android_keystore_attestation.sh`, `scripts/android_strongbox_attestation_ci.sh`, `scripts/android_strongbox_attestation_report.py` |
| Reviewers | Hardware Lab Lead, Compliance & Legal (JP) |

## 1. Capture Procedure

1. On each device listed in the StrongBox matrix, generate a challenge and capture the attestation bundle:
   ```bash
   adb shell am instrument -w \
     org.hyperledger.iroha.android/.attestation.CaptureStrongBoxInstrumentation
   scripts/android_keystore_attestation.sh \
     --bundle-dir artifacts/android/attestation/${DEVICE_TAG}/2026-02-12 \
     --trust-root trust-roots/google-strongbox.pem \
     --alias "${TRUSTED_ALIAS}" \
     --challenge-file "${TRUSTED_EXPECTATIONS}/challenge.hex" \
     --expected-leaf-spki-sha256 "${TRUSTED_LEAF_SPKI_SHA256}" \
     --revocation-snapshot "${TRUSTED_SNAPSHOT}" \
     --revocation-snapshot-sha256 "${TRUSTED_SNAPSHOT_SHA256}" \
     --evaluation-time-ms "${EVALUATION_TIME_MS}" \
     --require-strongbox \
     --output artifacts/android/attestation/${DEVICE_TAG}/2026-02-12/result.json
   ```
2. Archive `result.json` and `chain.pem` as evidence. Retain alias,
   challenge, leaf-SPKI digest, roots, and revocation inputs in a separately
   authenticated inventory.
3. Run the CI helper to re-verify all bundles offline:
   ```bash
   scripts/android_strongbox_attestation_ci.sh \
     --bundles-root artifacts/android/attestation \
     --expectations-root "${TRUSTED_EXPECTATIONS_ROOT}" \
     --trust-root trust-roots/google-strongbox.pem \
     --revocation-snapshot "${TRUSTED_SNAPSHOT}" \
     --revocation-snapshot-sha256 "${TRUSTED_SNAPSHOT_SHA256}" \
     --evaluation-time-ms "${EVALUATION_TIME_MS}"
   scripts/android_strongbox_attestation_report.py \
     --input artifacts/android/attestation \
     --output artifacts/android/attestation/report_20260212.txt
   ```

## 2. Device Summary (2026-02-12)

| Device Tag | Model / StrongBox | Bundle Path | Result | Notes |
|------------|-------------------|-------------|--------|-------|
| `pixel6-strongbox-a` | Pixel 6 / Tensor G1 | `artifacts/android/attestation/pixel6-strongbox-a/2026-02-12/result.json` | ✅ Passed (hardware-backed) | Challenge bound, OS patch 2025-03-05. |
| `pixel7-strongbox-a` | Pixel 7 / Tensor G2 | `.../pixel7-strongbox-a/2026-02-12/result.json` | ✅ Passed | Primary CI lane candidate; temperature within spec. |
| `pixel8pro-strongbox-a` | Pixel 8 Pro / Tensor G3 | `.../pixel8pro-strongbox-a/2026-02-13/result.json` | ✅ Passed (retest) | USB-C hub replaced; Buildkite `android-strongbox-attestation#221` captured the passing bundle. |
| `s23-strongbox-a` | Galaxy S23 / Snapdragon 8 Gen 2 | `.../s23-strongbox-a/2026-02-12/result.json` | ✅ Passed | Knox attestation profile imported 2026-02-09. |
| `s24-strongbox-a` | Galaxy S24 / Snapdragon 8 Gen 3 | `.../s24-strongbox-a/2026-02-13/result.json` | ✅ Passed | Knox attestation profile imported; CI lane now green. |

Device tags map to the device-lab lanes in `specs/compliance/android/device_lab_reservation.md`.

## 3. Reviewer Checklist

- [x] Verify `result.json` shows `strongbox_attestation: true` and certificates chain to trusted root.
- [x] Confirm challenge bytes match Buildkite runs `android-strongbox-attestation#219` (initial sweep) and `#221` (Pixel 8 Pro retest + S24 capture).
- [x] Re-run Pixel 8 Pro capture after hardware fix (owner: Hardware Lab Lead, completed 2026-02-13).
- [x] Complete Galaxy S24 capture once Knox profile approval arrives (owner: Device Lab Ops, completed 2026-02-13).

## 4. Distribution

- Attach this summary plus the latest report text file to partner compliance packets (FISC checklist §Data residency).
- Reference bundle paths when responding to regulator audits; do not transmit raw certificates outside encrypted channels.

## 5. Change Log

| Date | Change | Author |
|------|--------|--------|
| 2026-02-12 | Initial JP bundle capture + report. | Device Lab Ops |
