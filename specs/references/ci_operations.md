# CI Operations — Nightly Red-Team Lane

## Overview

- **Workflow:** `.github/workflows/nightly-red-team.yml`
- **Schedule:** Daily at 03:30 UTC (GitHub Actions cron) with manual rerun via `workflow_dispatch`.
- **Surfaces exercised:**
  - Consensus relay harness — `cargo test -p integration_tests extra_functional::unstable_network::block_after_genesis_is_synced -- --nocapture`
  - Contract manifest Torii path — `cargo test -p integration_tests contracts::post_and_get_contract_manifest_via_torii -- --nocapture`
  - Torii rate-limit guard — `cargo test -p iroha_torii handshake_rate_limited -- --nocapture`
- **Artifacts:** Logs for each workload are written to `artifacts/red-team/` and uploaded as workflow artifacts named `red-team-logs`.
- **Failure handling:** `scripts/report_red_team_failures.py` copies the logs, renders a templated issue body (surface, mitigation, owner, due date), and files a GitHub issue when any workload fails.

## SLA

- **Triage window:** <24 hours. Assign an owner, acknowledge the issue, and begin mitigation within one calendar day.
- **Owner hint:** Set a repository secret `RED_TEAM_OWNER` to a team mention (e.g., `@sora-org/red-team`) so the reporter assigns the correct group automatically. Empty secret falls back to the default placeholder in the workflow.

## Rerun instructions

1. Navigate to **Actions → Nightly Red Team**.
2. Click **Run workflow**, choose the desired branch (default: `main`), and confirm. Optional inputs are not required; the workflow uses the baked-in commands above.
3. Monitor the run; once the mitigation lands, rerun to confirm the lane is green before closing the issue.

## Failure triage checklist

- Inspect the uploaded logs under the `red-team-logs` artifact (`consensus.log`, `manifest.log`, `torii-rate-limit.log`).
- Update or reassign the auto-filed issue if the default owner is incorrect.
- Document root cause and mitigation in the issue; link any follow-up PRs.
- After the fix merges, rerun the workflow manually and close the issue once the rerun passes.

## Weekly XCFramework StrongBox sanity check

Swift CI on-call rotates through a weekly verification of the XCFramework smoke harness to ensure
StrongBox devices stay healthy and telemetry continues to surface lane metadata. Run the checklist
every Monday (or after returning from PTO) and record the outcome in the on-call
notes. This maintains an optional hardware integration; a missing or unhealthy
StrongBox lane does not block the software/simulator build or release corridor.

1. **Review the latest Buildkite run.**
   - Open `https://buildkite.com/sora/xcframework-smoke` and inspect the most recent run.
   - Confirm that the required `iphone-sim` and `ipad-sim` lanes are present. If
     an optional hardware drill was requested, also confirm the `strongbox`
     lane. Each job exposes a `device_tag` annotation and emits Buildkite
     metadata `ci/xcframework-smoke:<lane>:device_tag`. File hardware-lane
     incidents separately from baseline release failures.
2. **Kick an explicit StrongBox run.**
   - From the pipeline page, click **New Build**, select branch `master`, and set the environment
     variable `FORCE_DEVICE=ios14p-strongbox`. This forces the harness to acquire one of the
     dedicated StrongBox devices (roster `ios14p-strongbox-01/02/03`).
   - Monitor the run until it finishes. For long waits, check device availability with
     `devicekit list ios14p-strongbox`.
3. **Validate artifacts and telemetry.**
   - Download the generated report (`xcframework-smoke/report`) and ensure the destination,
     OS version, and `device_tag` match expectations.
   - Run `scripts/ci/run_xcframework_smoke.sh --tags devicekit:ios14p-strongbox --dry-run` locally
     (optional) to verify the harness still resolves the correct destinations.
   - Confirm `dashboards/mobile_ci.swift` updated within the hour. The `devices.strongbox` panel
     should show the recent run; if not, ping telemetry owners.
4. **Log the result.**
   - Add a short note to the CI on-call doc or weekly thread capturing the Buildkite run URL, device
     used, and any follow-up actions. If an incident was opened, link it explicitly.

## Android StrongBox attestation sweep

This workflow applies only when a team explicitly selects the optional
StrongBox qualification profile. It is not an ordinary build, test, governance,
deployment, or release gate; the software-backed baseline remains valid without
attestation bundles or physical hardware.

Run this workflow whenever new attestation bundles land for that selected
profile, at minimum before hardware-specific AND2/AND6 reviews and partner
pilots that claim the profile.

1. **Ensure evidence and governed expectations exist.**
   - Sync the latest device captures under `artifacts/android/attestation/<fleet-tag>/<date>/`.
   - Confirm each bundle contains `chain.pem`; keep its alias, challenge, and
     `leaf_spki_sha256.hex` in a separately authenticated mirrored expectations
     tree. Trust roots remain in the vendor authority store and must never be
     discovered from the evidence bundle.
2. **Trigger the Buildkite pipeline.**
   - From a checkout on the Buildkite agent, run
     `buildkite-agent pipeline upload --pipeline .buildkite/android-strongbox-attestation.yml`.
   - The step runs `scripts/android_strongbox_attestation_ci.sh`, generates a summary via
     `scripts/android_strongbox_attestation_report.py`, uploads
     `artifacts/android_strongbox_attestation_report.txt`, and annotates the build with
     `android-strongbox/report`.
3. **Review the report.**
   - Inspect the annotation; it lists every bundle with the alias, security levels, and any failures.
   - Download the artifact if additional details are required. Failed entries emit structured log
     lines (also printed to stderr by the report script).
4. **Update the reservation record and status.**
   - Record the Buildkite run URL and attestation date in the device-lab
     reservation ticket (`specs/compliance/android/device_lab_reservation.md`).
   - Note any remediation or outstanding bundles in `status.md` under the Android foundations
     section so governance can track readiness.

## Related dashboards

- Swift/mobile CI metrics feed into the dedicated dashboards documented in
  `specs/references/ios_metrics.md`. Ensure Buildkite lane failures that
  surface there are triaged in tandem with the red-team workflow to keep parity
  and release readiness aligned across SDKs.
- Buildkite XCFramework smoke lane is defined in `.buildkite/xcframework-smoke.yml` and
  emits telemetry via `scripts/ci/run_xcframework_smoke.sh`. Review the lane’s annotation
  (`xcframework-smoke/report`) after each run; failures will surface through the
  `mobile_ci` dashboard feed. The harness also records per-lane Buildkite metadata
  (`ci/xcframework-smoke:<lane>:device_tag`) so incidents can be tied back to the exact
  simulator or StrongBox device without parsing destination strings. Coordinate follow-up
  with the Swift parity triage runbook and dashboard schema guide when incidents arise.
- Android Norito fixture rotations use the workspace owner command
  `cargo run --locked -p xtask --features dev-tools --bin xtask --
  norito-rpc-fixtures --output-root <absent-absolute-external-root>` with two independent
  absent absolute external roots. Before any tracked update, require identical exact path sets,
  entry types, modes, completion manifests, and every file byte. Apply the
  reviewed identity-relative patch from either sealed root, then run
  `norito-rpc-verify` and `make android-fixtures-check`
  (`ci/check_android_fixtures.sh`) before commit.
- Desktop JVMs running the Android tests should add BouncyCastle (`org.bouncycastle:bcprov`) when native Ed25519 support is missing; the harness stubs the provider but attaching the jar keeps local runs aligned with CI.
