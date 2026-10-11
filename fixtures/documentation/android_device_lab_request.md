<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Device Lab Reservation Request Template

Use this template only for an explicitly requested physical-device or
StrongBox qualification drill. A reservation is not required for ordinary
software-backed builds, tests, deployments, governance signing, or releases.

Copy this template into the `_android-device-lab` Jira queue when booking
hardware. Attach links to Buildkite pipelines, compliance artefacts, and any
partner tickets that depend on the run.

```
Summary: <Milestone / workload> – <lane(s)> – <date/time UTC>

Milestone / Tracking:
- Roadmap item: AND6 / AND7 / AND8 (choose)
- Related ticket(s): <link to ANDx issue>, <partner-sla reference if any>

Requestor / Contact:
- Primary engineer:
- Backup engineer:
- Slack channel / pager escalation:

Reservation details:
- Lanes required: <pixel8pro-strongbox-a / pixel8a-ci-b / pixel7-fallback / firebase-burst / strongbox-external>
- Desired slot: <YYYY-MM-DD HH:MM UTC> for <duration>
- Workload type: <CI smoke / attestation sweep / chaos rehearsal / partner demo>
- Tooling to run: <scripts/buildkite job names>
- Artefacts produced: <logs, attestation bundles, dashboards>

Dependencies:
- Capacity snapshot reference: link to `android_strongbox_capture_status.md`
- Device-lab lanes touched: lane names from `specs/compliance/android/device_lab_reservation.md`
- Compliance linkage (if any): AND6 checklist row, evidence log ID

Fallback plan:
- If primary slot unavailable, alternate slot is:
- Needs fallback pool / Firebase? (yes/no)
- External StrongBox retainer required? (yes/no – include lead time)

Approvals:
- Hardware Lab Lead:
- Android Foundations TL (when CI lanes impacted):
- Program Lead (if StrongBox retainer invoked):

Post-run checklist:
- Attach Buildkite URL(s):
- Update evidence log row: <ID/date>
- Note deviations/overruns:
```
