<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Device Lab Reservation Procedure (AND6/AND7)

This playbook describes how the Android team books, confirms, and audits device
lab time for milestones **AND6** (CI & compliance hardening) and **AND7**
(observability readiness). It complements the contingency log in
`specs/compliance/android/device_lab_contingency.md` by ensuring capacity
shortfalls are avoided in the first place.

This playbook applies only when a team explicitly selects a physical-device or
StrongBox qualification. Hardware availability and reservations do not gate
ordinary software-backed builds, tests, deployments, governance signing, or
releases.

## 1. Goals & Scope

- Keep the StrongBox + general device pools above the roadmap-mandated 80 %
  capacity target throughout freeze windows.
- Provide a deterministic calendar so CI, attestation sweeps, and chaos
  rehearsals never compete for the same hardware.
- Capture an auditable trail (requests, approvals, post-run notes) that feeds
  the AND6 compliance checklist and the evidence log.

This procedure covers the dedicated Pixel lanes, the shared fallback pool, and
the external StrongBox lab retainer referenced in the roadmap. Ad‑hoc emulator
usage is out of scope.

## 2. Reservation Windows

| Pool / Lane | Hardware | Default Slot Length | Booking Lead Time | Owner |
|-------------|----------|---------------------|-------------------|-------|
| `pixel8pro-strongbox-a` | Pixel 8 Pro (StrongBox) | 4 h | 3 business days | Hardware Lab Lead |
| `pixel8a-ci-b` | Pixel 8a (CI general) | 2 h | 2 business days | Android Foundations TL |
| `pixel7-fallback` | Pixel 7 shared pool | 2 h | 1 business day | Release Engineering |
| `firebase-burst` | Firebase Test Lab smoke queue | 1 h | 1 business day | Android Foundations TL |
| `strongbox-external` | External StrongBox lab retainer | 8 h | 7 calendar days | Program Lead |

Slots are booked in UTC; overlapping reservations require explicit approval
from the Hardware Lab Lead.

## 3. Request Workflow

1. **Prepare context**
   - List the lanes from §2 you plan to exercise and the readiness tag
     (`attestation`, `ci`, `chaos`, `partner`) in the request.
   - Collect the latest capacity snapshot from
     `specs/sdk/android/android_strongbox_capture_status.md`.
2. **Submit request**
   - File a ticket in the `_android-device-lab` queue using the template in
     `fixtures/documentation/android_device_lab_request.md` (owner, dates, workloads,
     fallback requirement).
   - Attach any regulatory dependencies (e.g. AND6 attestation sweep, AND7
     telemetry drill) and link to the relevant roadmap entry.
3. **Approval**
   - Hardware Lab Lead reviews within one business day, confirms slot in the
     shared calendar (`Android Device Lab – Reservations`), and updates the
     `device_lab_capacity_pct` column in
     `specs/compliance/android/evidence_log.csv`.
4. **Execution**
   - Run the scheduled jobs; record Buildkite run IDs or tooling logs.
   - Note any deviations (hardware swaps, overruns).
5. **Closure**
   - Comment on the ticket with artefacts/links.
   - If the run was compliance-related, update
     `specs/compliance/android/and6_compliance_checklist.md` and add a row
     to `evidence_log.csv`.

Requests that impact partner demos (AND8) must cc Partner Engineering.

## 4. Change & Cancellation

- **Reschedule:** reopen the original ticket, propose a new slot, and update the
  calendar entry. If the new slot is within 24 h, ping Hardware Lab Lead + SRE
  directly.
- **Emergency cancellation:** follow the contingency plan
  (`device_lab_contingency.md`) and record the trigger/action/follow-up rows.
- **Overruns:** if a run exceeds its slot by >15 min, post an update and confirm
  whether the next reservation can proceed; otherwise hand off to the fallback
  pool or Firebase burst lane.

## 5. Evidence & Auditing

| Artefact | Location | Notes |
|----------|----------|-------|
| Reservation tickets | `_android-device-lab` queue (Jira) | Export weekly summary; link ticket IDs in evidence log. |
| Calendar export | `artifacts/android/device_lab/<YYYY-WW>-calendar.{ics,json}` | Run `scripts/android_device_lab_export.py --ics-url <calendar_ics_feed>` each Friday; the helper saves the filtered `.ics` file plus a JSON summary for the ISO week so audits can attach both artefacts without manual downloads. |
| Capacity snapshots | `specs/compliance/android/evidence_log.csv` | Update after every booking/closure. |
| Post-run notes | `specs/compliance/android/device_lab_contingency.md` (if contingency) or ticket comment | Required for audits. |

During quarterly compliance reviews, attach the calendar export, ticket summary,
and evidence log excerpt to the AND6 checklist submission.

### Calendar export automation

1. Obtain the ICS feed URL (or download a `.ics` file) for “Android Device Lab – Reservations”.
2. Execute

   ```bash
   python3 scripts/android_device_lab_export.py \
     --ics-url "https://calendar.example/ical/export" \
     --week <ISO week, defaults to current>
   ```

   The script writes both `artifacts/android/device_lab/<YYYY-WW>-calendar.ics`
   and `...-calendar.json`, capturing the selected ISO week.
3. Upload the generated files with the weekly evidence packet and reference the
   JSON summary in `specs/compliance/android/evidence_log.csv` when
   logging device-lab capacity.

## 6. Escalation Ladder

1. Hardware Lab Lead (primary)
2. Android Foundations TL
3. Program Lead / Release Engineering (for freeze windows)
4. External StrongBox lab contact (when retainer is invoked)

Escalations must be logged in the ticket and mirrored in the weekly Android
status mail.

## 7. Related Documents

- `specs/compliance/android/device_lab_contingency.md` — incident log for
  capacity shortfalls.
- `specs/compliance/android/and6_compliance_checklist.md` — master
  deliverables checklist.
- `specs/sdk/android/android_strongbox_attestation_run_log.md` —
  StrongBox attestation evidence referenced by AND6/AND7.

Maintaining this reservation procedure satisfies the roadmap action item “define
device-lab reservation procedure” and keeps partner-facing compliance artefacts
in sync with the rest of the Android readiness plan.

## 8. Failover Drill Procedure & Contacts

Roadmap item AND6 also requires a quarterly failover rehearsal. The full,
step-by-step instructions live in
`specs/compliance/android/device_lab_failover_runbook.md`, but the high
level workflow is summarised below so requestors can plan drills alongside
routine reservations.

1. **Schedule the drill:** Block the affected lanes (`pixel8pro-strongbox-a`,
   fallback pool, `firebase-burst`, external StrongBox retainer) in the shared
   calendar and `_android-device-lab` queue at least 7 days ahead of the drill.
2. **Simulate outage:** Depool the primary lane, trigger the PagerDuty
   (`AND6-device-lab`) incident, and annotate the dependent Buildkite jobs with
   the drill ID noted in the runbook.
3. **Fail over:** Promote the Pixel 7 fallback lane, initiate the Firebase burst
   suite, and engage the external StrongBox partner within 6 hours. Capture
   Buildkite run URLs, Firebase exports, and retainer acknowledgements.
4. **Validate and restore:** Verify attestation + CI runtimes, reinstate the
   original lanes, and update `device_lab_contingency.md` plus the evidence log
   with the bundle path + checksums.

### Contact & Escalation Reference

| Role | Primary Contact | Channel(s) | Escalation Order |
|------|-----------------|------------|------------------|
| Hardware Lab Lead | Priya Ramanathan | `@android-lab` Slack · +81-3-5550-1234 | 1 |
| Device Lab Ops | Mateo Cruz | `_android-device-lab` queue | 2 |
| Android Foundations TL | Elena Vorobeva | `@android-foundations` Slack | 3 |
| Release Engineering | Alexei Morozov | `release-eng@iroha.org` | 4 |
| External StrongBox Lab | Sakura Instruments NOC | `noc@sakura.example` · +81-3-5550-9876 | 5 |

Escalate sequentially if the drill uncovers blocking issues or if any fallback
lane cannot be brought online within 30 minutes. Always record the escalation
notes in the `_android-device-lab` ticket and mirror them in the contingency log.
