<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Device Lab Contingency Log

Record every activation of the Android device-lab contingency plan here.
Include enough detail for compliance reviews and future readiness audits.

| Date | Trigger | Actions Taken | Follow-ups | Owner |
|------|---------|---------------|------------|-------|
| 2026-02-11 | Capacity fell to 78% after Pixel 8 Pro lane outage and delayed Pixel 8a delivery (see `device_lab_reservation.md` §2). | Promoted Pixel 7 lane to primary CI target, borrowed shared Pixel 6 fleet, scheduled Firebase Test Lab smoke tests for retail-wallet sample, and engaged external StrongBox lab per AND6 plan. | Replace faulty USB-C hub for Pixel 8 Pro (due 2026-02-15); confirm Pixel 8a arrival and rebaseline capacity report. | Hardware Lab Lead |
| 2026-02-13 | Pixel 8 Pro hub replaced and Galaxy S24 approved, restoring capacity to 85%. | Returned Pixel 7 lane to secondary, re-enabled `android-strongbox-attestation` Buildkite job with tags `pixel8pro-strongbox-a` and `s24-strongbox-a`, updated the reservation record + evidence log. | Monitor Pixel 8a delivery ETA (still pending); keep spare hub inventory documented. | Hardware Lab Lead |
