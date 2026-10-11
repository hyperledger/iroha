<!--
  SPDX-License-Identifier: Apache-2.0
-->

---
title: Swift Hardware Requirements Review
summary: Review agenda for Swift key storage, attestation, and crypto dependencies.
---

# Swift Hardware Requirements Review (IOS4)

This brief schedules the hardware requirements review called out in the IOS4
roadmap. The session reviews optional Secure Enclave / Keychain coverage,
conditional attestation export, and dependency alignment with the Android AND2
StrongBox initiative before the multi-algorithm signing work lands. The
software-backed signing and custody baseline does not depend on this review,
physical devices, or hardware evidence.

## Session Overview

| Field | Details |
|-------|---------|
| Date | **2026-05-15 (Friday)** |
| Time | 15:00–16:30 UTC (90 minutes) |
| Location | Zoom — `https://meet.sora.dev/ios4-hw-review` |
| Facilitator | Mei Nakamura (Swift Observability TL) |
| Co-chairs | LLM (IOS4 acting DRI), Kenji Obata (Android AND2 TL) |
| Required attendees | Swift SDK team, Android AND2 team, `iroha_crypto` maintainer, Docs/Support, Compliance, Release Engineering |
| Optional attendees | SRE governance liaison, Hardware Lab operations |
| Pre-read deadline | 2026-05-13 23:00 UTC |

## Objectives

1. Inventory supported hardware tiers (Secure Enclave, simulator fallback,
   macOS Catalyst) and map them to the `SigningKey` storage abstractions defined
   in `specs/sdk/swift/ios4_crypto_api_rfc.md`.
2. Align evidence for deployments that explicitly select hardware attestation
   with the Android AND2 StrongBox programme so reviews can reuse artefacts.
3. Approve the optional hardware rollout matrix (devices × signing algorithms
   × multisig flows) and its automation hooks without gating the software lane.
4. Capture action items (CI coverage, device lab scheduling, doc updates) with
   explicit owners and due dates.

## Agenda

| Segment | Duration | Owner | Notes |
|---------|----------|-------|-------|
| Welcome / objectives | 10 min | LLM | Recap IOS4 scope, success criteria, and dependencies. |
| Hardware inventory review | 20 min | Mei Nakamura | Present Secure Enclave + macOS coverage, simulator fallbacks, and device gap analysis. |
| StrongBox lessons & attestation | 15 min | Kenji Obata | Share AND2 attestation cadence, evidence templates, and Norito metadata expectations. |
| `SigningKey` storage/telemetry walkthrough | 15 min | `iroha_crypto` maintainer | Ensure discriminants, Norito envelopes, and telemetry schemas line up. |
| Compliance & docs | 10 min | Docs/Support Manager | Confirm operator-facing requirements, update runbooks/reference docs. |
| Action item review | 10 min | LLM | Assign owners/dates, agree on follow-ups before IOS4 code freeze. |
| Q&A / buffer | 10 min | All | Holds spillover + risk review. |

## Pre-Reads & Inputs

- `specs/sdk/swift/ios4_crypto_api_rfc.md` (multi-algorithm API plan).
- `specs/sdk/swift/connect_risk_tracker.md` (Connect dependencies).
- Android AND2 StrongBox readiness deck (`specs/sdk/android/security.md`) and device-lab lanes (`specs/compliance/android/device_lab_reservation.md`).
- Latest device inventory / attestation evidence in `status.md` (Android section).
- Draft telemetry schema updates for `swift.crypto.signing` and
  `swift.multisig.session`.
- Swift hardware matrix + Secure Enclave attestation sample:
  - `specs/sdk/swift/hardware_matrix.md`
  - `specs/sdk/swift/attestation_sample.md`

## Required Outputs

These are required outputs of the hardware review itself, not prerequisites for
a provider-neutral Swift SDK build, release, deployment, or signing workflow.

- Updated hardware matrix & attestation checklist (to be recorded in
  `specs/sdk/swift/hardware_matrix.md` after the session).
- Confirmed CI device allocations (M-series Macs, iPhone/iPad variants,
  simulators) with owners for automation follow-ups.
- Action item log delivering:
  - Secure Enclave attestation export helper in `IrohaSwift`.
  - Device lab scheduling for nightly multisig smoke tests.
  - Compliance doc updates referencing the new signing/backups guidance.
- Meeting minutes + recording archived under
  `specs/sdk/swift/readiness/archive/2026-05/`.

## Logistics & Tracking

- Calendar invites sent 2026-04-25 to all required attendees; RSVP tracking lives
  in `specs/sdk/swift/readiness/archive/2026-05/hw_review_rsvp.md`.
- Notes owner: Elias Ortega (Docs/Support Manager).
- Follow-up checkpoint: include progress in the 2026-05-22 Swift status export
  and add any blockers to `roadmap.md` (IOS4 section).
