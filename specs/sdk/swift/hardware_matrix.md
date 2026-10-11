<!--
  SPDX-License-Identifier: Apache-2.0
-->

---
title: Swift Hardware Matrix
summary: Secure Enclave, simulator, and Catalyst coverage for Swift SDK validation.
---

# Swift Hardware Matrix (IOS4 Pre-read)

This matrix summarizes the Secure Enclave, simulator, and macOS Catalyst
coverage that the IOS4 hardware review will validate. Use it as a pre-read for
the 2026-05-15 session described in
`specs/sdk/swift/hardware_requirements_review.md`.

Software/in-memory custody is the provider-neutral build, test, release, and
production baseline. P0/P1 below are optional hardware-integration coverage
tiers; their availability and evidence do not gate the general Swift SDK.

## Device Coverage

| Tier | Hardware / OS | Storage Backend | Primary Use | Notes |
|------|---------------|-----------------|-------------|-------|
| P0 | iPhone 15 Pro / iOS 18 | Secure Enclave | Optional hardware-backed production wallets, multisig hosts | Hardware-integration reference with A17 Pro; attestation sample captured (see below). |
| P0 | iPad Pro (M4) / iPadOS 18 | Secure Enclave | Treasury dashboards, operational tooling | Shares attestation cadence with iPhone P0 but exposes additional multitasking metrics. |
| P1 | Apple Silicon Mac (M3) / macOS 15 | Secure Enclave | Optional desktop hardware integration | Catalyst hardware reference; record attestation evidence when this tier is explicitly qualified. |
| P2 | Simulator (x86_64) | In-memory deterministic seed | Provider-neutral release baseline, CI smoke, integration testing | Lacks Secure Enclave; relies on deterministic HKDF seeds documented in the IOS4 RFC. |
| P2 | CI-hosted macOS runners | Software/in-memory seed; optional shared Secure Enclave | Nightly multisig smoke harness | The software lane requires no device booking; optional hardware coverage is tracked alongside Android AND2. |

## Key Points

- When a Secure Enclave tier is explicitly selected, it must export
  attestation bundles using the helper that
  will ship with `SigningKey` once IOS4 lands. Pre-read sample:
  `specs/sdk/swift/readiness/archive/2026-05/secure_enclave_attestation_sample.json`.
- Software-backed wallets, simulators, and CI may rely on deterministic seed
  derivation as defined in `specs/sdk/swift/ios4_crypto_api_rfc.md`.
- Device bookings and rotation cadence follow
  `specs/compliance/android/device_lab_reservation.md` so the
  shared hardware lab can schedule AND2/IOS4 coverage without collisions.

## Optional Hardware Action Items Before Review

1. Capture fresh attestation samples for each Secure Enclave tier and drop them
   into `specs/sdk/swift/readiness/archive/2026-05/`.
2. Confirm CI runner availability for nightly multisig smoke tests.
3. Prepare a short demo of the forthcoming `SigningKey` Secure Enclave wrapper
   (even if a stub) so the review can lock implementation checkpoints.
