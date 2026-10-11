<!--
  SPDX-License-Identifier: Apache-2.0
-->

# Android Key Management & Attestation Guide

This guide documents the Iroha Android SDK key subsystem used in roadmap items
**AND2** (secure key management) and **AND5** (developer experience). It
collects implementation details from `java/iroha_android`, operator runbooks,
and readiness artifacts so application teams can configure deterministic key
flows before enabling StrongBox-backed signing in production.

Software-backed signing and custody are supported for ordinary production,
governance, build, test, deployment, and release workflows. StrongBox and TEE
providers are optional integrations. The `*_REQUIRED` preferences below are
strict only when an application explicitly selects them; they are never a
repository-wide prerequisite.

> **Sample walkthroughs:**  
> - [Operator console walkthrough](samples/operator_console.md#9-step-by-step-walkthrough) – Step 1 uses software custody by default and shows how optional StrongBox enrolment, alias policies, and attestation exports map to Sections 2–5 of this guide.

## 1. Architecture Overview

`IrohaKeyManager` multiplexes one or more `KeyProvider` implementations and
routes calls according to a `KeySecurityPreference`. Providers advertise their
capabilities via `KeyProviderMetadata` so applications can inspect hardware
coverage before choosing an alias policy.

| Component | Responsibility | Source |
|-----------|----------------|--------|
| `IrohaKeyManager` | Registers providers, enforces security preferences, exposes metadata/attestation/export helpers. | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/IrohaKeyManager.java` |
| `SoftwareKeyProvider` | Deterministic Ed25519 generation, HKDF/AES-GCM exports, emulator/desktop fallback. | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/crypto/SoftwareKeyProvider.java` |
| `KeystoreKeyProvider` + `SystemAndroidKeystoreBackend` | Reflection-based bridge to Android Keystore / StrongBox with attestation support and automatic fallback to TEE/software when StrongBox is absent. | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/crypto/keystore/SystemAndroidKeystoreBackend.java` |
| `AttestationVerifier` | Validates StrongBox/TEE certificate chains, mandatory challenge bindings, explicit evaluation time, and a fresh governed revocation snapshot; shared with CLI tooling (`scripts/android_keystore_attestation.sh`). | `java/iroha_android/src/main/java/org/hyperledger/iroha/android/crypto/keystore/attestation/AttestationVerifier.java` |

The default construction helpers cover the common cases:

- `withSoftwareProvider()` – a supported software-custody path for production,
  governance, CI, desktop tooling, and deterministic regression tests.
- `withDefaultProviders(KeyGenParameters)` – prefers StrongBox when available,
  falls back to TEE or software depending on the provided preferences, and
  honours requirements such as user authentication, attestation freshness, and
  key expiration windows.

## 2. Security Preferences

`KeySecurityPreference` defines the allowed provider set per request (see
`java/iroha_android/src/main/java/org/hyperledger/iroha/android/IrohaKeyManager.java:329`).
The manager orders providers accordingly and stops after the first successful
lookup/generation.

| Preference | Behaviour | Typical Use |
|------------|-----------|-------------|
| `STRONGBOX_REQUIRED` | Rejects the call unless a StrongBox-backed provider exists and can satisfy the alias. | An explicitly selected StrongBox qualification profile only. |
| `STRONGBOX_PREFERRED` | Tries StrongBox first, then other hardware providers, ends with software only if downgrades are allowed. | Shared builds that must prefer StrongBox but continue functioning when devices lack it. |
| `HARDWARE_REQUIRED` / `HARDWARE_PREFERRED` | Enforces/Prefers any hardware-backed provider (TEE or StrongBox) before falling back to software. | Standard device fleets where StrongBox coverage is mixed. |
| `SOFTWARE_ONLY` | Bypasses hardware providers entirely; always uses the deterministic software implementation. | Production software custody, emulator automation, offline recovery tools, and CI fixtures. |

Applications can expose these settings as configuration knobs (`iroha_config`
or feature flags) so operators decide whether to block or allow hardware
downgrades per environment. Selecting `STRONGBOX_REQUIRED` or
`HARDWARE_REQUIRED` is an explicit application policy decision, not an Iroha
SDK, governance, deployment, or release requirement.

## 3. Alias Lifecycle

1. **Lookup:** `generateOrLoad(alias, preference)` searches providers in the
   order dictated by the preference, reusing the first matching key it finds.
2. **Generation:** When the alias is unknown, the manager asks the highest-ranked
   provider to create the key. StrongBox requests can specify
   `KeyGenParameters.requireStrongBox()` and `allowStrongBoxFallback()` to control
   automatic downgrades.
3. **Persistence:** Hardware providers retain ownership of the alias. Software
   providers mirror the alias only when a downgrade occurs so future lookups
   remain deterministic.
4. **Rotation:** Delete the alias through the `KeyProvider` (or OS keystore) and
   call `generateOrLoad` again; the manager recreates the key under the same
   policy. Record rotations in `specs/android_support_playbook.md` (Section 5
   SLA table) to keep partners informed.

Recommended alias naming:

- Prefix environment / tenant (e.g., `prod/governance/alice`).
- Mirror the alias inside `iroha_config.telemetry.alias_labels` so telemetry and
  overrides (`specs/sdk/android/telemetry_override_log.md`) reference the
  same identifier.

## 4. Deterministic Export & Recovery

When software custody is selected (including production wallets, offline
signing laptops, and recovery drills),
use the deterministic export helpers wired into `IrohaKeyManager`
(`java/iroha_android/src/main/java/org/hyperledger/iroha/android/IrohaKeyManager.java:164`):

```java
IrohaKeyManager manager = IrohaKeyManager.withDefaultProviders();
KeyExportBundle bundle =
    manager.exportDeterministicKey("se-demo", "passphrase".toCharArray());
manager.importDeterministicKey(bundle, "passphrase".toCharArray());
```

Hardware-backed Keystore aliases are **non-exportable**. For user-managed accounts
that must recover on new devices, prefer software keys and explicitly require an
exportable Ed25519 provider (Bouncy Castle) so the deterministic bundle contains
the private key material:

```java
SoftwareKeyProvider provider =
    new SoftwareKeyProvider(SoftwareKeyProvider.ProviderPolicy.BOUNCY_CASTLE_REQUIRED,
        exportStore,
        passphraseProvider);
IrohaKeyManager manager = IrohaKeyManager.fromProviders(List.of(provider));
```

Or use the convenience helper:

```java
IrohaKeyManager manager =
    IrohaKeyManager.withExportableSoftwareKeys(exportStore, passphraseProvider);
```

`IrohaKeyManager` validates that generated keys are Ed25519 by checking the
SPKI prefix; emulators or misconfigured devices that downgrade to a different
algorithm raise `KeyManagementException` and emit
`android.keystore.key_validation.failure` telemetry (fields include
`spki_length`, `expected_spki_length`, `spki_prefix`, and `phase`). Surface that
error or fall back to `SOFTWARE_ONLY` when the policy allows it.

The bundle embeds HKDF-derived salts and AES-GCM metadata so the import helper
can detect tampering or passphrase mismatches deterministically. Store bundles
alongside operator runbooks and rotate the passphrase whenever an alias is
revoked. For automated flows, wrap the helper inside
`scripts/android_keystore_attestation.sh` or companion CLI tooling so exports are
captured with provenance hashes.

## 5. Attestation Workflow

When an application explicitly selects AND2 hardware qualification, every
hardware-backed alias in that profile must publish attestation artefacts:

1. **Provision** a new, unique alias with
   `KeyGenParameters.Builder.setAttestationChallenge(challenge)` before calling
   `generateOrLoad(...)`. Android binds the challenge while creating the key;
   never reuse an existing alias when the verifier issued a new challenge.
2. **Archive** the resulting PEM chain under
   `specs/sdk/android/strongbox_attestation_harness_plan.md` and
   record the device-lab lane from
   `specs/compliance/android/device_lab_reservation.md`.
3. **Verify** locally via `IrohaKeyManager.verifyAttestation(...)` or the
   `scripts/android_keystore_attestation.sh --bundle-dir <dir>` helper. Supply
   the alias, challenge, expected leaf-SPKI SHA-256, and trust roots from a
   separately authenticated source, not from the evidence directory. The
   verifier enforces:
   - Certificate path to Google/Pixel roots (configurable for OEM deployments).
   - A non-empty challenge binding (match against a separately trusted
     `--challenge-hex` or `--challenge-file`).
   - Exact leaf-key binding to the separately trusted SPKI digest and, in SDK
     use, every configured provider that currently resolves the alias.
   - A caller-supplied governed Android status snapshot that is fresh at the
     explicit evaluation time and rejects every listed certificate serial or
     TBS SHA-256 digest, including configured trust anchors.
   - Security level (StrongBox vs TEE) surfaced to telemetry dashboards.
4. **Publish** the attestation digest inside the partner readiness pack defined
   in `specs/android_support_playbook.md#9-compliance--audit-artefacts`.

Attestation summaries flow into telemetry via
`android.telemetry.redaction.attestation_*` counters (see
`specs/sdk/android/telemetry_redaction.md`). During incidents, follow the
override workflow in `android_support_playbook.md#8-telemetry-redaction--observability-and7`.

> **Note:** Android’s public APIs only expose certificates minted when the alias
> was provisioned. `verifyAttestation(...)` rereads and verifies that recorded
> chain; it does not claim to mint fresh evidence.
> `generateAttestation(alias, nonEmptyChallenge)` therefore fails explicitly on
> the platform backend. To answer a new challenge, deliberately provision a new
> alias with `KeyGenParameterSpec.Builder#setAttestationChallenge(...)`, verify
> its chain, and only then perform application-controlled key rotation.

## 6. Integrating With Transaction Builder

The key manager plugs directly into `TransactionBuilder`:

```java
TransactionBuilder builder =
    new TransactionBuilder(new NoritoJavaCodecAdapter(org.hyperledger.iroha.android.address.AccountAddress.DEFAULT_I105_DISCRIMINANT),
        IrohaKeyManager.withDefaultProviders());

SignedTransaction tx = builder.encodeAndSign(payload, "governance-primary",
    KeySecurityPreference.STRONGBOX_PREFERRED);
```

- **Offline envelopes:** Call
  `encodeAndSignEnvelopeWithAttestation(...)` to receive both the Norito envelope
  and any StrongBox attestation bundle. Use this path inside the retail wallet
  sample so offline devices can forward evidence to Torii later.
- **Operator console:** Surface `providerMetadata()` in diagnostics (for example,
  a health widget showing whether StrongBox is active) and expose buttons to
  trigger deterministic exports or attestation refreshes for the selected alias.

## 7. Policy & Configuration Hooks

- Mirror caller-selected StrongBox policies into
  `iroha_config.android.key_policy` (new knob to be threaded through AND2) so
  runtime components understand whether downgrades are allowed. The default
  software-custody path must not opt into a hardware-required policy.
- Record alias ownership, attestation timestamps, and export status in
  `specs/android_support_playbook.md` Section 11 to keep support and
  compliance teams aligned.
- When telemetry redaction overrides are approved (Section 8.2 of the playbook),
  include the alias + bundle hash so audit reviewers can cross-reference keys
  against overrides.

## 8. Testing & Diagnostics

| Scenario | Checklist |
|----------|-----------|
| Emulator / Desktop regression | Run `make android-tests && ci/run_android_tests.sh`. Ensure `hasHardwareBackedProvider()` returns `false` and `SOFTWARE_ONLY` paths pass. |
| Optional device lab StrongBox sweep | When qualifying that integration, execute `scripts/android_strongbox_attestation_bundle.sh` across the reserved device-lab lanes (`specs/compliance/android/device_lab_reservation.md`) and archive outputs per device. |
| Override / telemetry chaos | Follow `specs/sdk/android/telemetry_chaos_checklist.md` Scenario 2 to confirm attestation-dependent overrides propagate correctly. |
| Sample app smoke | Once AND5 samples land, gate CI via `ci/check_android_samples.sh` so Managed Device runs fail when aliases or preferences regress. |

Document outcomes in `status.md` (Android section) and attach logs/digests to the
relevant readiness archives.

## 9. References

- `java/iroha_android/src/main/java/org/hyperledger/iroha/android/IrohaKeyManager.java`
- `java/iroha_android/README.md`
- `specs/android_support_playbook.md`
- `specs/sdk/android/readiness/*` (attestation, telemetry, labs)
- `scripts/android_keystore_attestation.sh`
