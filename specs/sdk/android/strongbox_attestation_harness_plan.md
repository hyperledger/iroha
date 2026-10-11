<!-- SPDX-License-Identifier: Apache-2.0 -->

# StrongBox attestation source contract and qualification

The optional StrongBox qualification workflow verifies collected device evidence
against separately governed expectations. Ordinary software-backed signing does
not require a physical StrongBox bundle. Selecting the hardware qualification
workflow requires successful evidence verification; absent hardware or bundles
cannot count as a pass.

## Ownership

| Component | Responsibility | Source |
| --- | --- | --- |
| Android device integration | Provision a new key with its issued challenge and expose its certificate chain. Existing aliases cannot receive a fresh attestation challenge. | `kotlin/client-android`, `IrohaKeyManager` and keystore providers |
| Pure JVM verifier | Verify certificate paths at an explicit time, bind a nonempty expected challenge, apply governed revocation and classify security levels. | `kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/crypto/keystore/attestation` and `KeyAttestation` |
| Offline command | Parse explicit trust inputs, read bounded certificate/ZIP evidence and emit verified JSON. | `kotlin/tools`, `org.hyperledger.iroha.sdk.tools.AndroidAttestationCommand` |
| Repository launcher | Build the Kotlin application and forward its arguments unchanged. | `scripts/android_keystore_attestation.sh` |
| Lab runner and reporting | Walk collected bundles, apply separately trusted expectations and require successful StrongBox results. | `scripts/android_strongbox_attestation_ci.sh`, `scripts/android_strongbox_attestation_report.py`, `.buildkite/android-strongbox-attestation.yml` |

The three SDK modules retain their JVM/Android/wallet boundaries. `tools` is a
separate JVM application, with JDK 8 API enforcement and no Android dependency
or additional Maven SDK publication. There is one command implementation.

## Inputs and output

The command requires exactly one `--chain` or `--bundle-dir`, and exactly one
`--challenge-hex` or `--challenge-file`. Duplicate singleton arguments are
errors. At least one explicitly supplied root source is required:
`--trust-root`, `--trust-root-dir` or `--trust-root-bundle`; these flags may repeat.

The lab authority supplies `--alias`, `--expected-leaf-spki-sha256`,
`--revocation-snapshot`, `--revocation-snapshot-sha256` and
`--evaluation-time-ms` independently of the submitted evidence. Roots, aliases
and challenges found beside a submitted chain never become trusted inputs.
`--require-strongbox` additionally requires that security level.

The command bounds file bytes, certificate counts, directory depth, ZIP entries
and decompressed bytes. Archives are read in memory, never extracted. Symlink
input files and output paths that replace a consumed trust/evidence file are
rejected. `--help` lists the concrete limits.

Successful execution prints one JSON object with schema
`iroha.android.attestation.verification.v1`, alias, security levels, StrongBox
classification, challenge, chain length, evaluation time and verified SPKI and
revocation-snapshot commitments. `--output` atomically writes the same JSON.
Verification failures print diagnostics to stderr and exit 1 without a success
record. The launcher uses the configured external Gradle artifact root when
present, preserving reviewed source mounts.

## Evidence and remaining qualification

Build and test the canonical command from `kotlin`:

```sh
./gradlew :tools:test :tools:installDist --console=plain
tools/build/install/iroha-attestation/bin/iroha-attestation --help
```

The 2026-09-06 local checkpoint passes 25 tool tests: 22 Java consumer cases and
three reader cases. These preserve the retired Java command's fixture assertions
and cover mock Huawei/OSP roots, directory/ZIP inputs, explicit challenge/SPKI
and governed snapshot checks, input bounds and output identity. The repository
launcher also verifies the shared mock Huawei fixture and rejects a substituted
challenge. These are host checks; physical StrongBox execution remains unverified.

The selected lab workflow must still prove real-device challenge issuance,
trusted alias/SPKI provenance, governed root and revocation freshness, device
security level, and retained result/evidence identity. It fails for no bundles,
missing expectations, authority/evidence overlap, stale or revoked certificates,
a key mismatch, failed verification or missing output. Device and firmware
coverage belong to the device-lab reservation records
(`specs/compliance/android/device_lab_reservation.md`) and actual run evidence;
this source contract does not certify a fleet or procurement decision.
