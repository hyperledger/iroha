# Android public attestation probe

Standalone Kotlin diagnostic for collecting fresh P-256 key attestation from
registered AndroidKeyStore and HwKeyStore JCA providers. It is independent of
wallet/native builds and is not an admission verifier. Missing providers and
failed attestation are recorded; there is no imported-key or software fallback.
No network, storage or device-identifier permissions are requested.

Build from the canonical checkout using the existing Gradle wrapper:

```sh
ANDROID_HOME="$HOME/Library/Android/sdk" kotlin/gradlew \
  --project-dir examples/android/attestation-probe \
  assembleDebug testDebugUnitTest --console=plain
```

Launch `org.hyperledger.iroha.samples.attestationprobe`, enter an independently
chosen 64-character hexadecimal challenge, and select **Capture public
attestation**. The initial challenge is a fresh public 32-byte SecureRandom value,
not a wallet E1 challenge. The app does not request biometric authentication. Private keys
remain with the provider and diagnostic aliases are deleted in `finally`;
interrupted probe aliases are removed before the next capture.

Public artifacts are stored under the app's external `files/attestation-probe/`
directory and can be retrieved by the remote lab's file tool/ADB or through
**Export latest ZIP**, which opens Android's document picker. Each successful
provider export contains its original certificate bytes, a PEM chain in provider
order, public SPKI, and, when signing succeeds, an ECDSA/SHA-256 signature over
`challenge.bin`. The report records leaf/public-key matching and local signature
verification results, model/API/provider metadata, SHA-256 certificate/SPKI
hashes, errors and key-deletion status. It also reads Huawei shared-library and
permission metadata without requesting that permission. An unavailable provider
means activation/provisioning is unknown, not that hardware is unsupported. It does not read
serial numbers, IMEI, phone accounts, installed apps, wallet data or credentials.

Capture is not proof of hardware backing. Verify the original chain signatures,
independently trusted root, revocation, challenge, app identity, key properties
and boot state using the canonical verifier outside the phone. A software
attestation returned by a platform provider remains diagnostic evidence only.

Local unit tests cover challenge and export encoding. An APK build or those
tests do not establish device compatibility; real remote-device capture remains
necessary.
