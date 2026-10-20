# Android public attestation probe

Standalone Kotlin diagnostic for collecting fresh P-256 key attestation from
registered AndroidKeyStore and HwKeyStore JCA providers. It is independent of
wallet/native builds and is not an admission verifier. Missing providers and
failed attestation are recorded; there is no imported-key or software fallback.
No network, storage or device-identifier permissions are requested.

Generation requests signing-only EC secp256r1 with SHA-256 and the 32-byte
challenge. As with the canonical payment-key specification in
`kotlin/kagemusha-wallet-android`, it leaves authentication-related key-generation
setters unset. This diagnostic does not exercise payment confirmation or custody.

Build from the canonical checkout using the existing Gradle wrapper:

```sh
ANDROID_HOME="$HOME/Library/Android/sdk" kotlin/gradlew \
  --project-dir examples/android/attestation-probe \
  assembleDebug testDebugUnitTest --console=plain
```

Before building, put an independently chosen 32-byte public challenge as 64 hex
characters in `src/main/assets/public-challenge.hex` and record it separately
alongside the resulting APK hash. Launching
`org.hyperledger.iroha.samples.attestationprobe` automatically captures that
challenge once; changing the installed APK or bundled challenge causes a fresh
capture. Relaunching emits the saved automatic capture again. The editable
challenge and **Capture public attestation** button support additional manual
captures. These are diagnostic challenges, not wallet E1 requests.
The app does not request biometric authentication. Private keys
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
means activation/provisioning is unknown, not that hardware is unsupported.
Two explicit package-visibility declarations permit presence-only checks for
`com.google.android.gms` and `com.android.vending`. Each result is true, false,
or unknown on platform failure; it is local diagnostic evidence rather than
attested proof of the absence of Google services. There is no installed-app
enumeration. It does not read serial numbers, IMEI, phone accounts, wallet data or credentials.
Errors contain exception classes, without provider exception messages or stacks.

Every completed capture is also emitted under Logcat tag `IrohaAttestation`.
`IROHA_ATTESTATION BEGIN` and `END` repeat the capture ID, ZIP byte count, SHA-256,
and chunk count; indexed Base64 `CHUNK` lines contain at most 1,200 characters.
ZIPs over 256 KiB are refused. A `STATUS capture_started` or bounded `ERROR`
line distinguishes attempted capture from a test that never launched the app.
Retrieve the cloud lab's complete Logcat report and decode it with Python 3.10+:

```sh
python3 examples/android/attestation-probe/tools/extract_logcat.py \
  /path/to/logcat.txt /path/to/new-capture-directory
python3 -m unittest discover -s examples/android/attestation-probe/tools -p 'test_*.py'
```

The extractor accepts ordinary Logcat prefixes and identical repeated batches.
It rejects missing/conflicting frames, incorrect size/hash, unsafe ZIP members
and expanded contents over 1 MiB. Use `--capture-id` to select one capture when a
report contains other incomplete sessions. The output directory must be new.
Truncated cloud logs cannot establish a complete export, even if one marker is
visible. Transport checks establish only that the captured bytes are intact.

Capture is not proof of hardware backing. Verify the original chain signatures,
independently trusted root, revocation, challenge, app identity, key properties
and boot state using the canonical verifier outside the phone. A software
attestation returned by a platform provider remains diagnostic evidence only.

Local unit tests cover challenge, automatic-capture reuse and bounded export/recovery. An APK build or those
tests do not establish device compatibility; real remote-device capture remains
necessary.
