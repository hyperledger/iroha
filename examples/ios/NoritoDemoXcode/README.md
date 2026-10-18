# NoritoDemoXcode

`NoritoDemoXcode` is a reference SwiftUI wallet application that demonstrates how to
connect to an Iroha 3 Torii node, derive keys, and submit token transfers using the
`NoritoBridge` Swift bindings. The repository now includes the full Xcode project and
SwiftUI sources so contributors can open the demo without regenerating scaffolding.

## Project layout

```
NoritoDemoXcode/
├── Configs/
│   ├── SampleAccounts.json        # mock ledger bootstrap data
│   └── demo.env.example          # scheme environment template
├── NoritoDemoXcode/              # SwiftUI sources
│   ├── App.swift
│   ├── ContentView.swift
│   ├── Info.plist
│   └── NoritoBridgeKit.swift
├── NoritoDemoXcode.xcodeproj/    # pre-generated Xcode project
├── README.md
└── Scripts/
    └── generate-keys.sh          # convenience wrapper around the Rust key derivation flow
```

- `Configs/SampleAccounts.json` — example user accounts seeded in the mock ledger.
- `Configs/demo.env.example` — template for the scheme environment variables (Torii URL,
  Connect SID/token pairs, acceleration toggles).
- `NoritoDemoXcode/` — SwiftUI demo sources that showcase Connect WebSocket flows, Norito
  encryption helpers, and Metal/NEON acceleration hooks.
- `Scripts/generate-keys.sh` — helper for deriving new account keypairs using the Rust
  toolchain.

## Local build instructions

1. Open the repository on a macOS host.
2. Generate the authenticated XCFramework following
   [`docs/norito_bridge_release.md`](../../../docs/norito_bridge_release.md).
   Set `MOBILE_SDK_APPLE_ARTIFACT_DIR` to its absolute canonical artifact directory
   before invoking Xcode.
3. Copy `Configs/demo.env.example` to `.env` (or fill the same values directly inside the
   Xcode scheme). The app reads these variables on launch:
   - `TORII_NODE_URL` — base REST URL used for `/v1/connect` and `/v1/pipeline`.
   - `CONNECT_TOKEN_APP` / `CONNECT_TOKEN_WALLET` / `CONNECT_TOKEN_RELAY` — role and relay tokens returned by `/v1/connect/session`.
   - `CONNECT_NETWORK_ID` — exact canonical checksummed `NetworkId` bound into the SID and `Open` constraints.
   - The app generates a fresh app key and non-zero 16-byte nonce, derives the SID from those inputs, and rejects substituted session responses; an arbitrary SID cannot be configured.
   - `CONNECT_ROLE` — default role selected in the UI (`app` or `wallet`).
   - Optional helpers: `CONNECT_PEER_PUB_B64`, `CONNECT_SHARED_KEY_B64`,
     `CONNECT_APPROVE_ACCOUNT_ID`, `CONNECT_APPROVE_PRIVATE_KEY_B64`, `CONNECT_APPROVE_SIGNATURE_B64`.
4. Open `NoritoDemoXcode/NoritoDemoXcode.xcodeproj` in Xcode 15 or newer. The
   app and XCTest target already declare the repository-local `IrohaSwift` package.
5. Package admission validates the selected NoritoBridge artifact before building.
6. Select the `NoritoDemoXcode` scheme, assign an iOS simulator/device target, and load
   the environment variables via the scheme editor (`Edit Scheme → Run → Arguments`).
7. Build and run the project. The home screen confirms the Norito bridge status and
   exposes Connect session helpers once the framework is linked.

### Hardware acceleration

`NoritoDemoXcode/App.swift` loads a bundled `acceleration.{json,toml}` or
`client.{json,toml}` file at launch. The SDK also accepts an explicit file URL.
Use the canonical `[accel]` and `[accel.resource_limits]` tables; malformed present
configuration stops startup. When no file exists, SIMD, Metal and CUDA are enabled
with finite process resource ceilings. Unsupported or unqualified devices use CPU
execution. Explicit zero limits remain zero; omitted optional counts inherit the
native defaults. Runtime environment variables do not select acceleration policy.

### Pipeline submission walkthrough

`TransfersViewModel` calls `IrohaSDK.shared.submitAndWait(envelope:)`, which posts the
signed payload to `/v1/pipeline/transactions` and then polls
`/v1/pipeline/transactions/status` until the transaction reaches a terminal state. The
UI reflects intermediate states (`Queued`, `Approved`, etc.) so QA runs can confirm the
pipeline path end-to-end.
If the status endpoint returns `404` (Torii restart or cache miss), the SDK treats the
response as "pending" and keeps polling until a terminal status arrives.

## CI verification

- `scripts/ci/verify_norito_demo.sh` builds and tests the Xcode project on macOS. Override
  the simulator destination via `NORITO_DEMO_DESTINATION="platform=iOS Simulator,name=<sim>"`
  when the default `iPhone 15` device is unavailable. Set `NORITO_DEMO_SCHEME` if you need to
  target a non-default scheme and `NORITO_DEMO_DERIVED_DATA` to control where DerivedData is
  written (default: `artifacts/norito_demo_xcodebuild`). If no iOS simulators are installed,
  the script automatically falls back to the first available destination (for example
  `platform=macOS,arch=arm64,variant=Designed for [iPad,iPhone],name=My Mac`) before running
  the build; otherwise it skips gracefully when tooling or destinations are missing.
- The ordinary demo helper excludes `NativePrivacyPhysicalDeviceTests` and
  `KagemushaStoragePhysicalDeviceTests`. Run the native privacy
  class explicitly with `xcodebuild test` and a physical iOS device destination.
  All three native controls must execute with zero failures and zero skips; a
  simulator, unsigned build, or demo-helper success provides no physical evidence.
- The storage class exercises the current Swift adapter's actual Security/Secure Enclave
  and protected-file calls in a disposable app. It refuses simulator execution and app
  bundle identifiers outside `org.hyperledger.iroha.kagemusha.storage-probe.*`.
  Build the Debug test host with an authenticated current-source iOS XCFramework,
  `ENABLE_TESTABILITY=YES`, the actual signing team, and the literal build setting
  `PRODUCT_BUNDLE_IDENTIFIER=org.hyperledger.iroha.kagemusha.storage-probe.$(PRODUCT_NAME:rfc1034identifier)`
  so app and test bundle remain distinct. Select only
  `NoritoDemoXcodeTests/KagemushaStoragePhysicalDeviceTests` on the operator-selected
  physical device; never replace the selected device with an available simulator or another phone.
  Supply `KAGEMUSHA_STORAGE_PROBE_APP_ID_PREFIX` from the signed app's actual entitlement
  in the Test action environment (or the target's `EnvironmentVariables` dictionary in
  the generated `.xctestrun`). Its default `cycle` phase creates a random run, exercises
  pre-sign/final anchor acknowledgements and exact retained signature bytes through an
  adapter recreation, and removes only its own test key, anchor and directory.
  For process observations, supply one explicit UUID as `KAGEMUSHA_STORAGE_PROBE_RUN_ID`
  and run `KAGEMUSHA_STORAGE_PROBE_PHASE=prepare-selected`, `complete-release`, then
  `verify-release` in separate test-host processes. The later phases check prior process
  identifiers; `verify-release` cleans up. `cleanup` is an explicit recovery phase for
  an interrupted run. `observe-lock` after `prepare-selected` gives the operator 60 seconds
  to lock and 60 seconds to unlock; no observed lock means failure, never a skipped success.
  These probes use labelled opaque test anchor values and a disposable signature. They do
  not run Rust Advance or generate a Payment, prove App Attest enrollment, turn a process
  termination into power loss, or treat a developer file copy as supported stock restore.
  Preserve the `.xcresult`, exact source/artifact digests and actual device/OS identity
  with any result; complete native wallet and power/restore qualification remain separate.
- `ci/check_swift_samples.sh` wraps this helper and also builds/tests the XcodeGen template
  in `examples/ios/NoritoDemo` so CI can gate both demos in one step.

## Native enrollment probe

The separately selected `KagemushaEnrollmentPhysicalDeviceTests` consumes pinned
complete catalog/genesis inputs and the real Apple adapter in a disposable app.
Its live mailbox retains E1/E5/E6 originals and accepts external account signatures;
it contains no account signer, issuer or proof fallback. See the source-coupled
[probe interface](KagemushaEnrollmentProbe.md) for staging and recovery boundaries.
It is excluded from ordinary demo CI. The [monetary stage contract](KagemushaMonetaryProbe.md)
uses actual native operations and requires real externally supplied issuer/ledger
originals; no carrier or release qualification is implied.

## Torii + mock ledger integration

Use the automation in `scripts/ios_demo` (see the repository root README) to spawn a Torii
endpoint and a mock ledger that hosts the sample accounts. The SwiftUI demo connects to
this environment via the node URL defined in `demo.env.example`.

## Sample telemetry and logs

- Torii node logs are exported to `artifacts/torii.log`.
- Ledger state snapshots are emitted to `artifacts/ledger/` after each test run.
- Swift client logs can be tailed via the Xcode console or from the generated
  `DerivedData` path.
