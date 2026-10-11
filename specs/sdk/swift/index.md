---
title: Iroha Swift SDK Overview
summary: Landing page for installing IrohaSwift, running the quickstart, and understanding the Norito pipeline/connect helpers referenced by IOS2/IOS5 roadmap tasks.
---

# Iroha Swift SDK

The Swift SDK (IrohaSwift) targets iOS and macOS clients that require deterministic
Norito encoding, `/v1/pipeline` submission, and the Connect/WebSocket surfaces used in
Sora Nexus. SwiftPM (`IrohaSwift/Package.swift`) is its sole supported packaging
path and requires the authenticated NoritoBridge XCFramework.

## Installing IrohaSwift

The package formerly published under ad-hoc names has been renamed to `IrohaSwift`.
First-release consumers must select the immutable `0.1.0` release rather than a
moving branch.

These remote coordinates are release targets, not evidence that the tags are
already public. Keep public installation instructions behind the release gate
until the canonical signed monorepo `v0.1.0` tag, immutable NoritoBridge release
asset, reviewed package source, and ordinary Release package consumer are
verified. The separate `hyperledger/iroha-swift` SwiftPM repository and its
`0.1.0` tag are an additional
external publication target; the monorepo tag does not publish them. Local
development uses the relative package path.

- **Xcode SPM UI:** `File → Add Package Dependencies…` →
  `https://github.com/hyperledger/iroha-swift` (select exact version `0.1.0`) →
  add the `IrohaSwift` product to your targets.
- **`Package.swift`:**

  ```swift
  dependencies: [
      .package(
          url: "https://github.com/hyperledger/iroha-swift",
          exact: "0.1.0"
      )
  ],
  targets: [
      .target(
          name: "DemoApp",
          dependencies: [
              .product(name: "IrohaSwift", package: "iroha-swift")
          ]
      )
  ]
  ```

When developing from a checked-out workspace you can keep using the relative path variant
(`.package(name: "IrohaSwift", path: "../../IrohaSwift")`) to avoid fetching over the
network.

### Bridge delivery and platform minimums
- Toolchain/platform: SwiftPM supports iOS 15+ and macOS 12+ with Swift 5.9+.
- Bridge: authenticate the XCFramework ZIP and materialize it with its embedded
  manifest under ignored `dist/` or the canonical external directory selected
  by `MOBILE_SDK_APPLE_ARTIFACT_DIR` before resolution. Reviewed external builds
  require `MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT=1`. `IrohaSwift/VERSION`
  owns the package, tag and archive SemVer. Validate the archive consumer and an
  ordinary public `IrohaSwift` dependency in Release with native execution and
  no unsafe linker flags. Public installation and signed publication evidence
  remain release requirements; host/simulator checks do not qualify a device.
- Policy: the bridge is mandatory. Package resolution fails when `dist/NoritoBridge.xcframework` is absent or incomplete; runtime `bridgeUnavailable`/`nativeBridgeUnavailable` errors identify a broken or unloaded required artifact rather than selecting a Swift-only codec fallback.

## Quickstart

```swift
import IrohaSwift

let torii = ToriiClient(baseURL: URL(string: "http://127.0.0.1:8080")!)
var sdk = IrohaSDK(baseURL: torii.baseURL)

let keypair = try Keypair.generate()
let accountId = AccountId.make(publicKey: keypair.publicKey)

let transfer = TransferRequest(
    chainId: "00000000-0000-0000-0000-000000000000",
    authority: accountId,
    assetDefinitionId: "66owaQmAQMuHxPzxUN3bqZ6FJfDa",
    quantity: "1.23",
    destination: accountId,
    description: "demo",
    ttlMs: 60_000
)

if #available(iOS 15.0, macOS 12.0, *) {
    Task {
        let balances = try await torii.accountAssets(of: accountId).page(ToriiListQuery())
        print("balances", balances.items)

        let status = try await sdk.submitAndWait(transfer: transfer, keypair: keypair)
        print("pipeline status", status.content.status.kind)
    }
}
```

`TransferRequest`, `MintRequest`, and `BurnRequest` require canonical unprefixed
Base58 asset-definition IDs.

## SM2 Cryptography

`Sm2Keypair` wraps the NoritoBridge SM2 helpers so Swift clients can derive
deterministic keys from seeds, compute canonical multihashes, and sign or verify
messages without reimplementing the algorithm. When the bridge is not linked the
APIs surface `Sm2Error.bridgeUnavailable`.

```swift
let seed = Data("iroha-rust-sdk-sm2-deterministic-fixture".utf8)
let pair = try Sm2Keypair.deriveFromSeed(distid: "iroha-sdk-sm2-fixture", seed: seed)

let message = Data("swift sm2 demo".utf8)
let signature = try pair.sign(message: message)

print("prefixed multihash", try pair.publicKeyPrefixed())
print("SM2 ZA", try pair.computeZA().map { String(format: "%02X", $0) }.joined())

if try pair.verify(message: message, signature: signature) {
    print("signature verified")
}
```

Use `Sm2Keypair.defaultDistid()` to query the runtime default distinguishing
identifier and `Sm2Error.invalidKeyLength`/`invalidSignatureLength` guards when
marshalling raw buffers. The canonical fixture in `fixtures/sm/sm2_fixture.json`
is reused by Rust, Python, JavaScript, and Swift; CI enforces parity via
`ci/check_sm2_sdk_fixtures.sh`.

## Pipeline Submission & Polling

- `submitAndWait` performs `POST /v1/pipeline/transactions` and polls
  `/v1/pipeline/transactions/status` until the transaction reaches authoritative finality.
- The primary binary submitter validates one canonical V1 versioned signed transaction before
  network access and accepts only HTTP `202` as admission success.
- A `404` from `/v1/pipeline/transactions/status` means Torii has no cached status yet
  (for example after a restart); the Swift SDK treats this as "pending" and keeps polling.
- `pollPipelineStatus` monitors a hash that may have been submitted by another SDK or CLI.
- `PipelineStatusPollOptions` configures only polling interval, timeout, and max attempts.
  Only global, state-resolved `Applied` with a positive height succeeds; state-resolved
  `Rejected`/`Expired` fail, and every queue/cache hint remains pending.
- `PipelineSubmitOptions` controls only the optional idempotency key for a single transaction
  submission attempt. The SDK rejects redirects and never retries signed bodies after
  transport failures or HTTP errors; reconcile ambiguous outcomes through the transaction
  hash/status route.
- Pipeline submission and status always use the first-release `/v1/pipeline/*` routes;
  there is no endpoint or finality-policy selector.
- Completion-based APIs return a `Task<Void, Never>` so callers can cancel outstanding
  polls from UI layers.
- The `NoritoDemoXcode` sample ships with the pipeline helpers enabled out of the box; it
  surfaces live status transitions (`Queued`, `Approved`, etc.) while polling.
- CI smoke coverage for the XcodeGen template and SwiftUI demos runs via
  `ci/check_swift_samples.sh`; see `specs/sdk/swift/swift_sample_smoke_tests.md`
  for destinations, skips, and DerivedData paths used in IOS5 sample gates.
- Roadmap owners can follow the end-to-end adoption runbook in
  [`pipeline_adoption_guide.md`](pipeline_adoption_guide.md), which documents the
  retry/idempotency knobs, evidence capture expectations, and telemetry hooks that gate
  IOS2-WB2.

## Norito RPC helper

Roadmap item **NRPC-3B** adds a Swift helper that mirrors the JavaScript
`NoritoRpcClient`. Use it when you need direct access to the binary
`application/x-norito` endpoints (submitters, manifests, or future RPC
extensions) without re-implementing header logic or timeout plumbing.

```swift
import IrohaSwift

let session = URLSession(configuration: .ephemeral)
let rpc = NoritoRpcClient(
    baseURL: URL(string: "https://torii.dev.sora.net")!,
    session: session,
    defaultHeaders: ["User-Agent": "SwiftNRPC/1.0"],
    timeout: 10
)

let requestBody = try noritoEncode(typeName: "PipelineSubmitRequestV1",
                                   payload: Data(pipelineBytes))

if #available(iOS 15.0, macOS 12.0, *) {
    Task {
        let response = try await rpc.call(
            path: "/v1/pipeline/submit",
            payload: requestBody,
            params: ["dry_run": "false"]
        )
        // `response` contains the binary Norito payload returned by Torii.
        print("submit response bytes:", response.count)
    }
}
```

Key facts:

- Accepts absolute or relative paths and handles query parameters/percent encoding.
- Defaults `Content-Type`/`Accept` to `application/x-norito`, with overrides/removal
  supported via the `headers` and `accept` parameters.
- Propagates per-call timeouts (seconds) and exposes the HTTP status/body via
  `NoritoRpcError` on non-2xx responses.
- Regression tests live in
  `IrohaSwift/Tests/IrohaSwiftTests/NoritoRpcClientTests.swift`.

### Caller-managed transaction archives

The SDK does not automatically queue, drain, or replay signed envelopes. Applications may
use `FilePendingTransactionQueue` as an explicit local archive, but must first reconcile an
ambiguous submission through `getTransactionStatus(hashHex:)` before making any later
submission decision.

`FilePendingTransactionQueue` stores base64-encoded JSON records (one per line) and works
well for iOS/macOS apps that can supply an Application Support path:

```swift
let archiveURL = FileManager.default
    .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("pending.queue")
let archive = try FilePendingTransactionQueue(fileURL: archiveURL)
try archive.enqueue(envelope)
```

This archive is storage only. The application remains responsible for inspecting and
removing entries, and no queue operation transmits bytes to Torii.

### KAGEMUSHA wallet

The KAGEMUSHA V1 aggregate-balance protocol, its Torii API (`/v1/kagemusha/*`)
and the Swift top-up, redemption and operation-lookup clients were deleted on
2026-10-05. The SDK keeps the wallet wire codec (`KagemushaWalletWireV1`), the
Apple platform adapters (`KagemushaWalletApplePlatformV1`,
`KagemushaWalletAppleAppAttestV1`, `KagemushaWalletAppleSystemV1`) and the
generic `IrohaPeer*` QR, NFC and Nearby carriers; see the
[wallet wire record](../../kagemusha_wallet_wire_v1.md) and the
[design](../../kagemusha_single_design_proposal.md). Offline UI and peer handoff
must remain available without any network discovery call.

## SoraFS orchestrator client

`SorafsOrchestratorClient` wraps the same native Norito bridge used by the CLI parity harness, making
it easy to rerun multi-provider fetches without shelling out to `sorafs_cli`. The async API returns
both the assembled payload bytes and the typed `SorafsGatewayFetchReport` structure:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let client = SorafsOrchestratorClient()
    Task {
        let parity = try await client.fetch(
            plan: orchestratorFixture.plan,
            providers: orchestratorFixture.providerSpecs(at: fixturesDir, payload: payloadBytes),
            options: SorafsGatewayFetchOptions(telemetryRegion: "ci")
        )
        print("provider reports", parity.report.providerReports)
    }
}
```

- `fetch(plan:providers:options:)` accepts strongly typed fixtures and `SorafsGatewayFetchOptions`.
- `fetchRaw(planJSON:providersJSON:optionsJSON:)` replays the canonical JSON blobs under
  `fixtures/sorafs_orchestrator/`.
- Both methods accept a `cancellationHandler` so UI layers can tear down inflight fetches when a task
  is cancelled.

See `IrohaSwift/Sources/IrohaSwift/SorafsOrchestratorClient.swift` and the parity suite
(`IrohaSwift/Tests/IrohaSwiftTests/SorafsOrchestratorParityTests.swift`) for reference usage.

### DA manifest + proof-of-availability helpers

`ToriiClient.getDaManifestBundle(storageTicketHex:)` calls `/v1/da/manifests/{ticket}` and returns the
canonical manifest bytes, decoded Norito JSON, and chunk plan (`ToriiDaManifestBundle`). Pair it with
`ToriiClient.fetchDaPayloadViaGateway(...)` to mirror the `iroha app da prove-availability` flow inside Swift:

```swift
let torii = ToriiClient(baseURL: toriiURL)
let manifest = try await torii.getDaManifestBundle(storageTicketHex: ticketHex)
let providers = [
    try SorafsGatewayProvider(
        name: "gw-usw2",
        providerIdHex: "<provider hex>",
        gatewayPublicKeyHex: "<gateway Ed25519 public key hex>",
        baseURL: URL(string: "https://gateway-usw2.example")!,
        streamTokenB64: creds.streamTokenB64
    )
]
let session = try await torii.fetchDaPayloadViaGateway(
    manifestBundle: manifest,
    providers: providers,
    options: SorafsGatewayFetchOptions(telemetryRegion: "us-west-2")
)
print("assembled bytes", session.gatewayResult.payload.count)
print("scoreboard", session.gatewayResult.report.scoreboard ?? [])
print("telemetry region", session.gatewayResult.report.telemetryRegion ?? "<unset>")

The `telemetryRegion` mirrors the CLI’s `--telemetry-region` flag so evidence bundles and
scoreboard metadata line up between Swift and the Rust tooling.
```

`fetchDaPayloadViaGateway` accepts either a storage ticket (it will refetch the manifest) or a cached
`ToriiDaManifestBundle`, derives the chunker handle automatically, and reuses `SorafsOrchestratorClient`
under the hood. The helper returns `ToriiDaGatewayFetchResult`, which exposes the manifest metadata,
chunk plan JSON, final payload bytes, and the orchestrator report so SDKs can persist the same evidence
bundle as the CLI. See `ToriiClientTests` for regression coverage.

When `proofSummaryOptions` are supplied the client invokes the native bridge’s
`connect_norito_da_proof_summary` helper and decodes the JSON into a typed `ToriiDaProofSummary` /
`ToriiDaProofRecord` structure. This mirrors the `iroha app da prove-availability` output (hashes, offsets,
per-proof Merkle paths) without forcing apps to parse raw JSON. Options control sampling (`sampleCount`,
`sampleSeed`) and can force specific leaf indexes for deterministic tests. The proof engine is provided by
`NativeDaProofSummaryGenerator` by default, but a custom `DaProofSummaryGenerating` implementation can be
injected for mocks or pre-computed summaries:

```swift
let summaryOptions = ToriiDaProofSummaryOptions(sampleCount: 2, sampleSeed: 0xDEADBEEF)
let session = try await torii.fetchDaPayloadViaGateway(
    manifestBundle: manifest,
    providers: providers,
    proofSummaryOptions: summaryOptions
)
if let summary = session.proofSummary {
    print("blob hash", summary.blobHashHex)
    print("first proof leaf bytes", summary.proofs.first?.leafBytes.count ?? 0)
}
```

#### Proof summary artefacts

`ToriiDaProofSummaryArtifact` converts a `ToriiDaProofSummary` (from `fetchDaPayloadViaGateway` or a
direct `NativeDaProofSummaryGenerator` call) into the Norito JSON bundle emitted by
`iroha app da prove-availability`. Pair it with `DaProofSummaryArtifactEmitter.emit(...)` to optionally write
the artefact to disk while still receiving the parsed struct for post-processing:

```swift
let summary = try NativeDaProofSummaryGenerator.shared.makeProofSummary(
    manifest: manifest.manifestBytes,
    payload: session.gatewayResult.payload,
    options: ToriiDaProofSummaryOptions(sampleCount: 2)
)
let proofResult = try DaProofSummaryArtifactEmitter.emit(
    summary: summary,
    manifestPath: "artifacts/manifest.json",
    payloadPath: "artifacts/payload.bin",
    outputURL: URL(fileURLWithPath: "/tmp/proof_summary.json")
)
print("proofs emitted", proofResult.artifact.proofCount)
```

When a summary is not available yet, pass the manifest/payload bytes plus optional sampling options and
the emitter will invoke `NativeDaProofSummaryGenerator` (or any injected `DaProofSummaryGenerating`
implementation) before returning the artefact:

```swift
let generated = try DaProofSummaryArtifactEmitter.emit(
    manifestBytes: manifest.manifestBytes,
    payloadBytes: session.gatewayResult.payload,
    proofOptions: ToriiDaProofSummaryOptions(sampleCount: 4, sampleSeed: 0),
    outputURL: nil    // skip writing to disk, work with the in-memory artefact
)
```

The emitted JSON mirrors the CLI schema (`manifest_path`, `blob_hash`, `proofs[].leaf_bytes_b64`, etc.),
so Swift automation can archive PoR evidence alongside the orchestrator reports without shelling out to
the CLI.

### DA ingest submission

`ToriiClient.submitDaBlob(_:)` mirrors `iroha app da submit`, building the Norito request body, signing it,
posting to `/v1/da/ingest`, and decoding the receipt. Use `ToriiDaBlobSubmission` to describe the payload,
erasure profile, retention policy, optional metadata, and signing material:

```swift
var submission = ToriiDaBlobSubmission(
    networkId: networkId,                       // exact genesis-derived NetworkId
    owner: authorityI105,                       // canonical authenticated AccountId
    payload: payloadData,
    laneId: 42,
    epoch: 7,
    sequence: 1,
    metadata: [
        ToriiDaMetadataEntry(key: "da.stream", value: Data("taikai".utf8))
    ],
    clientBlobId: digest32Data,              // 32-byte digest (BLAKE3 recommended)
    privateKeyHex: signerHex,
    codec: "application/octet-stream"
)
let ingest = try await torii.submitDaBlob(submission)
print("status:", ingest.status, "duplicate:", ingest.duplicate)
if let receipt = ingest.receipt {
    print("storage ticket", receipt.storageTicketHex)
}
```

`ToriiDaBlobSubmission` defaults match the CLI (chunk size 256 KiB, RS 12/10 profile, `da.default`
retention tag). When the NoritoBridge XCFramework is linked the builder hashes the payload with BLAKE3
automatically, but environments without the bridge must still provide a 32-byte `clientBlobId`
(the CLI’s `blake3(payload)` output matches). Signers can pass a raw Ed25519 seed (`privateKey`),
hex string (`privateKeyHex`), or a pre-computed `signatureHex` +
`signerPublicKeyHex`. The builder always produces a signed request, including
for `noSubmit` artifact preparation. Its digest binds the exact `NetworkId`,
canonical owner controller bytes, lane/epoch/sequence, canonical payload BLAKE3
commitment and length, and the complete request-content commitment. Metadata
entries accept raw `Data` values with visibility/encryption flags so the JSON
matches Torii’s Norito schema. The builder always emits `compression` and the
nullable `norito_manifest` slot; absence is represented by explicit `null`.

`submitDaBlob` returns `ToriiDaIngestSubmitResult` which exposes the acceptance status, the optional
`ToriiDaIngestReceipt` (decoded digests, queued timestamp, operator signature, `rentQuote` micro values),
the `sora-pdp-commitment` response header, and the signing artefacts (client blob id, payload hash, signer, signature)
that were sent to Torii. Receipt decoding requires the current PDP, stripe-layout,
and rent slots and rejects unknown receipt or stripe fields.

## Hardware Acceleration

`AccelerationSettings` carries the canonical native process policy. SIMD, Metal
and CUDA default on, while device qualification determines availability. Optional
unsigned counts inherit defaults only when absent; zero is explicit. Concrete
`AccelerationResourceLimits` bound process resources separately from transaction
execution memory. The raw C/Swift resource record contains ten `UInt64` fields;
the native reader checks platform widths, including the `u32` discovery bound.

```swift
let policy = try AccelerationSettingsLoader.load(
    configurationURL: configurationURL,
    bundle: .main
)
let accepted = policy.apply()
sdk.accelerationSettings = policy
```

The loader reads the explicit URL, then bundled `acceleration.{json,toml}` or
`client.{json,toml}` files, then defaults if no file exists. It does not consume
runtime environment policy. Present malformed files throw. Node configuration
uses the root `accel` section and `[accel.resource_limits]` TOML table. Table and
key components may be quoted and contain surrounding whitespace. Dotted and inline
acceleration assignments are rejected explicitly; use the named tables. The retired
`acceleration` alias is rejected. Dedicated `fromJSON` accepts a direct policy
record. `apply()` reports whether the available native owner accepted the request;
it does not certify device availability or resource growth. SDK settings retain
the requested policy, while native readback reports applied policy.

Call `AccelerationSettings.runtimeState()` when exporting telemetry so dashboards can
record whether Metal/CUDA backends were detected, configured, and healthy on the host
that produced each evidence bundle:

```swift
if let runtime = AccelerationSettings.runtimeState() {
    telemetryEmitter(.metalEnabled, runtime.metal.available)
    telemetryEmitter(.metalParity, runtime.metal.parityOK)
    telemetryEmitter(.cudaSupported, runtime.cuda.supported)
    if let reason = runtime.metal.lastError {
        telemetryEmitter(.metalDisableReason, reason)
    }
}
```

The helper reports both the applied configuration and runtime flags (supported,
configured, available, parity) plus the backend disable/error message surfaced by
the Rust bridge. It returns `nil` when the Norito bridge is unavailable so unit tests
and CLI tools can remain portable; the Swift bridge frees the FFI buffers once the
strings are copied so callers do not need manual cleanup.

## Telemetry & Redaction Readiness

- `specs/sdk/swift/telemetry_redaction.md` — outlines the IOS7/IOS8 telemetry
  redaction plan, signal inventory, governance artefacts, and the hashing/bucketing rules
  that keep Swift observability in lockstep with Rust and Android.
- `dashboards/data/swift_schema.sample.json` — sample schema snapshot for the new signal
  inventory; `dashboards/data/mobile_parity.sample.json` now includes the `telemetry`
  block consumed by `swift_status_export.py` and `scripts/render_swift_dashboards.sh`. Use
  `scripts/swift_collect_redaction_status.py` + `scripts/swift_enrich_parity_feed.py` to automatically
  inject salt/override data, and manage manual overrides via
  `python3 scripts/swift_status_export.py telemetry-override …`.
- `specs/sdk/swift/telemetry_chaos_checklist.md` — scenario checklists for override/salt
  rehearsals so telemetry alerts stay validated ahead of IOS7 council gates.

## Release & Reproducibility

- `specs/sdk/swift/reproducibility_checklist.md` — step-by-step evidence bundle
  for IOS8 releases covering Norito fixtures, `make bridge-xcframework`, dashboard feeds,
  and checksum capture so auditors can replay Swift SDK builds.

## Support & SLA Playbook

The IOS8 roadmap requires a published support policy before partner pilots can move
forward. The [Swift SDK Support Playbook](support_playbook.md) documents the ownership
matrix, severity/SLA expectations, release gating artefacts, telemetry/chaos drills, and
partner communication flow so Release, Docs, SRE, and Support share a single checklist
for pilots, GA, hotfixes, and LTS maintenance windows.

## Connect & WebSockets

`ConnectClient`, `ConnectFrames`, and `ConnectSession` expose the WalletConnect-style
flows used by Nexus. Frames now require the native Norito bridge for encode/decode and
fail closed with `ConnectCodecError.bridgeUnavailable` when the XCFramework is missing.
See `ConnectClientTests` for usage.

`ConnectCrypto` provides NoritoBridge-backed helpers for Connect X25519 key generation,
public-key derivation, and directional symmetric key output. When the bridge is not
linked these helpers raise `ConnectCryptoError.bridgeUnavailable`.

After the approval handshake, call `ConnectSession.setDirectionKeys(_:)` with the derived
keys to decrypt ciphertext frames automatically. Use `ConnectSession.nextEnvelope()` when
you need the full decrypted payload (sign results, encrypted controls), or
`ConnectEnvelope.decrypt(frame:symmetricKey:)` for manual inspection.

### Session identifiers & directional keys

- Use `ConnectCrypto.deriveSessionID(networkID:appPublicKey:nonce:)` for the exact SID
  derivation `BLAKE2b-256("iroha-connect|sid|" || NetworkId_bytes || app_pk || nonce16)`.
  `ToriiClient.createConnectSession` sends all four identity fields and rejects a response
  that substitutes any of them.
- `ConnectCrypto.deriveDirectionKeys(localPrivateKey:peerPublicKey:sessionID:)` expands the X25519 secret via
  the bridge-backed HKDF (`iroha-connect|k_app` / `iroha-connect|k_wallet` labels) so
  both directions get a deterministic ChaCha20-Poly1305 key. Feed the resulting
  `ConnectDirectionKeys` into `ConnectSession.setDirectionKeys(_:)` immediately after the
  approval frame arrives.
- Wallets should persist the X25519 keypair via `ConnectKeyStore`: the default store
  writes to Application Support with an attestation bundle (SHA-256 of the public key,
  device label, created-at). Bridge-backed keys load automatically when you call
  `generateOrLoad(label:)`, and the returned attestation can be forwarded with approval
  frames. Integrity checks require canonical JSON ordering. Secure Enclave storage can be layered later by
  swapping the keystore backing.
- Queue/journal telemetry exports via `ConnectQueueJournal` + `ConnectQueueStateTracker`
  (see `ConnectQueueDiagnosticsTests`/`ConnectReplayRecorderTests`). Use
  `ConnectSessionDiagnostics.snapshot()` when wiring events into dashboards; evidence
  bundles can be emitted with `ConnectReplayRecorder.exportBundle`.
- You may bound local inbound work by passing `flowControl:` to `ConnectSession` or
  calling `setFlowControlWindow(_:)`. This limiter is strictly SDK-local and never
  serializes a Connect control frame.

### Flow control, journalling, telemetry

- Each direction maintains a 64-bit `sequence`; overflow fails the session before nonce
  reuse. Connect V1 has no `FlowControl`, `Resume`, or `Rotate` wire controls. Queue
  limiting, reconnect summaries, and key replacement are local application concerns.
- Journals now derive from `ConnectQueueStateTracker` and `ConnectSessionDiagnostics`.
  Call `ConnectQueueStateTracker.updateSnapshot` whenever queue depth or health changes,
  and `recordMetric(_:)` to append NDJSON rows (`metrics.ndjson`) so `iroha connect queue inspect`
  can summarise the telemetry bundle. When you need to export evidence, call
  `ConnectSessionDiagnostics.exportJournalBundle(to:)` and
  `ConnectSessionDiagnostics.exportQueueMetrics(to:)`—both methods copy the
  `state.json`, `app_to_wallet.queue`, `wallet_to_app.queue`, and `metrics.ndjson` files into
  a temporary directory alongside the Norito manifest expected by the CLI. Queue files are
  stream-parsed with a default cap of 32 records and 1 MiB per direction; oversize or truncated
  files raise `ConnectQueueError` instead of being loaded wholesale.
- Local diagnostics may record reconnect and queue summaries, but must not encode those
  summaries as Connect V1 controls.
- Use `ConnectSession.eventStream(filter:)` (iOS 15/macOS 12+) to iterate `ConnectEvent`
  values directly, or `eventsPublisher(filter:)` when you need a Combine pipeline for SwiftUI.
  The payloads cover sign requests/results, display prompts, control-close/reject envelopes,
  and the new `ConnectBalanceSnapshot` payload emitted by `/v1/connect/ws`.
- `ConnectSession.balanceStream(accountID:)` / `balancePublisher(accountID:)` surface
  the Norito-provided balance snapshots. Each snapshot carries queue diagnostics sourced
  from `ConnectSessionDiagnostics`, so the SDK exports `connect.queue_*` metrics without
  additional plumbing and UI clients can render real-time queue depth/latency indicators.

### Additional guides
- See `connect_dev_quickstart.md` for end-to-end setup (SPM/Pods, bridge bundling, Connect lifecycle) and offline queue/journal recipes with bounded defaults and troubleshooting.
- See `offline.md` for detailed offline queue/journal flows (Connect, pipeline, wallet) and evidence/export steps.
- See `connect_samples.md` for sample project outlines (SwiftUI app + CLI harness) and testing tips.

For higher-level walkthroughs, see:

- the [public Swift SDK tutorial](https://docs.iroha.tech/guide/tutorials/swift.html)
  for application integration and Connect flows;
- `docs/norito_demo_contributor.md` for the source-adjacent SwiftUI demo setup,
  acceleration toggles, and telemetry tips.

## Torii REST Coverage

`ToriiClient` currently ships helpers for:

- **Accounts:** `getAssets`, `getTransactions` (both accept optional `assetId` filters),
  attachment upload/list/delete, trigger management, and general query envelopes. The
  `getExplorerAccountQr(accountId:)`
  helper wraps `/v1/explorer/accounts/{account_id}/qr` and returns the inline SVG, literal, and
  metadata defined in {doc}`sns/address_display_guidelines` so explorers can embed share-ready
  preferred i105 QR payloads without reimplementing the renderer
  (omit the format to use i105 or use canonical I105 output).
- **Explorer:** `getExplorerInstructions` and `getExplorerTransactions` wrap
  `/v1/explorer/instructions` and `/v1/explorer/transactions` with
  `ToriiExplorerInstructionsParams`/`ToriiExplorerTransactionsParams` filters (including
  optional `assetId` and `account` scoping). Fetch a single
  transaction with `getExplorerTransactionDetail(hashHex:)` or a single instruction with
  `getExplorerInstructionDetail(hashHex:index:)`. Use
  `getExplorerTransactionTransfers`/`getExplorerTransactionTransferSummaries` to derive transfer
  details for a single transaction (optionally filtering by `matchingAccount` or
  `assetDefinitionId`), or `streamTransactionTransferSummaries` for history+live streaming of a single
  transaction. For transfer history, use
  `getExplorerTransfers`/`getExplorerTransferSummaries` (support `matchingAccount`,
  and `assetDefinitionId` filters), or the convenience helpers
  `getAccountTransferHistory` (alias: `getTransactionHistory`) and `iterateAccountTransferHistory`
  (iOS 15/macOS 12+) which page instructions with `kind: "Transfer"` and emit UI-ready
  `ToriiExplorerTransferSummary` records.
  These helpers accept `assetDefinitionId` filters. Transfer summaries expose the canonical
  `assetDefinitionId` plus `transferIndex` to track the entry position within batch transfer
  payloads.
  Convenience flags `isIncoming`, `isOutgoing`, and `isSelfTransfer` assist with UI direction
  labels. Use `direction(relativeTo:)` and `counterpartyAccountId(relativeTo:)` to recompute
  direction or display counterparties for a different account; `isIncoming(relativeTo:)`,
  `isOutgoing(relativeTo:)`, and `isSelfTransfer(relativeTo:)` are available for quick checks.
  Use `signedAmount(relativeTo:)` when you need a +/‑ string for UI totals.
  Transfer summaries also conform to `Identifiable` with a stable
  `transactionHash|instructionIndex|transferIndex` identifier.
  Live updates are available via `streamExplorerInstructions` and `streamExplorerTransactions`
  (SSE, iOS 15/macOS 12+). Combine callers can use
  `explorerInstructionsPublisher`/`explorerTransactionsPublisher`. Use
  `streamExplorerTransfers`/`streamExplorerTransferSummaries` when you want transfer-only SSE feeds,
  and `explorerTransfersPublisher`/`explorerTransferSummariesPublisher` in Combine pipelines. These
  transfer stream helpers accept the same `matchingAccount`, `assetDefinitionId`, and `assetId`
  filters as the history helpers. Use
  `streamAccountTransferHistory` to emit historical transfer summaries and then keep streaming live
  updates without stitching the two flows manually; Combine callers can use
  `accountTransferHistoryPublisher`.

  Asset-definition helpers now target canonical unprefixed Base58 IDs and dotted aliases (`name#domain.dataspace` / `name#dataspace`). Asset-definition list/get/query responses may include `alias_binding { alias, status, lease_expiry_ms, grace_until_ms, bound_at_ms }`; alias selectors resolve against latest committed block time and stop resolving after grace, while direct reads can still report `expired_pending_cleanup` until sweep.
- **Collections:** `torii.domains`, `accounts`, `assetDefinitions`, `nfts`, `rwas`,
  `repoAgreements`, `transactions`, `accountAssets(of:)`, `assetHolders(of:)` and
  `accountTransactions(of:)` read every Torii collection with one
  [query language](../../torii/collection_queries.md): build a `ToriiListQuery` from a
  `ToriiFilter` (or filter text), sort keys, `select`, `limit` and `cursor`, then call
  `page(_:)` for one page or iterate `pages(_:)`/`items(_:)`, which follow `next_cursor`.
- **Contracts:** register/deploy/fetch manifest/code bytes.
- **Pipeline:** `submitTransaction` (exact V1 Norito envelopes, HTTP `202` only, returns the submission receipt payload, and
  enforces `data_model_version` from `/v1/node/capabilities` with
  `ToriiClientError.dataModelMismatch` on mismatch), `getTransactionStatus`, and recovery
  snapshots via `getPipelineRecovery(height:)`.
- **Network time:** `getTimeNow` for `/v1/time/now` snapshots.
- **Zero-knowledge:** attachment operations and verifying key registry read/event helpers (`getVerifyingKey`, `listVerifyingKeys`, `streamVerifyingKeyEvents`).
- **Confidential assets:** derive the wallet key hierarchy locally through `deriveConfidentialKeyset`, build memo envelopes with
  `ConfidentialEncryptedPayload`, and inspect rollout windows with
  `getConfidentialAssetPolicy(assetDefinitionId:)`, which wraps
  `GET /v1/confidential/assets/{definition_id}/transitions` and exposes pending transition
  metadata (transition id, conversion window, derived window-open height). Use
  `getConfidentialGasSchedule()` when you need the active verification multipliers that
  Torii reads from `confidential_gas` in `/v1/configuration`. The first-release Swift SDK
  deliberately exposes no generic shield, shielded-transfer, or unshield request,
  encoder, or submission helper.
- **Runtime & capabilities:** `getNodeCapabilities`, `getRuntimeMetrics`, `getRuntimeAbiActive`,
  `getRuntimeAbiHash`, `listRuntimeUpgrades`, and the helper trio
  (`proposeRuntimeUpgrade`, `activateRuntimeUpgrade`, `cancelRuntimeUpgrade`) mirroring the
  `/v1/node/capabilities` and `/v1/runtime/*` surfaces with typed instruction bundles.
- **Governance:** draft typed V1 deployment proposals
  (`submitGovernanceDeployContractProposal`), submit standalone plain/ZK
  ballots, fetch proposal/lock/tally snapshots, and inspect certificate-driven
  Parliament attempts. Deployment drafts bind typed 32-byte code/ABI hashes,
  numeric ABI version `1`, and optional manifest provenance; there are no
  proposal window/mode controls. V1 exposes no client finalize or enact path:
  Core creates the final certificate and executes its effect at the exact
  derived enactment height.

> **Roadmap ADDR-5a:** Account-aware helpers (`getAssets`, `getTransactions`, and the matching `IrohaSDK` wrappers) accept canonical I105 account literals and percent-encode `/v1/accounts/{account_id}/…` paths automatically.

Upcoming work (tracked under IOS3) includes additional query builders and
WebSocket/SSE subscribers shared with Android/JS.

### Rendering account addresses

Swift mirrors the Rust/JS/Python helpers via `AccountAddress`. When building wallet or explorer
UI, use the canonical format described in [`specs/sns/address_display_guidelines.md`](../../sns/address_display_guidelines.md):

```swift
let address = try AccountAddress.fromAccount(
    publicKey: Data(repeating: 0, count: 32)
)
let formats = try address.displayFormats(networkPrefix: 753)

print("i105", formats.i105)
```

Account addresses are domainless and accept no domain label or selector. Domain routing and account
aliases are explicit, separate records. Account addresses validate public key lengths for known
algorithms (ed25519 requires 32 bytes; secp256k1 requires 33 bytes when enabled), and reject empty
keys.

Show i105 as the copy/share target and QR payload. This keeps Swift parity with the Android/JS
samples and prevents IME corruption of half-width kana.

To embed the share-ready SVG exposed by ADDR-6b, call
`ToriiClient.getExplorerAccountQr(accountId:)` and reuse the inline payload:

```swift
let qr = try await torii.getExplorerAccountQr(
    accountId: formats.i105,
)
print("SVG payload", qr.svg)
```

## Verifying Key Registry

`ToriiClient` wraps `/v1/zk/vk/*` so wallets can inspect registry state without hand-rolling JSON:

```swift
if #available(iOS 15, macOS 12, *) {
    let detail = try await torii.getVerifyingKey(backend: "halo2/ipa", name: "vk_main")
    let idsOnly = try await torii.listVerifyingKeys(
        query: ToriiVerifyingKeyListQuery(backend: "halo2/ipa", idsOnly: true)
    )
    print("active:", detail.record.status, "ids:", idsOnly.map(\.id.name))
}
```

Mutation DTOs remain useful when you are assembling locally signed transactions, but the direct Torii register/update/deprecate helpers now fail closed instead of accepting embedded private keys. Build the verifier-management instructions locally, sign them with your wallet key, and submit the resulting transaction through the pipeline helpers.

Completion-style overloads still mirror the async read and event-stream helpers so UIKit/SwiftUI layers can cancel work if the user dismisses a flow mid-flight.


For proof verification outcomes, the proof event stream follows the same pattern:

```swift
if #available(iOS 15, macOS 12, *) {
    let proofs = torii.streamProofEvents(
        filter: ToriiProofEventFilter(backend: "halo2/ipa", proofHashHex: String(repeating: "a", count: 64))
    )

    Task.detached {
        do {
            for try await message in proofs {
                switch message.event {
                case .verified(let body):
                    print("verified:", body.id.proofHashHex)
                case .rejected(let body):
                    print("rejected:", body.id.proofHashHex)
                }
            }
        } catch {
            print("proof stream error:", error)
        }
    }
}
```

Trigger lifecycle updates are exposed through `streamTriggerEvents`:

```swift
if #available(iOS 15, macOS 12, *) {
    let triggers = torii.streamTriggerEvents(
        filter: ToriiTriggerEventFilter(triggerId: "nightly-tick")
    )

    Task.detached {
        do {
            for try await message in triggers {
                switch message.event {
                case .created(let id):
                    print("created", id)
                case .deleted(let id):
                    print("deleted", id)
                case .extended(let payload):
                    print("extended by", payload.delta)
                case .shortened(let payload):
                    print("shortened by", payload.delta)
                case .metadataInserted(let change):
                    print("metadata inserted", change.key)
                case .metadataRemoved(let change):
                    print("metadata removed", change.key)
                }
            }
        } catch {
            print("trigger stream error:", error)
        }
    }
}
```

Fine-tune the lifecycle events by flipping the `includeCreated`, `includeDeleted`,
`includeExtended`, `includeShortened`, `includeMetadataInserted`, and
`includeMetadataRemoved` switches on the filter. The verifying-key, proof, and
trigger helpers use the canonical live-only `/v1/events/sse` feed: they accept no
resume cursor, and reconnecting can leave a gap. Terminal `stream_error` events
are surfaced as typed stream failures instead of being treated as continuation
points.

## Fixture Parity

The authoritative transaction fixture corpus lives in `fixtures/norito_rpc/`.
Swift's `IrohaSwift/Fixtures/` directory is a generated descriptor-only mirror:
it contains `transaction_payloads.json` and
`transaction_fixtures.manifest.json`, not copies of the canonical `.norito`
payloads. Regenerate and verify before updating tests or dashboards:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/second-new-norito-rpc-publication
python3 scripts/check_swift_fixtures.py
make swift-ci
```

Require identical exact path sets, entry types, modes, completion manifests,
and every file byte between the two owner publications before applying the
reviewed identity-relative tracked patch. The owner
command renders the canonical corpus, Java's generated mirror, and the
descriptor-only Python and Swift mirrors as one publication.
There is no SDK-specific regeneration delegate. CI pipelines run
`ci/check_swift_fixtures.sh` to enforce descriptor parity automatically.
`make swift-ci` also validates the dashboard feeds; when running in CI ensure the
Buildkite agents expose `ci/xcframework-smoke:<lane>:device_tag` metadata so the rendered
summary identifies which simulator or StrongBox lane produced each result.

For cadence details and escalation procedures see:

- `specs/swift_fixture_cadence_pre_read.md` for the governance decision,
  rotation calendar, and SLA definition shared with Android/Python.
- `specs/sdk/swift/ios2_fixture_cadence_brief.md` for the operational
  brief that maps scheduled/event-driven/fallback runs to metrics, dashboards,
  and status reporting obligations.
- `specs/sdk/swift/fixture_regen_playbook.md` for the regeneration +
  rollback steps, owner-command evidence, and hand-off
  between rotation owners.

## Support & Operations

Operational expectations, SLAs, release evidence, and partner communication
flows now live in `specs/sdk/swift/support_playbook.md`. Review that
playbook before sharing pilot/GA builds so parity dashboards, telemetry
redaction policy, reproducibility proofs, and public documentation stay aligned with
`roadmap.md` (IOS8) and the weekly updates captured in `status.md`.
