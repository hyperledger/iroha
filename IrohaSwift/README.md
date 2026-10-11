# IrohaSwift

Swift SDK for the first Hyperledger Iroha 3 release on Apple platforms.

`TairaTestnetProfile` exposes the public Torii origin, address discriminant,
Digital Shekel, and XOR metadata. Its client factory still requires the current
deployment's genesis-derived `NetworkId`; the stable chain UUID is not used for
signing:

```swift
let networkId = try NetworkId(literal: configuredNetworkIdLiteral)
let torii = TairaTestnetProfile.makeClient(deployedNetworkId: networkId)
```

Features:
- Collection queries for every Torii collection: typed filter builder with canonical text and JSON forms, cursor pages and on-demand iteration, typed `{code, message, details}` errors
- Torii HTTP client (balances, transactions, explorer instructions/transactions/RWAs, subscriptions, VPN quote/session/receipt flows, pipeline recovery, time service, ZK attachments, contracts)
- KAGEMUSHA wallet V1 wire helpers (`KagemushaWalletWireV1`) and the iPhone platform adapter of the Rust wallet Advance provider (`KagemushaWalletApplePlatformV1`)
- Petal Stream animated optical transport: stream encoder/assembler, camera-frame decoder, software and vector renderers, SwiftUI player and AVFoundation camera analyzer
- Health & metrics helpers (fetch `/v1/health` text probe and `/v1/metrics` Prometheus/JSON payloads)
- Norito envelope encoder (header + CRC64-XZ)
- Required Native NoritoBridge integration (`dist/NoritoBridge.xcframework`) powering transfer/mint/burn builders and JSON inspection helpers
- Norito RPC HTTP helper (`NoritoRpcClient`) with binary header/query/timeout handling
- One-shot pipeline submission helpers (POST `/v1/pipeline/transactions` plus hash-bound status polling)
- Ed25519 signing with CryptoKit plus native-bridge secp256k1, ML-DSA-65, GOST R 34.10-2012, BLS normal/small, and SM2 support
- Confidential key derivation (`ConfidentialKeyset.derive`) mirroring the Rust HKDF so wallets can obtain `sk_spend`, `nk`, `ivk`, `ovk`, and `fvk` locally
- Runtime capability helpers (`ToriiClient.getNodeCapabilities`, `getRuntimeMetrics`, `getRuntimeAbiActive`) mirroring the Torii `/v1/node/capabilities` and `/v1/runtime/*` surfaces
- Verifying key registry read/mutation/event helpers (`ToriiClient.getVerifyingKey`, `listVerifyingKeys`, `registerVerifyingKey`, `updateVerifyingKey`, `streamVerifyingKeyEvents`) covering `/v1/zk/vk` operations

### Collection queries

Every Torii collection (domains, accounts, asset definitions, NFTs, RWA lots,
permissions, subscription plans, subscriptions, UAID manifests, account history, contract activity/events,
account assets, asset holders, account transactions, repo agreements) is read
with one query language and returns one page envelope; see
[`specs/torii/collection_queries.md`](../specs/torii/collection_queries.md).

```swift
import IrohaSwift

let torii = ToriiClient(
    baseURL: URL(string: "https://taira.sora.org")!,
    localSigningContext: ToriiLocalSigningContext(networkId: networkId),
    canonicalRequestAuth: canonicalAuth // optional; a signature only widens visibility
)

// One page, filtered and sorted. The filter renders to the canonical text
// `owned_by = "<account>" and quantity >= "10.5"`.
let minimum = try KotodamaQuantity("10.5")
let query = ToriiListQuery(
    filter: ToriiRwa.Fields.ownedBy == accountId && ToriiRwa.Fields.quantity >= minimum,
    sort: [ToriiRwa.Fields.quantity.descending, ToriiRwa.Fields.id.ascending],
    limit: 50,
    includeTotal: true
)
let page = try await torii.rwas.page(query)
print(page.items.map(\.id), page.total ?? 0, page.hasMore)

// Every row: each page is requested only when iteration reaches it, by
// following `nextCursor`. Breaking out or cancelling the task stops paging.
for try await balance in torii.accountAssets(of: accountId).items(ToriiListQuery(limit: 100)) {
    print(balance.asset, balance.quantity)
}

// Torii rejections carry the standard error envelope; invalid controls are
// rejected locally with the same codes before anything is sent.
do {
    _ = try await torii.assetDefinitions.page(ToriiListQuery(filterText: #"colour = "red""#))
} catch let ToriiClientError.api(error) where error.code == "invalid_filter" {
    print(error.message, error.details?.field ?? "", error.details?.hint ?? "")
} catch let ToriiClientError.invalidQuery(error) {
    print(error.code, error.message)
}

// Transaction history, newest first. History pages may hold fewer rows than
// `limit` (even none) while `nextCursor` is set; `items` keeps following it.
let recent = ToriiListQuery(
    filter: ToriiTransaction.Fields.blockHeight >= 1_200 && ToriiTransaction.Fields.resultOk == false,
    limit: 50
)
for try await transaction in torii.accountTransactions(of: accountId).items(recent) {
    print(transaction.blockHeight, transaction.blockIndex, transaction.entrypointHash)
}

// Event streams take the same text grammar; this one is filtered on Torii
// with `tx_hash = "<hash>"`.
for try await message in torii.streamTransactionStatusEvents(hashHex: envelope.hashHex) {
    print(message.event.status, message.event.rejectionCode?.rawValue ?? "")
}
```

- Collections: `domains`, `accounts` (with `get(_:)`), `assetDefinitions`, `nfts`,
  `rwas`, `repoAgreements`, `accountAssets(of:)`, `assetHolders(of:)`,
  `transactions` and `accountTransactions(of:)`. Each has `page(_:)`, `pages(_:)`
  and `items(_:)`. Rows are typed (`ToriiDomain`, `ToriiAccount`,
  `ToriiAssetDefinition`, `ToriiTransaction`, …) with quantities as exact
  `KotodamaQuantity` values. Only the fields that identify a row (`id`; account,
  asset, scope and quantity for balances; entrypoint hash and block coordinates
  for transactions) are guaranteed; every other field is optional, and unknown
  fields are ignored. Read `select` projections and aggregates with
  `page(_:as: ToriiJSONObject.self)`.
- Transaction history (`transactions`, `accountTransactions(of:)`) is read newest
  first by block height and index. `sort`, `includeTotal` and `aggregate` are
  rejected locally with Torii's codes. Bounds on `blockHeight` in the filter's
  top-level `&&` also bound Torii's history scan. `assetIds` and
  `assetDefinitionIds` are lists that match element-wise: `==`/`in` keep rows
  where any element matches, `!=`/`notIn` rows where none does.
- Torii executes each collection query once over caller-visible global state.
  For collections supporting totals and `POST` aggregates, visible rows contribute
  exactly once even when they span several dataspace routes.
- Filters: `ToriiField` operators (`==`, `!=`, `<`, `<=`, `>`, `>=`), `in`, `notIn`,
  `exists`, `isNull`, `isNotNull`, combined with `&&`, `||`, `!` or
  `ToriiFilter.all { ... }`; or pass text verbatim with `ToriiListQuery(filterText:)`.
  `description` is the canonical text form and `jsonData()` the canonical JSON form.
  Integers that fit `u64`/`i64` are numbers; decimals and wider integers are exact
  decimal strings (`KotodamaDecimal`, `KotodamaQuantity`, `ToriiFilterValue.decimal`).
  `Double` is deliberately not a filter literal. Object and array literals (only
  against `metadata.<key>`) exist only in the JSON form: they are sent with
  `POST /query`, and `queryItems()` and event streams reject them.
  `ToriiEventFields` lists the event-stream fields.
- Every read is `POST <collection>/query` with the canonical body
  (`ToriiListQuery.requestBody()`); `queryItems()` gives the equivalent `GET`
  parameters. Only the first page of an iteration asks for `include_total`.

### KAGEMUSHA wallet V1

The Swift SDK carries the client side of the KAGEMUSHA wallet V1 design
([proposal](../specs/kagemusha_single_design_proposal.md) §8, wire record
[kagemusha_wallet_wire_v1.md](../specs/kagemusha_wallet_wire_v1.md)). The Rust
module `iroha_data_model::kagemusha::kagemusha_wallet_v1` owns the canonical
objects, and the Rust wallet Advance provider
(`crates/iroha_core_zk/src/kagemusha_wallet_advance_v1`) owns custody, signing
and the monotonic clock.

`KagemushaWalletWireV1` consumes `fixtures/kagemusha/wallet_v1_vectors.json` and
mirrors only what an SDK needs before it hands bytes to the typed decoder: the
SHA-256 domain-separated digests (`digest(role:body:)`, `signedObjectDigest`), the raw
low-S P-256 signature rule, the canonical σ-field encoding check
(`isCanonicalFieldValue`), the envelope frame header with its per-kind bounds
(`inspectEnvelope`, `validateEnvelope`) and the strict `kgm1:` text form
(`encodeText`, `decodeText`). Poseidon values (`credit_id`, `proof_digest`, the
Payment digest, commitments, chains, roots and openings) are computed only by the
native Rust core; Swift carries them as opaque canonical σ-field values and never
recomputes them. Structural envelope checks carry no monetary or delivery
authority; typed decoding and verification of the message bodies remain open
(TODO(G4)).

`KagemushaWalletApplePlatformV1` is the iPhone platform adapter of the Rust wallet
Advance provider (Secure Enclave payment key, passcode-bound keychain rollback anchor,
protected-data canary and custody root); `KagemushaWalletAppleSystemV1.swift` holds
its replaceable operating-system seams. Construct it with the app's App ID prefix,
which names its own keychain access group. Its only app-facing operation is
`attestEnrollment(slot:paymentPublicKey:challengeDigest:)`, the App Attest evidence of
enrollment step E5; key use and the anchor are reached only through the Rust provider.
Registering the adapter with the native bridge remains open (TODO(G2-bridge)).

The DA read/proof surface is fully typed. Use `getDaProofPolicies`,
`listDaCommitments`, `proveDaCommitment`, `verifyDaCommitment`,
`listDaPinIntents`, `proveDaPinIntent`, and `verifyDaPinIntent`. Manifest and
storage-ticket query conveniences accept 32-byte hex, but encode the canonical
Norito JSON transparent-byte wrapper. Proof models preserve `UInt64` exactly
and reject malformed hash checksums, unknown fields, contradictory verification
results, and Merkle paths inconsistent with their bundle location. List calls
use typed forward-only cursors bound to an exact ledger-tip height and block
hash; pass the returned `nextCursor` into the next list request. Commitment and
pin-intent proof selectors are separate from list requests and do not accept
offset pagination.

## Installation

The current SDK ships in this repository under `IrohaSwift/`. Use the local
package from the same source revision as the Iroha node you target until the
signed first-release cut is promoted. The remote coordinates below are release
targets, not evidence that the tags are already public.

The bridge requires the four `soranet_mldsa_*` exports owned by
`crates/soranet_pq/include/soranet_pq.h`. Swift loads those current symbols
unconditionally; an incomplete native artifact fails admission.

Install the authenticated native release archive before resolving the package.
`scripts/validate_norito_bridge_archive.py --consumer` accepts an independently
trusted archive SHA-256 and full producing commit, verifies the clean matching
source checkout, headers, pins, lock, ABI and native slices, and installs into
an absent `dist/NoritoBridge.xcframework`. Consumer Macs need Python 3.10+ and
Apple command-line tools, without the producer's Rust toolchain or exact tool
binaries. See [consumer installation](../docs/norito_bridge_release.md#consumer-installation)
for the command and trust inputs. The signed public release remains unpromoted;
use an authenticated local candidate or build the bridge from source:

```bash
cd /path/to/iroha
export CARGO_TARGET_DIR=/absolute/non-symlink/path/to/iroha-apple-cargo
export NORITO_BRIDGE_OUT_DIR=/absolute/non-symlink/path/to/iroha-apple-artifacts
export NORITO_BRIDGE_BUILD_DIR=/absolute/non-symlink/path/to/iroha-apple-build
export NORITO_BRIDGE_ARCHIVE_OUTPUT=/absolute/non-symlink/path/to/NoritoBridge.xcframework.zip
mkdir -p \
  "$CARGO_TARGET_DIR" \
  "$NORITO_BRIDGE_OUT_DIR" \
  "$NORITO_BRIDGE_BUILD_DIR" \
  "$(dirname "$NORITO_BRIDGE_ARCHIVE_OUTPUT")"
test ! -e "$NORITO_BRIDGE_ARCHIVE_OUTPUT"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
unset RUSTC_BOOTSTRAP
export RUSTC="$(rustup which --toolchain 1.93.1 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.93.1 rustdoc)"
export MOBILE_SDK_PYTHON_BINARY=/absolute/path/to/python3.12
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
scripts/build_norito_xcframework.sh \
  --lockfile-path /absolute/non-symlink/path/to/reviewed-release-lock/Cargo.lock \
  --archive-output "$NORITO_BRIDGE_ARCHIVE_OUTPUT"
```

The build requires Python 3.12, stock Rust 1.93.1, and an explicit
`--lockfile-path`; `RUSTC_BOOTSTRAP` must be unset. Normal builds and release
qualification require a separately materialized, read-only external snapshot of
the same canonical reviewed graph. The root source lock and selected build lock
have independent file identities and equal authenticated bytes. These builds
reject in-tree or symbolic Cargo targets. Explicit local integration uses the
fixed checkout directories described below. A nonempty external isolated target
is supported; builds sharing that target or output are serialized by held locks,
and every Apple slice is freshly invoked. The archive owner requires the explicit
epoch, snapshots the complete authenticated generation under the output lock, and
atomically publishes a sorted ZIP with normalized modes and timestamps.

### Swift Package Manager (`Package.swift`)

The immutable first-release dependency is:

```swift
dependencies: [
    .package(
        url: "https://github.com/hyperledger/iroha-swift",
        exact: "0.1.0"
    )
]
```

For development against this checkout, use the source-adjacent package:

```swift
// Package.swift
dependencies: [
    .package(name: "IrohaSwift", path: "/path/to/iroha/IrohaSwift")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "IrohaSwift", package: "IrohaSwift"),
            .product(name: "IrohaSwiftMobileTransports", package: "IrohaSwift"),
            .product(name: "IrohaSwiftTransferUI", package: "IrohaSwift")
        ]
    )
]
```

Import only the products your application uses:

```swift
import IrohaSwift
import IrohaSwiftMobileTransports
import IrohaSwiftTransferUI
```

The host app, not SwiftPM, owns Apple privacy strings and entitlements. Add the
keys used by the rails you enable (replace only the human-readable strings):

```xml
<!-- Info.plist: needed only when the app captures QR with the camera. -->
<key>NSCameraUsageDescription</key>
<string>Scan a wallet transfer QR code.</string>

<!-- Info.plist: Google Nearby. Keep the Bonjour service exact. -->
<key>NSBonjourServices</key>
<array>
    <string>_F2EBA4BCB49B._tcp</string>
</array>
<key>NSBluetoothAlwaysUsageDescription</key>
<string>Discover a nearby device for a wallet transfer.</string>
<key>NSLocalNetworkUsageDescription</key>
<string>Exchange a wallet transfer with a nearby device.</string>

<!-- Info.plist: Core NFC reader mode. Keep the AID exact. -->
<key>NFCReaderUsageDescription</key>
<string>Exchange a wallet transfer over NFC.</string>
<key>com.apple.developer.nfc.readersession.iso7816.select-identifiers</key>
<array>
    <string>F0504B45504B524E464301</string>
</array>
```

Reader builds also need the Near Field Communication Tag Reading capability,
which produces this entitlement:

```xml
<key>com.apple.developer.nfc.readersession.formats</key>
<array>
    <string>TAG</string>
</array>
```

Receiver/CardSession builds additionally require an Apple-provisioned HCE
profile containing the following entitlements. Do not make CardSession a
runtime fallback: require iOS 17.4 or newer and proceed only when
`IrohaPeerNfcCardSessionControllerV1.availability(...)` reports an eligible
device.

```xml
<key>com.apple.developer.nfc.hce</key>
<true/>
<key>com.apple.developer.nfc.hce.iso7816.select-identifier-prefixes</key>
<array>
    <string>F0504B45504B524E464301</string>
</array>
```

#### NoritoBridge policy (SwiftPM)

`Package.swift` checks for `dist/NoritoBridge.xcframework` next to the repository root and fails package resolution when the bridge is missing. Runtime errors such as `ConnectCodecError.bridgeUnavailable` and `SwiftTransactionEncoderError.nativeBridgeUnavailable` include the same bridge-location hint for broken or unloaded bridge symbols.

The canonical XCFramework contains `ios-arm64`, the universal
`ios-arm64_x86_64-simulator` slice, and the universal
`macos-arm64_x86_64` slice. The macOS slice must contain both `arm64` and
`x86_64`; the artifact checker rejects single-architecture substitutions.

Every bridge build includes mandatory privacy support using stock
Rust 1.93.1. Building an artifact does not establish provider, proving, hardware,
or release qualification. To build with the reviewed external graph:

```bash
export CARGO_TARGET_DIR=/absolute/non-symlink/path/to/iroha-apple-cargo
export NORITO_BRIDGE_OUT_DIR=/absolute/non-symlink/path/to/iroha-apple-artifacts
export NORITO_BRIDGE_BUILD_DIR=/absolute/non-symlink/path/to/iroha-apple-build
mkdir -p \
  "$CARGO_TARGET_DIR" \
  "$NORITO_BRIDGE_OUT_DIR" \
  "$NORITO_BRIDGE_BUILD_DIR"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
unset RUSTC_BOOTSTRAP
export RUSTC="$(rustup which --toolchain 1.93.1 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.93.1 rustdoc)"
scripts/build_norito_xcframework.sh \
  --lockfile-path /absolute/non-symlink/path/to/reviewed-release-lock/Cargo.lock
```

Every Apple slice includes the mandatory privacy support and
records the fixed `privacy-production-enabled` provenance marker. There is no
enable/disable option. Provider, hardware, proving and release qualification
still require their respective evidence.
The builder always compiles all five target libraries into the one caller-selected target,
uses the explicitly selected `Cargo.lock`, and fails closed if `xcodebuild` cannot
package them. The validator, Swift pin projector, and archive owner require the
same explicit `--lockfile-path`; omitted, symbolic, source-contained alternate,
and unreviewed external selections are rejected.

For integration inside this checkout, run the following from its canonical root.
Use the fixed ignored lane with owned, non-symbolic, mode `0700` directories. This explicit mode selects the root `Cargo.lock`
and accepts source changes with `--allow-dirty-source`; its artifacts carry
`artifact_scope=local-integration` and cannot be archived, handed off, or admitted
to a release build.

```bash
umask 077
bridge_local="$PWD/target/norito-bridge-local"
export CARGO_TARGET_DIR="$bridge_local/cargo"
export NORITO_BRIDGE_BUILD_DIR="$bridge_local/build"
export NORITO_BRIDGE_OUT_DIR="$bridge_local/artifacts"
mkdir -p "$CARGO_TARGET_DIR" "$NORITO_BRIDGE_BUILD_DIR" \
  "$NORITO_BRIDGE_OUT_DIR" "$bridge_local/projections"
chmod 0700 "$bridge_local" "$CARGO_TARGET_DIR" "$NORITO_BRIDGE_BUILD_DIR" \
  "$NORITO_BRIDGE_OUT_DIR" "$bridge_local/projections"
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_NET_OFFLINE=true
unset RUSTC_BOOTSTRAP MOBILE_SDK_REQUIRE_EXTERNAL_APPLE_ARTIFACT \
  IROHA_PRIVACY_RELEASE_CARGO_LOCKFILE_PATH
export RUSTC="$(rustup which --toolchain 1.93.1 rustc)"
export RUSTDOC="$(rustup which --toolchain 1.93.1 rustdoc)"
scripts/build_norito_xcframework.sh \
  --lockfile-path "$PWD/Cargo.lock" --local-integration --allow-dirty-source
export MOBILE_SDK_APPLE_ARTIFACT_DIR="$NORITO_BRIDGE_OUT_DIR"
```

A separate `MOBILE_SDK_LOCAL_UNIT_ARTIFACT_DIR` input may select a producer-validated
single-host macOS archive for debug unit tests. It requires genuine current-source
static capture, normalization, complete-archive native consumer checks, and the
explicit `local-unit` artifact schema. It retains every package test and exact
ABI-25 admission. It cannot be selected together with the external/release input;
iOS and Release compilation reject it. It is never accepted by the canonical
three-slice validator, pin owner, archive owner, or release publication.

The Apple pull-request lane preserves that build envelope while avoiding a
hosted-runner timeout: five isolated macOS jobs each build one attested target
library, and the sole Swift assembler accepts them only when their independent
archive digests and exact source, lock, toolchain, SDK, deployment-target, and
feature attestations all match. The assembler then produces the same three-slice
XCFramework and authenticated handoff used by the Swift lifecycle consumer.
Each attestation also retains its runner's Python, Git, and rustup evidence;
those orchestration tools may differ because they do not enter the hermetic
Cargo invocation.

CI runs `.github/workflows/mobile_sdk_artifacts.yml` to authenticate the exact
external Apple artifact, enforce mandatory missing-artifact rejection, run the
complete Swift suite, package the final ZIP, and validate SwiftPM consumers.
Release validation must include an ordinary application package that depends on
the public `IrohaSwift` product and executes native operations without unsafe
linker flags, as well as the packaged XCFramework ZIP consumer.

### SwiftPM delivery

SwiftPM is the sole supported Swift delivery path; CocoaPods support is retired.
`IrohaSwift/VERSION` owns the Swift package version, canonical `v<version>` tag,
and `NoritoBridge-v<version>.xcframework.zip` name. Materialize that authenticated
framework before resolving the path-based binary target. The package's ordinary
native export references preserve runtime symbol lookup without unsafe flags.
Public installation evidence requires the immutable asset, reviewed package
source, an installed Release consumer, and signed provenance (see
[`docs/norito_bridge_release.md`](../docs/norito_bridge_release.md)).

Usage:
```swift
import IrohaSwift

let toriiURL = URL(string: "https://torii.example")!
let sdk = IrohaSDK(baseURL: toriiURL)
let pqSDK = IrohaSDK(baseURL: toriiURL, defaultSigningAlgorithm: .mlDsa)
let gostSDK = IrohaSDK(baseURL: toriiURL, defaultSigningAlgorithm: .gost2012_256A)

// Generate a signing key using the SDK default (Ed25519 unless overridden)
let signingKey = try sdk.generateSigningKey()
let accountId = try AccountId.make(publicKey: try signingKey.publicKey())
let asset = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"

let walletToken = "<wallet-session-token>"
let networkId = try NetworkId(literal: configuredNetworkIdLiteral)
let feePayment = FeePaymentIntent.authority(chargeLimits: [], gasLimit: nil)
let toriiAuth = try ToriiClientAuthentication.bearerToken(
    walletToken,
    accountId: accountId,
    dataspaceId: "mibank.paynet"
)
let torii = ToriiClient(
    baseURL: toriiURL,
    authentication: toriiAuth,
    localSigningContext: ToriiLocalSigningContext(networkId: networkId)
)

// Account onboarding requires the dedicated route token explicitly. It remains
// separate from an optional global X-API-Token configured on the client. Plan,
// prepare, durably persist, and only then submit one exact envelope; no body
// contains a key or token.
// The bundled Norito bridge encodes the exact receipt body and verifies its
// domain-separated hash, exact genesis-derived network, and authority signature before
// prepare or submit.
// An older/missing bridge fails closed; JSON is never used as receipt hash input.
let onboardingIntent = try ToriiAccountOnboardingPlanRequest(
    alias: "merchant@paynet",
    accountId: accountId
)
// Persist this exact request with the workflow; every prepare, proof read, reopen,
// and submit requires it so a signed receipt cannot substitute the original intent.
let onboardingReceipt = try await torii.planAccountOnboarding(
    onboardingIntent,
    onboardingToken: routeToken,
    expectedAuthority: configuredOnboardingAuthority,
    expectedNetworkId: networkId
)
// Persist the caller's 64-character lowercase hexadecimal request ID across retries.
// It identifies this operation; it does not promise server-side deduplication.
let verifiedReceiptPlanHashHex = try ToriiAccountOnboardingReceiptVerifier.canonicalHash(
    canonicalBodyNorito: ToriiAccountOnboardingPlanBodyNorito.encode(onboardingReceipt.body)
).hexEncodedString()
let onboardingBinding = try ToriiPreparedOperationBindingV1(
    semanticHashHex: verifiedReceiptPlanHashHex,
    kind: .onboarding,
    requestId: persistedCallerRequestId,
    executionExpiresAtUnixMs: onboardingReceipt.body.validUntilMs
)
let onboardingPreparation = try await torii.prepareAccountOnboarding(
    onboardingReceipt,
    request: onboardingIntent,
    binding: onboardingBinding,
    feePayment: feePayment,
    onboardingToken: routeToken,
    expectedAuthority: configuredOnboardingAuthority,
    expectedNetworkId: networkId
)
switch onboardingPreparation {
case let .proofRequired(proof):
    // This result is nonterminal. After every prepare or reopen, obtain one
    // signed atomic observation before treating the original intent as satisfied.
    try JSONEncoder().encode(proof).write(to: onboardingProofURL, options: .atomic)
    let retained = try JSONDecoder().decode(
        ToriiAccountOnboardingProofRequiredPrepareResponseV1.self,
        from: Data(contentsOf: onboardingProofURL)
    )
    let verification = try await torii.verifyAccountOnboardingCurrentState(
        retained,
        request: onboardingIntent,
        receipt: onboardingReceipt,
        binding: onboardingBinding,
        expectedAuthority: configuredOnboardingAuthority,
        expectedNetworkId: networkId,
        canonicalAuth: canonicalAuth
    )
    print(verification)
case let .prepared(envelope):
    // The coordinator must persist these exact bytes before the first submit.
    try JSONEncoder().encode(envelope).write(to: onboardingEnvelopeURL, options: .atomic)
    let retained = try JSONDecoder().decode(
        ToriiAccountOnboardingPreparedTransactionV1.self,
        from: Data(contentsOf: onboardingEnvelopeURL)
    )
    let outcome = try await torii.submitPreparedAccountOnboarding(
        retained,
        expectedFeePayment: feePayment,
        request: onboardingIntent,
        onboardingToken: routeToken,
        expectedAuthority: configuredOnboardingAuthority,
        expectedNetworkId: networkId
    )
    // Treat Pending as nonterminal and reconcile this same retained hash.
    print(outcome.outcome)
}

// Faucet preparation is a separate child mutation and must happen only after
// onboarding is Applied. A ProofRequired result is nonterminal until one fresh
// atomic account-and-alias observation matches; rerun it after reopening
// durable state. Use a distinct `.faucet` binding/idempotency digest, persist
// the returned `ToriiAccountFaucetPreparedTransactionV1`, then pass those same
// bytes and this independently configured policy to both prepare and submit.
// A V1 claim always carries a positive direct PoW anchor height and nonempty
// canonical lowercase nonce hex; neither field has a null/optional form.
let faucetPolicy = try ToriiAccountFaucetPolicyV1(
    faucetAuthority: configuredFaucetAuthority,
    assetDefinitionId: configuredFaucetAssetDefinitionId,
    amount: try KotodamaQuantity(configuredFaucetAmount)
)
// `prepareAccountFaucet(..., policy: faucetPolicy, expectedNetworkId: networkId)`
// and `submitPreparedAccountFaucet(..., policy: faucetPolicy,
// expectedNetworkId: networkId)` reject authority, asset, amount, or fee-intent
// substitution before a retained envelope is submitted.

// Operator alias setup is plan-only on Torii. The wallet verifies the plan
// hash, its genesis-derived network identity, and byte-identical instruction
// frames, signs one ordinary transaction, and submits it through the existing
// pipeline endpoint.
let setupPlan = try await torii.planAliasSetup(setupRequest, canonicalAuth: canonicalAuth)
try await sdk.submitAliasSetupPlan(
    setupRequest,
    networkId: networkId,
    plan: setupPlan,
    bodyEncoder: encodeCanonicalAliasPlanBody,
    feePayment: feePayment,
    signingKey: signingKey
)

// Or opt into any native-bridge signing algorithm explicitly.
let pqSigningKey = try pqSDK.generateSigningKey()
let gostSigningKey = try gostSDK.signingKey(fromSeed: Data("seed".utf8))

// Read the account's balance of one asset (see "Collection queries")
let balances = try await torii.accountAssets(of: accountId).page(
    ToriiListQuery(filter: ToriiAccountAsset.Fields.asset == asset)
)
print(balances.items.map(\.quantity))

// List attachments published via the Torii app API
torii.listAttachments(canonicalAuth: canonicalAuth) { result in
    print("attachments:", result)
}

// Build and submit a signed transfer.
// `description` is not encoded yet; a non-empty one is rejected rather than dropped.
let transfer = TransferRequest(
    networkId: networkId,
    authority: accountId,
    assetDefinitionId: "66owaQmAQMuHxPzxUN3bqZ6FJfDa",
    quantity: "1.23",
    destination: "<destination_account_i105>",
    feePayment: feePayment,
    ttlMs: 60_000
)
let envelope = try sdk.buildSignedTransfer(transfer: transfer, signingKey: signingKey)
try await sdk.submit(envelope: envelope)

// Interleave canonical instruction frames and deployed-contract calls in one
// atomic transaction. All items share the signed gas limit.
let invocation = try TransactionContractInvocation(
    contractAddress: contractAddress,
    expectedCodeHash: expectedCodeHash,
    entrypoint: "apply",
    arguments: argumentRecord
)
let mixedEnvelope = try sdk.buildSignedExecutableBatch(
    networkId: networkId,
    authority: accountId,
    entries: [
        .instruction(registerFrame),
        .contractCall(invocation),
        .instruction(transferFrame),
    ],
    feePayment: .authority(chargeLimits: [], gasLimit: 500_000),
    signingKey: signingKey
)

// Query pipeline status if needed
torii.getTransactionStatus(hashHex: envelope.hashHex) { status in
    print(status)
}

// Await pipeline completion using the helper.
sdk.submitAndWait(envelope: envelope) { result in
    print("pipeline status:", result)
}
```

Executable batches must be non-empty. Contract-call entries require a positive
signature-bound gas limit and an exact lowercase V1 Bech32m contract address;
invalid payloads are rejected before signing.

### Cancel an asset lock with an exact state precondition

`CancelAssetLockInstructionV1` implements the first-release two-field
compare-and-cancel contract. The convenience initializer hashes exact,
nonblank lock-id text without surrounding whitespace or a BOM with native
Blake2b-256, sets Iroha's hash marker bit, and emits the checksummed `EscrowId`
literal. The preimage is bounded by
`CancelAssetLockInstructionV1.maxLockIdUTF8BytesV1` (4,096 UTF-8 bytes, not
characters), while the on-wire `EscrowId` remains 32 bytes. Internal bytes are
never trimmed or normalized. The expected remaining amount must use canonical
positive `Quantity` spelling:

```swift
let cancellation = try CancelAssetLockInstructionV1(
    lockId: "appeal-case-2048",
    expectedRemainingAmount: "250"
)
let instructionJSON = try cancellation.noritoJSON()
let instructionFrame = try cancellation.transactionInstructionFrame()
```

Use the `escrowId:` initializer when the exact canonical marked hash literal
comes from finalized ledger state. `noritoArchive()`, `decodeNoritoArchive(_:)`,
`decodeBareJSON(_:)`, and `decodeInstructionJSON(_:)` enforce the byte-canonical
two-field V1 shape. Missing `expected_remaining_amount`, zero or noncanonical
quantities, aliases, extra fields, malformed hash literals, legacy one-field
archives, and trailing bytes all fail closed. Old development state carrying
the retired one-field layout must be discarded and reseeded.

Lease renewal and native auto-renew use the same local-signing flow through
`planAliasLeaseRenewal`, `planAliasAutoRenew`, and
`submitAliasLifecyclePlan`. An exact auto-renew no-op returns without creating
or submitting an empty transaction. Visibility-aware reads are available as
signed or unsigned overloads of `resolveAccountAlias`,
`resolveAccountAliasIndex`, and `aliasesByAccount`; signed calls emit the
canonical Iroha account/signature/timestamp/nonce headers. Alias plan and
intent values never contain API tokens or private keys.
The default alias frame codec uses the bundled Rust instruction registry to
typed-decode and canonically re-encode every complete planner frame; an older
or missing bridge fails closed. Advanced callers may still inject an equivalent
registry codec for testing or alternate packaging.

Wallet-scoped Torii deployments commonly require the `Authorization`,
`X-Account-Id`, and `X-Dataspace-Id` headers on every request. Use
`ToriiClientAuthentication` or `defaultHeaders` on `ToriiClient` so the SDK
attaches those headers centrally instead of repeating them at each call site.
Credential-bearing headers are rejected over plain HTTP or host-mismatched
requests by the shared transport-security check.

`TransferRequest`, `MintRequest`, and `BurnRequest` expect
an exact genesis-derived `NetworkId` plus canonical unprefixed Base58
asset-definition IDs on the Swift surface. Human chain labels are display and
configuration values only and are never converted into a signing domain.

`IrohaSDK` validates the exact network identity and canonical account/asset
identifiers before signing and fails fast on malformed inputs. Override
`creationTimeProvider` when you need deterministic timestamps for fixture
generation or offline signing flows. `defaultSigningAlgorithm` controls the SDK
helpers used by `generateSigningKey()` / `signingKey(fromSeed:)`; `Keypair`
convenience APIs are Ed25519-only while native-backed algorithms use
`NoritoBridge`.

### Peer transport V1

The QR, NFC, and Nearby carriers (`IrohaPeerWireV1`, `IrohaPeerQRV1`,
`IrohaPeerNfcV1`, `IrohaPeerNearbyV1`, with the platform adapters in
`IrohaSwiftMobileTransports`) move complete KAGEMUSHA wallet V1 envelope frames
inside IPM1 messages ([kagemusha_wallet_wire_v1.md](../specs/kagemusha_wallet_wire_v1.md)
§6); no transport has a second codec. A carrier checks each frame only
structurally (`KagemushaWalletWireV1.inspectEnvelope`); its framing is outside every
digest and signature and grants no authority, so the wallet still performs typed
decoding and signature verification.

### Petal Stream optical transport

Petal Stream is the animated "streaming QR" in the Sakura-storm look: four
sakura-blossom finders, a `天`-shaped field of 256 katakana tiles and three
dotted rings. Each frame carries three independent lanes (tile polarity `P`,
katakana `K`, ring dots `D`), each one whitened Reed–Solomon codeword of
fountain-coded 16-byte atoms; every fourth frame repeats the stream beacon in
lane `D`, so a receiver can join at any frame and any single readable lane is
useful. `Sources/IrohaSwift/Petal/` is a function-by-function port of the
normative Rust crate `crates/iroha_petal` (decoder included) and passes the
shared fixtures `fixtures/petal/petal_stream_v1.json` and
`fixtures/petal/petal_captures_v1.json`.

```swift
// Sender: play an IPM1 message at 8 fps. Payloads may be up to 16 MiB - 1;
// receivers accept 64 KiB by default. `kind` is application-defined.
let encoder = try PetalStreamEncoder(payload: message.encoded, kind: 1)
PetalStreamView(encoder: encoder)                    // IrohaSwiftTransferUI

// Receiver: feed camera frames into one scan session.
let analyzer = PetalCameraAnalyzer { outcome in       // IrohaSwiftMobileTransports
    if let done = outcome.completed { handle(done.payload) }
}
analyzer.attach(to: videoDataOutput)
```

- `PetalStreamEncoder` / `PetalStreamAssembler` are the sender and receiver
  stream codecs; `PetalDecoder.decode(_:)` reads one `PetalLuma` frame (any
  rotation, optionally mirrored) and `PetalScanSession` combines decoding,
  reassembly and idle/absolute timeouts. The tile lanes `P` and `K` are first
  read against the light and dark levels of the finders; a lane that stays
  unreadable is read again with every patch normalised by its own contrast, so
  over-exposure, veiling light, glare and shadows cancel out.
- When a thumb, a glare or the edge of the frame hides one corner blossom,
  three blossoms that form a corner still locate the code: the fourth corner is
  inferred, refined against the dotted rings and reported as
  `PetalDecodedFrame.inferredCorner` (0 top-left, 1 top-right, 2 bottom-right,
  3 bottom-left of the upright code). After a frame decodes, the session reads
  the next frames with `PetalDecoder.track(_:previous:)`, which follows the
  blossoms from the last pose (at most 500 ms old) instead of searching the
  whole image; `PetalScanStats.tracked` and `.inferred` count both.
- `PetalRenderer` is the pixel-exact reference software renderer;
  `PetalDrawList` describes a frame for vector backends and
  `PetalCoreGraphicsRenderer` / `PetalFrameView` / `PetalStreamView`
  (`IrohaSwiftTransferUI`) draw it with CoreGraphics and SwiftUI.
- `PetalCameraAnalyzer` (`IrohaSwiftMobileTransports`) is an
  `AVCaptureVideoDataOutput` delegate that reads the Y plane of bi-planar YUV
  frames (or converts BGRA), reports `PetalScanOutcome` values through a
  callback and an `AsyncStream`, and stops after the payload completes.
  Scanner setup: use the 1280×720 session preset
  (`AVCaptureSession.Preset.hd1280x720`) where the device sustains about five
  decoded frames per second and fall back to 640×480 only when it cannot (at
  480p only lanes `P` and `D` read, so a 7.5 KB payment takes roughly four
  times longer). Automatic exposure over-exposes a mostly black screen, so set
  the exposure target bias to about −1 EV
  (`AVCaptureDevice.setExposureTargetBias`) or lock the exposure once the code
  has been seen (`specs/petal_stream.md` section 8, "Scanner guidance").

Run the Petal suites (codec, fixture conformance, golden captures, renderer,
SwiftUI and camera glue) with:

```bash
swift test --package-path IrohaSwift --disable-automatic-resolution --filter Petal
```

### Push Devices

`ToriiClient.registerPushDevice` and `unregisterPushDevice` wrap `/v1/notify/devices`. Apps obtain their FCM/APNs token from the platform SDK, then submit the token with canonical request auth for the owning account:

```swift
let body = ToriiPushDeviceRequest(accountId: accountId,
                                  platform: "FCM",
                                  token: fcmToken,
                                  topics: ["activity"])
try await torii.registerPushDevice(body, canonicalAuth: auth)
try await torii.unregisterPushDevice(body, canonicalAuth: auth)
```

### Subscriptions

Subscription plans live on asset definitions and are billed by triggers. Use
`bill_for.period = previous_period` for arrears billing (charge on the first for
last month) or `next_period` for fixed-price plans billed in advance.

```swift
let plan: ToriiSubscriptionPlan = [
    "provider": .string("<provider_account_i105>"),
    "billing": .object([
        "cadence": .object([
            "kind": .string("monthly_calendar"),
            "detail": .object([
                "anchor_day": .number(1),
                "anchor_time_ms": .number(0)
            ])
        ]),
        "bill_for": .object([
            "period": .string("previous_period"),
            "value": .null
        ]),
        "retry_backoff_ms": .number(86_400_000),
        "max_failures": .number(3),
        "grace_ms": .number(604_800_000)
    ]),
    "pricing": .object([
        "kind": .string("usage"),
        "detail": .object([
            "unit_price": .string("0.024"),
            "unit_key": .string("compute_ms"),
            "asset_definition": .string("usd#pay")
        ])
    ])
]

```

Direct subscription mutation helpers are not exposed. Build the equivalent
subscription instructions locally, sign them with wallet key material, and
submit the resulting transaction through `submitTransaction` or
`/v1/pipeline/transactions`.

### Canonical request signing

Authenticated app-facing Torii endpoints require `X-Iroha-Account`,
`X-Iroha-Signature`, `X-Iroha-Timestamp-Ms`, and `X-Iroha-Nonce` headers.
Use `ToriiCanonicalRequest` to build them; it signs the canonical request plus
the freshness metadata and auto-generates timestamp/nonce values when you do not
pass them explicitly. I105 remains the account spelling in data and paths; the
builder emits that identity in `X-Iroha-Account` as portable lowercase ASCII
canonical-address hex (`0x…`). Exact canonical lowercase-ASCII account aliases
(`label@dataspace` or `label@domain.dataspace`) remain unchanged after a bounded
structural preflight. Torii remains authoritative for UTS-46, active-catalog
resolution, and controller verification. String-based signing headers derive
and bound Foundation's percent-encoded wire query; pure query canonicalizers
continue to consume already-wire query text. Canonical signing
reserves the `0x` prefix for canonical-address hex, and also rejects non-token
methods, fragments, and paths that are not exact root-relative percent-encoded
wire paths:

```swift
let url = URL(string: "https://torii.example/v1/accounts/<account_i105>/assets?limit=5")!
let headers = try ToriiCanonicalRequest.buildHeaders(
    method: "get",
    url: url,
    accountId: "<account_i105>",
    privateKey: Data(repeating: 7, count: 32),
    networkId: networkId
)
var request = URLRequest(url: url)
headers.forEach { key, value in
    request.setValue(value, forHTTPHeaderField: key)
}
```

Attachment upload/list/get/delete methods require
`ToriiCanonicalRequestAuth` in both async and completion-handler forms. They
sign the exact method, encoded path, body, and immutable genesis-derived
`NetworkId` from `ToriiLocalSigningContext`, then reject redirects and replay.
Identifier resolve/claim-receipt and RAM-LFE execute/receipt-verify methods use
the same required authentication contract; claim receipt additionally requires
the exact canonical I105 path account to equal `canonicalAuth.accountId`.

RAM execution responses contain ciphertext and an execution receipt. They do not
supply a plaintext opening; identifier resolution requires the caller's independently
authenticated `outputOpening`. Production rejects the insecure `bfv-affine-v1` and
`bfv-programmed-v1` profiles. Private identifier execution remains unavailable until
a secure encryption profile is implemented and qualified.
The local `encryptInput` and plaintext `encryptedRequest` entry points throw
`ToriiClientError.ramLfeEncryptionUnavailable` before handling the input. Public
seed overrides are removed. Requests constructed from existing ciphertext remain
DTOs; they do not establish encryption support. Exact-lift arithmetic is retained
only in test fixtures.

### Sora VPN native lease flow

`ToriiClient` exposes the quote-first Sora VPN flow used by native XOR lease
escrow. Request a signed quote, submit the returned `OpenVpnLeaseEscrow`
transaction with the wallet, then create the VPN session with the committed
payment transaction hash and the same metering public key:

```swift
let auth = ToriiCanonicalRequestAuth(
    accountId: "<account_i105>",
    privateKey: Data(repeating: 7, count: 32)
)
let quote = try await torii.createVpnQuote(
    ToriiVpnQuoteCreateRequest(meteringPublicKeyHex: meteringPublicKeyHex),
    canonicalAuth: auth
)
// Submit quote.openLeaseInstruction as a signed transaction, then pass its hash:
let session = try await torii.createVpnSession(
    ToriiVpnSessionCreateRequest(
        quoteId: quote.quoteId,
        paymentTransactionHash: paymentHash,
        meteringPublicKeyHex: meteringPublicKeyHex
    ),
    canonicalAuth: auth
)
```

Relay operators submit cumulative receipt/voucher evidence with
`submitVpnReceipt`; the response's optional `settleLeaseInstruction` carries
`SettleVpnLease` when a settlement transaction must be signed and submitted, so
the operator receives only earned XOR and the customer gets the refundable balance.
The submission status is exactly `settlement_pending` until that instruction
commits; only a receipt read from committed WSV state uses `settled`. Exact
`disconnected`, `expired`, and `replaced` lifecycle statuses remain valid.

> **Account selectors:** Account-scoped collections (`ToriiClient.accountAssets(of:)` and `accountTransactions(of:)`) accept canonical I105 account ids or on-chain account aliases (`name@dataspace` / `name@domain.dataspace`). Torii resolves aliases to canonical account ids before serving the response. `accounts.get(_:)` requires the canonical I105 id.

### UAID portfolio and Space Directory

`getUaidPortfolio`, `getUaidBindings`, and `uaidManifests(of:)` accept only the
canonical `uaid:<64 lowercase hex>` literal with its low bit set. Portfolio and
binding responses require the exact current field sets, canonical I105 accounts,
and full asset ids bound to their returned definition, account, and dataspace;
nullable labels and aliases are preserved exactly and are never trimmed.
Manifest queries use `ToriiListQuery` filters (`dataspace_id`, `status`), cursor
pages and optional exact totals. Responses require `items` and `next_cursor`;
manifest rows retain lifecycle-derived status and lowercase hashes. The
embedded `ToriiUaidAssetPermissionManifest` is numeric V1, requires `issued_ms`,
`activation_epoch`, and `entries`, and rejects null for fields whose canonical
JSON representation is omission.

### Detached asset transfers

Use the SDK-owned two-phase `/v1/assets/transfer` flow for online payments. It
prepares exactly one numeric transfer, requires an explicit balance scope and
short creation/TTL window, and never accepts a private key, nonce, arbitrary
metadata, aliases, or legacy field spellings.

```swift
let request = ToriiAssetTransferRequest(
    authority: authority,
    assetDefinitionId: assetDefinitionId,
    assetBalanceScope: "dataspace:10", // or exactly "global"
    amount: "750",
    destination: destination,
    memo: "invoice 42",
    feePayment: .authority(chargeLimits: [], gasLimit: nil),
    creationTimeMs: torii.recommendedCreationTimeMs(),
    transactionTtlMs: 120_000
)
let draft = try await torii.prepareDetachedAssetTransfer(request)

// SigningKey keeps signing local. The public-key/signature overload is also
// available for Keychain or hardware-backed signers.
let submitted = try await torii.submitDetachedAssetTransfer(
    draft,
    signingKey: signingKey
)
let finality = try await torii.waitForDetachedAssetTransferFinality(
    draft,
    submittedResponse: submitted
)
```

Preparation fails closed unless ABI-25 native inspection proves the versioned
scaffold has the exact authority, network identity, protocol receipt chain, definition, source scope, amount,
destination, memo, typed fee payer, creation time, TTL, and no extra metadata.
The prepare route obtains the canonical fee quote and replaces only the charge
maxima before returning the scaffold. To select sponsorship, pass
`.sponsor(programId:programRevision:chargeLimits:gasLimit:)` with one exact
`FeeSponsorProgramId` and non-zero immutable revision; there is no account-only
sponsor selector or authority fallback.
Submission locally verifies Ed25519 authority/signature binding, uses native
finalization, and requires Torii's final transaction and entrypoint hashes to
match. `IrohaSDK` forwards the same prepare, submit, and finality methods.

For locally assembled transactions, build the complete unsigned payload first,
then call `quoteAndApplyFees(unsignedPayload:canonicalAuth:)`. Sign the returned
payload without changing any other field. `quoteFees` and
`getFeeSponsorProgram` expose the underlying account-signed
`/v1/fees/quote` and exact program lookup routes. Transaction metadata named
`fee_sponsor`, `gas_asset_id`, or `gas_limit` is retired and rejected.
The unsigned payload must carry the closed transaction domain as
`"domain": {"kind":"network","value":"hash:<64 uppercase hex>#<CRC16>"}`;
the retired `chain`, `chainId`, and `chain_id` keys and the genesis marker are rejected.

For the native retail payment policy, hash the customer's exact ordered
payment intent and inspect the complete assessment marker before signing:

```swift
let intent = RetailFeeQuoteRequestV1(
    accountId: accountId,
    assetDefinitionId: feeAssetDefinitionId,
    transfers: [RetailFeePaymentLegV1(destinationAccountId: recipient, amountMinorUnits: 100)]
)
let intentHash = try intent.intentHash()
let assessment = try RetailFeeAssessmentV1.decodeMarker(assessmentMarker)
guard assessment.intentHash == intentHash.map { String(format: "%02X", $0) }.joined() else {
    throw RetailFeeNativeError.invalidNativeOutput
}
let canonicalMarker = try assessment.marker()
```

The three ABI-25 retail fee operations use native typed Norito and reject
noncanonical markers. Local decoding does not verify that an assessment is
current or authorized. Signed read and verified finality remain required before
payment approval; admission checks the assessment against ledger state.

### Kotodama contract manifests

`ToriiClient.fetchContractManifest(artifactId:canonicalAuth:)` reads
`/v1/contracts/artifacts/{dataspace_id}/{hash}` with canonical account authentication and verifies the configured network and exact artifact identity before returning a strict `ToriiContractManifestRecord`. The model preserves
the `seiyaku`/`誓約` identity, the branded `kotoage`/`言挙げ`, `hajimari`/`始まり`, and
`kaizen`/`改善` lifecycle surface, exact flat-preorder argument and return schemas, bounded
access hints, triggers, state and error declarations, `kotoba`, and provenance. Unknown
fields, mismatched convenience hashes, English lifecycle aliases, and callbacks that bypass
a declared `kotoage` entrypoint are rejected during decoding. V1 type schemas use one flat
preorder node tape: a `List` node carries only `capacity`, and its element subtree follows it
immediately. The decoder rejects the retired nested `element` field, incomplete or overlong
tapes, and forged `AccountView`, `AssetView`, `AssetDefinitionView`, `DomainView`, `NftView`,
or `QueryPage<View>` shapes.

Contract alias and state reads are also SDK-owned. Use
`resolveContractAlias(_:)` for `/v1/contracts/aliases/resolve` and construct a
throwing `ToriiContractStateQuery` with one typed target (`.address` or
`.alias`) and one typed selector (`.path`, `.paths`, or `.prefix`) before calling
`queryContractState(_:)`. Responses reject unknown fields, duplicate JSON keys,
non-canonical base64, selector/target substitution, invalid pagination, and the
retired per-entry `decode_error` shape. A Torii JSON decode failure is instead a
top-level `ToriiClientError.api` carrying Torii's stable error envelope.

Wallets must use the two-step detached call flow when the signing key is held by
the client. Build the invocation from a trusted contract artifact and argument
schema, and commit to the exact final metadata (including deterministic
`contract_module`/`contract_event_*` entries when the selected contract emits
them) before asking Torii for signing bytes:

```swift
let intent = try ToriiContractCallDraftIntent(
    invocation: trustedInvocation,       // resolved address, code hash, entrypoint, argument record
    metadata: exactMergedMetadata
)
let draft = try await torii.prepareDetachedContractCall(
    ToriiContractCallRequest(
        authority: authority,
        contractAlias: "bisp::hbl.sbp",
        entrypoint: "spend_to_merchant",
        payload: .object(["amount": .string("750")]),
        metadata: callerMetadata,
        draftIntent: intent,
        creationTimeMs: creationTimeMs,
        transactionTtlMs: 120_000,
        feePayment: .authority(chargeLimits: [], gasLimit: 500_000)
    )
)
let signature = try signAfterUserPresence(draft.signingMessage)
let response = try await torii.submitDetachedContractCall(
    draft,
    publicKeyHex: publicKeyHex,
    signatureB64: signature.base64EncodedString()
)
let finality = try await torii.waitForDetachedContractCallFinality(
    draft,
    submittedResponse: response
)
```

`ToriiContractCallDraft` retains the normalized request and all resolved
contract, ABI, entrypoint, argument-record, metadata, gas, sponsor, payload,
time, and TTL bindings. Unsigned preparation fails closed without the independent
`ToriiContractCallDraftIntent`; response fields are never accepted as their own
proof of intent. The payload has exactly nine canonical fields; retired admission
fields and extra binary slots are rejected even with a matching recomputed payload
hash. Detached finalization preserves those exact verified payload bytes.
Submit accepts only the public key and detached signature; it fails closed unless the
returned receipt and queued pipeline status match the draft exactly.
`waitForDetachedContractCallFinality` then uses the canonical `scope=global`
pipeline lookup and returns only an applied, globally scoped, state-resolved
status with a positive block height.

Unsigned typed multisig writes follow the same trust boundary. Supply a
`ToriiMultisigUnsignedTransactionIntent` containing the configured network, exact
resolved multisig account and proposal hash, complete instruction executable,
and exact transaction metadata. The intent stays off wire, and Swift rejects
unsigned response bytes unless the payload matches it and the client's local
signing network. The raw Norito `proposeMultisig(noritoBody:)` overload cannot
independently interpret an opaque DTO, so it accepts submitted responses only;
use the typed request APIs when external signing is required.

### Explorer instruction history

Torii explorer endpoints expose instruction-level data, including transfer details.
Use `getExplorerTransfers` to fetch a page and derive transfer records:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let transfers = try await torii.getExplorerTransfers(
        query: ToriiListQuery(limit: 50),
        matchingAccount: "<account_i105>",
        assetDefinitionId: "<base58-asset-definition-id>"
    )
    for record in transfers {
        switch record.details {
        case .asset(let asset):
            print("transfer:", asset.amount,
                  asset.assetDefinitionId ?? "unknown asset",
                  "from:", asset.senderAccountId ?? "unknown",
                  "to:", asset.destinationAccountId)
        case .assetBatch(let entries):
            for entry in entries {
                print("batch transfer:", entry.amount,
                      entry.assetDefinitionId,
                      "from:", entry.senderAccountId,
                      "to:", entry.receiverAccountId)
            }
        }
    }
}
```

Explorer collections use `ToriiListQuery` and `ToriiPage`, with `items` and an explicit
`nextCursor`. Read `explorerInstructions`, `explorerTransactions`, `explorerRwas`,
`explorerAccounts`, `explorerDomains`, `explorerAssetDefinitions`, `explorerAssets`,
`explorerNfts`, `explorerBlocks`, `explorerLatestTransactions`, and
`explorerLatestInstructions` through `.page(query)`, `.pages(query)`, or `.items(query)`.
They use fixed bounded order and reject `sort`, `includeTotal`, and `aggregate`. Cursors
are opaque; empty pages may still have a continuation. The shared iterator follows them
and rejects repeated cursors. The `IrohaSDK.collections` accessor exposes the same API.

Explorer list/detail/stream calls and contract activity/event reads are public-dataspace requests
when the client has no `canonicalRequestAuth`. If the client was initialized with a default
canonical request signer, the SDK signs the exact requests automatically so Torii can add
restricted dataspaces visible to that account. Invalid or partial authentication fails at Torii;
it never falls back to anonymous visibility.

If you prefer a flattened, UI-ready shape, ask for transfer summaries:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let summaries = try await torii.getExplorerTransferSummaries(
        query: ToriiListQuery(limit: 50),
        matchingAccount: "<account_i105>"
    )
    for summary in summaries {
        print(summary.direction, summary.amount, summary.assetDefinitionId)
    }
}
```

For batch transfers, `transferIndex` tracks the entry position within the instruction payload.
Convenience flags `isIncoming`, `isOutgoing`, and `isSelfTransfer` help with UI direction labels.
If you need to recompute direction for another account or show counterparties, use
`direction(relativeTo:)` and `counterpartyAccountId(relativeTo:)`. Direction helpers also accept
`isIncoming(relativeTo:)`, `isOutgoing(relativeTo:)`, and `isSelfTransfer(relativeTo:)`.
Use `signedAmount(relativeTo:)` when you need a simple +/‑ string for UI totals.
Summaries conform to `Identifiable`, using `transactionHash|instructionIndex|transferIndex` as the
stable identifier.
Use `matchingAccount` or `assetDefinitionId` to filter transfer records and summaries.

For a one-shot transaction history helper, use `getTransactionHistory` (alias of
`getAccountTransferHistory`):

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let history = try await torii.getTransactionHistory(accountId: "<account_i105>",
                                                        limit: 50)
    for item in history {
        print(item.isIncoming ? "in" : "out", item.amount, item.assetDefinitionId)
    }
}
```

You can also pass `assetDefinitionId` or `assetId` to narrow results. The `assetId` filter matches
the source internal asset balance-bucket literal (`<base58-asset-definition-id>#<canonical-i105-account-id>`) as reported by explorer
transfers.
Transaction-scoped helpers (`getExplorerTransactionTransferSummaries`,
`streamTransactionTransferSummaries`) accept the same filters.

To stream multiple pages, use `iterateAccountTransferHistory`:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    for try await item in torii.iterateAccountTransferHistory(accountId: "<account_i105>",
                                                              limit: 25) {
        print(item.direction, item.amount, item.assetDefinitionId)
    }
}
```

You can also list transaction summaries or fetch a transaction detail payload:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let txPage = try await torii.explorerTransactions.page(ToriiListQuery(limit: 25))
    if let first = txPage.items.first {
        let detail = try await torii.getExplorerTransactionDetail(hashHex: first.hash)
        print("transaction status:", detail.status)
    }
}
```

To fetch a single instruction payload, use `getExplorerInstructionDetail` with the transaction hash
and instruction index.

If you need transfer details for a specific transaction, call
`getExplorerTransactionTransferSummaries(hashHex:matchingAccount:)`.
Use `streamTransactionTransferSummaries` or `transactionTransferSummariesPublisher` to keep
receiving live transfer updates for that transaction.

For RWA lots, use the dedicated explorer and chain-state helpers:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let lots = try await torii.explorerRwas.page(ToriiListQuery(
        filter: (ToriiField("owned_by") == "<account_i105>")
            .and(ToriiField("domain") == "commodities"),
        limit: 25
    ))
    if let first = lots.items.first {
        let detail = try await torii.getExplorerRwaDetail(rwaId: first.id)
        print(detail.quantity, detail.heldQuantity, detail.primaryReference)
    }

    let lotsOnChain = try await torii.rwas.page(ToriiListQuery(limit: 10))
    print(lotsOnChain.items.map(\.id))
}
```

Chain-state RWA lots are a collection like any other (see "Collection queries").
Reads are public; when the client has `canonicalRequestAuth` (with an immutable
`ToriiLocalSigningContext` for the deployment's exact genesis `NetworkId`), the
SDK signs the final method, path and canonical body locally and dispatches once
without redirects, which adds the restricted dataspaces visible to that account.
Aliases as signers and precomputed canonical headers fail closed.

For local instruction composition, `RwaInstructionBuilders` and the matching
`IrohaSDK` convenience methods now cover the dedicated RWA instruction family.
The richer registration/merge/control-policy payloads stay as `NoritoJSON`
objects so callers can pass canonical Rust-side JSON shapes directly:

```swift
let newRwa = try NoritoJSON.fromJSONObject([
    "domain": "commodities",
    "quantity": "10.5",
    "spec": ["scale": 1],
    "primary_reference": "vault-cert-001",
    "metadata": ["origin": "AE"],
    "parents": [],
    "controls": ["freeze_enabled": true]
])
let registerRwa = try sdk.buildRegisterRwa(rwa: newRwa)
let transferRwa = try sdk.buildTransferRwa(
    sourceAccountId: "<source_i105>",
    rwaId: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities",
    quantity: "1.5",
    destinationAccountId: "<destination_i105>"
)

let metadata = try NoritoJSON(["serial": "vault-01"])
let setMetadata = SetMetadataRequest(
    networkId: networkId,
    authority: "<source_i105>",
    target: .rwa("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities"),
    key: "serial",
    value: metadata
)
```

To react to new blocks as they commit, subscribe to the explorer SSE streams:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    for try await instruction in torii.streamExplorerInstructions() {
        if let details = instruction.transferDetails() {
            print("transfer:", details)
        }
    }
}
```

Use `streamExplorerTransactions()` if you only need transaction summaries.
Combine users can call `explorerInstructionsPublisher` / `explorerTransactionsPublisher`.
For a UI-ready transfer feed, use `streamExplorerTransferSummaries(matchingAccount:)` or
`explorerTransferSummariesPublisher`.
Transfer stream helpers accept `matchingAccount`, `assetDefinitionId`, and `assetId` filters.
If you need history plus live updates in one stream, use `streamAccountTransferHistory`.
Combine users can call `accountTransferHistoryPublisher` for the same flow.

### Account addresses

```swift
let address = try AccountAddress.fromAccount(publicKey: Data(repeating: 0, count: 32))
print(try address.canonicalHex())
print(try address.toI105(networkPrefix: 753))
```

Account addresses are domainless and accept no domain label or selector. Alias
labels and routing context are managed separately. Account addresses validate
public key lengths for known algorithms (ed25519 requires 32 bytes; secp256k1
requires 33 bytes when enabled) and reject empty keys.

### Pipeline submission defaults

`IrohaSDK` posts signed payloads to `/v1/pipeline/transactions` and polls
`/v1/pipeline/transactions/status` until the transaction reaches authoritative finality. The
helpers in `TxBuilder` (for example `submitAndWait(transfer:keypair:)`) wrap the same
flow. No additional configuration is required when targeting Torii builds that ship the
pipeline surface. The primary binary submitter rejects noncanonical or non-V1 signed wires before
network access and accepts only HTTP `202` as admission success.
If `/v1/pipeline/transactions/status` responds with `404`, Torii likely restarted or
evicted the in-memory status cache; the SDK treats this as "pending" and continues polling.
Pipeline submissions include an `Idempotency-Key` header derived from the transaction
hash. This deduplication hint does not authorize replay after an ambiguous outcome;
reconcile the exact hash first. Override `sdk.pipelineSubmitOptions.idempotencyKeyFactory`
or set it to `nil` when integrating with custom gateways.

### Metadata & governance helpers

`TxBuilder` includes Norito-backed builders for metadata edits and governance actions.
Use the new `NoritoJSON` helper to encode values deterministically before signing:

```swift
let metadata = try NoritoJSON(["region": "eu-west", "tier": 2])
let setMetadata = try SetMetadataRequest(networkId: networkId,
                                         authority: accountId,
                                         target: .account(accountId),
                                         key: "profile",
                                         value: metadata)
let envelope = try sdk.buildSetMetadata(request: setMetadata, signingKey: signingKey)
try await sdk.submit(envelope: envelope)
```

To observe the async flow directly:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    Task {
        let envelope = try sdk.buildSignedTransfer(transfer: transfer, keypair: kp)
        let status = try await sdk.submitAndWait(envelope: envelope) // POSTS + polls
        print("final state:", status.content.status.state)
    }
}
```

If you need the immediate submission receipt without waiting for a terminal state,
call `torii.submitTransaction(data: envelope.norito)` directly. The returned
`ToriiSubmitTransactionResponse` includes the receipt payload and signature; use
`receipt.hash` (or `receipt.payload.txHash`) to poll with `torii.getTransactionStatus(hashHex:)`.
`submitTransaction` validates the transaction submit schema from `/v1/node/capabilities`
(`data_model_version` + `signed_transaction_schema_hash_hex`) and throws
`ToriiClientError.dataModelMismatch` or
`ToriiClientError.transactionSchemaMismatch` if the node was built from a mismatched release.

`ToriiClient.getMetrics()` requests JSON and requires `Content-Type: application/json`.
Pass `asText: true` to request the text/Prometheus variant.

Swift concurrency wrappers are available on iOS 15/macOS 12 and newer:

```swift
if #available(iOS 15, macOS 12, *) {
    Task {
        let balances = try await torii.accountAssets(of: accountId).page()
        print("balances:", balances.items)

        try await sdk.submit(transfer: transfer, keypair: kp)

        let status = try await sdk.submitAndWait(transfer: transfer, keypair: kp)
        print("final status:", status.content.status.kind)

        let timeSnapshot = try await sdk.getTimeNow()
        print("network time", timeSnapshot.now)
    }
}

### Pipeline status polling

`IrohaSDK` exposes `submitAndWait` helpers (envelope + transfer/mint/burn variants) that
POST to `/v1/pipeline/transactions` and poll `/v1/pipeline/transactions/status` until a
canonical `Applied` status or a failure (`Rejected`/`Expired`) is observed. `Approved` and
`Committed` remain progress states. Tune only polling timing via
`PipelineStatusPollOptions` or by setting `sdk.pipelinePollOptions`:

```swift
var options = PipelineStatusPollOptions()
options.pollInterval = 0.25 // seconds between polls
options.timeout = 20        // abort if no status within 20 seconds

if #available(iOS 15, macOS 12, *) {
    let status = try await sdk.submitAndWait(envelope: envelope, pollOptions: options)
    print("hash", status.content.hash, "status", status.content.status.kind)
}
```

The public status response is deliberately metadata-only: an exact canonical typed
transaction hash matching `^[0-9a-f]{63}[13579bdf]$`,
closed status kind, optional committed height, read scope, and resolution source. The
decoder rejects unknown status kinds and retired rejection, diagnostic, trigger, or batch
fields. Status lookups request exact `scope=global`; responses accept only the current exact
`local` or `global` scope values; every other spelling is invalid. Detailed
committed-transaction data requires an involved account or operator to
submit a canonical signed `FindTransactions` query; Swift does not expose that method until
its generated signed-query surface is available.

Completion-based variants return a `Task<Void, Never>` so callers can cancel outstanding
polls. The finality policy is not configurable: only a global, state-resolved `Applied`
observation with a positive block height proves execution. State-resolved failures bubble
up as `PipelineStatusError.failure` (`Rejected`/`Expired`), while queue/cache hints remain
pending even when they carry a terminal kind. Other non-final observations eventually yield
`PipelineStatusError.timeout` when no terminal status arrives in time. Failure errors expose
the status kind but never public rejection or execution details.

Need to monitor a transaction initiated elsewhere? Use the dedicated helper:

```swift
if #available(iOS 15, macOS 12, *) {
    do {
        let status = try await sdk.pollPipelineStatus(hashHex: String(repeating: "b", count: 64))
        print(status.content.status.kind)
    } catch {
        print("pipeline error:", error)
    }
}
```

### Caller-managed transaction archive

`FilePendingTransactionQueue` can persist signed envelopes for explicit application recovery,
but `IrohaSDK` never drains or submits that archive. A signed transaction submission is one
HTTP attempt: redirects, transport failures, and 429/5xx responses are surfaced immediately.
After an ambiguous outcome, query pipeline status by the envelope hash before deciding whether
to construct a new transaction or explicitly resubmit an archived envelope:

```swift
let archiveURL = FileManager.default
    .urls(for: .documentDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("pending.queue")
let archive = try FilePendingTransactionQueue(fileURL: archiveURL)
try archive.enqueue(envelope)
```

`FilePendingTransactionQueue` stores base64-encoded `SignedTransactionEnvelope` blobs, so
operators can archive or inspect them later. Archiving does not authorize automatic replay;
the application owns reconciliation and any later explicit submission.

### Native privacy bridge

The four Goldilocks STARK/FRI protocols bind
`PrivacyProofSystemIdV1.starkFriSha3_384Goldilocks` and
`PrivacyEngineIdV1.nativeGoldilocksSha3_384StarkFri`, each at Norito tag 0.
These identities correspond to the native canonical labels
`stark-fri-sha3-384-goldilocks-v1` and
`native-goldilocks-sha3-384-stark-fri-v1`: SHA3-384 owns the outer byte suite.

`PrivacyNativeBridge` is selector-free.
`compiledProfileCatalogV1()` returns this binary's canonical typed
`PrivacyCompiledProfileCatalogV1` Norito archive, while `protocolsV1` exposes
the closed `PrivacyProtocolIdV1` enum in exact wire order. The local catalog
contains no governance or readiness state. Call
`ToriiClient.getPrivacyExact12CapabilityManifestV1(canonicalAuth:)` over HTTPS
to fetch the exact canonical committed manifest; redirects, JSON, compressed
representations, missing canonical request authentication, and a missing or
stale native bridge fail closed. The signed fetch bypasses local cached responses
and sends `Cache-Control: no-cache, no-store` for current committed state.
`PrivacyExact12CapabilityAdmissionV1` issues
an opaque per-protocol token only when the committed row is active, ready, and
byte-identical to the ABI25 native-validated compiled catalog. The generic
transaction-frame initializer rejects `SubmitPrivacyProofV1`, and the admitted
factory revalidates the native catalog, manifest, consensus action ceiling, and
complete final V1 envelope profile tuple both at construction and final encoding.
The client must supply `localSigningContext.networkId`: the authenticated origin
and its token retain that exact network, the deployment's raw32 network and genesis
fields must match it, and every retained statement's context must bind it.
Final batch encoding also compares the token and statement against the batch's
exact `networkId`; an admission from another network cannot be reused. Managed
fixture projection and standalone native validation do not mint network authority.

ABI25 requires exactly six privacy C exports, including
`iroha_privacy_validate_exact12_capability_manifest_v1`. Swift passes the exact
Torii archive to the canonical Rust validator before projecting its fields.
Rust checks the complete release and deployment records, artifact counts,
digests, audit signatures, and validator signatures. Every authority-bearing
path also compares the selected tuple against the native local catalog.
The managed decoder alone cannot establish production qualification; a bridge
without the manifest validator is unavailable.
`exact12FixtureBundleV1()` returns byte-complete Rust-derived statements,
envelopes, submit instructions, transaction intents, unsigned payloads, signed
transactions, and transaction hashes for all twelve rows;
`validateExact12FixtureBundleV1(_:)`
accepts only the canonical bundle and enforces a 2 MiB input ceiling. ABI 25
availability requires both compiled-catalog symbols, both exact-12 fixture symbols,
the capability-manifest validator, the zeroizing-free symbol, and successful typed probes. Generic
request/build/verify dispatch and free-form selectors are absent; proofs use
protocol-specific typed APIs.

`PrivacyExact12FixtureCodecV1` is the native-independent counterpart for the
Rust-derived bundle in
`fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64`. It exposes typed
outer rows and strictly decodes or encodes the canonical compact-length Norito
archive without loading `NoritoBridge`. The codec enforces the closed protocol
order, exact submit route, byte and allocation ceilings, canonical STANDARD
Base64, schema-specific frame padding, statement/envelope/proof discriminants,
instruction and transaction bindings, signed-payload identity, and the pipeline
transaction hash. Use `requireCanonicalArchive(_:expectedCanonicalArchive:)`
with the independently supplied Rust fixture to close the BLAKE3-derived
statement and transaction-intent bindings; Swift does not substitute a
different digest algorithm for those fields.

The enum contains exactly twelve IDs: `zk-ace-pq-authorization-v1`,
`anonymous-pgc-k-out-of-n-v1`, `verange-transparent-range-v1`,
`iroha-zk-ams-v1`, `vega-existing-credential-zk-v1`,
`iroha-zk-x509-stark-p256-v1`,
`iroha-jindo-polynomial-commitment-v1`,
`iroha-bootle-lantern-anoncred-v1`, `orchard-halo2-actions-v1`,
`monero-fcmp-plus-plus-v1`, `iroha-ivm-private-note-stark-v1`, and
`pq-masp-stark-v1`. Exact initialization rejects aliases, retired IDs, case
changes, and whitespace normalization. Each identity exposes its exact
four-byte `noritoDiscriminant`, `canonicalTypedVariantLabel`,
`expectedProofSystem`, and `expectedEngine`; the proof-system and native-engine
tags remain distinct Swift types even where their current numeric ordinals
coincide. Unknown tags and legacy variant labels fail closed.
The confidential-v2 Swift wallet helpers expose
`ConfidentialNoteOpening`, `ConfidentialNoteCommitment.deriveFromOpening`,
`ConfidentialNoteNullifier`, `ConfidentialOwnerTag`,
`ConfidentialNoteEncryption.encryptNote`,
`ConfidentialNoteDecryption.decryptNote`,
`ConfidentialNoteDecryption.decryptNoteWithOwnerTag`,
`LocalZkAssetMerklePathProvider`, and
`ToriiClient.getMerklePathForCommitment(asset:commitment:canonicalAuth:)`. Every note
decryption requires the configured exact `NetworkId` and derives the expected
owner tag from the supplied spend key; diversified notes must use the explicit
expected-owner-tag overload. Decrypted note plaintext rejects noncanonical
length varints before reconstructing the opening. Confidential note byte-vector
contents keep their raw bytes after the vector length. Proof witnesses remain
owned by each native engine. `ConfidentialProver` constructs local transfer,
full-redemption and private-change proofs through the shared Rust wallet owner;
there is no generic confidential witness archive. Direct verifier-record hashes use packed fixed
arrays, hashes inside `Option` or `Vec` use ConstVec element framing, and all
Iroha `Hash` values retain their marker bit. The verifier-record `status` field
uses the canonical four-byte `u32` enum discriminant. Swift
Merkle providers reject ambiguous local frontiers and Torii responses with
duplicate JSON keys, noncanonical integer
fields, non-lowercase fixed32 hex, depth/count drift, root drift,
direction-bit drift, or non-verifying paths before wallet code receives proof
material.

### Local confidential proofs

Create one `ConfidentialProver(networkId:assetDefinitionId:spendKey:)`, then call
`await proveTransfer(tree:inputs:outputs:)` or
`await proveUnshield(tree:inputs:publicAmount:change:)`. The native owner selects
the circuit and proving keys, checks conservation and membership, and verifies
the resulting proof locally. Supply one or two actual notes and either complete
commitments or one path per note in `ConfidentialTree`; an absent second input
requires no dummy note. Authenticate the network, canonical asset and expected
root before proving.

Securely retain each change opening before proving. Once its new leaf index and
root are authenticated, `change.asInput(leafIndex:)` supplies the native default
change diversifier, independently of the consumed notes' diversifiers.

Use integer literals for ordinary `ConfidentialAmount` values or its exact
decimal initializer for amounts up to `u128::MAX`. `ConfidentialProverError`
distinguishes invalid inputs, unavailable bridge, closed owner and native error
codes. Proving runs on a background queue. Call `close()` when finished: accepted
jobs finish with their own native ownership, even if their Swift task is cancelled.
Native key and witness owners clear their storage; Swift-managed `Data` copies
do not carry an erasure guarantee. A local artifact submits no transaction and
does not establish ledger or protocol activation authority.

With the current authenticated NoritoBridge artifact configured, run the
standalone public-API example with `swift run confidential-redemption-example`.
It uses secure random disposable keys and notes and makes no network request.
Its source is [ConfidentialRedemption.swift](Examples/ConfidentialRedemption/ConfidentialRedemption.swift).
The direct native consumer check is
`swift test --filter ConfidentialProverNativeTests`; unavailable native support
fails this check instead of skipping it.

### Confidential key derivation

Wallets derive the confidential key hierarchy locally:

```swift
let seed = Data(repeating: 0x42, count: 32)
let localKeyset = try ConfidentialKeyset.derive(from: seed)

if #available(iOS 15, macOS 12, *) {
    let sdkKeyset = try await sdk.deriveConfidentialKeyset(seedHex: localKeyset.spendKeyHex)
    assert(sdkKeyset == localKeyset)
}
```

`IrohaSDK.deriveConfidentialKeyset` is a local convenience wrapper around
`ConfidentialKeyset.derive`. No Torii request is made. Provide either
`seedHex` or `seedBase64`; inputs are trimmed automatically, all-zero spend keys are
rejected as inert material, and invalid encodings surface as
`ConfidentialKeyDerivationError`.

### Confidential encrypted payloads

Construct memo envelopes for confidential transfers:

```swift
let payload = try ConfidentialEncryptedPayload(
    ephemeralPublicKey: Data(ephemeralPublicKeyBytes),
    nonce: Data(nonceBytes),
    ciphertext: memoCiphertext
)

let noritoBytes = try payload.serializedPayload()      // bare Norito struct bytes
let envelope = try payload.noritoEnvelope()            // header + CRC64-XZ
```

Each initializer validates the X25519 public key length and rejects low-order
public keys, enforces the XChaCha20-Poly1305 nonce length (24 bytes), and
requires non-empty ciphertext. Use `ConfidentialEncryptedPayload.deserialize(from:)`
to parse existing Norito bytes and `asHexDictionary()` when logging or exporting
the fields.

### Confidential gas schedule

Operators can inspect the active confidential verification costs directly from Torii:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    if let schedule = try await sdk.getConfidentialGasSchedule() {
        print("proof base:", schedule.proofBase)
        print("per nullifier:", schedule.perNullifier)
    } else {
        print("node has not advertised confidential gas knobs yet")
    }
}
```

`getConfidentialGasSchedule()` wraps `GET /v1/configuration`, parsing the logger/network/
queue sections along with `confidential_gas` when present. When the node has not enabled
confidential proofs yet the helper simply returns `nil`, mirroring the Python/JS DTOs.

### Configuration snapshots

`getConfiguration()` returns the typed snapshot, including the active Norito-RPC transport policy:

```swift
if #available(iOS 15.0, macOS 12.0, *) {
    let snapshot = try await sdk.getConfiguration()
    if let noritoRpc = snapshot.transport?.noritoRpc {
        print("Norito-RPC stage:", noritoRpc.stage)
        print("mTLS required:", noritoRpc.requireMtls)
    }
}
```

Generic shield, shielded-transfer, and unshield instructions are not part of
the first-release SDK surface.

`ProofAttachment` emits registry-bound envelopes (`backend`, `proof_b64`, `vk_ref`, optional
`vk_commitment_hex`/`envelope_hash_hex`); embedded key bytes are not accepted by the Swift builder.
The complete canonical nested `ProofBox`, including compact field prefixes and
the fixed V1 vector count, is capped at 64 MiB. Call
`ProofAttachment.maximumProofByteCountV1(forBackend:)` to preflight a backend's
exact proof-vector ceiling without allocating proof storage.

### Multisig spec builder

The Swift SDK provides a multisignature builder so apps can assemble
deterministic registration payloads before submitting `MultisigRegister`
instructions. The helper mirrors `MultisigSpec` from the executor data model,
validates quorum, TTL, and signatory bounds, and exports the exact JSON layout
Torii expects:

```swift
let specBuilder = MultisigSpecBuilder()
    .setQuorum(3)
    .setTransactionTtl(milliseconds: 86_400_000) // 1 day
    .addSignatory(accountId: "<account_i105>", weight: 2)
    .addSignatory(accountId: "<signatory_b_i105>", weight: 1)
    .addSignatory(accountId: "<signatory_c_i105>", weight: 1)

let specPayload = try specBuilder.build()
let specJSON = try specBuilder.encodeJSON(prettyPrinted: true)
```

`MultisigSpecBuilder` enforces the 255-member limit, rejects zero-length TTLs, and ensures
the quorum can actually be met (total signatory weight ≥ quorum). The resulting
`MultisigSpecPayload` encodes signatories as `{ "<encoded_account_id>": weight }`.
Feed the JSON blob directly into your transaction
builder or store it alongside governance approvals for reproducibility. Use
`specPayload.previewProposalExpiry(requestedTtlMs:now:)` to surface the effective TTL
and approximate expiry for proposal/relayer flows; it clamps overrides to the policy cap
and flags when a requested TTL was reduced for UX messaging. Call
`specPayload.enforceProposalExpiry(requestedTtlMs:)` to reject overrides above the cap
before submitting a proposal so clients surface the same error the node would emit.

Submit the registration via the new Norito-backed transaction builders:

```swift
let request = MultisigRegisterRequest(
    networkId: try NetworkId(literal: configuredNetworkIdLiteral),
    authority: "<authority_account_i105>",
    accountId: "<multisig_account_i105>",
    spec: specPayload,
    ttlMs: 120_000
)

// completion handler variant
try sdk.submitAndWait(multisigRegister: request, keypair: councilKeypair) { result in
    switch result {
    case .success(let status):
        print("multisig account registered:", status.kind)
    case .failure(let error):
        print("error:", error)
    }
}

// or async/await
if #available(iOS 15.0, macOS 12.0, *) {
    let status = try await sdk.submitAndWait(multisigRegister: request, keypair: councilKeypair)
    print("registered multisig:", status.kind)
}
```
Choose a fresh canonical domainless controller account id (the key can be random and discarded
because direct multisig signing is forbidden). Alias domains are independent of canonical account
identity. Deterministically derived multisig keys are quarantined; registration requires a
non-derivable account id.

The SDK routes the request through the Norito native bridge so transactions are signed
locally and submitted through `/v1/pipeline/transactions` with the same deterministic
encoding the CLI uses.

### Inspect confidential asset policies

Wallets and auditors can poll an asset definition’s confidential policy and pending
transition metadata via `/v1/confidential/assets/{definition_id}/transitions`:

```swift
if #available(iOS 15, macOS 12, *) {
    let policy = try await torii.getConfidentialAssetPolicy(assetDefinitionId: "66owaQmAQMuHxPzxUN3bqZ6FJfDa")
    if let pending = policy.pendingTransition {
        print("Next mode:", pending.newMode, "opens at", pending.windowOpenHeight ?? pending.effectiveHeight)
    }
}
```

`ToriiConfidentialAssetPolicy` exposes the active/pending modes, verifier parameter ids,
and the derived window-open height so UI layers can display countdowns without manual JSON
decoding. The completion-based overload mirrors the async helper for apps that still rely
on callback-first code.

### Verifying key registry

Binding-only IVM verifier labels are retired and rejected. Production proof-backed IVM invocation remains closed until the complete native execution relation and finalized State authority are implemented and qualified.

Inspect verifying keys via the Torii helpers:

```swift
if #available(iOS 15, macOS 12, *) {
    let detail = try await torii.getVerifyingKey(backend: "halo2/ipa", name: "payments_v1")
    let current = try await torii.listVerifyingKeys(query: ToriiVerifyingKeyListQuery(backend: "halo2/ipa"))
    print("vk status:", detail.record.status, "count:", current.count)
}
```

### Runtime capabilities

Query runtime adverts to surface ABI metadata:

```swift
if #available(iOS 15, macOS 12, *) {
    let capabilities = try await torii.getNodeCapabilities()
    let metrics = try await torii.getRuntimeMetrics()
    let abiActive = try await torii.getRuntimeAbiActive()
    print("abi:", capabilities.abiVersion,
          "signed_tx_schema:", capabilities.signedTransactionSchemaHashHex ?? "missing",
          "active:", abiActive.abiVersion,
          "upgrades:", metrics.upgradeEventsTotal)
}
```

Completion-based APIs (`getNodeCapabilities(completion:)`, etc.) are also available when
Swift concurrency is not an option.

Generate upgrade instructions via the runtime helpers:

```swift
if #available(iOS 15, macOS 12, *) {
    let manifest = ToriiRuntimeUpgradeManifest(
        name: "Upgrade Foo",
        description: "Refresh runtime provenance",
        abiVersion: 1,
        abiHashHex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        addedSyscalls: [],
        startHeight: 1_000,
        endHeight: 1_200
    )

    let proposal = try await torii.proposeRuntimeUpgrade(manifest: manifest)
    let proposalInstructions = proposal.txInstructions

    let activation = try await torii.activateRuntimeUpgrade(idHex: String(repeating: "a", count: 64))
    let activationInstructions = activation.txInstructions
    let cancellation = try await torii.cancelRuntimeUpgrade(idHex: String(repeating: "a", count: 64))
    let cancellationInstructions = cancellation.txInstructions
    // Feed the returned `txInstructions` into your transaction builder / submit pipeline.
}
```

`PipelineSubmitOptions` controls only the optional idempotency key attached to the single
submission attempt. The default uses the transaction hash:

```swift
sdk.pipelineSubmitOptions = PipelineSubmitOptions(
    idempotencyKeyFactory: { envelope in envelope.hashHex }
)
```
Pipeline submissions always use `/v1/pipeline/transactions` and
`/v1/pipeline/transactions/status`. The owned Torii transport rejects redirects and does not
retry signed bodies; only HTTP `202` acknowledges admission. A custom
`ToriiTransactionSubmitting` implementation must provide the same one-shot contract.

Node-local pipeline and clock reads use a separate operator context. Construct
it once from the deployment's exact genesis `NetworkId` and operator signing
key, then install it on `ToriiClient` (or `IrohaSDK`):

```swift
let operatorContext = try ToriiOperatorSigningContext(
    networkId: networkId,
    signingKey: operatorSigningKey
)
let operatorTorii = ToriiClient(
    baseURL: toriiURL,
    operatorSigningContext: operatorContext
)
let preflight = try await operatorTorii.getPipelinePreflight()
let recovery = try await operatorTorii.getPipelineRecovery(height: 42)
let clock = try await operatorTorii.getTimeStatus()
```

`ToriiPipelinePreflightPipeline` exposes the current
`ivmMaxCyclesUpperBound` and `ivmAdmissionCycleLimit` values. Preflight fee
accounts must be exact canonical I105 ids; alias-shaped `name@domain` values
fail decoding.

`preflight.sumeragi` carries only `blockCadenceMs`, the signed-genesis target
block time. Torii serves no stall threshold, so `preflight.stallThresholdMs` is
derived as `ToriiPipelinePreflight.stallBlockCadences` (20) × `blockCadenceMs`,
and `preflight.isStatusStalled(status)` reports a stall only when
`status.queueSize > 0` and the time since the last non-empty block (or since
the last block, before the first non-empty one) exceeds it. Twenty cadences
cover one crashed leader's view change at the Sumeragi default timings; call
`status.isQueueStalled(stallThresholdMs:)` directly when the deployment's local
consensus timers are known.

These helpers sign the exact `GET`, substituted path, query, and empty body,
then dispatch once without redirects or retries. They reject bearer/API-token
fallback and caller-supplied operator headers. Swift has no peer, policy, or
proof-retention convenience method; use no invented SDK surface for those
routes.

### Verifying key registry

Interact with the Torii verifying-key endpoints to inspect and monitor Halo2 verifier metadata:

```swift
if #available(iOS 15, macOS 12, *) {
    let detail = try await torii.getVerifyingKey(backend: "halo2/ipa", name: "vk_main")
    print("vk status:", detail.record.status)

    let idsOnly = try await torii.listVerifyingKeys(
        query: ToriiVerifyingKeyListQuery(backend: "halo2/ipa", idsOnly: true)
    )
    print("known ids:", idsOnly.map(\.id.name))
}
```

Direct register/update helpers send only the public authority and verifier
metadata. Torii never receives a private key and never submits the transaction;
it returns a validated `ToriiVerifyingKeyTransactionDraft` for local signing.
Configure one immutable network trust context on clients that prepare signing
payloads; read-only clients may omit it:

```swift
if #available(iOS 15, macOS 12, *) {
    let torii = ToriiClient(
        baseURL: toriiURL,
        localSigningContext: ToriiLocalSigningContext(
            networkId: try NetworkId(literal: configuredNetworkIdLiteral)
        )
    )
    let draft = try await torii.registerVerifyingKey(
        ToriiVerifyingKeyRegisterRequest(
            authority: "alice",
            backend: "halo2/ipa",
            name: "vk_main",
            version: 1,
            circuitId: "halo2/ipa::transfer_v1",
            publicInputsSchemaHashHex: String(repeating: "a", count: 64),
            gasScheduleId: "halo2_default",
            verifyingKeyBytes: Data([1, 2, 3]),
            status: .active
        )
    )
    print("unsigned payload bytes:", draft.transactionPayload.count)
}
```

Pass `draft.transactionPayload` to Iroha SDK signing abstractions, which apply
the Iroha prehash themselves. Use `draft.signingMessage` only with low-level
signer interfaces that expect an already-prehashed 32-byte message; signing that
value through an SDK payload signer would hash it twice. After signing,
assemble and submit the signed transaction through the normal pipeline API.
Before returning a draft, the client decodes the canonical transaction, requires
the configured chain and requested authority, and accepts exactly one matching
register/update instruction whose identifier and complete verifying-key record
equal the request. Completion-style register/update overloads return the same
draft type.

```swift
if #available(iOS 15, macOS 12, *) {
    // Every event, narrowed on Torii: rejected transactions and committed blocks.
    let filter = ToriiEventFields.txStatus == "Rejected"
        || ToriiEventFields.blockStatus == "Committed"
    Task.detached {
        do {
            for try await message in torii.streamEvents(filter: filter) {
                switch message.event {
                case let .transaction(transaction):
                    print(transaction.hash, transaction.status, transaction.rejectionCode?.rawValue ?? "")
                case let .block(block):
                    print("block", block.status.name)
                case let .data(notice), let .other(notice):
                    print(notice.event, notice.summary ?? "") // diagnostic text only
                default:
                    break
                }
            }
        } catch {
            print("event stream error:", error)
        }
    }

    // Proof outcomes, narrowed on Torii by backend and matched locally by proof hash.
    let proofs = torii.streamProofEvents(
        filter: ToriiProofEventFilter(backend: "halo2/ipa", proofHashHex: String(repeating: "a", count: 64))
    )
    Task.detached {
        do {
            for try await message in proofs {
                switch message.event {
                case .verified(let body):
                    print("verified:", body.id.proofHashHex, body.verifyingKeyId?.name ?? "")
                case .rejected(let body):
                    print("rejected:", body.id.proofHashHex)
                case .pruned(let pruned):
                    print("pruned", pruned.removedCount, "at height", pruned.prunedAtHeight)
                }
            }
        } catch {
            print("proof stream error:", error)
        }
    }

    // Verifying-key and trigger events carry only their kind and a diagnostic summary.
    Task.detached {
        do {
            for try await message in torii.streamVerifyingKeyEvents() {
                print("verifying key changed:", message.event.summary ?? "")
            }
        } catch {
            print("verifying-key stream error:", error)
        }
    }
}
```

Every SSE `data` object carries `category` and `event`. `ToriiEvent` models the
pipeline events (`transaction`, `block`, `warning`, `witness`) and proof events and
keeps every other event as a `.data` or `.other` notice, so new event kinds never
fail a stream. Statuses are typed from their variant names
(`PipelineTransactionState`, `ToriiPipelineBlockEvent.Status`); a rejected
transaction carries a `ToriiTransactionRejectionCode` and a fixed public
`rejectionReason`. Event filters use the same builder over `ToriiEventFields`,
restricted to what subscriptions can match: `==` and `in` combined with `&&` and
`||`, `!` only over a status equality, and `txBlockHeight.isNull`. Other built
filters are rejected locally with `invalid_filter`; `streamEvents(filterText:)`
passes text through unchanged. Verifying-key and trigger events have no stable
fields, so `streamVerifyingKeyEvents()` and `streamTriggerEvents()` recognise them
by kind on an unfiltered stream; read the current record (for example with
`getVerifyingKey`) before acting on one. Trigger executions arrive as `.other`
(`ExecuteTrigger`, `TriggerCompleted`) on `streamEvents()`. `ToriiProofEventFilter`
narrows the stream on Torii with `serverFilter()` (`proof_backend`,
`proof_call_hash`, `proof_envelope_hash`) and matches the event kind and
`proofHashHex` locally; a pruning event matches when it removed that proof.

The canonical `/v1/events/sse` feed is live-only: its
Swift helpers expose no resume argument and never emit `Last-Event-ID`. A reconnect
can therefore have a gap. If Torii emits terminal `event: stream_error`, the typed
helpers fail with `ToriiClientError.stream(ToriiStreamError)`, preserving the stable
code, message, optional dropped-message count, and replay flag. Malformed terminal
error payloads fail closed as `ToriiClientError.invalidPayload` rather than being
silently filtered as an unrelated event. These generic event helpers remain anonymous
without `canonicalRequestAuth`; when configured, the SDK signs the final GET including
its exact `filter` query so restricted-dataspace events visible to that account are included.

### Hardware acceleration

`NoritoNativeBridge` now exposes the same acceleration controls as the Rust host via
`AccelerationSettings`. SIMD, Metal and CUDA are enabled by default with finite
process resource ceilings; device support and qualification determine availability.
Configure before encoding or interacting with the bridge:

```swift
// Enable Metal compute kernels and tweak Merkle GPU thresholds.
var accel = AccelerationSettings(enableMetal: true,
                                 merkleMinLeavesMetal: 256,
                                 preferCpuSha2MaxLeavesAarch64: 128)
let accepted = accel.apply() // True when the available native owner accepts policy.

// Or initialize the SDK with explicit settings
let tunedSDK = IrohaSDK(baseURL: torii.baseURL, accelerationSettings: accel)

// Load the same structure from an iroha_config JSON file.
if let configURL = Bundle.main.url(forResource: "acceleration", withExtension: "json") {
    do {
        let configSettings = try AccelerationSettings.fromIrohaConfigFile(at: configURL)
        let sdkFromConfig = IrohaSDK(baseURL: torii.baseURL, accelerationSettings: configSettings)
        _ = sdkFromConfig // use in your app
    } catch {
        assertionFailure("Invalid acceleration config: \\(error)")
    }
}
```

Optional counts use `nil` to inherit defaults and preserve an explicit zero.
Negative or overflowing file values are errors. Resource ceilings live under
`[accel.resource_limits]`; zero remains a zero ceiling. The loader accepts an explicit
file URL or bundled configuration and throws for malformed present policy. It does
not read runtime environment toggles. The native process owner supplies enabled
defaults; loading the Swift bridge preserves any existing native policy. Policy
acceptance is separate from hardware availability and qualification.
SDK construction without explicit acceleration settings inherits the current process
policy, preserving file-configured opt-outs.

To surface telemetry and parity evidence in dashboards, read the runtime state before
publishing metrics:

```swift
if let state = AccelerationSettings.runtimeState() {
    print("Metal supported:", state.metal.supported,
          "configured:", state.metal.configured,
          "available:", state.metal.available,
          "parity OK:", state.metal.parityOK)
    print("CUDA supported:", state.cuda.supported)
}
```

`runtimeState()` returns both the applied configuration and the Metal/CUDA runtime
status exposed by the bridge (`available` reflects whether the backend passed parity
self-tests on the current host). The helper returns `nil` when the Norito bridge
symbols are unavailable, matching the behaviour of the setter.

### Norito fixtures & parity

`getSumeragiStatus()` returns the sole native protocol-1 status model. Its
current-round, memory and same-applied-cut beacon readiness observations do not
confer finality authority. The JSON decoder requires every nullable field,
rejects duplicate/unknown fields and signed or non-integral number tokens, and
keeps all `UInt64` values exact. `SumeragiStatusWire` encodes the same model in a
complete canonical uncompressed Norito frame; bare payloads and retired status
layouts are rejected. JSON and wire parity share the Rust-generated corpus at
`fixtures/sumeragi/native_status_v1.tsv`.

`getSumeragiLanes()` parses the operator route `GET /v1/sumeragi/lanes`
(`specs/sumeragi_lanes.md` §8) into `ToriiSumeragiLaneStatus`. Each record requires
its committed `daLayout` RS16 geometry, including the encoding and resource bounds.
Lane observations do not confer finality.

The Rust xtask is the sole owner of the shared Norito RPC fixtures in
`fixtures/norito_rpc`. For that shared corpus, `IrohaSwift/Fixtures` is a generated
descriptor-only mirror containing `transaction_payloads.json` and
`transaction_fixtures.manifest.json`; shared `.norito` payload blobs remain in the
canonical directory. Swift-owned `swift_*` test artifacts are separate and are not
copies of the shared corpus.

Regenerate the canonical outputs and every SDK mirror before updating tests or
dashboards:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/second-new-norito-rpc-publication
```

Both external output roots are create-only and must not already exist. Before
any tracked update, require identical exact path sets, entry types, modes,
completion manifests, and every file byte. Apply the reviewed identity-relative
patch from either sealed root, then verify the tracked owner and Swift
descriptor mirror with:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-verify
make swift-fixtures-check
```

Run both the fixture parity check and dashboard validation in one shot:

```bash
make swift-ci
```

The parity checker compares the two generated JSON files directly with
`fixtures/norito_rpc` and rejects copied shared payload blobs. Commit the canonical
outputs and all generated SDK mirrors together; never use Java resources, an archive,
or a retained historical payload as an alternate Swift fixture source.

### Connect (WalletConnect-style relay)

For a qualified deployment carrying complete native execution proofs, construct
`ConnectClient` with `webSocketFactory: .urlSessionForExecutionProofs()`. This
explicitly sets the URLSession WebSocket message bound to four MiB plus 4,096
framing bytes. Ordinary factories retain their platform defaults. This option
does not qualify a wallet or proof profile: Torii, P2P peers and proxies must use
the matching reviewed execution transport configuration, and wallets must still
validate the complete canonical transaction and its approved fee limit.

The SDK ships `ConnectClient` and `ConnectSession` helpers for WebSocket
session management, typed frame exchange, and encrypted envelope handling.
Frame encoding/decoding flows through `ConnectCodec`, which requires the Norito
bridge (throws `ConnectCodecError.bridgeUnavailable` when the XCFramework is
absent). The launch identity is always the exact tuple `(NetworkId, app_pk,
nonce16)`; the SDK derives and verifies the SID instead of accepting a caller-
supplied identifier:

```swift
Task {
    do {
        let torii = ToriiClient(baseURL: URL(string: "https://node.example")!)
        let networkID = try NetworkId(literal: canonicalNetworkID)
        let keyPair = try ConnectCrypto.generateKeyPair()
        let nonce = try secureRandomBytes(count: 16)
        let created = try await torii.createConnectSession(
            networkID: networkID,
            appPublicKey: keyPair.publicKey,
            nonce: nonce
        )
        let request = try ConnectClient.makeWebSocketRequest(
            baseURL: torii.baseURL,
            sid: created.sid,
            role: .app,
            token: created.tokenApp
        )
        let connect = ConnectClient(request: request)
        let session = try ConnectSession(
            networkID: networkID,
            appPublicKey: keyPair.publicKey,
            nonce: nonce,
            relayToken: created.tokenRelay,
            client: connect
        )
        connect.start()
        let open = ConnectOpen(appPublicKey: keyPair.publicKey,
                               appMetadata: ConnectAppMetadata(name: "Demo dApp", iconURL: nil, description: nil),
                               constraints: ConnectConstraints(networkID: networkID),
                               permissions: ConnectPermissions(methods: ["SIGN_REQUEST_TX"]))
        try await session.sendOpen(open: open) // one-shot app→wallet sequence 1
        for try await event in session.eventStream() {
            print("connect event:", event)
        }
    } catch {
        print("connect setup failed: \(error)")
    }
}
```

`ToriiClient` exposes the Connect REST surface so apps can create sessions,
manage their registry/policy/manifest, and inspect one session through
`GET /v1/connect/status?sid=...` with its management token. The separate
`getConnectStatus()` aggregate targets `/v1/connect/status/aggregate` and
requires a `ToriiOperatorSigningContext`; never provision that node operator
key to an app or wallet.

```swift
let torii = ToriiClient(baseURL: URL(string: "https://torii.example")!)
let session = try await torii.createConnectSession(
    networkID: networkID,
    appPublicKey: appPublicKey,
    nonce: nonce
)
// Keep tokenManagement server-side; the canonical wallet URI carries token and relay.
let apps = try await torii.listConnectApps()
let manifest = try await torii.getConnectAdmissionManifest()
let wsRequest = try ConnectClient.makeWebSocketRequest(baseURL: torii.baseURL,
                                                       sid: session.sid,
                                                       role: .app,
                                                       token: session.tokenApp)
let connect = ConnectClient(request: wsRequest)
```

The request builder requires canonical unpadded base64url values for exactly
32-byte SIDs and role tokens. It keeps the role token out of the URL and sends
it only in the `Authorization` header.

Wallet approval code can derive the relay binding with
`ConnectCrypto.relayAuthHash(sessionID:relayToken:)` before signing the approval
preimage. Verify approvals with `ConnectCrypto.verifyApprovalSignature`; it binds
the exact network constraints, SID, app/wallet keys, canonical single-key Ed25519
I105 account, accepted permissions/proof, and relay authorization. Keep
`session.tokenManagement` server-side for deletion and per-session status calls.

Encryption/decryption of ciphertext envelopes is handled by the bridge-backed helpers:
derive keys via `ConnectCrypto`, call `session.setDirectionKeys(_:)`, and `ConnectSession`
will decrypt ciphertext frames into `ConnectEnvelope` instances automatically (use
`nextControlFrame()` or `await session.nextEnvelope()` for decrypted payloads).

Persist Connect X25519 keys via `ConnectKeyStore` so wallet approvals can include the
attestation bundle (SHA-256 digest + device label + created-at). The default store writes
to Application Support; inject a custom directory if you need sandboxed storage. Integrity
checks use a canonical JSON ordering; noncanonical HMAC orderings are rejected.
> After deriving direction keys (e.g., via `ConnectCrypto.deriveDirectionKeys`), call
> `ConnectSession.setDirectionKeys(_:)` to unlock automatic decryption of encrypted
> control frames. Use `ConnectEnvelope.decrypt(frame:symmetricKey:)` for direct access
> to the decrypted payload when you need to inspect non-control envelopes.

#### Retry policy

`ConnectRetryPolicy` mirrors the Rust reference implementation (`connect_retry::policy`) so every SDK samples the same exponential back-off with full jitter (base 5 s, cap 60 s). Provide the Connect session identifier as the seed to keep reconnection jitter deterministic across platforms:

```swift
let policy = ConnectRetryPolicy()
let seed = sessionID // 32-byte Data from the Connect session
for attempt in 0..<5 {
    let delayMs = policy.delayMillis(forAttempt: UInt32(attempt), seed: seed)
    try await Task.sleep(nanoseconds: UInt64(delayMs) * 1_000_000)
    try await connect.start()
}
```

The Android and JavaScript SDKs use the same seed/attempt mapping, so reconnect back-off remains identical regardless of the client stack.

### Governance API helpers

`ToriiClient` now wraps the governance REST endpoints so apps can draft contract deployment proposals, submit ballots, and fetch referendum state without reimplementing the HTTP layer. The responses include Norito transaction skeletons (`tx_instructions`) that you can feed into the SDK transaction builders:

```swift
let canonicalAuth = ToriiCanonicalRequestAuth(
    accountId: "<canonical-domainless-account-id>",
    privateKey: Data(repeating: 0x01, count: 32) // Replace with a securely loaded seed.
)
let proposal = ToriiGovernanceDeployContractProposalRequest(proposalOperator: canonicalAuth.accountId,
                                                            contractAlias: "demo::universal",
                                                            codeHash: Data(repeating: 0xf0, count: 32),
                                                            abiHash: Data(repeating: 0xe1, count: 32),
                                                            abiVersion: 1,
                                                            manifestProvenance: .init(
                                                                signer: "ed25519:…",
                                                                signature: "ed25519:…"
                                                            ))
let draft = try await torii.submitGovernanceDeployContractProposal(
    proposal,
    canonicalAuth: canonicalAuth
)

// Convert the instruction skeleton into a signed transaction envelope
// (TxBuilder helpers reuse the Norito payload emitted by Torii).
// try txBuilder.submit(envelope: yourConversionHelper(draft.txInstructions))

let tally = try await torii.getGovernanceTally(
    id: "referendum-123",
    canonicalAuth: canonicalAuth
)
print("approve:", tally.approve, "reject:", tally.reject)
```

Governance mutation DTOs are closed, public-only types. They cannot carry a
private key, witness, or an unrecognized JSON extension; sign the returned
transaction skeleton locally. Deployment proposals deliberately expose no
proposal window, voting mode, or `limits` field. Their typed 32-byte hashes
encode as exact lowercase 64-hex JSON strings, ABI V1 encodes as a number, and the response contains
only `proposal_id` plus `tx_instructions` (there is no compatibility `ok` flag).
Manifest provenance uses `ToriiContractManifestProvenance` rather than opaque
JSON.

Both V1 ZK submission formats share `GovernanceZkBallotPublicInputs`, whose
only fields are `root_hint`, `owner`, `amount`, `duration_blocks`, `direction`,
and `nullifier`. The flat envelope and nested `BallotProof` routes are available
through `submitGovernanceZkBallotV1` and `submitGovernanceZkBallotProofV1`.
Plain ballots accept a `UInt64` duration in Swift and encode it as the canonical
decimal JSON string required by Torii. ZK backend tags are exact non-empty
tokens: whitespace and control-character variants are rejected before an HTTP
request is dispatched. Referendum and election selectors use one first-release
grammar across REST and locally signed transactions: 1–128 RFC 3986 unreserved
ASCII bytes, without a leading dot.

Proposal-backed equal-Parliament-ballot, finalize, and enact draft routes are
retired; binding proposal transitions use certificate-driven Parliament
attempts. Locally signed `CastZkBallotRequest` transactions use the same
closed `GovernanceZkBallotPublicInputs` model as REST, including typed `UInt64`
durations and exact ballot directions. Arbitrary `NoritoJSON` public-input
objects are intentionally not accepted.

The same helpers are exposed on `IrohaSDK` via convenience methods (for example,
`sdk.submitGovernancePlainBallot(...)`, `sdk.getGovernanceProposal(idHex:)`). Unlock statistics (`/v1/gov/locks/stats`) accept optional `height` and `referendum_id` filters.

### Norito RPC helper

Use `NoritoRpcClient` when you need direct access to the binary RPC surface.
The helper mirrors the JavaScript client and centralizes the
`application/x-norito` headers, optional query parameters, and timeout
handling.

```swift
import IrohaSwift

let rpc = NoritoRpcClient(
    baseURL: URL(string: "https://torii.dev.sora.net")!,
    session: URLSession(configuration: .ephemeral),
    defaultHeaders: ["User-Agent": "SwiftNRPC/1.0"]
)
let payload = try noritoEncode(typeName: "PipelineSubmitRequestV1",
                               payload: signedEnvelopeBytes)

if #available(iOS 15.0, macOS 12.0, *) {
    Task {
        let response = try await rpc.call(
            path: "/v1/pipeline/submit",
            payload: payload,
            params: ["dry_run": "false"]
        )
        print("submit response bytes:", response.count)
    }
}
```

- Relative/absolute paths are supported and query parameters are percent-encoded.
- `Content-Type`/`Accept` default to `application/x-norito` with per-call overrides and
  removal (`headers: ["Accept": nil]`).
- `NoritoRpcError` exposes the HTTP status code + textual body for non-2xx responses.
- Regression tests live in `IrohaSwift/Tests/IrohaSwiftTests/NoritoRpcClientTests.swift`.

## SoraFS replication-order instructions

`SorafsReplicationInstructionBuilders` emits the exact native V1 JSON variants
and can schema-close them again with `decode(_:)`:

```swift
let issue = try SorafsReplicationInstructionBuilders.issueReplicationOrder(
    orderId: orderId,
    orderPayload: replicationOrderBytes,
    issuedEpoch: 20,
    deadlineEpoch: 28,
    musubiArchiveId: archiveId
)
let complete = try SorafsReplicationInstructionBuilders.completeReplicationOrder(
    orderId: orderId,
    providerId: providerId,
    completionEpoch: 27,
    expectedAuthority: try SorafsProviderIngestCompletionAuthorityV1(
        providerOwner: providerOwner,
        completionSigner: completionSigner,
        signerPolicy: try SorafsProviderIngestCompletionSignerPolicyV1(
            policyId: policyId,
            revision: 2,
            predecessorDigest: predecessorDigest,
            policyDigest: policyDigest
        )
    ),
    expectedAssignmentRevision: 3,
    finalizedAnchor: try SorafsProviderIngestFinalizedAnchorV1(
        height: 41,
        blockHash: blockHash
    )
)
let expire = try SorafsReplicationInstructionBuilders.expireReplicationOrder(
    orderId: orderId,
    expirationEpoch: 29
)
```

IDs must be non-zero lowercase 64-hex strings. Issue validates canonical,
bounded `ReplicationOrderV1` framing, the embedded order ID, target/provider
assignment policy, and deadline ordering. Its schema-closed JSON always carries
the fifth `musubi_archive` field as a canonical archive ID or `null`; the
four-field pre-binding shape is rejected. Completion requires the exact six-field
hard cut: `order_id`, `provider_id`, `completion_epoch`,
`expected_authority`, `expected_assignment_revision`, and `finalized_anchor`.
The authority retains the provider owner, mandatory completion signer, and four-part signer-policy chain;
missing, retired three-field, alias, or unknown shapes are rejected.

## NoritoBridge packaging

The release process for the Norito Swift bindings is documented in
[`docs/norito_bridge_release.md`](../docs/norito_bridge_release.md). Follow the
authenticated external-artifact build, validation, and packaging flow there.
`Package.swift` uses that exact local/external path and does not use a remote
URL/checksum binary target. Authenticate the immutable XCFramework ZIP and run an
ordinary SwiftPM Release consumer before claiming installation readiness.
Generated artifacts stay untracked, and the resulting release asset
uses the SemVer in `IrohaSwift/VERSION`; it need not numerically equal the
`norito` Rust crate version. The release binds Rust inputs through the reviewed
commit, source fingerprint, and root lockfile.
The canonical `NoritoBridge.artifacts.json` is embedded in the XCFramework and
records the bridge version plus per-platform SHA-256 hashes.
`dist/NoritoBridge.artifacts.json` is the stable relative symlink to that embedded
manifest; publishing the XCFramework therefore switches both binaries and evidence
through one atomic directory exchange.
`scripts/archive_norito_xcframework.py` is the only supported distribution archive
owner; `make bridge-xcframework` invokes it with `SOURCE_DATE_EPOCH`. Do not create
release ZIPs with `zip` or `ditto` directly. The owner recomputes repository/tool
provenance, authenticates every Mach-O architecture and required/forbidden export,
and publishes normalized ZIP bytes atomically; CI compiles a fresh SwiftPM consumer
from that exact archive.

### NoritoBridge policy and troubleshooting
- Builds require the authenticated `NoritoBridge.xcframework`, selected through
  `MOBILE_SDK_APPLE_ARTIFACT_DIR` or the default `dist/` directory; package resolution
  fails when the artifact is missing or malformed.
- SwiftPM retains the native exports through ordinary C references. Downstream
  packages inherit the required native links without additional linker flags.
- Broken bridge symbols surface `bridgeUnavailable`/`nativeBridgeUnavailable` errors
  that include the expected xcframework location.
- Example: `swift test --package-path IrohaSwift --disable-automatic-resolution`
  requires the bridge artifact and reviewed `Package.resolved` to be materialized first.

## SwiftUI demo and CI

A SwiftUI wallet example (`examples/ios/NoritoDemoXcode`) showcases token balances,
Torii WebSocket subscriptions, and IRH transfers. The Xcode project, Swift sources, and
configuration templates are checked into the repository. Launch the demo by
supplying the Norito bridge XCFramework and populating the `.env` file (keys
such as `TORII_NODE_URL`, `CONNECT_TOKEN_APP`,
`CONNECT_TOKEN_WALLET`, `CONNECT_TOKEN_RELAY`, and `CONNECT_NETWORK_ID` are read on startup). Validation
hooks for local and CI use live in `scripts/ci/verify_norito_demo.sh`.

For contributor setup and Torii mock ledger instructions, refer to
[`docs/norito_demo_contributor.md`](../docs/norito_demo_contributor.md).

## Musubi V1 registry reads

`MusubiToriiClientV1` is an exact-network authenticated client for the twelve typed
`/v1/musubi/queries/*` POST routes. Construction requires a `ToriiLocalSigningContext`, and every
method requires canonical account signing material. Each exact raw body/path is signed with that
context's `NetworkId`; requests use fresh one-shot authentication and never follow redirects. Its
first-release-only models preserve
structural package identities, immutable namespace bindings, canonical
structured SemVer requirements, exact unsigned JSON integers, finalized cursors,
one exact genesis-derived `NetworkId`, and the authoritative archive commitment. Decoding
rejects unknown fields, unsupported
ABI/edition versions, noncanonical names, and duplicate parent-local dependency
aliases instead of accepting legacy or ambiguous forms. Response bodies are
streamed into a 32 MiB bounded collector; declared oversize and the first
undeclared excess byte cancel the request before unbounded allocation.

Swift, Kotlin, and Java exercise the Rust-owned contract in
[`fixtures/musubi/sdk_v1.json`](../fixtures/musubi/sdk_v1.json). Authentication headers are built
only from each method's explicit canonical-auth value; caller-injected canonical or witness
headers fail before dispatch.

`search(_:canonicalAuth:)` posts to `/v1/musubi/queries/search` and returns a bounded,
structurally ordered page with a search-specific finalized projection cursor;
the discovery projection is never a resolver input.

`findArchiveRetention(_:canonicalAuth:)` accepts a sorted, distinct, non-zero archive batch
and verifies the response identity order plus the optional finalized-snapshot
binding before returning cache-prune classifications.

`MusubiInstructionV1` also provides fixture-backed field-to-Norito construction
for namespace registration; maintainer invitation, acceptance, revocation,
role replacement, and removal; permanent alias registration; exact release-
digest assertion; archive registration, location addition or renewal, and
location retirement; release publication and reversible yank state; package
metadata replacement; and Parliament-enacted package ownership recovery,
permanent-alias retargeting, artifact takedown, and registry-policy replacement.
Call
`transactionInstructionFrame()` for the dynamic pair consumed by transaction
builders, or
`standaloneInstructionBoxFrame()` only when an API explicitly requires a
standalone framed box. Both forms are checked against the Rust-owned
[`fixtures/musubi/instructions_v1.json`](../fixtures/musubi/instructions_v1.json);
one real signed-batch regression also extracts and compares all nineteen inline
pairs, including the compact `ChainId` and `TransactionSignature` wrappers.

## Development commands

- Run the package tests:

  ```bash
  swift test --package-path IrohaSwift --disable-automatic-resolution
  ```

- Render/validate the parity + CI dashboards (uses sample feeds by default):

  ```bash
  make swift-dashboards
  ```

  Use `SWIFT_PARITY_FEED` / `SWIFT_CI_FEED` environment variables to point at
  exporter output when available.

- Sync the Norito fixtures used for Swift parity/dashboards:

  ```bash
  cargo run --locked -p xtask --features dev-tools --bin xtask -- \
    norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication
  cargo run --locked -p xtask --features dev-tools --bin xtask -- \
    norito-rpc-fixtures --output-root /path/to/second-new-norito-rpc-publication
  ```

  Compare the exact path sets, entry types, modes, completion manifests, and
  every file byte before applying the reviewed identity-relative tracked patch;
  then run `norito-rpc-verify` and `make swift-fixtures-check`.

## Documentation & Integration Guides

- SDK overview and APIs: [`specs/sdk/swift/index.md`](../specs/sdk/swift/index.md)
- Public Swift SDK and Connect tutorial: [docs.iroha.tech](https://docs.iroha.tech/guide/tutorials/swift.html)
- Executable Connect examples: [`examples/ios/NoritoDemo`](../examples/ios/NoritoDemo/README.md) and [`examples/ios/NoritoDemoXcode`](../examples/ios/NoritoDemoXcode/README.md)
- SwiftUI demo contributor guide (local Torii setup, acceleration toggles): [`docs/norito_demo_contributor.md`](../docs/norito_demo_contributor.md)


## Kaigi V1

`KaigiInstructionsV1.swift` owns all nine native Kaigi instruction builders.
Private create requires the complete commitment, nullifier, roster root and
proof bundle; private join, leave and end use the same bundle. Usage takes a
separate scalar commitment and supplied proof. The node binds these artifacts
to the current call, original account, action and participation sequence.

`KaigiAuthorizationScalarV1` preserves all 32 little-endian Pasta Fp bytes below
the modulus, including zero. Commitment and nullifier wrappers each contain
one scalar field. They have no hash marker, alias tag or issuance timestamp.
The roster root remains a separate marked Iroha hash.

Account-controller policies retain the full u16 member count (1–65,535). The
public address constructors and parsers require the ABI-25 Rust address codec
for complete key and policy admission. Canonical I105 parsers reject surrounding
Unicode whitespace; unavailable native validation is an
explicit error. The
address decoder requires the single canonical count layout, V1 policy version,
nonzero weights, reachable threshold and members ordered by algorithm name and
full public-key bytes. `MultisigPolicyBuilder` sorts input members into that
order and rejects duplicates. Tests use the same canonical account encoder as
applications.

`KaigiPrivacyStateV1.decodeCanonicalRecordJSON` reads the full retained record,
including original host and retained original participant accounts. It checks
strict scalar/integer JSON, duplicate and unknown fields, effective participant
limits, lifecycle, roster ownership and reserved leave/end history capacity.
Arbitrary metadata keeps its own JSON values. Account comparisons retain full
controllers, including multisig policy, independent of network display prefixes.
The redacted Torii application view cannot supply this record. This projection
does not authenticate a response, recompute the roster root, check canonical
account ordering, establish rekey authority or verify an authorization proof.

`KaigiFinalWireFixturesV1.swift` pins all nine transparent instruction forms,
all five private actions and a complex private create to Rust-owned model
bytes. Its synthetic proofs are wire fixtures. Proof generation, native bridge
qualification and four-validator execution require separate evidence. The
canonical Swift package always requires the real ABI25 NoritoBridge artifact.

`ValidatorStakingNoritoV1` decodes first-release authority generations, epoch
authorizations, signed all-edge beacon DKG records, committee transitions,
typed registration, bond, withdrawal and slash plans, bounded reward claims with an explicit optional fee-custody
payment, and peer rebinding. Its Rust-authored fixture is
`fixtures/validator_staking/norito_v1.tsv`; the consumer tests also reject
truncated records, malformed peer bindings, invalid withdrawal hash widths or markers,
retired reward-plan layouts, invalid fee custody and
noncanonical quantity decimals. This structural codec
does not verify signatures, custody, or committee activation.
