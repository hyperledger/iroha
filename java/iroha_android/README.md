# IrohaAndroid

`IrohaAndroid` provides a native Android library that wraps Hyperledger Iroha
capabilities for Kotlin/Java mobile applications. The library includes key
management (including secure-element-backed keys), transaction building and
signing, Norito serialization helpers, and networking clients for interacting
with Iroha nodes.

The current API covers the offline key management façade, Norito encoding backed
by the shared `norito-java` implementation, the Android Keystore/StrongBox
backend (with cached attestations + explicit deterministic software providers), and
network client abstractions. The instruction helpers include RWA lot builders
alongside NFT helpers:
`RegisterRwaInstruction`, `TransferRwaInstruction`,
`MergeRwasInstruction`, `RedeemRwaInstruction`,
`FreezeRwaInstruction`, `UnfreezeRwaInstruction`,
`HoldRwaInstruction`, `ReleaseRwaInstruction`,
`ForceTransferRwaInstruction`, `SetRwaControlsInstruction`,
and RWA-aware metadata setters/removers.

## Gradle quickstart

Point Gradle at the repository that hosts the SDK (the default
`ci/publish_android_sdk.sh` output lives under `artifacts/android/maven`) and
depend on the surface you need:

```kotlin
repositories {
    google()
    mavenCentral()
    maven { url = uri("../../artifacts/android/maven") } // or your Nexus
}

dependencies {
    implementation("org.hyperledger.iroha:iroha-android:<version>") // Android AAR
    implementation("org.hyperledger.iroha:iroha-android-jvm:<version>")     // JVM tooling
}
```

The sample app (`:samples-android`) can validate AAR consumption from a local
repository with:

```bash
./gradlew -p java/iroha_android :samples-android:assembleDebug \
  -PirohaAndroidUsePublished=true \
  -PirohaAndroidRepoDir=$PWD/../artifacts/android/maven
```

It uses the local snapshot repository when it exists and otherwise uses the
in-repo project dependency. Set `irohaAndroidVersion` to match the
published coordinates when consuming from Maven.

The Java facades reuse the Kotlin SDK artifacts published as
`org.hyperledger.iroha.sdk:core-jvm` and `client-android`. Their Maven version
is pinned by `irohaKotlinSdkVersion` in `gradle.properties`; update that pin
when publishing a new compatible Kotlin transport release. An explicit
`-PirohaKotlinSdkVersion` overrides the pin, followed by the optional shared
`irohaSdkVersion` property and finally `irohaAndroidVersion` when the more
specific properties are absent. Composite builds substitute the in-tree
Kotlin projects while preserving these exact coordinates in generated POMs.

## DA commitment and pin-intent proofs

`HttpClientTransport.newDaToriiClient()` returns the Java typed DA client. It
covers the proof-policy, commitment list/prove/verify, and pin-intent
list/prove/verify routes. Use `DaModels.Digest32` for manifest and storage-ticket
digests and `BigInteger` for unsigned 64-bit counters.

```java
final DaToriiClient da = transport.newDaToriiClient();
DaModels.PinIntentListResponse page =
    da.listPinIntents(
            new DaModels.PinIntentListRequest(BigInteger.valueOf(100), null))
        .join();
while (page.nextCursor() != null) {
  page =
      da.listPinIntents(
              new DaModels.PinIntentListRequest(
                  BigInteger.valueOf(100), page.nextCursor()))
          .join();
}
final DaModels.PinIntentProof proof =
    da.provePinIntent(
            new DaModels.PinIntentQueryRequest(
                null,
                DaModels.Digest32.fromHex(ticketHex),
                null, null, null, null))
        .join();
if (proof != null) {
  assert da.verifyPinIntent(proof).join().valid();
}
```

List routes use immutable, server-issued snapshot cursors and return an explicit
nullable `nextCursor()`. Proof routes use separate selector-only request types;
pagination fields are not accepted by proof requests.

Responses are decoded into closed typed models. The client rejects unknown
fields, malformed transparent byte wrappers, invalid checksummed hashes,
contradictory verification responses, and Merkle paths whose direction/length
does not match the advertised bundle location. Requests are capped at 64 KiB
and buffered responses at 8 MiB.

## Authoritative Sumeragi status and operational diagnostics

Kotlin `core-jvm` owns Sumeragi status, diagnostics and wire decoding for Kotlin
and Java consumers. Use the `org.hyperledger.iroha.sdk` models and transport
described in the [Kotlin SDK README](../../kotlin/README.md#native-sumeragi-status).
Java consumer tests live in `kotlin/core-jvm/src/test/java`; the separate Java
release leg executes those tests against the same canonical production SDK.

## Peer carriers and KAGEMUSHA wallet wire

This SDK has no Java peer-transport or KAGEMUSHA implementation. Java consumers
call the canonical Kotlin types in `org.hyperledger.iroha.sdk.offline` directly:
the QR, NFC and Nearby carriers (`IrohaPeerQRCodecV1`, `IrohaPeerNfcV1`,
`IrohaPeerNearbySessionV1` and the shared `IrohaPeerWireMessageV1` envelope) in
`core-jvm`, their Android adapters in `client-android`, and
`KagemushaWalletWireV1` in `core-jvm`. The wire contract is
[KAGEMUSHA wallet wire V1](../../specs/kagemusha_wallet_wire_v1.md); Java-source
consumer tests live in `kotlin/core-jvm/src/test/java/org/hyperledger/iroha/sdk/offline/`.

## Fee quotes and sponsorship

Every transaction payload requires a typed `FeePaymentIntent`. Authority-paid
and exact sponsor-program selections are explicit:

```java
import java.util.Collections;
import org.hyperledger.iroha.android.model.FeePaymentIntent;
import org.hyperledger.iroha.android.model.FeeSponsorProgramId;

FeePaymentIntent authorityPaid =
    FeePaymentIntent.authority(Collections.emptyList());
FeePaymentIntent sponsored =
    FeePaymentIntent.sponsor(
        new FeeSponsorProgramId(sponsorAccountId, "wallet_payments"),
        3L,
        Collections.emptyList());
```

An empty charge-limit list is only an initial quote draft. Freeze the complete
unsigned payload, put `requested.toJsonMap()` in its required `fee_payment`
field, and call `HttpClientTransport.quoteFees(unsignedPayload, canonicalAuth)`.
Verify that the quote retained the payer, exact sponsor program/revision, and
gas bound; replace only `fee_payment` with the returned intent before signing
and submitting the same payload. Use
`HttpClientTransport.getFeeSponsorProgram(programId, canonicalAuth)` to inspect
one exact lifecycle record before selecting its revision. Contract/IVM drafts
require a positive gas bound in the intent.

The metadata keys `fee_sponsor`, `gas_asset_id`, and `gas_limit` are retired and
rejected. Sponsor rejection never falls back to the authority.

## Retail fee assessments and multisig proposals for Java callers

Use the canonical Kotlin-owned `org.hyperledger.iroha.sdk.client.MultisigProposeRequest`
and `org.hyperledger.iroha.sdk.client.HttpClientTransport` from `core-jvm` or
`client-android`. Java calls the public constructor and `proposeMultisig(request)`
directly. The request retains defensive instruction snapshots and the bounded
`JsonValue` assessment in `validationFeeAssessment`. Native Core owns assessment
validation and the exact signed nested marker. The transport requires the configured
trusted network and checks the complete unsigned proposal before returning signing
material. The public request also exposes `canonicalToriiJsonBytes()` and
`verifyToriiResponse(responseBytes, networkId)` for Java consumers.

The duplicate Java quote classes, quote endpoint methods, proposal DTO, and
proposal-specific Norito format are retired. See the [canonical SDK instructions](../../kotlin/README.md)
and [retirement inventory](../../specs/jvm_consolidation_inventory.md). Current
policy, enrollment, hardware and proof admission remain required.

## Atomic mixed executable batches

`Executable.batch(...)` preserves an exact interleaving of native instructions
and deployed-contract calls:

```java
Executable executable =
    Executable.batch(
        Arrays.asList(
            ExecutableBatchItem.instruction(registerInstruction),
            ExecutableBatchItem.contractCall(
                new ContractInvocation(
                    contractAddress, expectedCodeHash, "apply", argumentRecord)),
            ExecutableBatchItem.instruction(transferInstruction)));
```

The node applies the batch atomically. Empty batches are rejected. Contract
addresses must be canonical lowercase V1 Bech32m literals, and any batch that
contains a contract call must provide one positive signature-bound gas limit in
the `FeePaymentIntent`; these constraints are checked before signing.

## Native asset-lock cancellation

`CancelAssetLockInstruction` implements the V1 compare-and-cancel contract.
Supply the exact application lock ID and the positive canonical Quantity read
from finalized ledger state:

```java
import org.hyperledger.iroha.android.model.InstructionBox;
import org.hyperledger.iroha.android.model.instructions.CancelAssetLockInstruction;

CancelAssetLockInstruction cancel =
    CancelAssetLockInstruction.builder()
        .setLockId("appeal:case-42")
        .setExpectedRemainingAmount("20")
        .build();
InstructionBox instructionBox = cancel.toInstructionBox();
```

The builder derives the native escrow hash with Blake2b-256 and emits only
`escrow_id` plus `expected_remaining_amount`. The instruction pair uses the
canonical `iroha.instruction.v1::escrow::CancelAssetLock` wire ID; its payload
frame retains the concrete `iroha_data_model::isi::escrow::CancelAssetLock`
Norito schema name. The lock-ID
preimage must be nonempty exact text without surrounding whitespace or a BOM
and is bounded by `CancelAssetLockInstruction.MAX_LOCK_ID_UTF8_BYTES_V1`
(4,096 UTF-8 bytes, not characters); the on-wire `EscrowId` remains 32 bytes.
The retired one-field shape, aliases, extra fields, zero, and alternate numeric
spellings are rejected; stale expected amounts are rejected atomically by the
ledger.

## Account addresses

```java
import org.hyperledger.iroha.android.address.AccountAddress;

byte[] key = new byte[32];
AccountAddress address = AccountAddress.fromAccount(key, "ed25519");
System.out.println(address.canonicalHex());
System.out.println(address.toI105(753));

AccountAddress.DisplayFormats formats = address.displayFormats();
System.out.println(formats.i105);
System.out.println(formats.i105Warning);
```

Use `displayFormats()` whenever UI layers need to render or copy addresses so the warning text and
network prefix stay aligned with `specs/sns/address_display_guidelines.md`.

## Native privacy bridge

`PrivacyNativeBridge` exposes local build metadata only.
`compiledProfileCatalogV1()` returns this binary's canonical typed
`PrivacyCompiledProfileCatalogV1` Norito archive, and
`protocolsV1()` exposes the closed `ProtocolIdV1` enum in exact wire order. The
generic proof request/build/verify ABI and free-form algorithm selectors are
absent; proofs must use protocol-specific typed APIs. The local catalog never
establishes activation or readiness; proof submission requires a fresh
committed `/v1/privacy/capabilities` snapshot from live Torii.

Genesis `confidential_features` and `zk_policy_hash` values are opaque consensus
fingerprints, never client-side proof or backend selectors.
`ClientConfigManifestLoader` rejects those keys (and their camel-case aliases)
at any depth. Proof construction must use Torii's committed
`/v1/privacy/capabilities` response and the on-chain verifying-key registry.

`PrivacyExact12FixtureCodecV1` decodes the first-release
`PrivacyExact12FixtureBundleV1` entirely in Java; it does not load the native
bridge. Pass one canonical standard-Base64 line (without the fixture file's
final LF), or decode raw Norito bytes directly:

```java
PrivacyExact12FixtureBundleV1 bundle =
    PrivacyExact12FixtureCodecV1.decodeCanonicalBase64(fixtureLine);
byte[] canonicalArchive = PrivacyExact12FixtureCodecV1.encodeCanonical(bundle);
PrivacyExact12FixtureCodecV1.requireCanonicalArchive(receivedArchive, canonicalArchive);
```

The codec requires the exact schema, version, twelve-row order, uncompressed
`COMPACT_LEN` layout, and configured field/aggregate limits. It rejects
alternate Base64, truncation, trailing or unknown data, and reordered rows.
Use `requireCanonicalArchive` with an independently trusted fixture when exact
cross-row and cross-field identity matters.

The registry has exactly twelve IDs: `zk-ace-pq-authorization-v1`,
`anonymous-pgc-k-out-of-n-v1`, `verange-transparent-range-v1`,
`iroha-zk-ams-v1`, `vega-existing-credential-zk-v1`,
`iroha-zk-x509-stark-p256-v1`,
`iroha-jindo-polynomial-commitment-v1`,
`iroha-bootle-lantern-anoncred-v1`, `orchard-halo2-actions-v1`,
`monero-fcmp-plus-plus-v1`, `iroha-ivm-private-note-stark-v1`, and
`pq-masp-stark-v1`. Parsing is exact: aliases, retired IDs, case changes, and
whitespace normalization fail closed.

## Multisig specs and TTL preview

```java
import org.hyperledger.iroha.android.multisig.MultisigProposalTtlPreview;
import org.hyperledger.iroha.android.multisig.MultisigSpec;
import org.hyperledger.iroha.android.address.AccountAddress;

byte[] aliceKey = new byte[32];
byte[] bobKey = new byte[32];
String alice = AccountAddress.fromAccount(aliceKey, "ed25519").toI105(753);
String bob = AccountAddress.fromAccount(bobKey, "ed25519").toI105(753);
MultisigSpec spec =
    MultisigSpec.builder()
        .setQuorum(3)
        .setTransactionTtlMs(86_400_000L)
        .addSignatory(alice, 2)
        .addSignatory(bob, 1)
        .build();

MultisigProposalTtlPreview preview = spec.enforceProposalTtl(90_000L, System.currentTimeMillis());
System.out.println("effective ttl: " + preview.effectiveTtlMs());
System.out.println("expires at: " + preview.expiresAtMs());
```

`enforceProposalTtl` rejects TTL overrides above the policy cap (`transaction_ttl_ms`) before
submission so apps can surface the same error Torii would return. Use
`previewProposalExpiry` when you only need a preview (cap + expiry) without throwing.
When registering a multisig controller, supply an explicit canonical I105 account id for a random
controller key (the controller must never be used for direct signing). Nodes now quarantine
deterministically derived controller ids and will reject registration and subsequent
propose/approve attempts that use them.

```java
import java.util.Base64;
import org.hyperledger.iroha.android.model.InstructionBox;

InstructionBox registerMultisig =
    InstructionBox.fromWirePayload(
        "<WIRE_NAME_REGISTER_MULTISIG>",
        Base64.getDecoder().decode("<WIRE_PAYLOAD_BASE64>")); // Replace with wire payload bytes.
```

## Subscriptions

```java
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import org.hyperledger.iroha.android.client.SubscriptionToriiClient;
import org.hyperledger.iroha.android.numeric.NumericV1;
import org.hyperledger.iroha.android.subscriptions.SubscriptionCreateRequest;
import org.hyperledger.iroha.android.subscriptions.SubscriptionCreateResponse;
import org.hyperledger.iroha.android.subscriptions.SubscriptionPlanCreateRequest;
import org.hyperledger.iroha.android.subscriptions.SubscriptionPlanCreateResponse;
import org.hyperledger.iroha.android.subscriptions.SubscriptionUsageRequest;

SubscriptionToriiClient client =
    SubscriptionToriiClient.builder()
        .baseUri(URI.create("https://example.com"))
        .build();

Map<String, Object> plan = new LinkedHashMap<>();
plan.put("kind", "fixed");
plan.put("price", "120");
plan.put("period", "month");

SubscriptionPlanCreateResponse planResponse =
    client.createSubscriptionPlan(
            SubscriptionPlanCreateRequest.builder()
                .authority("<provider_account_i105>")
                .privateKey("<hex>")
                .planId("aws_compute#commerce")
                .plan(plan)
                .build())
        .join();

SubscriptionCreateResponse subscriptionResponse =
    client.createSubscription(
            SubscriptionCreateRequest.builder()
                .authority("<subscriber_account_i105>")
                .privateKey("<hex>")
                .subscriptionId("sub-001$subscriptions")
                .planId("aws_compute#commerce")
                .build())
        .join();

client.recordSubscriptionUsage(
        "sub-001$subscriptions",
        SubscriptionUsageRequest.builder()
            .authority("<provider_account_i105>")
            .privateKey("<hex>")
            .unitKey("compute_ms")
            .delta(NumericV1.QuantityValue.parseCanonical("3600000"))
            .build())
    .join();
```

## Verifying key registry

`HttpClientTransport` wraps Torii's `/v1/zk/vk/register` and
`/v1/zk/vk/update` routes. The helpers validate production verifier backends,
registry fields, height ranges, and inline verifier-key commitments before
sending the request. Neither request accepts or transmits a private key. Torii
returns HTTP 200 with an unsigned transaction draft. SDK `Signer`
implementations apply Iroha's prehash themselves, so pass
`transactionPayloadBytes()` to `Signer.sign`; use `signingMessageBytes()` only
with an external primitive that signs an already-prehashed message. Attach the
signature to the transaction payload and use the standard transaction ingress.
The `ClientConfig` used by the transport must include an immutable
`LocalSigningContext`; read-only clients may omit it, but draft-producing
mutation routes fail before network I/O when it is absent. The draft parser
binds the exact canonical genesis-derived `NetworkId` and rejects
non-canonical Norito, another network or authority, extra/substituted
instructions, any mismatch in the complete verifying-key record, and signing
messages that do not match the payload prehash:

```java
NetworkId networkId = NetworkId.parse("<canonical_network_id_hash_literal>");
ClientConfig config =
    ClientConfig.builder()
        .setLocalSigningContext(new LocalSigningContext(networkId))
        // Configure the Torii endpoint and other client policy here.
        .build();
HttpClientTransport transport = HttpClientTransport.withExecutor(executor, config);
byte[] vkBytes = new byte[] {1, 2, 3};

VerifyingKeyTransactionDraft registerDraft =
    transport
    .registerVerifyingKey(
        VerifyingKeyRegisterRequest.builder()
            .authority("<authority_i105>")
            .backend("halo2/ipa")
            .name("vk_main")
            .version(1L)
            .circuitId("halo2/ipa::transfer_v1")
            .publicInputsSchemaHashHex("a".repeat(64))
            .gasScheduleId("halo2_default")
            .verifyingKeyBytes(vkBytes)
            .status("Active")
            .build())
    .join();

VerifyingKeyTransactionDraft updateDraft =
    transport
    .updateVerifyingKey(
        VerifyingKeyUpdateRequest.builder()
            .authority("<authority_i105>")
            .backend("halo2/ipa")
            .name("vk_main")
            .version(2L)
            .circuitId("halo2/ipa::transfer_v1")
            .publicInputsSchemaHashHex("a".repeat(64))
            .status("Withdrawn")
            .build())
    .join();

if (registerDraft.submitted()) {
    throw new IllegalStateException("Torii must return an unsigned draft");
}
byte[] registerPayload = registerDraft.transactionPayloadBytes();
byte[] registerSigningMessage = registerDraft.signingMessageBytes();
byte[] registerSignature = signer.sign(registerPayload);
```

## Layout

```
java/iroha_android
├── src
│   ├── main/java
│   │   └── org/hyperledger/iroha/android
│   │       ├── IrohaKeyManager.java
│   │       ├── SigningException.java
│   │       ├── client
│   │       │   ├── ClientConfig.java
│   │       │   ├── ClientResponse.java
│   │       │   ├── HttpClientTransport.java
│   │       │   └── IrohaClient.java
│   │       ├── crypto
│   │       │   ├── KeyProviderMetadata.java
│   │       │   ├── Ed25519Signer.java
│   │       │   ├── SoftwareKeyProvider.java
│   │       │   └── keystore
│   │       │       ├── KeystoreBackend.java
│   │       │       ├── KeystoreKeyProvider.java
│   │       │       └── KeyGenParameters.java
│   │       ├── gpu
│   │       ├── model
│   │       │   ├── Executable.java
│   │       │   └── TransactionPayload.java
│   │       ├── norito
│   │       │   ├── NoritoCodecAdapter.java
│   │       │   ├── NoritoException.java
│   │       │   ├── NoritoJavaCodecAdapter.java
│   │       │   └── TransactionPayloadAdapter.java
│   │       ├── subscriptions
│   │       │   ├── SubscriptionPlanCreateRequest.java
│   │       │   ├── SubscriptionCreateRequest.java
│   │       │   ├── SubscriptionListResponse.java
│   │       │   └── SubscriptionToriiException.java
│   │       └── tx
│   │           ├── SignedTransaction.java
│   │           └── TransactionBuilder.java
│   └── test/java
│       └── org/hyperledger/iroha/android
│           ├── IrohaKeyManagerTests.java
│           ├── client/HttpClientTransportTests.java
│           ├── crypto/keystore/KeystoreKeyProviderTests.java
│           ├── norito/NoritoCodecAdapterTests.java
│           └── tx/TransactionBuilderTests.java
├── src/test/resources
│   └── transaction_payloads.json
├── schemas
│   └── norito_schema_manifest.json
```

## Modules & dependencies

- `:core` — shared Java sources used by both targets.
- `:android` — Android AAR surface (OkHttp transport, keystore helpers) published as
  `org.hyperledger.iroha:iroha-android`.
- `:jvm` — JVM jar (java.net.http transport) published as `org.hyperledger.iroha:iroha-android-jvm`.
- `:samples-android` — launchable demo that exercises Norito encoding and address helpers against the
  AAR; build with `gradle -p java/iroha_android :samples-android:assembleDebug`.

When consuming the workspace via an included build:

```kotlin
dependencies {
    implementation(project(":android")) // Android apps
    implementation(project(":jvm"))     // JVM tooling
}
```

Published artefacts can be pulled directly when the composite build is not in play:

```kotlin
dependencies {
    implementation("org.hyperledger.iroha:iroha-android:${IROHA_ANDROID_VERSION}") // Android (AAR)
    implementation("org.hyperledger.iroha:iroha-android-jvm:${IROHA_ANDROID_VERSION}") // JVM
}
```

The `:samples-android` app defaults to the in-repo `:android` project but can
consume a published Maven repo by setting `irohaAndroidUsePublished=true`
(or `ANDROID_SAMPLE_USE_PUBLISHED=1`) and pointing `irohaAndroidRepoDir` at
`artifacts/android/maven/<version>` from `ci/publish_android_sdk.sh`.
`MainActivity` renders an IH58 address from the AAR, and `SampleAddressTest`
keeps the wiring green for the published-vs-project toggle.

## Build & Test

The Gradle harness targets JDK 21 and wires the included `norito-java` build automatically. From the
repository root:

```bash
bash ci/run_android_tests.sh
# or
make android-tests
# or run a subset of tasks
ANDROID_GRADLE_TASKS=":core:check :android:testDebugUnitTest" bash ci/run_android_tests.sh
```

Use `ANDROID_HARNESS_MAINS` (comma-separated class names) to filter the main-based harnesses, and
`ANDROID_GRADLE_TASKS` to override the Gradle task list.

`gradle -p java/iroha_android :core:check` runs the shared JUnit/parameterised harnesses with
assertions enabled, enforces the pinned Norito schema manifest (`verifyNoritoSchemas`), and calls
`checkAndroidFixtures` (formerly `scripts/check_android_fixtures.py`) so the fixture manifest stays
in sync. Lint and JVM publishing are covered by the default CI task list above, and
`:android:testDebugUnitTest` exercises the Android-only harness alongside the shared tests.

Set `NORITO_JAVA_VERSION=<version>` to exercise a different Norito drop; the manifest guard fails if
it diverges from `schemas/norito_schema_manifest.json`.

`PlatformHttpTransportExecutor` now prefers the Android OkHttp factory when present (substituted in
core tests), falling back to the JDK client elsewhere. The Android module exposes
`OkHttpTransportExecutorFactory` for callers that want to reuse a shared `OkHttpClient`.

To keep JVM-only transports out of the Android artefacts, run the guard after producing an AAR:

```bash
make android-transport-guard
# or provide a custom classes.jar/aar
ANDROID_TRANSPORT_GUARD_AAR=java/iroha_android/android/build/outputs/aar/android-release.aar \
  bash ci/check_android_transport_guard.sh
# or
bash ci/check_android_transport_guard.sh /path/to/classes.jar
```

The guard is fail-closed: the compiled artifact, `jdeps`, and archive tooling
must all be present and successfully inspect the candidate. There is no
override for allowing JVM transports in an Android release.

### Transport defaults and troubleshooting

- HTTP clients use a strict runtime split: Android loads `OkHttpTransportExecutorFactory`, while JVM
  builds load `JavaHttpExecutorFactory`. Apps or services that want a custom transport should inject
  it explicitly with the relevant builder.
- Builders now auto-wire platform defaults: `HttpClientTransport.withDefaultExecutor(...)`,
  `ToriiEventStreamClient.builder()` (without `setTransportExecutor(...)`),
  `SorafsGatewayClient.builder()`, and `HttpSafetyDetectService.createDefault(...)` all pick the
  platform executor so Android apps land on the shared OkHttp client without extra wiring.
- WebSocket clients require an explicit connector. Android callers should inject
  `OkHttpWebSocketConnectorFactory.createDefault()`, while JVM callers should inject
  `JdkWebSocketConnectorFactory.createDefault()`. This keeps platform selection deterministic and
  avoids reflective discovery; `AndroidClientFactory` performs the injection for its clients.
- Android artefacts must not contain `java.net.http` bytecode. The mobile SDK artifact workflow
  assembles the Java release AAR and executes
  `ci/check_android_transport_guard.sh` (also available locally via `make android-transport-guard`)
  to fail when JVM-only classes leak into the Android bundle.
- Guard failures usually mean the wrong artefact was scanned (set `ANDROID_TRANSPORT_GUARD_AAR` to
  the release bundle if you used a custom output path) or a
  JVM-only module was added as an Android dependency. Rebuild with
  `gradle -p java/iroha_android :android:assembleRelease` and rerun the guard before publishing.
- Consumers can supply a custom `OkHttpClient` via `OkHttpTransportExecutorFactory` on Android (the
  default factory uses the shared client provider); JVM callers can opt into
  `JavaHttpExecutorFactory` when `java.net.http` is available on the module path.
- Custom executors must honor `TransportRequest.replayPolicy()`. `ONE_SHOT` requests permit one
  network dispatch and no redirect, authentication follow-up, connection retry, or status retry.
  The Android executor enforces this even when an injected OkHttp client enables redirects/retries;
  the JVM executor rejects a redirect-following `HttpClient` before dispatch.
- When using a custom `OkHttpClient` (for example with certificate pinning) and you need to release
  resources, call `HttpClientTransport.invalidateAndCancel()` (or
  `HttpTransportExecutor.invalidateAndCancel()`) to cancel in-flight requests and clean up the
  underlying dispatcher/connection pool.
- For Android-first apps that want a single transport surface, `AndroidClientFactory` constructs
  HTTP/Norito RPC/SSE/WebSocket/Safety Detect/SoraFS clients around a shared `OkHttpClient`,
  threading through `ClientConfig` headers/observers (including telemetry).

Tests rely on Java assertions (enabled in the Gradle test tasks). Make sure `JAVA_HOME` points to a
JDK 21 or newer installation before running the harness.

If your environment does not provide `/usr/libexec/java_home`, set `JAVA_HOME` explicitly (for
example on Homebrew-based macOS hosts):

```bash
JAVA_HOME="$(brew --prefix openjdk@21)/libexec/openjdk.jdk/Contents/Home" \
./gradlew test
```

Android Foundations pins this workspace to **JDK 21 LTS**. Possible upgrades are only evaluated after
Oracle’s quarterly CPU releases: stage the candidate by setting `ANDROID_JDK_NEXT=1` in Buildkite
so the Gradle harness and Android fixture parity checks soak the alternate toolchain. Capture
the CI logs and record the soak decision in `artifacts/android/fixture_runs/` and `status.md` before
promoting a new JDK.

`scripts/check_android_fixtures.py` keeps the checked-in Norito fixtures and
manifest in sync with the canonical hash metadata. Verify schema pinning with:

```bash
gradle -p java/iroha_android :core:verifyNoritoSchemas
```

Refresh the manifest after Norito schema updates via:

```bash
gradle -p java/iroha_android :core:regenNoritoSchemaManifest
```

Commit the updated `schemas/norito_schema_manifest.json` alongside any Norito changes.

To produce a combined CI-friendly report that exercises both the test harness
and the fixture parity gate, run:

```bash
python3 scripts/android_test_report.py --run-tests --output artifacts/android/test_report.json
```

The helper executes `ci/run_android_tests.sh`, writes the per-step summaries
under `artifacts/android/`, and exits non-zero if either the tests or fixture
parity fail (set `--allow-failures` only when you need a report without failing
the shell).

### Deterministic export & recovery

- `SoftwareKeyProvider.exportDeterministic(...)` emits v4 bundles with per-export salt/nonce,
  `kdf_kind`, and `kdf_work_factor`. Argon2id (64 MiB, 3 iterations, parallelism = 2) is the only
  export KDF. Passphrases must be >=12 characters and the importer rejects all-zero salt/nonce
  seeds.
- `SoftwareKeyProvider` can persist deterministic exports by wiring a `KeyExportStore` plus
  `KeyPassphraseProvider` (for example, `FileKeyExportStore` on Android/JVM, or
  `InMemoryKeyExportStore` in tests). The provider rehydrates keys from the store before generating
  new material, keeping software-backed accounts stable across app restarts.
- `KeyExportBundle.decode(Base64|bytes)` accepts the v4 payload only. Treat
  salt/nonce/ciphertext errors as tampering and capture a fresh bundle rather than reusing an old
  export between devices.
- Regression coverage in `DeterministicKeyExporterTests` includes wrong passphrases and tampered
  salt/nonce/ciphertext, and all-zero seed rejection. Clear passphrase char arrays after use in
  application code.
- `KeystoreKeyProviderTests` exercises cached inspection versus uncached recorded-chain
  verification, explicit re-attestation rejection, and the
  `android.keystore.attestation.failure` telemetry path; run
  `ANDROID_HARNESS_MAINS=org.hyperledger.iroha.android.crypto.keystore.KeystoreKeyProviderTests \
  bash ci/run_android_tests.sh` to spot-check cache and challenge matrices without rebuilding the
  full suite.

### Lint & dependency scanning (AND6 prototype)

Run

```bash
make android-lint
```

from the repository root to execute the AND6 static-analysis prototype
(`ci/check_android_javac_lint.sh`). The script reuses the lightweight javac
target used by `ci/run_android_tests.sh`, enables `-Xlint:all` with warnings treated as
errors, and then invokes `jdeps --summary` to ensure the Android surface only
depends on the approved JDK modules (`java.base`, `java.net.http`,
`jdk.httpserver`). Any new module dependency causes the lint run to fail so
publish jobs can gate on the same policy.

Every run copies the generated `jdeps` summary to
`artifacts/android/lint/jdeps-summary.txt` so CI/release artefacts always have
an up-to-date module list. Set
`ANDROID_LINT_KEEP_WORKDIR=1 make android-lint` to preserve the workspace for
manual inspection and/or provide
`ANDROID_LINT_SUMMARY_OUT=artifacts/android/lint/<tag>/jdeps-summary.txt make android-lint`
when you need an additional, versioned copy for compliance packets.

### Norito fixture rotation

The Rust xtask is the sole owner of the shared Norito RPC fixture corpus. Canonical
payloads, descriptors, manifests, schema hashes, and compact-hash vectors live in
`fixtures/norito_rpc`. The files under `java/iroha_android/src/test/resources` are a
generated Java mirror; Java keeps local `.norito` copies because its parity tests read
those payload bytes directly. Never edit the mirror or its hashes by hand.

Regenerate and verify the complete owner set from the repository root:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/second-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-verify
bash ci/check_android_fixtures.sh
```

Both external generation roots are create-only and must not already exist.
Before any tracked update, require identical exact path sets, entry types,
modes, completion manifests, and every file byte. Apply the reviewed
identity-relative patch from either sealed root, then run the verifier and
Android fixture checker shown above. `make android-fixtures-check` runs only the
parity check. A successful owner generation contains the canonical directory
and every SDK mirror together. Commit the complete generated change set, not an
Android-only subset. The parity wrapper can still write its JSON summary under
`artifacts/android/parity/` for CI evidence, but that report is not fixture source
material.

The test harness currently executes the key manager, keystore flows (with the
Android Keystore fallback backend), Norito codec round-trips that verify typed
instruction decoding, transaction builder signing, and HTTP client serialization
paths to keep the Java pathways aligned.

`connect_norito_bridge` exports JNI only for the Kotlin SDK classes
(`org.hyperledger.iroha.sdk.*`). The Java `NativeSignerBridge`,
`SorafsReferenceValidators` and `AtomicPrivateSettlementNativeResponseVerifierV1`
declare no native methods: they keep their Java argument checks and delegate to the
Kotlin owners, so native availability and the ABI-30 / signer-contract-7
requirements come from the Kotlin SDK. `NativeBridgeDelegationTests` rejects any
new Java `native` declaration. Native-dependent harness mains (ML-DSA, SoraFS
reference validators, native ZK signing) need a host build of the bridge; run them
with `IROHA_NATIVE_LIBRARY_PATH=<dir containing the library> ./gradlew :core:test`.

### Publishing snapshots (AND9)

Run

```bash
make android-publish-snapshot \
  ANDROID_PUBLISH_VERSION=0.2.0-dev.1 \
  ANDROID_PUBLISH_REPO_DIR=$PWD/artifacts/android/maven
```

(or call `./gradlew -p java/iroha_android publish -PirohaAndroidVersion=... -PirohaAndroidRepoDir=...`)
to build/publish both SDK targets (JVM jar and Android AAR), generate the
CycloneDX SBOMs, and emit runtime evidence. The helper stages outputs under
`artifacts/android/reports/<version>/{android,jvm}/` with optional Sigstore
bundles (`ANDROID_PUBLISH_SIGN=1`) and assembles the sample app against the
published AAR unless `ANDROID_PUBLISH_SKIP_SAMPLE=1` is set. Override the
staging root via `ANDROID_PUBLISH_REPORT_DIR` and Maven destinations via
`ANDROID_PUBLISH_REPO_URL`/`ANDROID_PUBLISH_REPO_DIR`.

Key evidence paths (also mirrored under `artifacts/android/reports/<version>`):

- JVM deps: `jvm/build/reports/publishing/iroha-android-jvm-<version>-runtimeClasspath.json`
- JVM runtime manifest/checksum:
  `jvm/build/reports/publishing/iroha-android-jvm-runtime-manifest.json` and
  `jvm/build/reports/publishing/iroha-android-jvm-<version>-runtime.sha256`
- Android deps:
  `android/build/reports/publishing/iroha-android-android-<version>-releaseRuntimeClasspath.json`
- Android runtime manifest/checksum:
  `android/build/reports/publishing/iroha-android-android-runtime-manifest.json` and
  `android/build/reports/publishing/iroha-android-android-<version>-runtime.sha256`
- SBOMs: recorded under `build/reports/` (JSON and XML) with the chosen path
  surfaced via the `sbom.path` field in each runtime manifest.

Every publish invocation automatically runs the manifest/SBOM tasks so
governance packets can attach the resulting JSON alongside the Maven repository
snapshot. See `specs/sdk/android/publishing_plan.md` for the full release
checklist.

### Observability Hooks


> **Instruction APIs:** The Java SDK provides typed `InstructionTemplate`
> builders for register, transfer, mint/burn, permission and role, trigger,
> governance, RWA, confidential-asset, Kaigi, and other implemented instruction
> families. `SetKeyValueInstruction` and `RemoveKeyValueInstruction` cover
> domain, account, asset-definition, NFT, RWA, and trigger metadata;
> `SetAssetKeyValueInstruction` and `RemoveAssetKeyValueInstruction` cover
> concrete asset balances. `InstructionBox.fromWirePayload(...)` carries other
> canonical Norito-framed instruction payloads without inventing a Java-side
> schema.

`ClientConfig` exposes request-scoped instrumentation, static header support,
and a retry-policy utility for caller-managed replay-safe reads. Applications can attach `ClientObserver`
implementations to capture metrics or send tracing data, register default headers
(for example, API tokens or `User-Agent` values). Signed, nonce-bearing, or body-carrying requests
never consume `RetryPolicy` and are never automatically retried.

### Crash telemetry

Enable crash telemetry by installing the built-in handler when configuring the
client:

```java
TelemetryOptions telemetryOptions = TelemetryOptions.builder()
    .setTelemetryRedaction(TelemetryOptions.Redaction.builder()
        .setSaltHex("<hex-salt>")
        .setSaltVersion("2026Q1")
        .setRotationId("rot-7")
        .build())
    .build();

ClientConfig clientConfig =
    ClientConfig.builder()
        .setBaseUri(new URI("https://torii.devnet.example"))
        .setTelemetryOptions(telemetryOptions)
        .setTelemetrySink(myTelemetrySink)
        .enableCrashTelemetryHandler()
        .build();
```

The handler records `android.crash.report.capture` automatically when uncaught
exceptions reach the process boundary. Upload pipelines can reuse the telemetry
configuration to emit `android.crash.report.upload` counters:

```java
clientConfig
    .crashTelemetryReporter()
    .ifPresent(reporter -> reporter.recordUpload(crashId, "sorafs", "success", retryCount));
```

Pass a custom `CrashTelemetryHandler.MetadataProvider` to `setCrashTelemetryMetadataProvider`
when additional crash context (e.g., watchdog buckets) is required.

### Torii streaming (SSE)

`HttpClientTransport.newEventStreamClient()` exposes the shared
`ToriiEventStreamClient` without synthesizing an account identity. With no
auth-bearing default headers, requests remain fully anonymous and public-only.
The client still reuses the same base URI, telemetry observers, and default
headers as the HTTP transport. Streaming clients consume Torii’s
server-sent event feeds and surface parsed frames via the listener interface:

```java
ToriiEventStreamClient streams = httpTransport.newEventStreamClient();
ToriiEventStream stream =
    streams.openSseStream(
        "/v1/events/sse",
        ToriiEventStreamOptions.defaultOptions(),
        new ToriiEventStreamListener() {
          @Override
          public void onEvent(ServerSentEvent event) {
            event.terminalStreamError().ifPresent(error -> {
              throw error;
            });
            System.out.println(event.event() + ": " + event.data());
          }
        });

// Remember to close the stream when your component is torn down.
stream.close();
```

Use `newEventStreamClient(canonicalAuth)` with a configured
`LocalSigningContext` for restricted visibility. The client generates all four
canonical headers after path resolution, filter normalization, and option-query
assembly, binding the signature to the exact final URI. Precomputed or partial
canonical headers are rejected before dispatch.

Listeners receive retry hints (via `retry:` frames) so applications can reuse
Torii’s back-off guidance, and telemetry observers attached to the transport
emit the same hashed-authority metadata recorded for HTTP submissions. When the
transport supports streaming responses (OkHttp/JDK/URLConnection), frames are
parsed as they arrive; other executors buffer the response before parsing.

The canonical `/v1/events/sse` and `/v1/contracts/events/sse` feeds are
live-only and have no replay log. The client rejects every case variant of
`Last-Event-ID` before HTTP dispatch for exactly those paths; replay-capable
custom streams may still receive that header. Raw listeners receive terminal
`event: stream_error` frames. Call `ServerSentEvent.terminalStreamError()`
before category filtering to project one into a strict `ToriiStreamException`
with its stable code, server message, optional unsigned dropped-message count,
replay flag, and raw JSON. Malformed or schema-expanded terminal envelopes fail
closed as `ToriiStreamProtocolException`. The typed pipeline-status stream does
this projection automatically. Reconnecting to a canonical feed starts a new
live subscription and can have a gap.

Use `ToriiEventStreamSubscription` when a long-lived component needs automatic
reconnects:

```java
ToriiEventStreamSubscription subscription =
    ToriiEventStreamSubscription.builder(
            streams, "/v1/events/sse", ToriiEventStreamOptions.defaultOptions(), listener)
        .setInitialBackoff(Duration.ofSeconds(1))
        .setMaxBackoff(Duration.ofSeconds(30))
        .addObserver(new ToriiEventStreamObserver() {
          @Override
          public void onReconnectScheduled(Duration delay, ReconnectReason reason) {
            telemetry.incrementReconnects(reason.name(), delay);
          }

          @Override
          public void onStreamFailure(Throwable error) {
            telemetry.recordFailure(error);
          }
        })
        .build()
        .start();

// Later
subscription.close();
```

The helper honours server-provided retry hints and uses exponential
backoff when the stream fails before emitting one. Observers registered via
`addObserver` receive structured lifecycle notifications (`streamOpened`,
`streamClosed`, `streamFailure`, and `onReconnectScheduled`) so telemetry
pipelines can tag reconnect attempts, failure causes, and delay budgets without
mutating the primary listener.

### Torii streaming (WebSocket)

The WebSocket surface rides on the transport abstractions
(`TransportRequest`/`TransportWebSocket`) so JVM and Android inject their platform
connectors explicitly. Android apps should pass the OkHttp connector to keep
`java.net.http` out of the AAR; JVM apps can instead inject
`JdkWebSocketConnectorFactory.createDefault()`:

```java
import okhttp3.OkHttpClient;
import org.hyperledger.iroha.android.client.okhttp.OkHttpWebSocketConnector;

ToriiWebSocketClient wsClient =
    ToriiWebSocketClient.builder()
        .setBaseUri(URI.create("https://torii.devnet.example"))
        .setWebSocketConnector(new OkHttpWebSocketConnector(new OkHttpClient()))
        .build();

ToriiWebSocketSession session =
    wsClient.connect(
        "/ws/telemetry",
        ToriiWebSocketOptions.builder()
            .addSubprotocol("norito-stream")
            .build(),
        new ToriiWebSocketListener() {
          @Override
          public void onText(ToriiWebSocketSession session, CharSequence data, boolean last) {
            System.out.println("payload: " + data);
          }
        });
```

Sessions expose async send helpers (`sendText`, `sendBinary`, `sendPing`, `sendClose`)
and share the same observer instrumentation used by HTTP/SSE clients. Ping/pong
support depends on the connector: the JDK connector honours both, while the
OkHttp connector returns a failed future for ping/pong because OkHttp does not
expose control frames. Subprotocol negotiation is surfaced via
`ToriiWebSocketSession.subprotocol()`, and reconnect helpers remain available
through `ToriiWebSocketSubscription`.

### Connect retry policy

The Connect stack uses the dedicated `org.hyperledger.iroha.android.connect.ConnectRetryPolicy`
helper to mirror the Rust reference implementation (`connect_retry::policy`). It applies
exponential back-off with full jitter (base 5 s, capped at 60 s) and derives jitter deterministically
from the Connect session identifier so Android, Swift, and JavaScript clients wait for the exact
same delay sequence:

```java
import org.hyperledger.iroha.android.connect.ConnectRetryPolicy;

byte[] sessionId = new byte[32]; // use the Connect session id bytes
ConnectRetryPolicy policy = new ConnectRetryPolicy();
for (int attempt = 0; attempt < 5; attempt++) {
    long delayMs = policy.delayMillis(attempt, sessionId);
    Thread.sleep(delayMs);
    // reconnect logic here
}
```

The deterministic seed/attempt mapping ensures reconnect telemetry stays aligned across SDKs.

### Connect error taxonomy

`org.hyperledger.iroha.android.connect.error.ConnectError` mirrors the shared taxonomy
(`specs/connect_error_taxonomy.md`) so Android apps emit the same `category`/`code`
pairs as the Swift and JavaScript SDKs. Wrap every transport, codec, or queue failure via
`ConnectErrors.from(Throwable)` (or manually create a `ConnectError` using the builder)
before forwarding attributes to OpenTelemetry:

```java
import org.hyperledger.iroha.android.connect.error.ConnectError;
import org.hyperledger.iroha.android.connect.error.ConnectErrors;

try {
    connectClient.send(frame);
} catch (Exception ex) {
    ConnectError error = ConnectErrors.from(ex);
    telemetry.emit("connect.error", error.telemetryAttributes());
    throw error;
}
```

Queue back-pressure helpers such as `ConnectQueueError.overflow(limit)` and
`ConnectQueueError.expired(ttlMillis)` already implement `ConnectErrorConvertible`, so they
map to the `queueOverflow` and `timeout` categories automatically. Use
`ConnectError.telemetryAttributes(...)` to project overrides (fatal flag, HTTP status, or
custom `underlying` context) when surfacing the events.

### Canonical request signing

Torii app endpoints use `X-Iroha-Account`, `X-Iroha-Signature`,
`X-Iroha-Timestamp-Ms`, and `X-Iroha-Nonce` headers. Use
`CanonicalRequestSigner` when calling account-scoped helpers or building ad-hoc
HTTP requests:

```java
import java.net.URI;
import java.security.Signature;
import java.util.Map;
import org.hyperledger.iroha.android.client.CanonicalRequestSigner;
import org.hyperledger.iroha.android.client.ToriiCanonicalRequestAuth;
import org.hyperledger.iroha.android.model.NetworkId;

URI uri = URI.create("https://torii.example/v1/node/capabilities");
NetworkId networkId =
    NetworkId.parse(
        "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0");
long timestampMs = System.currentTimeMillis();
String nonce = "fresh-visible-ascii-nonce";
ToriiCanonicalRequestAuth auth =
    new ToriiCanonicalRequestAuth(
        accountId,
        message -> {
          try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(message);
            return signature.sign();
          } catch (Exception error) {
            throw new IllegalStateException("canonical request signing failed", error);
          }
        });
Map<String, String> headers =
    CanonicalRequestSigner.buildHeaders(
        networkId, "get", uri, new byte[0], auth, timestampMs, nonce);
```

When `accountId` is I105, the signer keeps it as the semantic SDK identity but emits its
lowercase canonical-hex address in `X-Iroha-Account`, which is safe on strict
ASCII HTTP stacks. Canonical lowercase ASCII aliases (`label@dataspace` or
`label@domain.dataspace`) are emitted unchanged after a bounded structural
preflight. Torii remains authoritative for UTS-46, active alias bindings, and
controller verification.

Signatures cover the exact genesis-derived `NetworkId`, canonical
method/path/query/body layout, and freshness metadata. Labels and legacy chain
identifiers are never accepted as a signing domain. First-release network IDs use
exactly `hash:` plus 64 uppercase hexadecimal characters, `#`, and a four-character
uppercase hexadecimal CRC-16/IBM-3740 checksum. Methods are non-empty ASCII HTTP tokens
of at most 32 bytes,
paths use an exact root-relative ASCII wire spelling of at most 64 KiB, and nonces contain
1...256 visible ASCII bytes (`0x21...0x7e`, with no spaces).
Raw `witness_base64` body authentication is not exposed; multisig writes must
use a canonical signed transaction or a closed typed signed intent.
`prepareContractCall` requires `ToriiCanonicalRequestAuth` for the same authority
and a configured `LocalSigningContext`. It signs the exact prepare request once
and accepts only a canonical contract-call transaction payload. Keep the returned
payload bytes and quoted fee unchanged when signing and submitting through the
transaction API; submission failures are reconciled by transaction hash.

`prepareContractCall` accepts a draft receipt only when `payload_digest_hex` is
the exact lowercase BLAKE3-256 digest of the canonical UTF-8 JSON request
payload. An omitted payload hashes the empty byte sequence; noncanonical hex or
a digest mismatch fails closed before the draft is returned.
Encrypted RAM-LFE is unavailable until its diagnostic exact-lift BFV profile is
replaced. Execute responses contain ciphertext and a receipt; they do not provide
a plaintext opening. Identifier requests require an independently authenticated
opening. The retired execute `output_opening` field is rejected.
Local plaintext encryption refuses with `ram_lfe_encryption_unavailable`; public
seed overrides and the insecure production encryptor are removed. The canonical
Kotlin/JVM API exposes `RamLfeEncryptionUnavailableException` to Java callers.
Retired backend names and unknown modes are rejected on decode.

Identifier resolve/claim-receipt and RAM-LFE execute/receipt-verify calls require
`ToriiCanonicalRequestAuth` plus `ClientConfig.localSigningContext`. They sign the
exact POST path and body once, reject precomputed canonical headers, and bind a
claim-receipt path to the same exact canonical I105 signer account.

### Sora VPN native lease flow

`HttpClientTransport` exposes the quote-first Sora VPN endpoints. Quotes bind
the account, exit class, client metering key, XOR fee asset, escrow account, and
operator account, then return native `OpenVpnLeaseEscrow` instructions. Session
creation requires the committed hash of the exact quote-bound lease-open
transaction, and operator receipt submission returns a native `SettleVpnLease`
instruction with earned/refunded XOR amounts and provisional status
`settlement_pending`:

```java
java.util.function.Function<
        java.security.PrivateKey,
        org.hyperledger.iroha.android.client.CanonicalRequestSignatureProvider>
    signerFor =
        privateKey ->
            message -> {
              try {
                java.security.Signature signature =
                    java.security.Signature.getInstance("Ed25519");
                signature.initSign(privateKey);
                signature.update(message);
                return signature.sign();
              } catch (Exception error) {
                throw new IllegalStateException("canonical request signing failed", error);
              }
            };
ToriiCanonicalRequestAuth userAuth =
    new ToriiCanonicalRequestAuth(
        "<account_i105>", signerFor.apply(userKeyPair.getPrivate()));

VpnQuote quote = transport.createVpnQuote(
    new VpnQuoteCreateRequest("standard", "<metering_public_key_hex>"),
    userAuth).join();

VpnSession session = transport.createVpnSession(
    new VpnSessionCreateRequest(
        quote.exitClass(),
        quote.quoteId(),
        "<committed_open_lease_tx_hash>",
        quote.meteringPublicKeyHex()),
    userAuth).join();

ToriiCanonicalRequestAuth operatorAuth =
    new ToriiCanonicalRequestAuth(
        "<operator_i105>", signerFor.apply(operatorKeyPair.getPrivate()));
VpnReceipt pending = transport.submitVpnReceipt(
    new VpnReceiptSubmitRequest("<relay_receipt_hex>", "<client_voucher_hex>", quote.leaseIdHex()),
    operatorAuth).join();
```

Submit `quote.openLeaseInstruction()` and `pending.settleLeaseInstruction()` as
normal signed native instruction transactions. This keeps prepaid VPN funds in
XOR escrow until usage receipts and client vouchers prove the amount earned by
the operator. Only a receipt subsequently read from committed WSV state uses
status `settled`; the parser retains exact `disconnected`, `expired`, and
`replaced` lifecycle statuses as well.

### Pipeline Hashes

`HttpClientTransport.submitTransaction(...)` computes the canonical BLAKE2b-256
hash for every signed transaction via `SignedTransactionHasher` and surfaces it
through `ClientResponse.hashHex()`. Callers can forward the returned hash to
`waitForTransactionStatus(...)` (or other Torii polling helpers) without
reimplementing the hashing logic. If no authoritative admission outcome arrives,
`submitTransaction(...)` fails with `AmbiguousTransactionSubmissionException`; call
`reconcileWith(client)` or query its `hashHex()` before constructing and signing a replacement.
The SDK never resends the same signed bytes.

Public pipeline status contains only the canonical transaction hash—exactly
`[0-9a-f]{63}[13579bdf]`, including the Iroha `HashOf` marker—closed status kind,
optional committed height, read scope, and resolution source. The Java mirror rejects
rejection text, diagnostics, trigger completions, batch outcomes, unknown kinds, and
noncanonical metadata. Status scope is exactly `local` or `global`; `auto` is not a
first-release value, and `waitForTransactionStatus(...)` always requests `global`.
Transaction-hash request values, status responses, and Torii receipt headers are never trimmed,
case-folded, prefix-stripped, or decoded from byte-shaped values. Status reads accept only an exact
HTTP `200` envelope or `404` not-found response; `202` and `204` are protocol errors.
State-resolved `Rejected` and `Expired` are the only failures; every other non-success status
remains progress. Negative polling intervals and timeouts are rejected rather than clamped. Detailed
transaction reads require an involved account or operator to
send a one-shot canonical signed `FindTransactions` query bound to the exact genesis-derived
`NetworkId`; the Java mirror intentionally exposes no details helper until its signed-query
surface supports that contract.

The first-release ID commits to the canonical signed `TransactionPayload`
inside `TransactionEntrypoint::External`, not to the surrounding authorization
proof. Replacing a signature or multisig proof therefore does not create a
second ID for the same intent. Proof attachments live in
`TransactionPayload.attachments()` and remain signature- and ID-bound.

Torii returns a Norito-encoded transaction submission receipt (payload +
signature) on `/v1/pipeline/transactions`. The Android SDK surfaces the raw
receipt bytes via `ClientResponse.body()` so callers can decode them with their
Norito tooling when they need the receipt fields.

### Torii Reject Codes

Torii attaches an `x-iroha-reject-code` header when admission fails. Both the
JDK and Android/OkHttp transports keep that header intact via
`ClientResponse.rejectCode()` so apps can surface the precise Torii error without
re-parsing the response body:

```java
ClientResponse response = transport.submitTransaction(transaction).join();
response.rejectCode().ifPresent(code -> {
  // e.g., PRTRY:TX_SIGNATURE_MISSING — surface to the user/telemetry
});
```

### Resolving Account Aliases

`HttpClientTransport.resolveAccountAlias(...)` posts to `/v1/aliases/resolve` and
returns an `Optional<AccountAliasResolution>`. An `Optional.empty()` value
indicates the node responded with HTTP 404 for an unknown alias; other failures
complete the future exceptionally. `AccountAliasResolution.index()` is optional
and may be `null` when the alias backend does not expose a deterministic index.

```java
Optional<AccountAliasResolution> resolved =
    client.resolveAccountAlias("some_alias@universal").join();
resolved.ifPresentOrElse(
    resolution -> System.out.println("account: " + resolution.accountId()),
    () -> System.out.println("alias not found"));
```

### Reading Kotodama Manifests

`HttpClientTransport.getContractManifest(artifactId, canonicalAuth)` reads
`/v1/contracts/artifacts/{dataspace_id}/{code_hash}` into the Kotlin-owned
Kotodama V1 manifest model in `core-jvm`. `ContractArtifactId` carries the full
unsigned 64-bit dataspace ID as `BigInteger` and the canonical code hash. The
request requires canonical account authentication and a configured local signing
context; its response must match that network and exact artifact identity. The strict Kotlin decoder retains `seiyaku_name`, branded
entrypoint kinds, exact flat-preorder argument/return schemas, dynamic access hints,
completeness/skips, triggers, state, error codes, `kotoba`, and provenance. A
`List` node contains only `capacity` and its element subtree immediately follows
it. Unknown fields, legacy nested `element` metadata, incomplete or trailing
tapes, over-depth schemas, noncanonical Norito hashes, wrapper/manifest hash
mismatches, and inconsistent schemas are rejected before the future completes.

### Key Manager Defaults

`IrohaKeyManager.withDefaultProviders()` constructs a manager that prefers
hardware-backed keystore providers when available and also registers a software
provider as its general fallback. Software-backed custody is supported for
ordinary production, governance, build, test, deployment, and release paths;
hardware providers are optional. Pass custom `KeyGenParameters` when you
need to enforce StrongBox-only keys or user-authentication requirements while
retaining an explicit deterministic software provider for other signing paths.
If your desktop JVM lacks built-in Ed25519 support, configure the software
provider with BouncyCastle required.
The Android Keystore backend is offered only on keystore2 (API 31+). It decides
whether an alias exists through `KeyStore.getKey(alias, null)` alone, because
`containsAlias`/`getEntry` report Keystore errors as absent aliases and generating
under an occupied alias replaces its key. `load` throws instead of returning empty
when the Keystore cannot answer, so `generateOrLoad` never overwrites a key it could
not see.
Hardware-backed keys remain non-extractable; for user-managed accounts that must
roam across devices, prefer `SOFTWARE_ONLY` (or `withSoftwareProvider`) and use
`exportDeterministicKey(...)` / `importDeterministicKey(...)` to move key
material between devices securely. When you need fully exportable keys, build
the software provider with BouncyCastle enforced and a persistent export store:

```java
KeyExportStore store = new FileKeyExportStore(new File(filesDir, "keys.properties"));
KeyPassphraseProvider passphraseProvider = () -> "export-passphrase".toCharArray();
SoftwareKeyProvider provider =
    new SoftwareKeyProvider(
        SoftwareKeyProvider.ProviderPolicy.BOUNCY_CASTLE_REQUIRED,
        store,
        passphraseProvider);
IrohaKeyManager manager = IrohaKeyManager.fromProviders(List.of(provider));
```

Or use the convenience helper:

```java
IrohaKeyManager manager =
    IrohaKeyManager.withExportableSoftwareKeys(store, passphraseProvider);
```

To opt into post-quantum ML-DSA-65 transaction signing, select the signing
algorithm up front:

```java
IrohaKeyManager ed25519Manager = IrohaKeyManager.withSoftwareProvider();
IrohaKeyManager mlDsaManager =
    IrohaKeyManager.withSoftwareProvider(SigningAlgorithm.ML_DSA);
IrohaKeyManager gostManager =
    IrohaKeyManager.withSoftwareProvider(SigningAlgorithm.GOST_2012_256_A);

KeyGenParameters params =
    new KeyGenParameters.Builder()
        .setSigningAlgorithm(SigningAlgorithm.ML_DSA)
        .build();
IrohaKeyManager tunedManager = IrohaKeyManager.withDefaultProviders(params);
```

`ED25519` remains the default. `SECP256K1`, `BLS_NORMAL`, `BLS_SMALL`,
`ML_DSA`, the five `GOST_2012_*` variants, and `SM2` use the shared native
bridge and are software-only in this pass, so `HARDWARE_*` and `STRONGBOX_*`
preferences fail fast instead of silently falling back to an unexpected
provider.

The manager validates Ed25519 SPKI output and skips providers that return a
different algorithm (common on emulators), falling back to the next configured
provider.

`generateOrLoad(alias, preference)` accepts a `KeySecurityPreference` that
describes the caller-selected provider tier. The `*_REQUIRED` variants below
are explicit per-call policies, not SDK build, release, deployment, or
governance prerequisites:

- `STRONGBOX_REQUIRED` — only StrongBox-backed providers are consulted; the call
  fails if no StrongBox backend is registered or the target device cannot
  satisfy the request.
- `STRONGBOX_PREFERRED` — StrongBox providers are tried first, then other
  hardware-backed providers, and finally explicitly configured software providers.
- `HARDWARE_REQUIRED`/`HARDWARE_PREFERRED` — retain the previous semantics for
  “any hardware” while allowing deterministic software-provider selection.
- `SOFTWARE_ONLY` — bypass hardware providers entirely (valid for production
  software custody as well as emulator and deterministic testing scenarios).

Provider metadata is used only to choose candidate providers. For an existing
or newly generated Android Keystore alias, required policies inspect that
specific private key's `KeyInfo`: `STRONGBOX_REQUIRED` accepts only an exact
StrongBox result, while `HARDWARE_REQUIRED` accepts any proven secure-hardware
result. An unavailable or unrecognized per-key security level fails closed;
preferred policies may downgrade and report the measured route. Custom
`KeyProvider` implementations must override `outcomeFor(...)` to report proven
per-key provenance; its default is deliberately software-backed. A preference
set with `KeystoreKeyProvider.withPreference(...)` also governs later plain
`generate(...)` calls.

Aliases follow a predictable lifecycle: the manager looks up existing keys
across all providers in priority order, reuses the first match, and only
generates a new key when no provider has material for the alias. Hardware-backed
aliases remain pinned to the provider that created them, while software
providers are consulted only when the chosen preference allows a downgrade (for
example, `STRONGBOX_PREFERRED` on a device without StrongBox support). Required
policies reject weaker existing or newly generated aliases instead of treating
provider capability or a request flag as proof of the selected key's security
level.

Call `IrohaKeyManager.providerMetadata()` to inspect the registered providers
(name, hardware capability, attestation support) before deciding which
alias/security preference to use, and use the new
`IrohaKeyManager.verifyAttestation(...)` helper to validate the attestation
chain exported by hardware providers without wiring keystore internals through
application code.

`IrohaKeyManager.hasStrongBoxProvider()` is a convenience check that reports
whether a StrongBox-backed provider is registered, enabling applications to
surface hardware posture in diagnostics or gate user-facing flows before
attempting StrongBox-only operations.

```java
IrohaKeyManager manager = IrohaKeyManager.withDefaultProviders();
for (KeyProviderMetadata meta : manager.providerMetadata()) {
    System.out.printf("%s hardware=%s level=%s attestation=%s%n",
        meta.name(), meta.hardwareBacked(), meta.securityLevel(), meta.supportsAttestationCertificates());
}
```

Use `IrohaKeyManager.verifyAttestation(...)` (or the underlying
`KeystoreKeyProvider.verifyAttestation(...)`) alongside `AttestationVerifier`
when you need to validate the StrongBox/TEE attestation chain exported by the
Android backend. The verifier checks the certificate path, decoded challenge,
security level, explicit evaluation time, and a fresh governed offline
revocation snapshot while surfacing parsed metadata. It also rejects an alias
that resolves to different public keys across configured providers. A non-empty expected
challenge is mandatory; the retained challenge-less overloads fail closed. For
lab automation, pass the canonical `android-sdk-revocation-snapshot-v1.txt`,
its SHA-256 commitment obtained from the separately authenticated governance
record, and the evaluation time to `scripts/android_keystore_attestation.sh`
together with separately trusted roots, alias, challenge, and expected leaf-SPKI
digest. Never obtain those expectations from the untrusted evidence bundle. The snapshot commitment binds the
payload digest, freshness metadata, and both deny lists as one object. The
script compiles the same verifier and produces a JSON summary that should be
archived with each attestation bundle.

Android Keystore binds an attestation challenge only when it creates a key. To
obtain evidence for a new challenge, set
`KeyGenParameters.Builder.setAttestationChallenge(...)` and provision a new,
unique alias; rotate the application to that key only after its chain verifies.
The platform cannot re-attest an existing alias, so
`IrohaKeyManager.generateAttestation(alias, nonEmptyChallenge)` reports that
limitation instead of returning the stored chain as fresh evidence.
`verifyAttestation(...)` rereads the provisioning-time chain without using the
in-memory inspection cache and compares its embedded challenge with the
separately trusted expected value. StrongBox preferences are propagated to key
generation (`STRONGBOX_REQUIRED` forces StrongBox and
`STRONGBOX_PREFERRED` requests it), and backend errors are surfaced directly.

Native computation belongs to `org.hyperledger.iroha.sdk.gpu.Accelerators`
in `kotlin/core-jvm`. Both JVM languages use its explicit backend construction
and five bounded batch operations. See the [native bridge contract](../../specs/sdk/android/gpu_operator_guide.md)
for native loading and the hardware qualification task.

`SoftwareKeyProvider.exportDeterministic(...)` emits a versioned, AES-GCM
wrapped export bundle (v4) using per-export salt/nonce. The bundle records the
signing algorithm alongside `kdf_kind` and work factor; v4 uses Argon2id
(64 MiB, 3 iterations, parallelism 2). A minimum 12 character passphrase is
enforced for deterministic exports/imports. Salt/nonce reuse is rejected and
decode guards fail fast on tampered lengths.
The companion `importDeterministic(...)` helper restores the key pair while
validating the authentication tag. For Ed25519, both export and import derive
the public key from the private seed and compare it with the canonical SPKI, so
a substituted public key or an inconsistent input pair is rejected.

`IrohaKeyManager.exportDeterministicKey(...)` / `importDeterministicKey(...)`
surface the same functionality through the manager so applications do not need
direct access to the underlying `SoftwareKeyProvider` during recovery flows.

### Explicit Transaction Staging Queue

Applications can provide a `PendingTransactionQueue` (the default implementation
`FilePendingTransactionQueue` persists base64-encoded canonical pending-transaction
records) via `ClientConfig`. This is explicit local staging only:
`HttpClientTransport` neither enqueues failed submissions nor drains stored signed bytes.
Before deciding whether to replace a staged transaction, reconcile its canonical hash against
Torii. Do not replay a transaction whose earlier dispatch has an ambiguous outcome.
### Norito RPC Helper

Use `NoritoRpcClient` when you need to call Torii's Norito RPC endpoints
(`application/x-norito` payloads) alongside the REST pipeline. The helper
wraps the platform HTTP executor (OkHttp on Android, the JDK HTTP client
elsewhere), applies the correct binary content headers, and lets callers
override HTTP method, timeouts, headers, query parameters, and `Accept`
negotiation via `NoritoRpcRequestOptions`. The tests under
`client/NoritoRpcClientTests` demonstrate POST/GET flows, header overrides,
and error propagation, while the client builder accepts default headers (for
example `Authorization`) so instrumentation matches the REST transport. Call
`ClientConfig.toNoritoRpcClient()` for the platform default (OkHttp on Android)
or `ClientConfig.toNoritoRpcClient(HttpTransportExecutor)` when you already
have a custom executor. `HttpClientTransport.newNoritoRpcClient()` reuses
existing client configuration and telemetry hooks when spinning up a Norito
RPC transport.

### SoraFS Gateway Helpers

The `org.hyperledger.iroha.android.sorafs` package provides thin builders that map
directly to the Rust `sorafs_orchestrator` configuration. Use
`GatewayProvider.builder()` to describe gateway endpoints,
`GatewayFetchOptions.builder()` to compose telemetry/retry/transport overrides, and
`GatewayFetchRequest.builder()` to bundle everything into the JSON structure the
orchestrator expects. `TransportPolicy` and `AnonymityPolicy` mirror the CLI/SDK
labels (`soranet-first`, `anon-guard-pq`, etc.), ensuring Android clients participate
in the staged SoraNet anonymity rollout alongside the other SDKs.
The builders preserve and validate canonical protocol inputs without rewriting them:
`manifest_id_hex`, `provider_id_hex`, and the mandatory `gateway_public_key_hex` trust
anchor must be non-zero, lowercase, unprefixed 32-byte hex; stream tokens must use exact
standard Base64; and gateway URLs must be credential-free HTTPS origins with no query,
fragment, explicit port, or path.

`SorafsGatewayClient` wraps the HTTP transport so applications can submit orchestrator
requests without reimplementing header/observer plumbing. Call
`client.fetch(request)` when you only need the raw JSON/string output, or
`client.fetchSummary(request)` to receive a typed `GatewayFetchSummary` that exposes
provider receipts, anonymity ratios, and chunk metadata. The client reuses
`HttpTransportExecutor`, which means tests can provide deterministic fakes and production
code can share the same connection pool as the Torii pipeline transport.
`HttpClientTransport.newSorafsGatewayClient(...)` is a convenience helper that spawns the
gateway client using the same executor, timeout, headers, and observers as the primary Torii
transport so applications can rely on a single HTTP stack.

### Mock Torii Harness

The test suite now includes a lightweight HTTP harness (`src/test/java/org/hyperledger/iroha/android/client/mock/ToriiMockServer.java`)
that mirrors Torii's `/v1/pipeline/transactions` submission and `/v1/pipeline/transactions/status` routes. Integration tests such as
`HttpClientTransportHarnessTests` spin up the server, interact with it via `HttpClientTransport`, and assert on the recorded
requests/responses, providing end-to-end coverage for retries, headers, and offline queue replays without depending on a real Torii node.

The transaction descriptors, manifest, and matching `.norito` files under
`src/test/resources` are the generated Java mirror of `fixtures/norito_rpc`.
Regenerate them only through the canonical Rust owner:

```bash
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/first-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- \
  norito-rpc-fixtures --output-root /path/to/second-new-norito-rpc-publication
cargo run --locked -p xtask --features dev-tools --bin xtask -- norito-rpc-verify
python3 scripts/check_android_fixtures.py
```

Each invocation writes a complete publication only beneath its absent external
output root; it does not rewrite the tracked corpus. Require identical exact
path sets, entry types, modes, completion manifests, and every file byte before
applying the reviewed identity-relative tracked patch. Then run the verifier
and Android checker above. Always commit the complete generated set together;
never retain an old hash, retired fixture, or compatibility-only payload in the
Java resource directory.

### Musubi V1 registry reads

`MusubiToriiClientV1` and `MusubiModelsV1` mirror the Kotlin-default first-release
registry surface without reflection, Android framework dependencies, or legacy
wire aliases. The client exposes all twelve typed `/v1/musubi/queries/*` POST routes only with a
mandatory `LocalSigningContext` and per-call `ToriiCanonicalRequestAuth`. It signs each exact raw
body/path against the configured `NetworkId` and marks the request one-shot. The models strictly
preserve structured package IDs,
immutable namespace bindings, SemVer requirement ASTs, one exact genesis-derived
`NetworkId`, finalized cursors, and authoritative archive commitments. Unknown
fields, unsupported versions, and duplicate parent-local dependency aliases
fail closed.

Both Java and Kotlin validate the Rust-owned contract in
[`fixtures/musubi/sdk_v1.json`](../../fixtures/musubi/sdk_v1.json). Caller-injected canonical or
witness headers fail before dispatch; authentication comes only from the explicit per-call value.

`search(SearchQuery)` posts to `/v1/musubi/queries/search` and returns a bounded,
structurally ordered page with a search-specific finalized projection cursor;
the discovery projection is never a resolver input.

`findArchiveRetention(ArchiveRetentionQuery)` accepts only sorted, distinct,
non-zero archive identities and rejects a response whose identity order or
optional finalized snapshot differs from the exact request.

`MusubiInstructionsV1` mirrors the Kotlin typed construction surface for
immutable namespace-binding registration, package invitation creation,
acceptance, revocation, role replacement, and removal, permanent alias
registration, exact release-digest assertion, archive registration, location
addition or renewal, and location retirement, release publication and
reversible yank state, package metadata replacement, and Parliament-enacted
package ownership recovery, permanent-alias retargeting, artifact takedown, and
registry-policy replacement. Public namespace bindings are constructible,
maintainer roles require at least one independent permission, and mutation
reasons use the canonical non-empty
`MusubiModelsV1.Reason` value bounded to 1,024 UTF-8 bytes. Each builder exposes
`barePayload()`, `concreteFrame()`, and
`toInstructionBox()` and is checked at all four framing layers against
all nineteen cases in
[`fixtures/musubi/instructions_v1.json`](../../fixtures/musubi/instructions_v1.json).

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` for details.
