# JVM consolidation capability inventory

This 2026-09-06 source review resolves the 33-entry queue in
`target/architecture-redesign/jvm-unmatched-source-names.json` (SHA-256
`32704aaa153bc3ba33c7730e52ab93449b8a1f9e4abc086ababb5ac9f94ed5da`).
It compares implementations and consumers, not filenames. Eleven entries had
an existing Kotlin owner at review time (`SccpSubmitEncoding` has none now: its
Kotlin owner is removed with it); eight expose missing capabilities or invariants;
fourteen are duplicate implementations, construction wrappers or samples to
retire after their capability dependencies are satisfied. This closes that
queue only: it is not a complete SDK parity or runtime qualification claim.
The inventory itself is a source audit. Subsequent qualification below records implementation changes separately.

Path notation below is repository-relative:

- **J**: `java/iroha_android/src/main/java/org/hyperledger/iroha/android/`
- **JA**: `java/iroha_android/android/src/main/java/org/hyperledger/iroha/android/`
- **JJ**: `java/iroha_android/jvm/src/main/java/org/hyperledger/iroha/android/`
- **K**: `kotlin/core-jvm/src/main/java/org/hyperledger/iroha/sdk/`
- **KA**: `kotlin/client-android/src/main/java/org/hyperledger/iroha/sdk/`

Line numbers identify the reviewed source; subsequent edits can move them.
The sole public SDK package is `org.hyperledger.iroha.sdk`. Migration must not
retain Java-package aliases, duplicate public value wrappers, reflective
platform discovery or a JDK 11 implementation in the JDK 8 API surface.

## Existing canonical capability

| Java queue entry | Kotlin owner and implementation evidence |
| --- | --- |
| J `consensus/SumeragiJsonSupport.java` | Removed. K `consensus/SumeragiStatusModels.kt`, internal `SumeragiJsonPrimitives`, owns strict UTF-8, exact object fields, negative-zero rejection, bounded unsigned numbers and canonical hashes. Migrated Java consumers exercise the Kotlin status and diagnostics parsers. |
| J `consensus/NativeAmxV2Models.java` | Removed with the duplicate Sumeragi status, diagnostics and wire classes. K `consensus/NativeAmxV2.kt` owns the sole public value hierarchy and grouped parser; Java consumers call it directly. Remaining private-settlement responder checks invoke its canonical BLS peer validator directly. |
| J `alias/AliasNameSupport.java` | K `alias/AliasNames.kt:201` performs NFC/IDN segment and qualified-domain normalization plus exact u64 bounds; `AliasSetupModels.kt:961` and `AliasPlanVerifier.kt:423` own token/hash checks. No standalone public helper is needed. |
| J `privacy/ConfidentialNoteScalars.java` | Removed. K `privacy/ConfidentialNote.kt:533`: same Pasta modulus, 32-byte canonical/nonzero scalars, positive canonical u128 and defensive byte copies. |
| J `privacy/ConfidentialNoteCrypto.java` | Removed. K `privacy/ConfidentialNote.kt:149–390`: public-key derivation, X25519 agreement, HKDF and authenticated note encryption/decryption, including deterministic entropy entry points. Kotlin `ConfidentialNoteTest.kt:170` covers plaintext contract and tampering. |
| J `client/ZkRootsJson.java` | K `client/ZkRoots.kt:69`: response parser is absorbed by the response companion; preserves root strings and evaluated block height/hash checks. |
| J `client/AccountAliasUInt64.java` | K `client/AccountAliasReadModels.kt:202`: `requireAliasU64`/`aliasU64` retain BigInteger range and integer-token validation. Existing `AccountAliasReadModelsTest.kt` covers the read models. |
| J `client/SccpSubmitEncoding.java` | Removed with no Kotlin owner: its Kotlin counterpart K `client/SccpSubmitRequests.kt` is removed too. Per `specs/sccp.md` §8, Java has no SCCP surface, and Kotlin SCCP read models, `RecordSccpMessage` building and bundle verification are phase-2 work through `connect_norito_bridge`. The only SCCP code the JVM SDKs keep is `SccpRouteGovernance` payload validation in `ParliamentProposalValidatorV1`. |
| J `client/ZkMerklePathJson.java` | K `client/ZkMerklePath.kt`, response companion parser: required `next_zero_path`, integer directions, witness nodes and evaluated snapshot are retained. Kotlin `ConfidentialAssetToriiClientTest.kt` and `ZkAssetMerklePathTest.kt` are relevant consumers. |
| J `client/transport/BoundedResponseBodyReader.java` | K `client/transport/BoundedResponseBodyReader.kt`: canonical single Content-Length, CL/TE rejection, decoded-body limits, premature EOF, zero-progress/invalid stream-read checks and bodyless HTTP responses. Its existing Kotlin test covers these cases. Extract a shared internal body reader only if another retained transport needs it. |
| J `model/instructions/ZkInstructionUtils.java` | K `core/model/instructions/ZkAssetInstructions.kt:458–555`: exact text, portable verifier components, verifier-key IDs, fixed/nonzero bytes and fixed-32 flattening already have canonical owners. |

These rows establish capability ownership, not equality of every validation
branch. Preserve shared fixture assertions and Java-source consumer coverage
against these Kotlin classes when retiring the Java implementation.

The six Sumeragi/Native AMX Java suites now run from `kotlin/core-jvm` against
the canonical Kotlin API. All 51 original Java tests are preserved; the focused
111-test selection passes without failures, errors or skips under JDK 8 API
compilation. The five duplicate consensus production classes and six original
Java suites are removed, together with the old `IrohaClient`/`HttpClientTransport`
Sumeragi methods and their unused operator-config wiring. Private-settlement
attestation checks and shared onboarding response validation remain. This
records SDK ownership and focused coverage; release qualification remains
separate.

## Canonical custom-instruction bytes (2026-09-09)

Kotlin's custom JSON instruction adapter added a redundant field-length prefix,
producing a different multisig hash from Rust. The adapter now writes the one
canonical nested JSON field. A [shared Rust-produced fixture](../fixtures/multisig/README.md)
binds the complete 79-byte instruction vector, nested custom frame and its
independently checked hash. Rust asserts both bytes and hash. Three Kotlin tests
cover exact bytes/hash, truncation and extra-prefix rejection, and compact-length
boundaries; one Java consumer calls Kotlin's public codec API. The four tests
reproduce two failures before the correction and all pass afterward, with JDK 8
API enforcement retained and 678 qualification inputs unchanged during each run.

The wider 19-test selection passes nine and fails ten while requiring the missing
ABI-23 `connect_norito_bridge` address validator. Those native-dependent controls
remain unverified; no address-validation fallback or test bypass is introduced.
The duplicate Java codec and its conflicting older fixture are still pending
capability/consumer retirement. This focused correction does not establish full
JVM, JNI, Android or publication qualification. Frozen patch, original failures,
source seals and runtime reports are retained under ignored
`target/architecture-redesign/norito-identity-cutover/multisig-custom-json-correction-v1/`.

## Canonical Ed25519 admission

`K crypto/Ed25519PublicKeyAdmission.kt` owns canonical point decoding, identity
refusal and prime-order subgroup admission. Its bounded cache retains only
immutable public points after the complete check; cache membership does not
authenticate signatures or account ownership. Java production consumers and
retained Java refusal/mutation tests import this owner directly. The duplicate
Java class and its forwarding alias are removed.

## Capabilities and invariants still needing migration

Signer, verified Nearby and immutable Nexus migrations have focused and full JVM
evidence. WebSocket ownership now has real wire and Java-consumer coverage.
Attestation command ownership and migrated Java assertions now pass in Kotlin tooling.
Complete remaining Java implementation, JNI and publication retirement.

The compiled JNI inventory contains 77 Kotlin native declarations across ten
owners and three modules. The Rust SDK namespace now has exactly 77 matching
source exports. Six memo JNI exports without a JVM declaration and three
undeclared app-specific coordinator exports are removed; all 132 C ABI function
bodies are unchanged. Coordinator behavior lives directly under its Kotlin SDK
exports. Nineteen Android privacy duplicates are now removed with their Java
implementation consumers. The remaining 36 Android declarations are outside
this privacy closure and still require retirement.

Three new Java consumer classes preserve privacy, SoraFS reference validation,
and signer behavior against Kotlin. All 41 cases compile to JDK 8; 26 managed
Java cases and one existing Kotlin selector test pass with native loading
explicitly unavailable. Fifteen native cases require the rebuilt bridge.
The compiled declaration/export guard rejects the stale host library's seven
missing CUDA symbols and 76 unowned exports. It checks ownership and names;
native signature compatibility, execution, packaging and provenance remain
unqualified. The Android migration adds 21 managed Java cases covering key-manager
provider evidence/dispatch, explicit context isolation, canonical envelopes and
ZK model fixtures. All 32 scenarios in the three selected Java source suites now
map to these consumers, prior core consumers, existing internal Kotlin checks,
or compiled declaration constraints. The native ML-DSA manager case compiles
and requires `:client-android:testDebugHostNative` with an explicit rebuilt bridge.
The latest managed Android run passes 78 client and 2 wallet tests, including the
strengthened software fallback assertion. It does not execute the native case.

Java metadata authoring is now supported directly through the canonical
`JsonValue` factories. The immutable nominal class preserves canonical JSON
value equality; the payload owns an unmodifiable metadata copy for every map
size and rejects Java null entries. Five Java consumers and 41 existing
JSON/payload/codec tests pass. A wider selection also reached an existing
required-native assertion and failed without the bridge; the full JVM suite
has not requalified after this API change.

The canonical automatic native source is migrated; rebuilt native and hardware qualification remain open. These are seven capability groups across eight
queue entries, not eight replacement classes.

| Java queue entry | Concrete gap and canonical destination |
| --- | --- |
| J `client/CanonicalRequestSignatureProvider.java` | Migrated to Kotlin `RequestSigner`, used by canonical request authorization and all signing consumers. Five Java consumer tests cover opaque callbacks and canonical bytes; the full 1,253-test JVM run passes. Java implementation retirement remains. |
| J `nexus/NexusModelUtils.java` | Invariants now belong to immutable Kotlin `NexusAppModels` values: validated construction, owned arrays and immutable maps/sets, payload-derived hashes and canonical Ed25519. Twenty-seven focused tests, including five Java consumers, pass in the full JVM run. No public utility replacement or data-class copying remains. |
| J `offline/IrohaPeerNearbySecureChannelV1.java` | Kotlin `IrohaPeerNearbyV1.Session` owns typed verified-IPM1 seal/open, profile/sequence checks, bounded copies and wiping. Seven Kotlin and four Java consumer tests pass; both duplicate Java Nearby facades were removed. Device/radio qualification remains. |
| J `gpu/CudaAccelerators.java` | Migrated to K `gpu/Accelerators.kt`: bounded automatic batches, explicit disabled/injected/native contexts, owned arrays and canonical BN254 limbs. JNI snapshots and results use the common process envelope through foreign copy. Retired CUDA-only names have no aliases. Java API controls, host native binding and ordinary Poseidon/BN254 parity suites retain their assertions. Rebuilt native execution, per-family JNI completion receipts and CUDA device qualification remain open. |
| J `tools/AndroidKeystoreAttestationHarness.java` | Replaced by `kotlin/tools` application `iroha-attestation`, using the byte-identical pure verifier moved to `core-jvm`. All 25 tool tests pass (22 Java consumers, 3 bounded-reader cases), including the original fixture assertions, independently supplied roots/challenge/SPKI/snapshot/time, duplicate/conflicting argument rejection, ZIP/byte bounds and atomic output identity. The shell launcher invokes the installed Kotlin command; old Java command and tests are removed. Physical StrongBox qualification remains separate. |
| JA `client/okhttp/OkHttpTransportExecutor.java` | Migrated to Kotlin `OkHttpTransportExecutor` and per-client `HttpTransportScope`. Owned defaults, borrowed injection, cancellation, permanent close, bounded framing/decompression and one-shot dispatch pass 29 transport, 8 scope and 8 Java consumer tests. Twelve new SSE lifecycle tests also pass. The full JVM checkpoint is 1,295 tests; Android debug unit suites pass 57 client + 2 wallet tests. Java backend retirement remains. |
| JA `client/okhttp/OkHttpWebSocketConnector.java` | Kotlin `NettyWebSocketConnector` owns explicit NIO/TLS lifetimes and a single upgrade attempt. Twenty-nine WebSocket tests pass, including two Java consumers, real wire bounds, TLS hostname/trust rejection and concurrent close/send. The 72-test focused selection also covers security, SSE and HTTP scopes. |
| JA `client/okhttp/OkHttpTransportWebSocket.java` | Canonical Kotlin interfaces send/deliver complete messages; ignored fragment flags and unsupported public ping/pong controls are removed. The engine bounds frame/aggregate size and outgoing bytes/count, checks UTF8 before allocation and handles wire control frames internally. Subscription cancellation/reconnect tests pass; the full 1,295-test JVM suite passes, with Android requalification and Java backend retirement remaining. |

HTTP/SSE use the Kotlin-owned OkHttp adapter. WebSockets use an explicit Netty
handshake because OkHttp hides the hooks needed to prohibit upgrade replay. Both
engines live in Android-free `core-jvm`, retain JDK 8 API enforcement, and expose
explicit resource ownership. There is one implementation per protocol.

## Duplicate surface to retire

| Java queue entry | Disposition |
| --- | --- |
| J `gpu/CudaAcceleratorsKotlin.java` | Removed. Java and Kotlin consumers call the same Kotlin-owned batch API; no Optional/null facade, scalar alias or global backend setter remains. |
| J `crypto/keystore/AndroidKeystoreStubBackend.java` | Desktop unavailable-backend sentinel. KA `crypto/keystore/AndroidKeystoreBackend.kt:43` explicitly constructs `SystemAndroidKeystoreBackend`; platform/version handling stays in KA and software providers stay explicit. Do not restore desktop Android discovery. |
| JA `client/AndroidClientFactory.java` | Construction convenience for HTTP, RPC, SSE, WebSocket and SoraFS. Use Kotlin builders with explicit shared adapters once the transport gaps above close. Preserve capability tests, not the umbrella factory. |
| JA `offline/IrohaPeerNearbyAndroidV1.java` | Removed after verified-IPM1 ownership and Java consumer tests moved to the Kotlin session and Android adapter. |
| JA `client/transport/OkHttpTransportExecutor.java` | Delegates to the other Java OkHttp executor; no independent transport behavior. |
| JA `client/okhttp/OkHttpClientProvider.java` | Global shared-client selection/replacement wrapper. Replace with explicit adapter resource ownership; do not keep the singleton discovery surface. |
| JA `client/okhttp/OkHttpTransportExecutorFactory.java` | Construction wrapper; retain lifecycle tests when replacing it, not a second factory. |
| JA `client/okhttp/OkHttpWebSocketConnectorFactory.java` | Construction wrapper for the connector to migrate. |
| JJ `client/JavaHttpExecutor.java` | Alternative JDK `java.net.http` HTTP implementation. Canonical K OkHttp provides HTTP/SSE within JDK 8; move its useful retry/framing cases into the chosen transport tests and retire this backend. |
| JJ `client/JavaHttpExecutorFactory.java` | Alternative JDK-client construction wrapper; no independent protocol capability. |
| JJ `client/websocket/JdkWebSocketConnectorFactory.java` | Retire with alternate backend after the canonical WebSocket connector exists. |
| JJ `client/websocket/JdkWebSocketConnector.java` | Retire JDK-11-dependent connector; carry handshake/transport contract tests to the canonical implementation. |
| JJ `client/websocket/JavaTransportWebSocket.java` | Retire the alternate JDK socket wrapper. The canonical Kotlin API delivers complete messages; frame aggregation and ping/pong belong to the engine and have no duplicate public control surface. |
| `java/iroha_android/samples-android/src/main/java/org/hyperledger/iroha/android/samples/MainActivity.java` | AAR-linkage/address-rendering sample only (lines 10–31). Address functionality already exists in K. Replace the packaging smoke coverage with a Java consumer of the Kotlin AAR, not a second SDK sample implementation. |

## Concrete test migration and completion conditions

- **Request signing:** port the callback cases from J tests
  `client/CanonicalRequestSignerTests.java:386–452` (maximum signature,
  empty/all-zero/oversized rejection and canonical bytes supplied to callback)
  and callback consumers in `AtomicPrivateSettlementToriiClientV1Tests.java`.
  Kotlin currently uses direct PrivateKey fixtures; add a Java-source consumer
  with an opaque signer and no private-key access, mutation isolation and
  propagated signing failure. Existing Kotlin canonical-message goldens remain
  authoritative; the provider must not alter account/network/body/freshness
  binding or validation bounds.
- **Nearby:** change the existing session's `seal` to accept a verified
  `IrohaPeerWireMessageV1` and `open` to return it. Validate the message profile
  against the authenticated session; retain bounds before copying, use owned
  encode/decrypt buffers and wipe them in `finally`. Decode/authenticate fully
  before advancing inbound sequence. The Android radio transport remains a
  bounded encrypted-record carrier. Java facades are deleted as consumers move
  to the canonical Kotlin types. No dedicated Java Nearby test was located in
  the current test tree, despite the facade's golden-test comment. Add tests
  for valid verified payments, authenticated invalid IPM1, wrong profile,
  replay/reordering, malformed/oversized records, failed-decode sequence
  behavior, mutation and idempotent destruction. Existing Swift
  `IrohaSwift/Tests/IrohaSwiftTests/IrohaPeerNearbyV1Tests.swift:307–650` supplies
  relevant crypto/sequence cases, but its raw `IPM1-payment-fixture` strings
  must become valid verified messages for the typed boundary. Kotlin's existing
  Android permission test is not secure-channel or radio-lifecycle coverage.
- **WebSocket and HTTP lifecycle:** retain JA tests
  `client/okhttp/OkHttpWebSocketConnectorTests.java:30/94` (real mock-server
  messages and timeout), JJ test `client/websocket/JavaTransportWebSocketTests.java:14`
  (callbacks, binary/text, controls), and JA
  `client/okhttp/OkHttpTransportExecutorTests.java:62–315` (307/308,
  connection/status retries, gzip expansion, limits, timeout, scoped cancellation
  and shared-resource isolation). Factory-identity assertions can be removed;
  rewrite assertions around explicit ownership. Keep K
  `client/transport/OkHttpTransportExecutorTest.kt` for the
  existing framing/limit contract. A passing mock connector is insufficient:
  require real connector handshake/message/close tests and Android consumption.
- **Automatic native computation:** canonical Java consumers preserve validation,
  null-result, diagnostic status, ownership and injected-backend behavior. The
  host binding test resolves all seven `Accelerators` JNI declarations. Ordinary
  native suites retain all ten Poseidon CPU goldens and independent BN254 modular
  comparisons, batching and size-one equivalence. These suites permit the CPU
  fallback. Rebuilt JNI execution remains pending. `cudaHardwareTest` reports an
  open gate until per-family completion receipts can prove physical execution;
  availability and equal output alone are insufficient.
- **Attestation command:** all original harness assertions are migrated into
  `kotlin/tools` Java consumer tests. The 25-test suite passes, including both
  shared mock vendor fixtures, directory/ZIP roots, independently supplied
  identity/revocation commitments, and bounded reader/output behavior. The pure
  verifier moved byte-for-byte into `core-jvm`; Android device provisioning
  remains in `client-android`. The launcher builds the Kotlin distribution and
  preserves argv and the configured external artifact directory. Requalified Android host suites pass 57 client + 2 wallet tests; physical
  device evidence remains required.
- **Nexus values:** retain `NexusAppClientTest.java` transaction/Connect fixtures
  against K `NexusAppClientTest.kt`; add explicit constructor-input and
  accessor-output mutation tests for arrays, maps and sets, blank identifiers,
  and Java construction/signing. No dedicated mutation regression was found
  for all these Java values. Replacing the public Kotlin data classes also
  requires migrating test `.copy(...)` calls to valid immutable construction.

Retirement is complete only after the canonical Kotlin JVM/Android artifacts,
Java-source consumers, selected native/Android integration gates and retained
shared fixtures pass without compiling or loading the Java implementation.
The 33-entry queue cannot detect behavior gaps between identically named
classes (the request-auth and Nexus findings demonstrate this), nor does it
cover the complete Java publication, resource or JNI inventory.

## Subsequent implementation and qualification

- Kotlin auth now accepts the canonical `RequestSigner` interface. Software uses
  `RequestSigner.ed25519`; no auth constructor or request builder accepts a raw
  private key. All request consumers and 55 test calls migrated.
  Header/body signatures validate callback bounds and copy owned message/signature
  buffers. Five Java consumer tests cover exact canonical bytes, opaque callbacks,
  invalid output, software verification and failure without a second attempt.
- A fresh local `connect_norito_bridge` plus `kotlin-fixture-gen` build passes.
  With those explicit artifacts, the full Kotlin `core-jvm` suite passes 1,253
  tests, zero failures/errors/skips. This includes native JNI execution and the
  migrated Norito Java consumers. The production reflection guard passes.
- Nexus request/session/payload/signature records are now regular immutable Kotlin
  classes with byte-content equality, owned bytes and immutable collection snapshots.
  Signable payload hashes are derived from those owned bytes; the caller-supplied
  hash and all data-class copy methods are removed. Only canonical `ed25519` is
  accepted, including at construction; the `"0"` algorithm alias is removed.
  Receipts deeply snapshot JSON and retain transaction-hash validation. All 27
  focused Nexus tests pass, including five new Java construction, signing,
  mutation, algorithm and nested-receipt tests. Production reflection checks pass.
- The existing Kotlin Nearby session now seals and opens verified
  `IrohaPeerWireMessageV1` values, binds the authenticated profile, checks bounds
  before encoding and advances the receive sequence only after authenticated
  decoding succeeds. Owned temporary plaintext is wiped on every exit, including
  nested IPM1 decoder failure. Both duplicate Java Nearby facades are deleted;
  applications use the Kotlin session and Android radio adapter directly.
  Seven Kotlin adversarial/fixture tests and four Java consumer tests cover real
  role-bound signatures, compressed/exact shared messages, malformed authenticated
  plaintext, tamper/replay/reordering, ownership and destruction. These are host
  transport/shape tests, not offline-money proof or physical-radio qualification.
- HTTP/SSE now has one Kotlin-owned OkHttp backend. URLConnection, runtime platform
  discovery and overlapping default-client factories are removed. Shared framing
  validation runs before decompression, and decoded buffered bodies retain exact
  per-request limits. Requests and stream headers own immutable snapshots.
  Signed/mutating requests cannot replay on redirects, authentication follow-ups,
  connection loss or retry hints; original response hints are retained.
  Every HTTP/RPC/SSE/service client owns a call scope and implements `close`:
  default backends are owned; injected backends and scheduling executors remain
  borrowed. Closing disposes active streams safely during concurrent reads,
  rejects new admission, and cancels transaction polls. Twenty-nine Kotlin
  transport cases, seven scope cases and eight Java runtime consumers pass in
  the 1,253-test full JVM run. A subsequent focused run passes the eighth scope
  case and twelve SSE lifecycle cases, including cancellation during response
  admission/read, callback closure, reader rejection and borrowed executors.
- The canonical Netty WebSocket engine and subscription lifecycle pass 29 tests,
  including two Java consumers, real TLS/hostname rejection, oversized frame
  headers, fragmented aggregate bounds, UTF8, control replies, queued-byte/count
  bounds, late handshakes, reentrant closure and concurrent event-loop shutdown.
  All 72 focused transport/security/SSE/scope tests pass. The subsequent full JVM
  suite passes **1,295 tests, zero failures/errors/skips**, with the explicit local
  JNI library and fixture generator. The retired OkHttp WebSocket implementation
  is absent; its 503 upgrade replay could not meet the no-replay contract.
- Android debug JVM tests pass 57 client and 2 wallet tests without native builds.
  Challenge-less verification overloads/default arguments are removed, and the
  verifier builder requires policy/time inputs. Four Java consumer tests execute
  shared StrongBox certificates, challenge rejection, roots and time isolation.
  These are host tests, not physical StrongBox or release-native qualification.
- Android/device, publication/provenance and CUDA hardware qualification remain
  open. The remaining capability gaps above and duplicate Java implementation have
  not yet been retired.

- **Exact12 fixture owner:** the Java fixture codec and its two outer model
  classes are retired. All seven original Java tests, including every assertion,
  now compile against the canonical Kotlin API in
  `PrivacyExact12FixtureJavaConsumerTest`. JVM CI runs that consumer alongside
  the six Kotlin fixture tests; all 13 pass with the unchanged Rust-derived
  archive. This is codec/fixture execution evidence, not JNI or native packaging
  qualification. The privacy source guard takes its exact six C exports from
  the manifest parity auditor's single approved inventory.


The standalone Java privacy bridge assertions now belong to the Kotlin test
module as `PrivacyNativeBridgeJavaConsumerTest`. They call the canonical Kotlin
V1 owner and require its network-bound JNI declarations; no retired JNI aliases
are restored. The original registry, matrix, status, preflight, native archive and mutation
assertions remain. Internal archive rejection uses the identical truncations in
the selected Kotlin friend tests; native modifiers/descriptors and retired
generic methods are checked through the existing Python classfile owner,
without adding SDK reflection. The official JVM lane runs
this consumer with the existing canonical tests and selects JDK 21 executables
explicitly, preserving the authenticated Cargo PATH through final verification.
Native execution of this changed source remains a separate qualification gate.
The duplicate Java confidential/Merkle owner closure and its bridge and three
identity enums are removed. Its five confidential-note and eight Merkle-path
Java groups now live in `core-jvm` and call the canonical Kotlin capabilities.
The Java transport and instruction consumers use the canonical protocol enum
without label conversion. The official JVM lane selects both migrated suites.
The Rust bridge removes all 19 corresponding Android privacy exports; all 38
SDK signatures and body logic in the guarded pair owner are unchanged
(rustfmt expands one helper call); confidential macro bodies are unchanged. Source inventories,
JDK 8 API compilation, and migration checks are diagnostic evidence. Fresh
native execution, compiled export closure, Android packaging, and physical
hardware qualification remain open.

The remaining generic confidential witness archive producer is removed from
Java and Kotlin, together with Swift's orphan V1/V2 producer. The retired
`privacy_production` bridge module has no decoder for those archives. The mixed
Java compatibility group retains its complete BFV assertions; its witness-copy
assertions now exercise a Kotlin-owned historical fixture in test sources.
All five Swift witness archive groups exercise the historical test fixture.
The Java and Swift tests require the current typed archive decoders to reject
these retired archives. Source-absence and relocation negatives in
`scripts/tests/check_privacy_retired_witness_boundary_test.py` keep these fixtures
out of every production SDK source root. The compiled Kotlin/JVM class auditor
also rejects retired witness owners and test-fixture leakage into main outputs.
Engine-specific Rust witnesses remain local to their governed builders. A
generic witness serializer is not a replacement for an SDK proving route;
complete SDK proof-construction qualification remains open.

The capacity-declaration instruction now has one Kotlin-owned declaration payload,
with canonical bounded Base64, defensive byte ownership and strict rejection of
caller-provided registration time or derived provider/capacity/validity/metadata fields.
The duplicate Java implementation is removed. `SorafsCapacityDeclarationJavaConsumerTest`
preserves payload/action/Base64 coverage and replaces retired projection assertions with
explicit refusal tests through the canonical Kotlin API. The focused `:core-jvm:test --tests
org.hyperledger.iroha.sdk.sorafs.SorafsCapacityDeclarationJavaConsumerTest` passed with JDK 21
and the enforced JDK 8 API/source targets. The remaining capacity dispute/pricing Java
builders are unchanged.

`UpsertProviderCreditInstruction` has one Kotlin-owned argument template with an
explicit absence/exact-current-record hash guard. The duplicate Java builder is
removed. `SorafsProviderCreditJavaConsumerTest` preserves its four action, nominal
credit, strike-count and metadata assertions through the canonical Kotlin constructor;
Kotlin tests add required-guard, roundtrip and defensive-copy controls. These are
argument-template checks, not native transaction-wire or provider-readiness proofs.
Current-candidate JVM execution and native fixture capture remain validation gates.

## Kotodama manifest parser ownership (2026-09-23)

The 14 groups in the duplicate Java `ContractManifestTests` harness are covered
by the Kotlin-owned `ContractManifestTest`: exported and nominal shared fixtures,
explicit public returns, V1 call-table limits, complete manifest fields, trigger
names, numeric type grammar, bounded dynamic access, endpoint paths, flat schema
depth, and reserved projection/page shapes. The Kotlin suite also checks current
empty-product grammar. In particular, `Transfer{}` is a valid V1 nominal product;
the old Java rejection was obsolete, and the Kotlin and Java-source consumers
instead reject the noncanonical `Transfer{ }` spelling. Three Java-source
`ContractManifestJavaConsumerTest` cases exercise the Kotlin parser and immutable
model directly, including shared nominal errors, the 8,192-word table bound,
dynamic access declarations, and empty products. The duplicate Java test class
and its `GradleHarnessTests` registration are removed. The focused JDK 21 Gradle
run passes all 16 Kotlin and 3 Java-source tests with JDK 8 API enforcement.

The duplicate Java production manifest parser and models are also removed.
The Java `HttpClientTransport` exact-read path and `IrohaClient` method now return
the Kotlin-owned `ContractManifestRecord` and parse through the Kotlin-owned
`ContractJsonParser`. The syntax generator no longer targets the retired Java
parser. The configured full Java `:core:test` run passes 415/415 after aligning
the V1 Parliament transition list, BFV expected-error vector, and canonical
lowercase UAID parity input. This finishes manifest parser and record ownership;
broader duplicate Java implementation retirement, Android/device qualification,
and full release evidence remain open.

## Parliament Java-source consumer ownership (2026-09-24)

`ParliamentApiV1JavaConsumerTest` now compiles Java against the Kotlin-owned
`ParliamentApiV1` and top-level draft response/instruction models. It exercises
closed proposal validation, exact attempt-draft fields and retry bound,
authenticated draft response identifiers and wire ID, rejection of unknown
fields, and the canonical attempt-read route. The tests use JDK 8 APIs under
the Kotlin `core-jvm` compile guard. This is an initial Java-source consumer
slice, not retirement of the duplicate implementation or its test evidence.

At that September 24 checkpoint, the duplicate Java `ParliamentApiV1` and
`ParliamentProposalValidatorV1` were coupled to Java transport and wallet callers.
The September 30 migration below removes the duplicate proposal validator,
proposal model, paging value types and trust anchor, and compiles the affected
Java-source consumers against their Kotlin owners. The remaining Java transport,
wallet backend and non-proposal API implementation surface still requires
capability retirement with assertion preservation. Kotlin mirror tests alone
cannot replace Java-source compilation evidence; no compatibility facade or
fallback validator belongs in the first release.

## Complete-checkpoint Java paging ownership (2026-09-30)

The Java Android wallet accepts Kotlin's canonical
`ParliamentTimedOvnCastingTrustAnchorV1` and returns Kotlin's complete public-record
and page-verification owners. The duplicate Java trust anchor and diagnostic-only
paging value types are removed. Java transport and consumer tests invoke the canonical Kotlin response parser
directly; no Java forwarding parser is retained. `ParliamentTimedOvnCastingProofPagerV1` owns the pure paging loop for
both transport consumers: complete signed checkpoints survive promotion and
persistence, every next page waits for durable persistence, and the existing page,
height and checkpoint limits remain mandatory. Each transport retains exact
signed, bounded, one-shot requests and requires fresh nonce/timestamp authority.

Java and Kotlin consumer controls carry the genuine checked-in signed genesis
and height-2 checkpoints, whose lengths differ from a 32-byte context hash, and
assert defensive copies and persistence ordering. These managed controls test
API ownership and byte preservation; current native and device qualification is
recorded separately. Exact preceding source and assertion preimages are retained
in the unit-repair evidence lane after concurrent removal of repository history.

Java attempt-draft requests invoke Kotlin's `ParliamentApiV1` directly with its
`Proposal`, closed ten-kind inventory and recursive proposal validator; the
Java forwarding request builder and proposal-kind constant are removed. The duplicate Java
proposal model and validator are removed. Java consumer tests retain the existing
nested-payload rejection controls. The twentieth Musubi shared instruction fixture uses
the canonical Kotlin `AdvanceMusubiPinOutboxV1` owner in Java-source assertions
for every concrete and dynamic frame; it introduces no additional Java codec.

The Java-only `ClaimIdentifierWirePayloadEncoder` is removed. Its Java-source
consumer suite now exercises the canonical Kotlin encoder and receipt models,
including all five existing frame/parity/refusal cases. The canonical structural
decoder exposes defensive receipt-byte copies; signature and policy verification
remain separate. Consumers assert the mandatory absent phone-retail-canonicality
field and reject a phone-retail claim without its signed evidence rather than
emitting an incomplete receipt layout.

OMAPI discovery transfers an available channel/service owner only when its
caller-facing completion succeeds. Cancellation between discovery completion
and delivery disposes the undelivered owner exactly once. Managed regression
controls cover that completion order, successful delivery, pending cancellation,
original failure propagation and the existing single-reader/capability/timeout
refusals; they do not qualify native or physical-device execution.

## Retail fee quote and multisig proposal Java retirement (first release)

The duplicate `java/iroha_android` Hijiri quote classes, transport methods and
quote-only suites are retired with their old five-field policy/hash/coordinate
proposal DTO, marker constructor and Norito DTO encoder. They target a superseded
protocol. No alias or Java implementation replaces them. Java consumers use the
actual Kotlin-owned `MultisigProposeRequest`, `HttpClientTransport` and
`RetailFeeAssessmentBridge`; the immutable bounded assessment and sole Native
marker are the current protocol.

The generic Java instruction hash/exact outer multisig executable verifier and
its adversarial suite remain unchanged. Canonical Kotlin transport controls retain
proposal hashing, fee intent, trusted network, authority, complete metadata,
creation time, default lifetime, nonce, attachments, outer executable and alias
refusal checks. The shared Rust-produced instruction fixture remains unchanged.
`CanonicalMultisigJavaConsumerTest` exercises this Kotlin API from Java, including
instruction ownership, exact JSON shape, Ed25519 identity rejection, assessment
object/UTF-8 bounds and missing trusted signing-context refusal before dispatch.

This records source retirement and test declarations. The new controls have not
yet executed; JNI, physical hardware, genuine monetary/proof admission and
release qualification are separate. Original retired sources and assertion maps
are retained in the source packet.

## Provider-ingest completion authority ownership

Kotlin owns the mandatory provider owner, completion signer and signer-policy
record for both JVM languages. The affected Java Musubi provider attestation
models, JSON parser, instruction encoder and digest implementation are retired.
The Java transport consumes Kotlin's exact request/record types and canonical
record decoder; existing Java fixture, signed-request and mismatch assertions
remain Java-source consumers. Unrelated Java Musubi capabilities remain tracked
for their own retirement.

The separate Java replication completion authority, policy, anchor and instruction
builders are retired. `ReplicationOrderJavaConsumerTest` in Kotlin core preserves
every former issue/complete/expire builder assertion through Kotlin's typed API
and adds mandatory-signer/retired-layout controls. Canonical fixture regeneration
and combined Kotlin/Swift/Java validation remain required for this source change;
no new fixture hashes or runtime qualification are implied.

## Java peer-carrier and KAGEMUSHA duplicate retirement (first release)

The `java/iroha_android` peer carriers are removed. Kotlin owns them for both JVM
languages: K `offline/IrohaPeerWireV1.kt` (payload kind/profile, content
encoding, compression policy, limits, canonical payload and wire message),
`IrohaPeerNfcV1.kt`, `IrohaPeerQRV1.kt` (frame, codec, clock, scan
limits/result/session)
and `IrohaPeerNearbyV1.kt` (roles and the verified-IPM1 session), plus KA
`offline/IrohaPeerAndroidNfcV1.kt`. The fifteen J `offline/IrohaPeer*.java`
classes, JA `offline/IrohaPeerAndroidNfcV1.java` and its two Android resources
(`iroha_peer_transport_strings.xml`, `iroha_peer_nfc_v1_aids.xml`, both already
shipped by `client-android`) have no replacement facade. The JA manifest no
longer repeats the peer-transport permissions and features: `client-android`
declares them and is an `api` dependency, so the merged manifest is unchanged.
The unused Nearby Play Services dependency and the `androidTest` asset source
for `fixtures/offline` are removed with them.

The old-KAGEMUSHA Java surface is deleted without migration, because its
protocol is retired: J `offline/Kagemusha{Norito,Wire,WirePayloadKind,Wallet,
HardwareProvider,EnrolledOpenChallengeCodec,CoreCoordinatorFrame,
CoreCoordinatorArchive}V1.java`, `offline/IrohaPeerKagemushaAdapterV1.java`,
`client/KagemushaToriiClientV1.java`, `client/KagemushaToriiModelsV1.java`,
`model/instructions/TopUpKagemushaV1Instruction.java`, and JA
`offline/Kagemusha{CoreCoordinatorBridge,DeviceLifecycleBridge,
NativeCoreCoordinatorAdapter}V1.java`. These classes forwarded to the retired
Kotlin codec, wallet and coordinator. Their suites are removed with them, and
the `fixtures/offline/kagemusha_*` files are no longer Gradle test inputs. The
KAGEMUSHA wallet wire V1 (`specs/kagemusha_wallet_wire_v1.md`) has a single
owner, K `offline/KagemushaWalletWireV1.kt`, which Java consumers call
directly.

Assertion preservation: the generic NFC APDU round-trip, non-canonical
extended-APDU rejection and single no-data encoding checks of the former
`IrohaPeerNfcV1AdversarialTests` now run as the Java-source consumer
`kotlin/core-jvm/src/test/java/org/hyperledger/iroha/sdk/offline/IrohaPeerNfcJavaConsumerTest.java`.
Its message-tag check asserts the current seven wallet-envelope kinds rather than
the retired three-message vocabulary. Nearby Java-source coverage stays in
`IrohaPeerNearbyJavaConsumerTest.java`. The Java Taira profile names the Digital
Shekel asset `DIGITAL_SHEKEL_ASSET_*`, matching Swift and C#.

This records source retirement. The remaining Java Gradle failures predate it
and are tracked with their own owners; physical NFC/Nearby qualification is
separate.
