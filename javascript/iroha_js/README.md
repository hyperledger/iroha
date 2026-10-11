# Iroha JS SDK

`@iroha/iroha-js` is a JavaScript/TypeScript SDK for interacting
with Hyperledger Iroha nodes from Node.js runtimes. It provides Norito codecs,
Ed25519 signing, transaction and instruction builders, Torii query and
transaction clients, event streaming, and helpers for Connect, SoraFS, and DA
workflows.

TypeScript consumers can import the bundled `index.d.ts` definitions for the
SDK surface.

## Quickstart

Every Torii collection is a property of the client with the same three
methods: `list()` reads one page, `pages()` iterates pages and `iterate()`
iterates every item, following `nextCursor` until it is `null`. Filters use one
grammar for collections, event streams and the `iroha` CLI
(`specs/torii/collection_queries.md`).

```js
import { ListQueryError, ToriiClient, ToriiHttpError, field } from "@iroha/iroha-js";

const torii = new ToriiClient("https://torii.example");
const accountId = "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB";

// One page, filtered and sorted (`-field` sorts descending).
const page = await torii.assetDefinitions.list({
  filter: field("owned_by").eq(accountId).and(field("alias_binding.status").eq("permanent")),
  sort: "-alias_binding.bound_at_ms,id",
  limit: 50,
});
console.log(page.items.map((definition) => definition.id), page.nextCursor);

// Every matching item; a text filter is sent exactly as written.
for await (const holding of torii.accountAssets(accountId).iterate({
  filter: "quantity >= 10.5",
  select: ["asset", "quantity"],
})) {
  console.log(holding.asset, holding.quantity); // quantities are exact decimal strings
}

// Errors carry Torii's stable `code`, its message and structured `details`.
try {
  await torii.domains.list({ filter: "owner = 'alice'" });
} catch (error) {
  if (error instanceof ToriiHttpError) {
    // 400 invalid_filter: unknown field `owner`; details.hint suggests `owned_by`
    console.error(error.status, error.code, error.errorMessage, error.details?.hint);
  } else if (error instanceof ListQueryError) {
    console.error(error.code, error.message); // rejected locally, nothing was sent
  } else {
    throw error;
  }
}

// Event streams take the same filters; abort the signal or `break` to unsubscribe.
const subscription = new AbortController();
for await (const frame of torii.streamEvents({
  filter: field("tx_status").in(["Approved", "Rejected"]),
  signal: subscription.signal,
})) {
  if (frame.event === "stream_error") break; // the live stream lost events
  const { data } = frame; // { category: "Pipeline", event: "Transaction", status, ... }
  if (data.event === "Transaction" && data.status === "Rejected") {
    console.log(data.hash, data.rejection_code, data.rejection_reason);
  }
}
```

`ToriiBrowserClient` (`@iroha/iroha-js/torii-browser`) exposes the same
collections and `streamEvents`. See [Collection queries](#collection-queries)
for the full reference.

Public Taira metadata is available without copying runbook literals. Supply the
current deployment's genesis-derived `NetworkId`; the stable chain UUID is not
a signing identity and the profile never substitutes it:

```js
import {
  NetworkId,
  TAIRA_TESTNET_PROFILE,
  ToriiClient,
  createTairaLocalSigningContext,
} from "@iroha/iroha-js";

const networkId = NetworkId.parse(configuredNetworkIdLiteral);
const torii = new ToriiClient(TAIRA_TESTNET_PROFILE.toriiBaseUrl, {
  localSigningContext: createTairaLocalSigningContext(networkId),
});
```

Before an account exists, `ToriiClient.getAccountCapabilities({ signal })` and
the browser client's matching method read public `GET /v1/accounts/capabilities`.
The closed `AccountCapabilitiesV1` JSON response contains `schema_version: 1`,
the canonical `network_id`, a u16 `network_prefix`, the current `allowed_signing`
admission set, and explicit `default_signing: "ed25519"`. Ed25519 is the
first-release account-bootstrap policy and is mandatory in node admission;
array ordering and the node's default hash do not express signing preferences.
Compare the returned network identity with the user's selected network before
creating an identity. This advert is endpoint discovery, not signed network
evidence or permission to submit a transaction.

These SDK calls omit configured credentials, reject redirects, accept only the
exact V1 JSON shape, enforce a 4 KiB streamed response limit, and support abort
through body consumption. The route accepts no query or request body. Standard
Torii listener access controls still apply. `GET /v1/node/capabilities` is public
as well: `getNodeCapabilities()` reads it without credentials, and the
transaction preflight caches only a successful, matching probe.

Ordinary source-checkout unit tests can use a separate current Debug N-API
producer. From the repository root, select the worktree's existing warm Cargo
lane and an external artifact directory whose parent is owned mode `0700`:

```bash
python3.12 -I -S -B scripts/native_js_local_unit.py produce \
  --root "$PWD" --target-dir "$PWD/target/cargo-fast/<existing-lane>" \
  --output /absolute/owner-only-directory/js-native \
  --config /absolute/local-native-tools.json --acknowledge-local-unit-recipe
(cd javascript/iroha_js && IROHA_JS_NATIVE_DIR=/absolute/owner-only-directory/js-native \
  node ./scripts/run-test-profile.mjs unit)
```

The tool configuration has exactly `python`, `cargo`, `rustc`, `rustdoc`,
`node`, `clang`, `ld`, `codesign`, `sdk` and `developer_dir` paths. Use the
current canonical Python 3.12 and Node executables, stock Rust 1.93.1 tools,
and the selected Xcode's macOS SDK, clang and Apple linker. The producer uses
locked, offline Cargo with its native jobserver and incremental compilation;
it creates no additional Cargo target. It retains the actual compiler JSON,
complete dep-info after Cargo's natural successful terminal, original source
and native build inputs, exact tools, and independently copied emitted bytes.
The real Node consumer checks the current ABI and required exports before the
explicit local-unit manifest can be loaded. Loading rechecks current consumed
inputs and code before making an immutable native snapshot. No test is skipped
when source, receipt, native or export checks fail.

This artifact has only host Debug local-unit scope. Package publication,
`prepack`, Release/deploy and installed native qualification retain the strict
V4 provenance path below and do not admit its local-unit manifest.

From an Iroha source checkout, the provenance build for packaged native
artifacts wraps `cargo build -p iroha_js_host`:

```bash
npm install
npm run build:native
```

The native build writes strict V4 provenance with the execution policy
`trusted-local-cargo-v1`. Cargo compiles the authenticated live repository root.
The builder seals the tracked and untracked source inventory, original root Cargo
lockfile and exact compiled bytes, and checks that source state again after
compilation and during publication. Keep the checkout, index and HEAD unchanged
through compilation, publication and native-backed tests. A dirty checkout is
supported by the `debug` profile only; `release` and `deploy` require a clean
source tree. The attestation trusts the invoking user, local peer processes,
toolchain, build scripts, procedural macros, dependencies and build environment.
It is not a reproducible-build or hostile-executor proof.
Release processes that require that stronger property must compare matching
artifacts from independent controlled rebuilders.

`scripts/build-native.mjs` requires explicit canonical paths for Cargo, rustc
and rustdoc from the same stock Rust 1.93.1 toolchain, the repository-root
`Cargo.lock` and the Cargo target directory. It invokes stable Cargo with the
original root manifest and `--locked --offline`, and enforces
`CARGO_BUILD_JOBS=1`, `CARGO_INCREMENTAL=0`, `CARGO_NET_OFFLINE=true`.
It rejects `RUSTC_BOOTSTRAP`, `CARGO_PROFILE_*` overrides and alternate lockfiles.
The configured target must be the repository's `target` directory or wholly outside the source
tree. Preserve `IROHA_JS_CARGO_LOCKFILE_PATH` through publication and loading so
each provenance check observes the same original root dependency graph.

The configured target is a cache parent. Builds use an `iroha-js-source` child
keyed by the complete authenticated source fingerprint, canonical checkout,
toolchain executable paths and hashes, platform, profile and build flags.
Publication resolves the authenticated completed attempt in that child; it never
falls back to a shared profile directory. This deliberately rebuilds after any
authenticated source change. Interrupted, failed, drifted or corrupted attempts
remain available as evidence, and retries automatically use a fresh attempt
directory. Warm local artifacts require a completed receipt and matching output
hashes before and after Cargo; an arbitrary prepopulated cache is not accepted.
Each build retains its Cargo JSON stream beside the compiled addon. Successful
builds also retain a `.jsonl.inputs.json` receipt with every local compiler
artifact and its output hashes. Local manifests and entrypoints must belong to
the captured checkout, and emitted artifacts must stay inside its selected
target. Registry and Git dependencies still use ordinary locked, offline Cargo
resolution; this receipt does not claim an archive of their source bytes.

Loading a debug artifact from a dirty source tree verifies its recorded source
seal in a separate process before loading native code. This verifier has a
15-second timeout and does not inherit `NODE_OPTIONS`. In Electron, it runs
with `ELECTRON_RUN_AS_NODE=1` so verification cannot launch another application
or renderer. Verification failure or timeout prevents the native binding from
loading.

Native publication also assumes that the configured Cargo target is on a
single-host local, hard-link-capable filesystem and that cooperating builders
share one PID namespace. Its durable owner record recovers an interrupted
publisher only after that exact local PID is no longer live; foreign-host,
malformed, and ambiguous lock state is preserved and rejected. Do not publish
the native host through a network filesystem or a volume without hard-link
support. Concurrent publishers must all run the current owner-record protocol;
mixing an older empty-directory lock implementation with this one is
unsupported. Recovery retains a tiny owner-specific tombstone as an ABA guard
so a delayed recovery process cannot displace a newer live publisher.

Cargo may expose the validated profile-root `cdylib` as a hard link to its
`deps` artifact. The builder accepts that exact Cargo-JSON-validated path only
as an input, copies it into a private singly linked seal, and publishes from
that seal. Staging and final native binaries remain strictly singly linked.

When upgrading a source checkout from a revision that tracked the checksum
manifest but ignored the generated binary, Git can remove the manifest while
leaving an old `native/iroha_js_host.node`. The publisher intentionally rejects
that binary-only state. Remove that unverified leftover and rerun
`npm run build:native`; never manufacture a replacement checksum by hand.

The registry tarball intentionally contains no platform-specific `.node`
binary, Cargo workspace, install hook, or implicit downloader. Consequently,
`npm run build:native` is a source-checkout command, not a supported operation
inside a clean registry installation. Canonical account admission and instruction
frame/archive APIs require the native Rust codec in Node.js and are unavailable
in browsers. Browser HTTP clients, local cryptography, and portable data helpers
remain available where they do not require native account or instruction admission.
Node applications that use native APIs must
provide a separately built and checksum-verified host through
`IROHA_JS_NATIVE_DIR` before the first native-dependent call. The verified host
surface is then captured as an immutable runtime dependency; later environment
changes and mutable `globalThis` overrides cannot retarget it. The registry
publishes one executable tree, `dist/`; development
`src/` and `scripts/` copies stay in the source checkout. The registry artifact includes only
two portable, offline examples: `recipes/iso_bridge_builder.mjs` and
`recipes/nexus_app_transfer.mjs`. The wider recipe catalog is kept in the
source repository where its native and live-service prerequisites are
available.

`build:dist` publishes the JavaScript source tree. `prepack` builds that tree,
and `test:pack-install` verifies exact source/distribution parity and the package's
portable public imports. Native codec qualification separately requires a built
and verified Rust host.

When publishing or testing the packaged layout, build the ESM dist tree:

```bash
npm run build:dist
```

The checked-in `dist` tree is the input for local `file:` consumers. Dependency
installation does not rebuild or mutate the SDK checkout. `build:dist` uses an
inter-process lock, validates a staging tree, and publishes only when source and
distribution content differ, so explicit concurrent builds are deterministic.

Native bindings load only after verifying the platform-specific SHA-256 recorded
in `native/iroha_js_host.checksums.json`. When a binding is present but its
checksum is missing or mismatched, native access fails closed; it never falls
back around a present-but-unverified binary. The loader authenticates the
complete manifest, then loads a private, read-only, content-addressed snapshot
of the exact bytes it hashed so replacing the original path cannot race module
loading. Darwin manifests additionally bind a signing-identity-independent
Mach-O digest. It excludes only the final embedded signature and its mutable
`__LINKEDIT` size fields, allowing Electron or App Store distribution signing
while continuing to reject any change to loadable code or other commands;
macOS still validates the embedded signature when the snapshot is loaded. Run
`npm run build:native` explicitly from a source checkout after
installing the Rust toolchain. Set `IROHA_JS_NATIVE_DIR` only to a separately
verified native artifact directory.

## Native SoraFS Reference Validation

The repository SoraFS qualification runner pins
`IROHA_JS_NATIVE_BUILD_PROFILE=release` for its authenticated ABI-29 host
artifact. Plain source-checkout builds remain `debug` unless the profile is
selected explicitly.

SoraFS orderbook validation is available from the package root and from
`@iroha/iroha-js/sorafs`. Use `validateOrderbookPayload(kind, bytes, options)`
with Norito-encoded orderbook bytes and a kind such as `order-request`,
`trade-event`, or `settlement-receipt`; it returns the canonical
`ValidationOutcomeV1` JSON shape from the Rust reference validator.
Use `signOrderbookPayload(kind, bytes, privateKey)` to sign already encoded
`order-request`, `order-cancel`, or `settlement-receipt` bytes with a runtime
Ed25519 private key before submitting them to Torii orderbook routes.
Use `buildSignedOrderbookOrderRequest(fields, privateKey)`,
`buildSignedOrderbookOrderCancel(fields, privateKey)`, or
`buildSignedOrderbookSettlementReceipt(fields, privateKey)` when callers have
field values instead of pre-encoded Norito payload bytes. The builders accept
only the documented camelCase field names, encode canonical Norito bytes, attach the
Ed25519 payload signature, and return bytes ready for validation or embedding
in the corresponding native orderbook instruction. Torii orderbook mutation
routes accept only a full caller-signed transaction containing that one native
instruction; they do not accept raw orderbook payload bytes. Monetary fields
use unit-free XOR names such as `pricePerGib`,
`xorDebited`, `providerCredit`, and `feeAmount`. Their values must be canonical,
non-negative decimal strings with at most nine fractional digits and a mantissa
no greater than 2^511 - 1. JSON numbers, BigInts, exponents, signed or padded
spellings, trailing fractional zeros, duplicate camelCase/snake_case fields,
and the retired micro-XOR names are rejected rather than coerced.
`SORAFS_ORDERBOOK_PAYLOAD_KINDS` exports the stable kind labels for callers that
prefer constants over string literals.

PDP reference validation uses the same native bridge. Use
`validatePdpPayload(kind, bytes, options)` for one commitment, challenge, or
proof, `validatePdpCommitmentChallenge(...)` or
`validatePdpChallengeProof(...)` for pair binding, and
`validatePdpBundle(...)` for the full commitment/challenge/proof set.
`SORAFS_PDP_PAYLOAD_KINDS` exports stable kind labels. All SoraFS reference
validator options use the exact TypeScript camelCase names; snake_case option
aliases and alternate `payload`/`noritoBytes` byte fields are rejected before
native dispatch. Fixture-bundle and Governance DAG block entries use `bytes`.

## Petal Stream optical transport

`@iroha/iroha-js/petal` is Petal Stream, the animated optical transport used to
hand over a payload (for example a KAGEMUSHA `IPM1` peer message) from one
screen to a camera. Each square frame shows four sakura-blossom finders, a
`天`-shaped field of 256 tiles and three dotted rings. Tile polarity (lane `P`),
the katakana in each tile (lane `K`) and the ring dots (lane `D`) are three
independent Reed-Solomon codewords carrying fountain-coded 16-byte atoms, so any
readable lane of any frame helps and lost frames only cost time.

The module is a port of the `iroha_petal` Rust reference: the encoder is
bit-exact and the decoder follows the reference step by step. It is pure
JavaScript on typed arrays, with no Node built-ins, WebAssembly or dependencies,
and runs in browsers, Node and React Native-like engines.

```js
import {
  PetalCameraScanner,
  PetalStreamEncoder,
  PetalStreamPlayer,
} from "@iroha/iroha-js/petal";

// Sender: animate the frames on a canvas.
const encoder = new PetalStreamEncoder(payloadBytes, /* kind */ 2);
const player = new PetalStreamPlayer({
  encoder,
  context: canvas.getContext("2d"),
  fps: 8,
});
player.start();

// Receiver: read frames from the camera until the payload is complete.
const stream = await navigator.mediaDevices.getUserMedia({
  video: { facingMode: "environment", width: { ideal: 1280 }, height: { ideal: 720 } },
});
const scanner = new PetalCameraScanner({
  stream,
  // `stats.inferred` grows while a corner blossom is hidden (a thumb, a glare)
  onProgress: ({ progress }, stats) => render(progress.rank, progress.sourceAtoms, stats),
  onComplete: ({ meta, payload }) => accept(meta.kind, payload),
});
await scanner.start();
```

`PetalCameraScanner` grabs frames with `requestVideoFrameCallback` (falling back
to `requestAnimationFrame`), downsizes them to at most 1280 pixels on the long
side, converts them to Rec. 601 luma and feeds a `PetalScanSession`, which
applies the reference idle (30 s) and absolute (180 s) timeouts. Once a frame
decoded, the session reads the next ones by tracking the code from its pose
(no finder search) while that pose is at most 500 ms old, and falls back to a
full decode when tracking fails. A code whose corner blossom is hidden by a
thumb, a glare or the edge of the frame still reads: the fourth corner is
inferred from the other three and refined against the rings
(`frame.inferredCorner` names it; `stats().tracked` and `stats().inferred`
count both cases). Apps with their own camera pipeline can call
`session.push(luma, nowMs)` directly with a `PetalLuma` built by
`PetalLuma.fromStrided` (a camera Y plane), `PetalLuma.fromRgba` or
`PetalLuma.fromImageData`. Lower-level pieces are exported as well:
`decodePetalFrame`, `decodePetalFrameAt` and `trackPetalFrame`, the finder
search (`locate`, `locateCandidates`, `selectTriple`, `followFinder`), the
software `renderPetalFrame` (RGBA output, ready for `ImageData`), the vector
`petalDrawList` and `drawPetalFrame`, `PetalStreamAssembler`, the lane codecs
(`encodeLane`, `decodeLane`, `PetalFrameCells`), `PetalReedSolomon`, the
fountain code (`maskWords`, `encodeAtom`, `PetalFountainDecoder`) and `crc32c`.
A reassembled payload is only delivered after its CRC-32C matches the beacon;
it carries no authentication of its own.

The decoder reads the tile lanes (`P` and `K`) against the light and dark levels
measured at the finders first. A lane that does not decode that way is re-read
with a normalised read that rescales every tile by its own contrast, so
over-exposure, veiling light and shadows cost little (a deep glare still defeats
every lane in the frames it covers); lane `K` still needs a camera that resolves
the glyphs, and lane `D` carries the stream alone when nothing else reads. The
scanner does not change the camera's settings, so set the stream up for it
(`specs/petal_stream.md` section 8, "Scanner guidance"):

- Ask `getUserMedia` for about 1280×720; the default `maxSide` of 1280 already
  matches it. Only drop to 640 when the device cannot sustain about 5 decoded
  frames per second, because at 480p only lanes `P` and `D` read.
- Automatic exposure over-exposes a mostly black screen. Where the browser
  supports it, apply an exposure compensation of about -1 EV to the video track
  once the stream is open (Chrome on Android exposes it; feature-detect with
  `track.getCapabilities()`):

```js
const [track] = stream.getVideoTracks();
if (track.getCapabilities?.().exposureCompensation) {
  await track.applyConstraints({ advanced: [{ exposureCompensation: -1 }] });
}
```

`test/petal.test.js` checks the shared fixtures in `fixtures/petal/`
(`petal_stream_v1.json`, and the golden camera captures and tracking pairs in
`petal_captures_v1.json`) and ports the reference unit tests; run it on its own
with `node --test test/petal.test.js`.

## Atomic private settlement transport

`@iroha/iroha-js/atomic-private-settlement` is a browser-safe, witness-free
transport for the V1 private settlement routes. A native wallet or coordinator
must prepare the exact JSON object; JavaScript does not accept note witnesses,
capsule plaintext, spending keys, or a generic proof callback:

```js
import {
  AtomicPrivateSettlementOperationV1,
  AtomicPrivateSettlementPreparedRequestV1,
  AtomicPrivateSettlementToriiClientV1,
} from "@iroha/iroha-js/atomic-private-settlement";

const settlement = new AtomicPrivateSettlementToriiClientV1(toriiUrl, {
  sponsorHeaderProvider: (request) => sponsorSigner.headersFor(request),
});
const prepared = new AtomicPrivateSettlementPreparedRequestV1(
  AtomicPrivateSettlementOperationV1.LEG_UPLOAD,
  nativeCoordinator.preparedLegUploadJson(),
);

try {
  const response = await settlement.uploadLeg(prepared);
  try {
    nativeCoordinator.acceptToriiResponse(response.bytes());
  } finally {
    response.close();
  }
} finally {
  prepared.close();
}
```

Sponsor operations require exactly the canonical account-header quartet.
Committee proof reads require an exact validator role-header provider; capsule
reads and approvals require an exact governed auditor provider. Public bundle
status and receipt reads carry no caller identity. The client sends each exact
route once with redirects, credentials, ambient authorization, compression,
and retries disabled. It rejects header collisions, response URL substitution,
unknown public fields, malformed identifiers, and oversized responses, and it
never renders request or response bodies in errors.

This transport does not activate the protocol or establish production
readiness. Operators must keep the feature governed and disabled until the
deployment has passed the real-process, leakage, performance, independent
cryptographic-review, and artifact-publication gates.

## Native Privacy Bridge

The first-release native catalog surface exposes local build metadata:
`isPrivacyNativeAvailable()` and `privacyCompiledProfileCatalogV1()`. The
latter returns this binary's canonical Norito
`PrivacyCompiledProfileCatalogV1` archive. It intentionally contains no
committed height, consensus policy, activation, or readiness projection and
cannot authorize a network operation. Import
`getPrivacyExact12CapabilityManifestV1` from
`@iroha/iroha-js/privacy-capabilities` to fetch Torii's canonical Norito
manifest through the Node/N-API client with an HTTPS origin and immutable
`LocalSigningContext`. Explicit custom fetch implementations are trusted transport
dependencies and must preserve HTTPS authentication, response URL, and redirect semantics.
Public archive decoding is inspection-only; copying or re-decoding transport
bytes loses admission authority. The authenticated ABI29 binding applies
the bounded canonical decoder; transaction construction must then call
`requirePrivacyExact12CapabilityAdmissionV1`, which requires committed Active
state, registered production qualification, and byte-exact equality with the
selected local compiled-profile row and deployment network. The admission result
retains that exact network and Torii origin. There is no browser, JSON snapshot, or
mock authorization fallback. The generic
request/build/verify dispatcher and its free-form algorithm aliases do not
exist; proving is exposed only by protocol-specific typed APIs.

`buildKaigiAuthorizationProofV1()` consumes a mutable, canonical nonzero Pasta
Fp blinding and returns raw 32-byte commitment, nullifier, authorization, and
pre-roster-root buffers plus the canonical proof envelope. Its required context
is a typed deployment `NetworkId`, canonical call domain/name, full original host
and participant `AccountId` values, an exact `bigint` participation sequence,
one of `hostCreate`, `join`, `leave`, or `hostEnd`, and the exact pre-state root.
The blinding buffer is cleared on success and rejection; callers must keep any
separate copies under their own secret-lifetime policy. This API requires the
native prover, which verifies the generated envelope through the canonical Core
backend before returning it. Browser calls clear a supplied mutable blinding
and fail closed.

`buildKaigiUsageProofV1()` proves billing with that same host opening. Supply the
typed `networkId`, canonical `callId` and original `hostId`, exact current
`preRosterRoot`, the ledger's `segmentIndex` as an integer from zero through
`2^32 - 1`, positive `durationMs` and unsigned `billedGas` as `bigint` u64 values,
the stored raw `hostCommitment`, and mutable `blinding` bytes. It rejects an
opening that does not match the stored host C before proving, and returns
`{ hostCommitment, usageCommitment, preRosterRoot, proof }` only after Core verifies
the final 25-row usage relation. The supplied blinding is cleared on every call.
Use `usageCommitment` and `proof` in `buildRecordKaigiUsageInstruction` with those
same public metrics. Native authorization and usage cache only each fixed
circuit's public proving material; caller secrets remain owned by the invocation.

Pass `{ commitment: result.commitment }` and `{ digest: result.nullifier }` into
the matching Kaigi instruction builder. These values use raw canonical Pasta
field bytes, including in the Norito JSON byte-array representation. The signed
transaction identifies the participant; a proof binds its opening to the
retained original account and current action, while ledger validation enforces
membership and rekey lineage. Local proof construction alone does not establish
network admission or production qualification.

Private Kaigi entrypoint builders require a caller-supplied `feeSpend` produced
by a production confidential wallet or prover. The JavaScript SDK does not
synthesize a fee spend from an action hash, amount, and verifier key because
those values do not include the spend key, input-note witnesses, Merkle path,
or output-note witnesses required for a valid confidential transfer. The
`ConfidentialProver` creates local proof artifacts when the caller supplies
complete witness material; it is not an automatic Private Kaigi fee-spend adapter.

For local wallet proving, use `ConfidentialProver` with a network, canonical asset
ID and mutable 32-byte spend key. `proveTransfer()` and `proveRedemption()` select
the canonical circuit and key in Core and verify the generated proof before
resolving their promises. Native proof work runs off the JavaScript thread.
Full redemption omits `change`; partial redemption supplies one exact
change note. Supply `rootHex`, `treeCommitments` and the actual `inputs` from your
authenticated wallet snapshot. No dummy note, circuit ID or verifying-key record
is needed.

```js
import { ConfidentialProver } from "@iroha/iroha-js";

const prover = new ConfidentialProver({ networkId, assetDefinitionId, spendKey });
try {
  const proof = await prover.proveRedemption({
    rootHex, treeCommitments, inputs, publicAmount: 42n,
  });
  // A local proof is not ledger authorization; use an implemented protocol's admission path.
} finally {
  prover.dispose(); // clears its owned key copy; the caller owns the original spendKey
}
```

`ConfidentialProverError.code` distinguishes `INVALID_INPUT`, `NATIVE_UNAVAILABLE`,
`PROVING_FAILED` and `DISPOSED`. Use bigint or exact decimal strings for amounts
outside JavaScript's safe integer range. Disposing prevents new work and clears
the wallet's key; an already queued job owns its inputs and finishes independently.
Note openings expressed as JavaScript
strings remain managed by the JavaScript runtime; this API does not promise
secure erasure of those strings. The native runtime must be rebuilt from the
current source to expose these wallet methods.

Persist the private change opening securely before proving. Redemption change
belongs to the spender's native default diversifier, which may differ from the
input note's diversifier. After the change commitment has an authenticated leaf
index, use `confidentialChangeToInput(retainedChange, authenticatedLeafIndex)` to
create a later spend input. `defaultConfidentialDiversifier()` exposes the same
Core value for commitment derivation; callers do not need to encode a scalar.
The conversion leaves the source opening available to the caller and does not
authenticate its index, create a ledger note, or prove membership.

Use `await computeConfidentialRoot({ commitments })` to check a local history
with the native fixed-depth Merkle implementation. It accepts zero through
65,536 canonical commitments and runs off the JavaScript thread. Computing a
root does not authenticate it against ledger state. The source-only
[`confidential_redemption.mjs`](recipes/confidential_redemption.mjs) recipe uses
OS randomness and these public APIs to generate and locally verify a real proof;
it creates no ledger note and submits no transaction. After rebuilding the
verified native addon, run `node recipes/confidential_redemption.mjs`.

The source-only [`confidential_change_redemption.mjs`](recipes/confidential_change_redemption.mjs)
recipe retains a change opening, proves partial redemption, converts that change
with its native default diversifier, and spends it in a second locally verified
proof. It imports the public package entrypoint and checks event-loop progress
and completion after disposal. After `npm run build:native && npm run build:dist`,
run `node recipes/confidential_change_redemption.mjs`. Its constructed history is
only a disposable fixture, not authenticated ledger state.

Confidential wallet proofs take one or two actual input notes. Transfers take
one or two output notes; redemption accepts one change note when a remainder exists. The SDK
checks these counts and the 65,536-leaf tree capacity before native proving.
Supply only the actual inputs, including when spending the final leaf of a full
tree: the native prover supplies any absent second input internally. These APIs
derive membership paths from `treeCommitments`; path-based proving is currently
available through Core's Rust API.

`PRIVACY_PROTOCOL_IDS_V1` is the closed registry of exactly twelve identities,
in wire order: `zk-ace-pq-authorization-v1`,
`anonymous-pgc-k-out-of-n-v1`, `verange-transparent-range-v1`,
`iroha-zk-ams-v1`, `vega-existing-credential-zk-v1`,
`iroha-zk-x509-stark-p256-v1`,
`iroha-jindo-polynomial-commitment-v1`,
`iroha-bootle-lantern-anoncred-v1`, `orchard-halo2-actions-v1`,
`monero-fcmp-plus-plus-v1`, `iroha-ivm-private-note-stark-v1`, and
`pq-masp-stark-v1`. Each manifest row has exactly `protocol_id`,
`operation_schema`, `execution_mode`, `privacy_feature_mask`,
`compiled_profile`, `readiness`, and `activation`. Unknown fields, aliases,
duplicates, case-folded labels, and whitespace-normalized labels fail closed.

> **ESM-only:** The package ships as pure ESM. Use dynamic `import()` from
> CommonJS (`const { ToriiClient } = await import("@iroha/iroha-js/torii");`)
> when migrating existing CJS callers.

Common subpath imports for lighter bundling (ESM):

```js
import { ToriiClient } from "@iroha/iroha-js/torii";
import { noritoEncodeInstruction } from "@iroha/iroha-js/norito";
import { generateKeyPair } from "@iroha/iroha-js/crypto";
```

Every instruction codec operation and local signing context requires the deployment’s
explicit `networkPrefix` (an integer in `0..65535`, `369` for Taira). Obtain it
from the selected deployment alongside its exact `NetworkId`; there is no
implicit network default. Decoders take `(bytes, networkPrefix, options)`.

### External transaction signing

Use `@iroha/iroha-js/transaction-codec` in a Node runtime with the verified
native account owner to build and finalize canonical transparent transfers.
Account admission for this surface is unavailable in browsers. It supports one
`Transfer::Asset` instruction, single-key Ed25519 I105 authorities, canonical
asset identifiers, and accounts sharing one network prefix/chain discriminant.
Every ordinary transaction carries a nominal `NetworkId`: the exact marked
32-byte genesis-header hash, rendered as a canonical checksummed Iroha hash
literal. Human-readable `chain`, `chainId`, and `chain_id` transaction fields
are rejected; they are not aliases for this consensus identity.

```js
import { NetworkId } from "@iroha/iroha-js";
import {
  browserTransactionPayloadHashHex,
  buildBrowserTransferPayload,
  finalizeBrowserSignedTransaction,
} from "@iroha/iroha-js/transaction-codec";

const networkId = NetworkId.parse(
  "hash:32C903E5B3497E34C2B844EBFE8A39C19E6CF8F95D44C1FFB8BA9DCB42F91149#A2F0",
);
const payloadBytes = buildBrowserTransferPayload({
  networkId,
  authority,
  sourceAssetHoldingId: `${assetDefinitionId}#${authority}`,
  quantity: "1.25",
  destinationAccountId,
  feePayment: quotedFeePayment, // exact ergonomic intent supplied by the app quote flow
  metadata: { memo: "wallet transfer" },
  creationTimeMs: Date.now(),
  ttlMs: 30_000,
  nonce: 42,
  networkPrefix,
});

// Sign the exact 32-byte Iroha prehash, not the payload bytes or hex text.
const payloadHashHex = browserTransactionPayloadHashHex(payloadBytes, networkPrefix);
const payloadHash = Uint8Array.from(
  payloadHashHex.match(/../g),
  (octet) => Number.parseInt(octet, 16),
);
const signature = await wallet.signEd25519(payloadHash);

const finalized = finalizeBrowserSignedTransaction(
  {
    networkId,
    payloadBytes,
    payloadHashHex,
    authority,
    signingPublicKey: wallet.publicKey,
    signatureAlgorithm: "ed25519",
  },
  { algorithm: "ed25519", signature },
  wallet.publicKey,
);

console.log(finalized.hashHex, finalized.signedTransaction);
```

Finalization fails closed when the payload's exact `NetworkId`, asserted
prehash, authority, signing key, signature, metadata limits, or canonical
Norito framing disagree. The expected `networkId` is a nominal `NetworkId`
object supplied by the application; a string, byte array, human chain label,
foreign NetworkId, or genesis-domain payload is never normalized or accepted.
Ed25519 verification uses the same strict, uncofactored equation as the Rust
node and rejects ZIP-215/mixed-torsion aliases. Metadata arrays must be dense
plain arrays containing data elements only; metadata numbers must be safe
integers (encode decimal values as strings), and all strings must contain
well-formed Unicode scalar values. Metadata supplied as a JSON string must
already use the exact canonical encoding; use an object when canonicalization
is desired. Transfer quantities use positive plain-decimal syntax, at most 28
fractional digits, and the current Rust 64-byte signed-integer positive range
(`2^511 - 1`).
The codec only returns verified bytes and the canonical compact-entrypoint
pipeline hash: importing it does not enable Nexus, connect a wallet, submit to
Torii, or turn on live-send behavior. Applications must authorize and perform
those steps separately.

### Fee quotes and sponsor programs

All transaction builders require a typed `feePayment`. For live submission,
use the guided quote flow instead of inventing charge maxima:

```js
import {
  LocalSigningContext,
  NetworkId,
  ToriiClient,
  buildTransferAssetInstruction,
  quoteAndSignTransaction,
} from "@iroha/iroha-js";

const torii = new ToriiClient(toriiUrl);
const requestedFeePayment = {
  payer: "sponsor",
  programId: `${sponsorAccountId}/wallet_payments`,
  programRevision: 3,
  chargeLimits: [],
};
const canonicalAuth = { accountId: authority, privateKey };

const program = await torii.findFeeSponsorProgramById(
  requestedFeePayment.programId,
  { canonicalAuth },
);
if (program?.lifecycle.state !== "active") throw new Error("sponsor is not active");

const signed = await quoteAndSignTransaction(
  torii,
  {
    networkId,
    authority,
    instructions: [buildTransferAssetInstruction({
      sourceAssetHoldingId,
      destinationAccountId,
      quantity: "1",
    })],
    feePayment: requestedFeePayment,
    privateKey,
  },
  { canonicalAuth },
);
console.log(signed.quote.intent, signed.hash.toString("hex"));
```

`quoteAndSignTransaction` freezes the exact unsigned payload, account-signs
`POST /v1/fees/quote`, verifies that the returned intent retained the payer,
exact program/revision, and gas bound, and rejects any quote whose components,
debit decision, or exact sponsor-capacity evidence is inconsistent. This check
also runs for injected client implementations before the helper replaces only
`fee_payment` and signs.
Contract/IVM drafts require a positive `gasLimit`. The metadata keys
`fee_sponsor`, `gas_asset_id`, and `gas_limit` are retired and rejected, and a
sponsor rejection never falls back to the authority.

In standalone encoding examples below, `feePayment` denotes an already quoted
ergonomic intent with canonical charge limits.

### Mixed instruction and contract-call batches

Use `buildExecutableBatchTransaction` when one atomic transaction must
interleave native ISIs and deployed-contract calls. Entries execute in the
exact array order, and any contract call requires a positive signature-bound
`feePayment.gasLimit`. Empty batches and noncanonical contract addresses are
rejected before native or browser signing; addresses must use lowercase V1
Bech32m.

```js
import {
  buildExecutableBatchTransaction,
  buildTransferAssetInstruction,
} from "@iroha/iroha-js";

const mixed = buildExecutableBatchTransaction({
  networkId,
  authority,
  entries: [
    {
      kind: "instruction",
      instruction: buildTransferAssetInstruction(transferInput),
    },
    {
      kind: "contractCall",
      contractAddress,
      expectedCodeHash, // exact marked 32-byte hash (bytes or 64 hex digits)
      entrypoint: "settle",
      arguments: canonicalArgumentRecord, // optional, at most 1 MiB
    },
  ],
  feePayment: { ...quotedFeePayment, gasLimit: 100_000 },
  privateKey,
});
```

For external signing with the native account owner, pass the same ordered `entries` shape to
`buildBrowserExecutableBatchPayload`, then use
`validateBrowserExecutableBatchSignable` and
`finalizeBrowserExecutableBatchTransaction`. Keep using `buildTransaction` or
`buildBrowserInstructionTransactionPayload` for instruction-only transactions;
those APIs use the canonical `Executable::Instructions` wire tag.

The `@iroha/iroha-js/nexus-app` browser export contains no native binding or
`node:` imports. It retains bounded transport and hashing; transaction building,
Connect account admission, and account-dependent finalization require the Node
runtime with the native account owner. Supplying `toriiBaseUrl` gives
the facade a bounded Fetch-based pipeline submit/status client; applications
may instead inject `toriiClient` and `transactionCodec`. Torii response bodies
are capped at 64 KiB, submission requests time out after 15 seconds, polling
defaults to a 30-second budget, and credentials/query/fragment components are
rejected in the configured Torii base URL. Request and polling deadlines cover
headers, response-body reads/cancellation, and asynchronous status callbacks.
Requests omit ambient credentials and referrers and reject redirects.

The built-in Connect path keeps session proof keys separate from transaction
signing keys. With the native account owner, Connect verifies the approval proof and returns its
`accountId`, 32-byte X25519 `walletPublicKey`, and 64-byte `signature`.
`walletPublicKey` authenticates the Connect session proof; it is not the
Ed25519 transaction key. Each approval consumer receives an immutable wrapper
with detached proof-byte copies, so one consumer cannot rewrite verified state
seen by another. On this built-in path, `NexusAppClient.awaitApproval()` accepts
only that exact data-only `Uint8Array` proof shape, projects `accountId` into the
Nexus approval state, and derives the Ed25519 controller key from the canonical
I105 account. An injected `connectTransport.awaitApproval` instead returns the
custom `{accountId, signingPublicKey?}` approval shape and must not forward the
browser proof's `walletPublicKey`, `signature`, or a replacement `session`.
The facade enriches a copy of the exact caller session after binding the
approval key to the account's Ed25519 controller. For
`finalizeAndSubmit(..., { wait: true, signal })`, an already-aborted signal is
rejected before finalization, and the signal is checked again after
finalization and capability capture but before Torii submission. Wait-enabled
injected Torii clients must provide `waitForTransactionStatus`; the facade
enforces the wait signal and deadline even if that client does not. Retry logic
must inspect both `code` and `submissionState`: `operation_aborted` with
`not_submitted` was stopped before dispatch; `submission_outcome_unknown` with
`unknown` may already have reached Torii and includes
`signedTransactionHashHex` for reconciliation; `invalid_submission_response`,
`transaction_rejected`, `status_wait_aborted`, `status_wait_timeout`, and
`status_wait_failed` with `submitted` refer to a transaction whose submit call
resolved and may also expose the exact `submission` value. Do not automatically
retry an `unknown` or `submitted` outcome. This cancellation behavior is scoped
to status-waiting submissions; `wait: false` must omit `signal` and every other
status-only polling option. See `recipes/nexus_app_transfer.mjs` for an offline,
canonical end-to-end example.
Finality policy is fixed; success, failure, and terminal status iterables are
not accepted. Only global, state-resolved `Applied` succeeds; `Rejected` and
`Expired` fail, while all other status observations remain pending.

When supplying a custom `transactionCodec` to `NexusAppClient`, payload hash
aliases must be exact lowercase 64-character hex and must match the returned
payload bytes. Finalization must return canonical version-1, single-signature
`Transfer::Asset` bytes plus the exact compact-entrypoint hash. Before any
submission, the facade independently finalizes and hashes those bytes with the
transaction codec with native account admission, rejects conflicting byte/hash
aliases, and rechecks the signable payload prehash. Torii response hash aliases are likewise conflict-checked
before status polling or receipt construction.

 Kotodama V1 uses the Rust compiler as its only implementation. Node loads it
through `iroha_js_host` and performs compilation off the event-loop thread:

```js
import { compileKotodamaProgram } from "@iroha/iroha-js/kotodama-compiler";

const result = await compileKotodamaProgram(source);
```

Pass a bounded logical path to preserve useful file names in diagnostics and
sidecars. ZK contracts must explicitly select the canonical ZK policy; this is
the only compiler feature policy exposed by the adapter:

```js
const result = await compileKotodamaProgram(source, {
  sourceName: "contracts/private_transfer.ko",
  zk: true,
});
```

Pass `sources` for explicitly named companion files. The compiler resolves `include`
and `import` relative to their referring file while preserving each file in diagnostics:

```js
const result = await compileKotodamaProgram(
  'seiyaku App { include "parts/view.ko"; import "math.ko" as arith; }',
  {
    sourceName: "app.ko",
    sources: [
      { sourceName: "parts/view.ko", source: "view fn value() -> int { return arith::double(value: 3); }" },
      { sourceName: "math.ko", source: "module Math { export fn double(int value) -> int { return value * 2; } }" },
    ],
  },
);
```

Source paths stay inside their source root. Each file is bounded to 1 MiB; a
complete inventory permits 512 files and 16 MiB. Immutable locked dependencies
can be supplied with `imports: [{ alias, package }]` and
`packages: [{ identity, modules, sources, artifacts, exports, imports }]`; package
paths are relative to that package's root. Compiled contract imports use complete
`.to` bytes in `artifacts: [{ sourceName, artifact }]`, where `artifact` is an
array of bytes. Root and package artifacts belong to their respective immutable
inventories and count toward the shared file and byte limits. Compilation
performs no file or network discovery. The native and remote adapters use the
same request shape.

The browser export has no compiler implementation. It requires an explicit
canonical Rust compiler-service endpoint:

```js
import { compileKotodamaProgram } from "@iroha/iroha-js/kotodama-compiler";

const result = await compileKotodamaProgram(source, {
  compilerUrl: "https://compiler.example",
  sourceName: "contracts/payment.ko",
  zk: false,
});

if (!result.ok) {
  for (const diagnostic of result.diagnostics) {
    console.error(diagnostic.code, diagnostic.primary_span, diagnostic.message);
  }
} else {
  console.log(result.output.codeHashHex);
  console.log(result.output.manifest);
}
```

Offline browser compilation is intentionally unsupported so browser and Node
artifacts cannot drift from the canonical Rust compiler. Remote compiler
services must use HTTPS; loopback HTTP is accepted for local development. The
service receives the complete source, so use only an endpoint you trust. Node
and browser adapters reject source larger than the canonical 1 MiB UTF-8 limit
before invoking the native binding or making a network request.
Validated service URLs and Fetch implementations are kept in immutable private
client state, so later property mutation cannot redirect source. Responses must
be HTTP 200 with exact `application/json`, absent/identity content encoding, and
consistent byte framing. Successful artifacts are bounded to the ledger's exact
1 MiB post-header IVM code-memory limit and must carry canonical IVM 1.1/ABI-1
metadata, a checksummed CNTR Norito interface whose identity/capabilities and
collection counts match the manifest, ordered callable roots with bounded frames
and exact role vectors for the 8,192-word tables, fully framed ABI-1 indexed
literals, and a non-empty word-aligned instruction stream. These JavaScript framing checks do
not replace Rust instruction decoding or its control-flow, syscall, entrypoint,
access-claim, and other semantic admission checks. The service must therefore be
a trusted canonical Rust compiler endpoint; the ledger remains the final
authority on whether an artifact is deployable.

Source-map entries carry `source_kind: "function" | "statement"` and partition
each physical function's budget range. Inlined statements retain their original
helper names and source locations. Diagnostics preserve canonical English fields,
required `alternative_fixes`, and nullable `localized` presentation text.

Browser deployment performs those bounded structural checks before node
capability/state reads, signing, or submission. It does not expose a local
semantic-verifier selector: V1 workspace builds target Rust `std`, and browser
WebAssembly artifacts are not a supported release output. The authenticated
compiler service supplies canonical Rust output, and committed ledger admission
remains authoritative for semantic validation.
Browser deployment requires exact `networkId` explicitly. Its canonical raw
32-byte genesis identity binds every ordinary deployment transaction and is
committed directly by `deriveContractAddress(...)`, including address
derivation inside `deploySmartContractBrowser(...)`. Human-readable `chainId`
is not accepted as a contract-address security domain. `chainDiscriminant`
remains required only for strict I105 authority decoding. Every canonical V1
contract address uses the fixed lowercase `irohac` Bech32m prefix.
The first release accepts only `provenance: null`; signed provenance remains
disabled until its exact message and public-key algorithm can be verified.
The native binding and service receive the same canonical JSON-shaped request,
`{ source, artifacts, zk, sourceName?, sources?, imports?, packages? }`. The
adapter includes an empty `artifacts` array when no compiled imports are supplied.
`sourceName` is limited to 4096 UTF-8 bytes and
must not contain control characters. Unknown options—including ABI, vector,
debug-embedding, and test-mode selectors—fail closed.
Compilation failures resolve to `{ ok: false, diagnostics }` with the exact
structured Rust diagnostics; network, service, and malformed-response failures
reject the promise. A compiler service returns both successful and failed
compiler result envelopes with HTTP 200; non-success HTTP statuses are reserved
for service and transport failures.

This one-source API emits one deployable contract. Typed module graphs use the
project drivers behind `koto build` and `musubi build`; the JavaScript
adapter does not rewrite or flatten modules.
Kotodama V1 source keeps its branded declaration spellings: deployable units
use `seiyaku`/`誓約`, public calls use `kotoage`/`言挙げ`, and lifecycle hooks use
`hajimari`/`始まり` and `kaizen`/`改善`. The English source spellings `contract`,
`entry`, `init`, and `upgrade` are rejected by the canonical Rust parser.

For browser-only Connect bootstrap without importing the Node-first `ToriiClient`
surface, use the dedicated browser subpath:

```js
import {
  createConnectSessionPreview,
  registerConnectSession,
  resolveConnectLaunchUri,
  openConnectWebSocket,
} from "@iroha/iroha-js/connect-browser";
import { NetworkId } from "@iroha/iroha-js/browser";

const networkId = NetworkId.parse(window.IROHA_NETWORK_ID);
const preview = createConnectSessionPreview({
  networkId,
  node: "https://taira.sora.org",
});

const session = await registerConnectSession("https://taira.sora.org", preview, {
  node: "https://taira.sora.org",
});

const walletUri = resolveConnectLaunchUri("wallet", preview, session);
// Launch IrohaConnect with the canonical one-time wallet URI from Torii.
window.location.href = walletUri;

const socket = openConnectWebSocket(
  "https://taira.sora.org",
  preview.sidBase64Url,
  session.token_app,
  "app",
  { protocols: ["iroha-connect"] },
);
```

Use the Torii session response (`wallet_uri` / `app_uri`) for launch once the
session is registered. The preview URIs are tokenless bootstrap hints and now
mirror Torii's role-based `iroha://connect?...&role=...` shape so wallet and
app launchers stay consistent.

If Torii sits behind nginx or another reverse proxy, `/v1/connect/ws` must
forward websocket upgrade headers (`Connection: Upgrade`, `Upgrade: websocket`)
to the upstream node or browser Connect joins will fail with `400 Bad Request`.

To authenticate Torii canonical JSON requests with the wallet-approved account,
request the `sign_raw` method explicitly and scope it to the fixed canonical
request domain. The wallet is the permission enforcement boundary: it should
reject raw-sign prompts when this method/resource pair was not granted.

```js
import {
  TORII_CANONICAL_REQUEST_DOMAIN_TAG,
  createConnectAppSession,
  createConnectCanonicalRequestAuth,
} from "@iroha/iroha-js/connect-browser";
import { ToriiBrowserClient } from "@iroha/iroha-js/torii-browser";

const appSession = createConnectAppSession({
  baseUrl: "https://taira.sora.org",
  preview,
  session,
  appMeta: { name: "My dApp", url: window.location.origin },
  permissions: {
    methods: ["sign_raw"],
    resources: [TORII_CANONICAL_REQUEST_DOMAIN_TAG],
  },
});
const canonicalAuth = await createConnectCanonicalRequestAuth(appSession);
const torii = new ToriiBrowserClient("https://taira.sora.org");
const multisigSpec = await torii.getMultisigSpec(
  { multisigAccountId: canonicalAuth.authAccountId },
  canonicalAuth,
);
```

The same browser client exposes the ledger evidence routes without converting
their proof payload into an untyped JSON transport. `getLedgerBlockProof()`
requires Torii's canonical `application/x-norito` response, validates and
decodes the exact `BlockProofs` schema, and returns data that can be checked
locally:

```js
import {
  ToriiBrowserClient,
  verifyBlockProofs,
} from "@iroha/iroha-js/browser";

const torii = new ToriiBrowserClient("https://taira.sora.org");
const proofs = await torii.getLedgerBlockProof(blockHeight, transactionHash);
// Obtain this from the application's authenticated block/finality verifier,
// never from the same Torii proof response.
const trustedAnchor = authenticatedLedger.blockProofAnchor(blockHeight);
const verification = verifyBlockProofs(proofs, trustedAnchor);

if (!verification.valid) throw new Error("invalid transaction Merkle evidence");
```

The trusted anchor binds the requested entry hash and execution-order index,
the block height and hash, authenticated executed-block wire hash, and exact
`{root, leaf_count}` entry/result commitments, plus the exact FASTPQ transcript
projection from that authenticated executed block. Entry proofs use the full
executed-entrypoint tree so their indices are identical to result-proof indices.
Verification fails closed when the anchor is omitted or when Torii returns a
locally valid proof for another entry, index, or root. This SDK deliberately
exposes no helper that derives a trusted anchor from `proofs`: copying those
fields is circular evidence, not authentication. `verification.valid` means
only that the response is consistent with the independently authenticated
anchor supplied by the caller; it is not a finality verdict. Browser callers
therefore need an independently authenticated finality anchor obtained outside
the browser before calling this helper. Application Merkle leaves and
internal nodes use
distinct `iroha:merkle:leaf:v1\0` and `iroha:merkle:internal:v1\0` hash domains;
the raw transaction/result hash is passed as the proof leaf and the verifier
applies the leaf boundary itself. `getLedgerStateRoot()` and
`getLedgerStateProof()` return the same exact block header, post-state root, and
native Sumeragi finality proof. The carrier remains untrusted until a native
verifier authenticates it from an independently selected complete checkpoint.

Node callers can authenticate the finality anchor and the proof together with
the native Rust bridge. `expectedEntryHash` is the application-selected
32-byte entrypoint hash, not a value copied from the proof response:

```js
import {
  AUTHENTICATED_BLOCK_PROOFS_VERSION_V1,
  NetworkId,
  ToriiClient,
  verifyAuthenticatedBlockProofsV1,
} from "@iroha/iroha-js";

const torii = new ToriiClient("https://taira.sora.org");
const executedBlockWire = await torii.getLedgerExecutedBlockWire(blockHeight);
const verdict = await verifyAuthenticatedBlockProofsV1({
  version: AUTHENTICATED_BLOCK_PROOFS_VERSION_V1,
  networkId: NetworkId.parse(pinnedNetworkIdLiteral),
  trustedCheckpointNorito: independentlyAuthenticatedCheckpoint,
  expectedEntryHash: requestedTransactionEntrypointHash,
  finalityProofNorito,
  executedBlockWire,
  blockProofsNorito,
});

if (!verdict.valid) throw new Error(verdict.code);
```

Malformed archives and wrong-chain, wrong-context, stale, skipped, forged-QC,
or executed-wire mismatches reject the promise. Authenticated finality with a
substituted entry or invalid Merkle/result/transcript proof resolves with
`valid: false` with `checkpointNorito: null`. After `valid: true`, retain the
returned canonical `checkpointNorito` for the next verification. The complete
checkpoint carries the authenticated native prefix; `contextIdHex` is a diagnostic
digest and cannot replace it. A target proof must equal the checkpoint decision or
immediately extend it.
The canonical finality and `BlockProofs` archives are available from Torii,
and `getLedgerExecutedBlockWire(height)` fetches the exact result-bearing
`SignedBlockWire` from `/v1/ledger/block/{height}`. Torii binds the body to the
authenticated native certified history before returning it; staged, resultless, missing,
or hash-inconsistent bodies fail closed. Both the route and SDK enforce the
native verifier's 32 MiB carrier bound. Explorer/header JSON and
`/v1/blocks/stream` are not equivalent carriers.

`createConnectCanonicalRequestAuth()` passes the exact canonical request
message (including its timestamp and nonce) to `signRaw()` under
`iroha:torii:canonical-request:v1`, binds `authAccountId` to the approved
identity, and verifies the returned Ed25519 signature locally. The domain tag
is wallet policy/prompt context and is not prepended to the signed bytes.
Private keys never enter the dApp, and `signTransaction()` must not be used as
a substitute for signing canonical request bytes. A session permits only one
transaction or raw signature request in flight at a time; concurrent calls
reject with `ConnectSignRequestError` code `REQUEST_IN_FLIGHT`.

You can also use namespaced exports when you prefer grouped imports:

```js
import { Torii, Norito, Crypto } from "@iroha/iroha-js";

const torii = new Torii.ToriiClient("https://torii.example");
const encoded = Norito.noritoEncodeInstruction({ Register: { Domain: { id: "wonderland" } } }, networkPrefix);
const keys = Crypto.generateKeyPair();
```

> **Key storage:** Store Ed25519 seed material in dedicated key vaults or
> platform keystores whenever possible. The helpers shown below accept raw
> buffers for developer convenience, but production code should hydrate keys
> from secure storage and avoid logging them. Use
> `deriveConfidentialKeyset()` when building confidential workflows so all
> derived keys share the same handling guarantees.

```js
import { AccountAddress, generateKeyPair } from "@iroha/iroha-js";

const address = AccountAddress.fromAccount({
  publicKey: generateKeyPair().publicKey,
});
console.log(address.canonicalHex());
console.log(address.toI105(753));
console.log(address.toI105());

const formats = address.displayFormats(753);
console.log(formats.i105);
console.log(formats.i105Warning);
```

Every V1 controller family is deterministic and available through the verified
native address codec: `ed25519`, `secp256k1`, `ml-dsa`,
`gost3410-2012-256-paramset-a`, `gost3410-2012-256-paramset-b`,
`gost3410-2012-256-paramset-c`, `gost3410-2012-512-paramset-a`,
`gost3410-2012-512-paramset-b`, `sm2`, `bls_normal`, and `bls_small`.
There is no process-wide curve toggle. Pass exactly one of these canonical
labels; aliases and case-folded spellings are rejected before encoding.
Every constructor, canonical-byte decoder, and I105 parser requires cryptographic
admission by the Rust codec. Missing or stale native bindings fail closed, including
in browser builds; byte lengths alone never admit account identities. I105 input
must be exact, without surrounding whitespace. Constructor inputs are copied into
private state so later caller mutation cannot replace an admitted controller.

> ℹ️ When showing addresses in wallets, explorers, or SDK samples, follow the
> single-format UX checklist captured in
> [`specs/sns/address_display_guidelines.md`](../../specs/sns/address_display_guidelines.md):
> i105 remains the copy/share target, aliases should be shown as
> `name@dataspace` or `name@domain.dataspace`, and QR codes should always
> encode the i105 value.

## Subscriptions

Subscription plans are stored on asset definitions and billed by triggers. Use
`bill_for.period = "previous_period"` to charge in arrears (for example, bill
on the first for last month's usage); fixed-price plans typically bill the next
period in advance.

```js
import { ToriiClient } from "@iroha/iroha-js";

const torii = new ToriiClient("http://127.0.0.1:8080", {
  authToken: "provider-token",
});

const usagePlan = {
  provider: "<provider_account_i105>",
  billing: {
    cadence: {
      kind: "monthly_calendar",
      detail: { anchor_day: 1, anchor_time_ms: 0 },
    },
    bill_for: { period: "previous_period", value: null },
    retry_backoff_ms: 86_400_000,
    max_failures: 3,
    grace_ms: 604_800_000,
  },
  pricing: {
    kind: "usage",
    detail: {
      unit_price: "0.024",
      unit_key: "compute_ms",
      asset_definition: "usd#pay",
    },
  },
};

await torii.createSubscriptionPlan({
  authority: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  plan_id: "aws_compute#commerce",
  plan: usagePlan,
});

await torii.createSubscription({
  authority: "sorauﾛ1Ni1A1mYｲzｳﾚﾊGﾆｲgｵ4ﾜｾﾒﾔzｺﾍz6ﾀFoVDﾇXzｹCkﾙ4CQVXL",
  private_key: "subscriber-private-key-hex",
  subscription_id: "sub-001",
  plan_id: "aws_compute#commerce",
});

await torii.recordSubscriptionUsage("sub-001", {
  authority: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  unit_key: "compute_ms",
  delta: "3600000",
});

await torii.chargeSubscriptionNow("sub-001", {
  authority: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  private_key: "provider-private-key-hex",
});
```

## Multisig TTL preview and enforcement

```js
import { MultisigSpecBuilder, buildProposeMultisigInstruction } from "@iroha/iroha-js";

const spec = new MultisigSpecBuilder()
  .setQuorum(3)
  .setTransactionTtlMs(86_400_000)
  .addSignatory("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB", 2)
  .addSignatory("sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV", 1)
  .build();

// Preview the effective TTL (clamped to the policy cap) and expiry time
const preview = spec.enforceProposalTtl({ requestedTtlMs: 90_000, nowMs: Date.now() });
console.log(preview.effectiveTtlMs, preview.expiresAtMs, preview.wasCapped);

// Build a multisig proposal while enforcing the policy TTL cap client-side
const propose = buildProposeMultisigInstruction({
  accountId: "sorauﾛ1Ni1A1mYｲzｳﾚﾊGﾆｲgｵ4ﾜｾﾒﾔzｺﾍz6ﾀFoVDﾇXzｹCkﾙ4CQVXL",
  spec,
  instructions: [{ Log: { Level: "INFO", message: "hello" } }],
  transactionTtlMs: 45_000, // throws if above spec.transaction_ttl_ms
});

// Register the multisig controller with an explicit (non-derived) account id
const register = buildRegisterMultisigTransaction({
  networkId,
  feePayment,
  authority: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  accountId: "sorauﾛ1Ni1A1mYｲzｳﾚﾊGﾆｲgｵ4ﾜｾﾒﾔzｺﾍz6ﾀFoVDﾇXzｹCkﾙ4CQVXL",
  spec,
  privateKey: generateKeyPair().privateKey, // controller key is NOT used for signing
});
```

`enforceProposalTtl` rejects TTL overrides above the registered policy
(`transaction_ttl_ms`) before submitting a multisig proposal so client UX can
surface the same error Torii would return. Use `previewProposalExpiry` when you
only need a non-throwing preview for relayer TTL hints.

> Multisig controllers must never use derived keys. Supply an explicit account id in the
> signatory domain (random keys are fine; private halves should be discarded). Nodes will reject
> derived multisig ids at admission.

## ExecuteTrigger and multisig helper builders

```js
import {
  buildExecuteTriggerNorito,
  buildMultisigTriggerArgs,
  buildProposeMultisigExecuteTriggerInstruction,
  buildMultisigContractCallProposeRequest,
} from "@iroha/iroha-js";

const args = buildMultisigTriggerArgs("lifecycle", {
  action: "create",
  requestId: "mr1",
  fiId: "banka",
  toAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
  amountI64: 10,
  createdAtMs: Date.now(),
  expiresAtMs: Date.now() + 60_000,
});

// Direct ExecuteTrigger Norito bytes for the canonical multisig-critical path.
const directNorito = buildExecuteTriggerNorito("staged_mint_request_hbl", args);

// Wrap the same trigger call into a multisig proposal instruction.
const proposalInstruction = buildProposeMultisigExecuteTriggerInstruction({
  accountId: "sorauﾛ1Ni1A1mYｲzｳﾚﾊGﾆｲgｵ4ﾜｾﾒﾔzｺﾍz6ﾀFoVDﾇXzｹCkﾙ4CQVXL",
  trigger: "staged_mint_request_hbl",
  args,
  spec,
  signerAccountId: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  strictSignerCheck: true,
  transactionTtlMs: 45_000,
});

// Build the normalized Torii request body for the multisig contract-call flow.
const request = buildMultisigContractCallProposeRequest({
  multisigAccountAlias: "mintops@banka",
  signerAccountId: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
  entrypoint: "execute",
  trigger: "staged_mint_request_hbl",
  args,
  multisigSpec: spec,
  strictSignerCheck: true,
});
```

Use `isMultisigSignerAuthorized(spec, signerAccountId)` when you only need the
membership check without building a payload, and `buildExecuteTriggerInstruction(...)`
when you want the JSON form before Norito encoding.

```js
import {
  LocalSigningContext,
  NetworkId,
  ToriiClient,
  NoritoRpcClient,
  supportedCryptoAlgorithms,
  generateKeyPair,
  sign,
  verify,
  signEd25519,
  verifyEd25519,
  deriveConfidentialKeyset,
  noritoEncodeInstruction,
  noritoDecodeInstruction,
  buildRegisterDomainTransaction,
  buildCreateKaigiTransaction,
  buildJoinKaigiTransaction,
  buildTransaction,
  buildMintAssetInstruction,
  buildMintAssetTransaction,
  buildBurnAssetTransaction,
  buildBurnTriggerTransaction,
  buildMintAndTransferTransaction,
  buildRegisterDomainAndMintTransaction,
  buildRegisterAccountAndTransferTransaction,
  buildRegisterAssetDefinitionAndMintTransaction,
  buildRegisterRwaTransaction,
  buildRegisterDomainInstruction,
  buildRegisterAccountInstruction,
  buildTransferAssetInstruction,
  buildTransferAssetTransaction,
  buildTransferRwaInstruction,
  submitSignedTransaction,
  normalizeAccountId,
  normalizeAssetId,
  normalizeAssetHoldingId,
  normalizeRwaId,
} from "@iroha/iroha-js";

const { publicKey, privateKey } = generateKeyPair();
const authorityInput =
  "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV";
const newAccountIdInput =
  "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY";
const authority = normalizeAccountId(authorityInput);
const newAccountId = normalizeAccountId(newAccountIdInput);
const roseAssetId = normalizeAssetId("<base58-asset-definition-id>");
const lilyAssetId = normalizeAssetId("<base58-asset-definition-id>");
const roseAssetHoldingId = normalizeAssetHoldingId(`${roseAssetId}#${authority}`);
const lilyAssetHoldingId = normalizeAssetHoldingId(`${lilyAssetId}#${newAccountId}`);
const vaultLotId = normalizeRwaId(
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef$commodities",
);
// Normalise human-supplied identifiers once and reuse the canonical forms below.
const message = Buffer.from("test");
const signature = signEd25519(message, privateKey);
console.log(verifyEd25519(message, signature, publicKey)); // true
console.log(supportedCryptoAlgorithms());

// Native builds also expose generic helpers for secp256k1, ML-DSA-65,
// GOST R 34.10-2012 parameter sets, BLS normal/small, and SM2.
const pqKeys = generateKeyPair({ algorithm: "ml-dsa" });
const pqSignature = sign(message, pqKeys.privateKey, { algorithm: pqKeys.algorithm });
console.log(verify(message, pqSignature, pqKeys.publicKey, { algorithm: pqKeys.algorithm }));

const confidential = deriveConfidentialKeyset(Buffer.alloc(32, 0x42));
console.log(confidential.nkHex); // cb7149cc...

const networkId = NetworkId.parse(process.env.IROHA_NETWORK_ID);
const canonicalAuth = { accountId: authority, privateKey };
const torii = new ToriiClient("https://localhost:8080", {
  localSigningContext: new LocalSigningContext(networkId, networkPrefix),
});
const meta = await torii.uploadAttachment(Buffer.from("{}"), {
  contentType: "application/json",
  canonicalAuth,
});
console.log(meta.id);
console.log(meta.contentType, meta.size, meta.createdMs);
// Every attachment upload/list/get/delete call requires canonicalAuth. The
// immutable LocalSigningContext binds its one-shot signature to this exact
// genesis-derived NetworkId; redirects and retries are rejected.

When you pass `authToken` or `apiToken` credentials, prefer an `https://` Torii base URL; the
client will reject insecure schemes unless you opt into `allowInsecure: true` for local/dev use.
The client copies default canonical-auth key bytes and keeps credentials,
origins, retry policy, and validation caches in private state; underscored
properties are not a supported configuration or inspection surface.

const instruction = buildRegisterDomainInstruction({
  domainId: "wonderland",
  metadata: { key: "value" },
});
const encoded = noritoEncodeInstruction(instruction, networkPrefix);
const decoded = noritoDecodeInstruction(encoded, networkPrefix);
console.log(decoded.Register.Domain.id); // "wonderland"
// `noritoDecodeInstruction` throws on malformed bytes and when neither the
// portable codec nor the native runtime owns a wire ID, so handle decode errors.

const registerAccountInstruction = buildRegisterAccountInstruction({
  accountId: newAccountId,
  metadata: { nickname: "alice" },
});
console.log(noritoDecodeInstruction(registerAccountInstruction, networkPrefix).Register.Account.id);

const { signedTransaction } = buildTransaction({
  networkId,
  authority,
  instructions: [instruction],
  feePayment: { payer: "authority", chargeLimits: [] },
  privateKey,
});
const receipt = await torii.submitTransaction(signedTransaction);
const sampleHashHex =
  receipt?.payload?.tx_hash ?? "ab".repeat(32); // marked 32-byte Iroha hash as lowercase hex
const status = await torii.getTransactionStatus(sampleHashHex);
console.log(status?.status.kind); // e.g. "Applied"

// A 204 or empty response has no receipt. A non-empty application/x-norito
// response must decode successfully; missing native support, malformed bytes,
// and invalid decoder JSON reject the submission promise instead of returning null.

// Node submission accepts only the exact canonical VersionedSignedTransaction
// V1 wire emitted by the native builders. Framed, bare, headerless, alternate-
// layout, and opaque byte payloads are rejected before any network request.

// `submitTransactionAndWait(signedTransaction, options)` submits and waits for
// global Applied finality in one call. It derives the transaction hash from the
// signed bytes; an optional `hashHex` is only checked against that hash.
// Note: raw `getTransactionStatus` requires an exact lowercase 64-hex hash
// whose final nibble is odd (the canonical Iroha hash marker);
// its options support only { signal, scope }, where scope is the explicit read
// choice "local" or "global" and defaults to "global". An "auto" mode and
// cross-endpoint status fallback lists are not part of the API.
// Polling helper options support only { signal, intervalMs, timeoutMs, maxAttempts,
// onStatus }. Finality policy is not caller-selectable: every wait is global-only,
// exact state-resolved Applied succeeds, and Rejected or Expired always fails.
// Queued, Approved, Committed, and queue/cache Applied observations remain pending.
// Status HTTP responses are closed too: only `200` with the exact typed payload
// or `404` (not found yet) are valid. Empty `200`, `202`, `204`, and every other
// status fail rather than selecting a retired pending representation.
// intervalMs/timeoutMs must be non-negative integers (use timeoutMs: null to disable
// the deadline), maxAttempts must be a positive integer when provided, and onStatus
// must be a function.
const statusAbort = new AbortController();
try {
  await torii.waitForTransactionStatus(sampleHashHex, {
    signal: statusAbort.signal,
    intervalMs: 500,
    maxAttempts: 40,
  });
} catch (error) {
  if (error && error.name === "TransactionStatusError") {
    console.error(error.status); // e.g. Rejected
  }
  throw error;
}

// Submit while re-signing with a fresh private key (mutating buffer supported)
await submitSignedTransaction(torii, encoded, { networkId, privateKey });

// `torii` must carry an immutable exact-network OperatorSigningContext here.
// The node-local read is signed fresh and sent once without redirects/retries.
// Inspect the deterministic pipeline recovery sidecar for a given block height.
const recovery = await torii.getPipelineRecoveryTyped(42);
if (recovery) {
  console.log(
    `dag fingerprint: ${recovery.dag.fingerprintHex}, tx count=${recovery.txs.length}`,
  );
}

### Iterating NFTs, RWAs, and account assets

Torii collections iterate with opaque cursors (see
[Collection queries](#collection-queries)); Explorer feeds use the same `filter`, `select`, `limit`, and `cursor` controls.
Their server order is fixed, so sorting, totals, and aggregation are unavailable.

```js
const torii = new ToriiClient("https://torii.example");

const nftPage = await torii.nfts.list({ sort: "id", limit: 3 });
console.log("first nft page:", nftPage.items.map((nft) => nft.id));

const rwaPage = await torii.explorerRwas.list({
  filter: field("owned_by").eq(authority),
  limit: 2,
});
console.log("first RWA page:", rwaPage.items.map((it) => it.id));

for await (const lot of torii.explorerRwas.iterate({
  limit: 2,
  filter: field("owned_by").eq(authority).and(field("domain").eq("commodities")),
})) {
  console.log(`${lot.id} => ${lot.quantity}`);
}

for await (const holding of torii.accountAssets("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").iterate({
  filter: field("quantity").gte(1),
  sort: "-quantity",
  limit: 2,
})) {
  console.log(`${holding.asset} => ${holding.quantity}`);
}
```

Public status parsing accepts only the canonical hash, closed status kind, optional applied
block height, scope, and resolution source. Rejection text, diagnostics, trigger completions, and
batch outcomes are rejected. Authenticated transaction details require a one-shot canonical
signed `FindTransactions` query bound to the deployment's exact genesis-derived `NetworkId`;
the JavaScript package does not expose a details helper until that signed-query generator is
available.

See `recipes/assets_iterators.mjs` and `recipes/nft_account_iteration.mjs` for runnable examples.

### Auth headers and TLS guardrails

`ToriiClient` and `NoritoRpcClient` reject sending `Authorization`/`X-API-Token`
credentials over insecure `http`/`ws` or to mismatched hosts. Opt into
`allowInsecure: true` only for local testing; both clients emit an
`insecureTransportTelemetryHook` event when the escape hatch is used so audits
can flag leaked tokens.

```js
const torii = new ToriiClient("http://localhost:8080", {
  authToken: "dev-token",
  allowInsecure: true,
  insecureTransportTelemetryHook: (event) => console.warn("insecure", event),
});
await torii.getStatusSnapshot(); // emits telemetry; throws if allowInsecure is false

const rpc = new NoritoRpcClient("https://torii.example", { apiToken: "abc" });
const payload = new Uint8Array([0x01]);
await rpc.call("/v1/pipeline/submit", payload); // throws on host/protocol mismatch
```

Error strings stay stable (`ToriiClient: refusing to send credentials over insecure protocol …`)
and the regression suite in `javascript/iroha_js/test/transportSecurity.test.js` covers the
allowed permutations so dApps can mirror the same checks.

### Norito helpers and fixtures

The Norito encode/decode helpers mirror the Rust codecs. Instruction builders cover domain/account
registration and asset transfers; fixtures in `javascript/iroha_js/test/instructionBuilders.test.js`
and `javascript/iroha_js/test/transactionFixturesParity.test.js` keep the payloads aligned with the
Rust goldens.

The first-release retail builders `buildActivateRetailDailyLimitV1InstructionJson`,
`buildBindRetailIdentityV1InstructionJson`, and
`buildRetailMonetaryMovementV1InstructionJson` return exact JSON text for direct use
with `noritoEncodeInstruction` or transaction instruction inputs. They preserve
the full unsigned 64-bit physical dataspace ID without JavaScript number rounding.
The native instruction codec admits only the three exact typed envelopes and
their current wire IDs; retail instruction decode returns large integer fields
as `bigint`. Building an instruction does not install a policy, authenticate a
bank receipt, or verify ledger finality. A source-matched native addon is
required to encode and validate the instruction bytes.

```js
const registerDomain = noritoEncodeInstruction(
  buildRegisterDomainInstruction({ domainId: "wonderland" }), networkPrefix,
);
const registerAccount = buildRegisterAccountInstruction({
  accountId: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
});
const transfer = buildTransferAssetInstruction({
  sourceAssetHoldingId: "<base58-asset-definition-id>#<i105-account-id>",
  destinationAccountId: "sorauﾛ1PﾉｳﾇmEｴWｵebHﾑ6ﾔﾙｲヰiwuCWErJ7uｽoPGｱﾔnjﾑKﾋTCW2PV",
  quantity: "5",
});

const transferTx = buildTransaction({
  networkId,
  authority: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  instructions: [transfer],
  feePayment,
  privateKey,
});
console.log(noritoDecodeInstruction(registerDomain, networkPrefix).Register.Domain.id);
console.log(transferTx.signedTransaction.length); // deterministic Norito bytes
```

### Validation errors

Input guards exposed by helpers such as `normalizeAccountId()`, `normalizeAssetId()`,
`normalizeAssetHoldingId()`,
and the instruction builders now throw `ValidationError` instances. They extend
`TypeError` while providing a deterministic `code` and `path` that automation can
key on.

```js
import {
  ValidationError,
  ValidationErrorCode,
  normalizeAccountId,
} from "@iroha/iroha-js";

try {
  normalizeAccountId("invalid-account");
} catch (error) {
  if (error instanceof ValidationError) {
    console.log(error.code); // e.g. ERR_INVALID_ACCOUNT_ID
    console.log(error.path); // supplied parameter name
  }
  throw error;
}
```

The `ValidationErrorCode` enum covers common categories (`ERR_INVALID_STRING`,
`ERR_INVALID_ACCOUNT_ID`, `ERR_INVALID_NUMERIC`, etc.) so dashboards and CI checks
can count violations without parsing human-readable messages.

### Bundle size reports

Roadmap JS-04 tracks bundle-size impact whenever validation helpers evolve.
Run the reporting helper to generate a JSON summary backed by an actual
`npm pack` tarball:

```bash
npm run report:bundle-size
```

The script writes the report to
`artifacts/js-sdk-bundle-size/bundle-size-<timestamp>.json` by default and
prints the top contributors to stdout:

```
[bundle-size] @iroha/iroha-js@0.0.3
  files: 161 (total 4.4 MB)
  tarball: 873 KB (<sha256>)
  top files:
     1. dist/toriiClient.js — 1.1 MB (25.51% of total)
     2. index.d.ts — 433 KB (9.62% of total)
     3. dist/norito.js — 312 KB (6.93% of total)
     4. README.md — 202 KB (4.48% of total)
     5. dist/instructionBuilders.js — 189 KB (4.19% of total)
```

Pass `-- --out /tmp/report.json` to control the output path or
`-- --keep-tarball` to retain the generated `.tgz` for manual inspection. The
JSON artifact stores the same metadata used in release reviews. Bundle sizes
are informational; code growth has no byte ceiling or percentage gate.
`npm run bundle:check` verifies the declared eager/deferred module boundaries,
complete output inventory, and browser isolation.

// Build a fresh RegisterDomain transaction using the native builder helper
const built = buildRegisterDomainTransaction({
  networkId,
  authority,
  feePayment,
  domainId: "wonderland",
  metadata: { key: "value" },
  creationTimeMs: Date.now(),
  ttlMs: 60_000,
  nonce: 1,
  privateKey,
});
console.log(Buffer.from(built.hash).toString("hex"));

const mint = buildMintAssetInstruction({
  assetHoldingId: roseAssetHoldingId,
  quantity: "10",
});
const transfer = buildTransferAssetInstruction({
  sourceAssetHoldingId: roseAssetHoldingId,
  quantity: "5",
  destinationAccountId: authority,
});
console.log(noritoDecodeInstruction(mint)); // structured JSON

const mintTx = buildMintAssetTransaction({
  networkId,
  authority,
  feePayment,
  assetHoldingId: roseAssetHoldingId,
  quantity: "10",
  privateKey,
});

const burnTx = buildBurnAssetTransaction({
  networkId,
  authority,
  feePayment,
  assetHoldingId: roseAssetHoldingId,
  quantity: "2",
  privateKey,
});

const transferTx = buildTransferAssetTransaction({
  networkId,
  authority,
  feePayment,
  sourceAssetHoldingId: roseAssetHoldingId,
  quantity: "5",
  destinationAccountId: authority,
  privateKey,
});

const registerRwaTx = buildRegisterRwaTransaction({
  networkId,
  authority,
  feePayment,
  rwa: {
    domain: "commodities",
    quantity: "10.5",
    spec: { scale: 1 },
    primaryReference: "vault-cert-001",
    metadata: { origin: "AE" },
  },
  privateKey,
});

const transferRwa = buildTransferRwaInstruction({
  sourceAccountId: authority,
  rwaId: vaultLotId,
  quantity: "2.5",
  destinationAccountId: newAccountId,
});
console.log(noritoDecodeInstruction(transferRwa));

const setRwaMetadata = buildSetRwaKeyValueInstruction({
  rwaId: vaultLotId,
  key: "grade",
  value: { origin: "AE", score: 9n },
});
console.log(noritoDecodeInstruction(setRwaMetadata));

const mintAndTransferTx = buildMintAndTransferTransaction({
  networkId,
  authority,
  feePayment,
  mint: { assetHoldingId: roseAssetHoldingId, quantity: "10" },
  transfers: [
    {
      quantity: "6",
      destinationAccountId: authority,
    },
    {
      sourceAssetHoldingId: roseAssetHoldingId,
      quantity: "1",
      destinationAccountId: authority,
    },
  ],
  privateKey,
});

const domainAndMintTx = buildRegisterDomainAndMintTransaction({
  networkId,
  authority,
  feePayment,
  domain: { domainId: "garden_of_live_flowers", metadata: { key: "value" } },
  mints: [
    { assetId: roseAssetId, quantity: "5" },
    { assetId: normalizeAssetId("<base58-asset-definition-id>"), quantity: "2" },
  ],
  privateKey,
});

const accountAndTransferTx = buildRegisterAccountAndTransferTransaction({
  networkId,
  authority,
  feePayment,
  account: { accountId: newAccountId, metadata: { nickname: "alice" } },
  transfers: [
    {
      sourceAssetHoldingId: roseAssetHoldingId,
      quantity: "2",
      destinationAccountId: newAccountId,
    },
    {
      sourceAssetHoldingId: roseAssetHoldingId,
      quantity: "1",
      destinationAccountId: authority,
    },
  ],
  privateKey,
});

const assetDefinitionAndMintTx = buildRegisterAssetDefinitionAndMintTransaction({
  networkId,
  authority,
  feePayment,
  assetDefinition: {
    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    name: "rose",
    owningDomain: null,
    balanceScopePolicy: "Global",
    metadata: { description: "Rose asset" },
    mintable: "Not",
    spec: { scale: 4 },
  },
  mints: [
    {
      accountId: newAccountId,
      quantity: "3",
    },
    {
      assetId: roseAssetId,
      quantity: "1",
    },
  ],
  privateKey,
});

const assetDefinitionMintAndTransferTx = buildRegisterAssetDefinitionMintAndTransferTransaction({
  networkId,
  authority,
  feePayment,
  assetDefinition: {
    assetDefinitionId: "4jAY5UbAxnGPt31CkijmAsqXP4o4",
    name: "lily",
    owningDomain: null,
    balanceScopePolicy: "Global",
    metadata: { description: "Lily asset" },
  },
  mints: [
    {
      accountId: newAccountId,
      quantity: "8",
    },
    {
      assetId: lilyAssetId,
      quantity: "5",
    },
  ],
  transfers: [
    {
      quantity: "3",
      destinationAccountId: authority,
    },
    {
      sourceAssetHoldingId: lilyAssetHoldingId,
      quantity: "3",
      destinationAccountId: newAccountId,
    },
  ],
  privateKey,
});

// Build an arbitrary transaction from instruction payloads (JSON strings or objects)
const genericTx = buildTransaction({
  networkId,
  authority,
  instructions: [mint, transfer],
  feePayment,
  privateKey,
});

const kaigiCreateTx = buildCreateKaigiTransaction({
  networkId,
  authority,
  feePayment,
  call: {
    id: { domainId: "wonderland.universal", callName: "weekly-sync" },
    host: authority,
    gasRatePerMinute: 120,
    metadata: { topic: "roadmap" },
  },
  privateKey,
});

const kaigiJoinTx = buildJoinKaigiTransaction({
  networkId,
  authority,
  feePayment,
  join: {
    callId: "wonderland.universal:weekly-sync",
    participant: newAccountId,
  },
  privateKey,
});

console.log(Buffer.from(mintTx.hash).toString("hex"));
console.log(Buffer.from(burnTx.hash).toString("hex"));
console.log(Buffer.from(transferTx.hash).toString("hex"));
console.log(Buffer.from(mintAndTransferTx.hash).toString("hex"));
console.log(Buffer.from(assetDefinitionAndMintTx.hash).toString("hex"));
console.log(Buffer.from(assetDefinitionMintAndTransferTx.hash).toString("hex"));
console.log(Buffer.from(genericTx.hash).toString("hex"));
console.log(Buffer.from(kaigiCreateTx.hash).toString("hex"));
console.log(Buffer.from(kaigiJoinTx.hash).toString("hex"));

// The exported instruction builders cover register, mint/burn, transfer,
// permission and key/value, trigger, governance, RWA, confidential-asset,
// smart-contract deployment, and Kaigi families. `buildTransaction()` also
// accepts canonical instruction payloads supplied as JSON strings or objects.
```

## Norito RPC client

The `NoritoRpcClient` provides the binary Norito-RPC transport without requiring
manual Fetch calls throughout your code. It automatically sets the required
`Content-Type: application/x-norito` header, defaults `Accept` to the same
media type, and lets you provide shared headers (authorization tokens, custom
trace identifiers, etc.) when the client is constructed.

```js
import {
  NoritoRpcClient,
  noritoEncodeInstruction,
  buildRegisterDomainInstruction,
} from "@iroha/iroha-js";

const rpc = new NoritoRpcClient("https://localhost:8080", {
  defaultHeaders: { Authorization: `Bearer ${process.env.API_TOKEN ?? ""}` },
  timeoutMs: 5_000,
  // For http:// endpoints during local development, pass allowInsecure: true and attach
  // insecureTransportTelemetryHook to log the downgraded transport.
});

const payload = noritoEncodeInstruction(
  buildRegisterDomainInstruction({
    domainId: "wonderland",
    metadata: {},
  }), networkPrefix,
);

// Returns the raw Norito bytes Torii responds with (Uint8Array).
const responseBytes = await rpc.call("/v1/pipeline/submit", payload);

// Override media type and append query parameters when needed.
await rpc.call("/v1/pipeline/status", payload, {
  params: { hash: "deadbeef" },
  accept: "application/json",
});
```

Use the exported `NoritoRpcError` to detect non-success responses:

```js
import { NoritoRpcClient, NoritoRpcError } from "@iroha/iroha-js";

try {
  await rpc.call("/v1/pipeline/submit", payload);
} catch (error) {
  if (error instanceof NoritoRpcError) {
    console.error(`status ${error.status}: ${error.body}`);
  }
  throw error;
}
```

Pass a custom `fetchImpl`, per-request headers, alternate HTTP methods, or an
AbortSignal when integrating with higher-level transports. The helper returns
`Uint8Array` so you can feed the response straight into the Norito decode
utilities or persist it for parity fixtures. Constructor credentials, headers,
origin policy, Fetch implementation, and timeout are private snapshots; object
inspection does not expose them. Each supported binary payload container is
copied before Fetch sees it, so later caller mutation cannot change an in-flight
request. A per-call `authToken` or `apiToken` replaces its constructor value;
passing `null` or an empty string removes that credential for the call. Timeout
values must be non-negative safe integers; constructor `null` means no default
deadline.

Every `NoritoRpcClient.call(...)` dispatch is one-shot because its binary body
may be a signed query with a consumable nonce. The client passes
`redirect: "error"` to Fetch and never performs a transport retry. A custom
`fetchImpl` must honor that redirect mode and must neither follow a 307/308 nor
retry a body after dispatch. Treat a network error or timeout as an ambiguous
outcome and reconcile it before creating a newly signed request.

### Transport security and host validation

`ToriiClient` and `NoritoRpcClient` keep secrets bound to the client's base URL. When
`authToken`/`apiToken`/`Authorization` headers are present the request scheme and host must
match the client's base; absolute URL overrides are rejected, and insecure `http`/`ws` is allowed
only when you opt into `allowInsecure: true` (intended for local development). Cross-host calls
without credentials require an explicit `allowAbsoluteUrl: true` on the per-request options.
Attach `insecureTransportTelemetryHook` to record/alert whenever an insecure transport is used:

```js
const logInsecure = (event) => console.warn("[insecure-transport]", event);

const torii = new ToriiClient("http://127.0.0.1:8080", {
  authToken: process.env.IROHA_API_TOKEN ?? "",
  allowInsecure: true, // dev/local only
  insecureTransportTelemetryHook: logInsecure,
});

const rpc = new NoritoRpcClient("http://127.0.0.1:8080", {
  authToken: process.env.IROHA_API_TOKEN ?? "",
  allowInsecure: true, // dev/local only
  insecureTransportTelemetryHook: logInsecure,
});
```

For mock/testing targets without credentials, pass `allowAbsoluteUrl: true` to
`NoritoRpcClient.call` to intentionally reach a different host while keeping credentialled traffic
pinned to the configured base.

## Batching Best Practices

- Treat the instruction array passed to `buildTransaction` as authoritative: the
  order you supply becomes the exact Norito execution order on-chain. Keep
  dependent steps adjacent (for example, mint before transfer, transfer before
  burn) so later instructions can safely reference state written by earlier ones.
- Prefer the convenience helpers (`buildMintAndTransferTransaction`,
  `buildRegisterAssetDefinitionMintAndTransferTransaction`, etc.) when they fit
  your use case. They validate numeric quantities, asset IDs, and mutually
  exclusive options (`transfer` vs `transfers`) before serialisation.
- When assembling instructions manually, re-use the specific builders
  (`buildMintAssetInstruction`, `buildTransferAssetInstruction`,
  `buildBurnAssetInstruction`, `buildBurnTriggerRepetitionsInstruction`) so numeric
  inputs, metadata, and asset IDs are normalised identically to the convenience
  helpers. Pass the resulting objects directly to `buildTransaction`.
- Use canonical strings (`"10"`), `KotodamaQuantity`, or `bigint` for `Quantity`
  values. JavaScript `number` inputs are rejected because they cannot represent
  the full lossless domain. Strings must be plain canonical decimal literals (no
  exponent), with up to 28 fractional digits and a 512-bit mantissa.
- Keep asset IDs in canonical holding form
  (`<base58-asset-definition-id>#<i105-account-id>` with optional `#dataspace:<id>`) when
  chaining mint and transfer steps. The helpers do not guess missing account or
  scope suffixes, ensuring all peers derive the same destination.
- Reuse the exported `normalizeAccountId()` / `normalizeAssetId()` helpers when you
  accept human input. They canonicalise multihash identifiers into the uppercase
  format expected by the data model, preventing subtle casing mismatches before
  you hand values to the builders.
- During development, consider round-tripping instructions through
  `noritoEncodeInstruction`/`noritoDecodeInstruction` (as shown in
  `recipes/batching.mjs`) to confirm the payload shape matches your intent prior
  to signing or submitting transactions.

The source-checkout-only `recipes/batching.mjs` script demonstrates these
patterns end-to-end and prints deterministic hashes for the batched
transactions. It is not included in the portable registry tarball because its
generic transaction builder requires the verified native host.

## SM2 Deterministic Fixture & Helpers

The JS SDK now ships higher-level SM2 helpers backed by the native host:

- `generateSm2KeyPair({ distid? })`
- `deriveSm2KeyPairFromSeed(seed, distid?)`
- `loadSm2KeyPair(privateKey, distid?)`
- `signSm2(message, privateKey, distid?)`
- `verifySm2(message, signature, publicKey, distid?)`
- `sm2PublicKeyMultihash(publicKey, distid?)`

All helpers default to the canonical distinguishing ID (`1234567812345678`)
and share the same deterministic policy as the Rust/Python SDKs. The
cross-SDK fixture lives in `fixtures/sm/sm2_fixture.json` and can be retrieved
via `sm2FixtureFromSeed(distid, seed, message)` for parity tests:

```js
import {
  generateSm2KeyPair,
  deriveSm2KeyPairFromSeed,
  loadSm2KeyPair,
  signSm2,
  verifySm2,
  sm2PublicKeyMultihash,
  sm2FixtureFromSeed,
} from "@iroha/iroha-js";

const generated = generateSm2KeyPair();
console.log(generated.distid); // "1234567812345678"
console.log(sm2PublicKeyMultihash(generated.publicKey, generated.distid));

const seed = Buffer.from("11".repeat(32), "hex");
const derived = deriveSm2KeyPairFromSeed(seed, "1234567812345678");
const message = Buffer.from("69726F686120736D2073646B2066697874757265", "hex");
const signature = signSm2(message, derived.privateKey, derived.distid);
console.log(verifySm2(message, signature, derived.publicKey, derived.distid)); // true

const loaded = loadSm2KeyPair(derived.privateKey, derived.distid);
console.log(Buffer.from(loaded.publicKey).equals(derived.publicKey));

const fixture = sm2FixtureFromSeed(derived.distid, seed, message);
console.log(fixture.signature); // 1877845D5F...
```

When the `iroha_js_host` native module is unavailable the fixture helper falls
back to the JSON reference, allowing tests to continue asserting deterministic
outputs without rebuilding native artifacts.

## ISO Bridge Alias Helpers

Alias resolution endpoints surface ISO bridge account bindings so operators can
cross-check IBAN attestations without building bespoke HTTP clients. The JS SDK
now mirrors the Python helper coverage:

```js
const torii = new ToriiClient("http://localhost:8080", {
  config: { torii: { apiTokens: ["bridge-token"] } },
  localSigningContext: new LocalSigningContext(networkId, networkPrefix),
});

const resolved = await torii.resolveAlias("GB82 WEST 1234 5698 7654 32");
if (resolved) {
  console.log(`${resolved.alias} → ${resolved.account_id}`);
}

const permissioned = await torii.resolveAlias("tidal-river-4160@mibank.paynet", {
  canonicalAuth: {
    accountId: "operator-1@mibank.paynet",
    privateKey: operatorPrivateKey,
  },
});
console.log(permissioned?.account_id);

const indexed = await torii.resolveAliasByIndex(0);
console.log(indexed?.source); // "iso_bridge"
```

`resolveAlias*` returns `null` when the alias is missing and throws when the ISO
bridge runtime is disabled, matching Torii’s semantics. Pass `canonicalAuth`
when an alias namespace requires Torii request signatures. Its `accountId`
credential must be an exact canonical ASCII on-chain account alias
(`name@dataspace` or `name@domain.dataspace`). I105 remains the canonical form
for ordinary account fields, paths, and response models. Every signature also
requires the immutable genesis-derived `NetworkId` in the client's
`LocalSigningContext`; labels never substitute for it. Values are never
trimmed, case-folded, percent-decoded, or base64-decoded.

Browser wallets that keep private keys sealed can sign the same request through
an async signer callback:

```js
import { buildCanonicalJsonRequest } from "@iroha/iroha-js/canonical-request";

const request = await buildCanonicalJsonRequest({
  accountId: "operator-1@mibank.paynet",
  networkId,
  baseUrl: toriiBaseUrl,
  path: "/v1/aliases/resolve",
  body: { alias: "tidal-river-4160@mibank.paynet" },
  sign: ({ messageBase64 }) => signWithWalletKey(messageBase64),
});

const response = await fetch(`${toriiBaseUrl}/v1/aliases/resolve`, request);
```

Canonical methods are non-empty ASCII HTTP tokens and signed paths use the
exact root-relative ASCII wire spelling. The public header builders and the
fetch-facing JSON builder derive and bound the WHATWG-percent-encoded wire
query before signing; the standalone query canonicalizer consumes an
already-wire query. Callback signers return 1--3,309
non-zero signature bytes. The complete `0x` account-header prefix is reserved
for canonical address hex, not aliases. Alias headers receive only a bounded
lowercase-ASCII structural preflight; Torii remains authoritative for UTS-46,
active-catalog resolution, and controller verification. The SoraFS reputation helper can validate and
forward an externally constructed canonical witness (strict padded base64, at
most 768 KiB decoded), but the JavaScript SDK does not yet construct a typed
multisignature witness end to end.

The `canonical-request` subpath ships standalone DOM declarations, so browser
TypeScript consumers do not need ambient Node types.

> **Recipe:** run `node javascript/iroha_js/recipes/iso_alias.mjs` to exercise
> the lookup endpoints from the CLI. The script accepts `ISO_ALIAS_LABEL` and
> `ISO_ALIAS_INDEX` so ISO bridge gate jobs can confirm deterministic account
> bindings without writing bespoke tooling.

Sumeragi status is the native protocol-1 observation. With an exact-network
operator signing context, the Node and browser clients expose the same closed
21-field schema through `getSumeragiStatusTyped()`:

```js
const status = await torii.getSumeragiStatusTyped({ signal });
console.log(status.height, status.view, status.stage, status.halted);
console.log(status.committed_height, status.applied_height);
```

All nullable keys are mandatory. The bounded lossless JSON reader rejects
numeric-token drift, duplicate fields and malformed native keys, fingerprints,
beacon horizons and halt reasons. Parsed objects are immutable observations;
they are not finality proofs. Key admission uses the canonical Rust binding.
`getSumeragiStatus()` returns raw JSON. Retired global QC and grouped diagnostics
methods are removed. Native capture parity and actual cross-dataspace settlement
qualification remain open.

## Advanced Sumeragi Observability

`getSumeragiLanes()` requires every current record field, including the committed
`da_layout` RS16 encoding and resource bounds. Lane observations do not confer finality.

Torii exposes additional consensus observability endpoints. The JS SDK mirrors
them so operators can inspect key observations and on-chain parameters without
bespoke fetch plumbing:

```js
const blsKeys = await torii.getSumeragiBlsKeys();
console.log(`BLS-capable peers=${Object.values(blsKeys).filter(Boolean).length}`);

const lanes = await torii.getSumeragiLanes();
for (const { record, instance } of lanes) {
  console.log(`lane ${record.lane} merged=${record.merged.height} running=${instance !== null}`);
}

const params = await torii.getSumeragiParams();
console.log(`block cadence=${params.block_cadence_ms}ms drift=${params.max_clock_drift_ms}ms height=${params.chain_height}`);
```

All advanced helpers validate the Torii payloads and coerce numeric string
fields into numbers. If Torii returns malformed data (missing fields or invalid
types) the SDK raises a `TypeError`, ensuring broken responses never flow into
dashboards unnoticed.

The helpers bubble up HTTP errors so dashboards can distinguish network
failures from gated endpoints.

Gateway telemetry also exposes peer metadata (connectivity, config facts, map
info) for operators pinning Torii relays. The SDK normalises these payloads via
`listTelemetryPeersInfo`:

```js
const peers = await torii.listTelemetryPeersInfo();
for (const peer of peers) {
  console.log(
    `${peer.url} connected=${peer.connected} telemetry=${
      peer.telemetryUnsupported ? "disabled" : "enabled"
    }`,
  );
  if (peer.config?.queueCapacity) {
    console.log(`  queue=${peer.config.queueCapacity} public_key=${peer.config.publicKey}`);
  }
  if (peer.location) {
    console.log(`  location=${peer.location.city}, ${peer.location.country}`);
  }
}
```

Torii status snapshots extend the base `/status` payload with derived metrics:

```js
const snapshot = await torii.getStatusSnapshot();
console.log(
  `queue=${snapshot.status.queue_size} Δ=${snapshot.metrics.queue_delta} approvals=${snapshot.metrics.tx_approved_delta}`,
);
if (snapshot.status.governance) {
  const admission = snapshot.status.governance.manifest_admission;
  console.log(
    `governance checks=${admission.total_checks} runtime rejections=${admission.runtime_hook_rejected}`,
  );
}
```

## Sumeragi Evidence

Torii exposes no evidence-mutation routes. Use the authenticated native
Sumeragi status reads and Prometheus transport metrics for operations.
Consensus evidence is available through the supported read-only endpoints:

```js
const evidence = await torii.listSumeragiEvidence({
  limit: 20,
  kind: "NativeSumeragiEvidence",
});
console.log(`Committed ${evidence.total} evidence entries`);
const count = await torii.getSumeragiEvidenceCount();
console.log(`Committed evidence count: ${count.count}`);
```

The first-release JSON contract is closed: each item is a
`NativeSumeragiEvidence` record with the original instance, epoch context, signing
generation, ordered historical offenders, original frame digest, and
a non-null consensus admission height and
a `pending`, `applied`, or `cancelled` penalty status. Unknown response fields
and retired evidence kinds are rejected. Unsigned 64-bit values above
`Number.MAX_SAFE_INTEGER` are returned as `bigint` without rounding. Count
responses are capped at 1 KiB and JSON list responses at 1 MiB.

## SoraFS Storage Helpers

The hedging and billing helpers use a per-request canonical account signature,
disable transparent retries and redirects, require exact non-zero lowercase
32-byte checkpoint/cursor identifiers, and stream responses under the Torii
caps (1 MiB for JSON and 22 MiB for a published statement). The acknowledgement
proof is encoded with the shared
`iroha.torii.v1.sorafs.billing.acknowledgement_proof` Norito schema; no nonce,
proof, or field aliases are accepted.

```js
const canonicalAuth = {
  accountId: process.env.IROHA_ACCOUNT_ID,
  privateKey: Buffer.from(process.env.IROHA_PRIVATE_KEY_HEX, "hex"),
};
const checkpoint = process.env.SORAFS_BILLING_CHECKPOINT_HEX;

const status = await torii.getSorafsBillingStatus({ canonicalAuth });
const statements = await torii.listSorafsBillingStatements({
  expectedCheckpointFingerprintHex: checkpoint,
  limit: 25,
  canonicalAuth,
});
const statement = await torii.getSorafsBillingStatement(
  statements.items[0].statement_id_hex,
  checkpoint,
  { canonicalAuth },
);
await torii.acknowledgeSorafsBillingStatement(
  statements.items[0].statement_id_hex,
  checkpoint,
  {
    requestNonceHex: crypto.randomBytes(32).toString("hex"),
    authenticationProof: externalOwnerProof,
  },
  { canonicalAuth },
);
const exposure = await torii.getSorafsHedgingExposure({
  expectedCheckpointFingerprintHex: checkpoint,
  limit: 100,
  canonicalAuth,
});
```

`getSorafsBillingReconciliation` requires the governed billing-manager role.
The exposure and intent reads require a treasury- or hedging-observer role.
These APIs expose projections only; automatic hedge execution remains absent.

Pin registration accepts only an exact canonical `VersionedSignedTransaction`
V1 containing exactly one native `RegisterPinManifest` instruction. Build and fee-quote that
transaction locally; neither the raw private key nor any secret-bearing JSON
request is sent to Torii. The immediate response is only an admission identity,
not a finality, fee, custody, or pin-status receipt.
The manifest submission epoch is derived from the block consensus timestamp;
clients cannot supply or override it.

```js
const operatorId = process.env.SORAFS_OPERATOR_ID;
const operatorKeyHex = process.env.SORAFS_OPERATOR_KEY_HEX;
const networkIdLiteral = process.env.IROHA_NETWORK_ID;
if (!operatorId || !operatorKeyHex || !networkIdLiteral) {
  throw new Error(
    "set SORAFS_OPERATOR_ID, SORAFS_OPERATOR_KEY_HEX, and IROHA_NETWORK_ID",
  );
}
const networkId = NetworkId.parse(networkIdLiteral);

const { signedTransaction } = await buildRegisterPinManifestTransaction(torii, {
  networkId,
  authority: operatorId,
  privateKey: Buffer.from(operatorKeyHex, "hex"),
  feePayment: { payer: "authority", chargeLimits: [] },
  manifestPayload: fs.readFileSync("./manifest.norito"),
  alias: {
    namespace: "docs",
    name: "main",
    proof: fs.readFileSync("./artifacts/docs_alias.proof"),
  },
});
const admission = await torii.registerSorafsPinManifestTyped(signedTransaction);
console.log(
  `admitted transaction=${admission.tx_hash_hex} manifest=${admission.manifest_digest_hex}`,
);

// Local storage-state diagnostics use a separately provisioned, exact-network
// OperatorSigningContext; do not reuse the transaction key implicitly.
const operatorTorii = new ToriiClient(toriiUrl, {
  operatorSigningContext: runtimeOperatorSigningContext,
});
const storageState = await operatorTorii.getSorafsStorageState();
console.log(`pin queue depth=${storageState.pin_queue_depth}`);

const storedManifest = await torii.getSorafsManifest(admission.manifest_digest_hex);
console.log(`profile=${storedManifest.chunk_profile_handle} chunks=${storedManifest.chunk_count}`);

const daBundle = await torii.getDaManifest("0x" + "aa".repeat(32));
console.log(
  `DA manifest lane=${daBundle.lane_id} chunkPlanChunks=${daBundle.chunk_plan.chunk_fetch_specs.length}`,
);

const ingestResult = await torii.submitDaBlob({
  networkId,
  owner: operatorId,
  payload: fs.readFileSync("./artifacts/nexus_sidecar.car"),
  codec: "nexus_lane_sidecar",
  laneId: 7,
  epoch: 11,
  sequence: Date.now(),
  retentionPolicy: { storageClass: "Hot", governanceTag: "nexus.sidecars" },
  metadata: {
    "content-type": "application/car",
    "da.stream": {
      value: "governance",
      visibility: "Public",
    },
  },
  privateKeyHex: process.env.DA_SUBMITTER_PRIVATE_KEY,
});
if (ingestResult.receipt) {
  console.log(
    `storage ticket ${ingestResult.receipt.storage_ticket_hex} hash=${ingestResult.receipt.blob_hash_hex}`,
  );
  console.log(`quoted base rent ${ingestResult.receipt.rent_quote?.base_rent ?? "unavailable"} XOR`);
}

DA ingest always emits a signed first-release request, including `noSubmit`
artifact preparation. The canonical digest binds the exact genesis-derived
`NetworkId`, owner controller bytes, lane/epoch/sequence nonce, canonical
payload hash and byte length, and the complete request-content commitment.
Consensus re-verifies these witnesses against the committed account controller
and charges per-owner count and bytes; display chain labels and metadata cannot
select the security domain or quota identity.

DA rent-quote values use the same exact unit-free XOR contract: `base_rent`,
`protocol_reserve`, `provider_reward`, `pdp_bonus`, `potr_bonus`, and
`egress_credit_per_gib` remain canonical decimal strings. The SDK never
converts them to JavaScript numbers or projects them into `_micro` fields.

const session = await torii.fetchDaPayloadViaGateway({
  storageTicketHex: ingestResult.receipt.storage_ticket_hex,
  gatewayProviders: [
    {
      name: "alpha",
      providerIdHex: process.env.SORAFS_PROVIDER_ID,
      gatewayPublicKeyHex: process.env.SORAFS_GATEWAY_PUBLIC_KEY,
      baseUrl: "https://gateway.example.com/",
      streamTokenB64: process.env.SORAFS_STREAM_TOKEN,
    },
  ],
  fetchOptions: {
    maxPeers: 4,
    retryBudget: 5,
    scoreboard: {
      persist_path: "/tmp/scoreboard.json",
      telemetry_source_label: "ci-da-audit",
    },
  },
  proofSummary: {
    sampleCount: 12,
    sampleSeed: 99,
    leafIndexes: [0, 1, 2],
  },
});
console.log(`payload fetched (${session.gatewayResult.assembledBytes} bytes)`);
console.log(`proofs verified=${session.proofSummary?.proofs.every((proof) => proof.verified)}`);

// Derive handles manually when working with saved manifests:
const chunkerHandle = deriveDaChunkerHandle(session.manifest.manifest_bytes);
console.log(`resolved chunker handle=${chunkerHandle}`);

// You can also re-run the native helper on saved artefacts:
const summary = generateDaProofSummary(
  session.manifest.manifest_bytes,
  session.gatewayResult.payload,
  { sampleCount: 4, leafIndexes: [0, 5] },
);
console.log(`sample seed=${summary.sample_seed} proofCount=${summary.proof_count}`);

const artifact = buildDaProofSummaryArtifact(summary, {
  manifestPath: "./artifacts/manifest.to",
  payloadPath: "./artifacts/payload.car",
});
await emitDaProofSummaryArtifact({
  summary,
  manifestPath: artifact.manifest_path,
  payloadPath: artifact.payload_path,
  outputPath: "./artifacts/proof_summary.json",
});
console.log(`proof summary emitted to ${artifact.manifest_path} / proof_summary.json`);

// Mirror the CLI artefact layout without shelling out:
const manifestResult = await torii.getDaManifestToDir(
  ingestResult.receipt.storage_ticket_hex,
  { outputDir: "./artifacts/da/get_blob" },
);
const proveResult = await torii.proveDaAvailabilityToDir({
  storageTicketHex: ingestResult.receipt.storage_ticket_hex,
  gatewayProviders: [
    {
      name: "alpha",
      providerIdHex: process.env.SORAFS_PROVIDER_ID,
      gatewayPublicKeyHex: process.env.SORAFS_GATEWAY_PUBLIC_KEY,
      baseUrl: "https://gateway.example.com/",
      streamTokenB64: process.env.SORAFS_STREAM_TOKEN,
    },
    {
      name: "beta",
      providerIdHex: process.env.SORAFS_SECOND_PROVIDER_ID,
      gatewayPublicKeyHex: process.env.SORAFS_SECOND_GATEWAY_PUBLIC_KEY,
      baseUrl: "https://gateway-two.example.com/",
      streamTokenB64: process.env.SORAFS_SECOND_STREAM_TOKEN,
    },
  ],
  proofSummary: { sampleCount: 4, leafIndexes: [0, 2] },
  outputDir: "./artifacts/da/prove_availability",
});
console.log("manifest paths:", manifestResult.paths);
console.log("payload saved:", proveResult.payloadPath);
console.log("scoreboard saved:", proveResult.scoreboardPath);
console.log("proof summary saved:", proveResult.proofSummaryPath);
```

`getSorafsStorageState` fails before dispatch unless the client has an immutable
exact-network `OperatorSigningContext`. Payload bytes are available only through
request-bound CAR/chunk stream capabilities; Torii has no JSON payload-range
diagnostic or unsigned remote-hydration fallback. Without a valid capability, a
cache miss returns a capability-required error while already-local content
remains available.

`fetchDaPayloadViaGateway` automatically derives the chunker handle from the manifest bundle when you omit `chunkerHandle`, and the exported `deriveDaChunkerHandle` helper surfaces the same logic for bespoke tooling. `generateDaProofSummary` reuses the Norito + PoR logic from the CLI via the native binding so proofs remain identical across SDKs.

> **Multi-source enforcement:** the JS SDK requires at least two gateway providers for every orchestrated fetch. This matches the SF-6c roadmap requirement and keeps `cargo xtask sorafs-adoption-check` green by default.

Every gateway fetch also exposes the orchestrator’s scoreboard metadata so you
can attach the same evidence bundle as the CLI. `gatewayResult.metadata`
includes the direct/gateway provider counts, the derived provider-mix label
(`"gateway-only"` for the JS bindings unless you deliberately mix in local
providers), policy override flags, manifest IDs/CIDs, and telemetry labels—the
new `telemetryRegion` field mirrors the `--telemetry-region` CLI flag so adoption
reports can prove which fleet produced the capture:

```js
const { metadata } = session.gatewayResult;
console.log(
  `provider mix=${metadata.providerMix} transport=${metadata.transportPolicy} manifest=${metadata.gatewayManifestId}`,
);
if (!metadata.gatewayManifestProvided) {
  throw new Error("Gateway fetches must include a signed manifest envelope.");
}
```

`submitDaBlob` computes the BLAKE3 digest via the native binding, so run `npm run build:native`
before calling it—and the gateway/proof helpers—in development environments. Pass
`artifactDir: "./artifacts/da/submission_<stamp>"` (and `noSubmit: true` for dry
runs) to mirror the CLI ingest artefacts without leaving Node.

```js
const canonicalAuth = {
  accountId: operatorId,
  privateKey: Buffer.from(operatorKeyHex, "hex"),
};
const pinListing = await torii.listSorafsPinManifests({
  status: "approved",
  limit: 25,
  maxBytes: 64 * 1024,
});
const pinAnchor = pinListing.finalized_cursor;
console.log(
  `charged manifests=${pinListing.charged_usage.manifest_count} bytes=${pinListing.charged_usage.content_bytes}`,
);
if (pinListing.has_more) {
  const nextPinPage = await torii.listSorafsPinManifests({
    status: "approved",
    limit: 25,
    maxBytes: 64 * 1024,
    afterDigestHex: Buffer.from(pinListing.next_after_digest).toString("hex"),
    expectedFinalizedHeight: pinAnchor.height,
    expectedFinalizedBlockHashHex: Buffer.from(pinAnchor.block_hash).toString("hex"),
  });
  console.log(`next finalized page size=${nextPinPage.manifests.length}`);
}

const aliases = await torii.listSorafsAliases({ namespace: "docs", canonicalAuth });
console.log(`doc namespace aliases=${aliases.returned_count}`);

// Alias pages are closed first-release projections. Each record carries exact
// lineage, cache evaluation, successor, governance, and policy state.
console.log(aliases.attestation.block_height, aliases.aliases[0]?.cache_decision);

const replication = await torii.listSorafsReplicationOrders({
  status: "pending",
  canonicalAuth,
});
console.log(`pending replication orders=${replication.total_count}`);
for (const order of replication.replication_orders) {
  console.log(order.status.state, order.provider_completions.length);
}

const orderbook = await torii.getSorafsOrderbook({ limit: 25 });
console.log(`open committed orders=${orderbook.status.open_orders}`);
const anchor = orderbook.orders.finalized_cursor;
const orderbookEvents = await torii.listSorafsOrderbookEvents({
  limit: 25,
  expectedFinalizedHeight: anchor.height,
  expectedFinalizedBlockHashHex: anchor.block_hash,
});
console.log(`committed orderbook events=${orderbookEvents?.events.events.length ?? 0}`);
const next = orderbookEvents?.events.next_after;
const after = next
  ? {
      afterSequence: next.sequence,
      afterBlockHeight: next.block_height,
      afterBlockHashHex: next.block_hash,
      afterEventIndex: next.event_index,
    }
  : {};
for await (const event of torii.streamSorafsOrderbookEvents(after)) {
  console.log("orderbook event", event.event, event.data);
  break;
}
for await (const event of torii.streamSorafsOrderbookEventsWebSocket({
  ...after,
  WebSocketImpl: WebSocket,
})) {
  console.log("orderbook websocket event", event.event, event.data);
  break;
}
// LocalSigningContext must carry the deployment's exact NetworkId and I105
// network prefix explicitly (369 for Taira); no prefix is inferred or defaulted.
const orderResult =
  await torii.submitSorafsOrderbookOrder(signedSubmitOrderTransaction, {
    expectedReceiptSigner: toriiReceiptPublicKey,
  });
console.log("order transaction hash", orderResult.payload?.tx_hash);
// Each route accepts a full caller-signed transaction containing exactly one
// route-matching native orderbook instruction.
// Catch SorafsOrderbookSubmissionAmbiguousError after dispatch, reconcile its
// expectedIdentity against finalized state, and never resubmit automatically.
// Strict submits require HTTPS unless allowInsecure:true is explicitly set.
// timeoutMs is a whole-operation AbortSignal deadline covering preflight,
// dispatch, and receipt read. A custom fetchImpl is part of the trusted
// one-shot boundary and must honor that signal, redirect:"error", and zero replay.
await torii.submitSorafsOrderbookCancel(signedCancelOrderTransaction, {
  expectedReceiptSigner: toriiReceiptPublicKey,
});
await torii.submitSorafsOrderbookReceipt(signedRecordReceiptTransaction, {
  expectedReceiptSigner: toriiReceiptPublicKey,
});

for await (const manifest of torii.iterateSorafsPinManifests({ pageSize: 25 })) {
  console.log("manifest digest", Buffer.from(manifest.digest).toString("hex"));
}
for await (const alias of torii.iterateSorafsAliases({
  namespace: "docs",
  pageSize: 50,
  canonicalAuth,
})) {
  console.log("alias entry", alias.alias);
}
for await (const order of torii.iterateSorafsReplicationOrders({
  pageSize: 25,
  canonicalAuth,
})) {
  console.log("replication order", order.order_id_hex);
}
```

The pin-list route is a first-release hard cut: it uses an exclusive digest
cursor bound to one finalized height/hash and accepts no `offset`. `status` is
exactly lowercase, `limit` is `1..=256`, and `maxBytes` is
`1024..=262144`. Each page contains bounded summaries plus the consensus-kept
O(1) charged count/byte totals and the required retained `approved_epoch`; alias proofs, metadata, council envelopes,
and fee details are available only from the bounded per-digest
detail route. The async iterator locks the first page's finalized anchor for
every subsequent request.

Replication status is also a closed first-release union: `pending` carries only
`state`, while `completed`, `expired`, and `cancelled` carry an exact `epoch`.
Each order exposes the native `order` projection, `assignment_revision`, and
`provider_completions`, including provider-owner signer policy and finalized
anchor. Inventory responses retain full-width integer tokens as `bigint` and
reject duplicate keys, unknown fields and alternate numeric spellings. The
canonical order bytes remain an opaque bounded base64 field in this readback;
use the native codec for independent Norito validation. Replication filters use
exact lowercase status names, `limit` is `1..=500`, and `offset` is a u32.

`getSorafsPinManifest(digestHex)` returns the exact finalized native shape
`{ finalized_cursor, manifest }`, validates the record's native byte arrays and
retained approval lifecycle, and returns `null` for `404 Not Found`. Pin detail
contains only the finalized cursor and native manifest; query aliases and
replication orders through their dedicated endpoints. Callers may bind the read
to `expectedFinalizedHeight` and
`expectedFinalizedBlockHashHex`, which must be supplied together. Heights accept
safe integer numbers or full-width `bigint` values. The raw method retains JSON
byte arrays; `getSorafsPinManifestTyped` returns `Uint8Array` byte fields. Both
preserve integer tokens above the safe-number range as `bigint`, reject duplicate
keys and non-integer numeric spellings outside `manifest.metadata`, and permit
finite fractional JSON values inside that metadata object.

PoR automation helpers surface the first-release production endpoints so SDK
callers can submit authenticated Norito-encoded provider proofs and auditor
verdicts and retrieve coordinator exports. Challenge issuance and capacity
telemetry observations are owned by finalized ledger/coordinator workflows;
there is no client-side challenge or manual observation API.

```js
await torii.recordSorafsPorProof({ proof: porProofBytes });
await torii.recordSorafsPorVerdict({ verdict: porVerdictBytes });

const porStatuses = await torii.getSorafsPorStatus({ providerHex: providerIdHex });
const porExport = await torii.exportSorafsPorStatus({ startEpoch: 1024, endEpoch: 1032 });
const weeklyReport = await torii.getSorafsPorWeeklyReport("2026-W05");
```

`getSorafsPorStatus`, `exportSorafsPorStatus`, and `getSorafsPorWeeklyReport`
return Norito bytes (`Buffer` instances). Decode them with `norito::json`, the
Rust `norito` crate, or another canonical Norito runtime before inspecting the
structured payloads.

## UAID Portfolios & Space Directory Manifests

Universal Account IDs (UAIDs) power the Nexus dataspace model. Torii exposes
three read-only endpoints (documented in
[`specs/torii/portfolio_api.md`](../../specs/torii/portfolio_api.md))
so SDKs can inspect aggregated balances, dataspace bindings, and the canonical
capability manifests tracked by the Space Directory. The JS SDK surfaces typed
helpers for all three surfaces:

```js
const uaidLiteral = "uaid:0f4d86b20839a8ddbe8a1a3d21cf1c502d49f3f79f0fa1cd88d5f24c56c0ab11";

const portfolio = await torii.getUaidPortfolio(uaidLiteral);
// Optionally filter positions by a specific asset-holding id.
// const portfolio = await torii.getUaidPortfolio(uaidLiteral, { assetId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM#sorauﾛ1PaQｽGh1ｴ6pAﾜnqｸfJuｿMﾑVqﾏvQﾐﾚｼｾﾋaﾈｳﾊc1ｺﾊ1GGM2D" });
for (const ds of portfolio.dataspaces) {
  console.log(`dataspace ${ds.dataspace_alias ?? ds.dataspace_id} accounts=${ds.accounts.length}`);
  ds.accounts.forEach((account) => {
    account.assets.forEach((asset) => {
      console.log(`  ${asset.asset_definition_id} -> ${asset.quantity}`);
    });
  });
}

const bindings = await torii.getUaidBindings(uaidLiteral);
bindings.dataspaces.forEach((entry) => {
  console.log(`${entry.dataspace_alias ?? entry.dataspace_id}: ${entry.accounts.join(", ")}`);
});

const manifests = await torii.uaidManifests(uaidLiteral).list({
  filter: 'dataspace_id = 11 and status = "Active"',
  limit: 50,
  includeTotal: true,
});
console.log(
  `matched=${manifests.total} next=${manifests.nextCursor}`,
);
manifests.items.forEach((manifest) => {
  console.log(
    `manifest ${manifest.manifest_hash} status=${manifest.status} entries=${manifest.manifest.entries.length}`,
  );
});
```

Each helper validates the response payloads:

- `getUaidPortfolio` enforces numeric totals and returns the deterministically
  sorted dataspace/account tree.
- `getUaidBindings` mirrors the Space Directory bindings map so tooling can
  confirm which Torii account IDs are active per dataspace.
- `uaidManifests(uaid).list()` requires the exact shared page envelope, numeric
  manifest version `1`, lifecycle metadata, lower-case hashes, canonical
  accounts, and exact allow/deny entry shapes. Use the shared `filter`, `sort`,
  `select`, `limit`, `cursor`, and `includeTotal` controls.

The helpers require exact lower-case `uaid:<64-hex>` literals with LSB=1 and
throw on whitespace, raw hashes, or case variants, ensuring automation scripts
surface clear diagnostics before the request reaches Torii.

### Canonical contract arguments

Pass the entrypoint's signed `argument_schema` as `argumentSchema` to
`prepareContractCall`. The client checks the argument fields and converts safe
integer or bigint values for `int`, `decimal` and `quantity` to canonical strings
before hashing or signing the request. Invalid values report their field path.
The schema stays local and is not included in the Torii request.

Use the same schema when constructing the draft intent's payload digest:

```js
import {
  canonicalContractArguments,
  contractPayloadDigestHex,
} from "@iroha/iroha-js/contract-payload";

const argumentSchema = entrypoint.argument_schema;
const payload = canonicalContractArguments({ amount: 7n }, { argumentSchema });
const payloadDigestHex = contractPayloadDigestHex(payload);
```

`canonicalContractPayloadJson(payload, { argumentSchema })` and
`contractPayloadDigestHex(payload, { argumentSchema })` apply the same conversion.
`canonicalContractArguments(payload)` rejects numbers when their declared types
are unknown. The raw JSON canonicalizer and digest helpers, called without
options, retain JSON integer tokens for fields whose actual type permits them,
such as `Json` and `DataSpaceId`; they do not infer an entrypoint schema.

### Publishing & revoking manifests

Operators can stage capability rotations or emergency deny-wins decisions via
Torii as well. `publishSpaceDirectoryManifest()` posts the canonical manifest
JSON (or a structure parsed from the fixtures under
`fixtures/space_directory/capability/`) with the transaction authority, while
`revokeSpaceDirectoryManifest()` prepares an immediate revocation
for a UAID/dataspace pair. Both requests are secret-free and return canonical
transaction drafts for local signing. Both helpers require per-request
`canonicalAuth`; its exact canonical I105 account must equal the body authority.
The client must also have an immutable exact-network `LocalSigningContext`.
An optional `options.signal` lets callers abort the one-shot dispatch:

```js
import { promises as fs } from "node:fs";
import { LocalSigningContext, NetworkId, ToriiClient } from "@iroha/iroha-js";
import { contractPayloadDigestHex } from "@iroha/iroha-js/contract-payload";

const authority = "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB";
const canonicalAuth = { accountId: authority, privateKey: runtimePrivateKey };
const torii = new ToriiClient(toriiUrl, {
  localSigningContext: new LocalSigningContext(NetworkId.parse(exactNetworkId), networkPrefix),
});

const manifest = JSON.parse(
  await fs.readFile("fixtures/space_directory/capability/cbdc.manifest.json", "utf8"),
);

const controller = new AbortController();

await torii.publishSpaceDirectoryManifest(
  {
    authority,
    manifest,
    reason: "Rotation to attester set v2",
  },
  { canonicalAuth, signal: controller.signal },
);

await torii.revokeSpaceDirectoryManifest(
  {
    authority,
    uaid: "uaid:c2b61dd6bb73e91ee6d0949508d491bbc1b2a347a3f41b5cd35d733c1e751111",
    dataspaceId: 11,
    revokedEpoch: 9216,
    reason: "Emergency deny-wins trigger",
  },
  { canonicalAuth, signal: controller.signal },
);
```

The returned `transaction_payload_b64` and `signing_message_b64` must be
validated and signed locally. Submit the finalized signed transaction through
the normal transaction endpoint; preparation itself does not enqueue work.
`executeRamLfeProgram`, `verifyRamLfeReceipt`, `resolveIdentifier`, and
`issueIdentifierClaimReceipt` enforce the same exact-network canonical-account
contract (the claim account must also match the signed path). Canonical headers
are generated locally over the exact method, path, query, and body; callers
cannot supply precomputed headers or inline body secrets, and signed requests
are never redirected or retried.

RAM execution responses contain the output ciphertext and its execution receipt.
They do not contain a plaintext opening. Identifier resolution requires a separate,
independently authenticated plaintext opening supplied through `outputOpening`.
The current `bfv-affine-v1` and `bfv-programmed-v1` profiles are insecure and are
rejected by production execution and admission; private identifier execution
remains unavailable until a secure encryption profile is implemented and qualified.
`encryptIdentifierInputForPolicy` throws `RamLfeEncryptionUnavailableError`
with code `ram_lfe_encryption_unavailable` before reading policy or input. Seed
overrides and plaintext request-builder options are removed. Request builders
accept already-encrypted bytes and an independent opening; they do not establish
encryption support. Exact-lift arithmetic exists only in test fixtures.

## Sora VPN lease receipts

`submitVpnReceipt` returns earned/refund XOR fields and the native
`settleLeaseInstruction` that the operator must sign and submit. Its receipt
status is exactly `settlement_pending` while that instruction is uncommitted;
only a receipt later read from committed WSV state uses `settled`. The client
also retains the exact `disconnected`, `expired`, and `replaced` lifecycle
statuses and rejects padded or case-drifted spellings.

## SoraNet Puzzle & Token Service Client

The `SoranetPuzzleClient` helper talks to the optional
`soranet-puzzle-service` microservice so SDK consumers can mint Argon2 tickets,
inspect puzzle policy, and request ML-DSA-44 admission tokens without reimplementing
the HTTP transport. The client mirrors the JSON schema described in
[`specs/soranet/puzzle_service_operations.md`](../../specs/soranet/puzzle_service_operations.md).

```js
import { SoranetPuzzleClient } from "@iroha/iroha-js";

const puzzle = new SoranetPuzzleClient("http://localhost:8088", {
  defaultHeaders: {
    Authorization: `Bearer ${process.env.SORANET_PUZZLE_MINT_TOKEN}`,
  },
  timeoutMs: 5_000,
});

const config = await puzzle.getPuzzleConfig();
console.log(
  `difficulty=${config.difficulty} Argon2 lanes=${config.puzzle.lanes}`,
);

const ticket = await puzzle.mintPuzzleTicket("bb".repeat(32), {
  ttlSecs: 90,
});
console.log(
  `${ticket.credentialKind} ticket=${ticket.credentialB64} expires=${ticket.expiresAt}`,
);
if (ticket.signedTicketFingerprintHex) {
  console.log(`signed ticket fingerprint=${ticket.signedTicketFingerprintHex}`);
}

const token = await puzzle.mintAdmissionToken("aa".repeat(32), {
  ttlSecs: 300,
});
console.log(`token id=${token.tokenIdHex} issuer=${token.issuerFingerprintHex}`);
```

`mintPuzzleTicket` requires a nonzero 32-byte transcript hash as its first
argument. The service selects `credentialKind` from its immutable relay policy:
`raw` without a signed-ticket verifier key and `signed` when the verifier and
signing keys are configured. Signed responses include a
`signedTicketFingerprintHex` to help track replay cache state across restarts.

The service assigns admission-token issue times from its own clock; callers can
only request TTL. The mint and token-configuration endpoints require
the bearer credential stored in the service's `--mint-auth-token-path` file.
Run the plaintext service on loopback and terminate TLS at a local proxy. Use
`/v1/token/config` to display the active issuer fingerprint and revocation
window in operator tooling. Errors from the service propagate as
`SoranetPuzzleError` with `status`/`body` accessors so callers can feed
structured logs or retry policies easily.

## Kaigi Relay Telemetry

Relay operators and observability tooling can now inspect Kaigi health directly
from the SDK. The new helpers mirror the Torii endpoints so you can fetch
summaries, inspect a single relay, grab the aggregated health snapshot, or
stream the live registration/health SSE feed with domain/relay/kind filters:

```js
import { NetworkId, OperatorSigningContext, ToriiClient } from "@iroha/iroha-js";

const operatorSigningContext = new OperatorSigningContext(
  NetworkId.parse(exactNetworkId),
  runtimeOperatorSigner,
);
const torii = new ToriiClient(toriiUrl, { operatorSigningContext });

const relays = await torii.listKaigiRelays();
console.log(`registered relays: ${relays.total}`);
relays.items.forEach((relay) => {
  console.log(`${relay.relay_id} (${relay.domain}) status=${relay.status ?? "unknown"}`);
});

const detail = await torii.getKaigiRelay(relays.items[0]?.relay_id ?? "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE");
if (detail?.metrics) {
  console.log(`${detail.metrics.domain} registrations=${detail.metrics.registrations_total}`);
}

const health = await torii.getKaigiRelaysHealth();
console.log(
  `healthy=${health.healthy_total} degraded=${health.degraded_total} unavailable=${health.unavailable_total}`,
);

for await (const event of torii.streamKaigiRelayEvents({
  domain: "kaigi",
  kind: ["registration", "health"],
})) {
  if (event.data?.kind === "health") {
    console.log(`${event.data.relay_id} reported ${event.data.status}`);
    break;
  }
}
```

The three snapshot calls require that immutable exact-network context. Each call
generates fresh operator headers for the final encoded target and empty body,
then dispatches once with redirects and retries disabled; tokens and
precomputed operator headers are rejected. List and health also fail closed at
Torii's hard relay diagnostic cap instead of materializing an unbounded
registry. Keep signer material runtime-only.

`streamKaigiRelayEvents` yields strongly-typed SSE payloads so you can feed
operators dashboards without reimplementing filtering/normalisation logic. Its
SSE handshake remains a separate streaming protocol from the signed snapshot
reads.

## ISO 20022 Bridge

Submit ISO 20022 pacs.008 or pacs.009 payloads and poll their deterministic status
through the Torii bridge:

```js
import { NetworkId, OperatorSigningContext, ToriiClient } from "@iroha/iroha-js";

const operatorSigningContext = new OperatorSigningContext(
  NetworkId.parse(exactNetworkId),
  {
    publicKey: operatorPublicKey,
    sign: (message) => operatorSigner.sign(message),
  },
);
const torii = new ToriiClient(toriiUrl, { operatorSigningContext });
const xml = `<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.08">
  <!-- ... -->
</Document>`;

const status = await torii.submitIsoPacs008AndWait(xml, {
  profile: "swift-cbpr-plus",
  wait: {
    maxAttempts: 20,
    pollIntervalMs: 3_000,
    onPoll: ({ attempt, status }) => {
      const label = status?.status ?? "unknown";
      const hash = status?.transaction_hash ?? "<pending>";
      console.log(`[attempt ${attempt}] ${label} tx=${hash}`);
    },
  },
});
console.log(status.message_id, status.status, status.transaction_hash);
```

Every ISO submission and status poll requires this immutable exact-network
operator context. The SDK generates a fresh timestamp and nonce, signs the
exact method, path, sorted query, and body hash, and dispatches once with
redirect following disabled. Profile selection is the signed `profile` query
parameter. Bearer/API tokens, application-account auth headers, the retired
`X-Iroha-Iso-Profile` header, and caller-supplied operator headers are rejected
before dispatch.

`submitIsoPacs008` and `submitIsoPacs009` accept strings or binary buffers and
enforce `application/xml` content-type by default. `submitIsoPacs008AndWait` /
`submitIsoPacs009AndWait` build on those helpers to poll `/v1/iso20022/messages`
until the bridge reports a deterministic terminal state. Provide `wait` options
to customise the cadence, attach telemetry hooks, or opt into resolving as soon
as an `Accepted` status arrives (even before the Torii transaction hash is
available). If you already have a message identifier, call
`waitForIsoMessageStatus(messageId, waitOptions)` directly. Both helpers also
accept an `AbortSignal` so CI and long-running scripts can cancel pending
polls—pass `signal` inside `wait` options or call
`getIsoMessageStatus(id, { signal })` when you only need a single fetch.
Unknown fields inside `wait` options are rejected up front so mis-configured
automation fails before any network traffic is sent. Non-zero `pollIntervalMs`
values below 10 ms are rejected to avoid tight spin loops; keep `0` only for
deterministic unit tests and use sensible intervals in production flows.

`submitIsoMessage` combines the builders with the submission/wait helpers so callers can
provide structured ISO 20022 fields instead of hand-written XML. Pass `kind: "pacs.009"`
for PvP funding legs (defaults to pacs.008), and include `wait` options when you want the
helper to poll until Torii returns a deterministic status. The helper sets pragmatic MIME
types (`application/pacs008+xml` or `application/pacs009+xml`) and reuses the same
`AbortSignal` for both the submission and polling phases:

```js
const settlement = await torii.submitIsoMessage(
  {
    instructionId: "pvpfund-1",
    amount: { currency: "USD", value: "1250.50" },
    instigatingAgent: { bic: "BOFAUS3N" },
    instructedAgent: { bic: "DEUTDEFF" },
    purposeCode: "SECU",
  },
  {
    kind: "pacs.009",
    wait: { maxAttempts: 10, pollIntervalMs: 2_000 },
  },
);
console.log(settlement.status, settlement.transaction_hash);
```

Pass either `kind` or its alias `messageKind`; if both are provided they must match or the
helper will throw before any network requests are issued.

Pass a string `contentType` override when you submit namespaced XML (for
example, `application/pacs009+xml`). The helpers reject non-string or blank
overrides before issuing the HTTP request so CI jobs immediately surface
misconfigured headers instead of sending malformed traffic to Torii.

Attach a `retryProfile` when you need ISO submissions and status polls to ride a
custom retry budget (for example, an "iso" policy tuned for long-running bridge
workers). The same profile value flows into `waitForIsoMessageStatus`, so both
the submit and poll legs share the configured backoff.

All ISO bridge wait helpers throw `IsoMessageTimeoutError` when the message does
not reach a terminal status within the requested attempts.

### Generate camt.052 reports and camt.056 cancellation requests

The ISO helpers also cover the account-reporting (`camt.052`) and cancellation
(`camt.056`) schemas exercised by the ledger. Use the structured builders to avoid
manually stitching XML when you need to export statements or cancel pending transfers:

```js
import {
  buildCamt052Message,
  buildCamt056Message,
  buildSampleCamt052Message,
  buildSampleCamt056Message,
} from "@iroha/iroha-js";

const camt052 = buildCamt052Message({
  messageId: "report-20260305",
  creationDateTime: "2026-03-05T08:00:00Z",
  reportId: "report-20260305-page-1",
  pagination: { pageNumber: 1, lastPage: true },
  account: { otherId: "treasury-usd-001" },
  accountCurrency: "USD",
  balances: [
    {
      typeCode: "ITBD",
      amount: { currency: "USD", value: "950000.00" },
      creditDebitIndicator: "CRDT",
    },
  ],
  entries: [
    {
      amount: { currency: "USD", value: "5000.00" },
      creditDebitIndicator: "DBIT",
      status: "BOOK",
      reference: "pacs008-ffe5",
    },
  ],
});

const camt056 = buildCamt056Message({
  assignmentId: "cancel-ffe5",
  creationDateTime: "2026-03-05T10:00:00Z",
  cancellationId: "cancel-ffe5-tx",
  assignerAgent: { bic: "ALPHGB2L" },
  assigneeAgent: { bic: "OMEGGB2L" },
  debtorAgent: { bic: "ALPHGB2L" },
  creditorAgent: { bic: "OMEGGB2L" },
  originalMessageId: "pacs008-ffe5",
  originalMessageNameId: "pacs.008.001.08",
  interbankSettlementAmount: { currency: "USD", value: "5000.00" },
  interbankSettlementDate: "2026-03-05",
  originalInstructionId: "instr-ffe5",
  originalEndToEndId: "e2e-ffe5",
  originalTransactionId: "tx-ffe5",
});

// Sample helpers mirror the fixtures used in docs/tests.
const sampleReport = buildSampleCamt052Message();
const sampleCancellation = buildSampleCamt056Message();
```

Inputs are validated the same way as the pacs builders (BIC/IBAN/LEI checks,
ISO datetimes, CRDT/DBIT enumerations, pagination metadata), so malformed
reports or cancellation requests are rejected locally before hitting the Torii
bridge.

Bridge responses normalise `status` to `Pending`, `Accepted`, or `Rejected` and
ensure `pacs002_code` is one of `ACTC`, `ACSP`, `ACSC`, `ACWC`, `PDNG`, or
`RJCT`. Any other value raises a `TypeError` before the payload leaves the SDK,
so CI and operators catch unexpected bridge states immediately.

See `recipes/iso_bridge.mjs` for a runnable example that submits a sample
pacs.008 or pacs.009 payload, polls status with per-attempt logging, and shows
how to wire `ISO_POLL_ATTEMPTS`, `ISO_POLL_INTERVAL_MS`, `ISO_MESSAGE_ID`, and
`TORII_URL` through environment variables.

### ISO 20022 Message Builders

The SDK exports `buildPacs008Message` and `buildPacs009Message` helpers that map
structured inputs to standards-compliant XML while validating identifiers
described in the [ISO field mapping guide](../../specs/finance/settlement_iso_mapping.md).
Pass the required identifiers (BIC, amount, purpose code, etc.) and the helpers
emit deterministic XML payloads ready for submission via the Torii client. In
addition to the length/character checks, IBAN inputs must pass the canonical
mod-97 checksum so builders fail fast when an attestation hash contains a typo.
Creation timestamps must include a timezone offset (`Z` or `±HH:MM`) so the
payload is deterministic across hosts; timezone-less strings are rejected to
avoid lossy local-time conversions.

```js
import { buildPacs008Message, ToriiClient } from "@iroha/iroha-js";

const settlement = buildPacs008Message({
  messageId: "iso-demo-1",
  instructionId: "instr-1",
  settlementDate: "2026-02-10",
  amount: { currency: "EUR", value: "25.00" },
  instigatingAgent: { bic: "DEUTDEFF", lei: "529900ODI3047E2LIV03" },
  instructedAgent: { bic: "COBADEFF" },
  debtorAccount: { iban: "DE89370400440532013000" },
  creditorAccount: { otherId: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB" },
  purposeCode: "SECU",
  supplementaryData: { account_id: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB", leg: "delivery" },
});

const torii = new ToriiClient("http://localhost:8080");
const status = await torii.submitIsoPacs008AndWait(settlement, {
  wait: { maxAttempts: 15, pollIntervalMs: 3_000 },
});
console.log(status.status, status.transaction_hash);
```

For advanced flows, supply optional `debtorAgent`/`creditorAgent` (additional BIC/LEI pairs)
and `debtor`/`creditor` party metadata (legal name, LEI, proprietary IDs with custom scheme
codes). The builders insert those records as `DbtrAgt`/`CdtrAgt` and `Dbtr`/`Cdtr` elements so
PvP/RFQ pipelines can mirror the ISO 20022 guidance in
[`settlement_iso_mapping.md`](../../specs/finance/settlement_iso_mapping.md) without hand
crafting XML. Both builders also accept optional debtor/creditor accounts, purpose codes, and
structured supplementary JSON, making it trivial to carry Norito identifiers alongside the
standard MT-style fields.
Accounts may also carry proxy aliases (for example, phone-number or email handles) via
`proxy: { id, typeCode?, typeProprietary? }`. When present, the proxy is emitted under `Prxy`
alongside the IBAN, enforcing `Max2048Text` for the identifier and requiring either a 1-4
character type code or a proprietary label (but not both).
`buildPacs009Message` reuses the instruction id as both `MsgId` and `BizMsgIdr` when no explicit
message identifiers are provided and defaults `MsgDefIdr` to `pacs.009.001.08`, matching the
bridge’s canonical profile. When callers override `messageDefinitionId`, the helper uses the same
concrete value for both `MsgDefIdr` and the `Document` XSD namespace.
The `pacs.009` helper defaults `Purp` to `SECU` (the securities funding category purpose) but
accepts any valid ISO code when callers intentionally emit non-securities transfers; invalid
values still throw before submission so PvP funding flows stay aligned with the mapping guide
while other ISO scenarios remain supported.

Cash amounts are normalised to the correct ISO 4217 minor units before emission (for example,
`JPY` rejects fractional values, while `BHD` pads to three decimals). The helpers pad shorter
values with zeros and reject inputs that exceed the allowed precision so callers cannot produce
non-compliant interbank payloads.

The `recipes/iso_bridge_builder.mjs` example wires those helpers into a CLI that
derives sensible defaults, accepts overrides via environment variables or a JSON
config file, prints the generated XML, and optionally submits the message to
Torii when `ISO_SUBMIT=1`.

## Contract Deployment Helpers

Register manifests and bytecode directly from JavaScript without hand-crafting
Norito payloads. The SDK normalises hash literals, validates access-set hints,
and encodes code bytes as base64 strings before signing:

> Need a turnkey CLI instead of writing bespoke scripts? Use
> `javascript/iroha_js/recipes/contracts.mjs`. The helper reads your `.to`
> artifact (`CONTRACT_CODE_PATH`), requires a stable `CONTRACT_ALIAS`, and
> dispatches the alias-first deploy flow. Optional `CONTRACT_LEASE_EXPIRY_MS`
> lets CI stage leased alias bindings, and
> pass
> `TORII_AUTH_TOKEN`/`TORII_API_TOKEN` when the node is locked down.

```js
import { AccountAddress } from "@iroha/iroha-js";

const address = AccountAddress.fromAccount({
  publicKey: new Uint8Array(32),
});
console.log(address.canonicalHex());
console.log(address.toI105(753));
console.log(address.toI105());
```

```js
import {
  buildRegisterSmartContractCodeTransaction,
  buildRegisterSmartContractBytesTransaction,
  buildRemoveSmartContractBytesTransaction,
} from "@iroha/iroha-js";
import fs from "node:fs";

// Use the manifest emitted alongside this compiled artifact.
const manifest = JSON.parse(fs.readFileSync("./manifest.json", "utf8"));
const artifactId = { dataspaceId: "0", codeHash: manifest.code_hash };

const manifestTx = buildRegisterSmartContractCodeTransaction({
  networkId,
  authority,
  feePayment,
  artifactId,
  manifest,
  privateKey,
});

const codeTx = buildRegisterSmartContractBytesTransaction({
  networkId,
  authority,
  feePayment,
  artifactId,
  code: fs.readFileSync("./contract.to"),
  privateKey,
});

const removeBytesTx = buildRemoveSmartContractBytesTransaction({
  networkId,
  authority,
  feePayment,
  artifactId,
  reason: "retire archived artifact",
  privateKey,
});
```

Every artifact helper requires an explicit `{ dataspaceId, codeHash }` identity;
use a canonical decimal string for the full unsigned 64-bit dataspace range.
The same code hash in two dataspaces identifies two separately authorized artifacts.
Manifest registration also requires its `code_hash` to match that identity.
The local builder checks lifecycle kinds and permissions, unique declarations,
local callback targets, access-hint completeness and exact schema bindings before
native encoding. Unknown manifest fields, conflicting field aliases and textual
hashes without the Iroha marker bit are rejected. Native Norito encoding retains
`entrypoints`, `kotoba`, and `provenance`; committed ledger admission remains
authoritative. Bytecode helpers accept `Buffer`, typed arrays, or base64 strings.
`buildRemoveSmartContractBytesInstruction/Transaction` rejects empty reason strings.

Use `deploySmartContractBrowser` for the alias-first upload, manifest, and binding
workflow. Its authenticated deployment state supplies the dataspace ID.
`getContractManifest` and `getContractCodeBytes` take that explicit artifact ID
and canonical account authentication, and verify the returned network and scope.
Byte reads also verify the artifact hash. Standalone manifest registration uses
the ordinary signed transaction builders shown above.

The recipe mirrors the same validation rules: keys can be supplied as
`PRIVATE_KEY=ed25519:<hex>` or `PRIVATE_KEY_HEX=<hex>`, `CONTRACT_ALIAS`
selects the deploy dataspace via its suffix, and `CONTRACT_LEASE_EXPIRY_MS`
can stage a leased alias binding for rehearsal environments.

### Contract calls via Torii

`ToriiClient.prepareContractCall` wraps `/v1/contracts/call` and prepares an
unsigned transaction draft. The request contains the authority,
`contract_address` or `contract_alias`, the explicit entrypoint, optional
payload and metadata, typed `feePayment`, and an off-wire `draftIntent` built
from the locally verified contract artifact. Private signing material and the
intent are never sent to Torii. Contract drafts require canonical account HTTP
authentication and the exact nine-field transaction payload.
The client rejects the returned draft unless its exact network, authority,
executable, metadata, quoted fee, creation time, TTL, nonce,
and attachments match caller-trusted state. Sign only after that validation
succeeds, then submit the exact finalized transaction through the normal
transaction route.

```js
import { LocalSigningContext, NetworkId, ToriiClient } from "@iroha/iroha-js";

const torii = new ToriiClient(process.env.IROHA_TORII_URL, {
  canonicalRequestAuth: { accountId: AUTHORITY_ACCOUNT_ID, privateKey: runtimePrivateKey },
  authToken: process.env.IROHA_TORII_AUTH_TOKEN,
  localSigningContext: new LocalSigningContext(
    NetworkId.parse(EXACT_NETWORK_ID_LITERAL), networkPrefix,
  ),
});

const payload = { amount: 1 };
const contractAddress =
  "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw";
const response = await torii.prepareContractCall({
  authority: AUTHORITY_ACCOUNT_ID,
  contractAddress,
  entrypoint: "increment",
  payload,
  metadata: TRUSTED_FINAL_METADATA,
  feePayment: {
    payer: "authority",
    value: {
      charge_limits: [],
      gas_limit: 1_500_000,
    },
  },
  draftIntent: {
    executableB64: TRUSTED_EXECUTABLE_NORITO.toString("base64"),
    metadataB64: TRUSTED_FINAL_METADATA_NORITO.toString("base64"),
    contractAddress,
    codeHashHex: TRUSTED_CONTRACT_CODE_HASH_HEX,
    payloadDigestHex: contractPayloadDigestHex(payload),
  },
});

console.log("submitted:", response.submitted); // false
console.log("signing message:", response.signing_message_b64);
console.log("code hash:", response.code_hash_hex);
console.log("payload digest:", response.operation_receipt.payload_digest_hex);
```

Any browser-safe canonical JSON payload is cloned before submission so callers
can reuse the object elsewhere without mutation. Use safe integers and encode
decimal or wide numeric values as their canonical schema strings. The helper
rejects malformed entrypoint
selectors, missing or malformed typed fee intents, or invalid contract target
selectors before the request reaches Torii. `draftIntent` must come from a
trusted local builder or verified artifact/schema path; deriving its archives,
resolved address, code hash, or payload digest from the response being checked
defeats the trust boundary. The returned operation receipt is also checked
against that intent and the request's alias, entrypoint, fee gas bound, and
payload. Unsigned generic and contract-call multisig responses use the archive
intent requirement whenever `signatureB64` is absent. For detached/local
signing paths, use the explicit `/v1/fees/quote` flow described above instead of
the app-route convenience.

### Validation-fee policy and IVM proof status

The binding-only IVM proof-job and derivation routes were retired from Torii.
The SDK no longer exposes their request, response, polling or deployed-call
helpers. A new public preparation API depends on the complete authenticated
State and native-STARK execution relation. Constructing an `IvmProved`
transaction locally does not make it admissible: Core rejects private execution
proofs while that relation remains incomplete.

Validation-fee authority is ledger-native. Applications obtain bounded policy
proof pages with `ToriiClient.getValidationFeeCurrentPolicyProofPage`, anchored
to an immutable exact `NetworkId`/policy-chain binding and a durable checkpoint.
The ABI 29 native bridge verifies the Norito proof against the complete
independently selected native checkpoint and returns the policy projection together
with its promoted canonical checkpoint bytes. A checkpoint is exactly
`{ checkpointNorito: bytes }`; a height/context pair cannot replace it. Persist every
promoted checkpoint before requesting the next page. `catchUpValidationFeeCurrentPolicyProof` is available
when in-memory promotion is sufficient.

```js
const binding = {
  schema: "iroha.validation-fee-ledger-binding.v1",
  networkId: NetworkId.parse(TRUSTED_NETWORK_ID),
  policyChainGenesisHash: TRUSTED_POLICY_CHAIN_GENESIS_HASH,
  checkpoint: await loadDurableValidationFeeCheckpoint(),
};
const canonicalAuth = {
  accountId: AUTHORITY_ACCOUNT_ID,
  privateKey: AUTHORITY_PRIVATE_KEY,
};

let checkpoint = binding.checkpoint;
let page;
do {
  page = await torii.getValidationFeeCurrentPolicyProofPage(
    binding,
    checkpoint,
    { canonicalAuth },
  );
  await storeDurableValidationFeeCheckpoint(page.promotedCheckpoint);
  checkpoint = page.promotedCheckpoint;
} while (page.projection.more_available);

console.log("verified Parliament policy:", page.projection.current_policy);
```

Each projected Parliament authorization is the exact certificate-backed V1
record: `proposal_kind`, `proposal_operator`, `proposal_id`, `payload_hash`,
`governance_certificate_id`, `governance_certificate`,
`certified_at_height`, and `enacted_at_height`. The SDK rejects missing,
unknown, and structurally invalid nested fields, recursively checks the complete
certificate, and binds the proposal and canonical decimal-string heights to its
retained certificate.

Callers cannot provide validation-fee policy signatures, governance keysets, or
reserved policy metadata. Validator admission derives the active policy from
the Parliament registry and remains authoritative. An enabled first-release
policy requires the typed enacted lifecycle and immutable payout binding, and
charges exactly 10 minor units at scale 2 (`0.10`).

Validation-fee proposal IDs are available only through the native canonical
`ProposalKind` encoder. Both proposal kinds require the canonical proposal
operator, so a caller cannot fingerprint the same policy or payout binding
under a different retained proposer:

```js
import {
  computeValidationFeePayoutLifecycleProposalFingerprintV1,
  computeValidationFeePolicyProposalFingerprintV1,
} from "@iroha/iroha-js";

const lifecycleId =
  computeValidationFeePayoutLifecycleProposalFingerprintV1(
    PROPOSAL_OPERATOR_ACCOUNT_ID,
    payoutBinding,
  );
const policyId = computeValidationFeePolicyProposalFingerprintV1(
  PROPOSAL_OPERATOR_ACCOUNT_ID,
  policy,
  lifecycleId,
);
```

The native bridge rejects a missing or non-canonical operator plus missing,
extra, and non-canonical JSON fields before fingerprinting; these helpers do
not provide a JavaScript hashing fallback.

`computeIvmArtifactHashes(trustedArtifactBytes)` remains available from the
browser-safe `@iroha/iroha-js/ivm-artifact` export for independently checking
artifact identity. Its standalone DOM declarations do not require ambient Node
types. Complete artifacts are capped at 4 MiB (`IVM_ARTIFACT_MAX_BYTES`) before
copying or hashing; SharedArrayBuffer-backed inputs are rejected.

## Governance Proposal and Ballot Helpers

The governance ISI builders mirror the first-release Torii DTOs. Proposal
builders contain immutable proposal content only; Parliament derives lifecycle
timing and execution automatically. Hash inputs are normalized into the typed
32-byte governance hash wrappers, while ballot builders retain their standalone
referendum/election encoding:

```js
import { AccountAddress } from "@iroha/iroha-js";

const address = AccountAddress.fromAccount({ publicKey: new Uint8Array(32),
});
console.log(address.canonicalHex());
console.log(address.toI105(753));
console.log(address.toI105());
```

```js
import {
  buildProposeDeployContractTransaction,
  buildCastPlainBallotTransaction,
  buildCastZkBallotTransaction,
} from "@iroha/iroha-js";

const proposalTx = buildProposeDeployContractTransaction({
  networkId,
  authority,
  feePayment,
  proposal: {
    proposalOperator: authority,
    contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
    codeHash: Buffer.alloc(32, 0xaa),
    abiHash: `blake2b32:${"bb".repeat(32)}`,
    abiVersion: 1,
  },
  privateKey,
});

const zkOwner = "sorauﾛ1Ni1A1mYｲzｳﾚﾊGﾆｲgｵ4ﾜｾﾒﾔzｺﾍz6ﾀFoVDﾇXzｹCkﾙ4CQVXL"; // canonical I105 account id for ZK public inputs

const zkBallotTx = buildCastZkBallotTransaction({
  networkId,
  authority,
  feePayment,
  ballot: {
    electionId: "referendum-1",
    proof: Buffer.from(proofBytes),
    publicInputs: {
      owner: zkOwner,
      amount: "5000",
      duration_blocks: 7_200,
      direction: "Aye",
    },
  },
  privateKey,
});

const plainBallotTx = buildCastPlainBallotTransaction({
  networkId,
  authority,
  feePayment,
  ballot: {
    referendumId: "ref-plain",
    owner: authority,
    amount: "5000",
    durationBlocks: 7200,
    direction: "aye",
  },
  privateKey,
});

```

The local deployment builder accepts only a canonical `contractAddress`; alias
resolution belongs to Torii and is not available while building a transaction
offline. Its camel-case input is closed, ABI V1 is exact, and the optional
`manifestProvenance` object contains only `signer` and `signature`. ZK ballot
`publicInputs` are likewise closed to `root_hint`, `owner`, `amount`,
`duration_blocks`, `direction`, and `nullifier`. Durations retain the complete
u64 range and directions use exactly `Aye`, `Nay`, or `Abstain`.

Helper inputs accept either strings or raw `Buffer`s for 32-byte hashes and
convert proposal and ballot payloads to canonical Norito before signing.
Proposal timing, certification, and execution are Core-derived Parliament
state transitions and have no client-controlled lifecycle fields or terminal
builders.

See the source-checkout-only `recipes/governance.mjs` for an end-to-end script
that assembles the common governance transactions, prints deterministic hashes,
and optionally submits them to Torii (`GOV_SUBMIT=1`). Build the native binding
from the Iroha workspace first via `npm run build:native`; this recipe is not
part of the portable registry tarball.

## Confidential Asset Helpers

Node.js clients can register confidential assets and schedule policy
transitions without hand-writing Norito payloads. ABI V1 does not expose
generic shield, transfer, or unshield instructions; the instruction builders
and codec reject them.

```js
import { buildRegisterZkAssetTransaction } from "@iroha/iroha-js";

const registerTx = buildRegisterZkAssetTransaction({
  networkId,
  authority,
  feePayment,
  registration: {
    assetDefinitionId: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
    unshieldVerifyingKey: { backend: "halo2/ipa", name: "vk_unshield" },
  },
  privateKey,
});

```

`ProofAttachmentInput` requires the exact `{ backend, name }`
`verifyingKeyRef` shape; string shorthands, aliases, and embedded key bytes are
not accepted. Both id fields use the Rust portable registry grammar. Complete
ProofBox size is capped at 64 MiB, including the UTF-8 backend label, exact
canonical compact-length prefixes, and fixed V1 vector count. Prefix-width
transitions are charged exactly. Optional
`verifyingKeyCommitment` and `envelopeHash` digests must
be non-zero, and `envelopeHash` must equal the typed BLAKE2b-256 hash of the
proof bytes. Lane Merkle inputs require a complete 1–255-level path; raw
32-byte siblings are converted to canonical prehashed `HashOf` bytes before
Norito encoding. Election
builders (`buildCreateElectionTransaction`, `buildSubmitBallotTransaction`, and
`buildFinalizeElectionTransaction`) enforce the 2..=64 V1 election option
bound. Ballot ciphertexts and Halo2 proofs use canonical helper paths across
SDKs. See `index.d.ts` for the full set of confidential input shapes.

### Native-independent Exact12 fixture codec

`noritoDecodePrivacyExact12FixtureBundleBase64V1` reads the checked
`fixtures/privacy/exact12_typed_fixture_bundle_v1.norito.b64` archive without
loading `iroha_js_host`. The input must be exact canonical standard base64: no
whitespace, URL-safe alphabet, omitted padding, or alternate spelling is
accepted. The raw-byte companion
`noritoDecodePrivacyExact12FixtureBundleV1` enforces the 2 MiB archive bound,
canonical schema/header/layout, version 1, all twelve protocol rows in frozen
discriminant order, and the byte-complete statement, envelope, submission,
intent, unsigned-payload, signed-transaction, and transaction-hash bindings.

```js
import {
  noritoDecodePrivacyExact12FixtureBundleBase64V1,
  noritoEncodePrivacyExact12FixtureBundleV1,
} from "@iroha/iroha-js/norito";

const bundle = noritoDecodePrivacyExact12FixtureBundleBase64V1(checkedBase64);
const canonicalArchive = noritoEncodePrivacyExact12FixtureBundleV1(bundle);
```

Re-encoding a decoded checked bundle is byte-identical. Unknown fields,
aliases, reordered or substituted protocol rows, malformed declared lengths,
truncation, and trailing bytes fail closed.

The codec is exported by the package root and the browser-safe `./norito` leaf.
It is intentionally absent from the broad `./browser` facade so applications
that do not inspect release fixtures do not retain the complete Exact12 codec.

Binding-only IVM verifier labels are retired and rejected. Production proof-backed IVM invocation remains closed until the complete native execution relation and finalized State authority are implemented and qualified.

Verifying-key registry helpers mirror the Torii app API (`/v1/zk/vk/*`). Read
methods validate the canonical response before returning it; there is no parallel
raw/typed API or compatibility casing layer:

```js
import { LocalSigningContext, NetworkId, ToriiClient } from "@iroha/iroha-js";

const networkId = NetworkId.parse(process.env.IROHA_NETWORK_ID);

const torii = new ToriiClient("http://localhost:8080", {
  // Immutable local-signing context. Read-only clients may omit this.
  localSigningContext: new LocalSigningContext(networkId, networkPrefix),
});
const list = await torii.listVerifyingKeys({ backend: "halo2/ipa", status: "Active" });
console.log(list[0]?.record?.commitment_hex);
for await (const item of torii.iterateVerifyingKeys({ backend: "halo2/ipa", pageSize: 1 })) {
  console.log(item.id.name);
}

const detail = await torii.getVerifyingKey("halo2/ipa", "vk_main");
console.log(detail.record.status); // "Active"

const draft = await torii.registerVerifyingKey({
  authority: "sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB",
  backend: "halo2/ipa",
  name: "vk_main",
  version: 1,
  circuit_id: "halo2/ipa::transfer_v1",
  public_inputs_schema_hash_hex: "ab".repeat(32),
  gas_schedule_id: "halo2_default",
  vk_bytes: Buffer.from("vk-bytes"),
});
console.log(draft.submitted); // false
// Give transaction_payload_b64 and signing_message_b64 to the account's local
// wallet, then submit the assembled signed transaction with submitTransaction.
```

Register and update never accept private-key fields and never submit a
transaction. Torii returns a canonical unsigned draft with
`transaction_payload_b64` and `signing_message_b64`; key custody and signing
remain entirely in the client wallet. The client rejects drafts whose
transaction payload exceeds 16 MiB or whose 32-byte signing message is not the
canonical marker-adjusted Blake2b-256 Iroha hash of that payload. Before
returning a draft, it canonically decodes the Norito transaction and requires
the configured `NetworkId`, requested authority, exactly one requested
register/update instruction, and byte-exact equality of every verifying-key
record field. Register/update fail before the request when
`localSigningContext` was not configured; there is no raw-network, per-call, or
server-derived fallback.

## Connect Session Utilities

Connect overlays can now be bootstrapped directly from JS. The SDK exposes JSON
helpers alongside the existing WebSocket utilities so dApps can mint session
ids, preview deeplinks, and request role/management tokens in one path:

```js
import {
  NetworkId,
  ToriiClient,
  createConnectSessionPreview,
  bootstrapConnectPreviewSession,
} from "@iroha/iroha-js";

const torii = new ToriiClient("http://localhost:8080");
const networkId = NetworkId.parse(process.env.IROHA_NETWORK_ID);

const preview = createConnectSessionPreview({
  networkId,
  node: "torii.devnet.example",
});
console.log(preview.walletUri); // iroha://connect?sid=...
console.log(preview.appUri); // iroha://connect/app?sid=...

const session = await torii.createConnectSession({
  sid: preview.sidBase64Url,
  networkId: preview.networkId,
  appPublicKey: preview.appKeyPair.publicKey,
  nonce: preview.nonce,
  node: preview.node,
});

console.log(
  `tokens app=${session.token_app} wallet=${session.token_wallet} management=${session.token_management} relay=${session.token_relay}`,
);

// Or run the preview + registration flow in one step:
const { preview: bundledPreview, session: bundledSession, tokens: bundledTokens } =
  await bootstrapConnectPreviewSession(torii, {
    networkId,
    node: "torii.devnet.example",
    // override Torii node used during registration if needed:
    sessionOptions: { node: "torii.devnet.backup" },
  });
console.log(bundledPreview.walletUri);
console.log(`Connect session registered with tokens:`, bundledTokens?.wallet, bundledTokens?.relay);
```

`getConnectStatus()` reads the separate
`GET /v1/connect/status/aggregate` node diagnostic. It requires an immutable
exact-network `OperatorSigningContext` in the `ToriiClient` constructor and
dispatches once with a fresh operator signature. Load that context from
runtime-only operator configuration; never give it to a dApp or wallet. Apps
inspect only their own session through `GET /v1/connect/status?sid=...` with
the returned management token.

> **Note:** `sid` must encode exactly 32 bytes as either hexadecimal (with or without
> the `0x` prefix) or base64url per the Connect configuration. `createConnectSessionPreview`
> and `generateConnectSid` enforce the hashing rules described in `iroha_connect.md` so you
> don't need to hand-roll padding or domain separation.

### Connect registry administration

Platform teams can now manage Connect registry state directly from Node.js. The
client surfaces pagination helpers plus policy and manifest mutations so CI can
keep the overlay in sync with governance:

```js
const apps = await torii.listConnectApps({ limit: 10 });
const calc = apps.items.find((entry) => entry.appId === "calc.wallet");

const allAppIds = [];
for await (const app of torii.iterateConnectApps({ pageSize: 25 })) {
  allAppIds.push(app.appId);
}
console.log("connect registry apps:", allAppIds.join(", "));

await torii.registerConnectApp({
  appId: "calc.wallet",
  displayName: "Calc Wallet",
  namespaces: ["apps"],
  metadata: { website: "https://calc.example" },
  policy: { allow_guardian: true },
});

if (calc) {
  await torii.deleteConnectApp(calc.appId);
}

const policy = await torii.getConnectAppPolicy();
await torii.updateConnectAppPolicy({ ...policy, relayEnabled: true });

const manifest = await torii.getConnectAdmissionManifest();
await torii.setConnectAdmissionManifest({
  ...manifest,
  entries: manifest.entries.map((entry) => ({
    ...entry,
    namespaces: [...entry.namespaces, "preview"],
  })),
});
```

### Connect retry policy

`ConnectRetryPolicy` mirrors the Rust `connect_retry::policy` helper so browser and Node.js
clients share the same exponential back-off with full jitter (base 5 s, cap 60 s). Feed the
Connect session identifier into `delayMillis()` to derive deterministic jitter that matches
the Swift and Android SDKs:

```js
import { ConnectRetryPolicy } from "@iroha/iroha-js";

const sessionId = crypto.getRandomValues(new Uint8Array(32));
const retry = new ConnectRetryPolicy();
for (let attempt = 0; attempt < 5; attempt += 1) {
  const delayMs = retry.delayMillis(attempt, sessionId);
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  await reconnect();
}
```

Using a shared seed/attempt sequence keeps telemetry, dashboards, and dApp behaviour aligned across SDKs.

### Connect WebSocket sessions

Once a session is registered you can dial `/v1/connect/ws` without hand-building the query
parameters. `ToriiClient.openConnectWebSocket()` derives the canonical URL (switching
`http→ws`/`https→wss`) and instantiates whichever WebSocket implementation you provide.
In browsers the global `WebSocket` is used automatically; in Node.js pass a constructor such as
[`ws`](https://github.com/websockets/ws):

```js
import WebSocket from "ws";
import { ToriiClient } from "@iroha/iroha-js";

const torii = new ToriiClient("https://torii.nexus.example");
const session = await torii.createConnectSession({ sid: preview.sidBase64Url });

const socket = torii.openConnectWebSocket({
  sid: session.sid,
  role: "wallet",
  token: session.token_wallet,
  protocols: ["iroha-connect"],
  // For Node/`ws`, headers are attached automatically; provide websocketOptions to add your own.
  websocketOptions: { headers: { "x-debug": "1" } },
  WebSocketImpl: WebSocket,
});

socket.on("open", () => console.log("Connect WS ready"));
socket.on("message", (data) => console.log("frame", data));
```

When you only need the canonical URL, call `ToriiClient.buildConnectWebSocketUrl()` (or the
top-level `buildConnectWebSocketUrl(baseUrl, { sid, role, token })`) and hand it to your own
WebSocket/queue implementation. Tokens are carried via `Authorization: Bearer` headers by default,
and browser clients automatically attach a `Sec-WebSocket-Protocol: iroha-connect.token.v1.<b64url(token)>`
marker so secrets stay out of referrers. The module also exports `openConnectWebSocket(options)` which accepts an
explicit `baseUrl` for cases where you are not holding a `ToriiClient` instance. Both helpers reject
endpoint host/protocol overrides when a token is present (to prevent cross-host leaks) and will only
dial insecure `ws://` URLs when `allowInsecure: true` is set. When you call
`torii.openConnectWebSocket()` the `allowInsecure` flag and `insecureTransportTelemetryHook` are
inherited from the client config; standalone calls can supply their own
`insecureTransportTelemetryHook` to log or alert on insecure opt-ins during local development. Notes:

- Keep endpoint hosts/schemes aligned with the Torii base; credentialed calls reject overrides.
- Enable telemetry hooks to detect accidental `ws://` usage during development.
- Use `token_management` for session deletion and `GET /v1/connect/status?sid=...`.
- Deep links include `relay=<token_relay>`; SDKs bind that relay token into approval signatures and
  Torii uses it to authenticate cross-node Connect relay envelopes.
- In broadcast relay mode, Torii also gossips session claims over authenticated
  Iroha P2P so app and wallet WebSockets can attach through different Torii
  nodes. Claims carry token hashes plus the relay MAC key, never raw app,
  wallet, or management tokens.

### Connect error taxonomy

`ConnectError`, `ConnectQueueError`, and `connectErrorFrom()` mirror the shared taxonomy
documented in [`specs/connect_error_taxonomy.md`](../../specs/connect_error_taxonomy.md).
Wrap every failure that bubbles up from the Connect transport (WebSocket, fetch, codecs, queue)
before emitting telemetry so dashboards can rely on consistent `category`/`code` pairs:

```js
import {
  ConnectQueueError,
  connectErrorFrom,
} from "@iroha/iroha-js";
import { telemetry } from "./telemetry.js";

try {
  await queue.enqueue(frame);
} catch (error) {
  const connectError = connectErrorFrom(error);
  telemetry.emit("connect.error", connectError.telemetryAttributes({ fatal: true }));
  throw connectError;
}

const overflow = ConnectQueueError.overflow(256);
const attrs = overflow.toConnectError().telemetryAttributes();
console.log(attrs.category); // "queueOverflow"
console.log(attrs.code); // "queue.overflow"
```

`connectErrorFrom()` inspects HTTP status codes, Node.js error codes (TLS, socket, timeout),
`DOMException` names, and codec failures so Connect clients do not need bespoke switch statements.
If you implement a custom error type, expose `toConnectError()` and return a `ConnectError`
instance; the helper will pass it through unchanged.

### Connect queue journal

Use `ConnectQueueJournal` to persist Connect queue entries inside the browser.
The journal mirrors the Swift/Android file layout: entries are encoded as
`ConnectJournalRecordV1` Norito blobs, session identifiers are hashed with SHA-256,
and a background retention policy prunes expired or excess entries.

```js
import {
  ConnectDirection,
  ConnectQueueJournal,
} from "@iroha/iroha-js";

const journal = new ConnectQueueJournal(preview.sidBase64Url, {
  maxRecordsPerQueue: 32,
  maxBytesPerQueue: 1 << 20,
  storage: "indexeddb",
});

await journal.append(
  ConnectDirection.APP_TO_WALLET,
  frame.sequence,
  frame.ciphertext,
  { ttlMs: 60_000 },
);

const pending = await journal.records(ConnectDirection.APP_TO_WALLET);
const drained = await journal.popOldest(ConnectDirection.APP_TO_WALLET, 1);
```

IndexedDB is the default browser store. Use `storage: "memory"` only when a
test harness intentionally wants ephemeral storage. Applications can inspect
`journal.sessionKey` to derive deterministic evidence paths.

### Connect queue diagnostics

Queue diagnostics helpers mirror the new `iroha connect queue inspect` CLI workflow so Node.js
automation can persist the same telemetry/evidence bundles produced by Swift/Android tooling.

```js
import {
  appendConnectQueueMetric,
  exportConnectQueueEvidence,
  readConnectQueueSnapshot,
  updateConnectQueueSnapshot,
} from "@iroha/iroha-js";

const sid = preview.sidBase64Url;
await updateConnectQueueSnapshot(
  sid,
  (snapshot) => ({
    ...snapshot,
    state: "throttled",
    reason: "disk_watermark",
    app_to_wallet: { ...snapshot.app_to_wallet, depth: 12 },
  }),
);

await appendConnectQueueMetric(sid, {
  state: "throttled",
  app_to_wallet_depth: 12,
  wallet_to_app_depth: 3,
  reason: "disk_watermark",
});

const { manifest, targetDir } = await exportConnectQueueEvidence(sid, "./artifacts/connect-queue");
console.log(`Evidence bundle for ${manifest.session_id_base64} written to ${targetDir}`);
```

Operators can then run `iroha connect queue inspect --sid <sid> --root ~/.iroha/connect --metrics`
to print the same snapshot/telemetry summary captured above.

## Config Introspection

`extractToriiFeatureConfig()` normalises the ISO bridge and Connect sections
from a parsed `iroha_config`. It performs light validation, renames fields into
camelCase, and surfaces optional signer metadata so dashboards or CLIs can
display feature state without manual JSON parsing.

`extractConfidentialGasConfig()` returns the confidential verification gas schedule
(`proofBase`, `perPublicInput`, `perProofByte`, `perNullifier`, `perCommitment`) so tooling can
surface node gas policy without spelunking raw JSON.

```js
import { ToriiClient } from "@iroha/iroha-js";

const client = new ToriiClient("http://localhost:8080");
const gas = await client.getConfidentialGasSchedule();
if (gas) {
  console.log(`Proof base cost: ${gas.proofBase}`);
}
```

### Configuration snapshots

`getConfigurationTyped()` returns the `/v1/configuration` payload with typed fields so automation
can record logger/network queue settings without hand-parsing JSON.

```js
const torii = new ToriiClient("http://localhost:8080");
const snapshot = await torii.getConfigurationTyped();
if (snapshot) {
  console.log("Node key:", snapshot.publicKeyHex);
  console.log("Block gossip size:", snapshot.network.blockGossipSize);
  if (snapshot.queue) {
    console.log("Queue capacity:", snapshot.queue.capacity);
  }
  if (snapshot.confidentialGas) {
    console.log("Conf gas per nullifier:", snapshot.confidentialGas.perNullifier);
  }
  if (snapshot.transport?.noritoRpc) {
    console.log("Norito-RPC stage:", snapshot.transport.noritoRpc.stage);
  }
}
```

### Runtime and capability helpers

`ToriiClient` now covers the runtime capability endpoints so SDK consumers can surface ABI
versioning data without crafting raw HTTP calls. Use `getNodeCapabilities()` to inspect ABI
support and cryptography acceleration flags, `getRuntimeAbiActive()`/`getRuntimeAbiHash()` to
mirror the compiler guardrails, `getRuntimeMetrics()` for aggregate counters, and
`listRuntimeUpgrades()` to page through recorded manifests. The helper trio
`proposeRuntimeUpgrade()`, `activateRuntimeUpgrade()`, and `cancelRuntimeUpgrade()` post the
runtime JSON endpoints and return transaction skeletons (`wire_id` + payload hex) that you can
sign via `TxBuilder`, so rollout automation no longer needs bespoke HTTP clients.

```js
const torii = new ToriiClient("http://localhost:8080");
const caps = await torii.getNodeCapabilities();
console.log("ABI version", caps.abiVersion);
console.log("Allowed curve IDs", caps.crypto.curves.allowedCurveIds);
console.log("Allowed curve bitmap", caps.crypto.curves.allowedCurveBitmap);

const abi = await torii.getRuntimeAbiActive();
console.log(`Runtime ABI v${abi.abiVersion}`);

const upgrades = await torii.listRuntimeUpgrades();
for (const item of upgrades) {
  console.log(`${item.idHex} -> ${item.record.status.kind}`);
}

const manifest = {
  name: "ABI v1 maintenance",
  description: "Schedule a no-ABI-change runtime rollout",
  abiVersion: 1,
  abiHash: "0123...cdef",
  startHeight: 10_000,
  endHeight: 10_500,
};
const draft = await torii.proposeRuntimeUpgrade(manifest);
console.log(draft.tx_instructions);
```

### Network time helpers

`getNetworkTimeNow()` mirrors `/v1/time/now` so you can validate the network timestamp, offset,
and confidence window exposed by the node. `getNetworkTimeStatus()` wraps the node-local
`/v1/time/status` diagnostic and returns the peer sampling plus RTT histogram that the NRPC/AND7
runbooks consume. The status helper, `listPeers()`, `getPipelinePreflight()`, and
`getPipelineRecovery()` require an immutable `OperatorSigningContext` for the exact genesis
`NetworkId`. Each call signs the exact `GET`, substituted path, query, and empty body, dispatches
once, and rejects redirects, retries, tokens, and precomputed authentication headers.

```js
const torii = new ToriiClient("http://localhost:8080", { operatorSigningContext });
const ntsNow = await torii.getNetworkTimeNow();
console.log(`cluster time=${ntsNow.timestampMs} offset=${ntsNow.offsetMs}ms`);

const status = await torii.getNetworkTimeStatus();
for (const sample of status.samples) {
  console.log(sample.peer, sample.lastOffsetMs, sample.lastRttMs, sample.count);
}
console.log("histogram", status.rtt.buckets);
```

`getPipelinePreflight()` parses exactly the fields Torii serves and rejects any
other field. It exposes both `ivm_max_cycles_upper_bound` and
`ivm_admission_cycle_limit`. Its fee-account fields contain exact canonical I105
account ids; alias-shaped `name@domain` values are rejected as protocol drift.
The `sumeragi` section carries only `block_cadence_ms`, the signed-genesis
target block time. Torii serves no stall threshold, so the result's
`stallThresholdMs` is derived as 20 × `block_cadence_ms`, and
`isStatusStalled(status)` reports a stall only when `status.queue_size > 0` and
the time since the last non-empty block (or since the last block, before the
first non-empty one) exceeds it. Twenty cadences cover one crashed leader's view
change at the Sumeragi default timings; pass a deployment-specific threshold to
`isStatusQueueStalled(status, thresholdMs)` instead when the local consensus
timers are known.

```js
import { AccountAddress } from "@iroha/iroha-js";

const address = AccountAddress.fromAccount({ publicKey: new Uint8Array(32),
});
console.log(address.canonicalHex());
console.log(address.toI105(753));
console.log(address.toI105());
```

```js
import { extractToriiFeatureConfig } from "@iroha/iroha-js";

const config = JSON.parse(fs.readFileSync("iroha_config.json", "utf8"));
const features = extractToriiFeatureConfig({ config });

if (features.isoBridge?.enabled) {
  console.log(`Aliases: ${features.isoBridge.accountAliases.length}`);
}
console.log(`Connect enabled: ${features.connect?.enabled ?? false}`);
```

## Continuous Integration

- See `specs/sdk/js/quickstart.md` for an expanded walkthrough covering key management, transaction assembly, Torii configuration, and CI tips.

- Cache both `npm` and `cargo` directories so native bindings rebuild quickly across matrix runs.
- Run `npm run lint:test` before the dockerised integration job. The script enforces ESLint with zero warnings, builds the native addon, and runs the zero-skip hermetic profile. Release CI separately provisions and runs the 1 GiB and live qualification profiles.
- Test the declared minimum Node 20.19.0 and the existing Node 20, 22 and 24 CI lines alongside the `rust-toolchain.toml` version. These selectors do not establish release qualification; retain the exact runtime version and matching-candidate results.
- Use `node scripts/run-test-profile.mjs unit` for quick hermetic runs when native artifacts are already built. The profile refreshes `dist` from the current source before testing packaged browser exports. Raw `node --test` intentionally selects the fail-closed live and 1 GiB lanes as well.
- Layer any project-specific linting or formatting checks on top of `npm run lint:test` if your monorepo enforces stricter policies.
- See `specs/examples/iroha_js_ci.md` for extended guidance and optional smoke-job templates.

```yaml
name: iroha-js-ci

on:
  push:
    branches: [ main ]
  pull_request:

jobs:
  build:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node-version: ["20.19.0", 20, 22, 24]
    steps:
      - uses: actions/checkout@v4

      - name: Set up Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: npm

      - name: Set up Rust toolchain
        uses: dtolnay/rust-toolchain@v1
        with:
          toolchain: stable

      - name: Cache cargo build artifacts
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}

      - run: npm ci --ignore-scripts
      - run: npm run lint:test
```

## Integration Smoke Tests

`test/integrationTorii.test.js` exercises a live Torii node when the relevant
environment variables are set. The hermetic `npm test` profile excludes this
file; selecting the live suite without `IROHA_TORII_INTEGRATION_URL` fails.

- `IROHA_TORII_INTEGRATION_URL` — Torii base URL (required to enable the test).
- `IROHA_TORII_INTEGRATION_API_TOKEN` — optional API token for secured nodes.
- `IROHA_TORII_INTEGRATION_AUTH_TOKEN` — optional bearer token for auth-protected deployments.
- `IROHA_TORII_INTEGRATION_CONFIG` — optional path to an `iroha_config` JSON file; when present the test asserts that `extractToriiFeatureConfig()` normalises ISO bridge and Connect settings.
- `IROHA_TORII_INTEGRATION_CONNECT_SESSION` — optional JSON string containing the exact registration payload for `createConnectSession()`: `sid`, canonical `network_id`, base64url `app_pk`, base64url `nonce`, and optional `node`.
- `IROHA_TORII_INTEGRATION_CONNECT_PREVIEW` — optional JSON object consumed by the Connect preview bootstrapper test (`{"network_id":"hash:<64 uppercase hex>#<CRC16>","node":"torii.devnet.example","sessionOptions":{"node":"ingress.devnet.example"}}`). When present and `IROHA_TORII_INTEGRATION_MUTATE=1`, the suite calls `bootstrapConnectPreviewSession()`, validates the deeplink URIs/tokens, and deletes the staged session.
- `IROHA_TORII_INTEGRATION_CONNECT_APP` — optional JSON object describing a Connect app registration payload (`{"appId":"demo","namespaces":["apps"],"metadata":{"suite":"ci"}}`); when present and `IROHA_TORII_INTEGRATION_MUTATE=1`, the suite registers the app, verifies that list/get/iterator APIs return it, and then deletes it.
- `IROHA_TORII_INTEGRATION_CONTRACT_CALL` — optional JSON object describing a contract call payload (for example: `{"contractAddress":"irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw","entrypoint":"ping","payload":{"value":1},"feePayment":{"payer":"authority","value":{"charge_limits":[{"kind":{"kind":"pipeline_gas","value":null},"asset_definition_id":"xor#universal","max_amount":"1500000"}],"gas_limit":1500000}}}`). When supplied alongside `IROHA_TORII_INTEGRATION_MUTATE=1`, the suite invokes `ToriiClient.prepareContractCall` and validates the returned local-signing draft. The helper accepts camelCase keys plus overrides for `authority` and the required exact quoted `feePayment` intent.
- `IROHA_TORII_INTEGRATION_GOV_BALLOT` — optional JSON object ({`referendumId`,`owner`,`amount`,`durationBlocks`,`direction`} are the common keys) drafted via `governanceSubmitPlainBallot` when `IROHA_TORII_INTEGRATION_MUTATE=1`. Missing fields default to the configured `authority` and exact `NetworkId`, so the env var only needs vote-specific fields.
- `IROHA_TORII_INTEGRATION_NETWORK_ID` — canonical checksummed genesis-derived `NetworkId` used by Connect, governance drafts, and ordinary mutation transactions.
- `IROHA_TORII_INTEGRATION_ACCOUNT_ID` / `IROHA_TORII_INTEGRATION_PRIVATE_KEY_HEX` — optional overrides for the default signer (`defaults/client.toml`); the defaults target the canonical encoded account id derived from `account.public_key`.
- `IROHA_TORII_INTEGRATION_MUTATE` — set to `1` to enable mutation tests (registering disposable domains via the builder helpers). The docker harness described below enables this flag automatically.
- `IROHA_TORII_INTEGRATION_STREAM_ENABLED` — set to `1` (alongside `IROHA_TORII_INTEGRATION_MUTATE=1`) to exercise the event-stream coverage that waits for a `Pipeline.Block` SSE and asserts the typed payload mirrors Torii’s stream schema. Leave unset when SSE endpoints are disabled or proxied away.
- `IROHA_TORII_INTEGRATION_ISO_ENABLED` — set to `1` to exercise the ISO bridge smoke test (submits a tiny `pacs.008` payload and fetches its status). Leave unset/`0` to skip the ISO coverage when the bridge runtime is disabled.
- `IROHA_TORII_INTEGRATION_ISO_PACS008` — optional JSON object merged into the default ISO builder fields (useful for overriding BICs/amounts/message IDs when replaying production fixtures).
- `IROHA_TORII_INTEGRATION_ISO_PACS009` — optional JSON object merged into the default pacs.009 builder fields (same structure as the pacs.008 overrides; handy for replaying RTGS transfers with custom identifiers).
- `IROHA_TORII_INTEGRATION_ISO_ALIAS` — optional ISO alias (for example, `GB82 WEST 1234 5698 7654 32`) used by the alias-resolution integration test. Set alongside `IROHA_TORII_INTEGRATION_ISO_ENABLED=1` when the ISO runtime is active.
- `IROHA_TORII_INTEGRATION_ISO_ALIAS_INDEX` — optional deterministic index (integer) for exercising `resolveAliasByIndex`. Provide this when the target node exposes indexed alias metadata so the integration suite can cover both alias endpoints.
- `IROHA_TORII_INTEGRATION_SORAFS_ENABLED` — set to `1` to run the SoraFS registry/storage, payload-range, and PoR tests. An enabled SoraFS lane fails unless the payload manifest, positive range length, and PoR week inputs are all supplied and the endpoints respond.
- `IROHA_TORII_INTEGRATION_SORAFS_POR_WEEK` — ISO week label such as `2026-W05`, required when `IROHA_TORII_INTEGRATION_SORAFS_ENABLED=1`.
- `IROHA_TORII_INTEGRATION_UAID` — optional exact lower-case UAID literal (`uaid:<64-hex>`, LSB=1). When provided, the integration suite exercises the UAID portfolio/bindings/manifests endpoints so cross-dataspace APIs stay covered.
- `IROHA_TORII_INTEGRATION_UAID_DATASPACE` — optional dataspace id (non-negative integer) used to scope the UAID manifest request when `IROHA_TORII_INTEGRATION_UAID` is set. Leave unset to fetch manifests across every dataspace.
- `IROHA_TORII_INTEGRATION_SNS_SUFFIX` — optional SNS suffix id (u16) used to fetch the suffix policy snapshot. Supply alongside `IROHA_TORII_INTEGRATION_URL` to exercise the SNS policy smoke test.
- `IROHA_TORII_INTEGRATION_SNS_SELECTOR` — optional canonical name selector (for example `wonderland.sora`) used to fetch an SNS registration record.
- `IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_ENABLED` — set to `1` (alongside `IROHA_TORII_INTEGRATION_MUTATE=1`) to run the Space Directory manifest publish/revoke smoke tests. Supply a manifest JSON path via `IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_MANIFEST` (absolute or relative to the repo root; for example `fixtures/space_directory/capability/retail_dapp_access.manifest.json`). `IROHA_TORII_INTEGRATION_SPACE_DIRECTORY_REVOKE_EPOCH=<epoch>` overrides fixture epochs and is mandatory in qualification mode.
- `IROHA_TORII_INTEGRATION_DA_ENABLED` — set to `1` (and enable `IROHA_TORII_INTEGRATION_MUTATE=1`) to exercise the data-availability ingest smoke test (`submitDaBlob` + manifest polling). Leave unset when the DA ingest pipeline is disabled on the target Torii deployment.
- `IROHA_TORII_INTEGRATION_DA_TICKET` — optional hex-encoded storage ticket used to fetch an existing manifest bundle when DA endpoints are read-only or when you want to validate a production capture without submitting a new blob.
- `IROHA_TORII_INTEGRATION_DA_GATEWAYS` — optional JSON array describing the gateway providers used by `fetchDaPayloadViaGateway` (for example `[{"name":"gw-a","providerIdHex":"…","gatewayPublicKeyHex":"…","baseUrl":"https://gw-a.example","streamTokenB64":"..."}]`). Supply this alongside `IROHA_TORII_INTEGRATION_DA_TICKET` to stream proofs through the multi-source orchestrator.

Example invocation:

```bash
IROHA_TORII_INTEGRATION_URL=http://localhost:8080 \
IROHA_TORII_INTEGRATION_API_TOKEN=dev-token \
node --test javascript/iroha_js/test/integrationTorii.test.js
```

### Dockerised harness (`npm run test:integration`)

Use the bundled integration harness to spin up the four-validator Docker
Compose topology, wait for `/status`, and run the mutation-enabled smoke suite.
The `docker-compose.single.yml` filename is retained for compatibility; it no
longer denotes a one-validator network.

```bash
export IROHA_GENESIS_SIGNED_FILE="$PWD/target/js-integration-genesis/genesis.signed.nrt"
export IROHA_GENESIS_PUBLIC_KEY_FILE="$PWD/target/js-integration-genesis/genesis.public_key"
export IROHA_GENESIS_EXPECTED_HASH_FILE="$PWD/target/js-integration-genesis/genesis.expected_hash"
npm run test:integration
```

The default stack is an explicitly seeded development fixture. Prepare those
artifacts for its exact validator roster with Kagami beforehand; do not reuse a
random localnet body. The stack contains no genesis signing key or runtime
signer; the harness validates all three read-only inputs before starting it.
Normal generated deployments use seedless `kagami docker` prepared-bundle mode
and embed validated artifact paths directly.

`scripts/run_integration.mjs` performs the following steps:

1. Runs `npm ci` and rebuilds the native binding.
2. Starts all four validators in
   `defaults/docker-compose.single.yml` unless `--no-start` (or
   `JS_TORII_START=0`) is supplied. Use `--service` only to select one
   explicit service for a custom workflow.
3. Waits up to 90 s for `http://127.0.0.1:8080/status` (override via
   `--torii-url`/`--wait-seconds`/`IROHA_TORII_INTEGRATION_URL`).
4. Sets the mutation env vars (chain id, account id, private key) and runs
   `node --test test/integrationTorii.test.js`.
5. Tears the compose stack down (`down --remove-orphans`) on success or failure.

Flags/environment variables:

- `--compose-file` (or `JS_TORII_COMPOSE_FILE`) to point at a custom compose manifest.
- `--service` / `COMPOSE_SERVICE` to start only one explicitly selected
  service instead of the full validator stack.
- `--compose-bin` / `JS_TORII_COMPOSE_BIN` to use a non-default compose command.
- `IROHA_GENESIS_SIGNED_FILE`, `IROHA_GENESIS_PUBLIC_KEY_FILE`, and
  `IROHA_GENESIS_EXPECTED_HASH_FILE` supply the runtime-only trust-root bundle
  required by the default Compose manifest.
- `--no-start` to reuse an existing node (the harness still waits for `/status`).
- `--qualification` (or `JS_TORII_QUALIFICATION=1`) to require the complete live SoraFS, UAID/dataspace, Space Directory, DA ticket, and dual-gateway input set before any test starts. `npm run test:integration:qualification` is the equivalent package command.
- Pass additional `node --test` arguments after `--`, for example:

  ```bash
  npm run test:integration -- -- --test-name-pattern=torii
  ```
- `--enable-iso` (or `JS_TORII_ENABLE_ISO=1`) to flip on the ISO bridge smoke tests without
  setting `IROHA_TORII_INTEGRATION_ISO_ENABLED` manually. Combine with
  `--iso-alias <alias>`/`--iso-alias-index <index>` to pre-populate the ISO alias inputs used by
  `resolveAlias`/`resolveAliasByIndex`, and `--iso-pacs008 <json-or-path>` /
  `--iso-pacs009 <json-or-path>` to feed override payloads into the builders. The JSON arguments
  accept inline objects or filesystem paths (absolute or relative to the repo root); the harness
  validates and forwards the resulting string to
  `IROHA_TORII_INTEGRATION_ISO_PACS008`/`IROHA_TORII_INTEGRATION_ISO_PACS009`.

Each run registers a fresh domain (prefixed `jsintegration-…`) so repeated
executions remain deterministic. Clean up by truncating the devnet database or
recreating the Docker stack.

With `IROHA_TORII_INTEGRATION_MUTATE=1`, the suite now:

1. Registers disposable domains, universal domainless accounts, and asset
   definitions independently; account registration never carries a domain id.
2. Mints and re-mints the asset, transfers balances via the iterator helpers,
   and queries the relevant lists through both `/list` and `/query` endpoints.
3. Optionally submits a `pacs.008` message (when `IROHA_TORII_INTEGRATION_ISO_ENABLED=1`)
   to verify the bridge pipeline end-to-end.
4. Optionally inspects the SoraFS pin registry (when `IROHA_TORII_INTEGRATION_SORAFS_ENABLED=1`),
   using canonical account signatures for the alias/replication inventory
   projections. Operator-only storage-state and payload-fetch
   diagnostics are intentionally excluded from the public integration client.
5. Optionally submits a DA ingest payload and polls the manifest endpoint (when
   `IROHA_TORII_INTEGRATION_DA_ENABLED=1`), and can stream multi-source fetch
   evidence when `IROHA_TORII_INTEGRATION_DA_GATEWAYS`/`IROHA_TORII_INTEGRATION_DA_TICKET`
   are set.
6. Optionally listens for a `Pipeline.Block` event (when
   `IROHA_TORII_INTEGRATION_STREAM_ENABLED=1`) to prove the streaming helpers stay in lockstep
   with Torii’s SSE payloads before the ISO/SoraFS/DA suites run.

## Collection queries

| Collection | Client member | Request |
| --- | --- | --- |
| domains | `torii.domains` | `POST /v1/domains/query` |
| accounts | `torii.accounts` | `POST /v1/accounts/query` |
| asset definitions | `torii.assetDefinitions` | `POST /v1/assets/definitions/query` |
| NFTs | `torii.nfts` | `POST /v1/nfts/query` |
| RWA lots | `torii.rwas` | `POST /v1/rwas/query` |
| repo agreements | `torii.repoAgreements` | `POST /v1/repo/agreements/query` |
| account assets | `torii.accountAssets(accountId)` | `POST /v1/accounts/{account_id}/assets/query` |
| asset holders | `torii.assetHolders(definitionId)` | `POST /v1/assets/{definition_id}/holders/query` |
| transactions | `torii.transactions` | `POST /v1/transactions/query` |
| account transactions | `torii.accountTransactions(accountId)` | `POST /v1/accounts/{account_id}/transactions/query` |

Each member is a `ToriiCollection` with `list(query?, options?)`,
`pages(query?, options?)` and `iterate(query?, options?)`. `ToriiClient` and
`ToriiBrowserClient` share the implementation. A query has these optional
members:

| Member | Value |
| --- | --- |
| `filter` | a `Filter` built with `field()`, a text filter (sent unchanged) or the JSON form `{op, args}` |
| `sort` | `"-quantity,id"`, an array of keys, or `SortKey` values; at most 8 keys |
| `select` | field paths such as `["id", "alias_binding.status"]`; items keep their row paths |
| `aggregate` | `{groupBy, metrics: [{alias, fn, field?}], having?}`; cannot be combined with `select` |
| `limit` | page size (`1..u32`); the server default applies when absent |
| `cursor` | the previous page's `nextCursor` |
| `includeTotal` | `true` adds the exact `total` (a full scan) |

A page is `{ items, nextCursor, total }`. `total` is present only when
`includeTotal` was requested, and is a `bigint` beyond
`Number.MAX_SAFE_INTEGER`. Integers in items beyond that range are also `bigint`.
Only the fields that identify a row are always present (`id`; `account_id`,
`asset`, `scope` and `quantity` for balances; `entrypoint_hash`,
`block_height` and `block_index` for transactions); treat every other field as
possibly `null` or absent, as the row types do.

Pass field paths raw (`field("metadata.ui-order")`, `select`, `groupBy`): the
SDK backtick-quotes non-identifier segments wherever Torii parses text, so the
filter renders as ``metadata.`ui-order` >= 2`` and the sort key as
``"-metadata.`ui-order`"`` in both the JSON body and the `GET` form.

```js
import { Filter, ListQuery, field } from "@iroha/iroha-js";

const active = field("status").in(["active", "paused"]).or(field("metadata.archived").exists().not());
console.log(active.toString()); // status in ["active", "paused"] or not exists(metadata.archived)
console.log(JSON.stringify(active)); // {"op":"or","args":[...]}
// Parse text yourself to validate it early; bad input throws a FilterSyntaxError
// (code `invalid_filter`) with `line` and `column`.
const named = Filter.parse("metadata.`display-name` is not null");

// Grouped metrics (POST only): items are aggregate rows. Torii executes the query
// once over the caller-visible global state, so supported totals and aggregates
// count visible rows exactly once across dataspace routes.
const supply = await torii.accountAssets("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").list({
  filter: "quantity > 0",
  aggregate: {
    groupBy: ["asset"],
    metrics: [{ alias: "supply", fn: "sum", field: "quantity" }],
  },
  sort: "-supply",
});

// A validated query can be reused, inspected or continued.
const query = ListQuery.from({ filter: active, limit: 100 });
const first = await torii.rwas.list(query);
const next = first.nextCursor && (await torii.rwas.list(query.withCursor(first.nextCursor)));
```

Literals follow the Torii text rules: integers that fit `u64`/`i64` are numbers
(pass `bigint` beyond `Number.MAX_SAFE_INTEGER`), and decimals are exact strings
such as `"10.5"` or `KotodamaQuantity` values. Fractional JavaScript numbers
are rejected because they are not exact; object and array literals are allowed
only for `metadata.*` fields and travel in the JSON form.

`subscriptionPlans` and `subscriptions` are collections of flat rows keyed by
`id`. `uaidManifests(uaid)` and `accountPermissions(accountId)` use the same
filter, projection, ordering and cursor controls. Pages require `next_cursor`
on the wire (a nonempty token or null); unknown envelope fields are rejected.

Transactions, account transactions, `contractActivity`, `contractEvents` and
`accountHistory(accountId)` are history collections: rows come
newest first by `block_height`, then `block_index` (the position within the
block; account movements also carry `movement_index`), and `sort`, `includeTotal` and `aggregate` are rejected. Each page has
a bounded scan budget, so a page may hold fewer than `limit` items, even none,
together with a `nextCursor`; `pages()` and `iterate()` keep following it until
it is `null`, and stop with an error only if Torii returns the cursor it was
sent. Bounds on `block_height` in the filter's top-level `and` also bound the
server's scan: `block_height >= 1200 and block_height <= 1500 and result_ok = true`
reads only that range. The list fields `asset_ids` and
`asset_definition_ids` match element-wise: `=` and `in` select rows where any
element matches, `!=` and `not in` rows where none does; they cannot be sorted
or range-compared.

```js
for await (const tx of torii.accountTransactions("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").iterate({
  filter: field("asset_definition_ids").eq(assetDefinitionId),
  limit: 100,
})) {
  console.log(tx.block_height, tx.entrypoint_hash, tx.result_ok);
}
```

Collection routes are public. When a client is configured with
`canonicalRequestAuth` (`ToriiClient` also needs its `localSigningContext`),
queries are signed over the exact method, path and body so that restricted
dataspaces become visible; signed requests are sent once, without redirects or
retries. On `ToriiClient`, a per-call `canonicalAuth` option overrides the
configured credentials and `canonicalAuth: null` reads anonymously. Invalid queries throw a
`ListQueryError` before any request; server rejections are `ToriiHttpError`s
whose `code` is the same `invalid_filter`, `invalid_sort`, `invalid_select`,
`invalid_aggregate`, `invalid_limit`, `invalid_cursor`, `invalid_include_total`
or `invalid_query`, with `details.field`, `details.actual`, `details.expected`
(a comma-separated string) and `details.hint`. Every error derives from
`ToriiError`.

Account-scoped collections accept canonical I105 account ids or on-chain
account aliases (`name@dataspace` / `name@domain.dataspace`).

Asset and RWA quantities use the stricter `QuantityInput` surface:
`KotodamaQuantity`, an exact canonical quantity string, or `bigint`. JavaScript
`number` is deliberately rejected, and strings are never trimmed or rewritten;
for example `"1"` is valid while `" 1"`, `"01"`, `"+1"`, and `"1.0"` are not.

Account permissions use the shared collection cursor:

```js
const perms = await torii.accountPermissions("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").list({ limit: 5 });
console.log("effective permissions", perms.items.map((item) => item.name));
// The endpoint includes both direct grants and grants inherited from assigned roles.
for await (const perm of torii.accountPermissions("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").iterate({ limit: 2 })) {
  console.log("paged permission", perm.name);
}
```

Read Sora Name Service state with `getSnsPolicy(suffixId)` and
`getSnsRegistration("demo.domain")`; Torii serves them from the ledger-backed
`/v1/sns/policies/{suffix_id}` and `/v1/sns/names/domain/{literal}` routes.

```js
const policy = await torii.getSnsPolicy(0x1002);
console.log(policy.suffix, policy.pricing.length);
const record = await torii.getSnsRegistration("demo.domain");
console.log(record.owner, record.status.status);
```

## Torii Queries & Events

Browser keystores can configure one immutable read identity. Explorer
list/detail/latest/snapshot/metrics calls and contract activity/event replay or
streams then sign the exact final pathname and wire query. Without
`canonicalRequestAuth`, dataspace reads stay anonymous and public-only, while
the global-reader metrics route is expected to reject the request. The public
Explorer health call is never signed by this context. Incomplete contexts,
caller-precomputed canonical headers, and redirects are rejected.

Pass the Torii root itself (for example, `https://torii.example`), not a `/v1`
or `/v1/explorer` endpoint. The browser client accepts only an exact `string` or
`URL` using HTTP(S), rejects embedded URL credentials, queries, and fragments,
and snapshots its headers and timeout before any request. Both clients raise
the same `ToriiHttpError` (and `ToriiStreamGapError` for stream gaps), all
derived from `ToriiError`; the browser entry points do not alias
`ToriiBrowserClient` as `ToriiClient`.

```js
import { NetworkId } from "@iroha/iroha-js/browser";
import { ToriiBrowserClient } from "@iroha/iroha-js/torii-browser";

const browserTorii = new ToriiBrowserClient("https://torii.example", {
  networkId: NetworkId.parse(genesisNetworkHash),
  canonicalRequestAuth: {
    accountId: walletAccountId,
    sign: ({ messageBase64 }) => wallet.signCanonicalRequest(messageBase64),
  },
});

const visibleNfts = await browserTorii.explorerNfts.list({ limit: 25 });
const visibleDomains = await browserTorii.domains.list({ limit: 25 }); // signed with the read identity
```

```js
import { AccountAddress } from "@iroha/iroha-js";

const address = AccountAddress.fromAccount({ publicKey: new Uint8Array(32),
});
console.log(address.canonicalHex());
console.log(address.toI105(753));
console.log(address.toI105());
```

```js
import { ToriiClient } from "@iroha/iroha-js";

const torii = new ToriiClient("http://localhost:8080");

const health = await torii.getHealth(); // GET /health
console.log(health.status); // e.g. "Healthy"
const metricsText = await torii.getMetrics(); // GET /metrics, Prometheus text

const explorerMetrics = await torii.getExplorerMetrics();
if (explorerMetrics) {
  console.log(
    `finalized block #${explorerMetrics.finalizedBlockHeight} (avg commit ${explorerMetrics.averageCommitTimeMs} ms)`,
  );
} else {
  console.log("explorer metrics disabled on this node");
}

const qr = await torii.getExplorerAccountQr("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB");
console.log(qr.literal); // i105 literal embedded in the QR SVG
console.log(qr.svg); // inline SVG (192x192) ready to drop into your UI

const block = await torii.getBlock(42);
console.log(block?.height); // null when the block is missing

const recentBlocks = await torii.explorerBlocks.list({ limit: 5 });
console.log(
  `returned ${recentBlocks.items.length} blocks`,
);
console.log(`next=${recentBlocks.nextCursor}`);
for (const entry of recentBlocks.items) {
  console.log(`${entry.hash} rejected=${entry.transactions_rejected}`);
}

// With `canonicalRequestAuth` configured, Explorer, generic event SSE, and
// contract activity/event GETs are signed over the final path and query so
// restricted visible dataspaces are included. Without it, reads stay anonymous
// and public-only; invalid authentication never falls back to anonymous access.

// Collections follow next_cursor for you; see "Collection queries".
const holdings = [];
for await (const holding of torii.accountAssets("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").iterate({
  sort: "-quantity",
  limit: 2,
})) {
  holdings.push(holding.asset);
  if (holdings.length === 5) break; // leaving the loop stops paging
}
console.log("largest holdings", holdings);

const ownedNfts = [];
for await (const nft of torii.explorerNfts.iterate({
  filter: field("owned_by").eq("sorauﾛ1PｸCｶrﾑhyﾜｴﾄhｳﾔSqP2GFGﾗヱﾐｹﾇﾏzﾍｵﾐMﾇﾖﾄksJヱRRJXVB").and(field("domain").eq("wonderland")),
  limit: 10,
})) {
  ownedNfts.push(nft.id);
}
console.log("alice holds NFTs", ownedNfts);

// TypeScript users can pass a generic argument to shape `event.data`.
for await (const event of torii.streamEvents({
  filter: 'block_status = "Committed"',
})) {
  console.log(event.event, event.data);
  break; // stop after the first event in this example
}

const governanceCanonicalAuth = { accountId: authority, privateKey };
const governanceBinding = await torii.getGovernanceContract(
  "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
  { canonicalAuth: governanceCanonicalAuth },
);
console.log(
  `${governanceBinding.contract_address} :: ${governanceBinding.code_hash_hex}`,
);

// Governance read helpers accept an AbortSignal so long-running requests can be cancelled.
// Proposal ids are canonical lowercase 32-byte hashes. First-release referendum/election
// selectors are 1-128 RFC 3986 unreserved ASCII bytes and may not start with a dot.
const controller = new AbortController();
const proposal = await torii.getGovernanceProposal("ab".repeat(32), {
  signal: controller.signal,
  canonicalAuth: governanceCanonicalAuth,
});
console.log(proposal?.proposal?.kind);

// Typed wrapper returns a structured not-found result and a closed seven-variant
// ProposalKind union; it rejects unknown tags instead of leaking raw JSON.
const proposalResult = await torii.getGovernanceProposalTyped(
  "cd".repeat(32),
  { canonicalAuth: governanceCanonicalAuth },
);
if (!proposalResult.found) {
  console.warn("proposal not found");
}
const tallyResult = await torii.getGovernanceTallyTyped("ref-mainnet", {
  canonicalAuth: governanceCanonicalAuth,
});
if (!tallyResult.found) {
  console.warn("tally not found");
} else {
  console.log(
    `approve=${tallyResult.tally.approve} reject=${tallyResult.tally.reject}`,
  );
}
// Referendum, tally and lock reads preserve u64/u128 integers as number when safe,
// otherwise bigint. Tally results retain evaluated_block_height and evaluated_block_hash.
// Referenda require frozen plain_context and plain_result; closed PLAIN decisions
// are checked against that policy. Lock records require duration_blocks and custody.
// Found raw lock responses retain the native { locks: { locks: ... } } nesting;
// getGovernanceLocksTyped projects the inner map after validating the exact response.
// A 200 response requires a JSON body. Referendum/lock misses use found:false with
// the record omitted; HTTP 404 is also projected to the typed not-found result.
// JSON.stringify cannot print bigint: use String(value) for individual fields.
// These read checks do not qualify anonymous standalone ballots or private tally proofs.

// Governance write helpers also accept AbortSignal options so transactions can be cancelled.
const writeController = new AbortController();
const deployDraft = await torii.governanceProposeDeployContract({
  proposalOperator: governanceCanonicalAuth.accountId,
  contractAddress: "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw",
  codeHash: "11".repeat(32),
  abiHash: Buffer.alloc(32, 0xaa),
  abiVersion: 1,
  manifestProvenance: {
    signer: `ed25519:${manifestSignerMultihashHex}`,
    signature: `ed25519:${manifestSignatureHex}`,
  },
}, { canonicalAuth: governanceCanonicalAuth, signal: writeController.signal });
console.log("proposal instructions", deployDraft.tx_instructions.length);

const ballot = await torii.governanceSubmitPlainBallot({
  authority,
  networkId,
  referendumId: "ref-plain",
  owner: authority,
  amount: "5000",
  durationBlocks: 7200,
  direction: "Aye",
}, { canonicalAuth: governanceCanonicalAuth, signal: writeController.signal });
console.log("ballot draft instructions", ballot.tx_instructions.length);

const zkOwner = "sorauﾛ1Ni1A1mYｲzｳﾚﾊGﾆｲgｵ4ﾜｾﾒﾔzｺﾍz6ﾀFoVDﾇXzｹCkﾙ4CQVXL"; // canonical I105 account id for ZK public inputs
await torii.governanceSubmitZkBallotV1({
  authority,
  networkId,
  electionId: "ref-zk",
  backend: "halo2/ipa",
  envelope: Buffer.from(ballotEnvelopeBytes),
  owner: zkOwner,
  amount: "5000",
  durationBlocks: 7_200,
  direction: "Aye",
}, { canonicalAuth: governanceCanonicalAuth, signal: writeController.signal });

// governanceSubmitZkBallotProofV1 accepts the BallotProof DTO described in
// specs/governance_api.md.

// Governance mutation payloads are closed, secret-free DTOs. Deploy proposals
// accept the exact public manifest provenance object above; the retired opaque
// `limits` field is not sent. ZK-v1 requests use only rootHint, owner, amount,
// durationBlocks, direction, and nullifier for lock hints. Request DTOs use
// exact camelCase names; snake_case and envelope aliases are rejected before an
// HTTP request is attempted. Private-key fields are likewise rejected at any
// nesting depth; sign the returned transaction draft in the caller's wallet or
// key store. Ballot drafts require exact-network canonical account
// authentication, bind that account to `authority`, and never follow redirects
// or retry their nonce-bearing body. Plain-ballot durations are sent as canonical u64 decimal strings,
// including "0". Proposal-backed Parliament voting and enactment use the
// certificate-driven Parliament attempt API rather than the retired equal-ballot,
// finalize, and enact draft routes.
// Protected namespace labels are exact printable-ASCII tokens and are never
// trimmed.

const protectedNamespaceAbort = new AbortController();
await torii.setProtectedNamespaces(["apps", "system"], {
  signal: protectedNamespaceAbort.signal,
});
const protectedNamespaces = await torii.getProtectedNamespaces({
  signal: protectedNamespaceAbort.signal,
});
console.log(protectedNamespaces.namespaces); // ["apps", "system"]

const registeredTriggers = await torii.listTriggers({
  namespace: "apps",
  authority: "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY",
  limit: 5,
});
registeredTriggers.items.forEach((trigger) => {
  console.log(trigger.id, trigger.action.Mint?.Asset?.object);
});

const trigger = await torii.getTrigger("apps::mint_rewards");
if (!trigger) {
  await torii.registerTrigger({
    id: "apps::mint_rewards",
    namespace: "apps",
    action: {
      Mint: {
        Asset: {
          object: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
          destination_id: "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY",
          value: "5",
        },
      },
    },
  });
  const draft = await torii.registerTriggerTyped({
    id: "apps::mint_rewards",
    namespace: "apps",
    action: {
      Mint: {
        Asset: {
          object: "62Fk4FPcMuLvW5QjDGNF2a4jAmjM",
          destination_id: "sorauﾛ1PﾜKNﾗ7ｼｺa2WｸｼﾒﾐQﾎbｺﾄocﾆﾁヰJaｱbg6sｾgｲﾖPfX7WAWRY",
          value: "5",
        },
      },
    },
  });
  if (draft) {
    console.log(`trigger queued ok=${draft.ok} tx_instructions=${draft.tx_instructions.length}`);
  }
}

await torii.deleteTrigger("apps::archived");
await torii.deleteTriggerTyped("apps::archived");
const pending = await torii.queryTriggers({ limit: 10 });
console.log("latest triggers", pending.items.map((item) => item.id));

// Helpers are available for building the Norito action payloads expected by
// `/v1/triggers`. The builders serialise the action to base64 so Torii receives
// the canonical Norito representation regardless of how the instructions were
// assembled in JS.
const timeAction = buildTimeTriggerAction({
  authority,
  instructions: [
    buildMintAssetInstruction({
      assetHoldingId: "<base58-asset-definition-id>#<i105-account-id>",
      quantity: "250",
    }),
  ],
  startTimestampMs: Date.now() + 5_000,
  periodMs: 60_000,
  repeats: 10,
  metadata: { label: "hourly faucet" },
});
await torii.registerTrigger({
  id: "apps::mint_rose_hourly",
  namespace: "apps",
  action: timeAction,
});

const precommitAction = buildPrecommitTriggerAction({
  authority,
  instructions: [
    buildMintTriggerRepetitionsInstruction({ triggerId: "apps::guardian", repetitions: 1 }),
  ],
});
await torii.registerTrigger({
  id: "apps::guardian_refill",
  namespace: "apps",
  action: precommitAction,
});
```

The canonical `/v1/events/sse` and `/v1/contracts/events/sse` feeds are
live-only and have no replay log. Their helpers intentionally expose no
`lastEventId` option; reconnecting starts a new subscription and can have a
gap. `ToriiClient` yields the terminal `event: stream_error` frame before the
iterator ends; `ToriiBrowserClient` raises `ToriiStreamGapError` (with `code`
and `droppedMessages`) for that frame or for an unexpected end of the stream.
Either way, applications must handle the gap instead of treating closure as a
lossless continuation point. Aborting `signal` or leaving the `for await`
loop cancels the response body.

Contract-event rows (`contractEvents` pages and `streamContractEvents`) are
native emissions committed by successful contract execution, with `provenance`
always `"emitted"`. Each row retains the full typed `emission`, its rendered
`payload`, and the immutable `output_index` and `emission_index`; `event_id` is
`block_hash_hex:output_index:emission_index`. `execution_hash_hex` identifies the
owning Network, Pipeline, or Time execution. The emitting contract address,
immediate caller, and signed event definition determine `contract_address`,
`authority`, and `event_kind`. Both clients reject a `provenance` stream filter
naming anything else, and `ToriiClient` verifies these row fields against the
native emission. Call metadata and rejected executions cannot create event rows.

`streamEvents({ filter })` takes a `Filter`, a text filter or the JSON form.
Torii accepts `=` and `in` on `tx_hash`, `tx_status`, `tx_block_height`,
`tx_lane_id`, `tx_dataspace_id`, `block_status`, `block_height`,
`proof_backend`, `proof_call_hash` and `proof_envelope_hash`, combined with
`and`/`or`, plus `not tx_status = ...`, `not block_status = ...` and
`tx_block_height is null`; anything else is rejected with `400 invalid_filter`.
Transaction statuses are `Queued`, `Expired`, `Approved` and `Rejected`; block
statuses are `Created`, `Approved`, `Rejected`, `Committed` and `Applied`.

Each payload frame's `data` is one JSON object typed as `ToriiEventPayload`,
discriminated on `category` (`Pipeline`, `Data`, `Other`) and `event`:
`Transaction` (`hash`, `lane_id`, `dataspace_id`, `block_height`, `status`,
and `rejection_code`/`rejection_reason` when rejected), `Block` (`status`, and
the block rejection variant as `rejection_code`), `Warning`, `Witness`,
`ProofVerified`/`ProofRejected`, `ProofPruned`, the other data-event kinds
(`Asset`, `Domain`, ...) and `Time`/`ExecuteTrigger`/`TriggerCompleted`/`Other`
with a diagnostic `summary` that has no stable format. Integers beyond
`Number.MAX_SAFE_INTEGER` are `bigint`. Torii may add event kinds; the SDK
delivers unrecognized payloads unchanged, so keep a `default` branch.

Collection rows and explorer QR snapshots carry canonical I105 account
literals only; address-format hints are not supported.

### Asset-lock cancellation

Use the typed compare-and-cancel builder with the exact remaining quantity read
from finalized ledger state:

```js
import { buildCancelAssetLockInstruction } from "@iroha/iroha-js";

const cancel = buildCancelAssetLockInstruction({
  lockId: "merchant-lock-001",
  expectedRemainingAmount: "1500",
});
```

The builder derives the native `EscrowId` with Blake2b-256 and emits only
`escrow_id` plus `expected_remaining_amount`. The lock-ID preimage must be
nonempty exact text without surrounding whitespace or a BOM and is bounded by
`CANCEL_ASSET_LOCK_MAX_LOCK_ID_UTF8_BYTES_V1` (4,096 UTF-8 bytes, not
characters); the on-wire `EscrowId` remains 32 bytes. The precondition is
mandatory, positive, and canonically spelled; the retired one-field
cancellation and lossy JavaScript numbers are rejected before encoding.

For the appeal-finance fixture boundary, use the strict bare archive codec with
an already finalized canonical escrow hash:

```js
import {
  decodeCancelAssetLockV1,
  encodeCancelAssetLockV1,
  validateAppealFinanceCancelAssetLock,
} from "@iroha/iroha-js";

const archive = encodeCancelAssetLockV1({
  escrow_id:
    "hash:73CCD4E0DD69AD434DB75056B600AA4F74C8FC5556B11BDC799DFDB7EA29851F#434B",
  expected_remaining_amount: "20",
});
const fields = decodeCancelAssetLockV1(archive);
const diagnostic = validateAppealFinanceCancelAssetLock(archive);
```

This codec accepts exactly the two snake-case string fields and exact archive
bytes. The encoder returns an ordinary, owned, full-span `Uint8Array`; the bare
decoder rejects `Buffer`, `ArrayBuffer`, shared, subclass, and partial-view
aliases. Raw hex/base64, byte-array field aliases, nested identifiers, padding,
substituted schemas or flags, and trailing bytes are rejected. The validation
outcome is diagnostic and does not itself authorize settlement.

### SoraFS replication-order instructions

The V1 helpers emit the exact native Rust/Norito variants. IDs must be non-zero
lowercase 64-hex strings, and issue payloads must be canonical base64 containing
a bounded, canonical `ReplicationOrderV1` archive whose embedded order ID,
target, provider assignments, and deadline are valid.

```js
import {
  buildCompleteReplicationOrderInstruction,
  buildExpireReplicationOrderInstruction,
  buildIssueReplicationOrderInstruction,
} from "@iroha/iroha-js";

const issue = buildIssueReplicationOrderInstruction({
  orderId,
  orderPayload: replicationOrderBytes.toString("base64"),
  issuedEpoch: 20,
  deadlineEpoch: 28,
  musubiArchiveId, // omit for an ordinary non-Musubi replication order
});
const complete = buildCompleteReplicationOrderInstruction({
  orderId,
  providerId,
  completionEpoch: 27,
  expectedAuthority: {
    providerOwner,
    completionSigner,
    signerPolicy: {
      policyId,
      revision: 2,
      predecessorDigest,
      policyDigest,
    },
  },
  expectedAssignmentRevision: 3,
  finalizedAnchor: {
    height: 41,
    blockHash,
  },
});
const expire = buildExpireReplicationOrderInstruction({
  orderId,
  expirationEpoch: 29,
});
```

Issue instructions always carry the fifth `musubi_archive` option on the wire:
omitting `musubiArchiveId` encodes `None`, while supplying it binds the order to
one exact non-zero ArchiveId. The retired four-field wire shape is rejected.

Completion uses the exact six-field hard cut: `order_id`, `provider_id`,
`completion_epoch`, `expected_authority`, `expected_assignment_revision`, and
`finalized_anchor`. The authority retains the provider owner, mandatory completion signer, and
four-part signer-policy chain. The completion transaction is signed by the selected
completion signer; the provider owner controls that binding. Missing, retired three-field, alias, and unknown shapes are
rejected.

## Configuration

- Publishing guidance and the release automation flow live under `specs/sdk/js/publishing.md`. GitHub releases tagged `js-v<semver>` automatically trigger the provenance-enabled publish workflow (with changelog/semver guards); for manual runs use `npm run check:changelog` (or rely on the `prepublishOnly` hook), then call `npm run release:update-docs -- --version <x.y.z> [--date YYYY-MM-DD] --note "summary"` to sync release notes into `CHANGELOG.md`, `status.md`, and `roadmap.md`.

- Release guardrails ship with `npm run release:matrix`, which executes the
  configured Node/OS targets (see
  `scripts/release_matrix.targets.example.json`) and records per-target logs,
  `matrix.json`, `matrix.md`, and `matrix.prom` in
  `artifacts/js-sdk-release-matrix/`. Attach the generated evidence bundle to
  release artefacts so the JS5 publishing gate can verify which environments
  exercised the candidate build. Pass `--metrics-out <path>` to override the
  Prometheus textfile location and `--textfile-dir <dir>` (or set
  `JS_RELEASE_MATRIX_TEXTFILE_DIR`) to mirror the gauges into a node_exporter
  textfile directory so release dashboards can ingest the status automatically.
  See `specs/sdk/js/publishing.md` for the full workflow.

- `ToriiClient` accepts `timeoutMs`, `maxRetries`, `backoffInitialMs`, `backoffMultiplier`, `maxBackoffMs`, `retryStatuses`, and `retryMethods`, mirroring the retry knobs exposed in `iroha_config`.
- `ToriiBrowserClient` accepts its exact transport options directly. It does not
  accept the Node client's nested `config` object, and endpoint success statuses
  are fixed by the SDK rather than caller-configurable.
- Retry settings never apply to signed transaction or batch submission, or to a request carrying `canonicalAuth`/`X-Iroha-Nonce`: those final dispatches always use `redirect: "error"` and make exactly one Fetch call. `ToriiBrowserClient` applies the same redirect policy to signed transactions, canonical nonce-bearing requests, and configured dataspace-visible reads. Pre-dispatch validation reads, such as the node-capabilities check, retain the normal safe retry policy. A custom `fetchImpl` must preserve this one-shot boundary whenever it receives `redirect: "error"`; it must not follow 307/308 responses or replay the request after a network error, timeout, or retryable status.
- Attach `retryTelemetryHook` to capture deterministic per-attempt telemetry for dashboards and SLO drills; events include phase (`response`/`network`/`timeout`), attempt numbers, method/URL, status or error metadata, backoffMs, profile name when set, durationMs for the attempt, and timestampMs so logs can be correlated with Torii-side traces.
- Authentication headers can be supplied via `authToken` (maps to `Authorization: Bearer ...`) or `apiToken` (maps to `X-API-Token`). Requests that carry auth headers, `canonicalAuth`, or raw `private_key*` JSON fields pin to the client's base scheme/host; cross-host overrides are rejected, insecure `http`/`ws` requires `allowInsecure: true` (dev-only), and `insecureTransportTelemetryHook` captures any downgraded transports. Cross-host requests without sensitive material require `allowAbsoluteUrl: true`.
- Runtime defaults can be pulled from `iroha_config` JSON/TOML by passing a camelCase config object (map `torii.api_tokens` to `torii.apiTokens`) to `new ToriiClient(url, { config })`. The helper `resolveToriiClientConfig({ config })` returns the merged settings if you need to inspect them directly.
- SoraFS and DA integrations use the native SDK owners. Torii constructor options reject private test hooks and retired alias-header policy overrides.
- Developer-friendly environment overrides are supported for local workflows: `IROHA_TORII_TIMEOUT_MS`, `IROHA_TORII_MAX_RETRIES`, `IROHA_TORII_BACKOFF_INITIAL_MS`, `IROHA_TORII_BACKOFF_MULTIPLIER`, `IROHA_TORII_MAX_BACKOFF_MS`, `IROHA_TORII_RETRY_STATUSES`, `IROHA_TORII_RETRY_METHODS`, `IROHA_TORII_API_TOKEN`, and `IROHA_TORII_AUTH_TOKEN`.
- Retryable status codes default to `{429, 502, 503, 504}`; methods default to `GET`, `HEAD`, and `OPTIONS`. Override them when your workflow needs different semantics.
- See `recipes/configured-client.mjs` for a script that loads an `iroha_config` JSON document, applies environment overrides, and instantiates `ToriiClient` with the merged settings.

```js
import { AccountAddress } from "@iroha/iroha-js";

const address = AccountAddress.fromAccount({ publicKey: new Uint8Array(32),
});
console.log(address.canonicalHex());
console.log(address.toI105(753));
console.log(address.toI105());
```

```js
import { ToriiClient, resolveToriiClientConfig } from "@iroha/iroha-js";
import fs from "node:fs";

const rawConfig = JSON.parse(fs.readFileSync("./iroha_config.json", "utf8"));
const config = rawConfig?.torii
  ? {
      ...rawConfig,
      torii: {
        ...rawConfig.torii,
        apiTokens: rawConfig.torii.api_tokens ?? rawConfig.torii.apiTokens,
      },
    }
  : rawConfig;
const clientConfig = resolveToriiClientConfig({
  config,
  overrides: { timeoutMs: 2000 },
});

const torii = new ToriiClient(config?.torii?.address ?? "http://localhost:8080", {
  config,
  timeoutMs: clientConfig.timeoutMs,
});
```

### Native game sessions and compiled application adapters

The browser `@iroha/iroha-js/game` entry point provides canonical codecs and local
transaction instruction construction for generic `GameManifestV1` sessions:
`buildGameInstructionV1`, `encodeGameValueV1`, `decodeGameValueV1` and
`gameMessageHashV1`. Admission, opaque bounded inputs, jointly signed checkpoints,
consensus recovery and proof-derived outcomes are application-independent. The
closed browser instruction registry rejects unknown instructions; native racing
instruction aliases are not supported.

`buildJoinGameSessionV1` requires the exact terms shown for wallet approval:

```js
import { buildJoinGameSessionV1 } from "@iroha/iroha-js/game";

const instruction = buildJoinGameSessionV1({
  session_id: reviewedSession.session_id,
  input_key: inputPublicKey,
  application_data: applicationData,
  invitation_signature: null,
  expected_manifest_hash: reviewedSession.manifest_hash,
  expected_asset_definition: reviewedSession.asset_definition,
  expected_stake: reviewedSession.stake,
});
```

Keep `reviewedSession` as a detached snapshot of the displayed terms. Polling
must not silently replace its manifest, asset or amount before signing. The
native instruction compares all three expected terms with consensus state before
funding; zero-stake sessions explicitly sign `expected_stake: "0"`. Missing
preconditions and the original undeployed four-field encoding are rejected.
When a transaction also deposits an NFT, its `StakeGameItemV1` must identify the
same session and expected manifest. The transaction's explicit wallet fee limit
is separate from the stake and item deposit.

The separate `@iroha/iroha-js/race` entry point encodes the first compiled SORA CARS
adapter's tracks, integer state, results, public replay and native prover payload.
It maps six control words to twelve opaque input bytes and computes the generic
transcript and state commitment domains. These application helpers never hold a
wallet key. Wallet signing continues through Connect with locally constructed
Norito bytes and local signature verification.

`EXECUTION_PROOF_MAX_ENVELOPE_BYTES_V1` pins the four MiB complete execution
envelope and typed settlement payload bound. The RaceV1 inner STARK is separately
limited to three MiB. Browser transaction construction, signable validation and
signed hashing admit larger payloads only for one canonical
`VerifyExecutionProofV1` or `SettleGameSessionV1`; unrelated transactions retain
their one MiB bound, and larger mixed or executable-batch payloads are rejected.
Transport and wallet implementations must independently support the resulting
frame size before a network release can enable these proofs.

`validateConnectTransactionTransportStatus(status, payloadLength)` from
`@iroha/iroha-js/connect-browser` checks the endpoint-reported Connect WebSocket
and session-buffer bounds against the complete transaction plus the current
216-byte V1 encrypted-frame overhead. It does not authenticate the endpoint or
the wallet. Native deployments can explicitly apply
`configs/soranexus/execution-proof-transport.toml`; its dedicated reliable Connect
P2P topic preserves the Health frame bound. Applications should additionally
require `/v1/games/capabilities.execution_transport_ready === true` before accepting
new stakes, separately from proof-profile qualification. These readiness hints
must never become consensus admission conditions.

See `test/fixtures/game-v1-codec.json` for generic wire and gameplay digest vectors,
and `test/fixtures/race-v1-codec.json` for compiled application value vectors.
Qualification and authenticated block finality are separate from codec round trips
or endpoint-reported transaction status.

Canonical staking values are available through `encodeValidatorStakingValueV1`
and `decodeValidatorStakingValueV1` on the root and `norito` exports. The typed
monetary preconditions, automatic reward entitlements (with mandatory exact
`fee_claim`), signing generations and epoch authorizations use the Rust shared
fixtures. Amounts remain exact decimal strings and unsigned heights accept
`bigint`; native identity validation is mandatory. These are bare value codecs,
not preparation observations or evidence of authority. The executing network
still verifies its pinned XOR, custody, signer and finality obligations.

### Staking preparation observations

The client exposes the canonical `/v1/nexus/staking/prepare` read as
`preparePublicLanePlan(request, xorAssetDefinitionId)` in JavaScript and
`prepare_public_lane_plan(request, xor_asset_definition_id)` in Python. It uses
the client's immutable local signing context only to pin the expected network;
the read signs and submits no transaction. Supply the network's genesis-pinned
XOR definition explicitly. All proposed balances must use that definition and
Global scope. The response is a server observation, including its reported
block identity; it is not an independently authenticated state proof.

Requests and responses use exact bounded Norito frames. The client checks the
echoed request, epoch cut, expiry, recipients, selected accruals, and complete
ordered balance set before returning the plan for review. There is one dispatch
with no retry or redirect. Execution must recompute all monetary effects and
preconditions before any signed plan changes ledger balances.

JavaScript preparation retains one cancellation deadline through dispatch,
headers and success/error body reads, including responses arriving after the
caller has stopped waiting. The deadline uses the configured timeout with a
30-second maximum and does not restart when headers arrive.
