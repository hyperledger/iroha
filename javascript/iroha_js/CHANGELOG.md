# Changelog

All notable changes to `@iroha/iroha-js` are documented in this file.

## [Unreleased]

- Removed the retired KAGEMUSHA surface: the `Kagemusha` namespace, the
  `./kagemusha` subpath and `kagemusha.d.ts`; the Node and browser
  `getKagemushaReadiness`, `submitKagemushaTopUp`, `submitKagemushaRedemption`
  and `getKagemushaOperation` Torii methods with their response types; and the
  `iroha.kagemusha.v1.top_up` browser allowlist entry and Norito wire-id
  mapping. `TAIRA_TESTNET_PROFILE` now names the Digital Shekel asset fields
  `dsAssetDefinitionId`, `dsAssetAlias` and `dsAssetScale`.
- Unified Torii collection queries (`specs/torii/collection_queries.md`). Every
  collection is a `ToriiCollection` on both `ToriiClient` and
  `ToriiBrowserClient` (`domains`, `accounts`, `assetDefinitions`, `nfts`,
  `rwas`, `repoAgreements`, `transactions`, `accountAssets(id)`,
  `assetHolders(id)`, `accountTransactions(id)`) with `list()`, `pages()` and
  `iterate()` over `POST <collection>/query`. The shared query core exports the
  `field()` builder, `Filter` (canonical text and JSON forms, checked against
  `fixtures/torii/list_query/vectors.json`), `SortKey`, `ListQuery` and
  `decodePage`; pages are `{ items, nextCursor, total }`. Transaction
  collections are history collections that reject `sort`, `includeTotal` and
  `aggregate`. The `list*`/`query*`/`iterate*`/`iterate*Query` collection
  helpers, `queryTransactions`/`iterateTransactionsQuery`, the
  `*TransactionStatusTyped` and `submitTransactionAndWaitTyped` duplicates, the
  offset/`count_mode`/`fetch_size` options and the `{Eq: ...}` filter
  validators are removed.
- One error hierarchy for both clients: `ToriiError` (`code`, `details`), with
  `ToriiHttpError` (`status`, envelope `code`/`message`/`details`,
  `x-iroha-reject-code`), `ListQueryError`, `FilterSyntaxError` (`line`,
  `column`) and `ToriiStreamGapError`. `ToriiBrowserHttpError` and
  `ToriiBrowserStreamGapError` are removed.
- `streamEvents({ filter })` takes the collection-query text grammar (a
  `Filter`, text or the JSON form) on both clients; the retired
  `{Pipeline: ...}`/`{VerifyingKey: ...}` filter objects are rejected. Aborting
  the signal or leaving the loop cancels the response body. Payload frames are
  typed as `ToriiEventFrame<ToriiEventPayload>`, a union discriminated on
  `category`, `event` and `status` (transaction rejections carry
  `rejection_code` and `rejection_reason`); unrecognized kinds pass through
  unchanged, u64 values beyond `Number.MAX_SAFE_INTEGER` decode as `bigint`,
  and a payload that is not a JSON object fails with `invalid_response`. The
  stale `MergeLedger` event and `status: string` typings are removed.
- Collection row types mark only the identifying fields as always present;
  every other field is optional and nullable, and u64 fields are `ToriiU64`.
  Transaction rows carry `block_height`, `block_index`, `block_hash`,
  `asset_ids` and `asset_definition_ids` (no `asset_id`).
- Fixed: base URL path prefixes are kept; `getHealth()`/`getMetrics()` read
  `/health` and `/metrics`; the public capability preflight sends no
  credentials and no longer caches a failed or mismatched probe;
  `fetchImpl` is never called with a client receiver; the browser client no
  longer lowercases sort keys; `submitTransactionAndWait` derives the
  transaction hash from the signed bytes and only verifies an asserted
  `hashHex`; body reads honour abort signals.

- Corrected retail-fee quote and assessment framing to use the declared 16-byte
  Norito schema identities. Canonical markers and payment-intent hashes now use
  the same header layout as the native codecs.
- Validation-fee proof projections accept their exact declared fields regardless
  of declaration order; missing and unexpected policy fields remain rejected.

- Added the browser-safe `@iroha/iroha-js/petal` entry point: a pure
  JavaScript port of the `iroha_petal` Petal Stream optical transport (encoder
  bit-exact with the shared fixtures, decoder step by step). It
  provides the stream encoder and assembler (beacons, fountain atoms, CRC-32C
  verification, bounded pre-beacon buffering), the three Reed-Solomon lane
  codecs, the camera-frame decoder (`decodePetalFrame`, `decodePetalFrameAt`),
  `PetalScanSession` with idle and absolute timeouts, the software renderer and
  a vector draw list, plus `PetalStreamPlayer` (Canvas 2D) and
  `PetalCameraScanner` (`MediaStream`/video to luma) browser glue that touches
  no DOM globals at import time. The tile lanes are read against the finder
  light and dark levels first, and any lane that does not decode is re-read with
  a per-tile normalised read, so over-exposure, veiling light and shadows no
  longer cost lane `K`. Three corner blossoms that form a corner are enough: the
  hidden fourth is inferred, refined against the rings and reported as
  `inferredCorner`, and orientations are ranked by the ring gates plus the `天`.
  `PetalScanSession` follows a decoded code into the next frames by tracking its
  pose (`trackPetalFrame`, 500 ms window) and counts `tracked` and `inferred`
  frames; `PetalCameraScanner` passes those counters to `onProgress`. The shared
  `fixtures/petal` stream vectors, golden camera captures (eleven, including
  over-exposed, veiled, shadowed, covered-corner and cut-corner frames) and
  tracking pairs are part of the unit suite; the `PetalCameraScanner`
  documentation lists the camera setup the decoder is calibrated for (about
  1280×720, exposure compensation of about -1 EV).

- `getPipelinePreflight()` parses exactly the served `GET /v1/pipeline/preflight`
  body, checked against the Rust-generated `fixtures/torii/pipeline_preflight.json`:
  `sumeragi` carries only the positive `block_cadence_ms`, every object rejects
  fields Torii does not serve, fee amounts are strings and `settlement_mode` is
  `direct` or `lane_relay_burn`. Torii serves no stall threshold, so the result
  exposes the SDK-derived `stallThresholdMs` (20 × `block_cadence_ms`) that
  `isStatusStalled` applies; the typed `sumeragi.block_time_ms`,
  `commit_time_ms` and `stall_threshold_ms` fields are removed.

- Added `getSumeragiLanes()` on `ToriiClient` and `ToriiBrowserClient` plus
  `parseSumeragiLanesJson`/`parseSumeragiLanesPayload` in `sumeragi-typed`: the
  operator-signed `GET /v1/sumeragi/lanes` list is validated fail-closed (exact
  fields, canonical BLS-normal committee keys and 96-byte proofs, exact
  unsigned ranges) against the shared Rust-generated
  `fixtures/sumeragi/native_lanes_v1.tsv` corpus. `getSumeragiLeader` and its
  `ToriiSumeragiLeaderSnapshot`/`ToriiSumeragiPrfContext` types are removed:
  Torii serves no `/v1/sumeragi/leader` route; the current leader is part of
  the native status.

- `getSumeragiParams()` returns exactly the served
  `{ block_cadence_ms, max_clock_drift_ms, chain_height }` snapshot and rejects
  any other field. The retired `block_time_ms`, `commit_time_ms`,
  `collectors_k`, `redundant_send_r`, `da_enabled`, `next_mode` and
  `mode_activation_height` fields are gone, as are the unused
  `ToriiConsensusCaps` and `ToriiSumeragiCommitQuorumSummary` declarations.

- `validateNoritoFrame` and every Norito decoder built on it accept only the
  Norito v1 header flags `0x00` (fixed-width length prefixes) and `0x02`
  (`COMPACT_LEN`). The retired packed-sequence (`0x01`), packed-struct (`0x04`)
  and field-bitset (`0x20`) bits are rejected in every combination; previously
  `0x04` frames passed validation and were mis-decoded as ordinary structs.

- Canonical request signing hashes the exact byte range of every ArrayBuffer
  view, including DataView and wide typed arrays. Strict lossless JSON request
  serialization rejects array accessors without invoking them and rejects
  malformed Unicode in values and object keys before dispatch.

- Added the browser `game` entry point for canonical generic game-session
  manifests, opaque inputs, signed checkpoints, invitation admission and native
  execution-proof outcomes. Browser transaction signing admits only the closed
  generic instruction registry. The separate `race` entry point contains the
  first compiled SORA CARS application's value codecs and public prover payload;
  no native racing instruction aliases are exported.
  Execution envelopes and typed settlement payloads have a four MiB corridor,
  including local wallet payload validation and signed hashing; ordinary payload
  limits remain unchanged. The RaceV1 inner STARK is bounded at three MiB.

- Replaced every mutable process-global native/Norito override with immutable
  runtime contexts. Production entrypoints share one verified, snapshotted
  native surface; Torii clients and source-level test facades can carry isolated
  contexts through crypto, transaction, DA/SoraFS, proof, validation-fee, and
  Norito composition without cross-client state. Portable fallback now hides
  only an exactly classified missing native file; checksum, provenance, and
  load failures remain visible and every loader outcome is cached.
- Removed the pre-release `encodeInstruction` alias and the contradictory
  `SUPPORTED_CRYPTO_ALGORITHMS` constant. `noritoEncodeInstruction` is the sole
  instruction encoder, `CRYPTO_ALGORITHMS` is the known-label catalog, and
  `supportedCryptoAlgorithms()` reports the algorithms executable by the
  current runtime. Crypto and transaction private-key algorithm options also
  reject `null` instead of silently selecting Ed25519, and explicit falsey key
  seeds can no longer become random key generation.
- Moved Torii credentials, canonical-auth key material, origins, retry policy,
  and validation caches into private class state. Constructor inputs are
  snapshotted, canonical-auth byte containers are copied, and JSON/object
  inspection no longer exposes tokens or key bytes. Non-empty Norito
  transaction receipts now fail closed when their native decoder is missing,
  rejects the payload, or returns invalid JSON; only `204` or an empty body maps
  to an empty receipt.
- Hardened both smaller HTTP clients around the same immutable boundary.
  `NoritoRpcClient` now keeps credentials and transport state in private fields,
  copies every request body before dispatch, applies real per-call token
  overrides, validates exact booleans/timeouts, and drops the no-op `close()`
  compatibility method. `ToriiBrowserClient` now accepts only credential-free
  HTTP(S) Torii root URLs, snapshots headers and timeout policy, rejects unknown
  constructor options, and keeps route success statuses SDK-owned. The duplicate
  nested browser `config` input and browser-only `ToriiClient`/`ToriiHttpError`
  aliases are removed; the exact browser class names are the sole surface.
- Made instruction-codec ownership deterministic: supported V1 instructions
  use the pure-JavaScript codec first, while unsupported variants dispatch once
  to the native codec and propagate its exact error. Native error-message text
  is no longer interpreted as a compatibility signal. DA blob IDs use the
  portable BLAKE3 implementation, client gateway/proof helpers stay on that
  client's runtime, and `proofSummary: false` performs no hidden proof work.
- Reduced the registry artifact to one runtime tree. Published packages contain
  `dist/` plus the two portable recipes, not duplicate `src/` implementations or
  development scripts; declarations and recipes resolve that same tree. The
  address subpath now has an explicit browser condition, and package-layout
  tests reject source or script leakage. Native-only calls from a clean package
  now direct consumers to `IROHA_JS_NATIVE_DIR` instead of suggesting the
  source-checkout-only native build command.
- Removed the mutable curve-length map from address validation and read each
  length from its frozen V1 registry entry. SoraFS orderbook cancellation now
  preserves the caller's exact abort reason through its one-shot deadline and
  ambiguity error chain. Validation-fee fingerprint calls also reuse the
  runtime's already-bound native functions instead of rebinding per call.
- Added native and pure-JavaScript Norito parity for the complete account-scoped
  asset transfer-control family. Node and browser entry points now expose
  typed blacklist and calendar-cap builders alongside directional
  availability, with exact wire IDs, canonical window ordering, optional
  Quantity clearing semantics, and closed input validation.
- Hard-cut UAID portfolio, binding, and manifest reads to the exact first-release
  Torii JSON contract. Manifest queries now expose all five current filters,
  responses require pagination metadata and canonical nested identities, and
  manifests use numeric version `1` with omitted optional fields. Retired
  defaults, aliases, numeric coercions, case folding, prefixed hashes, and bare
  asset-definition ids are rejected before use.
- Hard-cut pipeline preflight to its current V1 shape: both IVM cycle limits
  are required and fee-account fields accept only exact canonical I105 ids.
  Live mutation fixtures now register universal accounts without domain input.
- Hard-cut the Node/native signed-transaction boundary to the exact canonical
  `VersionedSignedTransaction` V1 wire. Native builders now emit that wire,
  submission and SoraFS pin registration validate it before network I/O, and
  framed, bare, headerless, alternate-layout, opaque-prefix, and raw-entrypoint
  submission fallbacks are removed.
- Require per-request canonical account authentication for the SoraFS alias
  and replication inventory helpers, and require an immutable exact-network
  `OperatorSigningContext` for operator-only storage-state and storage-fetch
  diagnostics. Public live integration invokes only the signed inventory
  routes available to account clients.
- Hard-cut SoraFS alias inventory responses to the closed first-release Torii
  projection. Attestation, lineage, cache evaluation, successor, governance,
  status, and policy fields are required and cross-checked; unknown fields,
  coercive values, stale reason literals, and inconsistent pagination fail
  closed. `proof_expires_in_seconds` is present only while the proof is live.
- Add strict signed SoraFS orderbook submit helpers with native route/signature/network preflight, pinned Norito receipt authentication, exact identity headers, one-shot deadlines, and non-resubmittable ambiguous-admission errors.
- Hard-cut SoraFS pin listing to finalized, byte-bounded exclusive-keyset
  pages. The client rejects `offset`, legacy attestation/full-record payloads,
  forged or repeated continuation cursors, and anchor drift; list entries are
  now strict summaries with consensus-maintained charged count/byte totals.
- Closed every governance mutation request shape before network I/O and reject
  all retired private-key aliases, including inside ZK public inputs and the
  nested V1 ballot proof. Deploy proposals now encode `ContractCodeHash` and
  `ContractAbiHash` with their versioned 32-byte Norito layout, encode
  `AbiVersion` as numeric V1, expose exact typed public manifest provenance,
  and reject the ignored `limits`, `window`, and `mode` fields. ZK public
  inputs are closed to their six wire fields. Plain-ballot durations use
  canonical u64 decimal strings and accept zero. Retired the proposal-backed
  equal-Parliament-ballot, finalize, and enact client methods; binding proposal
  transitions now use certificate-driven Parliament attempts, while standalone
  plain/ZK referendum ballots remain available. Protected namespaces are exact
  printable-ASCII tokens, and Ministry agenda drafts now validate a closed,
  recursively secret-free typed V1 proposal while preserving full-u64
  timestamps losslessly.
- Replaced offset pagination on the six Explorer world collections with bounded,
  opaque seek cursors. Node and browser clients now send `cursor`/`limit`,
  validate the `{limit,next_cursor,has_more}` continuation contract, and the NFT
  and RWA async iterators advance only through server-issued cursors.
- Hard-cut Explorer block, transaction, instruction, and latest-history reads to
  snapshot-bound `cursor`/`limit` pagination. The Node block client and browser
  Explorer methods reject page/offset knobs and exact totals, validate the
  snapshot height/hash plus continuation invariants, and expose typed cursor
  metadata without reconstructing counts from hidden history. Node and browser
  Explorer, generic event SSE, and contract replay/stream reads now use the
  configured default canonical signer to include restricted dataspaces, with
  anonymous public-only behavior when no signer is configured. Browser callback signers cover the
  exact final path and wire query, reject redirects and precomputed auth, and do
  not change the public Explorer health request.
- Removed the generic `Shield`, `ZkTransfer`, and `Unshield` transaction surface
  from ABI V1. JavaScript builders, TypeScript declarations, exports, and Norito
  discriminants now fail closed.
- Added a Node-only native authenticated `BlockProofs` verifier. It accepts
  bounded canonical bridge-finality, exact executed-`SignedBlockWire`, and
  proof archives; pins the application-selected chain, height context, and
  expected entry hash; verifies Sumeragi-v2 roster PoPs and aggregate finality
  in Rust; derives the non-serializable proof anchor only from that verified
  artifact; and enforces immediate successor state. Browser builds reject this
  native-only operation. Torii exposes
  the finality and `BlockProofs` archives but not yet the exact executed block
  wire required to assemble this verification input from public routes alone.
- Removed asset-selected offline readiness discovery, including its
  selector-taking readiness methods, normalizers, types, and exports.
- Bound validation-fee policy and payout-lifecycle proposal fingerprints to
  the canonical proposal operator and exact typed proposal payload. Both native
  exports validate exact JSON and compute canonical `ProposalKind`
  fingerprints, and the JavaScript/TypeScript package exposes their current
  signatures without a fallback hashing path. Verified policy projections now
  retain the complete, recursively validated Parliament certificate and its
  proposal and enactment bindings.
- Bound the `CancelAssetLock` lock-ID preimage to the public V1 limit of 4,096
  UTF-8 bytes while preserving the fixed 32-byte `EscrowId` wire field.
- Added strict JavaScript/TypeScript `CancelAssetLock` parity. The new builder
  derives the native escrow id, requires a positive canonical
  `expected_remaining_amount`, and the native and pure-JavaScript codecs reject
  the retired one-field cancellation shape.
- Added the exact bare `CancelAssetLock` V1 archive encoder/decoder and
  appeal-finance reference-validation wrapper. They reject structured-field
  aliases, noncanonical quantities, substituted framing, and trailing bytes.
- Made transaction finality polling global-only and state-authoritative across
  the Node, browser, and Nexus clients. Raw status reads retain only explicit
  `local`/`global` diagnostics, while the pre-release `auto` mode, configurable
  polling scope, cross-endpoint fallback list, and caller-selected success,
  failure, or terminal statuses were removed. Only exact state-resolved
  `Applied` succeeds;
  queue/cache-resolved `Applied` remains pending, while `Rejected` and `Expired`
  are fixed failures. Validation-fee policy
  admission also rejects contract-address chain discriminants above `u16`
  before account derivation, closing an untrusted-input CPU exhaustion path.
- Added browser ledger evidence reads for headers, state roots, state QCs, and
  canonical Norito `BlockProofs`. The SDK validates the exact proof schema and
  frame checksum, requires aligned entry/result commitments and proofs, decodes
  bounded audit paths plus FASTPQ transcripts, and binds those transcripts to
  a caller-supplied, independently authenticated executed-block projection
  while locally verifying the Iroha BLAKE2b Merkle paths. The SDK exposes no
  response-to-anchor factory and does not claim to authenticate that anchor or
  verify the node-provided finality QC.
- Added browser Connect `SignRequestRaw` support and a canonical-request auth
  adapter. Apps can request the explicit `sign_raw` permission, keep account
  keys inside the approved wallet, and sign the exact Torii canonical message
  under a fixed domain tag with shared single-flight and local Ed25519 checks.
- Contract artifact admission requires the native Rust verifier and checks
  compiler identities and the canonical manifest before signing or submission.
  Browser contract deployment rejects operations requiring native admission.
- Made canonical Torii request authentication browser-safe and first-release
  exact: `X-Iroha-Account` accepts either a canonical I105 account literal or
  a canonical lowercase ASCII account alias, rejects padded, case-foldable,
  percent-encoded, and base64-substitute credentials before I/O. The request
  input remains I105, but the emitted header uses lowercase canonical hex so it
  is valid on every HTTP stack; ASCII aliases remain literal. Removed the
  private raw-header Fetch extension and Node socket transport.
- Migrated SoraFS pin registration to the first-release canonical manifest
  contract. Requests now carry only the canonical manifest payload and
  transaction metadata, reject legacy/unknown fields and inert successors,
  and enforce canonical bounded base64 before network I/O.
- Migrated typed Sumeragi status parsing to the authoritative flattened v2
  schema. The client now rejects legacy fields, unsupported versions,
  inconsistent frozen contexts or CommitQCs, impossible queue bounds, and
  malformed canonical lane evidence; generic `/status` parsing remains a
  separate operational-health surface.
- Added a strict shared native Cargo-profile selector. Production consumers can
  request the workspace's stripped/LTO `deploy` profile, and published checksum
  entries authenticate the selected `debug`, `release`, or `deploy` profile so
  packagers can reject development addons without relying on filename or size
  heuristics.
- Made Darwin native-binding checksums survive legitimate distribution
  re-signing without weakening code identity. Native manifests now bind both
  the exact development artifact and a strict Mach-O digest that excludes only
  the final signature blob and its mutable `__LINKEDIT` size containers;
  malformed layouts and changes to any loadable byte still fail closed.
- Added the corresponding fail-closed Authenticode profile for Windows native
  addons. Manifests bind the exact unsigned PE byte length and a digest that
  masks only the PE checksum/certificate-directory fields and one final,
  aligned certificate table; runtime verification rejects absent, malformed,
  or non-final signature regions. Native builds now also emit a binary-bound
  provenance record, and published checksum entries carry the exact source Git
  revision plus whether the tree stayed clean before and after Cargo, so a
  stale ignored addon cannot be relabeled as a production build from a newer
  clean checkout.
- Aligned the Torii client with the canonical first-release route catalog:
  removed the global RBC sampling/session and collector-plan helpers plus the
  retired `torii.rbc_sampling` config projection, while retaining aggregate
  Sumeragi v2 telemetry. The resulting merged pinned-esbuild baselines are 896,722
  bytes/59 modules for `toriiClient.js` and 314,580 bytes/52 modules for the
  public browser aggregate. Multisig proposal reads now use the canonical
  `/query` and `/resolve` routes through `queryMultisigProposals` and
  `resolveMultisigProposal`; the pre-release list/get method and type names were
  removed rather than retained as aliases.
- Hardened Kotodama compiler result normalization against malformed or hostile
  native/service output. Successful manifests, recursive entrypoint schemas,
  triggers, localization/provenance metadata, and source-map/budget sidecars
  now use exact bounded V1 field contracts with cross-sidecar identity checks;
  accessors, sparse byte arrays, unsafe integers, retired `Amount`/`U128`
  leaves, and inconsistent parameter/return schemas fail closed. TypeScript
  declarations now expose the canonical `Int`/`Decimal`/`Quantity` leaf set,
  and the exact `Norito` runtime namespace includes `validateNoritoFrame`.
  Remote compilation now has a 30-second total deadline (bounded to two
  minutes when overridden), supports caller cancellation without trusting
  instance accessors, and races uncooperative Fetch/body readers while
  deterministically releasing listeners, timers, and streams. Compiler URLs
  and Fetch implementations are retained in private immutable state; responses
  require absent/identity content encoding and exact result/null sentinels.
  Successful output now checks exact IVM 1.1 deployable mode/code-memory bounds,
  zero-padded CNTR framing, ABI-1 literal descriptors and pointer TLVs, embedded
  identity/capability/count bindings, and null provenance before Rust performs
  final semantic admission. Its complete browser export bundles to exactly
  51,640 bytes (50.4 KiB, six modules, zero Node-only inputs or global `Buffer`
  assignments) under a 51 KiB gate with 584 bytes (1.13%) of headroom.
- Recalibrated only bundle ceilings that now include the mandatory shared
  Numeric V1/Quantity implementation. Pinned esbuild measures the complete
  Node Torii client at 896,722 bytes/59 modules (896 KiB ceiling, 2.32%
  headroom), the browser transaction codec at 134,314 bytes/37 modules
  (136 KiB, 3.69%), and the Nexus browser facade at 215,950 bytes/46 modules
  (216 KiB, 2.42%). The one-module increase is the shared canonical numeric
  codec used for wire decoding and Quantity readback validation, not a legacy
  compatibility copy. Exact baseline tests and the Node-input/global-`Buffer`
  browser guards remain enforced; the complete public browser aggregate is
  314,580 bytes/52 modules under its unchanged 328 KiB ceiling.
- Made native-host publication repeatable on Windows and fail closed across
  replacement failures. The publisher now locks the destination, verifies and
  probes a staged addon for the required Norito and Kotodama exports, moves an
  existing binary/checksum pair aside before replacement, publishes the new
  checksum manifest last, re-verifies the public pair, and restores the exact
  prior state while cleaning transaction artifacts on failure. Publication is
  now also durable across hard process termination: a versioned append-only
  journal, fsynced files and directory entries, exact old/new component
  inventories, and lock-held startup recovery resolve every replacement phase
  without guessing. Ambiguous, duplicated, missing, symlinked, or tampered
  recovery artifacts are preserved and rejected. Distribution/native locking
  no longer seeds source checkouts with an orphan checksum manifest, so a clean
  checkout can bootstrap its first verified native binary without weakening
  the publisher's fail-closed handling of unjournaled partial pairs. The real
  required-export probe now uses Node's native loader directly while retaining
  the legacy private staging name, preserving crash recovery across upgrades.
  Lock ownership now fingerprints the exact owner file, rechecks ownership
  before destructive phases, and atomically quarantines stale candidates so a
  replacement lock is never unlinked through a stale-lock
  time-of-check/time-of-use race. Lock
  acquisition pins the exact bytes it fsynced and observes lease mtime changes;
  staged distribution trees are recursively fsynced and rehashed around
  publication. Canonical bounded journal phases, alternate valid manifest
  encodings for an identical addon, and ambiguous crash backups now fail or
  recover deterministically.
- Fixed the npm package surface to include the canonical Apache-2.0 license and
  reject stale README or backup artifacts during pack verification.
- Fixed the Node Kotodama binding to emit its canonical three-field result
  envelope with explicit null sentinels for inactive output or diagnostics.
- Tightened instruction and Torii Numeric admission to bound text before
  `BigInt`, enforce Rust's exact signed 512-bit mantissa range, preserve source
  scale for policy validation, and reject legacy noncanonical Numeric archives.
  Governance modes now fail closed on case-folded aliases, while native-only
  nested instructions retain their authenticated unknown-schema frames.
- Migrated SoraFS orderbook and DA rent-quote monetary fields to canonical,
  unit-free XOR quantity strings. The SDK preserves scale-nine submicro and
  wider-than-u128 values, rejects lossy JSON number/BigInt coercion and retired
  micro-XOR aliases, and exposes the exact field names in runtime output and
  TypeScript declarations.
- Replaced lossy Kotodama compiler exceptions with a discriminated asynchronous
  result. Node and browser-service compilation now preserve the canonical Rust
  diagnostic fields and UTF-8 byte spans, validate artifact/manifest/sidecar
  integrity on success, and bound compiler-service success and error bodies
  while reading them.
- Made the registry artifact independently consumable: NodeNext declaration
  targets and public subpath type exports are verified from a clean packed
  layout, registry recipes are restricted to clean-install portable examples,
  and native-only workflows are explicitly source-checkout scoped. Portable
  Node Ed25519 key generation/public-key derivation now use a native-equivalent
  Node-crypto fallback when the host binary is absent while preserving
  fail-closed behavior for present-but-unverified binaries. Shipped account
  examples are curve-valid canonical I105 literals and are regression-scanned.
- Fixed the built-in browser Connect approval handoff: browser Connect verifies
  the `{accountId, walletPublicKey, signature}` proof, while the Nexus facade
  projects the account and derives its Ed25519 controller instead of treating
  the X25519 `walletPublicKey` as a transaction key. Verified approvals are now
  returned as detached per-consumer snapshots, and a second approval frame
  closes the session without replacing the first identity. Submissions using
  `{wait: true, signal}` enforce intrinsic cancellation before dispatch and
  around injected waiters, require a wait capability before submission, capture
  extension callbacks with their original owners, hard-bound response bodies
  and asynchronous callbacks, and expose immutable error classification plus
  submission-state/hash context on failures. Status iterables are raw-entry
  bounded and acquired once.
- Made `build:dist` concurrency-safe and content-idempotent: explicit builds
  stage and validate the complete ESM tree under an inter-process lock, then
  replace `dist` only when its content changed, with stale-lock recovery,
  rollback to the last good tree after interrupted publication, and a shared
  reader lock for packaging. Consuming `file:` installs no longer run a mutating
  `prepare` hook; release gates now build first and verify the exact fresh tree
  through source/dist parity, safe tarball inspection, clean installation, and
  public/subpath imports.
- Added fail-closed proof-carrying deployed-contract submission. Callers now
  provide independently trusted ledger code and full-artifact identities;
  Torii simulation, fetched bytes, derived/proved bytecode, gas, entrypoint,
  payload, and proof/verifying-key backends are bound before signing. The new
  browser-safe `computeIvmArtifactHashes` helper and `./ivm-artifact` subpath
  compute both identities and ship standalone strict-DOM declarations without
  ambient Node types. Artifacts are capped at 4 MiB before allocation and
  SharedArrayBuffer-backed inputs are rejected, while genuine cross-realm
  ArrayBuffers remain supported. Code-byte, simulation, derivation, and proof
  responses now enforce declared and streamed endpoint-specific byte caps
  before fatal UTF-8 decoding and strict JSON parsing. Validation-fee authority
  now comes only from bounded Parliament proof pages verified by the ABI 21
  native bridge against an immutable ledger binding and durable checkpoint;
  caller-supplied policy signatures and keysets were removed. Proved-IVM
  submission quotes the exact unsigned payload, rebuilds the signature-bound
  fee intent, and signs only that rebuilt transaction. IVM proof polling
  validates options before job creation and best-effort cancels failed or
  aborted jobs.

## [0.0.3] - 2026-07-11

- Hardened Nexus wallet-signing boundaries: signables are now copied and
  independently validated as canonical `Transfer::Asset` payloads before any
  signer callback, Connect and transfer alias conflicts fail closed, polling
  options are validated before Torii submission, and non-canonical scaled
  numeric archives with trailing zeros are rejected. The exported
  `validateBrowserTransferSignable` helper and executable Nexus recipe smoke
  test expose and lock the same validation contract for integrators.
- Made the complete public `./browser` aggregate bundle-safe without global
  shims: browser Buffer edges resolve through the declared `buffer` dependency,
  while browser-safe modules import a package-local crypto adapter that maps to
  streaming `@noble/hashes` SHA-256 and securely chunked Web Crypto entropy;
  Node consumers retain native crypto semantics. The `./canonical-request`
  subpath now supports secure default nonce generation in browser builds and
  ships standalone strict-DOM declarations without ambient Node types.
  Release checks bundle both that subpath and the full browser namespace,
  reject Node-only graph inputs, and enforce measured 75 KiB and 300 KiB
  production bundle ceilings respectively.

- Hardened Nexus custom-codec boundaries with descriptor snapshots, exact and
  recomputed payload hashes, independently finalized canonical signed bytes,
  conflict-checked local/Torii aliases, and pre-copy byte limits. Release
  checks now pin `esbuild`, fail closed when it is unavailable, and enforce
  measured Torii, browser transaction-codec, and browser Nexus-app bundle
  ceilings. The `./nexus-app` graph no longer imports Node/native modules in a
  browser build; its default codec and bounded Torii submit/status transport
  are browser-safe and covered by runtime and adversarial tests. Its packed
  declarations also compile for strict DOM consumers without ambient Node
  types, using the runtime `buffer` package's self-contained type export.
- Added the browser-safe `@iroha/iroha-js/transaction-codec` subpath for
  canonical transparent Ed25519 transfer payloads, external-signing prehashes,
  verified signed-transaction finalization, and compact pipeline hashes. The
  codec rejects contradictory signer state, non-canonical Norito, and bounded
  metadata violations before producing submission bytes. Canonical metadata
  strings, pre-decode field limits, and the Rust 64-byte signed-numeric range
  are enforced before parsing or large-integer conversion. Browser and Node
  Ed25519 verification now match Rust strict verification, including exact
  uncofactored equations and mixed-torsion rejection.
- Added signed Torii alias-resolution ergonomics: `resolveAlias`,
  `resolveAliasByIndex`, and `lookupAliasesByAccount` now accept
  `canonicalAuth`, and `buildCanonicalJsonRequest` builds a signed JSON request
  from either private-key bytes or an async browser-wallet signer.
- `ToriiClient.callContract` now requires a `gasLimit` in the request payload so
  callers always supply the on-chain gas cap; typings, README docs, and test
  coverage reflect the stricter contract.【javascript/iroha_js/src/toriiClient.js:15360】【javascript/iroha_js/index.d.ts:4477】【javascript/iroha_js/test/toriiClient.test.js:13919】【javascript/iroha_js/test/integrationTorii.test.js:2701】【javascript/iroha_js/README.md:1909】
- Constrained the JS SDK to the first-release surface: Connect WebSocket URLs no longer accept token
  query parameters, Torii health snapshots now only parse JSON responses, the `X-Iroha-API-Token`
  alias is no longer emitted, V1 telemetry counter aliases are dropped, and account address
  decoding rejects extension-flag headers. Tests and docs now reflect the first-release surface.
- Added `ToriiClient.iterateVerifyingKeys` and an iterator option whitelist so
  registry pagination accepts its filter fields alongside paging knobs.
- The JS SNS helpers now track the ledger-backed `/v1/sns/names...` Torii API.
  `createSnsGovernanceCase`, `exportSnsGovernanceCases`, and
  `iterateSnsGovernanceCases` are retained only as validation stubs that reject
  because Torii removed `/v1/sns/governance/cases`; README guidance, typings,
  and Jest coverage now point callers at inline governance hooks and the new
  namespace-aware SNS routes.【javascript/iroha_js/src/toriiClient.js:4121】【javascript/iroha_js/index.d.ts:6578】【javascript/iroha_js/test/toriiClient.test.js:18238】【javascript/iroha_js/README.md:3226】
- ISO bridge status normalization now constrains Torii responses to the
  expected `Pending`/`Accepted`/`Rejected` labels and validates `pacs002_code`
  against the standard `ACTC`/`ACSP`/`ACSC`/`ACWC`/`PDNG`/`RJCT` set so JS-06
  callers get deterministic errors when the bridge returns an unexpected
  state. Typings, README/docs snippets, and Jest coverage exercise the new
  validation paths.【javascript/iroha_js/src/toriiClient.js:7168】【javascript/iroha_js/index.d.ts:3600】【javascript/iroha_js/test/toriiClient.test.js:940】【javascript/iroha_js/README.md:1232】【specs/sdk/js/governance_iso_examples.md:79】
- `decodeI105AccountAddress` now enforces string inputs and surfaces a
  clear `TypeError` for non-string values, keeping JS-04 validation parity for
  I105 helpers and preventing accidental coercion when decoding selectors.
  Jest coverage guards the new behaviour.【javascript/iroha_js/src/address.js:1635】【javascript/iroha_js/test/address.test.js:482】
- Added optional SNS integration smoke coverage gated by
  `IROHA_TORII_INTEGRATION_SNS_SUFFIX`/`IROHA_TORII_INTEGRATION_SNS_SELECTOR`
  so JS-04/ADDR-5 adopters can validate suffix policies and registration
  payloads against live Torii deployments without bespoke scripts. README
  environment docs and integration assertions cover the new toggles.【javascript/iroha_js/test/integrationTorii.test.js:2988】【javascript/iroha_js/README.md:2015】
- Added `ToriiClient.submitIsoMessage`, which builds pacs.008/pacs.009 payloads
  from structured fields, applies pacs-specific `Content-Type` defaults, reuses
  a single `AbortSignal` across submission and polling, and optionally waits
  for a terminal bridge status. Typings, README/docs snippets, and Jest
  coverage keep the JS-06 advanced ISO bridge flow deterministic for CI and
  operators.【javascript/iroha_js/src/toriiClient.js:493】【javascript/iroha_js/index.d.ts:5420】【javascript/iroha_js/test/toriiClient.test.js:2876】【javascript/iroha_js/README.md:1243】【specs/sdk/js/governance_iso_examples.md:92】
- Hardened `ToriiClient.waitForTransactionStatus{,Typed}` by validating the
  polling options up front: the helper now requires the options payload to be a
  plain object, enforces non-negative `intervalMs`/`timeoutMs`, positive
  `maxAttempts`, and a functional `onStatus` callback while reusing the same
  guards inside `submitTransactionAndWait`. README snippets and Jest coverage
  document the stricter JS-04 validation so callers receive actionable
  `TypeError`s before any Torii request is issued.【javascript/iroha_js/src/toriiClient.js:1756】【javascript/iroha_js/test/toriiClient.test.js:2598】【javascript/iroha_js/README.md:148】
- Added `ToriiClient.submitDaBlob` together with the DA ingest builder, typings, README
  snippet, and Jest coverage so JS-04/DA-8 callers can mirror the
  `iroha da submit` payload (BLAKE3 digest, typed metadata, retention policy) directly from
  Node without shelling out to the CLI.【javascript/iroha_js/src/toriiClient.js:1163】【javascript/iroha_js/src/dataAvailability.js:22】【javascript/iroha_js/index.d.ts:4030】【javascript/iroha_js/README.md:770】【javascript/iroha_js/test/toriiClient.test.js:1408】
- Added `buildDaProofSummaryArtifact` and `emitDaProofSummaryArtifact` so DA-8 proof
  workflows can serialise PoR summaries into the same Norito JSON emitted by
  `iroha da prove-availability`, with README usage, typings, and Jest coverage to keep the
  CLI-compatible artefacts reproducible from JS automation.【javascript/iroha_js/src/dataAvailability.js:111】【javascript/iroha_js/index.d.ts:3273】【javascript/iroha_js/README.md:820】【javascript/iroha_js/test/dataAvailability.proof.test.js:1】
- Hardened the Torii iterable/list/query helpers to reject non-object options,
  raising a `TypeError` before any HTTP call and documenting the stricter
  contract with README + Jest coverage so JS-04 validation stays aligned with
  the Rust/Python SDKs.【javascript/iroha_js/src/toriiClient.js:4391】【javascript/iroha_js/test/toriiClient.test.js:4452】【javascript/iroha_js/README.md:1689】
- Hardened the SoraFS, data availability, and UAID ToriiClient helpers by
  routing them through a shared `_normalizeOptionsWithSignal` guard so malformed
  `options` payloads are rejected before hitting Torii, and added Jest coverage
  to exercise the new JS-04 validation paths across the registry, PoR, storage,
  DA ingest, and Space Directory surfaces.【javascript/iroha_js/src/toriiClient.js:889】【javascript/iroha_js/src/toriiClient.js:5320】【javascript/iroha_js/test/toriiClient.test.js:1872】
- `ToriiClient.getSorafsPinManifest` now returns the exact finalized native
  `{ finalized_cursor, manifest }` response (or `null` for `404`), validates
  approval history, and exposes only the native manifest record. Alias and
  replication inventories are queried through their dedicated endpoints.
- Added `ToriiClient.getUaidPortfolio`, `getUaidBindings`, and `getUaidManifests`
  plus TypeScript definitions, README docs, and Jest coverage so the JS SDK
  mirrors the Nexus NX-16 UAID portfolio and Space Directory manifest APIs
  without bespoke JSON parsing. The helpers validate UAID literals, lifecycle
  metadata, and dataspace filters, keeping the new universal-account surfaces in
  lockstep with the Torii reference docs.【javascript/iroha_js/src/toriiClient.js:1234】【javascript/iroha_js/index.d.ts:3255】【javascript/iroha_js/README.md:818】【javascript/iroha_js/test/toriiClient.test.js:964】【specs/torii/portfolio_api.md:1】
- Added `ToriiClient.callContract` with typed request/response normalisation so
  Node.js clients can invoke `/v1/contracts/call` without hand-crafting JSON,
  keeping contract execution coverage aligned with the roadmap’s JS-04/JS-06
  goals.
- Added `ToriiClient.iterateConnectApps` along with cursor-aware pagination
  helpers, TypeScript definitions, README usage, and Jest coverage so Connect
  registry admins can stream `/v1/connect/app/apps` listings without manual
  `cursor` bookkeeping, advancing the roadmap’s JS-04 complex pagination
  deliverable.
- Added `ToriiClient.getExplorerAccountQr` with typed DTOs, TypeScript
  definitions, README usage, and Jest coverage so wallets and explorers can
  fetch share-ready QR payloads in canonical I105 form directly from Torii
  instead of reimplementing the renderer, progressing ADDR-6b’s SDK coverage
  goals.【javascript/iroha_js/src/toriiClient.js:1440】【javascript/iroha_js/index.d.ts:3513】【javascript/iroha_js/README.md:1538】【javascript/iroha_js/test/toriiClient.test.js:6650】
- Broadened the Dockerised integration smoke suite to cover asset re-mint
  flows, iterator-based queries, and an optional ISO `pacs.008` submission; the
  README now documents the new environment toggles and the CI workflow emits
  runtime/cache telemetry so JS-10’s “docs + tests + metrics” gate exercises
  more real-world scenarios.【javascript/iroha_js/test/integrationTorii.test.js:1】【javascript/iroha_js/README.md:1325】【.github/workflows/javascript-sdk.yml:56】
- Hardened `ToriiClient.createConnectSession`/`deleteConnectSession` by
  normalising `sid`, enforcing the 32-byte base64url/hex requirement, surfacing
  `extra` metadata, and rejecting malformed Torii responses so the Connect
  overlay helper satisfies the roadmap’s JS-04 validation goals. The README
  example now calls out the sid constraints plus returned URIs/tokens, and the
  TypeScript definitions/tests document the stricter behaviour.【javascript/iroha_js/src/toriiClient.js:2532】【javascript/iroha_js/README.md:1147】【javascript/iroha_js/test/toriiClient.test.js:5731】
- Added `generateConnectSid` and `createConnectSessionPreview` with README usage,
  TypeScript definitions, and Jest coverage so the JS SDK can mint session ids,
  derive deeplink URIs, and expose the Connect preview workflow called out in
  the roadmap’s JS-04 Connect deliverable.【javascript/iroha_js/src/connectSession.js:1】【javascript/iroha_js/index.d.ts:1295】【javascript/iroha_js/README.md:1140】【javascript/iroha_js/test/connectSession.test.js:1】
- Added `bootstrapConnectPreviewSession` to bundle the preview + Torii
  registration flow in one helper, with README docs, TypeScript declarations,
  and tests so JS SDK consumers can script the Connect preview setup without
  rewriting the session orchestration logic.【javascript/iroha_js/src/connectPreviewFlow.js:1】【javascript/iroha_js/src/index.js:1】【javascript/iroha_js/index.d.ts:1473】【javascript/iroha_js/README.md:1367】【javascript/iroha_js/test/connectPreviewFlow.test.js:1】
- Added normalised pipeline status helpers
  (`getTransactionStatus`, `getTransactionStatusTyped`,
  `waitForTransactionStatusTyped`, `submitTransactionAndWaitTyped`) with
  TypeScript definitions, README usage, and Jest coverage so JS-04 validation
  also covers the `/v1/pipeline/*` surfaces: the raw helper now enforces the
  canonical `kind`/`content.hash`/`status.kind` layout while the typed
  wrappers expose DTOs instead of forcing consumers to inspect Torii's JSON
  blobs.
- Added `getNetworkTimeNow` and `getNetworkTimeStatus` helpers (with TypeScript
  definitions, README usage, and tests) so the JS SDK can query the `/v1/time/*`
  endpoints and keep the NRPC/AND7 network-time diagnostics in lockstep with
  the Rust/Python clients.
- Normalized `ToriiClient.getHealth()` so it returns a typed `{status: string}`
  snapshot when Torii replies with JSON payloads, keeping the health telemetry
  surface aligned with JS-04 validation coverage.
- Normalised `ToriiClient.getBlock`/`listBlocks` responses into the typed
  `ToriiExplorerBlock` and `ToriiExplorerBlocksPage` DTOs (404 now yields `null`
  for `getBlock`), added TypeScript definitions/README docs, and extended the
  Jest suite so the explorer block endpoints enjoy the same JS-04 validation
  guarantees as the rest of the Torii query surface.
- Added `ToriiClient.listTelemetryPeersInfo` plus the corresponding DTOs,
  TypeScript declarations, README usage example, and unit tests so the JS SDK
  exposes the `/v1/telemetry/peers-info` surface that Rust/Python clients rely
  on for telemetry replay/peer analytics.
- Added `NoritoRpcClient` and the accompanying `NoritoRpcError`, TypeScript
  definitions, and tests so Node consumers can call the binary Norito-RPC
  surface with first-class helpers instead of wiring bespoke fetch logic.
- Added the missing `ToriiClient.submitTransactionAndWait` helper so the
  runtime now matches the published TypeScript definitions, validating
  `hashHex` inputs and reusing the existing pipeline polling logic.
- Added `ToriiClient` helpers for Sumeragi observability endpoints
  (`getSumeragiQc`, `getSumeragiBlsKeys`,
  `getSumeragiLeader`, `getSumeragiParams`) with README
  examples, TypeScript definitions, and tests
  so JS SDK consumers can inspect the same `/v1/sumeragi/*` diagnostics that
  Rust tooling relies on for roadmap JS-08 coverage.
- Hardened `listGovernanceInstances`/`listContractInstances` validation so
  `hashPrefix` must be hexadecimal and `order` is clamped to the Torii-supported
  values (`cid_asc`, `cid_desc`, `hash_asc`, `hash_desc`). The TypeScript
  definitions now encode the same order enum to keep JS-04 validation/typedef
  parity green.
- Added governance HTTP helpers (`governanceProposeDeployContract`,
  `governanceSubmitPlainBallot`, `governanceSubmitParliamentBallot`,
  `governanceSubmitZkBallotV1`, `governanceSubmitZkBallotProofV1`) with input
  validation, README snippets, and TypeScript definitions so the JS SDK covers
  the `/v1/gov/proposals/deploy-contract` and ballot DTOs described in
  `specs/governance_api.md`.
- Removed legacy `addressFormat` support from `ToriiClient.listAccounts`/`queryAccounts`;
  SDK account-list/query helpers are now canonical I105-only.
- Added runtime capability helpers to `ToriiClient`
  (`getNodeCapabilities`, `getRuntimeAbiActive`, `getRuntimeAbiHash`,
  `getRuntimeMetrics`, `listRuntimeUpgrades`) with README snippets, TypeScript
  definitions, and unit tests so JS-07 advanced endpoint coverage now includes
  the `/v1/node/capabilities` and `/v1/runtime/*` surfaces exposed by Torii.
- Added runtime upgrade transaction helpers
  (`proposeRuntimeUpgrade`, `activateRuntimeUpgrade`, `cancelRuntimeUpgrade`)
  so rollout automation can post manifests and fetch transaction skeletons
  directly from the JS SDK, complete with typed inputs, README examples, and
  Jest coverage.
- Added the missing `iterate*Query` TypeScript declarations
  (`iterateAccountsQuery`, `iterateDomainsQuery`,
  `iterateAssetDefinitionsQuery`, `iterateNftsQuery`,
  `iterateAccountAssetsQuery`, `iterateAccountTransactionsQuery`,
  `iterateAssetHoldersQuery`) so the typings now match the runtime
  implementation and close the remaining JS-04 validation/type gaps.
- Added shared Torii governance/query fixtures
  (`javascript/iroha_js/test/fixtures/torii_responses.json`) and migrated the
  `toriiClient` governance + iterable tests to those payloads so JS-04 parity
  checks rely on the same deterministic responses that Rust/Python SDKs use
  for ballot/proposal/council validation.
- Hardened `ToriiClient.listSumeragiEvidence` so responses are validated and
  normalised into the typed `SumeragiEvidenceRecord` structures, rejecting
  malformed fields and keeping runtime behaviour aligned with the published
  TypeScript definitions/tests.
- Validated alias resolution responses for `ToriiClient.resolveAlias` and
  `resolveAliasByIndex`, normalising payloads into the published
  `AliasResolutionDto` shape and rejecting malformed fields so JS-04 query
  parity remains strict across runtimes. Tests now assert both happy-path
  normalisation and failure diagnostics.
- Added `listSorafsPinManifests` to `ToriiClient` plus typed DTOs for the pin
  registry so SDK consumers can page strict finalized summaries from
  `/v1/sorafs/pin` with status filters, bounded keyset pagination, and
  consensus-maintained charged usage totals.
- Added `listSorafsAliases` and `listSorafsReplicationOrders` to `ToriiClient`
  so the JS SDK can page the `/v1/sorafs/aliases` and `/v1/sorafs/replication`
  endpoints with typed attestation metadata, fulfilling the remaining JS-07
  coverage for the pin registry's observability APIs.
- Added `ToriiClient.iterateSorafsPinManifests`,
  `iterateSorafsAliases`, and `iterateSorafsReplicationOrders` with README
  snippets, TypeScript declarations, and Jest coverage so the offset iterator
  helper can stream the SoraFS registry endpoints without bespoke pagination,
  extending the JS-07 query wrapper work to the storage APIs.【javascript/iroha_js/src/toriiClient.js:681】【javascript/iroha_js/index.d.ts:3408】【javascript/iroha_js/test/toriiClient.test.js:760】【javascript/iroha_js/README.md:732】
- Tightened the Sumeragi telemetry helpers by normalising the
  `getSumeragiQc`, `getSumeragiBlsKeys`,
  `getSumeragiLeader` and `getSumeragiParams`
  responses (raising type errors on malformed telemetry)
  and corrected the `getSumeragiStatus` TypeScript declaration to reflect that
  it returns the raw Torii payload while `getSumeragiStatusTyped` provides the
  validated snapshot.

## [0.0.2] - 2026-01-27

- Added governance instruction support to native Norito helpers so standalone
  ZK and plain ballot instructions round-trip through `noritoEncodeInstruction`.
  Proposal-backed certification and execution are consensus-owned and have no
  client-side roster, finalize, or enact builders.
- Updated the native build script to try an offline cargo build first and
  automatically retry online when dependencies are missing.
- Added release documentation automation script covering changelog/status/roadmap updates.
- Added opt-in Torii integration smoke tests and documentation for exercising ISO bridge, RBC sampling, and Connect endpoints from the JS SDK.
- Added `submitIsoPacs009` helper mirroring the new Torii `/v1/iso20022/pacs009` endpoint,
  updated recipes/README, and extended TypeScript definitions/tests so PvP funding legs can be
  submitted from the SDK alongside pacs.008 flows.

## [0.0.1] - 2024-01-01

- Initial preview release of the Norito/Torii JavaScript SDK.

<!--
Maintainer note: keep this changelog aligned with the versions published to npm.
Continue to follow the Keep a Changelog format with ISO-8601 dates.
-->
