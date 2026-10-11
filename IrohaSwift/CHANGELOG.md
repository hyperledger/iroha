# Changelog

All notable changes to `IrohaSwift` are documented in this file.

## [Unreleased]

- `KagemushaWalletDigestRoleV1` follows the 2026-10-05 KAGEMUSHA wallet wire
  revision: the `credit`, `proof`, `stepProof`, `payment`, `blacklistLeaf`,
  `blacklistNode`, `quotaWindow` and `quotaNode` roles are removed, because those
  values are now Poseidon σ-field values that the native Rust core computes, and
  `verifyingKeySet` is added (55 roles). `KagemushaWalletWireV1` adds
  `fieldModulus`, `fieldValueBytes` and `isCanonicalFieldValue(_:)`, and the
  `paymentFixedBytes`, `paymentProofBudgetBytes`, `verifyingKeyEntriesMaximum`,
  `verifyingKeyAllowlistMaximumBytes` and `creditOpeningSiblingsMaximum` bounds.
- Added `KagemushaWalletApplePlatformV1`, the iPhone platform adapter behind the
  Rust KAGEMUSHA wallet Advance provider: the Secure Enclave payment key, the
  keychain rollback anchor, the Complete-class protected-data canary, the custody
  root under Application Support and the boot session identity. Both custody
  keychain items are `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` in the
  app's own access group, which `init(appAttest:applicationIdentifierPrefix:)`
  derives from the App ID prefix. The adapter is constructible only for iPhone
  and iPad apps on their own device. `attestEnrollment(slot:paymentPublicKey:challengeDigest:)`
  produces the App Attest evidence of enrollment step E5
  (`KagemushaWalletAppleEnrollmentEvidenceV1`), with
  `KagemushaWalletAppleEnrollmentAttestationErrorV1` and
  `KagemushaWalletAppleAppAttestStageV1` for failures. The slot, profile,
  unavailable-reason, status and configuration-error types are public.
- Removed the aggregate-balance KAGEMUSHA wallet and its consumers, superseded by
  the KAGEMUSHA wallet V1 design (`KagemushaWalletWireV1` and
  `KagemushaWalletApplePlatformV1`): the wire codec and models (`KagemushaNoritoV1`,
  `KagemushaWireV1`, `KagemushaModelsV1`), `KagemushaWalletV1` orchestration, the
  hardware-provider, device-lifecycle and Core coordinator bridges, the App Attest
  ordinary enrollment and approval providers, reserve finality, top-up and
  redemption. `ToriiClient` no longer exposes `getKagemushaCapability`,
  `submitKagemushaTopUp`, `submitKagemushaRedemption`, `getKagemushaOperation`,
  `ToriiKagemushaStatus`, the `ToriiKagemushaOperation*` types or
  `ToriiTopUpOwnershipV1`; `TxBuilder.buildSignedKagemushaTopUp` and
  `KagemushaTopUpTransactionInputError` are gone. `ParticipantEnrollmentHttpCodecV1`,
  `AndroidProvisionedProof` and the `IrohaSwiftTransferUI` KAGEMUSHA flow views
  (`IrohaKagemushaFlowView` and its widgets) were removed with them. The native
  bridge loader no longer requires any `connect_norito_kagemusha_*` export, since
  the bridge exports none.
- Removed the signature-only KAGEMUSHA wallet suite (`Sources/IrohaSwift/KagemushaAttested/`):
  `KagemushaAmount`, `KagemushaConfig`, `KagemushaAccountProof`,
  `KagemushaLedgerPort`, `KagemushaPlatform`, `KagemushaStatus`,
  `KagemushaReadyState`, `KagemushaLimit`, `KagemushaError`, `KagemushaRefusal`,
  `KagemushaUnsupportedReason`, `KagemushaFrozenReason`,
  `KagemushaRevocationReason`, `KagemushaLoadResult`, `KagemushaOutgoingPayment`,
  `KagemushaReceiveResult`, `KagemushaRedemptionStatus`, `KagemushaRedeemResult`,
  `KagemushaDeliveredPayment`, `KagemushaSyncResult`, `KagemushaPeerMessage`,
  `KagemushaIssuerTransport`, `KagemushaURLSessionTransport` and the DEBUG-only
  `KagemushaTestKeyStore` and `KagemushaTestAttestationProvider`. Its Secure
  Enclave key handling moved into `KagemushaWalletApplePlatformV1`; the Rust
  provider owns custody storage and enrollment parsing.
- Collection queries follow `specs/torii/collection_queries.md`: `ToriiFilter`
  (builder operators, result builder, canonical text `description` and JSON
  `jsonData()`, client-side limits), `ToriiSortKey`, `ToriiAggregate`,
  `ToriiListQuery` (canonical `POST /query` body and `GET` parameters),
  `ToriiPage` and the on-demand `ToriiPageSequence`/`ToriiItemSequence`, checked
  against `fixtures/torii/list_query/vectors.json`. `ToriiClient` exposes
  `domains`, `accounts` (with `get(_:)`), `assetDefinitions`, `nfts`, `rwas`,
  `repoAgreements`, `accountAssets(of:)`, `assetHolders(of:)`, the history
  collections `transactions` and `accountTransactions(of:)` (rows
  `ToriiTransaction`, newest first; `sort`, `includeTotal` and `aggregate`
  rejected locally; pagers follow `nextCursor` across short and empty pages)
  with typed rows whose non-identity fields are optional. Filters with object or
  array literals are sent only in the JSON form (`queryItems()` and event
  streams reject them). Removed `listDomains`,
  `iterateDomains`, `listRwas`, `queryRwas`, `iterateRwas`, `getAssets`,
  `getTransactions`, their completion/Combine/`IrohaSDK` twins and
  `ToriiListOptions`/`ToriiListFilter`/`ToriiListSort`/`ToriiQueryEnvelope`
  and the offset/`total`-based page types.
- Torii error responses surface as `ToriiClientError.api(ToriiAPIError)` with
  `status`, envelope `code`, `message`, `details` and the `X-Iroha-Reject-Code`
  header; `ToriiClientError.invalidQuery` reports locally rejected controls with
  the same codes. `ToriiClientError.httpStatus` was removed.
- Event streams decode the specified `/v1/events/sse` payloads into `ToriiEvent`
  (pipeline transaction, block, warning and witness events; proof verified,
  rejected and pruned events; `.data`/`.other` notices for every other kind, so
  unknown events never fail a stream), wrapped in `ToriiEventMessage`.
  Transaction statuses, block statuses and `ToriiTransactionRejectionCode` are
  typed from their names. New `streamEvents(filter:)`/`streamEvents(filterText:)`
  take the collection text grammar, and built filters are checked against the
  event-stream subset before connecting. The transaction-status stream sends
  `tx_hash = "…"` and checks every event's hash (including the trailing one);
  proof streams send `proof_backend`/`proof_call_hash`/`proof_envelope_hash`
  filters and match pruning events too; `streamVerifyingKeyEvents()` and
  `streamTriggerEvents()` recognise their events by kind. The retired
  `{"VerifyingKey": …}`, `{"Trigger": …}` and `{"Proof": …}` shapes, their
  typed payloads and filters (`ToriiVerifyingKeyEventFilter`,
  `ToriiTriggerEventFilter`, `ToriiVerifyingKeyEvent`, `ToriiTriggerEvent`) were
  removed. Event streams follow the same transport policy as other requests
  (HTTPS for credentials, no redirects) and surface rejections with the parsed
  error envelope.
- `+` in query values is percent-encoded; `getStatusSnapshot()` no longer races
  on its sample state; `AccountId.make(publicKey:)` throws instead of trapping;
  building a transfer with a non-empty `TransferRequest.description` throws
  `TransactionInputError.transferDescriptionUnsupported` instead of silently
  dropping the memo; the always-failing `deployContractInstance` and
  `activateContractInstance` were removed.
- `ToriiCanonicalRequestAuth` is now only the account credential
  (`accountId`, `privateKey`); its `timestampMs`/`nonce` were removed because a
  reused credential replayed one nonce. `ToriiClient`, `MusubiToriiClientV1` and
  `AtomicPrivateSettlementToriiClientV1` draw a fresh timestamp and nonce for
  every signed request from `ToriiCanonicalRequestFreshness` (injectable for
  tests), so pinned-freshness errors and their both-or-neither checks are gone.

- Added the Petal Stream optical transport (`Sources/IrohaSwift/Petal/`), a
  function-by-function port of `crates/iroha_petal`: CRC-32C bound streams,
  whitened GF(256) Reed–Solomon lanes with errors-and-erasures decoding,
  the GF(2) fountain code (`PetalStreamEncoder`, `PetalStreamAssembler`),
  the reference software renderer and `PetalDrawList`, the camera decoder
  (`PetalDecoder`: adaptive threshold, blossom finders, Hartley-normalised
  homographies, joint polarity/katakana tile matching read against the finder
  levels and, for a lane that stays unreadable, again with every patch and
  template normalised by its own contrast so over-exposure, veiling light,
  glare and shadows cancel; rotation and mirror hypotheses ranked by the ring
  gates and the `天` silhouette; a blossom hidden by a thumb, a glare or the
  frame edge is inferred from the other three and reported as
  `PetalDecodedFrame.inferredCorner`) and `PetalScanSession`, which follows
  the code from its last pose (`PetalDecoder.track`, within 500 ms) instead
  of searching every frame and counts `tracked` and `inferred` frames in
  `PetalScanStats`. The suites check every section of
  `fixtures/petal/petal_stream_v1.json`, decode all eleven golden captures in
  `fixtures/petal/petal_captures_v1.json` with exactly the reference lanes and
  inferred corners, follow both tracking pairs and reproduce the clean capture
  pixel for pixel. `IrohaSwiftTransferUI` adds
  `PetalCoreGraphicsRenderer`, `PetalFrameView` and the animated
  `PetalStreamView`; `IrohaSwiftMobileTransports` adds the AVFoundation
  `PetalCameraAnalyzer` and `PetalCameraFrame` pixel-buffer conversion.
- `ToriiPipelinePreflight` decodes exactly the served `GET /v1/pipeline/preflight`
  body, checked against the Rust-generated `fixtures/torii/pipeline_preflight.json`:
  `ToriiPipelinePreflightSumeragi` carries only the positive `blockCadenceMs`,
  every object rejects fields Torii does not serve, unsigned limits reject
  negative values, fee amounts are `String`s and `settlementMode` is `direct` or
  `lane_relay_burn`. Torii serves no stall threshold, so
  `ToriiPipelinePreflight.stallThresholdMs` (`stallBlockCadences` = 20 times the
  block cadence) now drives `isStatusStalled(_:)`; `blockTimeMs`,
  `commitTimeMs` and `stallThresholdMs` were removed from the sumeragi section.
- Added `ToriiClient.getSumeragiLanes()` (async and completion-handler forms)
  for the operator-signed `GET /v1/sumeragi/lanes` list. Responses decode
  fail-closed into `ToriiSumeragiLaneStatus` (exact fields, canonical
  BLS-normal committee keys, 96-byte proofs of possession, uppercase 32-byte
  hex lane hashes) and are tested against the shared Rust-generated
  `fixtures/sumeragi/native_lanes_v1.tsv` corpus.
- Pinned Norito v1 headers to the fixed-width (`0x00`) and compact
  (`COMPACT_LEN`, `0x02`) layouts. `NoritoHeader.packedSeq`, `packedStruct`,
  `fieldBitset`, `varintOffsets`, and `compactSeqLen` were removed, and headers
  carrying any flag other than `COMPACT_LEN` (or none) are rejected.
  `ConfidentialEncryptedPayload.noritoEnvelope()` now defaults to
  `COMPACT_LEN` (payload bytes are unchanged), and the Connect queue journal
  rejects records whose header flag byte is non-zero.
- Replaced Explorer instruction, transaction, and transfer-history page-number
  pagination with snapshot-bound `cursor`/`limit` APIs and strict continuation
  metadata. The async, completion-handler, `IrohaSDK`, and Combine surfaces now
  share the same first-release contract; instruction boxes also expose the
  server-provided framed SHA-256 digest. Explorer lists, details, streams, and
  contract activity/event reads plus the generic event SSE feed now use the
  client's default canonical request signer when configured, while remaining
  anonymous for public dataspaces.
- Replaced the governance mutation boundary with closed public-only request
  types. Deploy proposals no longer expose ignored limits and now use typed
  manifest provenance; ZK public inputs are exact and shared across legacy,
  v1-envelope, and nested BallotProof routes; Parliament ballots use canonical
  enums; and plain-ballot durations encode as canonical decimal JSON strings.
  Added Swift client and `IrohaSDK` helpers for the v1-envelope, BallotProof,
  and Parliament ballot endpoints. Governance windows are ordered across REST
  and local transaction builders, ZK backends are exact tokens, enactment
  requests expose only the authoritative proposal id, deploy builders require
  ABI V1, and locally signed ZK ballots use the same closed typed public-input
  model with recursive private-key-alias defence.
- Bound the `CancelAssetLock` lock-ID preimage to the public V1 limit of 4,096
  UTF-8 bytes while preserving the fixed 32-byte `EscrowId` wire field.
- Added strict typed `CancelAssetLock` V1 parity. Swift now derives the native
  marked Blake2b-256 escrow id from a clean lock id, requires an exact positive
  `expected_remaining_amount`, emits a transaction-ready schema-bound Norito
  frame, and rejects the retired one-field JSON/Norito layout, aliases, extras,
  malformed identifiers, noncanonical quantities, and trailing bytes.
