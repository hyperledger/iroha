// Message and cell layouts of the SCCP v1 TON contracts (§5.3.2, §5.3.3).
//
// Field order is serialization order; every struct is the exact TL-B of the
// spec. The minter never reads a referenced cell of a message through these
// types: the automatic parser resolves library cells and throws exit code 9
// on a shape mismatch. The certificate cells (`TairaCert`, `QcFixed`,
// `XHead`, `XTail`, `CheckpointRef`) are opened by `sccp-finality.tolk`, the
// proof cells (`BlockRef`, `MessageProof`, `ControlProof`) by
// `sccp-verify.tolk` and the variable-shape cells (`SnakeBytes`, `HashChunk`,
// `KeyChunk`), burn wrappers and consumption tails by `sccp-cells.tolk`.
// Each of them checks that the cell is
// ordinary and has exactly the bit and reference counts of its layout, with
// the exit codes listed in `sccp-errors.tolk`.

/// `qc_fixed#_` — `QC_FIXED` without its trailing `signers` word (896 bits).
struct QcFixed {
    epoch: uint64
    epochContext: uint256
    view: uint64
    blockHash: uint256
    resultBody: uint256
}

/// `x_tail#_` — `X[109..221)` (896 bits).
struct XTail {
    bytes: bits896
}

/// `x_head#_` — `X[0..109)` (872 bits) and its tail.
struct XHead {
    bytes: bits872
    tail: Cell<XTail>
}

/// `taira_cert#_` — a `CommitQC` of the current generation over `X` (§5.3.2).
struct TairaCert {
    /// Compressed G2 aggregate signature (96 bytes).
    signature: bits768
    /// `be32(Σ_j bitmap[j] << 8j)`: bit `i` is canonical index `i` (§3.7).
    signers: uint32
    qc: Cell<QcFixed>
    x: Cell<XHead>
}

/// `checkpoint_ref#_` — a stored checkpoint, named by its `X` (§5.1.3).
struct CheckpointRef {
    x: Cell<XHead>
}

/// `block_ref#_` (`BlockRefV1`, §5.1.5; 425 data bits).
struct BlockRef {
    height: uint64
    sccpRoot: uint256
    messageCount: uint32
    historyIndex: uint64
    pathLen: uint8
    /// `(Maybe ^HashChunk)`, present iff `pathLen > 0`.
    path: cell?
}

/// `message_proof#_` (`MessageProofV1`, §5.1.5; 41 data bits).
struct MessageProof {
    leafIndex: uint32
    pathLen: uint8
    /// `^SnakeBytes` with the §3.2 payload.
    payload: cell
    /// `(Maybe ^HashChunk)`, present iff `pathLen > 0`.
    path: cell?
    block: Cell<BlockRef>
}

/// `control_proof#_` (`ControlProofV1`, §5.1.6; 690 data bits).
struct ControlProof {
    controlNonce: uint64
    track: uint8
    parliamentPaused: bool
    fastPauseUntilMs: uint64
    certificateId: uint256
    effectHash: uint256
    leafIndex: uint32
    pathLen: uint8
    path: cell?
    block: Cell<BlockRef>
}

/// `consume_tail#_` of every bucket consume round trip.
struct ConsumeTail {
    /// `SCCP_CONSUME_KIND_MINT` or `SCCP_CONSUME_KIND_VOID`.
    kind: uint1
    /// Mint recipient (owner of the Jetton wallet); `addr_none` for voids.
    recipient: address?
    /// Excess destination chosen by the caller.
    response: address
    messageId: uint256
}

/// TEP-74 burn custom payload required by SCCP wallets.
struct (0x53434254) SccpBurnToTaira {
    /// `^SnakeBytes` with the `taira_account` recipient bytes (1..=1024).
    recipient: cell
}

// ---------------------------------------------------------------------------
// Messages to the minter.

struct (0x53434930) SccpInit {
    queryId: uint64
}

/// One certificate of `submitCheckpoints` (§5.1.2–§5.1.3). `nextKeys` is
/// required iff a rotation applies with `X.next_committee_root ≠ cur.root`;
/// otherwise it is ignored and not read.
struct (0x53434b31) SccpCheckpoint {
    queryId: uint64
    response: address
    cert: Cell<TairaCert>
    /// `(Maybe ^KeyChunk)`.
    nextKeys: cell?
}

struct (0x53434631) SccpFinalize {
    queryId: uint64
    response: address
    cert: Cell<TairaCert>
    message: Cell<MessageProof>
}

struct (0x53434632) SccpFinalizeCheckpoint {
    queryId: uint64
    response: address
    ref: Cell<CheckpointRef>
    message: Cell<MessageProof>
}

struct (0x53435631) SccpVoidExpired {
    queryId: uint64
    response: address
    nonce: uint64
    cert: Cell<TairaCert>
    message: Cell<MessageProof>
}

struct (0x53435632) SccpVoidExpiredCheckpoint {
    queryId: uint64
    response: address
    nonce: uint64
    ref: Cell<CheckpointRef>
    message: Cell<MessageProof>
}

struct (0x53435633) SccpVoidFrozen {
    queryId: uint64
    response: address
    firstNonce: uint64
    count: uint16
}

struct (0x53434d31) SccpApplyControl {
    queryId: uint64
    response: address
    cert: Cell<TairaCert>
    control: Cell<ControlProof>
}

struct (0x53434d32) SccpApplyControlCheckpoint {
    queryId: uint64
    response: address
    ref: Cell<CheckpointRef>
    control: Cell<ControlProof>
}

struct (0x53434431) SccpDeployBuckets {
    queryId: uint64
    response: address
    count: uint8
}

/// Bucket reply: the nonce was unset and is now consumed (bounceable).
struct (0x53434332) SccpConsumed {
    queryId: uint64
    nonce: uint64
    amount: uint96
    tail: Cell<ConsumeTail>
}

/// Bucket reply: the nonce was already consumed (bounceable).
struct (0x53434336) SccpAlreadyConsumed {
    queryId: uint64
    nonce: uint64
    amount: uint96
    tail: Cell<ConsumeTail>
}

/// Bucket reply: the whole range is now consumed (bounceable).
struct (0x53434334) SccpRangeConsumed {
    queryId: uint64
    first: uint64
    count: uint16
}

/// Bucket reply: some nonce of the range was already consumed.
struct (0x53434337) SccpRangeRejected {
    queryId: uint64
    first: uint64
    count: uint16
}

/// Bucket report: the minter bounced `sccp_consumed` or
/// `sccp_already_consumed` for `nonce`, so its pending `amount` is released
/// (bounceable; the bucket ignores its bounce).
struct (0x53434339) SccpConsumeReverted {
    queryId: uint64
    nonce: uint64
    amount: uint96
}

/// Re-runs the recorded asynchronous step keyed by `nonce` (§5.3.4).
struct (0x53435931) SccpRetry {
    queryId: uint64
    response: address
    operationId: uint64
}

/// One reserved original operation. Its first 168 bits bind every bounce to
/// an immutable operation, stage and attempt before any optional data is read.
struct (0x53435231) SccpRecoveryDispatch {
    operationId: uint64
    stage: uint8
    attempt: uint64
    nonce: uint64
    count: uint16
    amount: uint96
}

/// Queries an existing receipt; never repeats the original effect.
struct (0x53435232) SccpRecoveryConfirm {
    operationId: uint64
    stage: uint8
    attempt: uint64
}

/// Deletes exactly one completed stage's receipt, including on retry.
struct (0x53435233) SccpRecoveryDrop {
    operationId: uint64
    stage: uint8
    attempt: uint64
}

/// Authenticated result: missing, applied, rejected, or deletion confirmed.
struct (0x53435234) SccpRecoveryAck {
    operationId: uint64
    stage: uint8
    attempt: uint64
    result: uint8
}

/// TEP-74 burn notification extended with the SCCP recipient (§5.3.3).
struct (0x7bdd97de) BurnNotificationForMinter {
    queryId: uint64
    jettonAmount: coins
    burnInitiator: address
    sendExcessesTo: address?
    sccp: Cell<SccpBurnToTaira>
}

/// `top_up query_id:uint64`: anyone may add value to a minter, wallet or bucket.
struct (0xd372158c) TopUpTons {
    queryId: uint64
}

/// TEP-89 `provide_wallet_address`.
struct (0x2c76b973) RequestWalletAddress {
    queryId: uint64
    ownerAddress: address
    includeOwnerAddress: bool
}

/// TEP-89 `take_wallet_address`.
struct (0xd1735400) ResponseWalletAddress {
    queryId: uint64
    jettonWalletAddress: address?
    ownerAddress: Cell<address>?
}

// ---------------------------------------------------------------------------
// Messages to a consumption bucket (sender MUST be the minter).

/// Sent with the canonical `StateInit`; the only way a bucket becomes
/// active (§5.3.4 step 2).
struct (0x53434338) SccpActivateBucket {
    queryId: uint64
    index: uint64
}

/// The first 256 body bits are `op ‖ query_id ‖ nonce ‖ amount`, so a bounce
/// returns the nonce and amount to the minter.
struct (0x53434331) SccpConsume {
    queryId: uint64
    nonce: uint64
    amount: uint96
    tail: Cell<ConsumeTail>
}

struct (0x53434333) SccpConsumeRange {
    queryId: uint64
    first: uint64
    count: uint16
}

struct (0x53434335) SccpUnconsume {
    nonce: uint64
}

// ---------------------------------------------------------------------------
// External-out messages of the minter.

struct (0x5343464e) SccpFinalizedEvent {
    messageId: uint256
    nonce: uint64
}

/// `messageId = 0` for frozen voids.
struct (0x5343564f) SccpVoidedEvent {
    messageId: uint256
    firstNonce: uint64
    count: uint16
}

struct (0x53435454) SccpTransferToTairaEvent {
    messageId: uint256
    nonce: uint64
    sender: address
    amount: coins
    /// `^SnakeBytes` with the §3.2 payload.
    payload: cell
}

struct (0x5343434e) SccpControlAppliedEvent {
    controlNonce: uint64
    track: uint8
    parliamentPaused: bool
    fastPauseUntilMs: uint64
    certificateId: uint256
}

/// The newly installed generation (§5.1.2 update 3).
struct (0x53435252) SccpCommitteeRotatedEvent {
    generation: uint64
    root: uint256
    untilMs: uint64
    start: uint64
}

/// A newly recorded checkpoint; `id = keccak256(X)`.
struct (0x53434b4e) SccpCheckpointedEvent {
    height: uint64
    id: uint256
}

/// A V1–V3 latch (§5.1.2): reason 1 carries the stored and the new id,
/// reasons 2 and 3 `X.committee_root` and `keccak256(X)`.
struct (0x53434c54) SccpLatchedEvent {
    reason: uint8
    generation: uint64
    height: uint64
    a: uint256
    b: uint256
}

/// Every full-path verification publishes its certificate (§5.1.3 step 12).
struct (0x53434346) SccpCertificateEvent {
    height: uint64
    generation: uint64
    cert: Cell<TairaCert>
}

// ---------------------------------------------------------------------------
// TEP-74 wallet messages.

type ForwardPayloadRemainder = RemainingBitsAndRefs

struct (0b0) PayloadInline {
    value: RemainingBitsAndRefs
}

struct (0b1) PayloadInRef {
    value: Cell<RemainingBitsAndRefs>
}

struct (0x0f8a7ea5) AskToTransfer {
    queryId: uint64
    jettonAmount: coins
    transferRecipient: address
    sendExcessesTo: address?
    customPayload: cell?
    forwardTonAmount: coins
    @abi.clientType(PayloadInline | PayloadInRef)
    forwardPayload: ForwardPayloadRemainder
}

struct (0x7362d09c) TransferNotificationForRecipient {
    queryId: uint64
    jettonAmount: coins
    transferInitiator: address?
    @abi.clientType(PayloadInline | PayloadInRef)
    forwardPayload: ForwardPayloadRemainder
}

struct (0x178d4519) InternalTransferStep {
    queryId: uint64
    jettonAmount: coins
    transferInitiator: address?
    sendExcessesTo: address?
    forwardTonAmount: coins
    @abi.clientType(PayloadInline | PayloadInRef)
    forwardPayload: ForwardPayloadRemainder
}

struct (0xd53276db) ReturnExcessesBack {
    queryId: uint64
}

/// TEP-74 burn; SCCP wallets require `customPayload = sccp_burn_to_taira`.
struct (0x595f07bc) AskToBurn {
    queryId: uint64
    jettonAmount: coins
    sendExcessesTo: address?
    customPayload: cell?
}

/// Checks a TEP-74 `Either Cell ^Cell` forward payload.
fun ForwardPayloadRemainder.checkIsCorrectTlbEither(self) {
    var mutableCopy = self;
    if (mutableCopy.loadMaybeRef() != null) {
        mutableCopy.assertEnd();
    }
}
