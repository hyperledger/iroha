// Exit codes of the SCCP v1 TON contracts.
//
// The shared codes are the TON side of the §5.2.2 error table, which maps
// each EVM error name to one TON exit code; the cross-check harness keys on
// the names. The TON-only codes cover rules of §5.3. Codes 409 and 432 are
// unassigned. The numeric values are part of the tested surface
// (`tests/unit/*.test.tolk`).
//
// Cells taken from a message (§5.3.2). A cell that is not ordinary (a library
// reference, pruned branch, Merkle proof or Merkle update) is `BadSnake`
// wherever it appears. An ordinary cell with other bit or reference counts
// than its layout answers by its kind:
//
//   TairaCert, QcFixed                      BadCertificate (§5.1.3 step 1)
//   XHead, XTail                            BadHeader      (§5.1.3 step 1)
//   CheckpointRef, BlockRef, MessageProof,
//   ControlProof                            BadSnake
//   SnakeBytes, HashChunk, KeyChunk lists   BadSnake
//
// A certificate's lengths are checked in the order `QC_FIXED`, `X`,
// signature. A `next_keys` list of more than 16 chunks is `BadCommittee`. A
// well-formed cell whose content fails a proof rule is `BadProof`, and a
// control leaf that violates the §3.4 constraints is `BadControl`.

enum SccpErrors {
    /// TEP-74 wallet balance too small.
    BalanceError = 47
    /// Attached value is below the required value (§5.3.5).
    NotEnoughValue = 48
    /// Unknown or malformed message.
    InvalidMessage = 49
    /// TEP-74 sender is not the wallet owner.
    NotOwner = 73
    /// Sender is not the canonical wallet of the claimed owner.
    NotValidWallet = 74
    /// Address is not `addr_std` in workchain 0 without anycast.
    WrongWorkchain = 333

    /// `GLOBALID` differs from TON mainnet.
    WrongChain = 400
    /// Finalization refused while the effective pause holds (§5.1.6).
    MintingIsPaused = 401
    /// The certificate is not of the current generation (`X.generation`,
    /// `X.committee_root`); the destination expired without a latch; or a
    /// stored checkpoint is neither of the current generation nor the
    /// handoff that installed it (§5.1.2, §5.1.3 U1 and U2).
    CommitteeNotAccepted = 402
    /// Committee keys violate §3.7 (size, order, root), or `next_keys` is
    /// missing or does not hash to the announced root.
    BadCommittee = 403
    /// `QC_FIXED`, the signature or the signer set is malformed (§5.1.3
    /// steps 1 and 5).
    BadCertificate = 404
    /// The signature is the identity (§5.1.3 step 6), or
    /// `BLS_FASTAGGREGATEVERIFY` answered false (steps 10 and 11).
    BadSignature = 405
    /// `X` has another length, violates X1–X7, is inactive or names another
    /// network (§3.6).
    BadHeader = 406
    /// A block reference, or a Merkle or history path, does not reproduce
    /// the certified root (§5.1.5).
    BadProof = 407
    /// Payload violates §3.2 or is not addressed to this revision.
    BadPayload = 408
    /// Cap check of §5.1.4 failed.
    SupplyCapExceeded = 410
    /// No stored checkpoint has this `X` (§5.1.3).
    UnknownCheckpoint = 411
    /// The recipient of an otherwise valid payload is not an account this
    /// minter can mint to (another workchain, a zero account id or the
    /// minter), or the Taira recipient of a burn exceeds 1024 bytes.
    BadRecipient = 412
    /// Burn amount is zero or out of range. The amount of an inbound
    /// payload is a §3.2 rule and answers `BadPayload`.
    BadAmount = 413
    /// Finalization after `deadline_ms`.
    DeadlinePassed = 414
    /// Void before `deadline_ms`.
    DeadlineNotReached = 415
    /// `voidFrozen` while the destination is still `Live`.
    NotFrozen = 416
    /// Control nonce not strictly above the stored one.
    StaleControl = 417
    /// Operation before `sccp_init`.
    NotInitialized = 418
    /// Second `sccp_init`.
    AlreadyInitialized = 419
    /// Control leaf fields violate the §3.4 constraints.
    BadControl = 420
    /// Snake cell or chunked list is not in its canonical shape, a proof or
    /// checkpoint reference cell has another shape, or a cell taken from a
    /// message is exotic.
    BadSnake = 421
    /// Bucket index is more than `SCCP_MAX_DEPLOY_AHEAD` past the deployed ones.
    BucketNotDeployed = 422
    /// Sender is not the minter.
    NotMinter = 423
    /// Sender is not the canonical bucket.
    NotBucket = 424
    /// Nonce argument mismatch, nonce outside this bucket, or a burn when
    /// the outbound source nonces are exhausted (§5.1.7).
    BadNonce = 425
    /// Bucket range or deployment count out of bounds.
    BadRange = 426
    /// Burn custom payload is missing or is not `sccp_burn_to_taira`.
    BadBurnPayload = 427
    /// `sccp_checkpoint` changed nothing (§5.1.3).
    NothingToDo = 428
    /// Stored configuration or initial data is not canonical.
    BadConfig = 429
    /// Bucket was not activated by its minter (never deployed by it, or
    /// recreated by someone else after deletion).
    BucketNotActive = 430
    /// `sccp_retry` for a nonce without a recorded retry.
    NothingToRetry = 431
    /// The latch is set: the `Live` check of an entry point failed on a
    /// destination that latched on a violation V1–V3 (§5.1.2).
    Equivocated = 433
    /// An inline certificate meets a violation V1–V3; only
    /// `sccp_checkpoint` latches, so submit it there (§5.1.2).
    LatchRequired = 434
}
