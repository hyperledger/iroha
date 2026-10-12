//! The destination ABI of revision 5 (`specs/sccp.md` §5.2.2 and §5.3): the EVM function
//! selectors, the event signatures and topics, and the one error table that maps every EVM
//! error name to its TON exit code.
//!
//! Selectors are the first four bytes of Keccak-256 over the canonical signature with tuple
//! types expanded, as the Solidity ABI does; `topic0` of an event is Keccak-256 over its
//! canonical signature. The tests recompute every value and compare it with the
//! specification table and with `fixtures/sccp/committee_transitions_v1.json`.
//!
//! [`DestinationError`] is the error type of the destination model
//! ([`super::destination`]). Cross-check harnesses compare outcomes by
//! [`DestinationError::name`], which is the same on every chain.
//!
use core::fmt;

/// Decode a hex literal of exactly `2 · N` digits at compile time.
const fn hex<const N: usize>(literal: &str) -> [u8; N] {
    let digits = literal.as_bytes();
    assert!(digits.len() == 2 * N, "hex literal has the wrong length");
    let mut out = [0_u8; N];
    let mut index = 0;
    while index < N {
        out[index] = (hex_nibble(digits[2 * index]) << 4) | hex_nibble(digits[2 * index + 1]);
        index += 1;
    }
    out
}

const fn hex_nibble(digit: u8) -> u8 {
    match digit {
        b'0'..=b'9' => digit - b'0',
        b'a'..=b'f' => digit - b'a' + 10,
        _ => panic!("hex literal has a digit outside 0-9a-f"),
    }
}

// ---------------------------------------------------------------------------------------------
// EVM structs (§5.2.2): tuple types as the canonical signatures expand them
// ---------------------------------------------------------------------------------------------

macro_rules! abi_taira_certificate {
    () => {
        "(bytes,bytes,bytes,bytes,bytes)"
    };
}
macro_rules! abi_checkpoint_ref {
    () => {
        "(bytes)"
    };
}
macro_rules! abi_block_ref {
    () => {
        "(uint64,bytes32,uint32,uint64,bytes32[])"
    };
}
macro_rules! abi_message_proof {
    () => {
        concat!("(bytes,uint32,bytes32[],", abi_block_ref!(), ")")
    };
}
macro_rules! abi_control_proof {
    () => {
        concat!(
            "(uint64,uint8,bool,uint64,bytes32,bytes32,uint32,bytes32[],",
            abi_block_ref!(),
            ")"
        )
    };
}

/// Expanded `TairaCertificateV1 { bytes qc; bytes header; bytes signature; bytes committee;
/// bytes signerYs; }`.
pub const ABI_TAIRA_CERTIFICATE: &str = abi_taira_certificate!();
/// Expanded `CheckpointRefV1 { bytes header; }`.
pub const ABI_CHECKPOINT_REF: &str = abi_checkpoint_ref!();
/// Expanded `BlockRefV1 { uint64 height; bytes32 sccpRoot; uint32 messageCount;
/// uint64 historyIndex; bytes32[] historyPath; }`.
pub const ABI_BLOCK_REF: &str = abi_block_ref!();
/// Expanded `MessageProofV1 { bytes payload; uint32 leafIndex; bytes32[] path;
/// BlockRefV1 block; }`.
pub const ABI_MESSAGE_PROOF: &str = abi_message_proof!();
/// Expanded `ControlProofV1 { uint64 controlNonce; uint8 track; bool parliamentPaused;
/// uint64 fastPauseUntilMs; bytes32 certificateId; bytes32 effectHash; uint32 leafIndex;
/// bytes32[] path; BlockRefV1 block; }`.
pub const ABI_CONTROL_PROOF: &str = abi_control_proof!();

// ---------------------------------------------------------------------------------------------
// EVM selectors (§5.2.2)
// ---------------------------------------------------------------------------------------------

/// `submitCheckpoints(TairaCertificateV1[])`.
pub const SIG_SUBMIT_CHECKPOINTS: &str =
    concat!("submitCheckpoints(", abi_taira_certificate!(), "[])");
/// Selector of [`SIG_SUBMIT_CHECKPOINTS`].
pub const SELECTOR_SUBMIT_CHECKPOINTS: [u8; 4] = hex("07a5e706");
/// `finalizeFromTaira(TairaCertificateV1,MessageProofV1)`.
pub const SIG_FINALIZE_FROM_TAIRA: &str = concat!(
    "finalizeFromTaira(",
    abi_taira_certificate!(),
    ",",
    abi_message_proof!(),
    ")"
);
/// Selector of [`SIG_FINALIZE_FROM_TAIRA`].
pub const SELECTOR_FINALIZE_FROM_TAIRA: [u8; 4] = hex("10efea88");
/// `finalizeFromCheckpoint(CheckpointRefV1,MessageProofV1)`.
pub const SIG_FINALIZE_FROM_CHECKPOINT: &str = concat!(
    "finalizeFromCheckpoint(",
    abi_checkpoint_ref!(),
    ",",
    abi_message_proof!(),
    ")"
);
/// Selector of [`SIG_FINALIZE_FROM_CHECKPOINT`].
pub const SELECTOR_FINALIZE_FROM_CHECKPOINT: [u8; 4] = hex("55c39595");
/// `applyControl(TairaCertificateV1,ControlProofV1)`.
pub const SIG_APPLY_CONTROL: &str = concat!(
    "applyControl(",
    abi_taira_certificate!(),
    ",",
    abi_control_proof!(),
    ")"
);
/// Selector of [`SIG_APPLY_CONTROL`].
pub const SELECTOR_APPLY_CONTROL: [u8; 4] = hex("32118e92");
/// `applyControlFromCheckpoint(CheckpointRefV1,ControlProofV1)`.
pub const SIG_APPLY_CONTROL_FROM_CHECKPOINT: &str = concat!(
    "applyControlFromCheckpoint(",
    abi_checkpoint_ref!(),
    ",",
    abi_control_proof!(),
    ")"
);
/// Selector of [`SIG_APPLY_CONTROL_FROM_CHECKPOINT`].
pub const SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT: [u8; 4] = hex("53899b1e");
/// `voidExpired(uint64,TairaCertificateV1,MessageProofV1)`.
pub const SIG_VOID_EXPIRED: &str = concat!(
    "voidExpired(uint64,",
    abi_taira_certificate!(),
    ",",
    abi_message_proof!(),
    ")"
);
/// Selector of [`SIG_VOID_EXPIRED`].
pub const SELECTOR_VOID_EXPIRED: [u8; 4] = hex("997fcd99");
/// `voidExpiredFromCheckpoint(uint64,CheckpointRefV1,MessageProofV1)`.
pub const SIG_VOID_EXPIRED_FROM_CHECKPOINT: &str = concat!(
    "voidExpiredFromCheckpoint(uint64,",
    abi_checkpoint_ref!(),
    ",",
    abi_message_proof!(),
    ")"
);
/// Selector of [`SIG_VOID_EXPIRED_FROM_CHECKPOINT`].
pub const SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT: [u8; 4] = hex("fbeb670e");
/// `voidFrozen(uint64 firstNonce,uint64 count)`.
pub const SIG_VOID_FROZEN: &str = "voidFrozen(uint64,uint64)";
/// Selector of [`SIG_VOID_FROZEN`].
pub const SELECTOR_VOID_FROZEN: [u8; 4] = hex("5b094c00");
/// `transferToTaira(bytes tairaRecipient,uint256 tokenAmount,uint64 expectedNonce)`.
pub const SIG_TRANSFER_TO_TAIRA: &str = "transferToTaira(bytes,uint256,uint64)";
/// Selector of [`SIG_TRANSFER_TO_TAIRA`].
pub const SELECTOR_TRANSFER_TO_TAIRA: [u8; 4] = hex("ebfc6ca8");
/// `committeeState()`: `(root, untilMs, start, high, generation)`.
pub const SIG_COMMITTEE_STATE: &str = "committeeState()";
/// Selector of [`SIG_COMMITTEE_STATE`].
pub const SELECTOR_COMMITTEE_STATE: [u8; 4] = hex("620ae238");
/// `checkpointHeader(uint64)`: `keccak256(X)` of the stored checkpoint, or zero.
pub const SIG_CHECKPOINT_HEADER: &str = "checkpointHeader(uint64)";
/// Selector of [`SIG_CHECKPOINT_HEADER`].
pub const SELECTOR_CHECKPOINT_HEADER: [u8; 4] = hex("405cf530");
/// `pauseState()`: `(parliamentPaused, fastPauseUntilMs, controlNonce, effective)`.
pub const SIG_PAUSE_STATE: &str = "pauseState()";
/// Selector of [`SIG_PAUSE_STATE`].
pub const SELECTOR_PAUSE_STATE: [u8; 4] = hex("d7118351");
/// `mintingPaused()`: the effective pause at `block.timestamp`.
pub const SIG_MINTING_PAUSED: &str = "mintingPaused()";
/// Selector of [`SIG_MINTING_PAUSED`].
pub const SELECTOR_MINTING_PAUSED: [u8; 4] = hex("e1a283d6");
/// `consensusInstance()`.
pub const SIG_CONSENSUS_INSTANCE: &str = "consensusInstance()";
/// Selector of [`SIG_CONSENSUS_INSTANCE`].
pub const SELECTOR_CONSENSUS_INSTANCE: [u8; 4] = hex("1682dae6");
/// `initialCommittee()`: `(generation, root, start, untilMs)` of the pin.
pub const SIG_INITIAL_COMMITTEE: &str = "initialCommittee()";
/// Selector of [`SIG_INITIAL_COMMITTEE`].
pub const SELECTOR_INITIAL_COMMITTEE: [u8; 4] = hex("86645f61");
/// `equivocated()`.
pub const SIG_EQUIVOCATED: &str = "equivocated()";
/// Selector of [`SIG_EQUIVOCATED`].
pub const SELECTOR_EQUIVOCATED: [u8; 4] = hex("78048149");
/// `maxValidityMs()`.
pub const SIG_MAX_VALIDITY_MS: &str = "maxValidityMs()";
/// Selector of [`SIG_MAX_VALIDITY_MS`].
pub const SELECTOR_MAX_VALIDITY_MS: [u8; 4] = hex("5cffa161");
/// `isConsumed(uint64 nonce)`.
pub const SIG_IS_CONSUMED: &str = "isConsumed(uint64)";
/// Selector of [`SIG_IS_CONSUMED`].
pub const SELECTOR_IS_CONSUMED: [u8; 4] = hex("95b67034");
/// `controlNonce()`: the nonce of the last applied control.
pub const SIG_CONTROL_NONCE: &str = "controlNonce()";
/// Selector of [`SIG_CONTROL_NONCE`].
pub const SELECTOR_CONTROL_NONCE: [u8; 4] = hex("4faac8ca");
/// `opCount()`.
pub const SIG_OP_COUNT: &str = "opCount()";
/// Selector of [`SIG_OP_COUNT`].
pub const SELECTOR_OP_COUNT: [u8; 4] = hex("cb58065f");
/// `transferNonces(address)`.
pub const SIG_TRANSFER_NONCES: &str = "transferNonces(address)";
/// Selector of [`SIG_TRANSFER_NONCES`].
pub const SELECTOR_TRANSFER_NONCES: [u8; 4] = hex("f6f0e8a6");
/// `tairaNetworkId()`.
pub const SIG_TAIRA_NETWORK_ID: &str = "tairaNetworkId()";
/// Selector of [`SIG_TAIRA_NETWORK_ID`].
pub const SELECTOR_TAIRA_NETWORK_ID: [u8; 4] = hex("6b91d731");
/// `routeRevision()`.
pub const SIG_ROUTE_REVISION: &str = "routeRevision()";
/// Selector of [`SIG_ROUTE_REVISION`].
pub const SELECTOR_ROUTE_REVISION: [u8; 4] = hex("1818891a");
/// `maxWrappedSupply()`.
pub const SIG_MAX_WRAPPED_SUPPLY: &str = "maxWrappedSupply()";
/// Selector of [`SIG_MAX_WRAPPED_SUPPLY`].
pub const SELECTOR_MAX_WRAPPED_SUPPLY: [u8; 4] = hex("d8bc4dcd");

/// Every entry point and view of §5.2.2 as `(function name, canonical signature, selector)`,
/// in the order of the specification table; the four unchanged views come last. The ERC-20
/// surface is not listed.
pub const SELECTORS: [(&str, &str, [u8; 4]); 24] = [
    (
        "submitCheckpoints",
        SIG_SUBMIT_CHECKPOINTS,
        SELECTOR_SUBMIT_CHECKPOINTS,
    ),
    (
        "finalizeFromTaira",
        SIG_FINALIZE_FROM_TAIRA,
        SELECTOR_FINALIZE_FROM_TAIRA,
    ),
    (
        "finalizeFromCheckpoint",
        SIG_FINALIZE_FROM_CHECKPOINT,
        SELECTOR_FINALIZE_FROM_CHECKPOINT,
    ),
    ("applyControl", SIG_APPLY_CONTROL, SELECTOR_APPLY_CONTROL),
    (
        "applyControlFromCheckpoint",
        SIG_APPLY_CONTROL_FROM_CHECKPOINT,
        SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT,
    ),
    ("voidExpired", SIG_VOID_EXPIRED, SELECTOR_VOID_EXPIRED),
    (
        "voidExpiredFromCheckpoint",
        SIG_VOID_EXPIRED_FROM_CHECKPOINT,
        SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT,
    ),
    ("voidFrozen", SIG_VOID_FROZEN, SELECTOR_VOID_FROZEN),
    (
        "transferToTaira",
        SIG_TRANSFER_TO_TAIRA,
        SELECTOR_TRANSFER_TO_TAIRA,
    ),
    (
        "committeeState",
        SIG_COMMITTEE_STATE,
        SELECTOR_COMMITTEE_STATE,
    ),
    (
        "checkpointHeader",
        SIG_CHECKPOINT_HEADER,
        SELECTOR_CHECKPOINT_HEADER,
    ),
    ("pauseState", SIG_PAUSE_STATE, SELECTOR_PAUSE_STATE),
    ("mintingPaused", SIG_MINTING_PAUSED, SELECTOR_MINTING_PAUSED),
    (
        "consensusInstance",
        SIG_CONSENSUS_INSTANCE,
        SELECTOR_CONSENSUS_INSTANCE,
    ),
    (
        "initialCommittee",
        SIG_INITIAL_COMMITTEE,
        SELECTOR_INITIAL_COMMITTEE,
    ),
    ("equivocated", SIG_EQUIVOCATED, SELECTOR_EQUIVOCATED),
    (
        "maxValidityMs",
        SIG_MAX_VALIDITY_MS,
        SELECTOR_MAX_VALIDITY_MS,
    ),
    ("isConsumed", SIG_IS_CONSUMED, SELECTOR_IS_CONSUMED),
    ("controlNonce", SIG_CONTROL_NONCE, SELECTOR_CONTROL_NONCE),
    ("opCount", SIG_OP_COUNT, SELECTOR_OP_COUNT),
    (
        "transferNonces",
        SIG_TRANSFER_NONCES,
        SELECTOR_TRANSFER_NONCES,
    ),
    (
        "tairaNetworkId",
        SIG_TAIRA_NETWORK_ID,
        SELECTOR_TAIRA_NETWORK_ID,
    ),
    ("routeRevision", SIG_ROUTE_REVISION, SELECTOR_ROUTE_REVISION),
    (
        "maxWrappedSupply",
        SIG_MAX_WRAPPED_SUPPLY,
        SELECTOR_MAX_WRAPPED_SUPPLY,
    ),
];

// ---------------------------------------------------------------------------------------------
// Events (§5.2.2)
// ---------------------------------------------------------------------------------------------

/// `SccpTransferToTaira(bytes32 indexed messageId, address indexed sender, uint64 nonce,
/// bytes payload)`: the inbound source event Taira consumes.
pub const EVENT_TRANSFER_TO_TAIRA: &str = "SccpTransferToTaira(bytes32,address,uint64,bytes)";
/// `topic0` of [`EVENT_TRANSFER_TO_TAIRA`].
pub const TOPIC_TRANSFER_TO_TAIRA: [u8; 32] =
    hex("79ac1cc63262b80bfbf96e55b2d49d96bd82f018ce0192f7002168724c7d264b");
/// `SccpFinalized(bytes32 indexed messageId, uint64 indexed nonce, address indexed recipient,
/// uint256 tokenAmount)`.
pub const EVENT_FINALIZED: &str = "SccpFinalized(bytes32,uint64,address,uint256)";
/// `topic0` of [`EVENT_FINALIZED`].
pub const TOPIC_FINALIZED: [u8; 32] =
    hex("8ab0eb669cb9abcdf0e37e9ce8443162d317d10c2b059296e40aebbd3fa23748");
/// `SccpVoided(bytes32 indexed messageId, uint64 indexed nonce)`; `messageId` is zero for
/// `voidFrozen`.
pub const EVENT_VOIDED: &str = "SccpVoided(bytes32,uint64)";
/// `topic0` of [`EVENT_VOIDED`].
pub const TOPIC_VOIDED: [u8; 32] =
    hex("fc0fe8523e61c1e6bcbb957a8b692dd0b08e1774c4c4bd897fbc68c047c82fcf");
/// `SccpCommitteeRotated(uint64 indexed generation, bytes32 root, uint64 untilMs,
/// uint64 startHeight)`.
pub const EVENT_COMMITTEE_ROTATED: &str = "SccpCommitteeRotated(uint64,bytes32,uint64,uint64)";
/// `topic0` of [`EVENT_COMMITTEE_ROTATED`].
pub const TOPIC_COMMITTEE_ROTATED: [u8; 32] =
    hex("6244ff84b5945581521adb818f0b307122dfde790299fb252046603a974d3d3d");
/// `SccpCheckpointed(uint64 indexed height, bytes32 header)`; the value is `keccak256(X)`.
pub const EVENT_CHECKPOINTED: &str = "SccpCheckpointed(uint64,bytes32)";
/// `topic0` of [`EVENT_CHECKPOINTED`].
pub const TOPIC_CHECKPOINTED: [u8; 32] =
    hex("fe0aa9a242fa773b609fa05dac2bc7034ac693373de95b042f61db6c8d218853");
/// `SccpLatched(uint8 indexed reason, uint64 generation, uint64 height, bytes32 a, bytes32 b)`.
pub const EVENT_LATCHED: &str = "SccpLatched(uint8,uint64,uint64,bytes32,bytes32)";
/// `topic0` of [`EVENT_LATCHED`].
pub const TOPIC_LATCHED: [u8; 32] =
    hex("0567b58957c8b229342697465e6c4c3c6f0f63efb05b97d09469929c47a331f7");
/// `SccpControlApplied(uint64 indexed controlNonce, uint8 track, bool parliamentPaused,
/// uint64 fastPauseUntilMs, bytes32 certificateId)`.
pub const EVENT_CONTROL_APPLIED: &str = "SccpControlApplied(uint64,uint8,bool,uint64,bytes32)";
/// `topic0` of [`EVENT_CONTROL_APPLIED`].
pub const TOPIC_CONTROL_APPLIED: [u8; 32] =
    hex("b069397cc6f8fa22bf7c0216c554253ab0fc92a3178d10969760b028dd174238");
/// `SccpCertificate(uint64 indexed height, uint64 indexed generation, bytes qc, bytes header,
/// bytes signature)`: every full-path verification (§5.1.3 step 12).
pub const EVENT_CERTIFICATE: &str = "SccpCertificate(uint64,uint64,bytes,bytes,bytes)";
/// `topic0` of [`EVENT_CERTIFICATE`].
pub const TOPIC_CERTIFICATE: [u8; 32] =
    hex("a89e234faf229fd8a8a7add0e9aec37a1986183e842549427a65eb2fb88c116e");

/// Every SCCP event of §5.2.2 as `(event name, canonical signature, topic0)`, in the order of
/// the specification table.
pub const EVENT_TOPICS: [(&str, &str, [u8; 32]); 8] = [
    (
        "SccpTransferToTaira",
        EVENT_TRANSFER_TO_TAIRA,
        TOPIC_TRANSFER_TO_TAIRA,
    ),
    ("SccpFinalized", EVENT_FINALIZED, TOPIC_FINALIZED),
    ("SccpVoided", EVENT_VOIDED, TOPIC_VOIDED),
    (
        "SccpCommitteeRotated",
        EVENT_COMMITTEE_ROTATED,
        TOPIC_COMMITTEE_ROTATED,
    ),
    ("SccpCheckpointed", EVENT_CHECKPOINTED, TOPIC_CHECKPOINTED),
    ("SccpLatched", EVENT_LATCHED, TOPIC_LATCHED),
    (
        "SccpControlApplied",
        EVENT_CONTROL_APPLIED,
        TOPIC_CONTROL_APPLIED,
    ),
    ("SccpCertificate", EVENT_CERTIFICATE, TOPIC_CERTIFICATE),
];

// ---------------------------------------------------------------------------------------------
// Errors (§5.2.2, §5.3)
// ---------------------------------------------------------------------------------------------

/// An error of the shared destination table (`specs/sccp.md` §5.2.2) or a TON-only exit code
/// (§5.3).
///
/// An EVM destination reverts with the custom error of this name; a TON destination throws
/// [`Self::ton_exit_code`]. A failed call changes nothing. Codes 409 and 432 are unassigned,
/// and the TEP-74 codes (47–74, 333) are not part of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DestinationError {
    /// The chain identity is not the profile's: `block.chainid` on EVM, `GLOBALID` on TON.
    WrongChain,
    /// A finalization while the effective pause holds (§5.1.6).
    MintingIsPaused,
    /// The certificate is not of the current generation, the destination has expired, or a
    /// stored checkpoint is neither of the current generation nor the handoff that installed
    /// it (§5.1.2, §5.1.3).
    CommitteeNotAccepted,
    /// The committee is not acceptable: its length, its root, a signer key's encoding, an
    /// identity aggregate key, or TON `next_keys` that are not the announced successor.
    BadCommittee,
    /// `QC_FIXED`, the signature length, `signerYs` or the signer set is malformed (§5.1.3
    /// steps 1 and 5).
    BadCertificate,
    /// The aggregate signature is the identity, is not the encoding of a point of the G2
    /// subgroup, or does not verify.
    BadSignature,
    /// `X` is not 221 bytes, violates X1–X7, is inactive or names another network.
    BadHeader,
    /// A block reference, a Merkle path or a history path does not reproduce the certified
    /// root.
    BadProof,
    /// The payload violates §3.2 or is not addressed to this deployment.
    BadPayload,
    /// The mint would exceed `maxWrappedSupply` (§5.1.4).
    SupplyCapExceeded,
    /// No stored checkpoint is `keccak256(X)` at `X.height`.
    UnknownCheckpoint,
    /// The recipient is not a valid account of this deployment, or is the contract itself.
    BadRecipient,
    /// An amount is zero or out of range; on EVM also a `voidFrozen` range out of bounds.
    BadAmount,
    /// A finalization after `deadline_ms`.
    DeadlinePassed,
    /// A void at or before `deadline_ms`.
    DeadlineNotReached,
    /// `voidFrozen` while the destination is `Live`.
    NotFrozen,
    /// The control nonce is not above the stored one.
    StaleControl,
    /// TON: an operation before `sccp_init`.
    NotInitialized,
    /// TON: a second `sccp_init`.
    AlreadyInitialized,
    /// The control fields violate the §3.4 constraints.
    BadControl,
    /// A nonce argument differs from the payload's nonce or from the sender's next nonce, or
    /// the sender's source nonces are exhausted (its next nonce is `2^64 − 1`, §5.1.7).
    BadNonce {
        /// The nonce the call had to name.
        expected: u64,
    },
    /// `submitCheckpoints` changed no state.
    NothingToDo,
    /// The constructor arguments or the stored initial data are not canonical.
    BadConfig,
    /// The destination is latched (§5.1.2).
    Equivocated,
    /// An inline certificate trips V1–V3: only `submitCheckpoints` latches.
    LatchRequired,
    /// EVM only: more than 16 certificates in one `submitCheckpoints` call.
    TooManyCertificates,
    /// EVM only: `transferToTaira` or `voidFrozen` calldata is not the canonical encoding.
    NonCanonicalCalldata,
    /// EVM only: the nonce is already consumed. TON reports it through the bucket's
    /// `sccp_already_consumed` reply, not an exit code.
    AlreadyConsumed {
        /// The consumed nonce.
        nonce: u64,
    },
    /// TON only: a snake cell or a chunked list is not canonical, or a message cell is exotic.
    BadSnake,
    /// TON only: the bucket index is too far past the deployed buckets.
    BucketNotDeployed,
    /// TON only: the sender is not the minter.
    NotMinter,
    /// TON only: the sender is not the canonical bucket.
    NotBucket,
    /// TON only: a bucket range or a deployment count is out of bounds; the `voidFrozen`
    /// range failure of a TON destination.
    BadRange,
    /// TON only: the burn custom payload is missing or is not `sccp_burn_to_taira`.
    BadBurnPayload,
    /// TON only: the bucket was not activated by its minter.
    BucketNotActive,
    /// TON only: `sccp_retry` for a nonce without a recorded step.
    NothingToRetry,
}

impl DestinationError {
    /// Every error of the table with zero arguments: the 28 shared names in the order of the
    /// §5.2.2 table, then the 8 TON-only names by exit code.
    pub const ALL: [Self; 36] = [
        Self::WrongChain,
        Self::MintingIsPaused,
        Self::CommitteeNotAccepted,
        Self::BadCommittee,
        Self::BadCertificate,
        Self::BadSignature,
        Self::BadHeader,
        Self::BadProof,
        Self::BadPayload,
        Self::SupplyCapExceeded,
        Self::UnknownCheckpoint,
        Self::BadRecipient,
        Self::BadAmount,
        Self::DeadlinePassed,
        Self::DeadlineNotReached,
        Self::NotFrozen,
        Self::StaleControl,
        Self::NotInitialized,
        Self::AlreadyInitialized,
        Self::BadControl,
        Self::BadNonce { expected: 0 },
        Self::NothingToDo,
        Self::BadConfig,
        Self::Equivocated,
        Self::LatchRequired,
        Self::TooManyCertificates,
        Self::NonCanonicalCalldata,
        Self::AlreadyConsumed { nonce: 0 },
        Self::BadSnake,
        Self::BucketNotDeployed,
        Self::NotMinter,
        Self::NotBucket,
        Self::BadRange,
        Self::BadBurnPayload,
        Self::BucketNotActive,
        Self::NothingToRetry,
    ];

    /// The name of the error in the shared table: the EVM custom error, without arguments.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::WrongChain => "WrongChain",
            Self::MintingIsPaused => "MintingIsPaused",
            Self::CommitteeNotAccepted => "CommitteeNotAccepted",
            Self::BadCommittee => "BadCommittee",
            Self::BadCertificate => "BadCertificate",
            Self::BadSignature => "BadSignature",
            Self::BadHeader => "BadHeader",
            Self::BadProof => "BadProof",
            Self::BadPayload => "BadPayload",
            Self::SupplyCapExceeded => "SupplyCapExceeded",
            Self::UnknownCheckpoint => "UnknownCheckpoint",
            Self::BadRecipient => "BadRecipient",
            Self::BadAmount => "BadAmount",
            Self::DeadlinePassed => "DeadlinePassed",
            Self::DeadlineNotReached => "DeadlineNotReached",
            Self::NotFrozen => "NotFrozen",
            Self::StaleControl => "StaleControl",
            Self::NotInitialized => "NotInitialized",
            Self::AlreadyInitialized => "AlreadyInitialized",
            Self::BadControl => "BadControl",
            Self::BadNonce { .. } => "BadNonce",
            Self::NothingToDo => "NothingToDo",
            Self::BadConfig => "BadConfig",
            Self::Equivocated => "Equivocated",
            Self::LatchRequired => "LatchRequired",
            Self::TooManyCertificates => "TooManyCertificates",
            Self::NonCanonicalCalldata => "NonCanonicalCalldata",
            Self::AlreadyConsumed { .. } => "AlreadyConsumed",
            Self::BadSnake => "BadSnake",
            Self::BucketNotDeployed => "BucketNotDeployed",
            Self::NotMinter => "NotMinter",
            Self::NotBucket => "NotBucket",
            Self::BadRange => "BadRange",
            Self::BadBurnPayload => "BadBurnPayload",
            Self::BucketNotActive => "BucketNotActive",
            Self::NothingToRetry => "NothingToRetry",
        }
    }

    /// The exit code a TON destination throws; `None` for an EVM-only error.
    #[must_use]
    pub const fn ton_exit_code(self) -> Option<u16> {
        Some(match self {
            Self::WrongChain => 400,
            Self::MintingIsPaused => 401,
            Self::CommitteeNotAccepted => 402,
            Self::BadCommittee => 403,
            Self::BadCertificate => 404,
            Self::BadSignature => 405,
            Self::BadHeader => 406,
            Self::BadProof => 407,
            Self::BadPayload => 408,
            Self::SupplyCapExceeded => 410,
            Self::UnknownCheckpoint => 411,
            Self::BadRecipient => 412,
            Self::BadAmount => 413,
            Self::DeadlinePassed => 414,
            Self::DeadlineNotReached => 415,
            Self::NotFrozen => 416,
            Self::StaleControl => 417,
            Self::NotInitialized => 418,
            Self::AlreadyInitialized => 419,
            Self::BadControl => 420,
            Self::BadSnake => 421,
            Self::BucketNotDeployed => 422,
            Self::NotMinter => 423,
            Self::NotBucket => 424,
            Self::BadNonce { .. } => 425,
            Self::BadRange => 426,
            Self::BadBurnPayload => 427,
            Self::NothingToDo => 428,
            Self::BadConfig => 429,
            Self::BucketNotActive => 430,
            Self::NothingToRetry => 431,
            Self::Equivocated => 433,
            Self::LatchRequired => 434,
            Self::TooManyCertificates
            | Self::NonCanonicalCalldata
            | Self::AlreadyConsumed { .. } => return None,
        })
    }

    /// Whether the error exists on TON only: it has an exit code and no EVM custom error.
    #[must_use]
    pub const fn is_ton_only(self) -> bool {
        matches!(
            self,
            Self::BadSnake
                | Self::BucketNotDeployed
                | Self::NotMinter
                | Self::NotBucket
                | Self::BadRange
                | Self::BadBurnPayload
                | Self::BucketNotActive
                | Self::NothingToRetry
        )
    }

    /// The canonical signature of the EVM custom error, `Name()` or `Name(uint64)`; `None`
    /// for a TON-only error.
    #[must_use]
    pub const fn evm_signature(self) -> Option<&'static str> {
        Some(match self {
            Self::WrongChain => "WrongChain()",
            Self::MintingIsPaused => "MintingIsPaused()",
            Self::CommitteeNotAccepted => "CommitteeNotAccepted()",
            Self::BadCommittee => "BadCommittee()",
            Self::BadCertificate => "BadCertificate()",
            Self::BadSignature => "BadSignature()",
            Self::BadHeader => "BadHeader()",
            Self::BadProof => "BadProof()",
            Self::BadPayload => "BadPayload()",
            Self::SupplyCapExceeded => "SupplyCapExceeded()",
            Self::UnknownCheckpoint => "UnknownCheckpoint()",
            Self::BadRecipient => "BadRecipient()",
            Self::BadAmount => "BadAmount()",
            Self::DeadlinePassed => "DeadlinePassed()",
            Self::DeadlineNotReached => "DeadlineNotReached()",
            Self::NotFrozen => "NotFrozen()",
            Self::StaleControl => "StaleControl()",
            Self::NotInitialized => "NotInitialized()",
            Self::AlreadyInitialized => "AlreadyInitialized()",
            Self::BadControl => "BadControl()",
            Self::BadNonce { .. } => "BadNonce(uint64)",
            Self::NothingToDo => "NothingToDo()",
            Self::BadConfig => "BadConfig()",
            Self::Equivocated => "Equivocated()",
            Self::LatchRequired => "LatchRequired()",
            Self::TooManyCertificates => "TooManyCertificates()",
            Self::NonCanonicalCalldata => "NonCanonicalCalldata()",
            Self::AlreadyConsumed { .. } => "AlreadyConsumed(uint64)",
            Self::BadSnake
            | Self::BucketNotDeployed
            | Self::NotMinter
            | Self::NotBucket
            | Self::BadRange
            | Self::BadBurnPayload
            | Self::BucketNotActive
            | Self::NothingToRetry => return None,
        })
    }

    /// The `uint64` argument of the EVM custom error: `expected` of `BadNonce` and `nonce` of
    /// `AlreadyConsumed`.
    #[must_use]
    pub const fn argument(self) -> Option<u64> {
        match self {
            Self::BadNonce { expected } => Some(expected),
            Self::AlreadyConsumed { nonce } => Some(nonce),
            _ => None,
        }
    }

    /// The error of the table with this name, with a zero argument.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|error| error.name() == name)
    }
}

impl fmt::Display for DestinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())?;
        if let Some(argument) = self.argument() {
            write!(formatter, "({argument})")?;
        }
        Ok(())
    }
}

impl std::error::Error for DestinationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use norito::json::Value;

    use super::{
        super::{
            finality::vectors::{bytes, field, reference, text},
            hashes::keccak256,
        },
        *,
    };

    fn selector_of(signature: &str) -> [u8; 4] {
        let hash = keccak256(&[signature.as_bytes()]);
        [hash[0], hash[1], hash[2], hash[3]]
    }

    fn transitions() -> Value {
        reference(
            "committee_transitions_v1.json",
            "iroha.sccp.committee-transitions.v1",
        )
    }

    /// The §5.2.2 selector table, as the specification prints it.
    const SPEC_SELECTORS: [(&str, &str); 24] = [
        ("submitCheckpoints", "07a5e706"),
        ("finalizeFromTaira", "10efea88"),
        ("finalizeFromCheckpoint", "55c39595"),
        ("applyControl", "32118e92"),
        ("applyControlFromCheckpoint", "53899b1e"),
        ("voidExpired", "997fcd99"),
        ("voidExpiredFromCheckpoint", "fbeb670e"),
        ("voidFrozen", "5b094c00"),
        ("transferToTaira", "ebfc6ca8"),
        ("committeeState", "620ae238"),
        ("checkpointHeader", "405cf530"),
        ("pauseState", "d7118351"),
        ("mintingPaused", "e1a283d6"),
        ("consensusInstance", "1682dae6"),
        ("initialCommittee", "86645f61"),
        ("equivocated", "78048149"),
        ("maxValidityMs", "5cffa161"),
        ("isConsumed", "95b67034"),
        ("controlNonce", "4faac8ca"),
        ("opCount", "cb58065f"),
        ("transferNonces", "f6f0e8a6"),
        ("tairaNetworkId", "6b91d731"),
        ("routeRevision", "1818891a"),
        ("maxWrappedSupply", "d8bc4dcd"),
    ];

    /// The §5.2.2 event table: the name and the first bytes of `topic0`.
    const SPEC_TOPIC_PREFIXES: [(&str, &str); 8] = [
        ("SccpTransferToTaira", "79ac1cc63262b80b"),
        ("SccpFinalized", "8ab0eb669cb9abcd"),
        ("SccpVoided", "fc0fe8523e61c1e6"),
        ("SccpCommitteeRotated", "6244ff84b5945581"),
        ("SccpCheckpointed", "fe0aa9a242fa773b"),
        ("SccpLatched", "0567b58957c8b229"),
        ("SccpControlApplied", "b069397cc6f8fa22"),
        ("SccpCertificate", "a89e234faf229fd8"),
    ];

    /// The §5.2.2 error table: the EVM name and its TON exit code, in table order.
    const SPEC_SHARED_ERRORS: [(&str, Option<u16>); 28] = [
        ("WrongChain", Some(400)),
        ("MintingIsPaused", Some(401)),
        ("CommitteeNotAccepted", Some(402)),
        ("BadCommittee", Some(403)),
        ("BadCertificate", Some(404)),
        ("BadSignature", Some(405)),
        ("BadHeader", Some(406)),
        ("BadProof", Some(407)),
        ("BadPayload", Some(408)),
        ("SupplyCapExceeded", Some(410)),
        ("UnknownCheckpoint", Some(411)),
        ("BadRecipient", Some(412)),
        ("BadAmount", Some(413)),
        ("DeadlinePassed", Some(414)),
        ("DeadlineNotReached", Some(415)),
        ("NotFrozen", Some(416)),
        ("StaleControl", Some(417)),
        ("NotInitialized", Some(418)),
        ("AlreadyInitialized", Some(419)),
        ("BadControl", Some(420)),
        ("BadNonce", Some(425)),
        ("NothingToDo", Some(428)),
        ("BadConfig", Some(429)),
        ("Equivocated", Some(433)),
        ("LatchRequired", Some(434)),
        ("TooManyCertificates", None),
        ("NonCanonicalCalldata", None),
        ("AlreadyConsumed", None),
    ];

    /// The TON-only codes of §5.2.2.
    const SPEC_TON_ONLY_ERRORS: [(&str, u16); 8] = [
        ("BadSnake", 421),
        ("BucketNotDeployed", 422),
        ("NotMinter", 423),
        ("NotBucket", 424),
        ("BadRange", 426),
        ("BadBurnPayload", 427),
        ("BucketNotActive", 430),
        ("NothingToRetry", 431),
    ];

    #[test]
    fn hex_literals_decode_at_compile_time() {
        assert_eq!(hex::<4>("07a5e706"), [0x07, 0xa5, 0xe7, 0x06]);
        assert_eq!(hex::<1>("f0"), [0xf0]);
        assert_eq!(hex::<0>(""), [0_u8; 0]);
        assert_eq!((hex_nibble(b'0'), hex_nibble(b'9')), (0, 9));
        assert_eq!((hex_nibble(b'a'), hex_nibble(b'f')), (10, 15));
    }

    #[test]
    fn struct_tuples_expand_as_the_abi_does() {
        assert_eq!(ABI_TAIRA_CERTIFICATE, "(bytes,bytes,bytes,bytes,bytes)");
        assert_eq!(ABI_CHECKPOINT_REF, "(bytes)");
        assert_eq!(ABI_BLOCK_REF, "(uint64,bytes32,uint32,uint64,bytes32[])");
        assert_eq!(
            ABI_MESSAGE_PROOF,
            "(bytes,uint32,bytes32[],(uint64,bytes32,uint32,uint64,bytes32[]))"
        );
        assert_eq!(
            ABI_CONTROL_PROOF,
            "(uint64,uint8,bool,uint64,bytes32,bytes32,uint32,bytes32[],\
             (uint64,bytes32,uint32,uint64,bytes32[]))"
        );
        // The example of §5.2.2.
        assert_eq!(
            SIG_SUBMIT_CHECKPOINTS,
            "submitCheckpoints((bytes,bytes,bytes,bytes,bytes)[])"
        );
        assert_eq!(
            SIG_FINALIZE_FROM_TAIRA,
            format!("finalizeFromTaira({ABI_TAIRA_CERTIFICATE},{ABI_MESSAGE_PROOF})")
        );
        assert_eq!(
            SIG_FINALIZE_FROM_CHECKPOINT,
            format!("finalizeFromCheckpoint({ABI_CHECKPOINT_REF},{ABI_MESSAGE_PROOF})")
        );
        assert_eq!(
            SIG_APPLY_CONTROL,
            format!("applyControl({ABI_TAIRA_CERTIFICATE},{ABI_CONTROL_PROOF})")
        );
        assert_eq!(
            SIG_APPLY_CONTROL_FROM_CHECKPOINT,
            format!("applyControlFromCheckpoint({ABI_CHECKPOINT_REF},{ABI_CONTROL_PROOF})")
        );
        assert_eq!(
            SIG_VOID_EXPIRED,
            format!("voidExpired(uint64,{ABI_TAIRA_CERTIFICATE},{ABI_MESSAGE_PROOF})")
        );
        assert_eq!(
            SIG_VOID_EXPIRED_FROM_CHECKPOINT,
            format!("voidExpiredFromCheckpoint(uint64,{ABI_CHECKPOINT_REF},{ABI_MESSAGE_PROOF})")
        );
    }

    #[test]
    fn rev5_selectors_topics_and_error_codes_match_spec() {
        // Selectors: recomputed, equal to the specification table, in its order.
        assert_eq!(SELECTORS.len(), SPEC_SELECTORS.len());
        for ((name, signature, selector), (spec_name, spec_selector)) in
            SELECTORS.into_iter().zip(SPEC_SELECTORS)
        {
            assert_eq!(name, spec_name);
            assert_eq!(signature.split('(').next(), Some(name), "{signature}");
            assert_eq!(selector_of(signature), selector, "{signature}");
            assert_eq!(selector, hex::<4>(spec_selector), "{name}");
        }

        // Topics: recomputed, equal to the specification table, in its order.
        assert_eq!(EVENT_TOPICS.len(), SPEC_TOPIC_PREFIXES.len());
        for ((name, signature, topic), (spec_name, spec_prefix)) in
            EVENT_TOPICS.into_iter().zip(SPEC_TOPIC_PREFIXES)
        {
            assert_eq!(name, spec_name);
            assert_eq!(signature.split('(').next(), Some(name), "{signature}");
            assert_eq!(keccak256(&[signature.as_bytes()]), topic, "{signature}");
            assert_eq!(topic[..8], hex::<8>(spec_prefix), "{name}");
        }

        // Errors: every name of the table with its TON exit code.
        let shared: Vec<(&str, Option<u16>)> = DestinationError::ALL
            .into_iter()
            .filter(|error| !error.is_ton_only())
            .map(|error| (error.name(), error.ton_exit_code()))
            .collect();
        assert_eq!(shared, SPEC_SHARED_ERRORS);
        let ton_only: Vec<(&str, u16)> = DestinationError::ALL
            .into_iter()
            .filter(|error| error.is_ton_only())
            .map(|error| (error.name(), error.ton_exit_code().expect("a TON code")))
            .collect();
        assert_eq!(ton_only, SPEC_TON_ONLY_ERRORS);
    }

    #[test]
    fn selectors_and_topics_match_the_reference_vectors() {
        let vectors = transitions();
        let selectors = field(&vectors, "selectors")
            .as_object()
            .expect("selectors by name");
        assert_eq!(selectors.len(), SELECTORS.len());
        for (name, signature, selector) in SELECTORS {
            let row = &selectors[name];
            assert_eq!(text(row, "signature"), signature, "{name}");
            assert_eq!(bytes(text(row, "selector")), selector, "{name}");
        }
        let topics = field(&vectors, "event_topics")
            .as_object()
            .expect("events by name");
        assert_eq!(topics.len(), EVENT_TOPICS.len());
        for (name, signature, topic) in EVENT_TOPICS {
            let row = &topics[name];
            assert_eq!(text(row, "signature"), signature, "{name}");
            assert_eq!(bytes(text(row, "topic0")), topic, "{name}");
        }
        // `control_v1.json` repeats the control event.
        let control = reference("control_v1.json", "iroha.sccp.control.v1");
        assert_eq!(text(&control, "event_signature"), EVENT_CONTROL_APPLIED);
        assert_eq!(
            bytes(text(&control, "topic_control_applied")),
            TOPIC_CONTROL_APPLIED
        );
    }

    #[test]
    fn error_table_matches_the_reference_vectors() {
        let vectors = transitions();
        let codes = field(&vectors, "error_codes");
        let shared = field(codes, "shared").as_object().expect("shared errors");
        let ton_only = field(codes, "ton_only")
            .as_object()
            .expect("TON-only errors");
        assert_eq!(shared.len() + ton_only.len(), DestinationError::ALL.len());
        for error in DestinationError::ALL {
            let table = if error.is_ton_only() {
                ton_only
            } else {
                shared
            };
            let code = table.get(error.name()).unwrap_or_else(|| {
                panic!("`{}` is missing from the reference table", error.name())
            });
            assert_eq!(
                code.as_u64(),
                error.ton_exit_code().map(u64::from),
                "{error}"
            );
            assert_eq!(code.is_null(), error.ton_exit_code().is_none(), "{error}");
        }
    }

    #[test]
    fn selectors_are_unique_and_disjoint_from_erc20() {
        let mut seen = BTreeSet::new();
        for (name, _, selector) in SELECTORS {
            assert!(seen.insert(selector), "duplicate selector of {name}");
        }
        for erc20 in [
            "name()",
            "symbol()",
            "decimals()",
            "totalSupply()",
            "balanceOf(address)",
            "transfer(address,uint256)",
            "transferFrom(address,address,uint256)",
            "approve(address,uint256)",
            "allowance(address,address)",
        ] {
            assert!(!seen.contains(&selector_of(erc20)), "{erc20}");
        }
        let topics: BTreeSet<[u8; 32]> = EVENT_TOPICS.into_iter().map(|row| row.2).collect();
        assert_eq!(topics.len(), EVENT_TOPICS.len());
    }

    #[test]
    fn errors_have_one_name_one_code_and_one_signature() {
        let names: BTreeSet<&str> = DestinationError::ALL
            .into_iter()
            .map(DestinationError::name)
            .collect();
        assert_eq!(names.len(), DestinationError::ALL.len());
        let codes: Vec<u16> = DestinationError::ALL
            .into_iter()
            .filter_map(DestinationError::ton_exit_code)
            .collect();
        assert_eq!(codes.len(), 33);
        assert_eq!(codes.iter().copied().collect::<BTreeSet<u16>>().len(), 33);
        // 409 and 432 stay unassigned.
        assert!(codes.iter().all(|code| (400..=434).contains(code)));
        assert!(!codes.contains(&409) && !codes.contains(&432));

        for error in DestinationError::ALL {
            assert_eq!(DestinationError::from_name(error.name()), Some(error));
            // An error is EVM-only, TON-only or shared.
            assert_eq!(
                error.evm_signature().is_none(),
                error.is_ton_only(),
                "{error}"
            );
            assert!(
                error.evm_signature().is_some() || error.ton_exit_code().is_some(),
                "{error}"
            );
            // Only `BadNonce` and `AlreadyConsumed` take an argument, one `uint64`.
            let name = error.name();
            let arguments = if error.argument().is_some() {
                "(uint64)"
            } else {
                "()"
            };
            let shown = error
                .argument()
                .map_or_else(|| name.to_owned(), |argument| format!("{name}({argument})"));
            if let Some(signature) = error.evm_signature() {
                assert_eq!(signature, format!("{}{arguments}", error.name()));
            }
            assert_eq!(error.to_string(), shown);
        }
        let with_argument: Vec<&str> = DestinationError::ALL
            .into_iter()
            .filter(|error| error.argument().is_some())
            .map(DestinationError::name)
            .collect();
        assert_eq!(with_argument, ["BadNonce", "AlreadyConsumed"]);
        assert_eq!(DestinationError::from_name("RosterNotAccepted"), None);
        assert_eq!(DestinationError::from_name(""), None);

        // The two errors with an argument.
        let nonce = DestinationError::BadNonce { expected: 7 };
        assert_eq!((nonce.name(), nonce.argument()), ("BadNonce", Some(7)));
        assert_eq!(nonce.to_string(), "BadNonce(7)");
        assert_eq!(nonce.ton_exit_code(), Some(425));
        let consumed = DestinationError::AlreadyConsumed { nonce: u64::MAX };
        assert_eq!(consumed.argument(), Some(u64::MAX));
        assert_eq!(
            consumed.to_string(),
            "AlreadyConsumed(18446744073709551615)"
        );
        assert_eq!(consumed.ton_exit_code(), None);
        assert_eq!(DestinationError::BadProof.argument(), None);
        let boxed: Box<dyn std::error::Error> = Box::new(DestinationError::LatchRequired);
        assert_eq!(boxed.to_string(), "LatchRequired");
    }
}
