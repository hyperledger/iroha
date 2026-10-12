//! Current SCCP EVM calls, views and source-log codecs (§5.2.2).
//!
//! Certificates use native BLS finality and proofs carry their actual block reference.
//! Source transfer/log codecs preserve strict lengths, widths, offsets and padding.
//! Dynamic void calldata parsing only checks encoder canonicality: void authority comes
//! from authenticated receipt logs, never from a bare successful-looking call.

use iroha_data_model::{bridge::SccpNetworkV1, sccp::deployment::SccpCommitteePinV1};

use super::committee::CommitteeStateV1;

use super::{
    constants::{MAX_TAIRA_ACCOUNT_BYTES, MAX_VOID_FROZEN_RANGE_EVM},
    destination::{
        BlockRefV1, CheckpointRefV1, ControlProofV1, MessageProofV1, TairaCertificateV1,
    },
    destination_abi::*,
    hashes::{word_address, word_bool, word_u64, word_u128},
    network::external_account_codec,
    payload::SccpTransferPayloadV1,
};

/// Bytes of one ABI word.
pub const WORD: usize = 32;
/// Bytes of the canonical `transferToTaira` head: selector and three head words.
pub const TRANSFER_TO_TAIRA_HEAD_BYTES: usize = 4 + 4 * WORD;

unit_error! {
    /// Strict ABI decoding errors.
    pub enum AbiError {
        /// The calldata selector is not the expected function's.
        WrongSelector => "calldata selector does not match the function",
        /// The data length differs from the canonical encoding.
        BadLength => "ABI data length is not canonical",
        /// A dynamic offset differs from the canonical encoding.
        BadOffset => "ABI dynamic offset is not canonical",
        /// An integer or address word has bits set outside its type width.
        DirtyWord => "ABI word has nonzero bits outside its type width",
        /// A `bool` word is not 0 or 1.
        BadBool => "ABI bool word is not 0 or 1",
        /// The padding after a `bytes` value is not zero.
        DirtyPadding => "ABI bytes padding is not zero",
        /// `tairaRecipient` is not 1..=1024 bytes.
        BadRecipientLength => "tairaRecipient must be 1..=1024 bytes",
        /// `tokenAmount` is zero or at least `2^128`.
        BadAmount => "tokenAmount must be in 1..2^128",
        /// A `voidFrozen` count is outside 1..=256 or the range passes `2^64 - 1`.
        BadVoidRange => "voidFrozen count must be 1..=256 and the range must end at most at 2^64 - 1",
        /// A log carries the wrong number of topics.
        WrongTopicCount => "log has the wrong number of topics",
        /// A log's `topic0` is not the expected event.
        WrongTopic => "log topic0 does not match the event",
        /// The log payload does not decode, or differs from the log's other fields.
        PayloadMismatch => "log payload does not match the event fields",
    }
}

// ---------------------------------------------------------------------------------------------
// Generic ABI tokens
// ---------------------------------------------------------------------------------------------

/// One Solidity ABI value, enough for every SCCP v1 signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AbiToken {
    /// A static one-word value (`uintN`, `bool`, `address`, `bytes32`).
    Word([u8; 32]),
    /// Dynamic `bytes`.
    Bytes(Vec<u8>),
    /// Dynamic-length array `T[]`.
    Array(Vec<AbiToken>),
    /// Tuple (struct); dynamic iff any member is.
    Tuple(Vec<AbiToken>),
}

impl AbiToken {
    /// Whether the value is encoded in the tail (behind an offset).
    #[must_use]
    pub fn is_dynamic(&self) -> bool {
        match self {
            Self::Word(_) => false,
            Self::Bytes(_) | Self::Array(_) => true,
            Self::Tuple(members) => members.iter().any(Self::is_dynamic),
        }
    }

    /// Bytes the value occupies in the head of its enclosing sequence.
    #[must_use]
    pub fn head_len(&self) -> usize {
        match self {
            Self::Tuple(members) if !self.is_dynamic() => members.iter().map(Self::head_len).sum(),
            _ => WORD,
        }
    }

    /// The value's own encoding: inline for static values, the tail content for dynamic ones.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Word(word) => out.extend_from_slice(word),
            Self::Bytes(bytes) => {
                out.extend_from_slice(&word_usize(bytes.len()));
                out.extend_from_slice(bytes);
                out.resize(out.len() + padding(bytes.len()), 0);
            }
            Self::Array(items) => {
                out.extend_from_slice(&word_usize(items.len()));
                encode_sequence_into(items, out);
            }
            Self::Tuple(members) => encode_sequence_into(members, out),
        }
    }
}

/// `word(x)` of a length or offset.
fn word_usize(value: usize) -> [u8; 32] {
    word_u64(u64::try_from(value).expect("ABI lengths fit in u64"))
}

/// Zero bytes that pad `len` bytes to a whole number of words.
const fn padding(len: usize) -> usize {
    (WORD - len % WORD) % WORD
}

fn encode_sequence_into(tokens: &[AbiToken], out: &mut Vec<u8>) {
    let head_len: usize = tokens.iter().map(AbiToken::head_len).sum();
    let mut head = Vec::with_capacity(head_len);
    let mut tail = Vec::new();
    for token in tokens {
        if token.is_dynamic() {
            head.extend_from_slice(&word_usize(head_len + tail.len()));
            token.encode_into(&mut tail);
        } else {
            token.encode_into(&mut head);
        }
    }
    out.extend_from_slice(&head);
    out.extend_from_slice(&tail);
}

/// `abi.encode(tokens…)`.
#[must_use]
pub fn encode_tokens(tokens: &[AbiToken]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_sequence_into(tokens, &mut out);
    out
}

/// `selector ‖ abi.encode(tokens…)`.
#[must_use]
pub fn encode_call(selector: [u8; 4], tokens: &[AbiToken]) -> Vec<u8> {
    let mut out = selector.to_vec();
    encode_sequence_into(tokens, &mut out);
    out
}

// ---------------------------------------------------------------------------------------------
// SCCP structs as tokens (§5.2.2)
// ---------------------------------------------------------------------------------------------

fn path_token(path: &[[u8; 32]]) -> AbiToken {
    AbiToken::Array(path.iter().copied().map(AbiToken::Word).collect())
}

/// The five dynamic byte fields of the current BLS certificate.
#[must_use]
pub fn certificate_token(certificate: &TairaCertificateV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Bytes(certificate.qc.clone()),
        AbiToken::Bytes(certificate.header.clone()),
        AbiToken::Bytes(certificate.signature.clone()),
        AbiToken::Bytes(certificate.committee.clone()),
        AbiToken::Bytes(certificate.signer_ys.clone()),
    ])
}
/// A stored checkpoint's exact finality header.
#[must_use]
pub fn checkpoint_token(checkpoint: &CheckpointRefV1) -> AbiToken {
    AbiToken::Tuple(vec![AbiToken::Bytes(checkpoint.header.clone())])
}
/// A leaf's block reference, including its history path under the selected header.
#[must_use]
pub fn block_ref_token(block: &BlockRefV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(block.height)),
        AbiToken::Word(block.sccp_root),
        AbiToken::Word(word_u64(u64::from(block.message_count))),
        AbiToken::Word(word_u64(block.history_index)),
        path_token(&block.history_path),
    ])
}
/// Current message proof, with the block reference inside its tuple.
#[must_use]
pub fn message_proof_token(proof: &MessageProofV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Bytes(proof.payload.clone()),
        AbiToken::Word(word_u64(u64::from(proof.leaf_index))),
        path_token(&proof.path),
        block_ref_token(&proof.block),
    ])
}
/// Current two-track control proof. A non-boolean raw pause byte remains invalid calldata.
#[must_use]
pub fn control_proof_token(control: &ControlProofV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(control.control_nonce)),
        AbiToken::Word(word_u64(u64::from(control.track))),
        AbiToken::Word(word_u64(u64::from(control.parliament_paused))),
        AbiToken::Word(word_u64(control.fast_pause_until_ms)),
        AbiToken::Word(control.certificate_id),
        AbiToken::Word(control.effect_hash),
        AbiToken::Word(word_u64(u64::from(control.leaf_index))),
        path_token(&control.path),
        block_ref_token(&control.block),
    ])
}
/// Encode current checkpoint certificates in their original order.
/// The caller enforces the contract's sixteen-certificate bound before submitting.
#[must_use]
pub fn submit_checkpoints_calldata(certificates: &[TairaCertificateV1]) -> Vec<u8> {
    encode_call(
        SELECTOR_SUBMIT_CHECKPOINTS,
        &[AbiToken::Array(
            certificates.iter().map(certificate_token).collect(),
        )],
    )
}

/// Encode the current `finalize_from_taira` destination call.
#[must_use]
pub fn finalize_from_taira_calldata(
    source: &TairaCertificateV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_FINALIZE_FROM_TAIRA,
        &[certificate_token(source), message_proof_token(proof)],
    )
}

/// Encode the current `finalize_from_checkpoint` destination call.
#[must_use]
pub fn finalize_from_checkpoint_calldata(
    source: &CheckpointRefV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_FINALIZE_FROM_CHECKPOINT,
        &[checkpoint_token(source), message_proof_token(proof)],
    )
}

/// Encode the current `apply_control` destination call.
#[must_use]
pub fn apply_control_calldata(source: &TairaCertificateV1, proof: &ControlProofV1) -> Vec<u8> {
    encode_call(
        SELECTOR_APPLY_CONTROL,
        &[certificate_token(source), control_proof_token(proof)],
    )
}

/// Encode the current `apply_control_from_checkpoint` destination call.
#[must_use]
pub fn apply_control_from_checkpoint_calldata(
    source: &CheckpointRefV1,
    proof: &ControlProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT,
        &[checkpoint_token(source), control_proof_token(proof)],
    )
}

/// Encode the current `void_expired` destination call.
#[must_use]
pub fn void_expired_calldata(
    nonce: u64,
    source: &TairaCertificateV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_VOID_EXPIRED,
        &[
            AbiToken::Word(word_u64(nonce)),
            certificate_token(source),
            message_proof_token(proof),
        ],
    )
}

/// Encode the current `void_expired_from_checkpoint` destination call.
#[must_use]
pub fn void_expired_from_checkpoint_calldata(
    nonce: u64,
    source: &CheckpointRefV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT,
        &[
            AbiToken::Word(word_u64(nonce)),
            checkpoint_token(source),
            message_proof_token(proof),
        ],
    )
}

/// `voidFrozen(uint64 firstNonce,uint64 count)` (`0x5b094c00`).
#[must_use]
pub fn void_frozen_calldata(first_nonce: u64, count: u64) -> Vec<u8> {
    encode_call(
        SELECTOR_VOID_FROZEN,
        &[
            AbiToken::Word(word_u64(first_nonce)),
            AbiToken::Word(word_u64(count)),
        ],
    )
}

/// The arguments of a canonical `transferToTaira` call (§5.1.7).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransferToTairaCallV1 {
    /// `taira_account` recipient bytes (1..=1024).
    pub taira_recipient: Vec<u8>,
    /// Amount in token units (= Taira units), in `1..2^128`.
    pub token_amount: u128,
    /// The caller's expected per-sender nonce.
    pub expected_nonce: u64,
}

impl TransferToTairaCallV1 {
    /// The canonical calldata `0xebfc6ca8 ‖ word(0x60) ‖ word(amount) ‖ word(nonce) ‖
    /// word(len) ‖ recipient ‖ zero padding` (standard ABI encoding of the three arguments).
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        encode_call(
            SELECTOR_TRANSFER_TO_TAIRA,
            &[
                AbiToken::Bytes(self.taira_recipient.clone()),
                AbiToken::Word(word_u128(self.token_amount)),
                AbiToken::Word(word_u64(self.expected_nonce)),
            ],
        )
    }

    /// Strictly decode canonical `transferToTaira` calldata: the selector, the offset `0x60`,
    /// a recipient length in 1..=1024, exact length `4 + 0x80 + ceil32(len)`, zero padding, a
    /// clean `uint64` nonce and `0 < tokenAmount < 2^128`. The contract reverts on every other
    /// encoding, so this is exactly the set of successful calls (§4.12.2).
    ///
    /// # Errors
    ///
    /// Returns the first violated [`AbiError`].
    pub fn decode(calldata: &[u8]) -> Result<Self, AbiError> {
        let args = strip_selector(calldata, SELECTOR_TRANSFER_TO_TAIRA)?;
        if args.len() < 4 * WORD {
            return Err(AbiError::BadLength);
        }
        if read_usize(args, 0)? != 3 * WORD {
            return Err(AbiError::BadOffset);
        }
        let len = read_usize(args, 3 * WORD)?;
        if !(1..=MAX_TAIRA_ACCOUNT_BYTES).contains(&len) {
            return Err(AbiError::BadRecipientLength);
        }
        if args.len() != 4 * WORD + len + padding(len) {
            return Err(AbiError::BadLength);
        }
        let recipient = &args[4 * WORD..4 * WORD + len];
        if args[4 * WORD + len..].iter().any(|byte| *byte != 0) {
            return Err(AbiError::DirtyPadding);
        }
        let token_amount = read_u128(args, WORD)?;
        if token_amount == 0 {
            return Err(AbiError::BadAmount);
        }
        Ok(Self {
            taira_recipient: recipient.to_vec(),
            token_amount,
            expected_nonce: read_u64(args, 2 * WORD)?,
        })
    }

    /// The inbound payload Taira rebuilds from this call (§4.12.2): `source` → Taira with
    /// `nonce = expectedNonce`, `amount = tokenAmount`, the caller as sender (20 bytes) and the
    /// route constants.
    ///
    /// # Errors
    ///
    /// Returns [`AbiError::PayloadMismatch`] when `source` is not an EVM profile or the payload
    /// rules fail.
    pub fn inbound_payload(
        &self,
        source: SccpNetworkV1,
        route_revision: u32,
        caller: &[u8; 20],
    ) -> Result<SccpTransferPayloadV1, AbiError> {
        let sender = evm_account(source, caller)?;
        SccpTransferPayloadV1::inbound(
            source,
            self.expected_nonce,
            route_revision,
            self.token_amount,
            sender,
            self.taira_recipient.clone(),
        )
        .map_err(|_| AbiError::PayloadMismatch)
    }
}

/// The payload account bytes of a 20-byte address on the EVM profile `network` (codec 2).
fn evm_account(network: SccpNetworkV1, address: &[u8; 20]) -> Result<Vec<u8>, AbiError> {
    match external_account_codec(network) {
        Some(super::constants::CODEC_EVM_ADDRESS20) => Ok(address.to_vec()),
        _ => Err(AbiError::PayloadMismatch),
    }
}

// ---------------------------------------------------------------------------------------------
// Canonical-encoding check of the void calls
// ---------------------------------------------------------------------------------------------

/// The ABI type of one value, as far as the canonical-encoding check needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbiShape {
    /// A static word holding an unsigned integer of the given byte width (`uint64` is 8,
    /// `bytes32` is 32).
    Uint(usize),
    /// Dynamic `bytes`.
    Bytes,
    /// Dynamic `bytes32[]`.
    Words,
    /// A tuple; dynamic iff any member is.
    Tuple(&'static [AbiShape]),
}

const SHAPE_U32: AbiShape = AbiShape::Uint(4);
const SHAPE_U64: AbiShape = AbiShape::Uint(8);
const SHAPE_B32: AbiShape = AbiShape::Uint(WORD);
const SHAPE_CERTIFICATE: AbiShape = AbiShape::Tuple(&[AbiShape::Bytes; 5]);
const SHAPE_CHECKPOINT: AbiShape = AbiShape::Tuple(&[AbiShape::Bytes]);
const SHAPE_BLOCK_REF: AbiShape =
    AbiShape::Tuple(&[SHAPE_U64, SHAPE_B32, SHAPE_U32, SHAPE_U64, AbiShape::Words]);
const SHAPE_MESSAGE_PROOF: AbiShape =
    AbiShape::Tuple(&[AbiShape::Bytes, SHAPE_U32, AbiShape::Words, SHAPE_BLOCK_REF]);
const VOID_EXPIRED_ARGS: &[AbiShape] = &[SHAPE_U64, SHAPE_CERTIFICATE, SHAPE_MESSAGE_PROOF];
const VOID_EXPIRED_FROM_CHECKPOINT_ARGS: &[AbiShape] =
    &[SHAPE_U64, SHAPE_CHECKPOINT, SHAPE_MESSAGE_PROOF];
/// Arguments of `voidFrozen`.
const VOID_FROZEN_ARGS: &[AbiShape] = &[SHAPE_U64, SHAPE_U64];

impl AbiShape {
    /// Whether the value is encoded in the tail (behind an offset).
    fn is_dynamic(self) -> bool {
        match self {
            Self::Uint(_) => false,
            Self::Bytes | Self::Words => true,
            Self::Tuple(members) => members.iter().any(|member| member.is_dynamic()),
        }
    }

    /// Bytes the value occupies in the head of its enclosing sequence.
    fn head_len(self) -> usize {
        match self {
            Self::Tuple(members) if !self.is_dynamic() => {
                members.iter().map(|member| member.head_len()).sum()
            }
            _ => WORD,
        }
    }

    /// Check the value's own canonical encoding at `data[at..]` (inline for a static value,
    /// the tail content for a dynamic one) and return its encoded size.
    fn canonical_size(self, data: &[u8], at: usize) -> Result<usize, AbiError> {
        match self {
            Self::Uint(bytes) => read_uint(data, at, bytes).map(|_| WORD),
            Self::Bytes => {
                let len = read_usize(data, at)?;
                let start = at + WORD;
                let end = start
                    .checked_add(len)
                    .and_then(|end| end.checked_add(padding(len)))
                    .filter(|end| *end <= data.len())
                    .ok_or(AbiError::BadLength)?;
                if data[start + len..end].iter().any(|byte| *byte != 0) {
                    return Err(AbiError::DirtyPadding);
                }
                Ok(end - at)
            }
            Self::Words => {
                let count = read_usize(data, at)?;
                count
                    .checked_mul(WORD)
                    .and_then(|bytes| bytes.checked_add(WORD))
                    .filter(|size| at.checked_add(*size).is_some_and(|end| end <= data.len()))
                    .ok_or(AbiError::BadLength)
            }
            Self::Tuple(members) => canonical_sequence_size(members, data, at),
        }
    }
}

/// Check the canonical encoding of the sequence `members` whose head starts at `data[base..]`
/// and return its encoded size. Every dynamic offset must be the position at which the
/// canonical encoder places that member's tail; the offsets are compared, never followed.
fn canonical_sequence_size(
    members: &[AbiShape],
    data: &[u8],
    base: usize,
) -> Result<usize, AbiError> {
    let mut head = base;
    let mut tail = members
        .iter()
        .map(|member| member.head_len())
        .sum::<usize>();
    for member in members {
        if member.is_dynamic() {
            let offset = read_usize(data, head).map_err(|error| match error {
                AbiError::DirtyWord => AbiError::BadOffset,
                other => other,
            })?;
            if offset != tail {
                return Err(AbiError::BadOffset);
            }
            tail += member.canonical_size(data, base + tail)?;
            head += WORD;
        } else {
            head += member.canonical_size(data, head)?;
        }
    }
    Ok(tail)
}

/// Require `args` (calldata after the selector) to be exactly the canonical ABI encoding of
/// `members`: canonical offsets, integer words within their widths, zero `bytes` padding and no
/// trailing bytes. This is an encoder canonicality check; dynamic void arguments need no extra on-chain
/// canonical-calldata rule. A source proof authenticates the emitted void logs.
fn check_canonical_args(args: &[u8], members: &[AbiShape]) -> Result<(), AbiError> {
    if canonical_sequence_size(members, args, 0)? == args.len() {
        Ok(())
    } else {
        Err(AbiError::BadLength)
    }
}

/// A decoded void call (§5.1.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VoidCallV1 {
    /// `voidExpired` or `voidExpiredFromCheckpoint` of one nonce (the first static head word).
    Expired {
        /// The voided nonce.
        nonce: u64,
        /// Whether the stored-checkpoint variant was called.
        from_checkpoint: bool,
    },
    /// `voidFrozen(firstNonce, count)`.
    Frozen {
        /// First voided nonce.
        first_nonce: u64,
        /// Number of voided nonces.
        count: u64,
    },
}

impl VoidCallV1 {
    /// Strictly decode a void call. The calldata must be exactly the canonical ABI encoding of
    /// `voidExpired`, `voidExpiredFromCheckpoint` or `voidFrozen` (canonical offsets, integer words
    /// within their widths, zero `bytes` padding, no trailing bytes), and a `voidFrozen` range
    /// must hold 1..=256 nonces ending at most at `2^64 - 1`. This parser accepts the canonical output of these encoders. Dynamic voids on
    /// chain are established from authenticated logs, not inferred from this calldata parser.
    ///
    /// # Errors
    ///
    /// Returns [`AbiError::WrongSelector`] for any other function, [`AbiError::BadVoidRange`]
    /// for an out-of-range `voidFrozen`, or the first violated encoding rule.
    pub fn decode(calldata: &[u8]) -> Result<Self, AbiError> {
        let selector = selector_of(calldata)?;
        let args = &calldata[4..];
        let from_checkpoint = match selector {
            SELECTOR_VOID_FROZEN => {
                check_canonical_args(args, VOID_FROZEN_ARGS)?;
                let first_nonce = read_u64(args, 0)?;
                let count = read_u64(args, WORD)?;
                if count == 0
                    || count > MAX_VOID_FROZEN_RANGE_EVM
                    || first_nonce.checked_add(count - 1).is_none()
                {
                    return Err(AbiError::BadVoidRange);
                }
                return Ok(Self::Frozen { first_nonce, count });
            }
            SELECTOR_VOID_EXPIRED => false,
            SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT => true,
            _ => return Err(AbiError::WrongSelector),
        };
        let members = if from_checkpoint {
            VOID_EXPIRED_FROM_CHECKPOINT_ARGS
        } else {
            VOID_EXPIRED_ARGS
        };
        check_canonical_args(args, members)?;
        Ok(Self::Expired {
            nonce: read_u64(args, 0)?,
            from_checkpoint,
        })
    }

    /// `(first nonce, count)` of the voided range.
    #[must_use]
    pub fn range(&self) -> (u64, u64) {
        match *self {
            Self::Expired { nonce, .. } => (nonce, 1),
            Self::Frozen { first_nonce, count } => (first_nonce, count),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// View calls
// ---------------------------------------------------------------------------------------------

/// The five fields returned by `committeeState()`. The equivocation latch is a separate view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitteeViewV1 {
    /// Current compressed-key committee root.
    pub root: [u8; 32],
    /// Deadline of the current generation, in milliseconds.
    pub until_ms: u64,
    /// First height in this generation.
    pub start: u64,
    /// Highest accepted height.
    pub high: u64,
    /// Current generation number.
    pub generation: u64,
}
impl CommitteeViewV1 {
    /// Combine the separately read latch with this view; omitting it would lose authority state.
    #[must_use]
    pub const fn with_equivocated(self, equivocated: bool) -> CommitteeStateV1 {
        CommitteeStateV1 {
            root: self.root,
            until_ms: self.until_ms,
            start: self.start,
            high: self.high,
            generation: self.generation,
            equivocated,
        }
    }
}
/// The independent Parliament and fast-pause fields returned by `pauseState()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PauseViewV1 {
    /// Parliament's persistent pause flag.
    pub parliament_paused: bool,
    /// Fast-pause expiry, in milliseconds.
    pub fast_pause_until_ms: u64,
    /// Latest destination control nonce.
    pub control_nonce: u64,
    /// Effective pause at the block where the view was read.
    pub effective: bool,
}
/// A current view call of §5.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewCallV1 {
    /// `committeeState()`.
    CommitteeState,
    /// `checkpointHeader(uint64)`.
    CheckpointHeader(u64),
    /// `pauseState()`.
    PauseState,
    /// `consensusInstance()`.
    ConsensusInstance,
    /// `initialCommittee()`.
    InitialCommittee,
    /// `equivocated()`.
    Equivocated,
    /// `maxValidityMs()`.
    MaxValidityMs,
    /// `isConsumed(uint64)`.
    IsConsumed(u64),
    /// `transferNonces(address)`.
    TransferNonces([u8; 20]),
    /// `tairaNetworkId()`.
    TairaNetworkId,
    /// `routeRevision()`.
    RouteRevision,
    /// `maxWrappedSupply()`.
    MaxWrappedSupply,
    /// `mintingPaused()`.
    MintingPaused,
    /// `controlNonce()`.
    ControlNonce,
    /// `opCount()`.
    OpCount,
}
/// A strictly decoded current destination view return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewReturnV1 {
    /// Current committee fields, before the separately read latch is joined.
    CommitteeState(CommitteeViewV1),
    /// Two-track pause state.
    PauseState(PauseViewV1),
    /// Immutable deployment committee pin.
    InitialCommittee(SccpCommitteePinV1),
    /// A `bool` return.
    Bool(bool),
    /// A `uint32` return.
    U32(u32),
    /// A `uint64` return.
    U64(u64),
    /// A `uint256` return below `2^128`.
    U128(u128),
    /// A `bytes32` return.
    Bytes32([u8; 32]),
}
impl ViewCallV1 {
    /// The function selector.
    #[must_use]
    pub const fn selector(&self) -> [u8; 4] {
        match self {
            Self::CommitteeState => SELECTOR_COMMITTEE_STATE,
            Self::CheckpointHeader(_) => SELECTOR_CHECKPOINT_HEADER,
            Self::PauseState => SELECTOR_PAUSE_STATE,
            Self::ConsensusInstance => SELECTOR_CONSENSUS_INSTANCE,
            Self::InitialCommittee => SELECTOR_INITIAL_COMMITTEE,
            Self::Equivocated => SELECTOR_EQUIVOCATED,
            Self::MaxValidityMs => SELECTOR_MAX_VALIDITY_MS,
            Self::IsConsumed(_) => SELECTOR_IS_CONSUMED,
            Self::TransferNonces(_) => SELECTOR_TRANSFER_NONCES,
            Self::TairaNetworkId => SELECTOR_TAIRA_NETWORK_ID,
            Self::RouteRevision => SELECTOR_ROUTE_REVISION,
            Self::MaxWrappedSupply => SELECTOR_MAX_WRAPPED_SUPPLY,
            Self::MintingPaused => SELECTOR_MINTING_PAUSED,
            Self::ControlNonce => SELECTOR_CONTROL_NONCE,
            Self::OpCount => SELECTOR_OP_COUNT,
        }
    }
    /// The `eth_call` data.
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        match self {
            Self::IsConsumed(nonce) | Self::CheckpointHeader(nonce) => {
                encode_call(self.selector(), &[AbiToken::Word(word_u64(*nonce))])
            }
            Self::TransferNonces(address) => {
                encode_call(self.selector(), &[AbiToken::Word(word_address(address))])
            }
            _ => self.selector().to_vec(),
        }
    }
    /// Strictly decode the return data of this call.
    ///
    /// # Errors
    /// Returns [`AbiError::BadLength`], [`AbiError::DirtyWord`] or [`AbiError::BadBool`].
    pub fn decode_return(&self, data: &[u8]) -> Result<ViewReturnV1, AbiError> {
        Ok(match self {
            Self::CommitteeState => {
                ViewReturnV1::CommitteeState(decode_committee_state_return(data)?)
            }
            Self::CheckpointHeader(_) => ViewReturnV1::Bytes32(decode_bytes32_return(data)?),
            Self::PauseState => ViewReturnV1::PauseState(decode_pause_state_return(data)?),
            Self::ConsensusInstance => ViewReturnV1::Bytes32(decode_bytes32_return(data)?),
            Self::InitialCommittee => {
                ViewReturnV1::InitialCommittee(decode_initial_committee_return(data)?)
            }
            Self::Equivocated => ViewReturnV1::Bool(decode_bool_return(data)?),
            Self::MaxValidityMs => ViewReturnV1::U64(decode_u64_return(data)?),
            Self::IsConsumed(_) => ViewReturnV1::Bool(decode_bool_return(data)?),
            Self::TransferNonces(_) => ViewReturnV1::U64(decode_u64_return(data)?),
            Self::TairaNetworkId => ViewReturnV1::Bytes32(decode_bytes32_return(data)?),
            Self::RouteRevision => ViewReturnV1::U32(decode_u32_return(data)?),
            Self::MaxWrappedSupply => ViewReturnV1::U128(decode_u128_return(data)?),
            Self::MintingPaused => ViewReturnV1::Bool(decode_bool_return(data)?),
            Self::ControlNonce => ViewReturnV1::U64(decode_u64_return(data)?),
            Self::OpCount => ViewReturnV1::U64(decode_u64_return(data)?),
        })
    }
}

fn single_word(data: &[u8]) -> Result<&[u8], AbiError> {
    if data.len() == WORD {
        Ok(data)
    } else {
        Err(AbiError::BadLength)
    }
}

/// Decode a single `bool` return word.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`] or [`AbiError::BadBool`].
pub fn decode_bool_return(data: &[u8]) -> Result<bool, AbiError> {
    read_bool(single_word(data)?, 0)
}

/// Decode a single `uint32` return word.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`] or [`AbiError::DirtyWord`].
pub fn decode_u32_return(data: &[u8]) -> Result<u32, AbiError> {
    let value = read_u64(single_word(data)?, 0)?;
    u32::try_from(value).map_err(|_| AbiError::DirtyWord)
}

/// Decode a single `uint64` return word.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`] or [`AbiError::DirtyWord`].
pub fn decode_u64_return(data: &[u8]) -> Result<u64, AbiError> {
    read_u64(single_word(data)?, 0)
}

/// Decode a single `uint256` return word that must be below `2^128`.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`] or [`AbiError::DirtyWord`].
pub fn decode_u128_return(data: &[u8]) -> Result<u128, AbiError> {
    read_u128(single_word(data)?, 0)
}

/// Decode a single `bytes32` return word.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`].
pub fn decode_bytes32_return(data: &[u8]) -> Result<[u8; 32], AbiError> {
    Ok(read_word(single_word(data)?, 0))
}

/// Decode the five exact words of `committeeState()` in ABI order.
///
/// # Errors
/// Returns [`AbiError::BadLength`] or [`AbiError::DirtyWord`].
pub fn decode_committee_state_return(data: &[u8]) -> Result<CommitteeViewV1, AbiError> {
    if data.len() != 5 * WORD {
        return Err(AbiError::BadLength);
    }
    Ok(CommitteeViewV1 {
        root: read_word(data, 0),
        until_ms: read_u64(data, WORD)?,
        start: read_u64(data, 2 * WORD)?,
        high: read_u64(data, 3 * WORD)?,
        generation: read_u64(data, 4 * WORD)?,
    })
}
/// Encode the exact `committeeState()` return for transports and fixtures.
#[must_use]
pub fn encode_committee_state_return(state: &CommitteeViewV1) -> Vec<u8> {
    encode_tokens(&[
        AbiToken::Word(state.root),
        AbiToken::Word(word_u64(state.until_ms)),
        AbiToken::Word(word_u64(state.start)),
        AbiToken::Word(word_u64(state.high)),
        AbiToken::Word(word_u64(state.generation)),
    ])
}
/// Decode the four exact words of `pauseState()` with strict booleans and integer widths.
///
/// # Errors
/// Returns [`AbiError::BadLength`], [`AbiError::DirtyWord`] or [`AbiError::BadBool`].
pub fn decode_pause_state_return(data: &[u8]) -> Result<PauseViewV1, AbiError> {
    if data.len() != 4 * WORD {
        return Err(AbiError::BadLength);
    }
    Ok(PauseViewV1 {
        parliament_paused: read_bool(data, 0)?,
        fast_pause_until_ms: read_u64(data, WORD)?,
        control_nonce: read_u64(data, 2 * WORD)?,
        effective: read_bool(data, 3 * WORD)?,
    })
}
/// Encode the exact `pauseState()` return for transports and fixtures.
#[must_use]
pub fn encode_pause_state_return(state: &PauseViewV1) -> Vec<u8> {
    encode_tokens(&[
        AbiToken::Word(word_bool(state.parliament_paused)),
        AbiToken::Word(word_u64(state.fast_pause_until_ms)),
        AbiToken::Word(word_u64(state.control_nonce)),
        AbiToken::Word(word_bool(state.effective)),
    ])
}
/// Decode the immutable deployment pin returned by `initialCommittee()`.
/// This decoding does not authenticate a deployment or certify a pin.
///
/// # Errors
/// Returns [`AbiError::BadLength`] or [`AbiError::DirtyWord`].
pub fn decode_initial_committee_return(data: &[u8]) -> Result<SccpCommitteePinV1, AbiError> {
    if data.len() != 4 * WORD {
        return Err(AbiError::BadLength);
    }
    Ok(SccpCommitteePinV1 {
        generation: read_u64(data, 0)?,
        committee_root: read_word(data, WORD),
        start_height: read_u64(data, 2 * WORD)?,
        until_ms: read_u64(data, 3 * WORD)?,
    })
}
/// Encode the exact `initialCommittee()` return for transports and fixtures.
#[must_use]
pub fn encode_initial_committee_return(pin: &SccpCommitteePinV1) -> Vec<u8> {
    encode_tokens(&[
        AbiToken::Word(word_u64(pin.generation)),
        AbiToken::Word(pin.committee_root),
        AbiToken::Word(word_u64(pin.start_height)),
        AbiToken::Word(word_u64(pin.until_ms)),
    ])
}

// ---------------------------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------------------------

/// `SccpTransferToTaira(bytes32 indexed messageId, address indexed sender, uint64 nonce,
/// bytes payload)`: `topics = [topic0, messageId, word(sender)]`,
/// `data = abi.encode(uint64 nonce, bytes payload)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransferToTairaLogV1 {
    /// `message_id` of the inbound payload.
    pub message_id: [u8; 32],
    /// The burning caller (20 bytes).
    pub sender: [u8; 20],
    /// The caller's per-sender nonce.
    pub nonce: u64,
    /// The §3.2 payload bytes.
    pub payload: Vec<u8>,
}

impl TransferToTairaLogV1 {
    /// The log's topics and data.
    #[must_use]
    pub fn encode(&self) -> (Vec<[u8; 32]>, Vec<u8>) {
        (
            vec![
                TOPIC_TRANSFER_TO_TAIRA,
                self.message_id,
                word_address(&self.sender),
            ],
            encode_tokens(&[
                AbiToken::Word(word_u64(self.nonce)),
                AbiToken::Bytes(self.payload.clone()),
            ]),
        )
    }

    /// Strictly decode the log: exactly three topics, the event's `topic0`, a clean address
    /// topic and canonical `abi.encode(uint64, bytes)` data without trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns the first violated [`AbiError`].
    pub fn decode(topics: &[[u8; 32]], data: &[u8]) -> Result<Self, AbiError> {
        if topics.len() != 3 {
            return Err(AbiError::WrongTopicCount);
        }
        if topics[0] != TOPIC_TRANSFER_TO_TAIRA {
            return Err(AbiError::WrongTopic);
        }
        let sender = read_address(&topics[2], 0)?;
        if data.len() < 3 * WORD {
            return Err(AbiError::BadLength);
        }
        let nonce = read_u64(data, 0)?;
        if read_usize(data, WORD)? != 2 * WORD {
            return Err(AbiError::BadOffset);
        }
        let len = read_usize(data, 2 * WORD)?;
        if len > data.len() {
            return Err(AbiError::BadLength);
        }
        let end = 3 * WORD + len;
        if data.len() != end + padding(len) {
            return Err(AbiError::BadLength);
        }
        if data[end..].iter().any(|byte| *byte != 0) {
            return Err(AbiError::DirtyPadding);
        }
        Ok(Self {
            message_id: topics[1],
            sender,
            nonce,
            payload: data[3 * WORD..end].to_vec(),
        })
    }

    /// Check the log against the payload it carries: the payload decodes as a `source` → Taira
    /// transfer of `route_revision`, its nonce and sender equal the log's, and its message id
    /// under `taira_network_id` equals `messageId`. Returns the decoded payload.
    ///
    /// # Errors
    ///
    /// Returns [`AbiError::PayloadMismatch`].
    pub fn verified_payload(
        &self,
        taira_network_id: &[u8; 32],
        source: SccpNetworkV1,
        route_revision: u32,
    ) -> Result<SccpTransferPayloadV1, AbiError> {
        let payload =
            SccpTransferPayloadV1::decode(&self.payload).map_err(|_| AbiError::PayloadMismatch)?;
        let sender = evm_account(source, &self.sender)?;
        let bound = payload.source() == Some(source)
            && payload.target() == Some(SccpNetworkV1::SoraTaira)
            && payload.route_revision == route_revision
            && payload.nonce == self.nonce
            && payload.sender.bytes == sender
            && payload.message_id(taira_network_id).ok() == Some(self.message_id);
        if bound {
            Ok(payload)
        } else {
            Err(AbiError::PayloadMismatch)
        }
    }
}

/// `SccpVoided(bytes32 indexed messageId, uint64 indexed nonce)`: `topics = [topic0,
/// messageId, word(nonce)]`, empty data; `messageId = 0` for `voidFrozen`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VoidedLogV1 {
    /// Voided message id, or zero for a frozen void.
    pub message_id: [u8; 32],
    /// Voided nonce.
    pub nonce: u64,
}

impl VoidedLogV1 {
    /// The log's topics and (empty) data.
    #[must_use]
    pub fn encode(&self) -> (Vec<[u8; 32]>, Vec<u8>) {
        (
            vec![TOPIC_VOIDED, self.message_id, word_u64(self.nonce)],
            Vec::new(),
        )
    }

    /// Strictly decode the log: exactly three topics, the event's `topic0`, a clean `uint64`
    /// nonce topic and empty data.
    ///
    /// # Errors
    ///
    /// Returns the first violated [`AbiError`].
    pub fn decode(topics: &[[u8; 32]], data: &[u8]) -> Result<Self, AbiError> {
        if topics.len() != 3 {
            return Err(AbiError::WrongTopicCount);
        }
        if topics[0] != TOPIC_VOIDED {
            return Err(AbiError::WrongTopic);
        }
        if !data.is_empty() {
            return Err(AbiError::BadLength);
        }
        Ok(Self {
            message_id: topics[1],
            nonce: read_u64(&topics[2], 0)?,
        })
    }

    /// Whether this is a `voidFrozen` void (`messageId = 0`).
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.message_id == [0; 32]
    }
}

// ---------------------------------------------------------------------------------------------
// Strict word readers
// ---------------------------------------------------------------------------------------------

/// The 4-byte selector of `calldata`.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`] for calldata shorter than 4 bytes.
pub fn selector_of(calldata: &[u8]) -> Result<[u8; 4], AbiError> {
    calldata
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .ok_or(AbiError::BadLength)
}

fn strip_selector(calldata: &[u8], selector: [u8; 4]) -> Result<&[u8], AbiError> {
    if selector_of(calldata)? != selector {
        return Err(AbiError::WrongSelector);
    }
    Ok(&calldata[4..])
}

/// The word at `offset`; callers check the length first.
fn read_word(data: &[u8], offset: usize) -> [u8; 32] {
    let mut word = [0_u8; 32];
    word.copy_from_slice(&data[offset..offset + WORD]);
    word
}

fn checked_word(data: &[u8], offset: usize) -> Result<[u8; 32], AbiError> {
    if data.len() < offset + WORD {
        return Err(AbiError::BadLength);
    }
    Ok(read_word(data, offset))
}

fn read_uint(data: &[u8], offset: usize, bytes: usize) -> Result<[u8; 32], AbiError> {
    let word = checked_word(data, offset)?;
    if word[..WORD - bytes].iter().any(|byte| *byte != 0) {
        return Err(AbiError::DirtyWord);
    }
    Ok(word)
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, AbiError> {
    let word = read_uint(data, offset, 8)?;
    Ok(u64::from_be_bytes(word[24..].try_into().expect("8 bytes")))
}

fn read_u128(data: &[u8], offset: usize) -> Result<u128, AbiError> {
    let word = read_uint(data, offset, 16)?;
    Ok(u128::from_be_bytes(
        word[16..].try_into().expect("16 bytes"),
    ))
}

fn read_usize(data: &[u8], offset: usize) -> Result<usize, AbiError> {
    usize::try_from(read_u64(data, offset)?).map_err(|_| AbiError::DirtyWord)
}

fn read_bool(data: &[u8], offset: usize) -> Result<bool, AbiError> {
    match read_uint(data, offset, 1).map_err(|_| AbiError::BadBool)?[31] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AbiError::BadBool),
    }
}

fn read_address(data: &[u8], offset: usize) -> Result<[u8; 20], AbiError> {
    let word = read_uint(data, offset, 20)?;
    Ok(word[12..].try_into().expect("20 bytes"))
}

#[cfg(test)]
mod tests;
