//! SCCP v1 EVM ABI (spec §5.1.7, §5.2.2, §4.12.2, §4.16).
//!
//! Canonical Solidity ABI encoders for native BLS certificate and checkpoint calls,
//! strict view and void-call decoders, and transfer/void log codecs. These are DATA
//! encodings: certificate verification and destination authority are separate.
//!
//! Dynamic offsets are relative to their enclosing sequence. Decoders reject gaps,
//! dirty integer words and padding, and trailing bytes. ETH and BSC share this ABI.

use iroha_data_model::bridge::SccpNetworkV1;

use super::{
    constants::{MAX_TAIRA_ACCOUNT_BYTES, MAX_VOID_FROZEN_RANGE_EVM},
    destination::{
        BlockRefV1, CheckpointRefV1, ControlProofV1, MessageProofV1, TairaCertificateV1,
    },
    destination_abi::{
        SELECTOR_APPLY_CONTROL, SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT, SELECTOR_CHECKPOINT_HEADER,
        SELECTOR_COMMITTEE_STATE, SELECTOR_CONSENSUS_INSTANCE, SELECTOR_CONTROL_NONCE,
        SELECTOR_EQUIVOCATED, SELECTOR_FINALIZE_FROM_CHECKPOINT, SELECTOR_FINALIZE_FROM_TAIRA,
        SELECTOR_INITIAL_COMMITTEE, SELECTOR_IS_CONSUMED, SELECTOR_MAX_VALIDITY_MS,
        SELECTOR_MAX_WRAPPED_SUPPLY, SELECTOR_MINTING_PAUSED, SELECTOR_OP_COUNT,
        SELECTOR_PAUSE_STATE, SELECTOR_ROUTE_REVISION, SELECTOR_SUBMIT_CHECKPOINTS,
        SELECTOR_TAIRA_NETWORK_ID, SELECTOR_TRANSFER_NONCES, SELECTOR_TRANSFER_TO_TAIRA,
        SELECTOR_VOID_EXPIRED, SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT, SELECTOR_VOID_FROZEN,
        TOPIC_TRANSFER_TO_TAIRA, TOPIC_VOIDED,
    },
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

/// EVM `TairaCertificateV1`; the TON compressed signature is not an EVM field.
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

/// `CheckpointRefV1 { header }`.
#[must_use]
pub fn checkpoint_ref_token(checkpoint: &CheckpointRefV1) -> AbiToken {
    AbiToken::Tuple(vec![AbiToken::Bytes(checkpoint.header.clone())])
}

/// `BlockRefV1 { height, sccpRoot, messageCount, historyIndex, historyPath }`.
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

/// `MessageProofV1 { payload, leafIndex, path, block }`.
#[must_use]
pub fn message_proof_token(proof: &MessageProofV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Bytes(proof.payload.clone()),
        AbiToken::Word(word_u64(u64::from(proof.leaf_index))),
        path_token(&proof.path),
        block_ref_token(&proof.block),
    ])
}

/// `ControlProofV1` with all authenticated pause fields and its block reference.
/// The raw `parliament_paused` byte is preserved; values above 1 produce an ABI
/// bool the destination rejects, never a silently normalized control.
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

/// `finalizeFromTaira(TairaCertificateV1,MessageProofV1)`.
#[must_use]
pub fn finalize_from_taira_calldata(
    certificate: &TairaCertificateV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_FINALIZE_FROM_TAIRA,
        &[certificate_token(certificate), message_proof_token(proof)],
    )
}

/// `finalizeFromCheckpoint(CheckpointRefV1,MessageProofV1)`.
#[must_use]
pub fn finalize_from_checkpoint_calldata(
    checkpoint: &CheckpointRefV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_FINALIZE_FROM_CHECKPOINT,
        &[checkpoint_ref_token(checkpoint), message_proof_token(proof)],
    )
}

/// `submitCheckpoints(TairaCertificateV1[])` in the supplied order.
/// The destination enforces the nonempty, at-most-16 batch limit.
#[must_use]
pub fn submit_checkpoints_calldata(certificates: &[TairaCertificateV1]) -> Vec<u8> {
    encode_call(
        SELECTOR_SUBMIT_CHECKPOINTS,
        &[AbiToken::Array(
            certificates.iter().map(certificate_token).collect(),
        )],
    )
}

/// `applyControl(TairaCertificateV1,ControlProofV1)`.
#[must_use]
pub fn apply_control_calldata(
    certificate: &TairaCertificateV1,
    control: &ControlProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_APPLY_CONTROL,
        &[certificate_token(certificate), control_proof_token(control)],
    )
}

/// `applyControlFromCheckpoint(CheckpointRefV1,ControlProofV1)`.
#[must_use]
pub fn apply_control_from_checkpoint_calldata(
    checkpoint: &CheckpointRefV1,
    control: &ControlProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT,
        &[
            checkpoint_ref_token(checkpoint),
            control_proof_token(control),
        ],
    )
}

/// `voidExpired(uint64,TairaCertificateV1,MessageProofV1)`.
#[must_use]
pub fn void_expired_calldata(
    nonce: u64,
    certificate: &TairaCertificateV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_VOID_EXPIRED,
        &[
            AbiToken::Word(word_u64(nonce)),
            certificate_token(certificate),
            message_proof_token(proof),
        ],
    )
}

/// `voidExpiredFromCheckpoint(uint64,CheckpointRefV1,MessageProofV1)`.
#[must_use]
pub fn void_expired_from_checkpoint_calldata(
    nonce: u64,
    checkpoint: &CheckpointRefV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    encode_call(
        SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT,
        &[
            AbiToken::Word(word_u64(nonce)),
            checkpoint_ref_token(checkpoint),
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
const SHAPE_BLOCK: AbiShape =
    AbiShape::Tuple(&[SHAPE_U64, SHAPE_B32, SHAPE_U32, SHAPE_U64, AbiShape::Words]);
const SHAPE_MESSAGE_PROOF: AbiShape =
    AbiShape::Tuple(&[AbiShape::Bytes, SHAPE_U32, AbiShape::Words, SHAPE_BLOCK]);
/// Arguments of `voidExpired`.
const VOID_EXPIRED_ARGS: &[AbiShape] = &[SHAPE_U64, SHAPE_CERTIFICATE, SHAPE_MESSAGE_PROOF];
/// Arguments of `voidExpiredFromCheckpoint`.
const VOID_EXPIRED_CHECKPOINT_ARGS: &[AbiShape] =
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
/// trailing bytes. This is a local encoding check, not proof or receipt authentication.
/// The contract requires this exact encoding for `voidFrozen`; its `voidExpired*`
/// entry points use Solidity's more permissive ABI decoder (§5.1.8, §5.2.2).
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
        /// Whether the certificate came from a stored checkpoint.
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
    /// must hold 1..=256 nonces ending at most at `2^64 - 1`. This local decoder is
    /// stricter than Solidity's ABI decoder for `voidExpired*`; successful voids are
    /// established by authenticated events (§5.1.8), not by this encoding check.
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
            VOID_EXPIRED_CHECKPOINT_ARGS
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

/// Decoded `committeeState()` DATA. The latch is a separate `equivocated()` view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CommitteeViewV1 {
    /// Current committee root.
    pub root: [u8; 32],
    /// Current trust deadline.
    pub until_ms: u64,
    /// Current generation's first height.
    pub start: u64,
    /// Highest certified height.
    pub high: u64,
    /// Current generation.
    pub generation: u64,
}

/// Decoded immutable `initialCommittee()` pin DATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InitialCommitteeViewV1 {
    /// Pinned generation.
    pub generation: u64,
    /// Pinned committee root.
    pub root: [u8; 32],
    /// Pinned first height.
    pub start: u64,
    /// Pinned trust deadline.
    pub until_ms: u64,
}

/// Decoded `pauseState()` DATA at the queried destination block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PauseStateV1 {
    /// Applied Parliament pause bit.
    pub parliament_paused: bool,
    /// Applied fast-pause deadline.
    pub fast_pause_until_ms: u64,
    /// Last applied control nonce.
    pub control_nonce: u64,
    /// Effective pause at the queried block's timestamp.
    pub effective: bool,
}

/// A view call of §5.2.2. Callers must pin related observations to one block.
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

/// A strictly decoded view return value; decoding authenticates no RPC observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewReturnV1 {
    /// Current committee fields, excluding the separately queried latch.
    CommitteeState(CommitteeViewV1),
    /// Immutable deployment pin.
    InitialCommittee(InitialCommitteeViewV1),
    /// Applied pause state.
    PauseState(PauseStateV1),
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
            Self::IsConsumed(value) | Self::CheckpointHeader(value) => {
                encode_call(self.selector(), &[AbiToken::Word(word_u64(*value))])
            }
            Self::TransferNonces(address) => {
                encode_call(self.selector(), &[AbiToken::Word(word_address(address))])
            }
            _ => self.selector().to_vec(),
        }
    }

    /// Strictly decode the return DATA of this call.
    ///
    /// # Errors
    /// Returns [`AbiError::BadLength`], [`AbiError::DirtyWord`] or [`AbiError::BadBool`].
    pub fn decode_return(&self, data: &[u8]) -> Result<ViewReturnV1, AbiError> {
        Ok(match self {
            Self::CommitteeState => {
                ViewReturnV1::CommitteeState(decode_committee_state_return(data)?)
            }
            Self::InitialCommittee => {
                ViewReturnV1::InitialCommittee(decode_initial_committee_return(data)?)
            }
            Self::PauseState => ViewReturnV1::PauseState(decode_pause_state_return(data)?),
            Self::IsConsumed(_) | Self::MintingPaused | Self::Equivocated => {
                ViewReturnV1::Bool(decode_bool_return(data)?)
            }
            Self::RouteRevision => ViewReturnV1::U32(decode_u32_return(data)?),
            Self::TransferNonces(_) | Self::ControlNonce | Self::OpCount | Self::MaxValidityMs => {
                ViewReturnV1::U64(decode_u64_return(data)?)
            }
            Self::MaxWrappedSupply => ViewReturnV1::U128(decode_u128_return(data)?),
            Self::TairaNetworkId | Self::ConsensusInstance | Self::CheckpointHeader(_) => {
                ViewReturnV1::Bytes32(decode_bytes32_return(data)?)
            }
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

/// Decode `committeeState()` in ABI order: root, untilMs, start, high, generation.
///
/// # Errors
/// Returns a length or integer-width error for noncanonical data.
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

/// Canonical `committeeState()` return data.
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

/// Decode `initialCommittee()` in ABI order: generation, root, start, untilMs.
///
/// # Errors
/// Returns a length or integer-width error for noncanonical data.
pub fn decode_initial_committee_return(data: &[u8]) -> Result<InitialCommitteeViewV1, AbiError> {
    if data.len() != 4 * WORD {
        return Err(AbiError::BadLength);
    }
    Ok(InitialCommitteeViewV1 {
        generation: read_u64(data, 0)?,
        root: read_word(data, WORD),
        start: read_u64(data, 2 * WORD)?,
        until_ms: read_u64(data, 3 * WORD)?,
    })
}

/// Canonical `initialCommittee()` return data.
#[must_use]
pub fn encode_initial_committee_return(state: &InitialCommitteeViewV1) -> Vec<u8> {
    encode_tokens(&[
        AbiToken::Word(word_u64(state.generation)),
        AbiToken::Word(state.root),
        AbiToken::Word(word_u64(state.start)),
        AbiToken::Word(word_u64(state.until_ms)),
    ])
}

/// Decode `pauseState()` in ABI order: parliamentPaused, fastPauseUntilMs, controlNonce, effective.
///
/// # Errors
/// Returns a length, integer-width or bool error for noncanonical data.
pub fn decode_pause_state_return(data: &[u8]) -> Result<PauseStateV1, AbiError> {
    if data.len() != 4 * WORD {
        return Err(AbiError::BadLength);
    }
    Ok(PauseStateV1 {
        parliament_paused: read_bool(data, 0)?,
        fast_pause_until_ms: read_u64(data, WORD)?,
        control_nonce: read_u64(data, 2 * WORD)?,
        effective: read_bool(data, 3 * WORD)?,
    })
}

/// Canonical `pauseState()` return data.
#[must_use]
pub fn encode_pause_state_return(state: &PauseStateV1) -> Vec<u8> {
    encode_tokens(&[
        AbiToken::Word(word_bool(state.parliament_paused)),
        AbiToken::Word(word_u64(state.fast_pause_until_ms)),
        AbiToken::Word(word_u64(state.control_nonce)),
        AbiToken::Word(word_bool(state.effective)),
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
mod tests {
    use super::*;
    use crate::v1::{
        destination_abi::{SELECTORS, TOPIC_CONTROL_APPLIED},
        hashes::keccak256,
    };

    const TAIRA: [u8; 32] = [0x11; 32];

    fn word_hex(data: &[u8], index: usize) -> String {
        crate::v1::hashes::to_hex(&data[index * WORD..(index + 1) * WORD])
    }

    // Deliberately arbitrary wire bytes: these tests establish ABI encoding, not BLS validity.
    fn certificate() -> TairaCertificateV1 {
        TairaCertificateV1 {
            qc: vec![0x11; 116],
            header: vec![0x22; 221],
            signature: vec![0x33; 192],
            committee: vec![0x44; 192],
            signer_ys: vec![0x55; 144],
            ton_signature: vec![0x66; 96],
        }
    }

    fn block() -> BlockRefV1 {
        BlockRefV1 {
            height: 3,
            sccp_root: [1; 32],
            message_count: 2,
            history_index: 5,
            history_path: vec![[2; 32], [3; 32], [4; 32]],
        }
    }

    #[test]
    fn token_shapes() {
        assert!(!AbiToken::Word([0; 32]).is_dynamic());
        assert!(AbiToken::Bytes(vec![]).is_dynamic());
        assert!(AbiToken::Array(vec![]).is_dynamic());
        let static_tuple = AbiToken::Tuple(vec![AbiToken::Word([1; 32]); 2]);
        assert!(!static_tuple.is_dynamic());
        assert_eq!(static_tuple.head_len(), 2 * WORD);
        assert_eq!(static_tuple.encode().len(), 2 * WORD);
        let cert = certificate_token(&certificate());
        assert!(cert.is_dynamic());
        assert_eq!(cert.head_len(), WORD);
        assert_eq!(cert.encode().len(), 38 * WORD);
        assert_eq!(block_ref_token(&block()).encode().len(), 9 * WORD);
        assert_eq!(
            checkpoint_ref_token(&CheckpointRefV1 {
                header: vec![9; 221]
            })
            .encode()
            .len(),
            9 * WORD
        );
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 31);
        assert_eq!(padding(32), 0);
        assert_eq!(padding(80), 16);
    }

    #[test]
    fn bytes_and_array_encoding() {
        let encoded = encode_tokens(&[AbiToken::Bytes(vec![0xab; 33])]);
        assert_eq!(encoded.len(), 4 * WORD);
        assert_eq!(word_hex(&encoded, 0), format!("{:064x}", 0x20));
        assert_eq!(word_hex(&encoded, 1), format!("{:064x}", 33));
        assert_eq!(encoded[2 * WORD..2 * WORD + 33], [0xab; 33]);
        assert!(encoded[2 * WORD + 33..].iter().all(|byte| *byte == 0));
        let array = encode_tokens(&[AbiToken::Array(vec![
            AbiToken::Word([1; 32]),
            AbiToken::Word([2; 32]),
        ])]);
        assert_eq!(word_hex(&array, 0), format!("{:064x}", 0x20));
        assert_eq!(word_hex(&array, 1), format!("{:064x}", 2));
        assert_eq!(array[2 * WORD..3 * WORD], [1; 32]);
        // Array of dynamic tuples: offsets relative to the first element head.
        let nested = encode_tokens(&[AbiToken::Array(vec![
            AbiToken::Tuple(vec![AbiToken::Bytes(vec![1])]),
            AbiToken::Tuple(vec![AbiToken::Bytes(vec![2, 3])]),
        ])]);
        assert_eq!(word_hex(&nested, 1), format!("{:064x}", 2));
        assert_eq!(word_hex(&nested, 2), format!("{:064x}", 0x40));
        // First tuple: offset word + length word + one padded data word.
        assert_eq!(word_hex(&nested, 3), format!("{:064x}", 0x40 + 3 * WORD));
        assert_eq!(nested.len(), 4 * WORD + 2 * 3 * WORD);
    }

    #[test]
    fn finalize_calldata_layout() {
        let (certificate, proof, _) = void_fixture();
        let data = finalize_from_taira_calldata(&certificate, &proof);
        assert_eq!(data[..4], SELECTOR_FINALIZE_FROM_TAIRA);
        let args = &data[4..];
        assert_eq!(word_hex(args, 0), format!("{:064x}", 2 * WORD));
        assert_eq!(word_hex(args, 1), format!("{:064x}", 40 * WORD));
        let cert = &args[2 * WORD..40 * WORD];
        // Five byte strings in ABI order; each offset is relative to this tuple.
        let mut tail = 5 * WORD;
        for (i, bytes) in [
            &certificate.qc,
            &certificate.header,
            &certificate.signature,
            &certificate.committee,
            &certificate.signer_ys,
        ]
        .iter()
        .enumerate()
        {
            assert_eq!(read_usize(cert, i * WORD).unwrap(), tail);
            assert_eq!(read_usize(cert, tail).unwrap(), bytes.len());
            assert_eq!(
                &cert[tail + WORD..tail + WORD + bytes.len()],
                bytes.as_slice()
            );
            tail += WORD + bytes.len() + padding(bytes.len());
        }
        assert_eq!(tail, cert.len());
        let msg = &args[40 * WORD..];
        assert_eq!(read_usize(msg, 0), Ok(4 * WORD));
        assert_eq!(read_u64(msg, WORD), Ok(1));
        assert_eq!(read_usize(msg, 2 * WORD), Ok(10 * WORD));
        assert_eq!(read_usize(msg, 3 * WORD), Ok(13 * WORD));
        assert_eq!(msg.len(), 22 * WORD);
        let blk = &msg[13 * WORD..];
        assert_eq!(read_u64(blk, 0), Ok(3));
        assert_eq!(read_word(blk, WORD), [1; 32]);
        assert_eq!(read_u64(blk, 2 * WORD), Ok(2));
        assert_eq!(read_u64(blk, 3 * WORD), Ok(5));
        assert_eq!(read_usize(blk, 4 * WORD), Ok(5 * WORD));
        assert_eq!(read_usize(blk, 5 * WORD), Ok(3));
        // Changing the TON-only signature cannot change EVM calldata.
        let mut other = certificate.clone();
        other.ton_signature.clear();
        assert_eq!(finalize_from_taira_calldata(&other, &proof), data);
    }

    #[test]
    fn every_state_changing_call_uses_its_selector() {
        let (cert, proof, checkpoint) = void_fixture();
        let control = ControlProofV1 {
            control_nonce: 1,
            track: 2,
            parliament_paused: 0,
            fast_pause_until_ms: 99,
            certificate_id: [3; 32],
            effect_hash: [4; 32],
            leaf_index: 0,
            path: vec![],
            block: block(),
        };
        let calls = [
            finalize_from_taira_calldata(&cert, &proof),
            finalize_from_checkpoint_calldata(&checkpoint, &proof),
            submit_checkpoints_calldata(&[cert.clone()]),
            apply_control_calldata(&cert, &control),
            apply_control_from_checkpoint_calldata(&checkpoint, &control),
            void_expired_calldata(9, &cert, &proof),
            void_expired_from_checkpoint_calldata(9, &checkpoint, &proof),
            void_frozen_calldata(4, 2),
            TransferToTairaCallV1 {
                taira_recipient: vec![1],
                token_amount: 5,
                expected_nonce: 0,
            }
            .calldata(),
        ];
        let expected = [
            SELECTOR_FINALIZE_FROM_TAIRA,
            SELECTOR_FINALIZE_FROM_CHECKPOINT,
            SELECTOR_SUBMIT_CHECKPOINTS,
            SELECTOR_APPLY_CONTROL,
            SELECTOR_APPLY_CONTROL_FROM_CHECKPOINT,
            SELECTOR_VOID_EXPIRED,
            SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT,
            SELECTOR_VOID_FROZEN,
            SELECTOR_TRANSFER_TO_TAIRA,
        ];
        for (calldata, selector) in calls.iter().zip(expected) {
            assert_eq!(selector_of(calldata), Ok(selector));
            assert_eq!((calldata.len() - 4) % WORD, 0);
            assert!(SELECTORS.iter().any(|(_, _, known)| *known == selector));
        }
        for (index, from_checkpoint) in [(5, false), (6, true)] {
            assert_eq!(
                VoidCallV1::decode(&calls[index]),
                Ok(VoidCallV1::Expired {
                    nonce: 9,
                    from_checkpoint
                })
            );
        }
        assert_eq!(
            VoidCallV1::decode(&calls[7]),
            Ok(VoidCallV1::Frozen {
                first_nonce: 4,
                count: 2
            })
        );
        assert_eq!(VoidCallV1::decode(&calls[7]).unwrap().range(), (4, 2));
        assert_eq!(VoidCallV1::decode(&calls[5]).unwrap().range(), (9, 1));
        assert_eq!(VoidCallV1::decode(&calls[0]), Err(AbiError::WrongSelector));
        assert_eq!(VoidCallV1::decode(&[0x5b]), Err(AbiError::BadLength));
        let mut long = calls[7].clone();
        long.push(0);
        assert_eq!(VoidCallV1::decode(&long), Err(AbiError::BadLength));
        let mut dirty = calls[5].clone();
        dirty[4] = 1;
        assert_eq!(VoidCallV1::decode(&dirty), Err(AbiError::DirtyWord));
        // All new control fields keep their independent ABI positions, including raw bool.
        let encoded = control_proof_token(&control).encode();
        for (word, value) in [(0, 1), (1, 2), (2, 0), (3, 99), (6, 0)] {
            assert_eq!(read_u64(&encoded, word * WORD), Ok(value));
        }
        assert_eq!(read_word(&encoded, 4 * WORD), [3; 32]);
        assert_eq!(read_word(&encoded, 5 * WORD), [4; 32]);
        let mut malformed = control;
        malformed.parliament_paused = 2;
        assert_eq!(
            read_bool(&control_proof_token(&malformed).encode(), 2 * WORD),
            Err(AbiError::BadBool)
        );
    }

    /// `calldata` with a zero word inserted at argument offset `at`.
    fn with_gap(calldata: &[u8], at: usize) -> Vec<u8> {
        let mut out = calldata[..4 + at].to_vec();
        out.extend_from_slice(&[0; WORD]);
        out.extend_from_slice(&calldata[4 + at..]);
        out
    }

    /// Adds `delta` to the `u64` word at argument offset `at`.
    fn bump(calldata: &mut [u8], at: usize, delta: u64) {
        let low = 4 + at + 24..4 + at + WORD;
        let value = u64::from_be_bytes(calldata[low.clone()].try_into().expect("8 bytes")) + delta;
        calldata[low].copy_from_slice(&value.to_be_bytes());
    }

    fn void_fixture() -> (TairaCertificateV1, MessageProofV1, CheckpointRefV1) {
        let certificate = certificate();
        let checkpoint = CheckpointRefV1 {
            header: certificate.header.clone(),
        };
        let proof = MessageProofV1 {
            payload: vec![0x02; 133],
            leaf_index: 1,
            path: vec![[0x77; 32], [0x88; 32]],
            block: block(),
        };
        (certificate, proof, checkpoint)
    }

    #[test]
    fn abi_shapes_measure_the_canonical_encoding() {
        let fixed = AbiShape::Tuple(&[SHAPE_U64, SHAPE_B32]);
        assert!(!fixed.is_dynamic());
        assert_eq!(fixed.head_len(), 2 * WORD);
        assert_eq!(fixed.canonical_size(&[0; 2 * WORD], 0), Ok(2 * WORD));
        assert!(SHAPE_CERTIFICATE.is_dynamic());
        assert_eq!(SHAPE_CERTIFICATE.head_len(), WORD);
        assert!(AbiShape::Bytes.is_dynamic() && AbiShape::Words.is_dynamic());
        assert!(!SHAPE_U64.is_dynamic());
        let (cert, proof, checkpoint) = void_fixture();
        for (calldata, shapes) in [
            (
                finalize_from_taira_calldata(&cert, &proof),
                [SHAPE_CERTIFICATE, SHAPE_MESSAGE_PROOF],
            ),
            (
                finalize_from_checkpoint_calldata(&checkpoint, &proof),
                [SHAPE_CHECKPOINT, SHAPE_MESSAGE_PROOF],
            ),
        ] {
            assert_eq!(check_canonical_args(&calldata[4..], &shapes), Ok(()));
            assert_eq!(
                canonical_sequence_size(&shapes, &calldata[4..], 0),
                Ok(calldata.len() - 4)
            );
        }
        let checkpoint_call = finalize_from_checkpoint_calldata(&checkpoint, &proof);
        assert_eq!(
            check_canonical_args(
                &checkpoint_call[4..],
                &[SHAPE_CERTIFICATE, SHAPE_MESSAGE_PROOF]
            ),
            Err(AbiError::BadOffset)
        );
        let bytes = encode_tokens(&[AbiToken::Bytes(vec![9; 33])]);
        assert_eq!(AbiShape::Bytes.canonical_size(&bytes, WORD), Ok(3 * WORD));
        assert_eq!(
            AbiShape::Bytes.canonical_size(&bytes[..3 * WORD - 1], WORD),
            Err(AbiError::BadLength)
        );
        let words = encode_tokens(&[path_token(&[[5; 32]; 3])]);
        assert_eq!(AbiShape::Words.canonical_size(&words, WORD), Ok(4 * WORD));
        assert_eq!(
            AbiShape::Words.canonical_size(&words[..4 * WORD - 1], WORD),
            Err(AbiError::BadLength)
        );
        assert_eq!(
            AbiShape::Uint(1).canonical_size(&word_u64(0x100), 0),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(SHAPE_B32.canonical_size(&[0xff; 32], 0), Ok(WORD));
    }

    #[test]
    fn void_expired_decodes_only_the_canonical_encoding() {
        let (cert, proof, _) = void_fixture();
        let canonical = void_expired_calldata(9, &cert, &proof);
        assert_eq!(
            VoidCallV1::decode(&canonical),
            Ok(VoidCallV1::Expired {
                nonce: 9,
                from_checkpoint: false
            })
        );
        let args = &canonical[4..];
        let cert_at = read_usize(args, WORD).unwrap();
        let proof_at = read_usize(args, 2 * WORD).unwrap();
        let path_at = proof_at + read_usize(args, proof_at + 2 * WORD).unwrap();
        let block_at = proof_at + read_usize(args, proof_at + 3 * WORD).unwrap();
        let edit = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut data = canonical.clone();
            change(&mut data);
            VoidCallV1::decode(&data)
        };
        assert_eq!(edit(&|d| d.push(0)), Err(AbiError::BadLength));
        assert_eq!(
            edit(&|d| d.extend_from_slice(&[0; WORD])),
            Err(AbiError::BadLength)
        );
        assert_eq!(
            edit(&|d| {
                d.pop();
            }),
            Err(AbiError::BadLength)
        );
        // Nonce, leaf index, block height/count/history index use their full declared widths.
        for (at, width) in [
            (0, 8),
            (proof_at + WORD, 4),
            (block_at, 8),
            (block_at + 2 * WORD, 4),
            (block_at + 3 * WORD, 8),
        ] {
            assert_eq!(
                edit(&|d| d[4 + at + WORD - width - 1] = 1),
                Err(AbiError::DirtyWord)
            );
        }
        assert_eq!(edit(&|d| d[4 + WORD] = 1), Err(AbiError::BadOffset));
        assert_eq!(
            edit(&|d| {
                *d = with_gap(d, cert_at);
                bump(d, WORD, 32);
                bump(d, 2 * WORD, 32);
            }),
            Err(AbiError::BadOffset)
        );
        // A gap before the first nested byte string, shifting each later sibling.
        assert_eq!(
            edit(&|d| {
                *d = with_gap(d, cert_at + 5 * WORD);
                for i in 0..5 {
                    bump(d, cert_at + i * WORD, 32);
                }
                bump(d, 2 * WORD, 32);
            }),
            Err(AbiError::BadOffset)
        );
        assert_eq!(
            edit(&|d| {
                *d = with_gap(d, path_at);
                bump(d, proof_at + 2 * WORD, 32);
                bump(d, proof_at + 3 * WORD, 32);
            }),
            Err(AbiError::BadOffset)
        );
        let payload_end = proof_at + 5 * WORD + 160;
        assert_eq!(
            edit(&|d| d[4 + payload_end - 1] = 1),
            Err(AbiError::DirtyPadding)
        );
        // QC padding and header padding must also be zero.
        for i in [0, 1, 4] {
            let at = cert_at + read_usize(args, cert_at + i * WORD).unwrap();
            let len = read_usize(args, at).unwrap();
            assert_eq!(
                edit(&|d| d[4 + at + WORD + len] = 1),
                Err(AbiError::DirtyPadding)
            );
        }
        assert!(matches!(
            edit(&|d| bump(d, path_at, 1)),
            Err(AbiError::BadLength | AbiError::BadOffset)
        ));
    }

    #[test]
    fn void_expired_checkpoint_decodes_only_the_canonical_encoding() {
        let (cert, proof, checkpoint) = void_fixture();
        let canonical = void_expired_from_checkpoint_calldata(u64::MAX, &checkpoint, &proof);
        assert_eq!(
            VoidCallV1::decode(&canonical),
            Ok(VoidCallV1::Expired {
                nonce: u64::MAX,
                from_checkpoint: true
            })
        );
        let proof_at = read_usize(&canonical[4..], 2 * WORD).unwrap();
        let block_at = proof_at + read_usize(&canonical[4..], proof_at + 3 * WORD).unwrap();
        let mut dirty = canonical.clone();
        dirty[4 + block_at + 3 * WORD + 23] = 1;
        assert_eq!(VoidCallV1::decode(&dirty), Err(AbiError::DirtyWord));
        let mut gap = with_gap(&canonical, block_at + 5 * WORD);
        bump(&mut gap, block_at + 4 * WORD, 32);
        assert_eq!(VoidCallV1::decode(&gap), Err(AbiError::BadOffset));
        let mut swapped = void_expired_calldata(1, &cert, &proof);
        swapped[..4].copy_from_slice(&SELECTOR_VOID_EXPIRED_FROM_CHECKPOINT);
        assert_eq!(VoidCallV1::decode(&swapped), Err(AbiError::BadOffset));
        let mut inverse = canonical.clone();
        inverse[..4].copy_from_slice(&SELECTOR_VOID_EXPIRED);
        assert_eq!(VoidCallV1::decode(&inverse), Err(AbiError::BadOffset));
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(VoidCallV1::decode(&trailing), Err(AbiError::BadLength));
    }

    /// Every integer at the maximum of its declared width is canonical: a shape narrower than
    /// the Solidity type would refuse a void the destination lets succeed.
    #[test]
    fn void_expired_accepts_every_integer_at_its_full_width() {
        let (cert, mut proof, checkpoint) = void_fixture();
        proof.leaf_index = u32::MAX;
        proof.block.height = u64::MAX;
        proof.block.message_count = u32::MAX;
        proof.block.history_index = u64::MAX;
        for (data, from_checkpoint) in [
            (void_expired_calldata(u64::MAX, &cert, &proof), false),
            (
                void_expired_from_checkpoint_calldata(u64::MAX, &checkpoint, &proof),
                true,
            ),
        ] {
            assert_eq!(
                VoidCallV1::decode(&data),
                Ok(VoidCallV1::Expired {
                    nonce: u64::MAX,
                    from_checkpoint
                })
            );
        }
    }

    #[test]
    fn void_frozen_decodes_only_admitted_ranges() {
        for (first_nonce, count) in [(0, 1), (0, 256), (u64::MAX, 1), (u64::MAX - 255, 256)] {
            assert_eq!(
                VoidCallV1::decode(&void_frozen_calldata(first_nonce, count)),
                Ok(VoidCallV1::Frozen { first_nonce, count })
            );
        }
        for (first_nonce, count) in [(0, 0), (0, 257), (u64::MAX, 2), (u64::MAX - 254, 256)] {
            assert_eq!(
                VoidCallV1::decode(&void_frozen_calldata(first_nonce, count)),
                Err(AbiError::BadVoidRange),
                "{first_nonce} + {count}"
            );
        }
        let canonical = void_frozen_calldata(4, 3);
        let mut dirty_count = canonical.clone();
        dirty_count[4 + WORD + 23] = 1;
        assert_eq!(VoidCallV1::decode(&dirty_count), Err(AbiError::DirtyWord));
        assert_eq!(
            VoidCallV1::decode(&canonical[..canonical.len() - 1]),
            Err(AbiError::BadLength)
        );
        let mut trailing_word = canonical;
        trailing_word.extend_from_slice(&[0; WORD]);
        assert_eq!(VoidCallV1::decode(&trailing_word), Err(AbiError::BadLength));
    }

    #[test]
    fn submit_checkpoints_layout() {
        let cert = certificate();
        let data = submit_checkpoints_calldata(&[cert.clone(), cert.clone()]);
        let args = &data[4..];
        assert_eq!(data[..4], SELECTOR_SUBMIT_CHECKPOINTS);
        assert_eq!(read_usize(args, 0), Ok(WORD));
        assert_eq!(read_usize(args, WORD), Ok(2));
        // Dynamic array element offsets start after the array's length word.
        assert_eq!(read_usize(args, 2 * WORD), Ok(2 * WORD));
        assert_eq!(read_usize(args, 3 * WORD), Ok(40 * WORD));
        assert_eq!(
            &args[4 * WORD..42 * WORD],
            certificate_token(&cert).encode()
        );
        assert_eq!(&args[42 * WORD..], certificate_token(&cert).encode());
        let empty = submit_checkpoints_calldata(&[]);
        assert_eq!(read_usize(&empty[4..], WORD), Ok(0));
    }

    #[test]
    fn transfer_to_taira_canonical_roundtrip_and_negatives() {
        let call = TransferToTairaCallV1 {
            taira_recipient: vec![0xaa; 35],
            token_amount: 1_000_000_000,
            expected_nonce: 7,
        };
        let data = call.calldata();
        assert_eq!(data.len(), TRANSFER_TO_TAIRA_HEAD_BYTES + 64);
        assert_eq!(word_hex(&data[4..], 0), format!("{:064x}", 0x60));
        assert_eq!(TransferToTairaCallV1::decode(&data), Ok(call.clone()));
        let max = TransferToTairaCallV1 {
            taira_recipient: vec![1; 1024],
            token_amount: u128::MAX,
            expected_nonce: u64::MAX,
        };
        assert_eq!(TransferToTairaCallV1::decode(&max.calldata()), Ok(max));

        let mut wrong_selector = data.clone();
        wrong_selector[0] ^= 1;
        assert_eq!(
            TransferToTairaCallV1::decode(&wrong_selector),
            Err(AbiError::WrongSelector)
        );
        let mut bad_offset = data.clone();
        bad_offset[4 + 31] = 0x80;
        assert_eq!(
            TransferToTairaCallV1::decode(&bad_offset),
            Err(AbiError::BadOffset)
        );
        let mut dirty_padding = data.clone();
        let last = dirty_padding.len() - 1;
        dirty_padding[last] = 1;
        assert_eq!(
            TransferToTairaCallV1::decode(&dirty_padding),
            Err(AbiError::DirtyPadding)
        );
        let mut trailing = data.clone();
        trailing.extend_from_slice(&[0; 32]);
        assert_eq!(
            TransferToTairaCallV1::decode(&trailing),
            Err(AbiError::BadLength)
        );
        assert_eq!(
            TransferToTairaCallV1::decode(&data[..data.len() - 1]),
            Err(AbiError::BadLength)
        );
        let empty = TransferToTairaCallV1 {
            taira_recipient: vec![],
            ..call.clone()
        };
        assert_eq!(
            TransferToTairaCallV1::decode(&empty.calldata()),
            Err(AbiError::BadRecipientLength)
        );
        let long = TransferToTairaCallV1 {
            taira_recipient: vec![1; 1025],
            ..call.clone()
        };
        assert_eq!(
            TransferToTairaCallV1::decode(&long.calldata()),
            Err(AbiError::BadRecipientLength)
        );
        let zero = TransferToTairaCallV1 {
            token_amount: 0,
            ..call.clone()
        };
        assert_eq!(
            TransferToTairaCallV1::decode(&zero.calldata()),
            Err(AbiError::BadAmount)
        );
        let mut huge = data.clone();
        huge[4 + WORD + 15] = 1;
        assert_eq!(
            TransferToTairaCallV1::decode(&huge),
            Err(AbiError::DirtyWord)
        );
        let mut dirty_nonce = data;
        dirty_nonce[4 + 2 * WORD + 23] = 1;
        assert_eq!(
            TransferToTairaCallV1::decode(&dirty_nonce),
            Err(AbiError::DirtyWord)
        );
    }

    #[test]
    fn transfer_to_taira_rebuilds_the_inbound_payload() {
        let call = TransferToTairaCallV1 {
            taira_recipient: vec![0xaa; 35],
            token_amount: 1_000_000_000,
            expected_nonce: 7,
        };
        let caller = [0x33; 20];
        let bsc = call
            .inbound_payload(SccpNetworkV1::BscMainnet, 2, &caller)
            .unwrap();
        assert_eq!(bsc.sender.bytes, caller);
        assert_eq!(bsc.nonce, 7);
        assert_eq!(bsc.route_revision, 2);
        assert_eq!(bsc.amount, 1_000_000_000);
        assert_eq!(bsc.route_id, "taira_bsc_xor");
        let eth = call
            .inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &caller)
            .unwrap();
        assert_eq!(eth.sender.bytes, caller);
        assert_eq!(
            call.inbound_payload(SccpNetworkV1::TonMainnet, 1, &caller),
            Err(AbiError::PayloadMismatch)
        );
        assert_eq!(
            call.inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &[0; 20]),
            Err(AbiError::PayloadMismatch)
        );
    }

    #[test]
    fn view_calls_and_returns() {
        assert_eq!(ViewCallV1::ControlNonce.calldata(), SELECTOR_CONTROL_NONCE);
        let consumed = ViewCallV1::IsConsumed(300).calldata();
        assert_eq!(consumed.len(), 36);
        assert_eq!(consumed[..4], SELECTOR_IS_CONSUMED);
        assert_eq!(word_hex(&consumed[4..], 0), format!("{:064x}", 300));
        let nonces = ViewCallV1::TransferNonces([0x44; 20]).calldata();
        assert_eq!(nonces[4..16], [0; 12]);
        assert_eq!(nonces[16..], [0x44; 20]);

        let state = CommitteeViewV1 {
            root: [1; 32],
            generation: 8,
            until_ms: 99,
            start: 4,
            high: 50,
        };
        let encoded = encode_committee_state_return(&state);
        assert_eq!(
            ViewCallV1::CommitteeState.decode_return(&encoded),
            Ok(ViewReturnV1::CommitteeState(state))
        );
        let mut dirty = encoded.clone();
        dirty[WORD] = 1;
        assert_eq!(
            decode_committee_state_return(&dirty),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(
            decode_committee_state_return(&encoded[..4 * WORD]),
            Err(AbiError::BadLength)
        );

        let one = word_u64(1);
        assert_eq!(
            ViewCallV1::MintingPaused.decode_return(&one),
            Ok(ViewReturnV1::Bool(true))
        );
        assert_eq!(
            ViewCallV1::IsConsumed(0).decode_return(&[0; 32]),
            Ok(ViewReturnV1::Bool(false))
        );
        assert_eq!(decode_bool_return(&word_u64(2)), Err(AbiError::BadBool));
        assert_eq!(
            ViewCallV1::RouteRevision.decode_return(&one),
            Ok(ViewReturnV1::U32(1))
        );
        assert_eq!(
            decode_u32_return(&word_u64(1 << 32)),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(
            ViewCallV1::OpCount.decode_return(&one),
            Ok(ViewReturnV1::U64(1))
        );
        assert_eq!(
            ViewCallV1::MaxWrappedSupply.decode_return(&word_u128(u128::MAX)),
            Ok(ViewReturnV1::U128(u128::MAX))
        );
        let mut wide = [0_u8; 32];
        wide[15] = 1;
        assert_eq!(decode_u128_return(&wide), Err(AbiError::DirtyWord));
        assert_eq!(
            ViewCallV1::TairaNetworkId.decode_return(&TAIRA),
            Ok(ViewReturnV1::Bytes32(TAIRA))
        );
        assert_eq!(
            decode_bytes32_return(&TAIRA[..31]),
            Err(AbiError::BadLength)
        );
        assert_eq!(decode_u64_return(&[0; 33]), Err(AbiError::BadLength));
        for call in [
            ViewCallV1::CommitteeState,
            ViewCallV1::TairaNetworkId,
            ViewCallV1::RouteRevision,
            ViewCallV1::MaxWrappedSupply,
            ViewCallV1::MintingPaused,
            ViewCallV1::ControlNonce,
            ViewCallV1::ConsensusInstance,
            ViewCallV1::InitialCommittee,
            ViewCallV1::Equivocated,
            ViewCallV1::PauseState,
            ViewCallV1::OpCount,
            ViewCallV1::MaxValidityMs,
        ] {
            assert_eq!(call.calldata(), call.selector());
        }
    }

    #[test]
    fn native_authority_views_preserve_all_fields_and_reject_dirty_values() {
        let pin = InitialCommitteeViewV1 {
            generation: u64::MAX,
            root: [0xff; 32],
            start: u64::MAX,
            until_ms: u64::MAX,
        };
        let bytes = encode_initial_committee_return(&pin);
        assert_eq!(
            ViewCallV1::InitialCommittee.decode_return(&bytes),
            Ok(ViewReturnV1::InitialCommittee(pin))
        );
        for index in [0, 2, 3] {
            let mut dirty = bytes.clone();
            dirty[index * WORD + 23] = 1;
            assert_eq!(
                decode_initial_committee_return(&dirty),
                Err(AbiError::DirtyWord)
            );
        }
        assert_eq!(
            decode_initial_committee_return(&bytes[..bytes.len() - 1]),
            Err(AbiError::BadLength)
        );
        let pause = PauseStateV1 {
            parliament_paused: false,
            fast_pause_until_ms: u64::MAX,
            control_nonce: u64::MAX,
            effective: true,
        };
        let bytes = encode_pause_state_return(&pause);
        assert_eq!(
            ViewCallV1::PauseState.decode_return(&bytes),
            Ok(ViewReturnV1::PauseState(pause))
        );
        for index in [0, 3] {
            let mut dirty = bytes.clone();
            dirty[index * WORD + WORD - 1] = 2;
            assert_eq!(decode_pause_state_return(&dirty), Err(AbiError::BadBool));
        }
        for index in [1, 2] {
            let mut dirty = bytes.clone();
            dirty[index * WORD + 23] = 1;
            assert_eq!(decode_pause_state_return(&dirty), Err(AbiError::DirtyWord));
        }
        assert_eq!(
            decode_pause_state_return(&bytes[..bytes.len() - 1]),
            Err(AbiError::BadLength)
        );
        let state = CommitteeViewV1 {
            root: [0xff; 32],
            until_ms: u64::MAX,
            start: u64::MAX,
            high: u64::MAX,
            generation: u64::MAX,
        };
        let bytes = encode_committee_state_return(&state);
        assert_eq!(decode_committee_state_return(&bytes), Ok(state));
        for index in 1..5 {
            let mut dirty = bytes.clone();
            dirty[index * WORD + 23] = 1;
            assert_eq!(
                decode_committee_state_return(&dirty),
                Err(AbiError::DirtyWord)
            );
        }
        assert_eq!(
            ViewCallV1::Equivocated.decode_return(&word_bool(true)),
            Ok(ViewReturnV1::Bool(true))
        );
        assert_eq!(
            ViewCallV1::ConsensusInstance.decode_return(&[0x67; 32]),
            Ok(ViewReturnV1::Bytes32([0x67; 32]))
        );
        assert_eq!(
            ViewCallV1::MaxValidityMs.decode_return(&word_u64(u64::MAX)),
            Ok(ViewReturnV1::U64(u64::MAX))
        );
        let lookup = ViewCallV1::CheckpointHeader(u64::MAX);
        assert_eq!(lookup.calldata()[..4], SELECTOR_CHECKPOINT_HEADER);
        assert_eq!(read_u64(&lookup.calldata()[4..], 0), Ok(u64::MAX));
        assert_eq!(
            lookup.decode_return(&[0; 32]),
            Ok(ViewReturnV1::Bytes32([0; 32]))
        );
        assert_eq!(
            lookup.decode_return(&[0x42; 32]),
            Ok(ViewReturnV1::Bytes32([0x42; 32]))
        );
    }

    fn inbound_log() -> (TransferToTairaLogV1, SccpTransferPayloadV1) {
        let sender = [0x33; 20];
        let payload = SccpTransferPayloadV1::inbound(
            SccpNetworkV1::BscMainnet,
            4,
            1,
            77,
            sender.to_vec(),
            vec![9; 40],
        )
        .unwrap();
        let log = TransferToTairaLogV1 {
            message_id: payload.message_id(&TAIRA).unwrap(),
            sender,
            nonce: 4,
            payload: payload.encode().unwrap(),
        };
        (log, payload)
    }

    #[test]
    fn transfer_to_taira_log_roundtrip_and_binding() {
        let (log, payload) = inbound_log();
        let (topics, data) = log.encode();
        assert_eq!(
            topics[0],
            keccak256(&[b"SccpTransferToTaira(bytes32,address,uint64,bytes)"])
        );
        assert_eq!(
            TransferToTairaLogV1::decode(&topics, &data),
            Ok(log.clone())
        );
        assert_eq!(
            log.verified_payload(&TAIRA, SccpNetworkV1::BscMainnet, 1),
            Ok(payload)
        );
        assert_eq!(
            log.verified_payload(&TAIRA, SccpNetworkV1::EthereumMainnet, 1),
            Err(AbiError::PayloadMismatch)
        );
        assert_eq!(
            log.verified_payload(&TAIRA, SccpNetworkV1::BscMainnet, 2),
            Err(AbiError::PayloadMismatch)
        );
        assert_eq!(
            log.verified_payload(&[0x12; 32], SccpNetworkV1::BscMainnet, 1),
            Err(AbiError::PayloadMismatch)
        );
        let wrong_nonce = TransferToTairaLogV1 {
            nonce: 5,
            ..log.clone()
        };
        assert_eq!(
            wrong_nonce.verified_payload(&TAIRA, SccpNetworkV1::BscMainnet, 1),
            Err(AbiError::PayloadMismatch)
        );

        assert_eq!(
            TransferToTairaLogV1::decode(&topics[..2], &data),
            Err(AbiError::WrongTopicCount)
        );
        let mut wrong_topic = topics.clone();
        wrong_topic[0] = TOPIC_CONTROL_APPLIED;
        assert_eq!(
            TransferToTairaLogV1::decode(&wrong_topic, &data),
            Err(AbiError::WrongTopic)
        );
        let mut dirty_sender = topics.clone();
        dirty_sender[2][0] = 0x41;
        assert_eq!(
            TransferToTairaLogV1::decode(&dirty_sender, &data),
            Err(AbiError::DirtyWord)
        );
        let mut bad_offset = data.clone();
        bad_offset[2 * WORD - 1] = 0x60;
        assert_eq!(
            TransferToTairaLogV1::decode(&topics, &bad_offset),
            Err(AbiError::BadOffset)
        );
        let mut trailing = data.clone();
        trailing.extend_from_slice(&[0; 32]);
        assert_eq!(
            TransferToTairaLogV1::decode(&topics, &trailing),
            Err(AbiError::BadLength)
        );
        let mut padded = data.clone();
        let last = padded.len() - 1;
        padded[last] = 1;
        assert_eq!(
            TransferToTairaLogV1::decode(&topics, &padded),
            Err(AbiError::DirtyPadding)
        );
        assert_eq!(
            TransferToTairaLogV1::decode(&topics, &data[..64]),
            Err(AbiError::BadLength)
        );
        let mut huge_length = data.clone();
        huge_length[2 * WORD..3 * WORD].copy_from_slice(&word_u64(u64::MAX));
        assert_eq!(
            TransferToTairaLogV1::decode(&topics, &huge_length),
            Err(AbiError::BadLength)
        );
    }

    #[test]
    fn voided_log_roundtrip() {
        let log = VoidedLogV1 {
            message_id: [7; 32],
            nonce: 12,
        };
        let (topics, data) = log.encode();
        assert_eq!(topics[0], keccak256(&[b"SccpVoided(bytes32,uint64)"]));
        assert!(data.is_empty());
        assert_eq!(VoidedLogV1::decode(&topics, &data), Ok(log));
        assert!(!log.is_frozen());
        let frozen = VoidedLogV1 {
            message_id: [0; 32],
            nonce: 3,
        };
        assert!(frozen.is_frozen());
        assert_eq!(VoidedLogV1::decode(&topics, &[0]), Err(AbiError::BadLength));
        assert_eq!(
            VoidedLogV1::decode(&topics[..1], &data),
            Err(AbiError::WrongTopicCount)
        );
        let mut wrong = topics.clone();
        wrong[0] = TOPIC_TRANSFER_TO_TAIRA;
        assert_eq!(
            VoidedLogV1::decode(&wrong, &data),
            Err(AbiError::WrongTopic)
        );
        let mut dirty = topics;
        dirty[2][0] = 1;
        assert_eq!(VoidedLogV1::decode(&dirty, &data), Err(AbiError::DirtyWord));
    }

    #[test]
    fn evm_helpers() {
        for network in [SccpNetworkV1::EthereumMainnet, SccpNetworkV1::BscMainnet] {
            assert_eq!(evm_account(network, &[1; 20]), Ok(vec![1; 20]));
        }
        for network in [SccpNetworkV1::SoraTaira, SccpNetworkV1::TonMainnet] {
            assert_eq!(
                evm_account(network, &[1; 20]),
                Err(AbiError::PayloadMismatch)
            );
        }
        assert_eq!(selector_of(&[1, 2, 3]), Err(AbiError::BadLength));
        assert_eq!(read_bool(&word_u64(1), 0), Ok(true));
        assert_eq!(read_address(&word_address(&[5; 20]), 0), Ok([5; 20]));
        assert_eq!(checked_word(&[0; 31], 0), Err(AbiError::BadLength));
    }
}
