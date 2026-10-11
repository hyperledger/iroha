//! SCCP v1 EVM ABI (spec §5.1.7, §5.2.2, §4.12.2, §4.16).
//!
//! Standard Solidity ABI encoders for every state-changing entry point of `SccpTairaXor.sol`
//! (`finalizeFromTaira`, `finalizeFromTairaHistorical`, `rotateRosters`, `applyControl`,
//! `applyControlHistorical`, `voidExpired`, `voidExpiredHistorical`, `voidFrozen` and the
//! canonical `transferToTaira`), encoders and strict decoders of the view calls, strict decoders
//! of the `transferToTaira`, `voidExpired*` and `voidFrozen` calldata, and strict encoders and
//! decoders of the `SccpTransferToTaira` and `SccpVoided` logs.
//!
//! The encoders produce exactly the calldata Solidity's own encoder produces: heads in argument
//! order, dynamic values as offsets into the tail relative to the start of their enclosing
//! sequence, `bytes` length-prefixed and zero-padded to 32 bytes. The decoders are strict: they
//! accept only that canonical form (canonical offsets, clean integer words, zero padding and no
//! trailing bytes), which is the only form a destination accepts for those calls (§5.1.7,
//! §5.1.8, §5.2.2).
//!
//! The same calldata runs on ETH and BSC.

use iroha_data_model::bridge::SccpNetworkV1;

use super::{
    constants::{
        MAX_TAIRA_ACCOUNT_BYTES, MAX_VOID_FROZEN_RANGE_EVM, SELECTOR_APPLY_CONTROL,
        SELECTOR_APPLY_CONTROL_HISTORICAL, SELECTOR_CONTROL_NONCE, SELECTOR_DOMAIN_SEPARATOR,
        SELECTOR_FINALIZE_FROM_TAIRA, SELECTOR_FINALIZE_FROM_TAIRA_HISTORICAL,
        SELECTOR_INITIAL_ROSTER_DIGEST, SELECTOR_INITIAL_ROSTER_GENERATION, SELECTOR_IS_CONSUMED,
        SELECTOR_MAX_ROSTER_VALIDITY_MS, SELECTOR_MAX_WRAPPED_SUPPLY, SELECTOR_MINTING_PAUSED,
        SELECTOR_OP_COUNT, SELECTOR_ROSTER_STATE, SELECTOR_ROTATE_ROSTERS, SELECTOR_ROUTE_REVISION,
        SELECTOR_TAIRA_NETWORK_ID, SELECTOR_TRANSFER_NONCES, SELECTOR_TRANSFER_TO_TAIRA,
        SELECTOR_VOID_EXPIRED, SELECTOR_VOID_EXPIRED_HISTORICAL, SELECTOR_VOID_FROZEN,
        TOPIC_TRANSFER_TO_TAIRA, TOPIC_VOIDED,
    },
    eip712::AttestationFieldsV1,
    hashes::{word_address, word_bool, word_u64, word_u128},
    network::external_account_codec,
    payload::SccpTransferPayloadV1,
    proof::{ControlProofV1, HistoryProofV1, MessageProofV1},
    roster::{RosterStateV1, RosterV1},
    signature::SignatureSetV1,
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

/// `RotationV1 { attestation, current, signatures, next }` (§5.2.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RotationV1 {
    /// The rotation attestation (`nextRosterDigest ≠ 0`) signed by `current`.
    pub attestation: AttestationFieldsV1,
    /// The destination's current roster.
    pub current: RosterV1,
    /// At least `t` signatures of `current` over the attestation digest.
    pub signatures: SignatureSetV1,
    /// The successor roster.
    pub next: RosterV1,
}

fn path_token(path: &[[u8; 32]]) -> AbiToken {
    AbiToken::Array(path.iter().copied().map(AbiToken::Word).collect())
}

/// `AttestationV1` (a static tuple of ten words).
#[must_use]
pub fn attestation_token(attestation: &AttestationFieldsV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(attestation.height)),
        AbiToken::Word(word_u64(attestation.epoch)),
        AbiToken::Word(word_u64(attestation.timestamp_ms)),
        AbiToken::Word(attestation.block_hash),
        AbiToken::Word(attestation.sccp_root),
        AbiToken::Word(word_u64(u64::from(attestation.message_count))),
        AbiToken::Word(attestation.history_root),
        AbiToken::Word(word_u64(attestation.history_size)),
        AbiToken::Word(attestation.roster_digest),
        AbiToken::Word(attestation.next_roster_digest),
    ])
}

/// `RosterV1 { generation, validFromMs, validUntilMs, threshold, members }` with
/// `threshold = ⌊2n/3⌋ + 1` and the members packed in their stored order.
#[must_use]
pub fn roster_token(roster: &RosterV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(roster.generation)),
        AbiToken::Word(word_u64(roster.valid_from_ms)),
        AbiToken::Word(word_u64(roster.valid_until_ms)),
        AbiToken::Word(word_usize(roster.threshold())),
        AbiToken::Bytes(roster.packed_members()),
    ])
}

/// `SignaturesV1 { signerBitmap, signatures }`.
#[must_use]
pub fn signatures_token(signatures: &SignatureSetV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(u64::from(signatures.signer_bitmap))),
        AbiToken::Bytes(signatures.signatures.clone()),
    ])
}

/// `MessageProofV1 { payload, leafIndex, path }`.
#[must_use]
pub fn message_proof_token(proof: &MessageProofV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Bytes(proof.payload.clone()),
        AbiToken::Word(word_u64(u64::from(proof.leaf_index))),
        path_token(&proof.path),
    ])
}

/// `HistoryProofV1 { height, sccpRoot, messageCount, leafIndex, path }`.
#[must_use]
pub fn history_proof_token(history: &HistoryProofV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(history.block.height)),
        AbiToken::Word(history.block.sccp_root),
        AbiToken::Word(word_u64(u64::from(history.block.message_count))),
        AbiToken::Word(word_u64(history.leaf_index)),
        path_token(&history.path),
    ])
}

/// `ControlProofV1 { controlNonce, paused, leafIndex, path }`.
#[must_use]
pub fn control_proof_token(control: &ControlProofV1) -> AbiToken {
    AbiToken::Tuple(vec![
        AbiToken::Word(word_u64(control.control_nonce)),
        AbiToken::Word(word_bool(control.paused)),
        AbiToken::Word(word_u64(u64::from(control.leaf_index))),
        path_token(&control.path),
    ])
}

/// `RotationV1 { attestation, current, signatures, next }`.
#[must_use]
pub fn rotation_token(rotation: &RotationV1) -> AbiToken {
    AbiToken::Tuple(vec![
        attestation_token(&rotation.attestation),
        roster_token(&rotation.current),
        signatures_token(&rotation.signatures),
        roster_token(&rotation.next),
    ])
}

// ---------------------------------------------------------------------------------------------
// State-changing calls
// ---------------------------------------------------------------------------------------------

/// An attestation with the roster that signed it and its signature set: the common prefix of
/// every finalize, control and `voidExpired*` call.
#[derive(Debug, Clone, Copy)]
pub struct AttestedV1<'a> {
    /// The attestation.
    pub attestation: &'a AttestationFieldsV1,
    /// The accepted roster named by `attestation.rosterDigest`.
    pub roster: &'a RosterV1,
    /// At least `t` signatures of `roster` over the attestation digest.
    pub signatures: &'a SignatureSetV1,
}

impl AttestedV1<'_> {
    fn tokens(&self) -> [AbiToken; 3] {
        [
            attestation_token(self.attestation),
            roster_token(self.roster),
            signatures_token(self.signatures),
        ]
    }
}

/// `finalizeFromTaira(AttestationV1,RosterV1,SignaturesV1,MessageProofV1)` (`0x8056d161`).
#[must_use]
pub fn finalize_from_taira_calldata(attested: AttestedV1<'_>, proof: &MessageProofV1) -> Vec<u8> {
    let [attestation, roster, signatures] = attested.tokens();
    encode_call(
        SELECTOR_FINALIZE_FROM_TAIRA,
        &[attestation, roster, signatures, message_proof_token(proof)],
    )
}

/// `finalizeFromTairaHistorical(AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,MessageProofV1)`
/// (`0x96925736`).
#[must_use]
pub fn finalize_from_taira_historical_calldata(
    attested: AttestedV1<'_>,
    history: &HistoryProofV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    let [attestation, roster, signatures] = attested.tokens();
    encode_call(
        SELECTOR_FINALIZE_FROM_TAIRA_HISTORICAL,
        &[
            attestation,
            roster,
            signatures,
            history_proof_token(history),
            message_proof_token(proof),
        ],
    )
}

/// `rotateRosters(RotationV1[])` (`0x909ea456`).
#[must_use]
pub fn rotate_rosters_calldata(rotations: &[RotationV1]) -> Vec<u8> {
    encode_call(
        SELECTOR_ROTATE_ROSTERS,
        &[AbiToken::Array(
            rotations.iter().map(rotation_token).collect(),
        )],
    )
}

/// `applyControl(AttestationV1,RosterV1,SignaturesV1,ControlProofV1)` (`0x0ce970d6`).
#[must_use]
pub fn apply_control_calldata(attested: AttestedV1<'_>, control: &ControlProofV1) -> Vec<u8> {
    let [attestation, roster, signatures] = attested.tokens();
    encode_call(
        SELECTOR_APPLY_CONTROL,
        &[
            attestation,
            roster,
            signatures,
            control_proof_token(control),
        ],
    )
}

/// `applyControlHistorical(AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,ControlProofV1)`
/// (`0x935a913b`).
#[must_use]
pub fn apply_control_historical_calldata(
    attested: AttestedV1<'_>,
    history: &HistoryProofV1,
    control: &ControlProofV1,
) -> Vec<u8> {
    let [attestation, roster, signatures] = attested.tokens();
    encode_call(
        SELECTOR_APPLY_CONTROL_HISTORICAL,
        &[
            attestation,
            roster,
            signatures,
            history_proof_token(history),
            control_proof_token(control),
        ],
    )
}

/// `voidExpired(uint64,AttestationV1,RosterV1,SignaturesV1,MessageProofV1)` (`0xc3de98ad`).
#[must_use]
pub fn void_expired_calldata(
    nonce: u64,
    attested: AttestedV1<'_>,
    proof: &MessageProofV1,
) -> Vec<u8> {
    let [attestation, roster, signatures] = attested.tokens();
    encode_call(
        SELECTOR_VOID_EXPIRED,
        &[
            AbiToken::Word(word_u64(nonce)),
            attestation,
            roster,
            signatures,
            message_proof_token(proof),
        ],
    )
}

/// `voidExpiredHistorical(uint64,AttestationV1,RosterV1,SignaturesV1,HistoryProofV1,MessageProofV1)`
/// (`0xbe335b84`).
#[must_use]
pub fn void_expired_historical_calldata(
    nonce: u64,
    attested: AttestedV1<'_>,
    history: &HistoryProofV1,
    proof: &MessageProofV1,
) -> Vec<u8> {
    let [attestation, roster, signatures] = attested.tokens();
    encode_call(
        SELECTOR_VOID_EXPIRED_HISTORICAL,
        &[
            AbiToken::Word(word_u64(nonce)),
            attestation,
            roster,
            signatures,
            history_proof_token(history),
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

const SHAPE_U8: AbiShape = AbiShape::Uint(1);
const SHAPE_U32: AbiShape = AbiShape::Uint(4);
const SHAPE_U64: AbiShape = AbiShape::Uint(8);
const SHAPE_B32: AbiShape = AbiShape::Uint(WORD);
/// `AttestationV1` (§5.2.2).
const SHAPE_ATTESTATION: AbiShape = AbiShape::Tuple(&[
    SHAPE_U64, SHAPE_U64, SHAPE_U64, SHAPE_B32, SHAPE_B32, SHAPE_U32, SHAPE_B32, SHAPE_U64,
    SHAPE_B32, SHAPE_B32,
]);
/// `RosterV1`.
const SHAPE_ROSTER: AbiShape =
    AbiShape::Tuple(&[SHAPE_U64, SHAPE_U64, SHAPE_U64, SHAPE_U8, AbiShape::Bytes]);
/// `SignaturesV1`.
const SHAPE_SIGNATURES: AbiShape = AbiShape::Tuple(&[SHAPE_U32, AbiShape::Bytes]);
/// `MessageProofV1`.
const SHAPE_MESSAGE_PROOF: AbiShape =
    AbiShape::Tuple(&[AbiShape::Bytes, SHAPE_U32, AbiShape::Words]);
/// `HistoryProofV1`.
const SHAPE_HISTORY_PROOF: AbiShape =
    AbiShape::Tuple(&[SHAPE_U64, SHAPE_B32, SHAPE_U32, SHAPE_U64, AbiShape::Words]);
/// Arguments of `voidExpired`.
const VOID_EXPIRED_ARGS: &[AbiShape] = &[
    SHAPE_U64,
    SHAPE_ATTESTATION,
    SHAPE_ROSTER,
    SHAPE_SIGNATURES,
    SHAPE_MESSAGE_PROOF,
];
/// Arguments of `voidExpiredHistorical`.
const VOID_EXPIRED_HISTORICAL_ARGS: &[AbiShape] = &[
    SHAPE_U64,
    SHAPE_ATTESTATION,
    SHAPE_ROSTER,
    SHAPE_SIGNATURES,
    SHAPE_HISTORY_PROOF,
    SHAPE_MESSAGE_PROOF,
];
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
/// trailing bytes. `SccpTairaXor` reverts with `NonCanonicalCalldata` (or in the ABI decoder) on
/// every other encoding of a void (§5.1.8, §5.2.2), so this is exactly its accepted set.
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
    /// `voidExpired` or `voidExpiredHistorical` of one nonce (the first static head word).
    Expired {
        /// The voided nonce.
        nonce: u64,
        /// Whether the historical variant was called.
        historical: bool,
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
    /// `voidExpired`, `voidExpiredHistorical` or `voidFrozen` (canonical offsets, integer words
    /// within their widths, zero `bytes` padding, no trailing bytes), and a `voidFrozen` range
    /// must hold 1..=256 nonces ending at most at `2^64 - 1`. The destination reverts on every
    /// other call (§5.1.8), so this is exactly the set of successful void calls Taira can see.
    ///
    /// # Errors
    ///
    /// Returns [`AbiError::WrongSelector`] for any other function, [`AbiError::BadVoidRange`]
    /// for an out-of-range `voidFrozen`, or the first violated encoding rule.
    pub fn decode(calldata: &[u8]) -> Result<Self, AbiError> {
        let selector = selector_of(calldata)?;
        let args = &calldata[4..];
        let historical = match selector {
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
            SELECTOR_VOID_EXPIRED_HISTORICAL => true,
            _ => return Err(AbiError::WrongSelector),
        };
        let members = if historical {
            VOID_EXPIRED_HISTORICAL_ARGS
        } else {
            VOID_EXPIRED_ARGS
        };
        check_canonical_args(args, members)?;
        Ok(Self::Expired {
            nonce: read_u64(args, 0)?,
            historical,
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

/// A view call of §5.2.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewCallV1 {
    /// `rosterState()`.
    RosterState,
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
    /// `domainSeparator()`.
    DomainSeparator,
    /// `initialRosterDigest()`.
    InitialRosterDigest,
    /// `initialRosterGeneration()`.
    InitialRosterGeneration,
    /// `opCount()`.
    OpCount,
    /// `maxRosterValidityMs()`.
    MaxRosterValidityMs,
}

/// A strictly decoded view return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewReturnV1 {
    /// `rosterState()`.
    RosterState(RosterStateV1),
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
            Self::RosterState => SELECTOR_ROSTER_STATE,
            Self::IsConsumed(_) => SELECTOR_IS_CONSUMED,
            Self::TransferNonces(_) => SELECTOR_TRANSFER_NONCES,
            Self::TairaNetworkId => SELECTOR_TAIRA_NETWORK_ID,
            Self::RouteRevision => SELECTOR_ROUTE_REVISION,
            Self::MaxWrappedSupply => SELECTOR_MAX_WRAPPED_SUPPLY,
            Self::MintingPaused => SELECTOR_MINTING_PAUSED,
            Self::ControlNonce => SELECTOR_CONTROL_NONCE,
            Self::DomainSeparator => SELECTOR_DOMAIN_SEPARATOR,
            Self::InitialRosterDigest => SELECTOR_INITIAL_ROSTER_DIGEST,
            Self::InitialRosterGeneration => SELECTOR_INITIAL_ROSTER_GENERATION,
            Self::OpCount => SELECTOR_OP_COUNT,
            Self::MaxRosterValidityMs => SELECTOR_MAX_ROSTER_VALIDITY_MS,
        }
    }

    /// The `eth_call` data.
    #[must_use]
    pub fn calldata(&self) -> Vec<u8> {
        match self {
            Self::IsConsumed(nonce) => {
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
    ///
    /// Returns [`AbiError::BadLength`], [`AbiError::DirtyWord`] or [`AbiError::BadBool`].
    pub fn decode_return(&self, data: &[u8]) -> Result<ViewReturnV1, AbiError> {
        Ok(match self {
            Self::RosterState => ViewReturnV1::RosterState(decode_roster_state_return(data)?),
            Self::IsConsumed(_) | Self::MintingPaused => {
                ViewReturnV1::Bool(decode_bool_return(data)?)
            }
            Self::RouteRevision => ViewReturnV1::U32(decode_u32_return(data)?),
            Self::TransferNonces(_)
            | Self::ControlNonce
            | Self::InitialRosterGeneration
            | Self::OpCount
            | Self::MaxRosterValidityMs => ViewReturnV1::U64(decode_u64_return(data)?),
            Self::MaxWrappedSupply => ViewReturnV1::U128(decode_u128_return(data)?),
            Self::TairaNetworkId | Self::DomainSeparator | Self::InitialRosterDigest => {
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

/// Decode `rosterState()`:
/// `(bytes32 digest, uint64 generation, uint64 validUntilMs, bytes32 prevDigest,
/// uint64 prevValidUntilMs)`.
///
/// # Errors
///
/// Returns [`AbiError::BadLength`] or [`AbiError::DirtyWord`].
pub fn decode_roster_state_return(data: &[u8]) -> Result<RosterStateV1, AbiError> {
    if data.len() != 5 * WORD {
        return Err(AbiError::BadLength);
    }
    Ok(RosterStateV1 {
        digest: read_word(data, 0),
        generation: read_u64(data, WORD)?,
        valid_until_ms: read_u64(data, 2 * WORD)?,
        prev_digest: read_word(data, 3 * WORD),
        prev_valid_until_ms: read_u64(data, 4 * WORD)?,
    })
}

/// The canonical return data of `rosterState()` (for tests and fixtures).
#[must_use]
pub fn encode_roster_state_return(state: &RosterStateV1) -> Vec<u8> {
    encode_tokens(&[
        AbiToken::Word(state.digest),
        AbiToken::Word(word_u64(state.generation)),
        AbiToken::Word(word_u64(state.valid_until_ms)),
        AbiToken::Word(state.prev_digest),
        AbiToken::Word(word_u64(state.prev_valid_until_ms)),
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
        constants::{SELECTORS, TOPIC_CONTROL_APPLIED},
        hashes::keccak256,
        proof::HistoryBlockV1,
    };

    const TAIRA: [u8; 32] = [0x11; 32];

    fn word_hex(data: &[u8], index: usize) -> String {
        crate::v1::hashes::to_hex(&data[index * WORD..(index + 1) * WORD])
    }

    fn roster() -> RosterV1 {
        RosterV1 {
            generation: 7,
            valid_from_ms: 1_800_000_000_000,
            valid_until_ms: 1_801_209_600_000,
            members: (1..=4).map(|byte| [byte; 20]).collect(),
        }
    }

    fn attestation() -> AttestationFieldsV1 {
        AttestationFieldsV1 {
            height: 10,
            epoch: 1,
            timestamp_ms: 1_800_000_100_000,
            block_hash: [0xb1; 32],
            sccp_root: [0xc2; 32],
            message_count: 3,
            history_root: [0xd3; 32],
            history_size: 2,
            roster_digest: [0xe4; 32],
            next_roster_digest: [0; 32],
        }
    }

    fn signatures() -> SignatureSetV1 {
        SignatureSetV1 {
            signer_bitmap: 0b0111,
            signatures: vec![0x5a; 3 * 65],
        }
    }

    #[test]
    fn token_shapes() {
        assert!(!AbiToken::Word([0; 32]).is_dynamic());
        assert!(AbiToken::Bytes(vec![]).is_dynamic());
        assert!(AbiToken::Array(vec![]).is_dynamic());
        let attestation = attestation_token(&attestation());
        assert!(!attestation.is_dynamic());
        assert_eq!(attestation.head_len(), 10 * WORD);
        assert_eq!(attestation.encode().len(), 10 * WORD);
        let roster = roster_token(&roster());
        assert!(roster.is_dynamic());
        assert_eq!(roster.head_len(), WORD);
        // 4 static words, offset, length, 80 member bytes padded to 96.
        assert_eq!(roster.encode().len(), 6 * WORD + 96);
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
        let proof = MessageProofV1 {
            payload: vec![0x02; 100],
            leaf_index: 1,
            path: vec![[0x77; 32], [0x88; 32]],
        };
        let roster = roster();
        let attestation = attestation();
        let signatures = signatures();
        let attested = AttestedV1 {
            attestation: &attestation,
            roster: &roster,
            signatures: &signatures,
        };
        let data = finalize_from_taira_calldata(attested, &proof);
        assert_eq!(data[..4], SELECTOR_FINALIZE_FROM_TAIRA);
        let args = &data[4..];
        // Head: 10 attestation words, then three offsets.
        assert_eq!(word_hex(args, 0), format!("{:064x}", 10));
        assert_eq!(args[3 * WORD..4 * WORD], [0xb1; 32]);
        let roster_offset = 13 * WORD;
        assert_eq!(word_hex(args, 10), format!("{roster_offset:064x}"));
        let roster_len = 6 * WORD + 96;
        assert_eq!(
            word_hex(args, 11),
            format!("{:064x}", roster_offset + roster_len)
        );
        let signatures_len = 3 * WORD + 224; // bitmap, offset, length, 195 bytes padded to 224
        assert_eq!(
            word_hex(args, 12),
            format!("{:064x}", roster_offset + roster_len + signatures_len)
        );
        // Roster tuple: generation, from, until, threshold 3, offset 0xa0, length 80.
        let roster_words = &args[roster_offset..];
        assert_eq!(word_hex(roster_words, 0), format!("{:064x}", 7));
        assert_eq!(word_hex(roster_words, 3), format!("{:064x}", 3));
        assert_eq!(word_hex(roster_words, 4), format!("{:064x}", 5 * WORD));
        assert_eq!(word_hex(roster_words, 5), format!("{:064x}", 80));
        // Message proof: offset 0x60 to payload, leaf index, offset to path.
        let proof_words = &args[roster_offset + roster_len + signatures_len..];
        assert_eq!(word_hex(proof_words, 0), format!("{:064x}", 3 * WORD));
        assert_eq!(word_hex(proof_words, 1), format!("{:064x}", 1));
        assert_eq!(
            word_hex(proof_words, 2),
            format!("{:064x}", 3 * WORD + WORD + 128)
        );
        assert_eq!(proof_words.len(), 3 * WORD + WORD + 128 + 3 * WORD);
    }

    #[test]
    fn every_state_changing_call_uses_its_selector() {
        let roster = roster();
        let attestation = attestation();
        let signatures = signatures();
        let attested = AttestedV1 {
            attestation: &attestation,
            roster: &roster,
            signatures: &signatures,
        };
        let proof = MessageProofV1::default();
        let history = HistoryProofV1 {
            block: HistoryBlockV1 {
                height: 3,
                sccp_root: [1; 32],
                message_count: 1,
            },
            leaf_index: 0,
            path: vec![[2; 32]],
        };
        let control = ControlProofV1 {
            control_nonce: 1,
            paused: true,
            leaf_index: 0,
            path: vec![],
        };
        let rotation = RotationV1 {
            attestation,
            current: roster.clone(),
            signatures: signatures.clone(),
            next: roster.clone(),
        };
        let calls = [
            finalize_from_taira_calldata(attested, &proof),
            finalize_from_taira_historical_calldata(attested, &history, &proof),
            rotate_rosters_calldata(&[rotation]),
            apply_control_calldata(attested, &control),
            apply_control_historical_calldata(attested, &history, &control),
            void_expired_calldata(9, attested, &proof),
            void_expired_historical_calldata(9, attested, &history, &proof),
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
            SELECTOR_FINALIZE_FROM_TAIRA_HISTORICAL,
            SELECTOR_ROTATE_ROSTERS,
            SELECTOR_APPLY_CONTROL,
            SELECTOR_APPLY_CONTROL_HISTORICAL,
            SELECTOR_VOID_EXPIRED,
            SELECTOR_VOID_EXPIRED_HISTORICAL,
            SELECTOR_VOID_FROZEN,
            SELECTOR_TRANSFER_TO_TAIRA,
        ];
        for (calldata, selector) in calls.iter().zip(expected) {
            assert_eq!(selector_of(calldata), Ok(selector));
            assert_eq!((calldata.len() - 4) % WORD, 0);
            assert!(SELECTORS.iter().any(|(_, _, known)| *known == selector));
        }
        assert_eq!(
            VoidCallV1::decode(&calls[5]),
            Ok(VoidCallV1::Expired {
                nonce: 9,
                historical: false
            })
        );
        assert_eq!(
            VoidCallV1::decode(&calls[6]),
            Ok(VoidCallV1::Expired {
                nonce: 9,
                historical: true
            })
        );
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
        let mut long_frozen = calls[7].clone();
        long_frozen.push(0);
        assert_eq!(VoidCallV1::decode(&long_frozen), Err(AbiError::BadLength));
        let mut dirty_nonce = calls[5].clone();
        dirty_nonce[4] = 1;
        assert_eq!(VoidCallV1::decode(&dirty_nonce), Err(AbiError::DirtyWord));
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

    fn void_fixture() -> (
        RosterV1,
        AttestationFieldsV1,
        SignatureSetV1,
        MessageProofV1,
        HistoryProofV1,
    ) {
        let proof = MessageProofV1 {
            payload: vec![0x02; 133],
            leaf_index: 1,
            path: vec![[0x77; 32], [0x88; 32]],
        };
        let history = HistoryProofV1 {
            block: HistoryBlockV1 {
                height: 3,
                sccp_root: [1; 32],
                message_count: 2,
            },
            leaf_index: 5,
            path: vec![[2; 32], [3; 32], [4; 32]],
        };
        (roster(), attestation(), signatures(), proof, history)
    }

    #[test]
    fn abi_shapes_measure_the_canonical_encoding() {
        assert!(!SHAPE_ATTESTATION.is_dynamic());
        assert_eq!(SHAPE_ATTESTATION.head_len(), 10 * WORD);
        assert!(SHAPE_ROSTER.is_dynamic());
        assert_eq!(SHAPE_ROSTER.head_len(), WORD);
        assert!(AbiShape::Bytes.is_dynamic() && AbiShape::Words.is_dynamic());
        assert!(!SHAPE_U64.is_dynamic());
        let (roster, attestation, signatures, proof, history) = void_fixture();
        let attested = AttestedV1 {
            attestation: &attestation,
            roster: &roster,
            signatures: &signatures,
        };
        // The same shapes measure the finalize calls, which share every argument struct.
        let direct = finalize_from_taira_calldata(attested, &proof);
        let direct_args = [
            SHAPE_ATTESTATION,
            SHAPE_ROSTER,
            SHAPE_SIGNATURES,
            SHAPE_MESSAGE_PROOF,
        ];
        assert_eq!(check_canonical_args(&direct[4..], &direct_args), Ok(()));
        assert_eq!(
            canonical_sequence_size(&direct_args, &direct[4..], 0),
            Ok(direct.len() - 4)
        );
        let historical = finalize_from_taira_historical_calldata(attested, &history, &proof);
        let historical_args = [
            SHAPE_ATTESTATION,
            SHAPE_ROSTER,
            SHAPE_SIGNATURES,
            SHAPE_HISTORY_PROOF,
            SHAPE_MESSAGE_PROOF,
        ];
        assert_eq!(
            check_canonical_args(&historical[4..], &historical_args),
            Ok(())
        );
        assert_eq!(
            check_canonical_args(&historical[4..], &direct_args),
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
            SHAPE_U8.canonical_size(&word_u64(0x100), 0),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(SHAPE_B32.canonical_size(&[0xff; 32], 0), Ok(WORD));
    }

    #[test]
    fn void_expired_decodes_only_the_canonical_encoding() {
        let (roster, attestation, signatures, proof, _) = void_fixture();
        let attested = AttestedV1 {
            attestation: &attestation,
            roster: &roster,
            signatures: &signatures,
        };
        let canonical = void_expired_calldata(9, attested, &proof);
        let expired = Ok(VoidCallV1::Expired {
            nonce: 9,
            historical: false,
        });
        assert_eq!(VoidCallV1::decode(&canonical), expired);
        let args = &canonical[4..];
        let roster_at = read_usize(args, 11 * WORD).expect("roster offset");
        let proof_at = read_usize(args, 13 * WORD).expect("proof offset");
        let path_at = proof_at + read_usize(args, proof_at + 2 * WORD).expect("path offset");
        let edit = |change: &dyn Fn(&mut Vec<u8>)| {
            let mut calldata = canonical.clone();
            change(&mut calldata);
            VoidCallV1::decode(&calldata)
        };
        assert_eq!(edit(&|data| data.push(0)), Err(AbiError::BadLength));
        assert_eq!(
            edit(&|data| data.extend_from_slice(&[0; WORD])),
            Err(AbiError::BadLength)
        );
        assert_eq!(
            edit(&|data| {
                data.pop();
            }),
            Err(AbiError::BadLength)
        );
        // Attestation height (uint64), messageCount (uint32), roster threshold (uint8) and the
        // message leaf index (uint32) with one bit above their width.
        assert_eq!(
            edit(&|data| data[4 + WORD + 23] = 1),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(
            edit(&|data| data[4 + 6 * WORD + 27] = 1),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(
            edit(&|data| data[4 + roster_at + 3 * WORD + 30] = 1),
            Err(AbiError::DirtyWord)
        );
        assert_eq!(
            edit(&|data| data[4 + proof_at + WORD + 27] = 1),
            Err(AbiError::DirtyWord)
        );
        // Offsets: high bits, and a zero word inserted before the roster tail, before the
        // members bytes and before the path, with every enclosing offset moved accordingly.
        // Solidity's own decoder reads each of these as the same arguments.
        assert_eq!(
            edit(&|data| data[4 + 11 * WORD] = 1),
            Err(AbiError::BadOffset)
        );
        assert_eq!(
            edit(&|data| {
                *data = with_gap(data, roster_at);
                for head in 11..14 {
                    bump(data, head * WORD, 0x20);
                }
            }),
            Err(AbiError::BadOffset)
        );
        assert_eq!(
            edit(&|data| {
                *data = with_gap(data, roster_at + 5 * WORD);
                bump(data, roster_at + 4 * WORD, 0x20);
                bump(data, 12 * WORD, 0x20);
                bump(data, 13 * WORD, 0x20);
            }),
            Err(AbiError::BadOffset)
        );
        assert_eq!(
            edit(&|data| {
                *data = with_gap(data, path_at);
                bump(data, proof_at + 2 * WORD, 0x20);
            }),
            Err(AbiError::BadOffset)
        );
        // Nonzero payload padding (133 bytes padded to 160) and a path count past the data.
        let payload_end = proof_at + 4 * WORD + 160;
        assert_eq!(
            edit(&|data| data[4 + payload_end - 1] = 1),
            Err(AbiError::DirtyPadding)
        );
        assert_eq!(
            edit(&|data| bump(data, path_at, 1)),
            Err(AbiError::BadLength)
        );
    }

    #[test]
    fn void_expired_historical_decodes_only_the_canonical_encoding() {
        let (roster, attestation, signatures, proof, history) = void_fixture();
        let attested = AttestedV1 {
            attestation: &attestation,
            roster: &roster,
            signatures: &signatures,
        };
        let canonical = void_expired_historical_calldata(u64::MAX, attested, &history, &proof);
        assert_eq!(
            VoidCallV1::decode(&canonical),
            Ok(VoidCallV1::Expired {
                nonce: u64::MAX,
                historical: true,
            })
        );
        let history_at = read_usize(&canonical[4..], 13 * WORD).expect("history offset");
        let mut dirty_leaf_index = canonical.clone();
        dirty_leaf_index[4 + history_at + 3 * WORD + 23] = 1;
        assert_eq!(
            VoidCallV1::decode(&dirty_leaf_index),
            Err(AbiError::DirtyWord)
        );
        let mut gap = with_gap(&canonical, history_at + 5 * WORD);
        bump(&mut gap, history_at + 4 * WORD, 0x20);
        bump(&mut gap, 14 * WORD, 0x20);
        assert_eq!(VoidCallV1::decode(&gap), Err(AbiError::BadOffset));
        // The direct layout is not a historical encoding and vice versa.
        let mut swapped = void_expired_calldata(1, attested, &proof);
        swapped[..4].copy_from_slice(&SELECTOR_VOID_EXPIRED_HISTORICAL);
        assert_eq!(VoidCallV1::decode(&swapped), Err(AbiError::BadOffset));
        let mut trailing = canonical;
        trailing.push(0);
        assert_eq!(VoidCallV1::decode(&trailing), Err(AbiError::BadLength));
    }

    /// Every integer at the maximum of its declared width is canonical: a shape narrower than
    /// the Solidity type would refuse a void the destination lets succeed.
    #[test]
    fn void_expired_accepts_every_integer_at_its_full_width() {
        let (mut roster, mut attestation, mut signatures, mut proof, mut history) = void_fixture();
        attestation.height = u64::MAX;
        attestation.epoch = u64::MAX;
        attestation.timestamp_ms = u64::MAX;
        attestation.message_count = u32::MAX;
        attestation.history_size = u64::MAX;
        roster.generation = u64::MAX;
        roster.valid_from_ms = u64::MAX;
        roster.valid_until_ms = u64::MAX;
        signatures.signer_bitmap = u32::MAX;
        proof.leaf_index = u32::MAX;
        history.block.height = u64::MAX;
        history.block.message_count = u32::MAX;
        history.leaf_index = u64::MAX;
        let attested = AttestedV1 {
            attestation: &attestation,
            roster: &roster,
            signatures: &signatures,
        };
        // The encoder derives the `uint8` threshold from n, so its low byte is set directly.
        let max_threshold = |mut calldata: Vec<u8>| {
            let roster_at = read_usize(&calldata[4..], 11 * WORD).expect("roster offset");
            calldata[4 + roster_at + 4 * WORD - 1] = 0xff;
            calldata
        };
        let direct = max_threshold(void_expired_calldata(u64::MAX, attested, &proof));
        assert_eq!(
            VoidCallV1::decode(&direct),
            Ok(VoidCallV1::Expired {
                nonce: u64::MAX,
                historical: false,
            })
        );
        let historical = max_threshold(void_expired_historical_calldata(
            u64::MAX,
            attested,
            &history,
            &proof,
        ));
        assert_eq!(
            VoidCallV1::decode(&historical),
            Ok(VoidCallV1::Expired {
                nonce: u64::MAX,
                historical: true,
            })
        );
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
    fn rotate_rosters_layout() {
        let roster = roster();
        let rotation = RotationV1 {
            attestation: attestation(),
            current: roster.clone(),
            signatures: signatures(),
            next: roster,
        };
        let data = rotate_rosters_calldata(&[rotation.clone(), rotation]);
        let args = &data[4..];
        assert_eq!(word_hex(args, 0), format!("{:064x}", 0x20));
        assert_eq!(word_hex(args, 1), format!("{:064x}", 2));
        assert_eq!(word_hex(args, 2), format!("{:064x}", 0x40));
        let rotation_len = 13 * WORD + 2 * (6 * WORD + 96) + (3 * WORD + 224);
        assert_eq!(word_hex(args, 3), format!("{:064x}", 0x40 + rotation_len));
        assert_eq!(args.len(), 4 * WORD + 2 * rotation_len);
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

        let state = RosterStateV1 {
            digest: [1; 32],
            generation: 8,
            valid_until_ms: 99,
            prev_digest: [2; 32],
            prev_valid_until_ms: 50,
        };
        let encoded = encode_roster_state_return(&state);
        assert_eq!(
            ViewCallV1::RosterState.decode_return(&encoded),
            Ok(ViewReturnV1::RosterState(state))
        );
        let mut dirty = encoded.clone();
        dirty[WORD] = 1;
        assert_eq!(decode_roster_state_return(&dirty), Err(AbiError::DirtyWord));
        assert_eq!(
            decode_roster_state_return(&encoded[..4 * WORD]),
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
            ViewCallV1::RosterState,
            ViewCallV1::TairaNetworkId,
            ViewCallV1::RouteRevision,
            ViewCallV1::MaxWrappedSupply,
            ViewCallV1::MintingPaused,
            ViewCallV1::ControlNonce,
            ViewCallV1::DomainSeparator,
            ViewCallV1::InitialRosterDigest,
            ViewCallV1::InitialRosterGeneration,
            ViewCallV1::OpCount,
            ViewCallV1::MaxRosterValidityMs,
        ] {
            assert_eq!(call.calldata(), call.selector());
        }
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
