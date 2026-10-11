//! TON destination encodings (spec §5.3.2, §5.3.3, §7.1, §7.2).
//!
//! Minter message bodies built from verified bundles and rotation plans (`sccp_finalize*`,
//! `sccp_void_*`, `sccp_rotate`, `sccp_apply_control*`, `sccp_init`, `sccp_deploy_buckets`,
//! `sccp_retry`), internal messages, wallet-v5 (`v5r1`) external messages signed with an
//! owner-only Ed25519 key file, the TVM stack encoding of get-method arguments and results, and
//! the values a sender attaches (§5.3.5): a margin over the minter's quotes and the deployment
//! funding of `MINTER_FLOOR`. Roster members are never sent: the minter reads them from storage.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use iroha_sccp::v1::{
    eip712::AttestationFieldsV1,
    evm_abi::RotationV1,
    proof::{ControlProofV1, HistoryProofV1, MessageProofV1},
    roster::RosterV1,
    signature::SignatureSetV1,
    ton_cell::{
        Cell, CellBuilder, TonCellError, cell_from_boc, hash_chunks, member_chunks, snake_bytes,
        ton_minter_floor_at_mainnet_prices,
    },
};
use zeroize::Zeroizing;

use super::{
    bundle::{BundlePurposeV1, VerifiedMessageBundleV1},
    control::VerifiedControlBundleV1,
    evm::{KeyFileError, load_key_file_secret},
};

/// `sccp_init`.
pub const OP_SCCP_INIT: u32 = 0x5343_4930;
/// `sccp_finalize`.
pub const OP_SCCP_FINALIZE: u32 = 0x5343_4631;
/// `sccp_finalize_historical`.
pub const OP_SCCP_FINALIZE_HISTORICAL: u32 = 0x5343_4632;
/// `sccp_void_expired`.
pub const OP_SCCP_VOID_EXPIRED: u32 = 0x5343_5631;
/// `sccp_void_expired_historical`.
pub const OP_SCCP_VOID_EXPIRED_HISTORICAL: u32 = 0x5343_5632;
/// `sccp_void_frozen`.
pub const OP_SCCP_VOID_FROZEN: u32 = 0x5343_5633;
/// `sccp_rotate`.
pub const OP_SCCP_ROTATE: u32 = 0x5343_5231;
/// `sccp_apply_control`.
pub const OP_SCCP_APPLY_CONTROL: u32 = 0x5343_4d31;
/// `sccp_apply_control_historical`.
pub const OP_SCCP_APPLY_CONTROL_HISTORICAL: u32 = 0x5343_4d32;
/// `sccp_deploy_buckets`.
pub const OP_SCCP_DEPLOY_BUCKETS: u32 = 0x5343_4431;
/// `sccp_retry`.
pub const OP_SCCP_RETRY: u32 = 0x5343_5931;
/// Fixed part of the margin added to a minter quote, in nanotons (0.05 TON).
pub const QUOTE_MARGIN_MIN: u128 = 50_000_000;
/// Gas, forwarding and `sccp_init` headroom of a minter deployment, in nanotons (0.1 TON).
pub const DEPLOY_INIT_HEADROOM: u128 = 100_000_000;
/// Default `wallet_id` of a mainnet workchain-0 `v5r1` wallet (subwallet 0).
pub const WALLET_V5R1_MAINNET_ID: u32 = 2_147_483_409;
/// Send mode: pay transfer fees separately and ignore action errors.
pub const SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS: u8 = 3;
const OP_SIGNED_EXTERNAL: u32 = 0x7369_676e;
const OP_ACTION_SEND_MSG: u32 = 0x0ec3_c86d;
const MAX_SEND_ACTIONS: usize = 255;

/// Why a TON message could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TonError {
    /// A cell could not be built.
    Cell(TonCellError),
    /// The bundle was verified for another purpose.
    WrongPurpose,
    /// A path, roster or signature set does not fit its TL-B field.
    FieldTooLarge,
    /// A wallet transfer carries no message or more than 255.
    BadActionCount,
    /// The key file was refused.
    KeyFile(KeyFileError),
    /// A TVM stack is malformed or holds another value type.
    BadStack,
}

impl core::fmt::Display for TonError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cell(error) => write!(formatter, "TON cell: {error}"),
            Self::WrongPurpose => {
                formatter.write_str("the bundle was verified for another purpose")
            }
            Self::FieldTooLarge => formatter.write_str("a value does not fit its TL-B field"),
            Self::BadActionCount => {
                formatter.write_str("a wallet transfer carries 1..=255 messages")
            }
            Self::KeyFile(error) => write!(formatter, "key file: {error}"),
            Self::BadStack => formatter.write_str("malformed TVM stack"),
        }
    }
}

impl std::error::Error for TonError {}

impl From<TonCellError> for TonError {
    fn from(error: TonCellError) -> Self {
        Self::Cell(error)
    }
}

// ---------------------------------------------------------------------------------------------
// Cell formats (§5.3.2)
// ---------------------------------------------------------------------------------------------

/// `attestation#_ height epoch timestamp_ms message_count history_size block_hash sccp_root
/// tail:^AttestationTail`.
///
/// # Errors
///
/// Never fails for well-formed fields; the `Result` mirrors the builder.
pub fn attestation_cell(attestation: &AttestationFieldsV1) -> Result<Cell, TonError> {
    let mut tail = CellBuilder::new();
    tail.store_bytes(&attestation.history_root)?
        .store_bytes(&attestation.roster_digest)?
        .store_bytes(&attestation.next_roster_digest)?;
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(attestation.height), 64)?
        .store_uint(u128::from(attestation.epoch), 64)?
        .store_uint(u128::from(attestation.timestamp_ms), 64)?
        .store_uint(u128::from(attestation.message_count), 32)?
        .store_uint(u128::from(attestation.history_size), 64)?
        .store_bytes(&attestation.block_hash)?
        .store_bytes(&attestation.sccp_root)?
        .store_ref(tail.build())?;
    Ok(cell.build())
}

/// `signatures#_ signer_bitmap first:^SignatureCell`, one `r s v next` cell per signature in
/// ascending bitmap order.
///
/// # Errors
///
/// Returns [`TonError::FieldTooLarge`] for a set without signatures or with a partial one.
pub fn signatures_cell(set: &SignatureSetV1) -> Result<Cell, TonError> {
    if set.signatures.is_empty() || !set.signatures.len().is_multiple_of(65) {
        return Err(TonError::FieldTooLarge);
    }
    let mut next: Option<Cell> = None;
    for signature in set.signatures.chunks_exact(65).rev() {
        let mut cell = CellBuilder::new();
        cell.store_bytes(&signature[..64])?
            .store_uint(u128::from(signature[64]), 8)?
            .store_maybe_ref(next.take())?;
        next = Some(cell.build());
    }
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(set.signer_bitmap), 32)?
        .store_ref(next.ok_or(TonError::FieldTooLarge)?)?;
    Ok(cell.build())
}

fn path_len(path: &[[u8; 32]]) -> Result<u128, TonError> {
    u8::try_from(path.len())
        .map(u128::from)
        .map_err(|_| TonError::FieldTooLarge)
}

/// `message_proof#_ leaf_index path_len payload:^SnakeBytes path:(Maybe ^HashChunk)`.
///
/// # Errors
///
/// Returns a cell error or [`TonError::FieldTooLarge`].
pub fn message_proof_cell(proof: &MessageProofV1) -> Result<Cell, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(proof.leaf_index), 32)?
        .store_uint(path_len(&proof.path)?, 8)?
        .store_ref(snake_bytes(&proof.payload)?)?
        .store_maybe_ref(hash_chunks(&proof.path)?)?;
    Ok(cell.build())
}

/// `history_proof#_ height sccp_root message_count leaf_index path_len path:(Maybe ^HashChunk)`.
///
/// # Errors
///
/// Returns a cell error or [`TonError::FieldTooLarge`].
pub fn history_proof_cell(history: &HistoryProofV1) -> Result<Cell, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(history.block.height), 64)?
        .store_bytes(&history.block.sccp_root)?
        .store_uint(u128::from(history.block.message_count), 32)?
        .store_uint(u128::from(history.leaf_index), 64)?
        .store_uint(path_len(&history.path)?, 8)?
        .store_maybe_ref(hash_chunks(&history.path)?)?;
    Ok(cell.build())
}

/// `control_proof#_ control_nonce paused leaf_index path_len path:(Maybe ^HashChunk)`.
///
/// # Errors
///
/// Returns a cell error or [`TonError::FieldTooLarge`].
pub fn control_proof_cell(control: &ControlProofV1) -> Result<Cell, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(control.control_nonce), 64)?
        .store_bit(control.paused)?
        .store_uint(u128::from(control.leaf_index), 32)?
        .store_uint(path_len(&control.path)?, 8)?
        .store_maybe_ref(hash_chunks(&control.path)?)?;
    Ok(cell.build())
}

/// `roster_spec#_ generation valid_from_ms valid_until_ms n t members:^MemberChunk`.
///
/// # Errors
///
/// Returns a cell error or [`TonError::FieldTooLarge`].
pub fn roster_spec_cell(roster: &RosterV1) -> Result<Cell, TonError> {
    let n = u8::try_from(roster.n()).map_err(|_| TonError::FieldTooLarge)?;
    let t = u8::try_from(roster.threshold()).map_err(|_| TonError::FieldTooLarge)?;
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(roster.generation), 64)?
        .store_uint(u128::from(roster.valid_from_ms), 64)?
        .store_uint(u128::from(roster.valid_until_ms), 64)?
        .store_uint(u128::from(n), 8)?
        .store_uint(u128::from(t), 8)?
        .store_ref(member_chunks(&roster.members)?)?;
    Ok(cell.build())
}

// ---------------------------------------------------------------------------------------------
// Minter messages (§5.3.3)
// ---------------------------------------------------------------------------------------------

/// A workchain-0 account id.
pub type TonAccountV1 = [u8; 32];

fn header(op: u32, query_id: u64, response: &TonAccountV1) -> Result<CellBuilder, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(op), 32)?
        .store_uint(u128::from(query_id), 64)?
        .store_address_std(0, response)?;
    Ok(cell)
}

/// `sccp_finalize` (or `sccp_finalize_historical`) for a bundle verified with
/// [`BundlePurposeV1::Finalize`]; excess value returns to `response`.
///
/// # Errors
///
/// Returns [`TonError::WrongPurpose`] or a cell error.
pub fn finalize_body(
    bundle: &VerifiedMessageBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.purpose != BundlePurposeV1::Finalize {
        return Err(TonError::WrongPurpose);
    }
    let signed = &bundle.attested.signed;
    let op = if bundle.history.is_some() {
        OP_SCCP_FINALIZE_HISTORICAL
    } else {
        OP_SCCP_FINALIZE
    };
    let mut body = header(op, query_id, response)?;
    body.store_ref(attestation_cell(&signed.attestation)?)?
        .store_ref(signatures_cell(&signed.signatures)?)?;
    if let Some(history) = &bundle.history {
        body.store_ref(history_proof_cell(history)?)?;
    }
    body.store_ref(message_proof_cell(&bundle.proof)?)?;
    Ok(body.build())
}

/// `sccp_void_expired` (or its historical variant) for a bundle verified with
/// [`BundlePurposeV1::VoidExpired`]; the `nonce` field is the payload nonce.
///
/// # Errors
///
/// Returns [`TonError::WrongPurpose`] or a cell error.
pub fn void_expired_body(
    bundle: &VerifiedMessageBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.purpose != BundlePurposeV1::VoidExpired {
        return Err(TonError::WrongPurpose);
    }
    let signed = &bundle.attested.signed;
    let op = if bundle.history.is_some() {
        OP_SCCP_VOID_EXPIRED_HISTORICAL
    } else {
        OP_SCCP_VOID_EXPIRED
    };
    let mut body = header(op, query_id, response)?;
    body.store_uint(u128::from(bundle.nonce()), 64)?
        .store_ref(attestation_cell(&signed.attestation)?)?
        .store_ref(signatures_cell(&signed.signatures)?)?;
    if let Some(history) = &bundle.history {
        body.store_ref(history_proof_cell(history)?)?;
    }
    body.store_ref(message_proof_cell(&bundle.proof)?)?;
    Ok(body.build())
}

/// `sccp_void_frozen first_nonce count` (one bucket, at most 512 nonces).
///
/// # Errors
///
/// Returns [`TonError::FieldTooLarge`] for an empty or oversized range.
pub fn void_frozen_body(
    first_nonce: u64,
    count: u16,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if count == 0 || count > 512 {
        return Err(TonError::FieldTooLarge);
    }
    let mut body = header(OP_SCCP_VOID_FROZEN, query_id, response)?;
    body.store_uint(u128::from(first_nonce), 64)?
        .store_uint(u128::from(count), 16)?;
    Ok(body.build())
}

/// `sccp_rotate` of one verified rotation (TON rotates one generation per message).
///
/// # Errors
///
/// Returns a cell error or [`TonError::FieldTooLarge`].
pub fn rotate_body(
    rotation: &RotationV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    let mut body = header(OP_SCCP_ROTATE, query_id, response)?;
    body.store_ref(attestation_cell(&rotation.attestation)?)?
        .store_ref(signatures_cell(&rotation.signatures)?)?
        .store_ref(roster_spec_cell(&rotation.next)?)?;
    Ok(body.build())
}

/// `sccp_apply_control` (or its historical variant) for a verified control bundle.
///
/// # Errors
///
/// Returns a cell error.
pub fn apply_control_body(
    bundle: &VerifiedControlBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    let signed = &bundle.attested.signed;
    let op = if bundle.history.is_some() {
        OP_SCCP_APPLY_CONTROL_HISTORICAL
    } else {
        OP_SCCP_APPLY_CONTROL
    };
    let mut body = header(op, query_id, response)?;
    body.store_ref(attestation_cell(&signed.attestation)?)?
        .store_ref(signatures_cell(&signed.signatures)?)?;
    if let Some(history) = &bundle.history {
        body.store_ref(history_proof_cell(history)?)?;
    }
    body.store_ref(control_proof_cell(&bundle.control)?)?;
    Ok(body.build())
}

/// `sccp_init query_id`.
///
/// # Errors
///
/// Never fails; the `Result` mirrors the builder.
pub fn init_body(query_id: u64) -> Result<Cell, TonError> {
    let mut body = CellBuilder::new();
    body.store_uint(u128::from(OP_SCCP_INIT), 32)?
        .store_uint(u128::from(query_id), 64)?;
    Ok(body.build())
}

/// `sccp_deploy_buckets query_id response count`.
///
/// # Errors
///
/// Returns [`TonError::FieldTooLarge`] for zero buckets.
pub fn deploy_buckets_body(
    count: u8,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if count == 0 {
        return Err(TonError::FieldTooLarge);
    }
    let mut body = header(OP_SCCP_DEPLOY_BUCKETS, query_id, response)?;
    body.store_uint(u128::from(count), 8)?;
    Ok(body.build())
}

/// `sccp_retry query_id response nonce`: re-runs the step the minter recorded for `nonce`
/// (get method `get_sccp_retry`).
///
/// # Errors
///
/// Never fails for a workchain-0 response; the `Result` mirrors the builder.
pub fn retry_body(nonce: u64, query_id: u64, response: &TonAccountV1) -> Result<Cell, TonError> {
    let mut body = header(OP_SCCP_RETRY, query_id, response)?;
    body.store_uint(u128::from(nonce), 64)?;
    Ok(body.build())
}

// ---------------------------------------------------------------------------------------------
// Attached values (§5.3.5)
// ---------------------------------------------------------------------------------------------

/// The value to attach for a minter quote (`finalize_required_value`, `rotate_required_value`,
/// ...): the quote plus 10%, and at least [`QUOTE_MARGIN_MIN`] more. The minter returns every
/// nanoton its step does not use to the `response` address, so the margin only absorbs price
/// and balance changes between the quote and the send.
#[must_use]
pub fn quote_with_margin(required: u128) -> u128 {
    required.saturating_add((required / 10).max(QUOTE_MARGIN_MIN))
}

/// The value to send with a minter deployment (its `sccp_init`): `MINTER_FLOOR` at TON mainnet
/// storage prices plus 25% and [`DEPLOY_INIT_HEADROOM`]. The value stays in the minter, so it
/// starts above its floor; should storage prices have risen, the first finalize, void or control
/// pays the remaining deficit (burns never do).
#[must_use]
pub fn minter_deploy_value() -> u128 {
    let floor = ton_minter_floor_at_mainnet_prices();
    floor + floor / 4 + DEPLOY_INIT_HEADROOM
}

// ---------------------------------------------------------------------------------------------
// Messages and the wallet
// ---------------------------------------------------------------------------------------------

/// An internal `MessageRelaxed` to workchain-0 account `destination` carrying `value` nanotons,
/// `body` in a reference and an optional `StateInit` in a reference.
///
/// # Errors
///
/// Returns a cell error for a value of `2^120` or more.
pub fn internal_message(
    destination: &TonAccountV1,
    value: u128,
    bounce: bool,
    body: Cell,
    state_init: Option<Cell>,
) -> Result<Cell, TonError> {
    let mut message = CellBuilder::new();
    message
        .store_bit(false)? // int_msg_info$0
        .store_bit(true)? // ihr_disabled
        .store_bit(bounce)?
        .store_bit(false)? // bounced
        .store_uint(0, 2)? // src: addr_none (filled by the wallet)
        .store_address_std(0, destination)?
        .store_coins(value)?
        .store_bit(false)? // no extra currencies
        .store_coins(0)? // ihr_fee
        .store_coins(0)? // fwd_fee
        .store_uint(0, 64)? // created_lt
        .store_uint(0, 32)?; // created_at
    match state_init {
        Some(state_init) => {
            message
                .store_bit(true)?
                .store_bit(true)?
                .store_ref(state_init)?;
        }
        None => {
            message.store_bit(false)?;
        }
    }
    message.store_bit(true)?.store_ref(body)?;
    Ok(message.build())
}

/// An Ed25519 key of a `v5r1` wallet; the seed is zeroized on drop and never printed.
pub struct TonWalletKeyV1 {
    key: SigningKey,
}

impl core::fmt::Debug for TonWalletKeyV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("TonWalletKeyV1")
            .field("public_key", &hex::encode(self.public_key()))
            .finish_non_exhaustive()
    }
}

impl TonWalletKeyV1 {
    /// Wrap a 32-byte Ed25519 seed.
    #[must_use]
    pub fn from_seed(seed: &Zeroizing<[u8; 32]>) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
        }
    }

    /// Load an owner-only key file holding the 32-byte seed as 64 hex digits.
    ///
    /// # Errors
    ///
    /// Returns [`TonError::KeyFile`].
    pub fn load(path: &Path) -> Result<Self, TonError> {
        Ok(Self::from_seed(
            &load_key_file_secret(path).map_err(TonError::KeyFile)?,
        ))
    }

    /// The Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

/// The `v5r1` external message from `wallet` sending `messages` (each an internal message with
/// its send mode), signed by `key` over the hash of the request without its signature.
/// Returns the external message `BoC`.
///
/// # Errors
///
/// Returns [`TonError::BadActionCount`] or a cell error.
pub fn wallet_v5_transfer(
    wallet: &TonAccountV1,
    wallet_id: u32,
    seqno: u32,
    valid_until: u32,
    messages: &[(Cell, u8)],
    key: &TonWalletKeyV1,
) -> Result<Vec<u8>, TonError> {
    if messages.is_empty() || messages.len() > MAX_SEND_ACTIONS {
        return Err(TonError::BadActionCount);
    }
    let mut actions = CellBuilder::new().build();
    for (message, mode) in messages {
        let mut action = CellBuilder::new();
        action
            .store_ref(actions)?
            .store_uint(u128::from(OP_ACTION_SEND_MSG), 32)?
            .store_uint(u128::from(*mode), 8)?
            .store_ref(message.clone())?;
        actions = action.build();
    }
    let mut request = CellBuilder::new();
    request
        .store_uint(u128::from(OP_SIGNED_EXTERNAL), 32)?
        .store_uint(u128::from(wallet_id), 32)?
        .store_uint(u128::from(valid_until), 32)?
        .store_uint(u128::from(seqno), 32)?
        .store_maybe_ref(Some(actions))?
        .store_bit(false)?; // no extended actions
    let unsigned = request.build();
    let signature = key.key.sign(unsigned.hash()).to_bytes();
    request.store_bytes(&signature)?;
    let body = request.build();
    let mut external = CellBuilder::new();
    external
        .store_uint(0b10, 2)? // ext_in_msg_info$10
        .store_uint(0, 2)? // src: addr_none
        .store_address_std(0, wallet)?
        .store_coins(0)? // import_fee
        .store_bit(false)? // no StateInit
        .store_bit(true)?
        .store_ref(body)?;
    Ok(external.build().to_boc()?)
}

/// Load a contract code artifact (`code_boc64`) as a cell.
///
/// # Errors
///
/// Returns [`TonError::Cell`] for a malformed bag of cells.
pub fn code_cell(code_boc: &[u8]) -> Result<Cell, TonError> {
    Ok(cell_from_boc(code_boc)?)
}

// ---------------------------------------------------------------------------------------------
// Get methods and the TVM stack
// ---------------------------------------------------------------------------------------------

/// The TVM method id of get method `name`: `(crc16_xmodem(name) & 0xffff) | 0x10000`.
#[must_use]
pub fn get_method_id(name: &str) -> u64 {
    let mut crc = 0_u16;
    for byte in name.bytes() {
        crc ^= u16::from(byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    u64::from(crc) | 0x1_0000
}

/// A `VmStack` `BoC` of small integer arguments (bottom first).
///
/// # Errors
///
/// Never fails for at most a few hundred values; the `Result` mirrors the builder.
pub fn stack_of_ints(values: &[i64]) -> Result<Vec<u8>, TonError> {
    let mut list = CellBuilder::new().build();
    for value in values {
        let mut node = CellBuilder::new();
        node.store_ref(list)?
            .store_uint(1, 8)? // vm_stk_tinyint#01
            .store_uint(u128::from(value.cast_unsigned()), 64)?;
        list = node.build();
    }
    let depth = u128::try_from(values.len()).map_err(|_| TonError::FieldTooLarge)?;
    let mut root = CellBuilder::new();
    root.store_uint(depth, 24)?;
    // The root holds the top list node inline: its `rest` reference and value bits.
    if values.is_empty() {
        return Ok(root.build().to_boc()?);
    }
    let top = list;
    let mut builder = CellBuilder::new();
    builder.store_uint(depth, 24)?;
    for child in top.refs() {
        builder.store_ref(child.clone())?;
    }
    for bit in 0..top.bit_len() {
        builder.store_bit(top.data()[bit / 8] & (0x80 >> (bit % 8)) != 0)?;
    }
    Ok(builder.build().to_boc()?)
}

/// A TVM integer as a 33-byte two's-complement big-endian value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TvmIntV1(pub [u8; 33]);

impl TvmIntV1 {
    /// The value as a `u64`, when it is one.
    #[must_use]
    pub fn to_u64(self) -> Option<u64> {
        if self.0[..25].iter().any(|byte| *byte != 0) {
            return None;
        }
        Some(u64::from_be_bytes(self.0[25..].try_into().ok()?))
    }

    /// The value as an unsigned 256-bit word, when it is one.
    #[must_use]
    pub fn to_u256(self) -> Option<[u8; 32]> {
        (self.0[0] == 0)
            .then(|| self.0[1..].try_into().ok())
            .flatten()
    }
}

struct Bits<'a> {
    cell: &'a Cell,
    offset: usize,
}

impl Bits<'_> {
    fn read(&mut self, bits: usize) -> Result<u128, TonError> {
        if bits > 128 || self.offset + bits > self.cell.bit_len() {
            return Err(TonError::BadStack);
        }
        let mut value = 0_u128;
        for _ in 0..bits {
            let bit = self.cell.data()[self.offset / 8] & (0x80 >> (self.offset % 8)) != 0;
            value = (value << 1) | u128::from(bit);
            self.offset += 1;
        }
        Ok(value)
    }
}

fn read_value(bits: &mut Bits<'_>) -> Result<Option<TvmIntV1>, TonError> {
    match bits.read(8)? {
        0x00 => Ok(None),
        0x01 => {
            let raw = u64::try_from(bits.read(64)?).map_err(|_| TonError::BadStack)?;
            let value = raw.cast_signed();
            let mut out = [if value < 0 { 0xff } else { 0 }; 33];
            out[25..].copy_from_slice(&value.to_be_bytes());
            Ok(Some(TvmIntV1(out)))
        }
        0x02 => {
            // `vm_stk_int#0201_`: seven more tag bits (`0000000`), then an `int257`.
            if bits.read(7)? != 0 {
                return Err(TonError::BadStack);
            }
            let mut out = [0_u8; 33];
            let sign = bits.read(1)? == 1;
            let high = bits.read(128)?;
            let low = bits.read(128)?;
            out[0] = if sign { 0xff } else { 0 };
            out[1..17].copy_from_slice(&high.to_be_bytes());
            out[17..].copy_from_slice(&low.to_be_bytes());
            Ok(Some(TvmIntV1(out)))
        }
        _ => Err(TonError::BadStack),
    }
}

/// The integers of a get-method result stack, bottom (first returned value) first; `None` for
/// a null entry.
///
/// # Errors
///
/// Returns [`TonError::BadStack`] for a malformed stack or a non-integer entry.
pub fn parse_int_stack(boc: &[u8]) -> Result<Vec<Option<TvmIntV1>>, TonError> {
    let root = cell_from_boc(boc)?;
    let mut bits = Bits {
        cell: &root,
        offset: 0,
    };
    let depth = usize::try_from(bits.read(24)?).map_err(|_| TonError::BadStack)?;
    let mut values = Vec::with_capacity(depth);
    let mut node = &root;
    let mut offset = 24;
    for _ in 0..depth {
        let mut reader = Bits { cell: node, offset };
        values.push(read_value(&mut reader)?);
        node = node
            .refs()
            .first()
            .and_then(|rest| rest.cell())
            .ok_or(TonError::BadStack)?;
        offset = 0;
    }
    values.reverse();
    Ok(values)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attached_values_cover_the_quote_and_the_floor() {
        assert_eq!(quote_with_margin(0), QUOTE_MARGIN_MIN);
        assert_eq!(
            quote_with_margin(100_000_000),
            100_000_000 + QUOTE_MARGIN_MIN
        );
        assert_eq!(quote_with_margin(2_000_000_000), 2_200_000_000);
        assert_eq!(quote_with_margin(u128::MAX), u128::MAX);
        let floor = ton_minter_floor_at_mainnet_prices();
        assert!(minter_deploy_value() > floor + floor / 5);
        // about 12.4 TON at mainnet prices (MINTER_FLOOR is about 9.84 TON)
        assert_eq!(
            minter_deploy_value(),
            9_840_563_965 + 2_460_140_991 + 100_000_000
        );
    }

    #[test]
    fn method_ids_follow_crc16_xmodem() {
        // `seqno` is the well-known method id 85143.
        assert_eq!(get_method_id("seqno"), 85_143);
        assert_eq!(get_method_id("get_public_key"), 78_748);
    }

    #[test]
    fn int_stacks_round_trip() {
        let boc = stack_of_ints(&[7, -2]).expect("stack");
        let values = parse_int_stack(&boc).expect("parses");
        assert_eq!(values.len(), 2);
        assert_eq!(values[0].expect("int").to_u64(), Some(7));
        assert_eq!(values[1].expect("int").0[32], 0xfe);
        assert!(values[1].expect("int").to_u64().is_none());
        let empty = stack_of_ints(&[]).expect("empty");
        assert!(parse_int_stack(&empty).expect("parses").is_empty());
    }

    #[test]
    fn wallet_transfers_are_signed_external_messages() {
        let key = TonWalletKeyV1::from_seed(&Zeroizing::new([5; 32]));
        let body = init_body(9).expect("body");
        let message = internal_message(&[1; 32], 50_000_000, true, body, None).expect("message");
        let boc = wallet_v5_transfer(
            &[2; 32],
            WALLET_V5R1_MAINNET_ID,
            3,
            1_900_000_000,
            &[(message.clone(), SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
            &key,
        )
        .expect("transfer");
        let external = cell_from_boc(&boc).expect("parses");
        let request = external.refs()[0].cell().expect("body");
        assert_eq!(request.bit_len(), 32 * 4 + 2 + 512);
        assert_eq!(&request.data()[..4], &0x7369_676e_u32.to_be_bytes());
        assert!(wallet_v5_transfer(&[2; 32], 1, 3, 1, &[], &key).is_err());
    }

    #[test]
    fn minter_messages_carry_their_op_and_response() {
        let body = void_frozen_body(4, 2, 1, &[3; 32]).expect("body");
        assert_eq!(&body.data()[..4], &OP_SCCP_VOID_FROZEN.to_be_bytes());
        assert_eq!(body.bit_len(), 32 + 64 + 267 + 64 + 16);
        assert!(void_frozen_body(4, 0, 1, &[3; 32]).is_err());
        assert!(deploy_buckets_body(0, 1, &[3; 32]).is_err());
        let retry = retry_body(513, 1, &[3; 32]).expect("body");
        assert_eq!(&retry.data()[..4], &OP_SCCP_RETRY.to_be_bytes());
        assert_eq!(retry.bit_len(), 32 + 64 + 267 + 64);
        let set = SignatureSetV1 {
            signer_bitmap: 0b11,
            signatures: vec![1; 130],
        };
        let cell = signatures_cell(&set).expect("signatures");
        assert_eq!(cell.bit_len(), 32);
        let first = cell.refs()[0].cell().expect("first");
        assert_eq!(first.bit_len(), 521);
        assert_eq!(first.refs().len(), 1);
    }
}
