//! TON destination encodings (spec §5.3.2, §5.3.3, §7.1, §7.2).
//!
//! Minter message bodies built from verified bundles and rotation plans (`sccp_finalize*`,
//! `sccp_void_*`, `sccp_checkpoint`, `sccp_apply_control*`, `sccp_init`, `sccp_deploy_buckets`,
//! `sccp_retry`), internal messages, wallet-v5 (`v5r1`) external messages signed with an
//! owner-only Ed25519 key file, the TVM stack encoding of get-method arguments and results, and
//! the values a sender attaches (§5.3.5): a margin over the minter's quotes and the deployment
//! funding of `MINTER_FLOOR`. The minter verifies with its stored keys; only an authenticated key-changing checkpoint sends successor keys.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use iroha_sccp::v1::{
    constants::{MAX_BLOCK_PATH, MAX_HISTORY_PATH, MAX_PAYLOAD_BYTES},
    destination::{
        BlockRefV1, CheckpointRefV1, ControlProofV1, MessageProofV1, TairaCertificateV1,
    },
    finality::{QcFixedV1, SccpFinalityHeaderV1},
    ton_cell::{
        Cell, CellBuilder, TonCellError, burn_to_taira_payload, cell_from_boc, hash_chunks,
        key_chunks, snake_bytes, ton_minter_floor_at_mainnet_prices,
    },
};
use zeroize::Zeroizing;

use super::{
    bundle::{BundlePurposeV1, VerifiedCertificateSourceV1, VerifiedMessageBundleV1},
    control::VerifiedControlBundleV1,
    evm::{KeyFileError, load_key_file_secret},
    rotation::VerifiedRotationV1,
};

/// `sccp_init`.
pub const OP_SCCP_INIT: u32 = 0x5343_4930;
/// `sccp_finalize`.
pub const OP_SCCP_FINALIZE: u32 = 0x5343_4631;
/// `sccp_finalize_checkpoint`.
pub const OP_SCCP_FINALIZE_CHECKPOINT: u32 = 0x5343_4632;
/// `sccp_void_expired`.
pub const OP_SCCP_VOID_EXPIRED: u32 = 0x5343_5631;
/// `sccp_void_expired_checkpoint`.
pub const OP_SCCP_VOID_EXPIRED_CHECKPOINT: u32 = 0x5343_5632;
/// `sccp_void_frozen`.
pub const OP_SCCP_VOID_FROZEN: u32 = 0x5343_5633;
/// `sccp_checkpoint`.
pub const OP_SCCP_CHECKPOINT: u32 = 0x5343_4b31;
/// `sccp_apply_control`.
pub const OP_SCCP_APPLY_CONTROL: u32 = 0x5343_4d31;
/// `sccp_apply_control_checkpoint`.
pub const OP_SCCP_APPLY_CONTROL_CHECKPOINT: u32 = 0x5343_4d32;
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
    /// A proof path or fixed certificate field does not fit its current TL-B shape.
    FieldTooLarge,
    /// QC or finality header bytes are not the current fixed layout.
    BadCertificate,
    /// A wallet transfer carries no message or more than 255.
    BadActionCount,
    /// The key file was refused.
    KeyFile(KeyFileError),
    /// A TVM stack is malformed or holds another value type.
    BadStack,
    /// A retained wallet message differs from the exact v5r1 external-message shape.
    BadWalletEnvelope,
}

impl core::fmt::Display for TonError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Cell(error) => write!(formatter, "TON cell: {error}"),
            Self::WrongPurpose => {
                formatter.write_str("the bundle was verified for another purpose")
            }
            Self::FieldTooLarge => formatter.write_str("a value does not fit its TL-B field"),
            Self::BadCertificate => formatter.write_str("malformed current certificate"),
            Self::BadActionCount => {
                formatter.write_str("a wallet transfer carries 1..=255 messages")
            }
            Self::KeyFile(error) => write!(formatter, "key file: {error}"),
            Self::BadStack => formatter.write_str("malformed TVM stack"),
            Self::BadWalletEnvelope => formatter.write_str("malformed v5r1 wallet envelope"),
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

/// The mandatory `sccp_burn_to_taira` custom payload of a Jetton burn.
///
/// The ordinary wrapper has exactly its opcode and one reference. The complete ordinary
/// recipient snake uses canonical 127-byte chunks and holds 1..=1024 bytes, matching the
/// wallet and minter admission before any debit or forwarding (§5.3.4).
///
/// # Errors
/// Returns [`TonError::Cell`] for an empty or oversized recipient.
pub fn burn_payload_cell(recipient: &[u8]) -> Result<Cell, TonError> {
    Ok(burn_to_taira_payload(recipient)?)
}

/// Standard TEP-74 burn body carrying the required SCCP recipient payload.
///
/// # Errors
/// Refuses zero or non-contract amount, invalid recipient and cell capacity violations.
pub fn burn_body(
    query_id: u64,
    amount: u128,
    response: &TonAccountV1,
    recipient: &[u8],
) -> Result<Cell, TonError> {
    if amount == 0 || amount >= (1u128 << 96) {
        return Err(TonError::FieldTooLarge);
    }
    let mut body = CellBuilder::new();
    body.store_uint(0x595f_07bc, 32)?
        .store_uint(query_id.into(), 64)?
        .store_coins(amount)?
        .store_address_std(0, response)?
        .store_bit(true)?
        .store_ref(burn_payload_cell(recipient)?)?;
    Ok(body.build())
}

/// `x_head#_ bytes:bits872 tail:^XTail`, with the original fixed 221-byte header.
///
/// # Errors
/// Returns a cell-capacity error.
pub fn header_cell(header: &SccpFinalityHeaderV1) -> Result<Cell, TonError> {
    let mut tail = CellBuilder::new();
    tail.store_bytes(header.tail())?;
    let mut head = CellBuilder::new();
    head.store_bytes(header.head())?.store_ref(tail.build())?;
    Ok(head.build())
}

/// `taira_cert#_ signature:bits768 signers:uint32 qc:^QcFixed x:^XHead`.
/// This only encodes the current wire shape; callers supply an authenticated certificate.
///
/// # Errors
/// Rejects a malformed QC/header or a compressed signature whose length is not 96 bytes.
pub fn certificate_cell(certificate: &TairaCertificateV1) -> Result<Cell, TonError> {
    let qc = QcFixedV1::parse(&certificate.qc).map_err(|_| TonError::BadCertificate)?;
    let header =
        SccpFinalityHeaderV1::parse(&certificate.header).map_err(|_| TonError::BadCertificate)?;
    if certificate.ton_signature.len() != 96 {
        return Err(TonError::FieldTooLarge);
    }
    let mut fixed = CellBuilder::new();
    fixed
        .store_uint(u128::from(qc.epoch), 64)?
        .store_bytes(&qc.epoch_context)?
        .store_uint(u128::from(qc.view), 64)?
        .store_bytes(&qc.block_hash)?
        .store_bytes(&qc.result_body)?;
    let mut cell = CellBuilder::new();
    cell.store_bytes(&certificate.ton_signature)?
        .store_uint(u128::from(qc.signers), 32)?
        .store_ref(fixed.build())?
        .store_ref(header_cell(&header)?)?;
    Ok(cell.build())
}

/// `checkpoint_ref#_ x:^XHead`; the original header identifies the stored checkpoint.
///
/// # Errors
/// Rejects a malformed fixed header or a cell-capacity error.
pub fn checkpoint_ref_cell(reference: &CheckpointRefV1) -> Result<Cell, TonError> {
    let header =
        SccpFinalityHeaderV1::parse(&reference.header).map_err(|_| TonError::BadCertificate)?;
    let mut cell = CellBuilder::new();
    cell.store_ref(header_cell(&header)?)?;
    Ok(cell.build())
}

fn path_len(path: &[[u8; 32]], maximum: usize) -> Result<u128, TonError> {
    if path.len() > maximum {
        return Err(TonError::FieldTooLarge);
    }
    u8::try_from(path.len())
        .map(u128::from)
        .map_err(|_| TonError::FieldTooLarge)
}

/// `block_ref#_ height root count history_index path_len path:(Maybe ^HashChunk)`.
///
/// # Errors
/// Rejects a history path longer than 32 or a cell-capacity error.
pub fn block_ref_cell(block: &BlockRefV1) -> Result<Cell, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(block.height), 64)?
        .store_bytes(&block.sccp_root)?
        .store_uint(u128::from(block.message_count), 32)?
        .store_uint(u128::from(block.history_index), 64)?
        .store_uint(path_len(&block.history_path, MAX_HISTORY_PATH)?, 8)?
        .store_maybe_ref(hash_chunks(&block.history_path)?)?;
    Ok(cell.build())
}

/// `message_proof#_ leaf_index path_len payload:^SnakeBytes path:(Maybe ^HashChunk) block:^BlockRef`.
///
/// # Errors
/// Rejects an oversized payload/path or a cell-capacity error.
pub fn message_proof_cell(proof: &MessageProofV1) -> Result<Cell, TonError> {
    if proof.payload.len() > MAX_PAYLOAD_BYTES {
        return Err(TonError::FieldTooLarge);
    }
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(proof.leaf_index), 32)?
        .store_uint(path_len(&proof.path, MAX_BLOCK_PATH)?, 8)?
        .store_ref(snake_bytes(&proof.payload)?)?
        .store_maybe_ref(hash_chunks(&proof.path)?)?
        .store_ref(block_ref_cell(&proof.block)?)?;
    Ok(cell.build())
}

/// Current 690-bit control proof, including both pause mechanisms and the authenticated cause.
///
/// # Errors
/// Rejects a non-boolean Parliament byte, an oversized path or a cell-capacity error.
pub fn control_proof_cell(control: &ControlProofV1) -> Result<Cell, TonError> {
    if control.parliament_paused > 1 {
        return Err(TonError::FieldTooLarge);
    }
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(control.control_nonce), 64)?
        .store_uint(u128::from(control.track), 8)?
        .store_bit(control.parliament_paused != 0)?
        .store_uint(u128::from(control.fast_pause_until_ms), 64)?
        .store_bytes(&control.certificate_id)?
        .store_bytes(&control.effect_hash)?
        .store_uint(u128::from(control.leaf_index), 32)?
        .store_uint(path_len(&control.path, MAX_BLOCK_PATH)?, 8)?
        .store_maybe_ref(hash_chunks(&control.path)?)?
        .store_ref(block_ref_cell(&control.block)?)?;
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

/// Finalize a verified direct or historical message using its verified inline/checkpoint source.
///
/// # Errors
/// Returns `WrongPurpose` or a current certificate/proof encoding error.
pub fn finalize_body(
    bundle: &VerifiedMessageBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.purpose != BundlePurposeV1::Finalize {
        return Err(TonError::WrongPurpose);
    }
    let (op, source) = match &bundle.certificate.source {
        VerifiedCertificateSourceV1::Inline(certificate) => {
            (OP_SCCP_FINALIZE, certificate_cell(certificate)?)
        }
        VerifiedCertificateSourceV1::Checkpoint(reference) => {
            (OP_SCCP_FINALIZE_CHECKPOINT, checkpoint_ref_cell(reference)?)
        }
    };
    let mut body = header(op, query_id, response)?;
    body.store_ref(source)?
        .store_ref(message_proof_cell(&bundle.proof)?)?;
    Ok(body.build())
}

/// Void an expired verified message using its verified inline/checkpoint source.
///
/// # Errors
/// Returns `WrongPurpose` or a current certificate/proof encoding error.
pub fn void_expired_body(
    bundle: &VerifiedMessageBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.purpose != BundlePurposeV1::VoidExpired {
        return Err(TonError::WrongPurpose);
    }
    let (op, source) = match &bundle.certificate.source {
        VerifiedCertificateSourceV1::Inline(certificate) => {
            (OP_SCCP_VOID_EXPIRED, certificate_cell(certificate)?)
        }
        VerifiedCertificateSourceV1::Checkpoint(reference) => (
            OP_SCCP_VOID_EXPIRED_CHECKPOINT,
            checkpoint_ref_cell(reference)?,
        ),
    };
    let mut body = header(op, query_id, response)?;
    body.store_uint(u128::from(bundle.nonce()), 64)?
        .store_ref(source)?
        .store_ref(message_proof_cell(&bundle.proof)?)?;
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
    if count == 0
        || count > 512
        || first_nonce
            .checked_add(u64::from(count) - 1)
            .is_none_or(|last| last >> 9 != first_nonce >> 9)
    {
        return Err(TonError::FieldTooLarge);
    }
    let mut body = header(OP_SCCP_VOID_FROZEN, query_id, response)?;
    body.store_uint(u128::from(first_nonce), 64)?
        .store_uint(u128::from(count), 16)?;
    Ok(body.build())
}

/// One verified checkpoint; TON successor keys are sent only for an actual key change.
///
/// # Errors
/// Returns a current certificate/key encoding error.
pub fn checkpoint_body(
    checkpoint: &VerifiedRotationV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    let mut body = header(OP_SCCP_CHECKPOINT, query_id, response)?;
    body.store_ref(certificate_cell(checkpoint.certificate())?)?
        .store_maybe_ref(checkpoint.next_keys().map(key_chunks).transpose()?)?;
    Ok(body.build())
}

/// Apply a verified complete control using its verified inline/checkpoint source.
///
/// # Errors
/// Returns a current certificate/control encoding error.
pub fn apply_control_body(
    bundle: &VerifiedControlBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    let (op, source) = match &bundle.certificate.source {
        VerifiedCertificateSourceV1::Inline(certificate) => {
            (OP_SCCP_APPLY_CONTROL, certificate_cell(certificate)?)
        }
        VerifiedCertificateSourceV1::Checkpoint(reference) => (
            OP_SCCP_APPLY_CONTROL_CHECKPOINT,
            checkpoint_ref_cell(reference)?,
        ),
    };
    let mut body = header(op, query_id, response)?;
    body.store_ref(source)?
        .store_ref(control_proof_cell(&bundle.control)?)?;
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

/// `sccp_retry query_id response operation_id`: retries the durable recovery operation
/// recorded under that id (get method `get_sccp_recovery`).
///
/// # Errors
///
/// Never fails for a workchain-0 response; the `Result` mirrors the builder.
pub fn retry_body(
    operation_id: u64,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    let mut body = header(OP_SCCP_RETRY, query_id, response)?;
    body.store_uint(u128::from(operation_id), 64)?;
    Ok(body.build())
}

// ---------------------------------------------------------------------------------------------
// Attached values (§5.3.5)
// ---------------------------------------------------------------------------------------------

/// The value to attach for a minter quote (`finalize_required_value`, `checkpoint_required_value`,
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
    let mut request = wallet_v5_request_builder(wallet_id, seqno, valid_until, messages)?;
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

/// Exact v5r1 signing request without a signature, for an external signer.
/// Sign this cell's representation hash with the selected wallet's Ed25519 key;
/// append the signature to its bits and wrap it in an external message to that wallet.
///
/// # Errors
/// Refuses an empty or oversized action list and malformed cells.
pub fn wallet_v5_unsigned_request(
    wallet_id: u32,
    seqno: u32,
    valid_until: u32,
    messages: &[(Cell, u8)],
) -> Result<Cell, TonError> {
    Ok(wallet_v5_request_builder(wallet_id, seqno, valid_until, messages)?.build())
}

fn wallet_v5_request_builder(
    wallet_id: u32,
    seqno: u32,
    valid_until: u32,
    messages: &[(Cell, u8)],
) -> Result<CellBuilder, TonError> {
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
    Ok(request)
}

/// Public recovery coordinates of an original signed v5r1 envelope. These are diagnostic
/// metadata, never proof that the wallet executed, rejected or expired the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletEnvelopeV1 {
    /// Original basechain wallet account.
    pub wallet: TonAccountV1,
    /// Original wallet namespace.
    pub wallet_id: u32,
    /// Original replay-protection sequence number.
    pub seqno: u32,
    /// Original deadline in Unix seconds.
    pub valid_until: u32,
}

/// Read only the exact envelope shape emitted by [`wallet_v5_transfer`].
/// This does not validate its signature or grant retry/completion authority.
///
/// # Errors
/// Refuses another message layout, workchain, body shape or malformed `BoC`.
pub fn wallet_v5_envelope(boc: &[u8]) -> Result<WalletEnvelopeV1, TonError> {
    let root = cell_from_boc(boc)?;
    let malformed = || TonError::BadWalletEnvelope;
    if root.bit_len() != 277 || root.refs().len() != 1 {
        return Err(malformed());
    }
    let mut bits = Bits {
        cell: &root,
        offset: 0,
    };
    if bits.read(2)? != 2
        || bits.read(2)? != 0
        || bits.read(2)? != 2
        || bits.read(1)? != 0
        || bits.read(8)? != 0
    {
        return Err(malformed());
    }
    let mut wallet = [0; 32];
    wallet[..16].copy_from_slice(&bits.read(128)?.to_be_bytes());
    wallet[16..].copy_from_slice(&bits.read(128)?.to_be_bytes());
    if bits.read(4)? != 0 || bits.read(1)? != 0 || bits.read(1)? != 1 {
        return Err(malformed());
    }
    let body = root.refs()[0].cell().ok_or_else(malformed)?;
    if body.bit_len() != 642 || body.refs().len() != 1 {
        return Err(malformed());
    }
    let mut bits = Bits {
        cell: body,
        offset: 0,
    };
    if bits.read(32)? != u128::from(OP_SIGNED_EXTERNAL) {
        return Err(malformed());
    }
    let wallet_id = u32::try_from(bits.read(32)?).map_err(|_| malformed())?;
    let valid_until = u32::try_from(bits.read(32)?).map_err(|_| malformed())?;
    let seqno = u32::try_from(bits.read(32)?).map_err(|_| malformed())?;
    if bits.read(1)? != 1 || bits.read(1)? != 0 {
        return Err(malformed());
    }
    Ok(WalletEnvelopeV1 {
        wallet,
        wallet_id,
        seqno,
        valid_until,
    })
}

/// Fixed recovery row coordinates; a getter observation is not proof of transfer completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryRowV1 {
    /// Immutable nonce, amount, count, chained id, query id and original tail commitment.
    pub identity: [u8; 32],
    /// Activation, consumption, mint, unconsume or range stage (1..=5).
    pub stage: u8,
    /// Wait, drop, failed or queued phase (0..=3).
    pub phase: u8,
    /// Monotonic attempt within the stage.
    pub attempt: u64,
}

/// Decode the exact current `RecoveryOperation` cell for retry binding.
///
/// # Errors
/// Refuses another row shape, an unknown stage or an opaque tail.
pub fn recovery_row(cell: &Cell) -> Result<RecoveryRowV1, TonError> {
    if cell.bit_len() != 369 || cell.refs().len() != 1 {
        return Err(TonError::BadWalletEnvelope);
    }
    let mut bits = Bits { cell, offset: 0 };
    let stage = u8::try_from(bits.read(3)?).map_err(|_| TonError::BadWalletEnvelope)?;
    let phase = u8::try_from(bits.read(2)?).map_err(|_| TonError::BadWalletEnvelope)?;
    if !(1..=5).contains(&stage) {
        return Err(TonError::BadWalletEnvelope);
    }
    let attempt = u64::try_from(bits.read(64)?).map_err(|_| TonError::BadWalletEnvelope)?;
    let mut identity = CellBuilder::new();
    for _ in 69..367 {
        identity.store_bit(bits.read(1)? != 0)?;
    }
    identity.store_ref(
        cell.refs()[0]
            .cell()
            .ok_or(TonError::BadWalletEnvelope)?
            .clone(),
    )?;
    Ok(RecoveryRowV1 {
        identity: *identity.build().hash(),
        stage,
        phase,
        attempt,
    })
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
    finish_stack(&list, values.len())
}

/// A `VmStack` `BoC` of unsigned 64-bit arguments, preserving the complete nonce range.
///
/// # Errors
/// Returns an error if the stack depth or a cell exceeds the current TL-B bound.
pub fn stack_of_uints(values: &[u64]) -> Result<Vec<u8>, TonError> {
    let mut list = CellBuilder::new().build();
    for &value in values {
        let mut node = CellBuilder::new();
        node.store_ref(list)?
            .store_uint(2, 8)? // vm_stk_int#0201_, positive int257
            .store_uint(0, 7)?
            .store_uint(0, 1)?
            .store_uint(0, 128)?
            .store_uint(u128::from(value), 128)?;
        list = node.build();
    }
    finish_stack(&list, values.len())
}

fn finish_stack(list: &Cell, depth: usize) -> Result<Vec<u8>, TonError> {
    let depth = u128::try_from(depth).map_err(|_| TonError::FieldTooLarge)?;
    let mut root = CellBuilder::new();
    root.store_uint(depth, 24)?;
    for child in list.refs() {
        root.store_ref(child.clone())?;
    }
    for bit in 0..list.bit_len() {
        root.store_bit(list.data()[bit / 8] & (0x80 >> (bit % 8)) != 0)?;
    }
    Ok(root.build().to_boc()?)
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

/// Supported get-method stack values. Cells remain intact for canonical committee-key parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TvmStackValueV1 {
    /// A TVM null value.
    Null,
    /// A signed TVM integer.
    Integer(TvmIntV1),
    /// An ordinary cell, referenced by the stack node.
    Cell(Cell),
}

fn read_value(bits: &mut Bits<'_>) -> Result<TvmStackValueV1, TonError> {
    let value = match bits.read(8)? {
        0x00 => TvmStackValueV1::Null,
        0x01 => {
            let raw = u64::try_from(bits.read(64)?).map_err(|_| TonError::BadStack)?;
            let value = raw.cast_signed();
            let mut out = [if value < 0 { 0xff } else { 0 }; 33];
            out[25..].copy_from_slice(&value.to_be_bytes());
            TvmStackValueV1::Integer(TvmIntV1(out))
        }
        0x02 => {
            // `vm_stk_int#0201_`: seven more tag bits, then an int257.
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
            TvmStackValueV1::Integer(TvmIntV1(out))
        }
        0x03 => TvmStackValueV1::Cell(
            bits.cell
                .refs()
                .get(1)
                .and_then(|reference| reference.cell())
                .ok_or(TonError::BadStack)?
                .clone(),
        ),
        _ => return Err(TonError::BadStack),
    };
    let refs = if matches!(value, TvmStackValueV1::Cell(_)) {
        2
    } else {
        1
    };
    if bits.offset != bits.cell.bit_len() || bits.cell.refs().len() != refs {
        return Err(TonError::BadStack);
    }
    Ok(value)
}

/// Decode integer, null and cell get-method results in their return order.
/// The advertised depth cannot exceed the original `BoC` byte count: every stack node
/// consumes at least its tag byte. Each node and the final empty list are consumed exactly.
///
/// # Errors
/// Returns an error for malformed, truncated, excessive-depth or unsupported stack values.
pub fn parse_stack(boc: &[u8]) -> Result<Vec<TvmStackValueV1>, TonError> {
    let root = cell_from_boc(boc)?;
    let mut bits = Bits {
        cell: &root,
        offset: 0,
    };
    let depth = usize::try_from(bits.read(24)?).map_err(|_| TonError::BadStack)?;
    if depth > boc.len() {
        return Err(TonError::BadStack);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(depth)
        .map_err(|_| TonError::BadStack)?;
    let mut node = &root;
    let mut offset = 24;
    for _ in 0..depth {
        values.push(read_value(&mut Bits { cell: node, offset })?);
        node = node
            .refs()
            .first()
            .and_then(|rest| rest.cell())
            .ok_or(TonError::BadStack)?;
        offset = 0;
    }
    if node.bit_len() != offset || !node.refs().is_empty() {
        return Err(TonError::BadStack);
    }
    values.reverse();
    Ok(values)
}

/// Integer-only get-method results, with `None` for null.
///
/// # Errors
/// Rejects malformed stacks and every cell or unsupported value.
pub fn parse_int_stack(boc: &[u8]) -> Result<Vec<Option<TvmIntV1>>, TonError> {
    parse_stack(boc)?
        .into_iter()
        .map(|value| match value {
            TvmStackValueV1::Null => Ok(None),
            TvmStackValueV1::Integer(value) => Ok(Some(value)),
            TvmStackValueV1::Cell(_) => Err(TonError::BadStack),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_burn_body_retains_exact_query_amount_owner_and_recipient() {
        let body = burn_body(19, 1, &[0x42; 32], &[0x07; 34]).unwrap();
        assert_eq!(&body.data()[..4], &0x595f_07bcu32.to_be_bytes());
        assert_eq!(&body.data()[4..12], &19u64.to_be_bytes());
        assert_eq!(body.bit_len(), 32 + 64 + 4 + 8 + 267 + 1);
        assert_eq!(body.refs().len(), 1);
        assert_eq!(
            body.refs()[0].hash(),
            burn_payload_cell(&[0x07; 34]).unwrap().hash()
        );
        assert!(burn_body(1, 0, &[1; 32], &[2; 34]).is_err());
        assert!(burn_body(1, 1u128 << 96, &[1; 32], &[2; 34]).is_err());
        assert!(burn_body(1, 1, &[1; 32], &[]).is_err());
        assert_ne!(
            body.hash(),
            burn_body(20, 1, &[0x42; 32], &[0x07; 34]).unwrap().hash()
        );
    }

    #[test]
    fn burn_payloads_match_wallet_and_minter_admission() {
        use iroha_sccp::v1::{
            constants::MAX_TAIRA_ACCOUNT_BYTES, destination::check_ton_burn_payload,
        };

        for len in [1, 127, 128, MAX_TAIRA_ACCOUNT_BYTES] {
            let recipient = vec![0x42; len];
            let payload = burn_payload_cell(&recipient).expect("admitted recipient");
            let imported = cell_from_boc(&payload.to_boc().unwrap()).unwrap();
            assert_eq!(check_ton_burn_payload(Some(&imported)), Ok(recipient));
        }
        assert_eq!(
            burn_payload_cell(&[]),
            Err(TonError::Cell(TonCellError::BadSnake))
        );
        assert_eq!(
            burn_payload_cell(&[0x42; MAX_TAIRA_ACCOUNT_BYTES + 1]),
            Err(TonError::Cell(TonCellError::SnakeTooLong))
        );
    }

    #[test]
    fn unsigned_stack_preserves_full_nonce_range() {
        let values = [0, 1, i64::MAX as u64, (i64::MAX as u64) + 1, u64::MAX];
        let actual = parse_int_stack(&stack_of_uints(&values).unwrap()).unwrap();
        assert_eq!(
            actual
                .into_iter()
                .map(|value| value.unwrap().to_u64().unwrap())
                .collect::<Vec<_>>(),
            values
        );
        assert!(
            parse_int_stack(&stack_of_uints(&[]).unwrap())
                .unwrap()
                .is_empty()
        );
    }

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
        // The maximum recovery book funds a 95.28 TON floor, plus 25% and
        // initialization headroom: about 119.20 TON at mainnet prices.
        assert_eq!(
            minter_deploy_value(),
            95_277_832_032 + 23_819_458_008 + 100_000_000
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
        assert_eq!(
            wallet_v5_envelope(&boc).unwrap(),
            WalletEnvelopeV1 {
                wallet: [2; 32],
                wallet_id: WALLET_V5R1_MAINNET_ID,
                seqno: 3,
                valid_until: 1_900_000_000,
            }
        );
        assert!(wallet_v5_envelope(&message.to_boc().unwrap()).is_err());
        assert!(wallet_v5_envelope(&boc[..boc.len() - 1]).is_err());
        let external = cell_from_boc(&boc).expect("parses");
        let request = external.refs()[0].cell().expect("body");
        assert_eq!(request.bit_len(), 32 * 4 + 2 + 512);
        assert_eq!(&request.data()[..4], &0x7369_676e_u32.to_be_bytes());
        let unsigned = wallet_v5_unsigned_request(
            WALLET_V5R1_MAINNET_ID,
            3,
            1_900_000_000,
            &[(message.clone(), SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
        .unwrap();
        assert_eq!(unsigned.bit_len(), 130);
        assert_eq!(unsigned.refs(), request.refs());
        let mut signature = [0_u8; 64];
        for bit in 0..512 {
            let source = 130 + bit;
            signature[bit / 8] |=
                ((request.data()[source / 8] >> (7 - source % 8)) & 1) << (7 - bit % 8);
        }
        key.key
            .verifying_key()
            .verify_strict(
                unsigned.hash(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .unwrap();
        let changed = wallet_v5_unsigned_request(
            WALLET_V5R1_MAINNET_ID,
            4,
            1_900_000_000,
            &[(message, SEND_MODE_PAY_FEES_SEPARATELY_IGNORE_ERRORS)],
        )
        .unwrap();
        assert!(
            key.key
                .verifying_key()
                .verify_strict(
                    changed.hash(),
                    &ed25519_dalek::Signature::from_bytes(&signature)
                )
                .is_err()
        );
        assert!(wallet_v5_transfer(&[2; 32], 1, 3, 1, &[], &key).is_err());
    }

    #[test]
    fn recovery_row_preserves_original_cause_across_only_mutable_progress_fields() {
        let row = |stage, phase, attempt, nonce, tail: Cell| {
            let mut cell = CellBuilder::new();
            cell.store_uint(stage, 3)
                .unwrap()
                .store_uint(phase, 2)
                .unwrap()
                .store_uint(attempt, 64)
                .unwrap()
                .store_uint(nonce, 64)
                .unwrap()
                .store_uint(73, 96)
                .unwrap()
                .store_uint(1, 10)
                .unwrap()
                .store_uint(0, 64)
                .unwrap()
                .store_uint(19, 64)
                .unwrap()
                .store_uint(0, 2)
                .unwrap()
                .store_ref(tail)
                .unwrap();
            cell.build()
        };
        let tail = init_body(5).unwrap();
        let original = recovery_row(&row(2, 2, 1, 7, tail.clone())).unwrap();
        let retry = recovery_row(&row(2, 0, 2, 7, tail.clone())).unwrap();
        assert_eq!(original.identity, retry.identity);
        assert_ne!(
            (original.phase, original.attempt),
            (retry.phase, retry.attempt)
        );
        let stage = recovery_row(&row(3, 0, 1, 7, tail.clone())).unwrap();
        assert_eq!(stage.identity, original.identity);
        assert_ne!(stage.stage, original.stage);
        assert_ne!(
            recovery_row(&row(2, 2, 1, 8, tail.clone()))
                .unwrap()
                .identity,
            original.identity
        );
        assert_ne!(
            recovery_row(&row(2, 2, 1, 7, init_body(6).unwrap()))
                .unwrap()
                .identity,
            original.identity
        );
        assert!(recovery_row(&row(0, 0, 0, 7, tail.clone())).is_err());
        assert!(recovery_row(&tail).is_err());
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
        assert!(void_frozen_body(511, 2, 1, &[3; 32]).is_err());
        assert!(void_frozen_body(u64::MAX, 2, 1, &[3; 32]).is_err());
        assert!(void_frozen_body(512, 512, 1, &[3; 32]).is_ok());
        assert!(void_frozen_body(u64::MAX, 1, 1, &[3; 32]).is_ok());
    }
}

#[cfg(test)]
#[path = "ton/current_tests.rs"]
mod current_tests;

#[cfg(test)]
#[path = "ton/golden_tests.rs"]
mod golden_tests;
