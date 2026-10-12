//! TON destination encodings (spec §5.3.2, §5.3.3, §7.1, §7.2).
//!
//! Minter message bodies built from verified bundles and rotation plans (`sccp_finalize*`,
//! `sccp_void_*`, `sccp_checkpoint`, `sccp_apply_control*`, `sccp_init`, `sccp_deploy_buckets`,
//! `sccp_retry`), internal messages, wallet-v5 (`v5r1`) external messages signed with an
//! owner-only Ed25519 key file, the TVM stack encoding of get-method arguments and results, and
//! the values a sender attaches (§5.3.5): a margin over the minter's quotes and the deployment
//! funding of `MINTER_FLOOR`. Current committee keys come from storage; a key-changing checkpoint supplies successor keys.

use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use iroha_sccp::v1::{
    destination::{
        BlockRefV1, CertificateSourceV1, CheckpointRefV1, ControlProofV1, MessageProofV1,
        MessagePurposeV1, TairaCertificateV1,
    },
    ton_cell::{
        Cell, CellBuilder, TonCellError, cell_from_boc, hash_chunks, snake_bytes,
        ton_minter_floor_at_mainnet_prices,
    },
};
use zeroize::Zeroizing;

use super::{
    bundle::VerifiedMessageBundleV1,
    control::VerifiedControlBundleV1,
    evm::{KeyFileError, load_key_file_secret},
    rotation::VerifiedCheckpointV1,
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
    /// The proof was qualified for another destination profile.
    WrongNetwork,
    /// A native certificate, path or committee does not fit its TL-B field.
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
            Self::WrongNetwork => {
                formatter.write_str("proof evidence is not for a TON destination")
            }
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

/// The exact 221-byte `X`, split into the canonical 872-bit head and 896-bit tail.
///
/// # Errors
/// Refuses any other header length before slicing or allocating cells.
pub fn header_cell(bytes: &[u8]) -> Result<Cell, TonError> {
    if bytes.len() != 221 {
        return Err(TonError::FieldTooLarge);
    }
    let mut tail = CellBuilder::new();
    tail.store_bytes(&bytes[109..])?;
    let mut head = CellBuilder::new();
    head.store_bytes(&bytes[..109])?.store_ref(tail.build())?;
    Ok(head.build())
}
/// Native `TairaCert`: compressed aggregate, signer word, exact QC prefix and exact X.
/// This encoder preserves bytes; certificate authentication belongs to preflight.
///
/// # Errors
/// Rejects non-exact native fields before building cells.
pub fn certificate_cell(certificate: &TairaCertificateV1) -> Result<Cell, TonError> {
    if certificate.qc.len() != 116 || certificate.ton_signature.len() != 96 {
        return Err(TonError::FieldTooLarge);
    }
    let mut qc = CellBuilder::new();
    qc.store_bytes(&certificate.qc[..112])?;
    let mut cell = CellBuilder::new();
    cell.store_bytes(&certificate.ton_signature)?
        .store_bytes(&certificate.qc[112..])?
        .store_ref(qc.build())?
        .store_ref(header_cell(&certificate.header)?)?;
    Ok(cell.build())
}
/// Stored-checkpoint reference: one reference to the exact X head.
///
/// # Errors
/// Refuses a non-exact header length.
pub fn checkpoint_ref_cell(reference: &CheckpointRefV1) -> Result<Cell, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_ref(header_cell(&reference.header)?)?;
    Ok(cell.build())
}
/// Maximal two-key chunks of canonical compressed BLS keys, each with a Maybe continuation.
///
/// # Errors
/// Rejects a noncanonical native committee geometry/order before encoding.
pub fn key_chunks(keys: &[[u8; 48]]) -> Result<Cell, TonError> {
    if iroha_sccp::v1::committee::quorum(keys.len()).is_none()
        || !iroha_sccp::v1::committee::is_canonical_order(keys)
    {
        return Err(TonError::FieldTooLarge);
    }
    let mut next = None;
    for chunk in keys.chunks(2).rev() {
        let mut cell = CellBuilder::new();
        for key in chunk {
            cell.store_bytes(key)?;
        }
        cell.store_maybe_ref(next.take())?;
        next = Some(cell.build());
    }
    next.ok_or(TonError::FieldTooLarge)
}
fn path_len(path: &[[u8; 32]], maximum: usize) -> Result<u128, TonError> {
    if path.len() > maximum {
        return Err(TonError::FieldTooLarge);
    }
    u8::try_from(path.len())
        .map(u128::from)
        .map_err(|_| TonError::FieldTooLarge)
}
/// Native block reference: direct or historical proof geometry lives in one tuple.
///
/// # Errors
/// Refuses a history path exceeding 32 siblings.
pub fn block_ref_cell(block: &BlockRefV1) -> Result<Cell, TonError> {
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(block.height), 64)?
        .store_bytes(&block.sccp_root)?
        .store_uint(u128::from(block.message_count), 32)?
        .store_uint(u128::from(block.history_index), 64)?
        .store_uint(path_len(&block.history_path, 32)?, 8)?
        .store_maybe_ref(hash_chunks(&block.history_path)?)?;
    Ok(cell.build())
}
/// Native message proof: leaf index, path length, payload, path and block references.
///
/// # Errors
/// Refuses payloads exceeding 4096 bytes and block paths exceeding nine siblings.
pub fn message_proof_cell(proof: &MessageProofV1) -> Result<Cell, TonError> {
    if proof.payload.len() > 4096 {
        return Err(TonError::FieldTooLarge);
    }
    let mut cell = CellBuilder::new();
    cell.store_uint(u128::from(proof.leaf_index), 32)?
        .store_uint(path_len(&proof.path, 9)?, 8)?
        .store_ref(snake_bytes(&proof.payload)?)?
        .store_maybe_ref(hash_chunks(&proof.path)?)?
        .store_ref(block_ref_cell(&proof.block)?)?;
    Ok(cell.build())
}
/// Native complete control proof, including track, both pause mechanisms and effect identity.
///
/// # Errors
/// Refuses nonboolean pause bytes and paths exceeding the native bounds.
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
        .store_uint(path_len(&control.path, 9)?, 8)?
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

/// Encode the explicitly selected native finalize form, with history inside its block ref.
///
/// # Errors
/// Refuses the wrong verified purpose or a malformed cell field.
pub fn finalize_body(
    bundle: &VerifiedMessageBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.network() != iroha_data_model::bridge::SccpNetworkV1::TonMainnet {
        return Err(TonError::WrongNetwork);
    }

    if bundle.purpose() != MessagePurposeV1::Finalize {
        return Err(TonError::WrongPurpose);
    }
    let (op, source) = match bundle.source() {
        CertificateSourceV1::Inline(certificate) => {
            (OP_SCCP_FINALIZE, certificate_cell(certificate)?)
        }
        CertificateSourceV1::Checkpoint(reference) => {
            (OP_SCCP_FINALIZE_CHECKPOINT, checkpoint_ref_cell(reference)?)
        }
    };
    let mut body = header(op, query_id, response)?;
    body.store_ref(source)?
        .store_ref(message_proof_cell(bundle.proof())?)?;
    Ok(body.build())
}
/// Encode the explicitly selected native expired-transfer form and authenticated nonce.
///
/// # Errors
/// Refuses the wrong verified purpose or a malformed cell field.
pub fn void_expired_body(
    bundle: &VerifiedMessageBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.network() != iroha_data_model::bridge::SccpNetworkV1::TonMainnet {
        return Err(TonError::WrongNetwork);
    }

    if bundle.purpose() != MessagePurposeV1::VoidExpired {
        return Err(TonError::WrongPurpose);
    }
    let (op, source) = match bundle.source() {
        CertificateSourceV1::Inline(certificate) => {
            (OP_SCCP_VOID_EXPIRED, certificate_cell(certificate)?)
        }
        CertificateSourceV1::Checkpoint(reference) => (
            OP_SCCP_VOID_EXPIRED_CHECKPOINT,
            checkpoint_ref_cell(reference)?,
        ),
    };
    let mut body = header(op, query_id, response)?;
    body.store_uint(u128::from(bundle.nonce()), 64)?
        .store_ref(source)?
        .store_ref(message_proof_cell(bundle.proof())?)?;
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
            .is_none_or(|last| first_nonce / 512 != last / 512)
    {
        return Err(TonError::FieldTooLarge);
    }
    let mut body = header(OP_SCCP_VOID_FROZEN, query_id, response)?;
    body.store_uint(u128::from(first_nonce), 64)?
        .store_uint(u128::from(count), 16)?;
    Ok(body.build())
}

/// One native `sccp_checkpoint` with verified successor keys only when the rotation needs them.
///
/// # Errors
/// Refuses malformed native cell fields.
pub fn checkpoint_body(
    checkpoint: &VerifiedCheckpointV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if checkpoint.flavor() != iroha_sccp::v1::destination::DestinationFlavor::Ton {
        return Err(TonError::WrongNetwork);
    }

    let next_keys = checkpoint.next_keys().map(key_chunks).transpose()?;
    let mut body = header(OP_SCCP_CHECKPOINT, query_id, response)?;
    body.store_ref(certificate_cell(checkpoint.certificate())?)?
        .store_maybe_ref(next_keys)?;
    Ok(body.build())
}
/// Encode the explicitly selected native control form and complete control proof.
///
/// # Errors
/// Refuses malformed native cell fields.
pub fn apply_control_body(
    bundle: &VerifiedControlBundleV1,
    query_id: u64,
    response: &TonAccountV1,
) -> Result<Cell, TonError> {
    if bundle.network() != iroha_data_model::bridge::SccpNetworkV1::TonMainnet {
        return Err(TonError::WrongNetwork);
    }

    let (op, source) = match bundle.source() {
        CertificateSourceV1::Inline(certificate) => {
            (OP_SCCP_APPLY_CONTROL, certificate_cell(certificate)?)
        }
        CertificateSourceV1::Checkpoint(reference) => (
            OP_SCCP_APPLY_CONTROL_CHECKPOINT,
            checkpoint_ref_cell(reference)?,
        ),
    };
    let mut body = header(op, query_id, response)?;
    body.store_ref(source)?
        .store_ref(control_proof_cell(bundle.proof())?)?;
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

/// Encode full-width unsigned nonce arguments as canonical positive TVM `int257` values.
///
/// # Errors
/// Returns [`TonError::FieldTooLarge`] above 64 arguments, or a cell encoding failure.
pub fn stack_of_uints(values: &[u64]) -> Result<Vec<u8>, TonError> {
    if values.len() > 64 {
        return Err(TonError::FieldTooLarge);
    }
    let mut list = CellBuilder::new().build();
    for &value in values {
        let mut node = CellBuilder::new();
        node.store_ref(list)?
            .store_uint(2, 8)?
            .store_uint(0, 7)?
            .store_uint(0, 1)?
            .store_uint(0, 128)?
            .store_uint(u128::from(value), 128)?;
        list = node.build();
    }
    let mut root = CellBuilder::new();
    root.store_uint(values.len() as u128, 24)?;
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

/// A bounded native get-method stack value. Unsupported TVM values are refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TvmStackValueV1 {
    /// `vm_stk_null#00`.
    Null,
    /// A signed tiny integer or canonical `int257` carrier.
    Int(TvmIntV1),
    /// `vm_stk_cell#03`; the complete referenced cell is retained.
    Cell(Cell),
}

/// Parse the integer/null/cell surface used by native SCCP get methods, bottom first.
///
/// This decodes DATA only. The caller supplies the independent account/block observation.
/// The input is bounded to 64 KiB and 64 values before allocation; list depth, exact bit and
/// reference consumption, and the terminal empty list are mandatory. No alternative stack
/// layout is inferred and unsupported tags are refused.
///
/// # Errors
/// Returns [`TonError::BadStack`] for malformed, oversized or unsupported stacks.
pub fn parse_native_stack(boc: &[u8]) -> Result<Vec<TvmStackValueV1>, TonError> {
    if boc.len() > 65_536 {
        return Err(TonError::BadStack);
    }
    let root = cell_from_boc(boc)?;
    let mut bits = Bits {
        cell: &root,
        offset: 0,
    };
    let depth = usize::try_from(bits.read(24)?).map_err(|_| TonError::BadStack)?;
    if depth > 64 {
        return Err(TonError::BadStack);
    }
    let mut values = Vec::with_capacity(depth);
    let mut node = &root;
    let mut offset = 24;
    for _ in 0..depth {
        let mut reader = Bits { cell: node, offset };
        let tag = reader.read(8)?;
        let value = if tag == 3 {
            if node.refs().len() != 2 {
                return Err(TonError::BadStack);
            }
            TvmStackValueV1::Cell(node.refs()[1].cell().ok_or(TonError::BadStack)?.clone())
        } else {
            if node.refs().len() != 1 {
                return Err(TonError::BadStack);
            }
            reader.offset = offset;
            match read_value(&mut reader)? {
                None => TvmStackValueV1::Null,
                Some(value) => TvmStackValueV1::Int(value),
            }
        };
        if reader.offset != node.bit_len() {
            return Err(TonError::BadStack);
        }
        values.push(value);
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

/// The integers of a strictly decoded native get-method result stack, bottom first.
///
/// # Errors
/// Returns [`TonError::BadStack`] for a malformed stack or a non-integer entry.
pub fn parse_int_stack(boc: &[u8]) -> Result<Vec<Option<TvmIntV1>>, TonError> {
    parse_native_stack(boc)?
        .into_iter()
        .map(|value| match value {
            TvmStackValueV1::Null => Ok(None),
            TvmStackValueV1::Int(value) => Ok(Some(value)),
            TvmStackValueV1::Cell(_) => Err(TonError::BadStack),
        })
        .collect()
}

/// Decode the exact maximal two-key `KeyChunk` chain returned by `get_sccp_committee`.
///
/// Root binding and curve validity belong to the independently pinned destination
/// observation. This parser checks committee count geometry and consumes every bit/reference.
///
/// # Errors
/// Returns [`TonError::BadStack`] for invalid count, chunk geometry, links or trailing data.
pub fn parse_key_chunks(cell: &Cell, count: usize) -> Result<Vec<[u8; 48]>, TonError> {
    if !iroha_sccp::v1::committee::is_valid_committee_size(count) {
        return Err(TonError::BadStack);
    }
    let mut keys = Vec::with_capacity(count);
    let mut node = cell;
    while keys.len() < count {
        let take = (count - keys.len()).min(2);
        let mut bits = Bits {
            cell: node,
            offset: 0,
        };
        for _ in 0..take {
            let mut key = [0; 48];
            for part in key.chunks_exact_mut(16) {
                part.copy_from_slice(&bits.read(128)?.to_be_bytes());
            }
            keys.push(key);
        }
        let more = bits.read(1)? != 0;
        if bits.offset != node.bit_len()
            || more != (keys.len() < count)
            || node.refs().len() != usize::from(more)
        {
            return Err(TonError::BadStack);
        }
        if more {
            node = node.refs()[0].cell().ok_or(TonError::BadStack)?;
        }
    }
    Ok(keys)
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
        let certificate = TairaCertificateV1 {
            qc: vec![1; 116],
            header: vec![2; 221],
            ton_signature: vec![3; 96],
            ..TairaCertificateV1::default()
        };
        let cell = certificate_cell(&certificate).expect("native certificate");
        assert_eq!(cell.bit_len(), 800);
        assert_eq!(cell.refs().len(), 2);
        let qc = cell.refs()[0].cell().expect("QC");
        assert_eq!(qc.bit_len(), 896);
        assert_eq!(qc.refs().len(), 0);
        let x = cell.refs()[1].cell().expect("X head");
        assert_eq!(x.bit_len(), 872);
        assert_eq!(x.refs().len(), 1);
        assert_eq!(x.refs()[0].cell().expect("X tail").bit_len(), 896);
        assert_eq!(&cell.data()[96..100], &certificate.qc[112..116]);
        assert_eq!(qc.data(), &certificate.qc[..112]);
    }
    #[test]
    fn native_ton_cells_preserve_exact_bytes_and_reject_field_overflow() {
        use crate::pure::test_support::{Fixture, NETWORK};
        use iroha_sccp::v1::destination::DestinationFlavor;
        let f = Fixture::new(DestinationFlavor::Ton);
        let b = f.message(true);
        let certificate = b.certificate.to_destination_certificate().unwrap();
        let encoded = certificate_cell(&certificate).unwrap();
        assert_eq!(
            encoded.data(),
            [&certificate.ton_signature[..], &certificate.qc[112..]].concat()
        );
        assert_eq!(
            encoded.refs()[0].cell().unwrap().data(),
            &certificate.qc[..112]
        );
        let head = encoded.refs()[1].cell().unwrap();
        assert_eq!(
            [head.data(), head.refs()[0].cell().unwrap().data()].concat(),
            certificate.header
        );
        assert_eq!(cell_from_boc(&encoded.to_boc().unwrap()).unwrap(), encoded);
        let reference = checkpoint_ref_cell(&CheckpointRefV1 {
            header: certificate.header.clone(),
        })
        .unwrap();
        assert_eq!((reference.bit_len(), reference.refs().len()), (0, 1));
        assert_eq!(reference.refs()[0].cell().unwrap(), head);
        for length in [0, 220, 222] {
            assert_eq!(header_cell(&vec![0; length]), Err(TonError::FieldTooLarge));
        }
        let mut bad = certificate.clone();
        bad.qc.pop();
        assert_eq!(certificate_cell(&bad), Err(TonError::FieldTooLarge));
        let mut bad = certificate;
        bad.ton_signature.push(0);
        assert_eq!(certificate_cell(&bad), Err(TonError::FieldTooLarge));
        let proof = b.message_proof(&NETWORK, &b.message_id).unwrap();
        let block = block_ref_cell(&proof.block).unwrap();
        assert_eq!((block.bit_len(), block.refs().len()), (425, 1));
        let message = message_proof_cell(&proof).unwrap();
        assert_eq!((message.bit_len(), message.refs().len()), (41, 3));
        assert_eq!(message.refs()[2].cell().unwrap(), &block);
        assert_eq!(cell_from_boc(&message.to_boc().unwrap()).unwrap(), message);
        let mut bad = proof.clone();
        bad.payload.resize(4097, 0);
        assert_eq!(message_proof_cell(&bad), Err(TonError::FieldTooLarge));
        let mut bad = proof.clone();
        bad.path.resize(10, [0; 32]);
        assert_eq!(message_proof_cell(&bad), Err(TonError::FieldTooLarge));
        let mut bad = proof.block;
        bad.history_path.resize(33, [0; 32]);
        assert_eq!(block_ref_cell(&bad), Err(TonError::FieldTooLarge));
        bad.history_path.truncate(32);
        assert!(block_ref_cell(&bad).is_ok());
    }

    #[test]
    fn native_ton_key_chunks_and_full_control_leaf_are_exact() {
        use crate::pure::test_support::{Fixture, NOW};
        use iroha_sccp::v1::destination::DestinationFlavor;
        let f = Fixture::new(DestinationFlavor::Ton);
        let keys: Vec<_> = f.members.iter().map(|(key, _)| *key).collect();
        let chunk = key_chunks(&keys).unwrap();
        assert_eq!((chunk.bit_len(), chunk.refs().len()), (769, 1));
        assert_eq!(&chunk.data()[..96], keys[..2].concat());
        let last = chunk.refs()[0].cell().unwrap();
        assert_eq!((last.bit_len(), last.refs().len()), (769, 0));
        assert_eq!(&last.data()[..96], keys[2..].concat());
        assert_eq!(chunk.data()[96], 0x80);
        assert_eq!(last.data()[96], 0);
        assert_eq!(cell_from_boc(&chunk.to_boc().unwrap()).unwrap(), chunk);
        assert_eq!(key_chunks(&keys[..3]), Err(TonError::FieldTooLarge));
        let mut wrong = keys.clone();
        wrong.swap(0, 1);
        assert_eq!(key_chunks(&wrong), Err(TonError::FieldTooLarge));
        let mut wrong = keys;
        wrong[1] = wrong[0];
        assert_eq!(key_chunks(&wrong), Err(TonError::FieldTooLarge));
        let b = f.control(true, false, NOW + 1000);
        let proof = b.control_proof(f.deployment.network, 1).unwrap();
        let cell = control_proof_cell(&proof).unwrap();
        assert_eq!((cell.bit_len(), cell.refs().len()), (690, 2));
        let mut bits = Bits {
            cell: &cell,
            offset: 0,
        };
        assert_eq!(bits.read(64).unwrap(), 4);
        assert_eq!(bits.read(8).unwrap(), 2);
        assert_eq!(bits.read(1).unwrap(), 0);
        assert_eq!(bits.read(64).unwrap(), u128::from(NOW + 1000));
        for expected in [proof.certificate_id, proof.effect_hash] {
            assert_eq!(
                bits.read(128).unwrap(),
                u128::from_be_bytes(expected[..16].try_into().unwrap())
            );
            assert_eq!(
                bits.read(128).unwrap(),
                u128::from_be_bytes(expected[16..].try_into().unwrap())
            );
        }
        assert_eq!(bits.read(32).unwrap(), u128::from(proof.leaf_index));
        assert_eq!(bits.read(8).unwrap(), proof.path.len() as u128);
        assert_eq!(bits.read(1).unwrap(), 1);
        assert_eq!(bits.offset, cell.bit_len());
        assert_eq!(cell_from_boc(&cell.to_boc().unwrap()).unwrap(), cell);
        let mut bad = proof.clone();
        bad.parliament_paused = 2;
        assert_eq!(control_proof_cell(&bad), Err(TonError::FieldTooLarge));
        let mut bad = proof;
        bad.path.resize(10, [0; 32]);
        assert_eq!(control_proof_cell(&bad), Err(TonError::FieldTooLarge));
    }

    #[test]
    fn native_ton_message_bodies_use_explicit_sources_and_purposes() {
        use crate::pure::{
            bundle::{BundleSourceV1, verify_message_bundle},
            control::verify_control_bundle,
            test_support::{DAY, Fixture, NOW, T0, reads},
        };
        use iroha_sccp::v1::destination::DestinationFlavor;
        let f = Fixture::new(DestinationFlavor::Ton);
        for historical in [false, true] {
            let b = f.message(historical);
            for (source, stored, finalize_op, void_op, control_op) in [
                (
                    BundleSourceV1::Inline,
                    false,
                    OP_SCCP_FINALIZE,
                    OP_SCCP_VOID_EXPIRED,
                    OP_SCCP_APPLY_CONTROL,
                ),
                (
                    BundleSourceV1::Checkpoint,
                    true,
                    OP_SCCP_FINALIZE_CHECKPOINT,
                    OP_SCCP_VOID_EXPIRED_CHECKPOINT,
                    OP_SCCP_APPLY_CONTROL_CHECKPOINT,
                ),
            ] {
                let view = f.observation(NOW, reads(&b.certificate, stored));
                let verified = verify_message_bundle(
                    &b,
                    &b.message_id,
                    &view,
                    source,
                    MessagePurposeV1::Finalize,
                )
                .unwrap();
                let body = finalize_body(&verified, 7, &[0x31; 32]).unwrap();
                assert_eq!(&body.data()[..4], &finalize_op.to_be_bytes());
                assert_eq!((body.bit_len(), body.refs().len()), (363, 2));
                assert_eq!(cell_from_boc(&body.to_boc().unwrap()).unwrap(), body);
                assert_eq!(
                    void_expired_body(&verified, 7, &[0x31; 32]),
                    Err(TonError::WrongPurpose)
                );
                let expired = f.observation(T0 + DAY + 1, reads(&b.certificate, stored));
                let void = verify_message_bundle(
                    &b,
                    &b.message_id,
                    &expired,
                    source,
                    MessagePurposeV1::VoidExpired,
                )
                .unwrap();
                let body = void_expired_body(&void, 8, &[0x31; 32]).unwrap();
                assert_eq!(&body.data()[..4], &void_op.to_be_bytes());
                assert_eq!((body.bit_len(), body.refs().len()), (427, 2));
                let mut nonce = Bits {
                    cell: &body,
                    offset: 363,
                };
                assert_eq!(nonce.read(64).unwrap(), 5);
                assert_eq!(
                    finalize_body(&void, 8, &[0x31; 32]),
                    Err(TonError::WrongPurpose)
                );
                let b = f.control(historical, false, NOW + 1000);
                let view = f.observation(NOW, reads(&b.certificate, stored));
                let verified = verify_control_bundle(&b, &view, source).unwrap();
                let body = apply_control_body(&verified, 9, &[0x31; 32]).unwrap();
                assert_eq!(&body.data()[..4], &control_op.to_be_bytes());
                assert_eq!((body.bit_len(), body.refs().len()), (363, 2));
                assert_eq!(body.refs()[1].cell().unwrap().bit_len(), 690);
            }
        }
        for (first, count) in [(511, 2), (u64::MAX, 2), (0, 513)] {
            assert_eq!(
                void_frozen_body(first, count, 1, &[1; 32]),
                Err(TonError::FieldTooLarge)
            );
        }
        assert!(void_frozen_body(512, 512, 1, &[1; 32]).is_ok());
    }

    #[test]
    fn native_ton_checkpoints_bind_successor_keys_and_refuse_evm_qualification() {
        use crate::pure::{
            bundle::{BundleSourceV1, verify_message_bundle},
            control::verify_control_bundle,
            rotation::verify_rotation_steps,
            test_support::{Fixture, NOW, reads},
        };
        use iroha_sccp::v1::{committee::committee_root, destination::DestinationFlavor};
        use std::collections::BTreeMap;
        for flavor in [DestinationFlavor::Ton, DestinationFlavor::Evm] {
            let f = Fixture::new(flavor);
            let rotations = f.rotations(1);
            let view = f.observation(NOW, reads(&rotations[0].certificate, false));
            let plan = verify_rotation_steps(&rotations, None, &view, 8).unwrap();
            let checkpoint = &plan.checkpoints()[0];
            if flavor == DestinationFlavor::Ton {
                let body = checkpoint_body(checkpoint, 10, &[0x31; 32]).unwrap();
                assert_eq!(&body.data()[..4], &OP_SCCP_CHECKPOINT.to_be_bytes());
                assert_eq!((body.bit_len(), body.refs().len()), (364, 1));
                assert!(checkpoint.next_keys().is_none());
                // A genuine old-committee certificate authenticates a distinct canonical successor.
                let mut fields = f.fields(150, 7);
                fields.flags |= iroha_sccp::v1::finality::FLAG_ROTATION;
                fields.validity_ms = 14 * crate::pure::test_support::DAY;
                // Regenerate keys with a separate deterministic BLS seed; never take them as the pin.
                let mut next: Vec<[u8; 48]> = (0_u8..4)
                    .map(|i| {
                        let pair = iroha_crypto::KeyPair::from_seed(
                            vec![99, i],
                            iroha_crypto::Algorithm::BlsNormal,
                        );
                        let (_, raw) = pair.public_key().to_bytes();
                        <[u8; 48]>::try_from(raw).unwrap()
                    })
                    .collect();
                next.sort();
                fields.next_committee_root = committee_root(&next).unwrap();
                let rotation = iroha_sccp::api::SccpRotationV1 {
                    certificate: f.certificate(&fields, 7),
                    next_committee: next.clone(),
                };
                let view = f.observation(NOW, BTreeMap::new());
                let plan = verify_rotation_steps(&[rotation], None, &view, 8).unwrap();
                let checkpoint = &plan.checkpoints()[0];
                assert_eq!(checkpoint.next_keys(), Some(next.as_slice()));
                let body = checkpoint_body(checkpoint, 11, &[0x31; 32]).unwrap();
                assert_eq!((body.bit_len(), body.refs().len()), (364, 2));
                assert_eq!(body.refs()[1].cell().unwrap(), &key_chunks(&next).unwrap());
                assert_eq!(cell_from_boc(&body.to_boc().unwrap()).unwrap(), body);
            } else {
                assert_eq!(
                    checkpoint_body(checkpoint, 10, &[0x31; 32]),
                    Err(TonError::WrongNetwork)
                );
                let b = f.message(false);
                let view = f.observation(NOW, reads(&b.certificate, false));
                let verified = verify_message_bundle(
                    &b,
                    &b.message_id,
                    &view,
                    BundleSourceV1::Inline,
                    MessagePurposeV1::Finalize,
                )
                .unwrap();
                assert_eq!(
                    finalize_body(&verified, 10, &[0x31; 32]),
                    Err(TonError::WrongNetwork)
                );
                let b = f.control(false, true, 0);
                let view = f.observation(NOW, reads(&b.certificate, false));
                let verified = verify_control_bundle(&b, &view, BundleSourceV1::Inline).unwrap();
                assert_eq!(
                    apply_control_body(&verified, 10, &[0x31; 32]),
                    Err(TonError::WrongNetwork)
                );
            }
        }
    }
    #[test]
    fn native_stack_preserves_cells_and_rejects_ambiguous_shapes() {
        let cell = CellBuilder::new().build();
        let rest = CellBuilder::new().build();
        let mut root = CellBuilder::new();
        root.store_uint(1, 24)
            .unwrap()
            .store_ref(rest)
            .unwrap()
            .store_uint(3, 8)
            .unwrap()
            .store_ref(cell.clone())
            .unwrap();
        let bytes = root.build().to_boc().unwrap();
        assert_eq!(
            parse_native_stack(&bytes).unwrap(),
            vec![TvmStackValueV1::Cell(cell)]
        );
        assert!(parse_int_stack(&bytes).is_err());
        root.store_bit(false).unwrap();
        assert!(parse_native_stack(&root.build().to_boc().unwrap()).is_err());
        let mut oversized = CellBuilder::new();
        oversized.store_uint(65, 24).unwrap();
        assert!(parse_native_stack(&oversized.build().to_boc().unwrap()).is_err());
        let mut trailing = CellBuilder::new();
        trailing
            .store_uint(0, 24)
            .unwrap()
            .store_bit(false)
            .unwrap();
        assert!(parse_native_stack(&trailing.build().to_boc().unwrap()).is_err());
        let mut extra_ref = CellBuilder::new();
        extra_ref
            .store_uint(0, 24)
            .unwrap()
            .store_ref(CellBuilder::new().build())
            .unwrap();
        assert!(parse_native_stack(&extra_ref.build().to_boc().unwrap()).is_err());
        assert!(parse_native_stack(&vec![0; 65_537]).is_err());
    }

    #[test]
    fn native_key_chunks_consume_exact_geometry() {
        let keys = vec![[1; 48], [2; 48], [3; 48], [4; 48]];
        let cell = iroha_sccp::v1::ton_cell::key_chunks(&keys).unwrap();
        assert_eq!(parse_key_chunks(&cell, 4).unwrap(), keys);
        assert!(parse_key_chunks(&cell, 7).is_err());
        assert!(parse_key_chunks(&cell, 3).is_err());
        let mut trailing = CellBuilder::new();
        trailing
            .store_bytes(&keys[0])
            .unwrap()
            .store_bytes(&keys[1])
            .unwrap()
            .store_bit(false)
            .unwrap();
        assert!(parse_key_chunks(&trailing.build(), 4).is_err());
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
        assert!(stack_of_uints(&[0; 65]).is_err());
    }
}
