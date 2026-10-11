//! EVM destination transactions (spec §5.2.2, §7.1 step 7, §7.2 step 2, §7.3, §7.4, §8).
//!
//! - Calldata of every state-changing `SccpTairaXor` entry point, built with
//!   `iroha_sccp::v1::evm_abi` from verified inputs only: `finalizeFromTaira` and its historical
//!   form, `rotateRosters` in batches of at most 16, `applyControl` and its historical form,
//!   `voidExpired` and its historical form, `voidFrozen` and the canonical `transferToTaira`.
//! - EIP-1559 (type 2) transactions for Ethereum (chain id 1) and BSC (chain id 56): canonical
//!   RLP with an empty access list, and secp256k1 signing over
//!   `keccak256(0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to,
//!   value, data, accessList]))` with RFC 6979 nonces, low-S and `yParity ∈ {0, 1}`.
//! - `--emit` export of the unsigned transaction for an external signer: the raw
//!   `0x02 ‖ rlp(…)` bytes, the signing hash, and QR-friendly uppercase-hex parts in the QR
//!   alphanumeric character set. A signature returned by the signer is attached with
//!   [`Eip1559TransactionV1::with_signature`], which checks its form and the recovered sender.
//! - The owner-only key-file loader: external keys come only from regular, non-symlink files of
//!   mode `0600` or stricter owned by the current user, holding the 32-byte secret as hex. Keys
//!   are never read from argv or environment variables.

use core::fmt;
use std::path::Path;

use iroha_data_model::bridge::SccpNetworkV1;
use iroha_sccp::v1::{
    constants::{
        BSC_CHAIN_ID, ETHEREUM_CHAIN_ID, MAX_TAIRA_ACCOUNT_BYTES, MAX_VOID_FROZEN_RANGE_EVM,
    },
    evm_abi::{
        TransferToTairaCallV1, apply_control_calldata as abi_apply_control,
        apply_control_historical_calldata, finalize_from_taira_calldata,
        finalize_from_taira_historical_calldata, rotate_rosters_calldata as abi_rotate_rosters,
        void_expired_calldata as abi_void_expired, void_expired_historical_calldata,
        void_frozen_calldata as abi_void_frozen,
    },
    hashes::keccak256,
    signature::{self, SignatureError},
};
use zeroize::Zeroizing;

use super::{
    bundle::{BundlePurposeV1, VerifiedMessageBundleV1},
    control::VerifiedControlBundleV1,
    rotation::RotationPlanV1,
};

/// EIP-2718 type byte of EIP-1559 transactions.
pub const EIP1559_TX_TYPE: u8 = 0x02;
/// Prefix of every QR part of an exported unsigned transaction.
pub const QR_PREFIX: &str = "SCCP-EIP1559:";
/// Largest key file accepted (a 64-digit hex secret with prefix and newline fits easily).
pub const MAX_KEY_FILE_BYTES: usize = 128;

/// Errors of the EVM encoders, transactions and key files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvmError {
    /// A bundle verified for one purpose was used for another call.
    WrongPurpose,
    /// `voidFrozen` needs `1 ≤ count ≤ 256` and `firstNonce + count ≤ 2^64`.
    BadVoidRange,
    /// `transferToTaira` needs a `taira_account` recipient of 1..=1024 bytes.
    BadRecipient,
    /// `transferToTaira` needs `0 < amount < 2^128`.
    BadAmount,
    /// EIP-1559 transactions are built for Ethereum and BSC only.
    UnsupportedNetwork(SccpNetworkV1),
    /// `maxPriorityFeePerGas > maxFeePerGas`.
    PriorityFeeAboveMaxFee,
    /// A zero gas limit.
    ZeroGasLimit,
    /// The bytes are not a canonical EIP-1559 transaction encoding.
    Rlp(&'static str),
    /// The signature is malformed or does not recover a signer.
    Signature(SignatureError),
    /// The signature recovers another address than the expected sender.
    WrongSender {
        /// The sender the signature recovers.
        recovered: [u8; 20],
    },
    /// A QR part size too small for the part header and one byte.
    QrPartTooSmall,
    /// The key file is unusable.
    KeyFile(KeyFileError),
}

impl fmt::Display for EvmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongPurpose => {
                formatter.write_str("the bundle was verified for a different destination call")
            }
            Self::BadVoidRange => {
                formatter.write_str("voidFrozen needs 1..=256 nonces that end at or below 2^64")
            }
            Self::BadRecipient => {
                formatter.write_str("the Taira recipient must be 1..=1024 account bytes")
            }
            Self::BadAmount => formatter.write_str("the amount must be in 1..2^128"),
            Self::UnsupportedNetwork(network) => write!(
                formatter,
                "EIP-1559 transactions are not built for {}",
                network.profile_key()
            ),
            Self::PriorityFeeAboveMaxFee => {
                formatter.write_str("maxPriorityFeePerGas exceeds maxFeePerGas")
            }
            Self::ZeroGasLimit => formatter.write_str("the gas limit must be nonzero"),
            Self::Rlp(reason) => write!(formatter, "invalid EIP-1559 encoding: {reason}"),
            Self::Signature(error) => write!(formatter, "transaction signature: {error}"),
            Self::WrongSender { recovered } => write!(
                formatter,
                "the signature recovers 0x{}, not the expected sender",
                hex::encode(recovered)
            ),
            Self::QrPartTooSmall => {
                formatter.write_str("a QR part must hold its header and at least one byte")
            }
            Self::KeyFile(error) => write!(formatter, "key file: {error}"),
        }
    }
}

impl std::error::Error for EvmError {}

impl From<SignatureError> for EvmError {
    fn from(error: SignatureError) -> Self {
        Self::Signature(error)
    }
}

impl From<KeyFileError> for EvmError {
    fn from(error: KeyFileError) -> Self {
        Self::KeyFile(error)
    }
}

// ---------------------------------------------------------------------------------------------
// Calldata
// ---------------------------------------------------------------------------------------------

/// `finalizeFromTaira` (direct) or `finalizeFromTairaHistorical` for a bundle verified with
/// [`BundlePurposeV1::Finalize`].
///
/// # Errors
///
/// Returns [`EvmError::WrongPurpose`] for a bundle verified for voiding.
pub fn finalize_calldata(bundle: &VerifiedMessageBundleV1) -> Result<Vec<u8>, EvmError> {
    if bundle.purpose != BundlePurposeV1::Finalize {
        return Err(EvmError::WrongPurpose);
    }
    let attested = bundle.attested.attested();
    Ok(bundle.history.as_ref().map_or_else(
        || finalize_from_taira_calldata(attested, &bundle.proof),
        |history| finalize_from_taira_historical_calldata(attested, history, &bundle.proof),
    ))
}

/// `voidExpired` or `voidExpiredHistorical` for a bundle verified with
/// [`BundlePurposeV1::VoidExpired`]; the `nonce` argument is the payload nonce.
///
/// # Errors
///
/// Returns [`EvmError::WrongPurpose`] for a bundle verified for finalization.
pub fn void_expired_calldata(bundle: &VerifiedMessageBundleV1) -> Result<Vec<u8>, EvmError> {
    if bundle.purpose != BundlePurposeV1::VoidExpired {
        return Err(EvmError::WrongPurpose);
    }
    let attested = bundle.attested.attested();
    Ok(bundle.history.as_ref().map_or_else(
        || abi_void_expired(bundle.nonce(), attested, &bundle.proof),
        |history| {
            void_expired_historical_calldata(bundle.nonce(), attested, history, &bundle.proof)
        },
    ))
}

/// `applyControl` or `applyControlHistorical` for a verified control bundle.
#[must_use]
pub fn apply_control_calldata(bundle: &VerifiedControlBundleV1) -> Vec<u8> {
    let attested = bundle.attested.attested();
    bundle.history.as_ref().map_or_else(
        || abi_apply_control(attested, &bundle.control),
        |history| apply_control_historical_calldata(attested, history, &bundle.control),
    )
}

/// One `rotateRosters` calldata per batch of at most 16 verified rotations, in order.
#[must_use]
pub fn rotate_rosters_calldata(plan: &RotationPlanV1) -> Vec<Vec<u8>> {
    plan.batches().map(abi_rotate_rosters).collect()
}

/// `voidFrozen(firstNonce, count)` with the contract's range bounds.
///
/// # Errors
///
/// Returns [`EvmError::BadVoidRange`] unless `1 ≤ count ≤ 256` and the range ends at or below
/// `2^64`.
pub fn void_frozen_calldata(first_nonce: u64, count: u64) -> Result<Vec<u8>, EvmError> {
    let end = u128::from(first_nonce) + u128::from(count);
    if count == 0 || count > MAX_VOID_FROZEN_RANGE_EVM || end > 1_u128 << 64 {
        return Err(EvmError::BadVoidRange);
    }
    Ok(abi_void_frozen(first_nonce, count))
}

/// The canonical `transferToTaira(recipient, amount, expectedNonce)` calldata (§5.1.7).
///
/// # Errors
///
/// Returns [`EvmError::BadRecipient`] or [`EvmError::BadAmount`].
pub fn transfer_to_taira_calldata(
    taira_recipient: &[u8],
    amount: u128,
    expected_nonce: u64,
) -> Result<Vec<u8>, EvmError> {
    if taira_recipient.is_empty() || taira_recipient.len() > MAX_TAIRA_ACCOUNT_BYTES {
        return Err(EvmError::BadRecipient);
    }
    if amount == 0 {
        return Err(EvmError::BadAmount);
    }
    Ok(TransferToTairaCallV1 {
        taira_recipient: taira_recipient.to_vec(),
        token_amount: amount,
        expected_nonce,
    }
    .calldata())
}

// ---------------------------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------------------------

fn rlp_length_prefix(len: usize, short: u8, out: &mut Vec<u8>) {
    if len <= 55 {
        out.push(short + u8::try_from(len).expect("at most 55"));
    } else {
        let be = (len as u64).to_be_bytes();
        let skip = be.iter().take_while(|byte| **byte == 0).count();
        let len_of_len = u8::try_from(be.len() - skip).expect("at most 8");
        out.push(short + 55 + len_of_len);
        out.extend_from_slice(&be[skip..]);
    }
}

/// RLP of a byte string.
#[must_use]
pub fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if let [byte] = bytes
        && *byte < 0x80
    {
        return vec![*byte];
    }
    let mut out = Vec::with_capacity(bytes.len() + 9);
    rlp_length_prefix(bytes.len(), 0x80, &mut out);
    out.extend_from_slice(bytes);
    out
}

/// RLP of an unsigned integer: its minimal big-endian bytes (zero is the empty string).
#[must_use]
pub fn rlp_uint(value: u128) -> Vec<u8> {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|byte| **byte == 0).count();
    rlp_bytes(&be[skip..])
}

/// RLP of a list of already encoded items.
#[must_use]
pub fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let len = items.iter().map(Vec::len).sum();
    let mut out = Vec::with_capacity(len + 9);
    rlp_length_prefix(len, 0xc0, &mut out);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// One strictly decoded RLP item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RlpItem<'a> {
    Bytes(&'a [u8]),
    List(&'a [u8]),
}

/// Decode one canonical RLP item from the front of `input`; returns it and the rest.
fn rlp_take(input: &[u8]) -> Result<(RlpItem<'_>, &[u8]), EvmError> {
    let (&prefix, rest) = input.split_first().ok_or(EvmError::Rlp("truncated item"))?;
    let (is_list, short_base) = if prefix >= 0xc0 {
        (true, 0xc0_u8)
    } else {
        (false, 0x80_u8)
    };
    if !is_list && prefix < 0x80 {
        return Ok((RlpItem::Bytes(&input[..1]), rest));
    }
    let offset = prefix - short_base;
    let (len, rest) = if offset <= 55 {
        (usize::from(offset), rest)
    } else {
        let len_of_len = usize::from(offset - 55);
        if rest.len() < len_of_len {
            return Err(EvmError::Rlp("truncated length"));
        }
        let (len_bytes, rest) = rest.split_at(len_of_len);
        if len_bytes[0] == 0 {
            return Err(EvmError::Rlp("length with leading zeros"));
        }
        let len = len_bytes.iter().try_fold(0_usize, |acc, byte| {
            acc.checked_mul(256)
                .and_then(|acc| acc.checked_add(usize::from(*byte)))
                .ok_or(EvmError::Rlp("length overflows"))
        })?;
        if len <= 55 {
            return Err(EvmError::Rlp("long form for a short payload"));
        }
        (len, rest)
    };
    if rest.len() < len {
        return Err(EvmError::Rlp("truncated payload"));
    }
    let (payload, rest) = rest.split_at(len);
    if is_list {
        return Ok((RlpItem::List(payload), rest));
    }
    if len == 1 && payload[0] < 0x80 {
        return Err(EvmError::Rlp("single byte below 0x80 must encode itself"));
    }
    Ok((RlpItem::Bytes(payload), rest))
}

/// Decode the items of a list payload.
fn rlp_items(mut payload: &[u8]) -> Result<Vec<RlpItem<'_>>, EvmError> {
    let mut items = Vec::new();
    while !payload.is_empty() {
        let (item, rest) = rlp_take(payload)?;
        items.push(item);
        payload = rest;
    }
    Ok(items)
}

fn rlp_expect_bytes(item: RlpItem<'_>) -> Result<&[u8], EvmError> {
    match item {
        RlpItem::Bytes(bytes) => Ok(bytes),
        RlpItem::List(_) => Err(EvmError::Rlp("expected a byte string")),
    }
}

fn rlp_expect_uint(item: RlpItem<'_>, max_bytes: usize) -> Result<u128, EvmError> {
    let bytes = rlp_expect_bytes(item)?;
    if bytes.len() > max_bytes {
        return Err(EvmError::Rlp("integer too large"));
    }
    if bytes.first() == Some(&0) {
        return Err(EvmError::Rlp("integer with leading zeros"));
    }
    Ok(bytes
        .iter()
        .fold(0_u128, |acc, byte| (acc << 8) | u128::from(*byte)))
}

fn rlp_expect_u64(item: RlpItem<'_>) -> Result<u64, EvmError> {
    u64::try_from(rlp_expect_uint(item, 8)?).map_err(|_| EvmError::Rlp("integer too large"))
}

fn rlp_expect_word(item: RlpItem<'_>) -> Result<[u8; 32], EvmError> {
    let bytes = rlp_expect_bytes(item)?;
    if bytes.len() > 32 || bytes.first() == Some(&0) {
        return Err(EvmError::Rlp(
            "signature scalar is not a minimal 32-byte integer",
        ));
    }
    let mut word = [0_u8; 32];
    word[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(word)
}

fn minimal(word: &[u8; 32]) -> &[u8] {
    let skip = word.iter().take_while(|byte| **byte == 0).count();
    &word[skip..]
}

// ---------------------------------------------------------------------------------------------
// EIP-1559 transactions
// ---------------------------------------------------------------------------------------------

/// Chain id of the EIP-1559 networks (Ethereum and BSC).
///
/// # Errors
///
/// Returns [`EvmError::UnsupportedNetwork`] for Taira and TON.
pub fn eip1559_chain_id(network: SccpNetworkV1) -> Result<u64, EvmError> {
    match network {
        SccpNetworkV1::EthereumMainnet => Ok(ETHEREUM_CHAIN_ID),
        SccpNetworkV1::BscMainnet => Ok(BSC_CHAIN_ID),
        other => Err(EvmError::UnsupportedNetwork(other)),
    }
}

/// An unsigned EIP-1559 transaction with an empty access list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Eip1559TransactionV1 {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// Sender account nonce.
    pub nonce: u64,
    /// Tip per gas (wei).
    pub max_priority_fee_per_gas: u128,
    /// Fee cap per gas (wei).
    pub max_fee_per_gas: u128,
    /// Gas limit.
    pub gas_limit: u64,
    /// Callee; `None` creates a contract.
    pub to: Option<[u8; 20]>,
    /// Value (wei).
    pub value: u128,
    /// Calldata or init code.
    pub data: Vec<u8>,
}

impl Eip1559TransactionV1 {
    /// A zero-value call of `data` on the destination contract `to` on `network`.
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::UnsupportedNetwork`], [`EvmError::PriorityFeeAboveMaxFee`] or
    /// [`EvmError::ZeroGasLimit`].
    pub fn contract_call(
        network: SccpNetworkV1,
        to: [u8; 20],
        data: Vec<u8>,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> Result<Self, EvmError> {
        let transaction = Self {
            chain_id: eip1559_chain_id(network)?,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to: Some(to),
            value: 0,
            data,
        };
        transaction.validate()?;
        Ok(transaction)
    }

    /// Check the fee ordering and the gas limit.
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::PriorityFeeAboveMaxFee`] or [`EvmError::ZeroGasLimit`].
    pub fn validate(&self) -> Result<(), EvmError> {
        if self.max_priority_fee_per_gas > self.max_fee_per_gas {
            return Err(EvmError::PriorityFeeAboveMaxFee);
        }
        if self.gas_limit == 0 {
            return Err(EvmError::ZeroGasLimit);
        }
        Ok(())
    }

    fn rlp_fields(&self) -> Vec<Vec<u8>> {
        vec![
            rlp_uint(u128::from(self.chain_id)),
            rlp_uint(u128::from(self.nonce)),
            rlp_uint(self.max_priority_fee_per_gas),
            rlp_uint(self.max_fee_per_gas),
            rlp_uint(u128::from(self.gas_limit)),
            rlp_bytes(self.to.as_ref().map_or(&[][..], |to| &to[..])),
            rlp_uint(self.value),
            rlp_bytes(&self.data),
            rlp_list(&[]),
        ]
    }

    /// `0x02 ‖ rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value,
    /// data, accessList])`: the bytes an external signer signs.
    #[must_use]
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = vec![EIP1559_TX_TYPE];
        out.extend_from_slice(&rlp_list(&self.rlp_fields()));
        out
    }

    /// `keccak256` of [`Self::unsigned_bytes`].
    #[must_use]
    pub fn signing_hash(&self) -> [u8; 32] {
        keccak256(&[&self.unsigned_bytes()])
    }

    /// Sign with `key`.
    ///
    /// # Errors
    ///
    /// Returns a validation error or [`EvmError::Signature`].
    pub fn sign(&self, key: &EvmSigningKey) -> Result<SignedEip1559V1, EvmError> {
        self.validate()?;
        let signature = key.sign_digest(&self.signing_hash())?;
        let signed = self.with_signature(&signature)?;
        if signed.sender()? != key.address() {
            return Err(EvmError::Signature(SignatureError::SigningFailed));
        }
        Ok(signed)
    }

    /// Attach an externally produced 65-byte `r ‖ s ‖ v` signature (`v ∈ {0, 1, 27, 28}`),
    /// requiring the low-S form of EIP-2 and a recoverable sender.
    ///
    /// # Errors
    ///
    /// Returns a validation error or [`EvmError::Signature`].
    pub fn with_signature(&self, signature: &[u8; 65]) -> Result<SignedEip1559V1, EvmError> {
        self.validate()?;
        let y_parity = match signature[64] {
            0 | 27 => false,
            1 | 28 => true,
            _ => return Err(EvmError::Signature(SignatureError::BadRecoveryByte)),
        };
        let mut normalized = *signature;
        normalized[64] = 27 + u8::from(y_parity);
        signature::check_signature_form(&normalized)?;
        let mut r = [0_u8; 32];
        let mut s = [0_u8; 32];
        r.copy_from_slice(&signature[..32]);
        s.copy_from_slice(&signature[32..64]);
        let signed = SignedEip1559V1 {
            transaction: self.clone(),
            y_parity,
            r,
            s,
        };
        signed.sender()?;
        Ok(signed)
    }

    /// Attach an external signature and require that it recovers `expected_sender`.
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::WrongSender`] or any [`Self::with_signature`] error.
    pub fn with_signature_from(
        &self,
        signature: &[u8; 65],
        expected_sender: &[u8; 20],
    ) -> Result<SignedEip1559V1, EvmError> {
        let signed = self.with_signature(signature)?;
        let recovered = signed.sender()?;
        if recovered != *expected_sender {
            return Err(EvmError::WrongSender { recovered });
        }
        Ok(signed)
    }

    /// The `--emit` export for an external signer.
    #[must_use]
    pub fn export_unsigned(&self) -> UnsignedEip1559ExportV1 {
        UnsignedEip1559ExportV1 {
            unsigned: self.unsigned_bytes(),
            signing_hash: self.signing_hash(),
        }
    }

    fn from_fields(fields: &[RlpItem<'_>]) -> Result<Self, EvmError> {
        let [
            chain_id,
            nonce,
            priority,
            max_fee,
            gas_limit,
            to,
            value,
            data,
            access_list,
        ] = fields
        else {
            return Err(EvmError::Rlp("an unsigned transaction has 9 fields"));
        };
        let to = match rlp_expect_bytes(*to)? {
            [] => None,
            bytes => Some(
                <[u8; 20]>::try_from(bytes).map_err(|_| EvmError::Rlp("`to` is not 20 bytes"))?,
            ),
        };
        match access_list {
            RlpItem::List([]) => {}
            _ => return Err(EvmError::Rlp("the access list must be empty")),
        }
        let transaction = Self {
            chain_id: rlp_expect_u64(*chain_id)?,
            nonce: rlp_expect_u64(*nonce)?,
            max_priority_fee_per_gas: rlp_expect_uint(*priority, 16)?,
            max_fee_per_gas: rlp_expect_uint(*max_fee, 16)?,
            gas_limit: rlp_expect_u64(*gas_limit)?,
            to,
            value: rlp_expect_uint(*value, 16)?,
            data: rlp_expect_bytes(*data)?.to_vec(),
        };
        transaction.validate()?;
        Ok(transaction)
    }

    /// Strictly decode [`Self::unsigned_bytes`] (canonical RLP, no trailing bytes).
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::Rlp`] or a validation error.
    pub fn decode_unsigned(bytes: &[u8]) -> Result<Self, EvmError> {
        let fields = decode_typed_list(bytes)?;
        Self::from_fields(&rlp_items(fields)?)
    }
}

fn decode_typed_list(bytes: &[u8]) -> Result<&[u8], EvmError> {
    let (&kind, body) = bytes.split_first().ok_or(EvmError::Rlp("empty input"))?;
    if kind != EIP1559_TX_TYPE {
        return Err(EvmError::Rlp("not an EIP-1559 (type 2) transaction"));
    }
    match rlp_take(body)? {
        (RlpItem::List(fields), []) => Ok(fields),
        (RlpItem::List(_), _) => Err(EvmError::Rlp("trailing bytes")),
        (RlpItem::Bytes(_), _) => Err(EvmError::Rlp("expected a field list")),
    }
}

/// A signed EIP-1559 transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignedEip1559V1 {
    /// The signed fields.
    pub transaction: Eip1559TransactionV1,
    /// Parity of the signature's `R` point.
    pub y_parity: bool,
    /// Signature `r`.
    pub r: [u8; 32],
    /// Signature `s` (low-S).
    pub s: [u8; 32],
}

impl SignedEip1559V1 {
    /// The raw transaction for `eth_sendRawTransaction`.
    #[must_use]
    pub fn raw(&self) -> Vec<u8> {
        let mut fields = self.transaction.rlp_fields();
        fields.push(rlp_uint(u128::from(self.y_parity)));
        fields.push(rlp_bytes(minimal(&self.r)));
        fields.push(rlp_bytes(minimal(&self.s)));
        let mut out = vec![EIP1559_TX_TYPE];
        out.extend_from_slice(&rlp_list(&fields));
        out
    }

    /// `0x`-prefixed lowercase hex of [`Self::raw`].
    #[must_use]
    pub fn raw_hex(&self) -> String {
        format!("0x{}", hex::encode(self.raw()))
    }

    /// The transaction hash (`keccak256` of the raw transaction).
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        keccak256(&[&self.raw()])
    }

    /// The 65-byte `r ‖ s ‖ v` form with `v ∈ {27, 28}`.
    #[must_use]
    pub fn signature(&self) -> [u8; 65] {
        let mut out = [0_u8; 65];
        out[..32].copy_from_slice(&self.r);
        out[32..64].copy_from_slice(&self.s);
        out[64] = 27 + u8::from(self.y_parity);
        out
    }

    /// The sender the signature recovers.
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::Signature`] for a malformed or unrecoverable signature.
    pub fn sender(&self) -> Result<[u8; 20], EvmError> {
        Ok(signature::recover_address(
            &self.transaction.signing_hash(),
            &self.signature(),
        )?)
    }

    /// Strictly decode a signed EIP-1559 transaction (canonical RLP, empty access list,
    /// low-S, recoverable sender).
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::Rlp`] or a signature error.
    pub fn decode(raw: &[u8]) -> Result<Self, EvmError> {
        let fields = rlp_items(decode_typed_list(raw)?)?;
        let [unsigned @ .., y_parity, r, s] = fields.as_slice() else {
            return Err(EvmError::Rlp("a signed transaction has 12 fields"));
        };
        let transaction = Eip1559TransactionV1::from_fields(unsigned)?;
        let y_parity = match rlp_expect_uint(*y_parity, 1)? {
            0 => false,
            1 => true,
            _ => return Err(EvmError::Rlp("yParity must be 0 or 1")),
        };
        let mut signature = [0_u8; 65];
        signature[..32].copy_from_slice(&rlp_expect_word(*r)?);
        signature[32..64].copy_from_slice(&rlp_expect_word(*s)?);
        signature[64] = u8::from(y_parity);
        let signed = transaction.with_signature(&signature)?;
        if signed.raw() != raw {
            return Err(EvmError::Rlp("non-canonical encoding"));
        }
        Ok(signed)
    }
}

/// The `--emit` export of an unsigned EIP-1559 transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnsignedEip1559ExportV1 {
    /// `0x02 ‖ rlp(…)` without a signature.
    pub unsigned: Vec<u8>,
    /// `keccak256(unsigned)`, the digest the external signer signs.
    pub signing_hash: [u8; 32],
}

impl UnsignedEip1559ExportV1 {
    /// `0x`-prefixed lowercase hex of the unsigned bytes.
    #[must_use]
    pub fn hex(&self) -> String {
        format!("0x{}", hex::encode(&self.unsigned))
    }

    /// Uppercase-hex QR payloads `SCCP-EIP1559:<part>/<total>:<HEX>` of at most
    /// `max_chars_per_part` characters each, all in the QR alphanumeric set (digits, `A`–`Z`,
    /// `-`, `/`, `:`). A scanner concatenates the hex of parts `1..=total` in order.
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::QrPartTooSmall`] when a part cannot hold its header and one byte.
    pub fn qr_payloads(&self, max_chars_per_part: usize) -> Result<Vec<String>, EvmError> {
        let hex = hex::encode_upper(&self.unsigned);
        let mut parts = 1_usize;
        loop {
            let header = QR_PREFIX.len() + 2 * decimal_digits(parts) + 2;
            let room = max_chars_per_part
                .checked_sub(header)
                .map(|room| room & !1)
                .filter(|room| *room >= 2)
                .ok_or(EvmError::QrPartTooSmall)?;
            let needed = hex.len().div_ceil(room).max(1);
            if needed <= parts {
                return Ok(hex
                    .as_bytes()
                    .chunks(room)
                    .enumerate()
                    .map(|(index, chunk)| {
                        format!(
                            "{QR_PREFIX}{}/{needed}:{}",
                            index + 1,
                            core::str::from_utf8(chunk).expect("hex is ASCII")
                        )
                    })
                    .collect());
            }
            parts = needed;
        }
    }
}

fn decimal_digits(value: usize) -> usize {
    value.checked_ilog10().map_or(1, |log| log as usize + 1)
}

// ---------------------------------------------------------------------------------------------
// Owner-only key files
// ---------------------------------------------------------------------------------------------

/// Why an external key file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyFileError {
    /// The path is a symbolic link.
    Symlink,
    /// The path is not a regular file.
    NotRegularFile,
    /// Group or other permission bits are set (mode `0600` or stricter is required).
    Permissions {
        /// The permission bits of the file mode (`mode & 0o7777`).
        mode: u16,
    },
    /// The file is owned by another user.
    NotOwner,
    /// The file was replaced between the check and the open.
    Replaced,
    /// The file is larger than [`MAX_KEY_FILE_BYTES`].
    TooLarge,
    /// The content is not one 32-byte hex secret (optional `0x`, optional trailing newline).
    BadFormat,
    /// The secret is not a valid secp256k1 scalar.
    InvalidSecret,
    /// The file could not be opened or read.
    Io(std::io::ErrorKind),
    /// Owner-only files cannot be checked on this platform.
    Unsupported,
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Symlink => formatter.write_str("the key file must not be a symbolic link"),
            Self::NotRegularFile => formatter.write_str("the key file must be a regular file"),
            Self::Permissions { mode } => write!(
                formatter,
                "the key file mode {mode:o} grants group or other access; use 0600"
            ),
            Self::NotOwner => formatter.write_str("the key file must be owned by the current user"),
            Self::Replaced => formatter.write_str("the key file was replaced while it was opened"),
            Self::TooLarge => formatter.write_str("the key file is too large"),
            Self::BadFormat => {
                formatter.write_str("the key file must hold one 32-byte secret as 64 hex digits")
            }
            Self::InvalidSecret => {
                formatter.write_str("the key file secret is not a valid secp256k1 scalar")
            }
            Self::Io(kind) => write!(formatter, "the key file cannot be read: {kind}"),
            Self::Unsupported => {
                formatter.write_str("owner-only key files require Unix permissions")
            }
        }
    }
}

impl std::error::Error for KeyFileError {}

/// Parse key-file content: optional `0x`, 64 hex digits, optional trailing newline.
///
/// # Errors
///
/// Returns [`KeyFileError::BadFormat`].
pub(crate) fn parse_key_file_secret(bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    let body = body.strip_prefix(b"0x").unwrap_or(body);
    if body.len() != 64 {
        return Err(KeyFileError::BadFormat);
    }
    let mut secret = Zeroizing::new([0_u8; 32]);
    hex::decode_to_slice(body, &mut secret[..]).map_err(|_| KeyFileError::BadFormat)?;
    Ok(secret)
}

/// Read the 32-byte secret of an owner-only key file (TON keys use it as an Ed25519 seed).
///
/// # Errors
///
/// Returns the [`KeyFileError`] of the first failed check.
pub(crate) fn load_key_file_secret(path: &Path) -> Result<Zeroizing<[u8; 32]>, KeyFileError> {
    parse_key_file_secret(&read_owner_only_file(path)?)
}

/// A secp256k1 key for EVM transactions; the secret is zeroized on drop and never printed.
pub struct EvmSigningKey {
    secret: Zeroizing<[u8; 32]>,
    address: [u8; 20],
}

impl fmt::Debug for EvmSigningKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvmSigningKey")
            .field("address", &format_args!("0x{}", hex::encode(self.address)))
            .finish_non_exhaustive()
    }
}

impl EvmSigningKey {
    /// Wrap a secret scalar.
    ///
    /// # Errors
    ///
    /// Returns [`KeyFileError::InvalidSecret`] unless `1 ≤ secret < N`.
    pub fn from_secret(secret: [u8; 32]) -> Result<Self, KeyFileError> {
        let secret = Zeroizing::new(secret);
        let address =
            signature::address_of_secret(&secret).map_err(|_| KeyFileError::InvalidSecret)?;
        Ok(Self { secret, address })
    }

    /// Parse the key-file content: optional `0x`, 64 hex digits, optional trailing newline.
    ///
    /// # Errors
    ///
    /// Returns [`KeyFileError::BadFormat`] or [`KeyFileError::InvalidSecret`].
    pub fn from_key_file_bytes(bytes: &[u8]) -> Result<Self, KeyFileError> {
        Self::from_secret(*parse_key_file_secret(bytes)?)
    }

    /// Load an owner-only key file: a regular, non-symlink file of mode `0600` or stricter
    /// owned by the current user.
    ///
    /// # Errors
    ///
    /// Returns the [`KeyFileError`] of the first failed check.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let bytes = read_owner_only_file(path)?;
        Self::from_key_file_bytes(&bytes)
    }

    /// The key's 20-byte address.
    #[must_use]
    pub fn address(&self) -> [u8; 20] {
        self.address
    }

    /// Sign a 32-byte digest (RFC 6979, low-S, `v ∈ {27, 28}`, §3.8 form).
    ///
    /// # Errors
    ///
    /// Returns [`EvmError::Signature`] when signing fails.
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 65], EvmError> {
        Ok(signature::sign_digest(&self.secret, digest)?)
    }
}

#[cfg(unix)]
fn read_owner_only_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    use std::{
        fs::{self, File},
        io::Read as _,
        os::unix::fs::MetadataExt as _,
    };

    use rustix::fs::{Mode, OFlags};

    let io = |error: std::io::Error| KeyFileError::Io(error.kind());
    let check = |metadata: &fs::Metadata| -> Result<(), KeyFileError> {
        if metadata.file_type().is_symlink() {
            return Err(KeyFileError::Symlink);
        }
        if !metadata.is_file() {
            return Err(KeyFileError::NotRegularFile);
        }
        if metadata.mode() & 0o077 != 0 {
            return Err(KeyFileError::Permissions {
                mode: u16::try_from(metadata.mode() & 0o7777).unwrap_or(u16::MAX),
            });
        }
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            return Err(KeyFileError::NotOwner);
        }
        Ok(())
    };
    let before = fs::symlink_metadata(path).map_err(io)?;
    check(&before)?;
    let descriptor = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|error| {
        if error == rustix::io::Errno::LOOP {
            KeyFileError::Symlink
        } else {
            KeyFileError::Io(std::io::Error::from(error).kind())
        }
    })?;
    let mut file = File::from(descriptor);
    let opened = file.metadata().map_err(io)?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(KeyFileError::Replaced);
    }
    check(&opened)?;
    // A fixed buffer is never reallocated, so no unzeroized copy of the secret is left behind.
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_KEY_FILE_BYTES + 1]);
    let mut filled = 0;
    loop {
        let read = file.read(&mut buffer[filled..]).map_err(io)?;
        if read == 0 {
            break;
        }
        filled += read;
        if filled > MAX_KEY_FILE_BYTES {
            return Err(KeyFileError::TooLarge);
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

#[cfg(not(unix))]
fn read_owner_only_file(_path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyFileError> {
    Err(KeyFileError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key() -> EvmSigningKey {
        EvmSigningKey::from_secret(keccak256(&[b"SCCP/FIXTURE/KEY/V1", &[0]])).expect("key")
    }

    #[test]
    fn rlp_encodes_the_yellow_paper_vectors() {
        assert_eq!(rlp_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(rlp_bytes(&[]), vec![0x80]);
        assert_eq!(rlp_bytes(&[0x0f]), vec![0x0f]);
        assert_eq!(rlp_bytes(&[0x80]), vec![0x81, 0x80]);
        assert_eq!(rlp_uint(0), vec![0x80]);
        assert_eq!(rlp_uint(15), vec![0x0f]);
        assert_eq!(rlp_uint(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        assert_eq!(
            rlp_list(&[rlp_bytes(b"cat"), rlp_bytes(b"dog")]),
            vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
        );
        let long = vec![b'a'; 56];
        let encoded = rlp_bytes(&long);
        assert_eq!(&encoded[..2], &[0xb8, 56]);
        assert_eq!(encoded.len(), 58);
        let big = vec![0_u8; 1024];
        assert_eq!(&rlp_bytes(&big)[..3], &[0xb9, 0x04, 0x00]);
    }

    #[test]
    fn rlp_decoder_rejects_non_canonical_items() {
        assert_eq!(
            rlp_take(&[0x83, b'd', b'o', b'g']).expect("item"),
            (RlpItem::Bytes(b"dog"), &[][..])
        );
        assert_eq!(rlp_take(&[0x05]).expect("item").0, RlpItem::Bytes(&[0x05]));
        assert!(rlp_take(&[0x81, 0x05]).is_err(), "single byte in long form");
        assert!(
            rlp_take(&[0xb8, 0x05, 1, 2, 3, 4, 5]).is_err(),
            "short in long form"
        );
        assert!(
            rlp_take(&[0xb9, 0x00, 0x38]).is_err(),
            "length leading zero"
        );
        assert!(rlp_take(&[0x83, b'd']).is_err(), "truncated");
        assert!(rlp_take(&[]).is_err(), "empty");
        assert_eq!(
            rlp_expect_uint(RlpItem::Bytes(&[0, 1]), 8),
            Err(EvmError::Rlp("integer with leading zeros"))
        );
        assert_eq!(rlp_expect_uint(RlpItem::Bytes(&[]), 8), Ok(0));
        assert!(rlp_expect_uint(RlpItem::Bytes(&[1; 9]), 8).is_err());
        assert!(rlp_expect_bytes(RlpItem::List(&[])).is_err());
        assert_eq!(rlp_items(&[0x01, 0x80]).expect("items").len(), 2);
        assert!(rlp_expect_word(RlpItem::Bytes(&[0, 1])).is_err());
        assert_eq!(rlp_expect_word(RlpItem::Bytes(&[1])).expect("word")[31], 1);
    }

    #[test]
    fn eip1559_sign_recovers_the_signer_and_roundtrips() {
        let key = fixture_key();
        let transaction = Eip1559TransactionV1::contract_call(
            SccpNetworkV1::BscMainnet,
            [0x22; 20],
            vec![0xde, 0xad],
            3,
            1,
            2,
            100_000,
        )
        .expect("transaction");
        assert_eq!(transaction.chain_id, 56);
        let signed = transaction.sign(&key).expect("signed");
        assert_eq!(signed.sender().expect("sender"), key.address());
        let decoded = SignedEip1559V1::decode(&signed.raw()).expect("decodes");
        assert_eq!(decoded, signed);
        assert_eq!(decoded.hash(), keccak256(&[&signed.raw()]));
        assert!(signed.raw_hex().starts_with("0x02"));
        assert_eq!(
            Eip1559TransactionV1::decode_unsigned(&transaction.unsigned_bytes()).expect("unsigned"),
            transaction
        );
        let mut trailing = signed.raw();
        trailing.push(0);
        assert!(SignedEip1559V1::decode(&trailing).is_err());
        let mut wrong_type = signed.raw();
        wrong_type[0] = 0x01;
        assert!(SignedEip1559V1::decode(&wrong_type).is_err());
    }

    #[test]
    fn external_signatures_are_checked() {
        let key = fixture_key();
        let transaction = Eip1559TransactionV1::contract_call(
            SccpNetworkV1::EthereumMainnet,
            [0x22; 20],
            Vec::new(),
            0,
            1,
            1,
            21_000,
        )
        .expect("transaction");
        let signature = key
            .sign_digest(&transaction.export_unsigned().signing_hash)
            .expect("signature");
        let mut parity = signature;
        parity[64] -= 27;
        assert_eq!(
            transaction
                .with_signature_from(&parity, &key.address())
                .expect("0/1 parity accepted")
                .sender()
                .expect("sender"),
            key.address()
        );
        assert!(matches!(
            transaction.with_signature_from(&signature, &[0x33; 20]),
            Err(EvmError::WrongSender { .. })
        ));
        let mut bad_v = signature;
        bad_v[64] = 29;
        assert_eq!(
            transaction.with_signature(&bad_v),
            Err(EvmError::Signature(SignatureError::BadRecoveryByte))
        );
        let high_s = {
            let mut out = signature;
            let s: [u8; 32] = signature[32..64].try_into().expect("s");
            let mut n = iroha_sccp::v1::constants::SECP256K1_N;
            // n - s, with borrow.
            let mut borrow = 0_i16;
            for index in (0..32).rev() {
                let value = i16::from(n[index]) - i16::from(s[index]) - borrow;
                borrow = i16::from(value < 0);
                n[index] = u8::try_from(value.rem_euclid(256)).expect("byte");
            }
            out[32..64].copy_from_slice(&n);
            out
        };
        assert_eq!(
            transaction.with_signature(&high_s),
            Err(EvmError::Signature(SignatureError::BadS))
        );
    }

    #[test]
    fn transactions_validate_fees_gas_and_networks() {
        assert_eq!(
            Eip1559TransactionV1::contract_call(
                SccpNetworkV1::EthereumMainnet,
                [1; 20],
                Vec::new(),
                0,
                3,
                2,
                21_000
            ),
            Err(EvmError::PriorityFeeAboveMaxFee)
        );
        assert_eq!(
            Eip1559TransactionV1::contract_call(
                SccpNetworkV1::EthereumMainnet,
                [1; 20],
                Vec::new(),
                0,
                1,
                2,
                0
            ),
            Err(EvmError::ZeroGasLimit)
        );
        for network in [SccpNetworkV1::SoraTaira, SccpNetworkV1::TonMainnet] {
            assert_eq!(
                eip1559_chain_id(network),
                Err(EvmError::UnsupportedNetwork(network))
            );
        }
        assert_eq!(eip1559_chain_id(SccpNetworkV1::EthereumMainnet), Ok(1));
        assert_eq!(eip1559_chain_id(SccpNetworkV1::BscMainnet), Ok(56));
    }

    #[test]
    fn qr_payloads_split_into_alphanumeric_parts() {
        let export = UnsignedEip1559ExportV1 {
            unsigned: (0..=255_u8).collect(),
            signing_hash: [0; 32],
        };
        assert!(export.hex().starts_with("0x0001"));
        let single = export.qr_payloads(4_296).expect("single");
        assert_eq!(single.len(), 1);
        assert!(single[0].starts_with("SCCP-EIP1559:1/1:0001"));
        let parts = export.qr_payloads(100).expect("parts");
        assert!(parts.len() > 1);
        let total = parts.len();
        let mut joined = String::new();
        for (index, part) in parts.iter().enumerate() {
            assert!(part.len() <= 100, "{part}");
            assert!(
                part.bytes().all(|byte| byte.is_ascii_digit()
                    || byte.is_ascii_uppercase()
                    || b"-/:".contains(&byte)),
                "{part}"
            );
            let header = format!("{QR_PREFIX}{}/{total}:", index + 1);
            joined.push_str(part.strip_prefix(&header).expect("header"));
        }
        assert_eq!(joined, hex::encode_upper(&export.unsigned));
        assert_eq!(export.qr_payloads(10), Err(EvmError::QrPartTooSmall));
        assert_eq!(decimal_digits(0), 1);
        assert_eq!(decimal_digits(9), 1);
        assert_eq!(decimal_digits(10), 2);
    }

    #[test]
    fn calldata_builders_enforce_their_bounds() {
        assert_eq!(void_frozen_calldata(0, 0), Err(EvmError::BadVoidRange));
        assert_eq!(void_frozen_calldata(0, 257), Err(EvmError::BadVoidRange));
        assert_eq!(
            void_frozen_calldata(u64::MAX, 2),
            Err(EvmError::BadVoidRange)
        );
        assert!(void_frozen_calldata(u64::MAX, 1).is_ok());
        assert_eq!(
            void_frozen_calldata(4, 3).expect("calldata")[..4],
            [0x5b, 0x09, 0x4c, 0x00]
        );
        assert_eq!(
            transfer_to_taira_calldata(&[], 1, 0),
            Err(EvmError::BadRecipient)
        );
        assert_eq!(
            transfer_to_taira_calldata(&[1; 1025], 1, 0),
            Err(EvmError::BadRecipient)
        );
        assert_eq!(
            transfer_to_taira_calldata(&[1; 34], 0, 0),
            Err(EvmError::BadAmount)
        );
        let calldata = transfer_to_taira_calldata(&[1; 34], 5, 9).expect("calldata");
        let decoded = TransferToTairaCallV1::decode(&calldata).expect("canonical");
        assert_eq!(decoded.token_amount, 5);
        assert_eq!(decoded.expected_nonce, 9);
    }

    #[test]
    fn key_file_content_is_strict() {
        let hex = "998dba6f0ff534544e377f85847d49e338287a687a30139a1e4900525c48f197";
        let key = EvmSigningKey::from_key_file_bytes(hex.as_bytes()).expect("bare hex");
        assert_eq!(key.address(), fixture_key().address());
        assert!(EvmSigningKey::from_key_file_bytes(format!("0x{hex}\n").as_bytes()).is_ok());
        assert!(
            EvmSigningKey::from_key_file_bytes(hex.to_uppercase().as_bytes()).is_ok(),
            "hex case is not significant"
        );
        for bad in [
            format!("{hex}\n\n"),
            format!(" {hex}"),
            hex[..62].to_owned(),
            format!("0X{hex}"),
            format!("{hex}zz"),
        ] {
            assert_eq!(
                EvmSigningKey::from_key_file_bytes(bad.as_bytes()).map(|key| key.address()),
                Err(KeyFileError::BadFormat),
                "{bad:?}"
            );
        }
        assert_eq!(
            EvmSigningKey::from_key_file_bytes(&[b'0'; 64]).map(|key| key.address()),
            Err(KeyFileError::InvalidSecret)
        );
        let debug = format!("{key:?}");
        assert!(debug.contains("0x7e90b4f929bcfd28c8dec8831d30dacb139d7184"));
        assert!(!debug.contains(hex));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_must_be_owner_only_regular_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("evm.key");
        std::fs::write(
            &path,
            "0x998dba6f0ff534544e377f85847d49e338287a687a30139a1e4900525c48f197\n",
        )
        .expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let key = EvmSigningKey::load(&path).expect("owner-only key loads");
        assert_eq!(key.address(), fixture_key().address());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).expect("mode");
        assert!(
            EvmSigningKey::load(&path).is_ok(),
            "0400 is stricter than 0600"
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("mode");
        assert!(matches!(
            EvmSigningKey::load(&path),
            Err(KeyFileError::Permissions { .. })
        ));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
        let link = dir.path().join("link.key");
        symlink(&path, &link).expect("symlink");
        assert_eq!(
            EvmSigningKey::load(&link).map(|key| key.address()),
            Err(KeyFileError::Symlink)
        );
        assert_eq!(
            EvmSigningKey::load(dir.path()).map(|key| key.address()),
            Err(KeyFileError::NotRegularFile)
        );
        assert!(matches!(
            EvmSigningKey::load(&dir.path().join("missing.key")),
            Err(KeyFileError::Io(std::io::ErrorKind::NotFound))
        ));
        let large = dir.path().join("large.key");
        std::fs::write(&large, vec![b'0'; MAX_KEY_FILE_BYTES + 1]).expect("write");
        std::fs::set_permissions(&large, std::fs::Permissions::from_mode(0o600)).expect("mode");
        assert_eq!(
            EvmSigningKey::load(&large).map(|key| key.address()),
            Err(KeyFileError::TooLarge)
        );
        assert!(
            KeyFileError::Permissions { mode: 0o100_644 }
                .to_string()
                .contains("644")
        );
    }

    #[test]
    fn evm_errors_display() {
        assert!(EvmError::WrongPurpose.to_string().contains("different"));
        assert!(
            EvmError::UnsupportedNetwork(SccpNetworkV1::TonMainnet)
                .to_string()
                .contains("ton-mainnet")
        );
        assert!(
            EvmError::WrongSender {
                recovered: [0xab; 20]
            }
            .to_string()
            .contains("0xabab")
        );
        assert_eq!(
            EvmError::from(KeyFileError::BadFormat),
            EvmError::KeyFile(KeyFileError::BadFormat)
        );
    }
}
