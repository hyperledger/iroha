//! [`Transaction`] structures and related implementations.
#![allow(clippy::std_instead_of_core)]
// TODO: Remove when a proper `Display` will be implemented for `Transaction`
#![allow(clippy::use_debug)]
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_set, format, string::String, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    iter::IntoIterator,
};
#[cfg(feature = "std")]
use std::{collections::btree_set, time::Duration};

use derive_more::{Constructor, DebugCustom, Display};
use getset::Getters;
use iroha_crypto::{Hash, SignatureOf, SignatureVerificationFail, SignaturesOf};
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
#[cfg(feature = "transparent_api")]
use iroha_version::declare_versioned_with_scale;
use iroha_version::{declare_versioned, version, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::Account, isi::InstructionBox, metadata::UnlimitedMetadata, model, Identifiable,
};

/// Default maximum number of instructions and expressions per transaction
pub const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);

/// Default maximum number of instructions and expressions per transaction
pub const DEFAULT_MAX_WASM_SIZE_BYTES: u64 = 2_u64.pow(22); // 4 MiB

/// Trait for basic transaction operations
pub trait Transaction {
    /// Result of hashing
    type HashOf: Transaction;

    /// Returns payload of a transaction
    fn payload(&self) -> &TransactionPayload;

    /// Calculate transaction [`Hash`](`iroha_crypto::Hash`).
    #[inline]
    #[cfg(feature = "std")]
    fn hash(&self) -> iroha_crypto::HashOf<Self::HashOf>
    where
        Self: Sized,
    {
        iroha_crypto::HashOf::new(self.payload()).transmute()
    }

    /// Checks if number of instructions in payload or wasm size exceeds maximum
    ///
    /// # Errors
    ///
    /// Fails if number of instructions or wasm size exceeds maximum
    #[inline]
    fn check_limits(&self, limits: &TransactionLimits) -> Result<(), error::TransactionLimitError> {
        match &self.payload().instructions {
            Executable::Instructions(instructions) => {
                let instruction_count: u64 = instructions
                    .iter()
                    .map(InstructionBox::len)
                    .sum::<usize>()
                    .try_into()
                    .expect("`usize` should always fit in `u64`");

                if instruction_count > limits.max_instruction_number {
                    return Err(error::TransactionLimitError {
                        reason: format!(
                            "Too many instructions in payload, max number is {}, but got {}",
                            limits.max_instruction_number, instruction_count
                        ),
                    });
                }
            }
            Executable::Wasm(WasmSmartContract(raw_data)) => {
                let len: u64 = raw_data
                    .len()
                    .try_into()
                    .expect("`usize` should always fit in `u64`");

                if len > limits.max_wasm_size_bytes {
                    return Err(error::TransactionLimitError {
                        reason: format!(
                            "Wasm binary too large, max size is {}, but got {}",
                            limits.max_wasm_size_bytes, len
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Checks if this transaction is waiting longer than specified in
    /// `transaction_time_to_live` from `QueueConfiguration` or
    /// `time_to_live_ms` of this transaction.  Meaning that the
    /// transaction will be expired as soon as the lesser of the
    /// specified TTLs was reached.
    #[cfg(feature = "std")]
    fn is_expired(&self, transaction_time_to_live: Duration) -> bool {
        let tx_timestamp = Duration::from_millis(self.payload().creation_time);
        crate::current_time().saturating_sub(tx_timestamp)
            > core::cmp::min(
                transaction_time_to_live,
                Duration::from_millis(self.payload().time_to_live_ms),
            )
    }

    /// If `true`, this transaction is regarded to have been tampered
    /// to have a future timestamp.
    #[cfg(feature = "std")]
    fn is_in_future(&self, threshold: Duration) -> bool {
        let tx_timestamp = Duration::from_millis(self.payload().creation_time);
        tx_timestamp.saturating_sub(crate::current_time()) > threshold
    }
}

/// Trait for signing transactions
#[cfg(feature = "std")]
pub trait Sign {
    /// Sign transaction with provided key pair.
    ///
    /// # Errors
    ///
    /// Fails if signature creation fails
    fn sign(
        self,
        key_pair: iroha_crypto::KeyPair,
    ) -> Result<SignedTransaction, iroha_crypto::Error>;
}

model! {
    /// Either ISI or Wasm binary
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type(local)]
    pub enum Executable {
        /// Ordered set of instructions.
        Instructions(Vec<InstructionBox>),
        /// WebAssembly smartcontract
        Wasm(WasmSmartContract),
    }
}

impl FromIterator<InstructionBox> for Executable {
    fn from_iter<T: IntoIterator<Item = InstructionBox>>(iter: T) -> Self {
        Self::Instructions(iter.into_iter().collect())
    }
}

impl<T: IntoIterator<Item = InstructionBox>> From<T> for Executable {
    fn from(collection: T) -> Self {
        collection.into_iter().collect()
    }
}

impl From<WasmSmartContract> for Executable {
    fn from(source: WasmSmartContract) -> Self {
        Self::Wasm(source)
    }
}

model! {
    /// Wrapper for byte representation of [`Executable::Wasm`].
    ///
    /// Uses **base64** (de-)serialization format.
    #[derive(DebugCustom, Clone, PartialEq, Eq, Hash, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[debug(fmt = "WASM binary(len = {})", "self.0.len()")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `WasmSmartContract` has no trap representation in `Vec<u8>`
    #[ffi_type(unsafe {robust})]
    pub struct WasmSmartContract(
        /// Raw wasm blob.
        #[serde(with = "base64")]
        Vec<u8>,
    );
}

impl AsRef<[u8]> for WasmSmartContract {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

model! {
    /// Iroha [`Transaction`] payload.
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionPayload {
        /// Account ID of transaction creator.
        pub account_id: <Account as Identifiable>::Id,
        /// Instructions or WebAssembly smartcontract
        pub instructions: Executable,
        /// Time of creation (unix time, in milliseconds).
        pub creation_time: u64,
        /// The transaction will be dropped after this time if it is still in a `Queue`.
        pub time_to_live_ms: u64,
        /// Random value to make different hashes for transactions which occur repeatedly and simultaneously
        pub nonce: Option<u32>,
        /// Metadata.
        pub metadata: UnlimitedMetadata,
    }

    /// Container for limits that transactions must obey.
    #[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Getters, Constructor, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "{max_instruction_number},{max_wasm_size_bytes}_TL")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionLimits {
        /// Maximum number of instructions per transaction
        pub max_instruction_number: u64,
        /// Maximum size of wasm binary
        pub max_wasm_size_bytes: u64,
    }
}

model! {
    /// Structure that represents the initial state of a transaction before the transaction receives any signatures.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct TransactionBuilder {
        /// [`Transaction`] payload.
        pub payload: TransactionPayload,
    }

}

impl TransactionBuilder {
    /// Construct [`Self`].
    #[inline]
    #[must_use]
    #[cfg(feature = "std")]
    pub fn new(
        account_id: <Account as Identifiable>::Id,
        instructions: impl Into<Executable>,
        proposed_ttl_ms: u64,
    ) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let creation_time = crate::current_time().as_millis() as u64;

        Self {
            payload: TransactionPayload {
                account_id,
                instructions: instructions.into(),
                creation_time,
                time_to_live_ms: proposed_ttl_ms,
                nonce: None,
                metadata: UnlimitedMetadata::new(),
            },
        }
    }

    /// Adds metadata to the `Transaction`
    #[must_use]
    #[inline]
    pub fn with_metadata(mut self, metadata: UnlimitedMetadata) -> Self {
        self.payload.metadata = metadata;
        self
    }

    /// Adds nonce to the `Transaction`
    #[must_use]
    #[inline]
    pub fn with_nonce(mut self, nonce: u32) -> Self {
        self.payload.nonce = Some(nonce);
        self
    }
}

#[cfg(feature = "std")]
impl Sign for TransactionBuilder {
    fn sign(
        self,
        key_pair: iroha_crypto::KeyPair,
    ) -> Result<SignedTransaction, iroha_crypto::Error> {
        let signature = SignatureOf::new(key_pair, &self.payload)?;
        let signatures = btree_set::BTreeSet::from([signature]);

        Ok(SignedTransaction {
            payload: self.payload,
            signatures,
        })
    }
}

#[cfg(any(feature = "ffi_import", feature = "ffi_export"))]
declare_versioned!(VersionedSignedTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_import"), not(feature = "ffi_export")))]
declare_versioned!(VersionedSignedTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, IntoSchema);

impl VersionedSignedTransaction {
    /// Convert from `&VersionedSignedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &SignedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Convert from `&mut VersionedSignedTransaction` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut SignedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedSignedTransaction` to V1
    #[inline]
    pub fn into_v1(self) -> SignedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

impl Transaction for VersionedSignedTransaction {
    type HashOf = Self;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        match self {
            Self::V1(v1) => &v1.payload,
        }
    }
}

impl From<VersionedValidTransaction> for VersionedSignedTransaction {
    fn from(transaction: VersionedValidTransaction) -> Self {
        match transaction {
            VersionedValidTransaction::V1(transaction) => {
                let signatures = transaction.signatures.into();

                SignedTransaction {
                    payload: transaction.payload,
                    signatures,
                }
                .into()
            }
        }
    }
}

model! {
    /// Structure that represents the second state of the transaction after receiving at least one signature.
    ///
    /// `Iroha` and its clients use [`Transaction`] to send transactions over the network.
    /// After a transaction is signed and before it can be processed any further,
    /// the transaction must be accepted by the `Iroha` peer.
    /// The peer verifies the signatures and checks the limits.
    #[version(n = 1, versioned = "VersionedSignedTransaction")]
    #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[display(fmt = "{self:?}")] // TODO ?
    #[ffi_type]
    pub struct SignedTransaction {
        /// [`Transaction`] payload.
        pub payload: TransactionPayload,
        /// [`SignatureOf`]<[`TransactionPayload`]>.
        pub signatures: btree_set::BTreeSet<SignatureOf<TransactionPayload>>,
    }
}

impl SignedTransaction {
    /// Return signatures
    pub fn signatures(&self) -> impl ExactSizeIterator<Item = &SignatureOf<TransactionPayload>> {
        self.signatures.iter()
    }
}

impl Transaction for SignedTransaction {
    type HashOf = Self;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        &self.payload
    }
}

#[cfg(feature = "std")]
impl Sign for SignedTransaction {
    fn sign(
        mut self,
        key_pair: iroha_crypto::KeyPair,
    ) -> Result<SignedTransaction, iroha_crypto::Error> {
        let signature = SignatureOf::new(key_pair, &self.payload)?;
        self.signatures.insert(signature);

        Ok(SignedTransaction {
            payload: self.payload,
            signatures: self.signatures,
        })
    }
}

model! {
    /// Transaction Value used in Instructions and Queries
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type(local)]
    pub enum TransactionValue {
        /// Committed transaction
        Transaction(Box<VersionedSignedTransaction>),
        /// Rejected transaction with reason of rejection
        RejectedTransaction(Box<VersionedRejectedTransaction>),
    }
}

impl TransactionValue {
    /// Used to return payload of the transaction
    #[inline]
    pub fn payload(&self) -> &TransactionPayload {
        match self {
            TransactionValue::Transaction(tx) => tx.payload(),
            TransactionValue::RejectedTransaction(tx) => tx.payload(),
        }
    }
}

impl PartialOrd for TransactionValue {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionValue {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.payload()
            .creation_time
            .cmp(&other.payload().creation_time)
    }
}

model! {
    /// `TransactionQueryResult` is used in `FindAllTransactions` query
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionQueryResult {
        /// Transaction
        pub tx_value: TransactionValue,
        /// The hash of the block to which `tx` belongs to
        pub block_hash: Hash,
    }
}

impl TransactionQueryResult {
    #[inline]
    /// Return payload of the transaction
    pub fn payload(&self) -> &TransactionPayload {
        self.tx_value.payload()
    }
}

impl PartialOrd for TransactionQueryResult {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TransactionQueryResult {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.payload()
            .creation_time
            .cmp(&other.payload().creation_time)
    }
}

#[cfg(any(feature = "ffi_import", feature = "ffi_export"))]
declare_versioned!(VersionedValidTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_import"), not(feature = "ffi_export")))]
declare_versioned!(VersionedValidTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, IntoSchema);

impl VersionedValidTransaction {
    /// Convert from `&VersionedValidTransaction` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Convert from `&mut VersionedValidTransaction` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedValidTransaction` to V1
    #[inline]
    pub fn into_v1(self) -> ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

impl Transaction for VersionedValidTransaction {
    type HashOf = VersionedSignedTransaction;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        &self.as_v1().payload
    }
}

model! {
    /// `ValidTransaction` represents trustfull Transaction state.
    #[version_with_scale(n = 1, versioned = "VersionedValidTransaction")]
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type]
    pub struct ValidTransaction {
        /// The [`Transaction`]'s payload.
        pub payload: TransactionPayload,
        /// [`SignatureOf`]<[`TransactionPayload`]>.
        pub signatures: SignaturesOf<TransactionPayload>,
    }
}

impl ValidTransaction {
    /// Return signatures
    pub fn signatures(&self) -> impl ExactSizeIterator<Item = &SignatureOf<TransactionPayload>> {
        self.signatures.iter()
    }
}

impl Transaction for ValidTransaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        &self.payload
    }
}

#[cfg(any(feature = "ffi_import", feature = "ffi_export"))]
declare_versioned!(VersionedRejectedTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_import"), not(feature = "ffi_export")))]
declare_versioned!(VersionedRejectedTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, IntoSchema);

impl VersionedRejectedTransaction {
    /// Convert from `&VersionedRejectedTransaction` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Convert from `&mut VersionedRejectedTransaction` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedRejectedTransaction` to V1
    #[inline]
    pub fn into_v1(self) -> RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

impl Transaction for VersionedRejectedTransaction {
    type HashOf = VersionedSignedTransaction;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        match self {
            Self::V1(v1) => &v1.payload,
        }
    }
}

model! {
    /// [`RejectedTransaction`] represents transaction rejected by some validator at some stage of the pipeline.
    #[version(n = 1, versioned = "VersionedRejectedTransaction")]
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type]
    pub struct RejectedTransaction {
        /// The [`Transaction`]'s payload.
        pub payload: TransactionPayload,
        /// [`SignatureOf`] [`Transaction`].
        pub signatures: SignaturesOf<TransactionPayload>,
        /// The reason for rejecting this transaction during the validation pipeline.
        #[getset(get = "pub")]
        pub rejection_reason: error::TransactionRejectionReason,
    }
}

impl RejectedTransaction {
    /// Return signatures
    pub fn signatures(&self) -> impl ExactSizeIterator<Item = &SignatureOf<TransactionPayload>> {
        self.signatures.iter()
    }
}

impl Transaction for RejectedTransaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        &self.payload
    }
}

impl From<VersionedRejectedTransaction> for VersionedSignedTransaction {
    fn from(transaction: VersionedRejectedTransaction) -> Self {
        match transaction {
            VersionedRejectedTransaction::V1(transaction) => {
                let signatures = transaction.signatures.into();

                SignedTransaction {
                    payload: transaction.payload,
                    signatures,
                }
                .into()
            }
        }
    }
}

#[cfg(feature = "transparent_api")]
declare_versioned_with_scale!(VersionedAcceptedTransaction 1..2, Debug, Clone, iroha_macro::FromVariant, Serialize);

model! {
    /// `AcceptedTransaction` — a transaction accepted by iroha peer.
    #[version_with_scale(n = 1, versioned = "VersionedAcceptedTransaction")]
    #[derive(Debug, Clone, Decode, Encode, Serialize)]
    pub(crate) struct AcceptedTransaction {
        /// Payload of this transaction.
        pub payload: TransactionPayload,
        /// Signatures for this transaction.
        pub signatures: SignaturesOf<TransactionPayload>,
    }
}

#[cfg(feature = "transparent_api")]
impl VersionedAcceptedTransaction {
    /// Convert from `&VersionedAcceptedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Convert from `&mut VersionedAcceptedTransaction` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedAcceptedTransaction` to V1
    pub fn into_v1(self) -> AcceptedTransaction {
        match self {
            VersionedAcceptedTransaction::V1(v1) => v1,
        }
    }
}

#[cfg(feature = "transparent_api")]
impl Transaction for VersionedAcceptedTransaction {
    type HashOf = VersionedSignedTransaction;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        &self.as_v1().payload
    }
}

#[cfg(feature = "transparent_api")]
impl Transaction for AcceptedTransaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &TransactionPayload {
        &self.payload
    }
}

#[cfg(feature = "transparent_api")]
impl AcceptedTransaction {
    /// Accept transaction. Transition from [`Transaction`] to [`AcceptedTransaction`].
    ///
    /// # Errors
    ///
    /// - if it does not adhere to limits
    /// - if signature verification fails
    #[cfg(feature = "std")]
    pub fn accept<const IS_GENESIS: bool>(
        transaction: SignedTransaction,
        limits: &TransactionLimits,
    ) -> Result<Self, error::AcceptTransactionFailure> {
        if !IS_GENESIS {
            transaction.check_limits(limits)?
        }
        let signatures: SignaturesOf<_> = transaction
            .signatures
            .try_into()
            .expect("Transaction should have at least one signature");
        signatures.verify(&transaction.payload)?;

        Ok(Self {
            payload: transaction.payload,
            signatures,
        })
    }
}

#[cfg(feature = "transparent_api")]
impl From<VersionedAcceptedTransaction> for VersionedSignedTransaction {
    fn from(tx: VersionedAcceptedTransaction) -> Self {
        let tx: AcceptedTransaction = tx.into_v1();
        let tx: SignedTransaction = tx.into();
        tx.into()
    }
}

#[cfg(feature = "transparent_api")]
impl From<AcceptedTransaction> for SignedTransaction {
    fn from(transaction: AcceptedTransaction) -> Self {
        SignedTransaction {
            payload: transaction.payload,
            signatures: transaction.signatures.into_iter().collect(),
        }
    }
}

mod base64 {
    //! Module with (de-)serialization functions for
    //! [`WasmSmartContract`](super::WasmSmartContract)'s bytes using `base64`.
    //!
    //! No extra heap allocation is performed nor for serialization nor for deserialization.

    use serde::{Deserializer, Serializer};

    #[cfg(not(feature = "std"))]
    use super::Vec;

    /// Serialize bytes using `base64`
    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&base64::display::Base64Display::with_config(
            bytes,
            base64::STANDARD,
        ))
    }

    /// Deserialize bytes using `base64`
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                base64::decode(v).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_str(Visitor)
    }
}

pub mod error {
    //! Module containing errors that can occur in transaction lifecycle
    use super::*;

    model! {
        /// Error type for transaction from [`Transaction`] to [`AcceptedTransaction`]
        #[derive(Debug, Display, FromVariant)]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        pub(crate) enum AcceptTransactionFailure {
            /// Failure during limits check
            TransactionLimit(#[cfg_attr(feature = "std", source)] TransactionLimitError),
            /// Failure during signature verification
            SignatureVerification(#[cfg_attr(feature = "std", source)] SignatureVerificationFail<TransactionPayload>),
        }

        /// Error which indicates max instruction count was reached
        #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `TransactionLimitError` has no trap representation in `String`
        #[ffi_type(unsafe {robust})]
        pub struct TransactionLimitError {
            /// Reason why signature condition failed
            pub reason: String
        }

        /// Transaction was reject because it doesn't satisfy signature condition
        #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[display(fmt = "Failed to verify signature condition specified in the account: {reason}")]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `UnsatisfiedSignatureConditionFail` has no trap representation in `String`
        #[ffi_type(unsafe {robust})]
        pub struct UnsatisfiedSignatureConditionFail {
            /// Reason why signature condition failed
            pub reason: String,
        }

        /// Transaction was rejected because of one of its instructions failing.
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[ffi_type]
        pub struct InstructionExecutionFail {
            /// Instruction for which execution failed
            #[getset(get = "pub")]
            pub instruction: InstructionBox,
            /// Error which happened during execution
            pub reason: String,
        }

        /// Transaction was reject because of low authority
        #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[display(fmt = "Action not permitted: {reason}")]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `NotPermittedFail` has no trap representation in `String`
        #[ffi_type(unsafe {robust})]
        pub struct NotPermittedFail {
            /// The cause of failure.
            pub reason: String,
        }

        /// Transaction was rejected because execution of `WebAssembly` binary failed
        #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[display(fmt = "Failed to execute wasm binary: {reason}")]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `WasmExecutionFail` has no trap representation in `String`
        #[ffi_type(unsafe {robust})]
        pub struct WasmExecutionFail {
            /// Error which happened during execution
            pub reason: String,
        }

        /// Transaction was reject because expired
        #[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[display(fmt = "Transaction expired: consider increase transaction ttl (current {time_to_live_ms}ms)")]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `TransactionExpired` has no trap representation in `u64`
        #[ffi_type(unsafe {robust})]
        pub struct TransactionExpired {
            /// Transaction ttl.
            pub time_to_live_ms: u64,
        }

        /// The reason for rejecting transaction which happened because of transaction.
        #[derive(Debug, Display, Clone, PartialEq, Eq, Hash, FromVariant, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        #[ffi_type(local)]
        pub enum TransactionRejectionReason {
            /// Failed to validate transaction limits (e.g. number of instructions)
            #[display(fmt = "Transaction rejected due to an unsatisfied limit condition: {_0}")]
            LimitCheck(#[cfg_attr(feature = "std", source)] error::TransactionLimitError),
            /// Insufficient authorisation.
            #[display(fmt = "Transaction rejected due to insufficient authorisation: {_0}")]
            NotPermitted(#[cfg_attr(feature = "std", source)] NotPermittedFail),
            /// Failed to verify signature condition specified in the account.
            #[display(fmt = "Transaction rejected due to an unsatisfied signature condition: {_0}")]
            UnsatisfiedSignatureCondition(#[cfg_attr(feature = "std", source)] UnsatisfiedSignatureConditionFail),
            /// Failed to execute instruction.
            #[display(fmt = "Transaction rejected due to failure in instruction execution: {_0}")]
            InstructionExecution(#[cfg_attr(feature = "std", source)] InstructionExecutionFail),
            /// Failed to execute WebAssembly binary.
            #[display(fmt = "Transaction rejected due to failure in WebAssembly execution: {_0}")]
            WasmExecution(#[cfg_attr(feature = "std", source)] WasmExecutionFail),
            /// Genesis account can sign only transactions in the genesis block.
            #[display(fmt = "The genesis account can only sign transactions in the genesis block")]
            UnexpectedGenesisAccountSignature,
            /// Transaction gets expired.
            #[display(fmt = "Transaction rejected due to being expired: {_0}")]
            Expired(#[cfg_attr(feature = "std", source)] TransactionExpired),
        }
    }

    impl Display for InstructionExecutionFail {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            use InstructionBox::*;
            let kind = match self.instruction {
                Burn(_) => "burn",
                Fail(_) => "fail",
                If(_) => "if",
                Mint(_) => "mint",
                Pair(_) => "pair",
                Register(_) => "register",
                Sequence(_) => "sequence",
                Transfer(_) => "transfer",
                Unregister(_) => "un-register",
                SetKeyValue(_) => "set key-value pair",
                RemoveKeyValue(_) => "remove key-value pair",
                Grant(_) => "grant",
                Revoke(_) => "revoke",
                ExecuteTrigger(_) => "execute trigger",
                SetParameter(_) => "set parameter",
                NewParameter(_) => "new parameter",
            };
            write!(
                f,
                "Failed to execute instruction of type {}: {}",
                kind, self.reason
            )
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for TransactionLimitError {}

    #[cfg(feature = "std")]
    impl std::error::Error for UnsatisfiedSignatureConditionFail {}

    #[cfg(feature = "std")]
    impl std::error::Error for InstructionExecutionFail {}

    #[cfg(feature = "std")]
    impl std::error::Error for WasmExecutionFail {}

    #[cfg(feature = "std")]
    impl std::error::Error for NotPermittedFail {}

    #[cfg(feature = "std")]
    impl std::error::Error for TransactionExpired {}

    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this module.

        pub use super::{
            InstructionExecutionFail, NotPermittedFail, TransactionRejectionReason,
            UnsatisfiedSignatureConditionFail, WasmExecutionFail,
        };
    }
}

#[cfg(feature = "http")]
mod http {
    #[cfg(not(feature = "std"))]
    use alloc::vec::vec;
    #[cfg(feature = "std")]
    use std::vec;

    use iroha_version::declare_versioned_with_scale;
    use warp::{reply::Response, Reply};

    use super::*;

    declare_versioned_with_scale!(VersionedPendingTransactions 1..2, Debug, Clone, FromVariant, IntoSchema);

    model! {
        /// Represents a collection of transactions that the peer sends to describe its pending transactions in a queue.
        #[version_with_scale(n = 1, versioned = "VersionedPendingTransactions")]
        #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `PendingTransactions` has no trap representation in `Vec<Transaction>`
        #[ffi_type(unsafe {robust})]
        pub struct PendingTransactions(Vec<SignedTransaction>);
    }

    impl VersionedPendingTransactions {
        /// Convert from `&VersionedPendingTransactions` to V1 reference
        #[inline]
        pub const fn as_v1(&self) -> &PendingTransactions {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Convert from `&mut VersionedPendingTransactions` to V1 mutable reference
        #[inline]
        pub fn as_mut_v1(&mut self) -> &mut PendingTransactions {
            match self {
                Self::V1(v1) => v1,
            }
        }

        /// Performs the conversion from `VersionedPendingTransactions` to V1
        #[inline]
        pub fn into_v1(self) -> PendingTransactions {
            match self {
                Self::V1(v1) => v1,
            }
        }
    }

    impl FromIterator<SignedTransaction> for PendingTransactions {
        fn from_iter<T: IntoIterator<Item = SignedTransaction>>(iter: T) -> Self {
            Self(iter.into_iter().collect())
        }
    }

    impl IntoIterator for PendingTransactions {
        type Item = SignedTransaction;

        type IntoIter = vec::IntoIter<Self::Item>;

        fn into_iter(self) -> Self::IntoIter {
            let PendingTransactions(transactions) = self;
            transactions.into_iter()
        }
    }

    impl Reply for VersionedPendingTransactions {
        #[inline]
        fn into_response(self) -> Response {
            use iroha_version::scale::EncodeVersioned;
            Response::new(self.encode_versioned().into())
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::http::{PendingTransactions, VersionedPendingTransactions};
    #[cfg(feature = "std")]
    pub use super::Sign;
    pub use super::{
        error::prelude::*, Executable, RejectedTransaction, SignedTransaction, Transaction,
        TransactionBuilder, TransactionLimits, TransactionPayload, TransactionQueryResult,
        TransactionValue, ValidTransaction, VersionedRejectedTransaction,
        VersionedSignedTransaction, VersionedValidTransaction, WasmSmartContract,
    };
    #[cfg(feature = "transparent_api")]
    pub use super::{AcceptedTransaction, VersionedAcceptedTransaction};
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::restriction)]

    use super::*;
    #[cfg(feature = "transparent_api")]
    use crate::prelude::FailBox;

    #[test]
    #[cfg(feature = "transparent_api")]
    fn transaction_not_accepted_max_instruction_number() {
        let key_pair = iroha_crypto::KeyPair::generate().expect("Failed to generate key pair.");
        let inst: InstructionBox = FailBox {
            message: "Will fail".to_owned(),
        }
        .into();
        let tx = TransactionBuilder::new(
            "root@global".parse().expect("Valid"),
            vec![inst; DEFAULT_MAX_INSTRUCTION_NUMBER as usize + 1],
            1000,
        )
        .sign(key_pair)
        .expect("Valid");
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };
        let result = AcceptedTransaction::accept::<false>(tx, &tx_limits);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "Too many instructions in payload, max number is {}, but got {}",
                tx_limits.max_instruction_number,
                DEFAULT_MAX_INSTRUCTION_NUMBER + 1
            )
        );
    }

    #[test]
    #[cfg(feature = "transparent_api")]
    fn genesis_transaction_ignore_limits() {
        let key_pair = iroha_crypto::KeyPair::generate().expect("Failed to generate key pair.");
        let inst: InstructionBox = FailBox {
            message: "Will fail".to_owned(),
        }
        .into();
        let tx = TransactionBuilder::new(
            "root@global".parse().expect("Valid"),
            vec![inst; DEFAULT_MAX_INSTRUCTION_NUMBER as usize + 1],
            1000,
        )
        .sign(key_pair)
        .expect("Valid");
        let tx_limits = TransactionLimits {
            max_instruction_number: 4096,
            max_wasm_size_bytes: 0,
        };

        assert!(AcceptedTransaction::accept::<true>(tx, &tx_limits).is_ok());
    }

    #[test]
    fn wasm_smart_contract_debug_repr_should_contain_just_len() {
        let contract = WasmSmartContract::new(vec![0, 1, 2, 3, 4]);
        assert_eq!(format!("{contract:?}"), "WASM binary(len = 5)");
    }
}
