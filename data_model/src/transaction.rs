//! [`Transaction`] structures and related implementations.
#![allow(clippy::std_instead_of_core)]
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, collections::btree_set, format, string::String, vec, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    iter::IntoIterator,
};
#[cfg(feature = "std")]
use std::{collections::btree_set, time::Duration, vec};

use derive_more::{DebugCustom, Display};
use iroha_crypto::{Hash, SignatureOf, SignaturesOf};
use iroha_ffi::FfiType;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, declare_versioned_with_scale, version, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "warp")]
use warp::{reply::Response, Reply};

use crate::{account::Account, ffi, isi::Instruction, metadata::UnlimitedMetadata, Identifiable};

/// Default maximum number of instructions and expressions per transaction
pub const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);

/// Error which indicates max instruction count was reached
#[derive(
    Debug, Clone, PartialEq, Eq, Display, Decode, Encode, Deserialize, Serialize, IntoSchema, Hash,
)]
pub struct TransactionLimitError(String);

#[cfg(feature = "std")]
impl std::error::Error for TransactionLimitError {}

/// Default maximum number of instructions and expressions per transaction
pub const DEFAULT_MAX_WASM_SIZE_BYTES: u64 = 2_u64.pow(22); // 4 MiB

/// Trait for basic transaction operations
pub trait Txn {
    /// Result of hashing
    type HashOf: Txn;

    /// Returns payload of a transaction
    fn payload(&self) -> &Payload;

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
    #[allow(clippy::expect_used)]
    fn check_limits(&self, limits: &TransactionLimits) -> Result<(), TransactionLimitError> {
        match &self.payload().instructions {
            Executable::Instructions(instructions) => {
                let instruction_count: u64 = instructions
                    .iter()
                    .map(Instruction::len)
                    .sum::<usize>()
                    .try_into()
                    .expect("`usize` should always fit in `u64`");

                if instruction_count > limits.max_instruction_number {
                    return Err(TransactionLimitError(format!(
                        "Too many instructions in payload, max number is {}, but got {}",
                        limits.max_instruction_number, instruction_count
                    )));
                }
            }
            Executable::Wasm(WasmSmartContract { raw_data }) => {
                let len: u64 = raw_data
                    .len()
                    .try_into()
                    .expect("`usize` should always fit in `u64`");

                if len > limits.max_wasm_size_bytes {
                    return Err(TransactionLimitError(format!(
                        "Wasm binary too large, max size is {}, but got {}",
                        limits.max_wasm_size_bytes, len
                    )));
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

/// Either ISI or Wasm binary
#[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum Executable {
    /// Ordered set of instructions.
    Instructions(Vec<Instruction>),
    /// WebAssembly smartcontract
    Wasm(WasmSmartContract),
}

impl<T: IntoIterator<Item = Instruction>> From<T> for Executable {
    fn from(collection: T) -> Self {
        Self::Instructions(collection.into_iter().collect())
    }
}

/// Wrapper for byte representation of [`Executable::Wasm`].
///
/// Uses **base64** (de-)serialization format.
#[derive(
    Clone, DebugCustom, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[debug(fmt = "<WASM is truncated>")]
pub struct WasmSmartContract {
    /// Raw wasm blob.
    #[serde(with = "base64")]
    pub raw_data: Vec<u8>,
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
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                base64::decode(v).map_err(serde::de::Error::custom)
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

impl AsRef<[u8]> for WasmSmartContract {
    fn as_ref(&self) -> &[u8] {
        self.raw_data.as_ref()
    }
}

/// Iroha [`Transaction`] payload.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Payload {
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

impl Payload {
    /// Used to compare the contents of the transaction independent of when it was created.
    pub fn equals_excluding_creation_time(&self, other: &Payload) -> bool {
        self.account_id == other.account_id
            && self.instructions == other.instructions
            && self.time_to_live_ms == other.time_to_live_ms
            && self.metadata == other.metadata
    }
}

/// Container for limits that transactions must obey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct TransactionLimits {
    /// Maximum number of instructions per transaction
    pub max_instruction_number: u64,
    /// Maximum size of wasm binary
    pub max_wasm_size_bytes: u64,
}

declare_versioned!(
    VersionedSignedTransaction 1..2,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    FromVariant,
    FfiType,
    IntoSchema,
);

impl VersionedSignedTransaction {
    /// Converts from `&VersionedSignedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &SignedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedSignedTransaction` to V1 mutable reference
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

impl Txn for VersionedSignedTransaction {
    type HashOf = Self;

    #[inline]
    fn payload(&self) -> &Payload {
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

/// Trait for signing transactions
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

/// Structure that represents the initial state of a transaction before the transaction receives any signatures.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FfiType,
    IntoSchema,
)]
#[display(fmt = "{self:?}")] // TODO ?
pub struct Transaction {
    /// [`Transaction`] payload.
    pub payload: Payload,
}

impl Transaction {
    /// Construct [`Self`].
    #[inline]
    #[must_use]
    #[cfg(feature = "std")]
    pub fn new(
        account_id: <Account as Identifiable>::Id,
        instructions: Executable,
        proposed_ttl_ms: u64,
    ) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let creation_time = crate::current_time().as_millis() as u64;

        Self {
            payload: Payload {
                account_id,
                instructions,
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
impl Sign for Transaction {
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

impl Txn for Transaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

/// Structure that represents the second state of the transaction after receiving at least one signature.
///
/// `Iroha` and its clients use [`SignedTransaction`] to send transactions over the network.
/// After a transaction is signed and before it can be processed any further,
/// the transaction must be accepted by the `Iroha` peer.
/// The peer verifies the signatures and checks the limits.
#[version(n = 1, versioned = "VersionedSignedTransaction")]
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FfiType,
    IntoSchema,
)]
#[display(fmt = "{self:?}")] // TODO ?
pub struct SignedTransaction {
    /// [`Transaction`] payload.
    pub payload: Payload,
    /// [`SignatureOf`] [`Payload`].
    pub signatures: btree_set::BTreeSet<SignatureOf<Payload>>,
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

impl Txn for SignedTransaction {
    type HashOf = Self;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

declare_versioned_with_scale!(VersionedPendingTransactions 1..2, Debug, Clone, FromVariant);

impl VersionedPendingTransactions {
    /// Converts from `&VersionedPendingTransactions` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &PendingTransactions {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedPendingTransactions` to V1 mutable reference
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

impl FromIterator<SignedTransaction> for VersionedPendingTransactions {
    fn from_iter<T: IntoIterator<Item = SignedTransaction>>(iter: T) -> Self {
        PendingTransactions(iter.into_iter().collect()).into()
    }
}

#[cfg(feature = "warp")]
impl Reply for VersionedPendingTransactions {
    #[inline]
    fn into_response(self) -> Response {
        use iroha_version::scale::EncodeVersioned;
        Response::new(self.encode_versioned().into())
    }
}

/// Represents a collection of transactions that the peer sends to describe its pending transactions in a queue.
#[version_with_scale(n = 1, versioned = "VersionedPendingTransactions")]
#[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct PendingTransactions(pub Vec<SignedTransaction>);

impl FromIterator<SignedTransaction> for PendingTransactions {
    fn from_iter<T: IntoIterator<Item = SignedTransaction>>(iter: T) -> Self {
        PendingTransactions(iter.into_iter().collect())
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

/// Transaction Value used in Instructions and Queries
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, FfiType, IntoSchema,
)]
#[ffi_type(local)]
pub enum TransactionValue {
    /// Committed transaction
    Transaction(Box<VersionedSignedTransaction>),
    /// Rejected transaction with reason of rejection
    RejectedTransaction(Box<VersionedRejectedTransaction>),
}

impl TransactionValue {
    /// Used to return payload of the transaction
    #[inline]
    pub fn payload(&self) -> &Payload {
        match self {
            TransactionValue::Transaction(tx) => tx.payload(),
            TransactionValue::RejectedTransaction(tx) => tx.payload(),
        }
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

impl PartialOrd for TransactionValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.payload()
                .creation_time
                .cmp(&other.payload().creation_time),
        )
    }
}

ffi::declare_item! {
    /// `TransactionQueryResult` is used in `FindAllTransactions` query
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, FfiType, IntoSchema)]
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
    pub fn payload(&self) -> &Payload {
        self.tx_value.payload()
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

impl PartialOrd for TransactionQueryResult {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            self.payload()
                .creation_time
                .cmp(&other.payload().creation_time),
        )
    }
}

declare_versioned!(VersionedValidTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, IntoSchema);

impl VersionedValidTransaction {
    /// Converts from `&VersionedValidTransaction` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedValidTransaction` to V1 mutable reference
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

impl Txn for VersionedValidTransaction {
    type HashOf = VersionedSignedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.as_v1().payload
    }
}

/// `ValidTransaction` represents trustfull Transaction state.
#[version_with_scale(n = 1, versioned = "VersionedValidTransaction")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct ValidTransaction {
    /// The [`Transaction`]'s payload.
    pub payload: Payload,
    /// [`SignatureOf`] [`Payload`].
    pub signatures: SignaturesOf<Payload>,
}

impl Txn for ValidTransaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

declare_versioned!(VersionedRejectedTransaction 1..2, Debug, Clone, PartialEq, Eq, Hash, FromVariant, FfiType, IntoSchema);

impl VersionedRejectedTransaction {
    /// Converts from `&VersionedRejectedTransaction` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedRejectedTransaction` to V1 mutable reference
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

impl Txn for VersionedRejectedTransaction {
    type HashOf = VersionedSignedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        match self {
            Self::V1(v1) => &v1.payload,
        }
    }
}

/// [`RejectedTransaction`] represents transaction rejected by some validator at some stage of the pipeline.
#[version(n = 1, versioned = "VersionedRejectedTransaction")]
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, Decode, Encode, Deserialize, Serialize, FfiType, IntoSchema,
)]
pub struct RejectedTransaction {
    /// The [`Transaction`]'s payload.
    pub payload: Payload,
    /// [`SignatureOf`] [`Transaction`].
    pub signatures: SignaturesOf<Payload>,
    /// The reason for rejecting this transaction during the validation pipeline.
    pub rejection_reason: TransactionRejectionReason,
}

impl Txn for RejectedTransaction {
    type HashOf = SignedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

/// Transaction was reject because it doesn't satisfy signature condition
#[derive(
    Debug, Clone, PartialEq, Eq, Display, Decode, Encode, Deserialize, Serialize, IntoSchema, Hash,
)]
#[display(
    fmt = "Failed to verify signature condition specified in the account: {}",
    reason
)]
pub struct UnsatisfiedSignatureConditionFail {
    /// Reason why signature condition failed
    pub reason: String,
}

#[cfg(feature = "std")]
impl std::error::Error for UnsatisfiedSignatureConditionFail {}

/// Transaction was rejected because of one of its instructions failing.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema, Hash)]
pub struct InstructionExecutionFail {
    /// Instruction which execution failed
    pub instruction: Instruction,
    /// Error which happened during execution
    pub reason: String,
}

impl Display for InstructionExecutionFail {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        use Instruction::*;
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
        };
        write!(
            f,
            "Failed to execute instruction of type {}: {}",
            kind, self.reason
        )
    }
}
#[cfg(feature = "std")]
impl std::error::Error for InstructionExecutionFail {}

/// Transaction was rejected because execution of `WebAssembly` binary failed
#[derive(
    Debug, Clone, PartialEq, Eq, Display, Decode, Encode, Deserialize, Serialize, IntoSchema, Hash,
)]
#[display(fmt = "Failed to execute wasm binary: {}", reason)]
pub struct WasmExecutionFail {
    /// Error which happened during execution
    pub reason: String,
}

#[cfg(feature = "std")]
impl std::error::Error for WasmExecutionFail {}

/// Transaction was reject because of low authority
#[derive(
    Debug, Clone, PartialEq, Eq, Display, Decode, Encode, Deserialize, Serialize, IntoSchema, Hash,
)]
#[display(fmt = "Action not permitted: {}", reason)]
pub struct NotPermittedFail {
    /// The cause of failure.
    pub reason: String,
}

#[cfg(feature = "std")]
impl std::error::Error for NotPermittedFail {}

/// The reason for rejecting transaction which happened because of new blocks.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Display,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
#[display(fmt = "Block was rejected during consensus")]
pub enum BlockRejectionReason {
    /// Block was rejected during consensus.
    ConsensusBlockRejection,
}

#[cfg(feature = "std")]
impl std::error::Error for BlockRejectionReason {}

/// The reason for rejecting transaction which happened because of transaction.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Display,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
    Hash,
)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum TransactionRejectionReason {
    /// Insufficient authorisation.
    #[display(fmt = "Transaction rejected due to insufficient authorisation: {}", self.0)]
    NotPermitted(#[cfg_attr(feature = "std", source)] NotPermittedFail),
    /// Failed to verify signature condition specified in the account.
    #[display(fmt = "Transaction rejected due to an unsatisfied signature condition: {}", self.0)]
    UnsatisfiedSignatureCondition(
        #[cfg_attr(feature = "std", source)] UnsatisfiedSignatureConditionFail,
    ),
    /// Failed to validate transaction limits (e.g. number of instructions)
    #[display(fmt = "Transaction rejected due to an unsatisfied limit condition: {}", self.0)]
    LimitCheck(#[cfg_attr(feature = "std", source)] TransactionLimitError),
    /// Failed to execute instruction.
    #[display(fmt = "Transaction rejected due to failure in instruction execution: {}", self.0)]
    InstructionExecution(#[cfg_attr(feature = "std", source)] InstructionExecutionFail),
    /// Failed to execute WebAssembly binary.
    #[display(fmt = "Transaction rejected due to failure in WebAssembly execution: {}", self.0)]
    WasmExecution(#[cfg_attr(feature = "std", source)] WasmExecutionFail),
    /// Genesis account can sign only transactions in the genesis block.
    #[display(fmt = "The genesis account can only sign transactions in the genesis block.")]
    UnexpectedGenesisAccountSignature,
}

/// The reason for rejecting pipeline entity such as transaction or block.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Display,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    FromVariant,
    IntoSchema,
)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum RejectionReason {
    /// The reason for rejecting the block.
    #[display(fmt = "Block was rejected: {}", self.0)]
    Block(#[cfg_attr(feature = "std", source)] BlockRejectionReason),
    /// The reason for rejecting transaction.
    #[display(fmt = "Transaction was rejected: {}", self.0)]
    Transaction(#[cfg_attr(feature = "std", source)] TransactionRejectionReason),
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{
        BlockRejectionReason, Executable, InstructionExecutionFail, NotPermittedFail, Payload,
        PendingTransactions, RejectedTransaction, RejectionReason, Sign, SignedTransaction,
        Transaction, TransactionLimits, TransactionQueryResult, TransactionRejectionReason,
        TransactionValue, Txn, UnsatisfiedSignatureConditionFail, ValidTransaction,
        VersionedPendingTransactions, VersionedRejectedTransaction, VersionedSignedTransaction,
        VersionedValidTransaction, WasmExecutionFail, WasmSmartContract,
    };
}
