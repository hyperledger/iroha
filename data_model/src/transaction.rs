//! This module contains [`Transaction`] structures and related implementations

use std::{cmp::Ordering, collections::BTreeSet, vec::IntoIter as VecIter};

use eyre::{eyre, Result};
use iroha_crypto::{HashOf, KeyPair, SignatureOf, SignaturesOf};
use iroha_macro::Io;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, declare_versioned_with_scale, version, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
#[cfg(feature = "warp")]
use warp::{reply::Response, Reply};

use crate::{
    account::Account, current_time, isi::Instruction, metadata::UnlimitedMetadata,
    prelude::TransactionRejectionReason, Identifiable,
};

/// Default maximum number of instructions and expressions per transaction
pub const DEFAULT_MAX_INSTRUCTION_NUMBER: u64 = 2_u64.pow(12);

/// Trait for basic transaction operations
pub trait Txn {
    /// Result of hashing
    type HashOf: Txn;

    /// Returns payload of a transaction
    fn payload(&self) -> &Payload;

    /// Checks if number of instructions in payload exceeds maximum
    ///
    /// # Errors
    /// Fails if instruction length exceeds maximum instruction number
    #[inline]
    fn check_instruction_len(&self, max_instruction_len: u64) -> Result<()> {
        self.payload().check_instruction_len(max_instruction_len)
    }

    /// Calculate transaction [`Hash`](`iroha_crypto::Hash`).
    #[inline]
    fn hash(&self) -> HashOf<Self::HashOf>
    where
        Self: Sized,
    {
        HashOf::new(&self.payload()).transmute()
    }
}

/// Iroha [`Transaction`] payload.
#[derive(Clone, Debug, Io, Encode, Decode, Serialize, Deserialize, Eq, PartialEq, IntoSchema)]
pub struct Payload {
    /// Account ID of transaction creator.
    pub account_id: <Account as Identifiable>::Id,
    /// An ordered set of instructions.
    pub instructions: Vec<Instruction>,
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

    /// Checks if number of instructions in payload exceeds maximum
    ///
    /// # Errors
    /// Fails if instruction length exceeds maximum instruction number
    pub fn check_instruction_len(&self, max_instruction_number: u64) -> Result<()> {
        if self
            .instructions
            .iter()
            .map(Instruction::len)
            .sum::<usize>() as u64
            > max_instruction_number
        {
            return Err(eyre!("Too many instructions in payload"));
        }
        Ok(())
    }
}

declare_versioned!(
    VersionedTransaction 1..2,
    Debug,
    Clone,
    PartialEq,
    Eq,
    iroha_macro::FromVariant,
    IntoSchema,
);

impl VersionedTransaction {
    /// Converts from `&VersionedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &Transaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedTransaction` to V1 mutable reference
    #[inline]
    pub fn as_mut_v1(&mut self) -> &mut Transaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedTransaction` to V1
    #[inline]
    pub fn into_v1(self) -> Transaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Default [`Transaction`] constructor.
    #[inline]
    pub fn new(
        instructions: Vec<Instruction>,
        account_id: <Account as Identifiable>::Id,
        proposed_ttl_ms: u64,
    ) -> VersionedTransaction {
        Transaction::new(instructions, account_id, proposed_ttl_ms).into()
    }

    /// Sign transaction with the provided key pair.
    ///
    /// # Errors
    /// Fails if signature creation fails
    pub fn sign(self, key_pair: &KeyPair) -> Result<VersionedTransaction> {
        self.into_v1().sign(key_pair).map(Into::into)
    }
}

impl Txn for VersionedTransaction {
    type HashOf = Self;

    #[inline]
    fn payload(&self) -> &Payload {
        match self {
            Self::V1(v1) => &v1.payload,
        }
    }
}

impl From<VersionedValidTransaction> for VersionedTransaction {
    fn from(transaction: VersionedValidTransaction) -> Self {
        match transaction {
            VersionedValidTransaction::V1(transaction) => {
                let signatures = transaction
                    .signatures
                    .values()
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                let transaction = Transaction {
                    payload: transaction.payload,
                    signatures,
                };
                transaction.into()
            }
        }
    }
}

/// This structure represents transaction in non-trusted form.
///
/// `Iroha` and its' clients use [`Transaction`] to send transactions via network.
/// Direct usage in business logic is strongly prohibited. Before any interactions
/// `accept`.
#[version(n = 1, versioned = "VersionedTransaction")]
#[derive(Clone, Debug, Io, Encode, Decode, Serialize, Deserialize, Eq, PartialEq, IntoSchema)]
pub struct Transaction {
    /// [`Transaction`] payload.
    pub payload: Payload,
    /// [`Transaction`]'s [`Signature`]s.
    pub signatures: BTreeSet<SignatureOf<Payload>>,
}

impl Transaction {
    /// Default [`Transaction`] constructor.
    #[inline]
    pub fn new(
        instructions: Vec<Instruction>,
        account_id: <Account as Identifiable>::Id,
        proposed_ttl_ms: u64,
    ) -> Transaction {
        Transaction::with_metadata(
            instructions,
            account_id,
            proposed_ttl_ms,
            UnlimitedMetadata::new(),
            None,
        )
    }

    /// [`Transaction`] constructor with nonce.
    #[inline]
    pub fn with_nonce(
        instructions: Vec<Instruction>,
        account_id: <Account as Identifiable>::Id,
        proposed_ttl_ms: u64,
        nonce: u32,
    ) -> Transaction {
        Transaction::with_metadata(
            instructions,
            account_id,
            proposed_ttl_ms,
            UnlimitedMetadata::new(),
            Some(nonce),
        )
    }

    /// [`Transaction`] constructor with metadata.
    #[inline]
    pub fn with_metadata(
        instructions: Vec<Instruction>,
        account_id: <Account as Identifiable>::Id,
        proposed_ttl_ms: u64,
        metadata: UnlimitedMetadata,
        nonce: Option<u32>,
    ) -> Transaction {
        #[allow(clippy::cast_possible_truncation, clippy::expect_used)]
        Transaction {
            payload: Payload {
                instructions,
                account_id,
                creation_time: current_time().as_millis() as u64,
                time_to_live_ms: proposed_ttl_ms,
                nonce,
                metadata,
            },
            signatures: BTreeSet::new(),
        }
    }

    /// Sign transaction with the provided key pair.
    ///
    /// # Errors
    /// Fails if signature creation fails
    pub fn sign(self, key_pair: &KeyPair) -> Result<Transaction> {
        let mut signatures = self.signatures.clone();
        signatures.insert(SignatureOf::new(key_pair.clone(), &self.payload)?);
        Ok(Transaction {
            payload: self.payload,
            signatures,
        })
    }
}

impl Txn for Transaction {
    type HashOf = Self;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

declare_versioned_with_scale!(VersionedPendingTransactions 1..2, iroha_macro::FromVariant, Clone, Debug);

impl VersionedPendingTransactions {
    /// Converts from `&VersionedPendingTransactions` to V1 reference
    pub const fn as_v1(&self) -> &PendingTransactions {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedPendingTransactions` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut PendingTransactions {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedPendingTransactions` to V1
    pub fn into_v1(self) -> PendingTransactions {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

impl FromIterator<Transaction> for VersionedPendingTransactions {
    fn from_iter<T: IntoIterator<Item = Transaction>>(iter: T) -> Self {
        PendingTransactions(iter.into_iter().collect()).into()
    }
}

#[cfg(feature = "warp")]
impl Reply for VersionedPendingTransactions {
    fn into_response(self) -> Response {
        use iroha_version::scale::EncodeVersioned;

        match self.encode_versioned() {
            Ok(bytes) => Response::new(bytes.into()),
            Err(e) => e.into_response(),
        }
    }
}

/// Represents a collection of transactions that the peer sends to describe its pending transactions in a queue.
#[version_with_scale(n = 1, versioned = "VersionedPendingTransactions")]
#[derive(Debug, Clone, Encode, Decode, Deserialize, Serialize, Io, IntoSchema)]
pub struct PendingTransactions(pub Vec<Transaction>);

impl FromIterator<Transaction> for PendingTransactions {
    fn from_iter<T: IntoIterator<Item = Transaction>>(iter: T) -> Self {
        PendingTransactions(iter.into_iter().collect())
    }
}

impl IntoIterator for PendingTransactions {
    type Item = Transaction;

    type IntoIter = VecIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        let PendingTransactions(transactions) = self;
        transactions.into_iter()
    }
}

/// Transaction Value used in Instructions and Queries
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, IntoSchema)]
pub enum TransactionValue {
    /// Committed transaction
    Transaction(VersionedTransaction),
    /// Rejected transaction with reason of rejection
    RejectedTransaction(VersionedRejectedTransaction),
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

declare_versioned_with_scale!(VersionedValidTransaction 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

impl VersionedValidTransaction {
    /// Converts from `&VersionedValidTransaction` to V1 reference
    #[inline]
    pub const fn as_v1(&self) -> &ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedValidTransaction` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedValidTransaction` to V1
    pub fn into_v1(self) -> ValidTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

impl Txn for VersionedValidTransaction {
    type HashOf = VersionedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.as_v1().payload
    }
}

/// `ValidTransaction` represents trustfull Transaction state.
#[version_with_scale(n = 1, versioned = "VersionedValidTransaction")]
#[derive(Clone, Debug, Io, Encode, Decode, iroha_schema::IntoSchema)]
pub struct ValidTransaction {
    /// The [`Transaction`]'s payload.
    pub payload: Payload,
    /// [`Transaction`]'s [`Signature`]s.
    pub signatures: SignaturesOf<Payload>,
}

impl Txn for ValidTransaction {
    type HashOf = Transaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

declare_versioned!(VersionedRejectedTransaction 1..2, Clone, Debug, PartialEq, Eq, iroha_macro::FromVariant, IntoSchema);

impl VersionedRejectedTransaction {
    /// Converts from `&VersionedRejectedTransaction` to V1 reference
    pub const fn as_v1(&self) -> &RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Converts from `&mut VersionedRejectedTransaction` to V1 mutable reference
    pub fn as_mut_v1(&mut self) -> &mut RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }

    /// Performs the conversion from `VersionedRejectedTransaction` to V1
    pub fn into_v1(self) -> RejectedTransaction {
        match self {
            Self::V1(v1) => v1,
        }
    }
}

impl Txn for VersionedRejectedTransaction {
    type HashOf = VersionedTransaction;

    #[inline]
    fn payload(&self) -> &Payload {
        match self {
            Self::V1(v1) => &v1.payload,
        }
    }
}

/// [`RejectedTransaction`] represents transaction rejected by some validator at some stage of the pipeline.
#[version(n = 1, versioned = "VersionedRejectedTransaction")]
#[derive(Clone, Debug, Io, Encode, Decode, Serialize, Deserialize, PartialEq, Eq, IntoSchema)]
pub struct RejectedTransaction {
    /// The [`Transaction`]'s payload.
    pub payload: Payload,
    /// [`Transaction`]'s [`Signature`]s.
    pub signatures: SignaturesOf<Payload>,
    /// The reason for rejecting this transaction during the validation pipeline.
    pub rejection_reason: TransactionRejectionReason,
}

impl Txn for RejectedTransaction {
    type HashOf = Transaction;

    #[inline]
    fn payload(&self) -> &Payload {
        &self.payload
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    pub use super::{
        Payload, PendingTransactions, RejectedTransaction, Transaction, TransactionValue, Txn,
        ValidTransaction, VersionedPendingTransactions, VersionedRejectedTransaction,
        VersionedTransaction, VersionedValidTransaction,
    };
}
