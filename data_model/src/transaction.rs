//! [`Transaction`] structures and related implementations.
#![allow(clippy::std_instead_of_core)]
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{Display, Formatter, Result as FmtResult},
    iter::IntoIterator,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

use derive_more::{DebugCustom, Display};
use getset::Getters;
use iroha_crypto::SignaturesOf;
use iroha_data_model_derive::model;
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version};
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

pub use self::model::*;
use crate::{
    account::AccountId,
    isi::{Instruction, InstructionBox},
    metadata::UnlimitedMetadata,
    name::Name,
    Value,
};

#[model]
pub mod model {
    use super::*;

    /// Either ISI or Wasm binary
    #[derive(
        DebugCustom,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    // TODO: Temporarily made opaque
    #[ffi_type(opaque)]
    pub enum Executable {
        /// Ordered set of instructions.
        #[debug(fmt = "{_0:?}")]
        Instructions(Vec<InstructionBox>),
        /// WebAssembly smartcontract
        Wasm(WasmSmartContract),
    }

    /// Wrapper for byte representation of [`Executable::Wasm`].
    ///
    /// Uses **base64** (de-)serialization format.
    #[derive(
        DebugCustom,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[debug(fmt = "WASM binary(len = {})", "self.0.len()")]
    #[serde(transparent)]
    #[repr(transparent)]
    // SAFETY: `WasmSmartContract` has no trap representation in `Vec<u8>`
    #[ffi_type(unsafe {robust})]
    pub struct WasmSmartContract(
        /// Raw wasm blob.
        #[serde(with = "base64")]
        pub(super) Vec<u8>,
    );

    /// Iroha [`Transaction`] payload.
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionPayload {
        /// Creation timestamp (unix time in milliseconds).
        #[getset(skip)]
        pub creation_time_ms: u64,
        /// Account ID of transaction creator.
        pub authority: AccountId,
        /// ISI or a `WebAssembly` smartcontract.
        pub instructions: Executable,
        /// If transaction is not committed by this time it will be dropped.
        #[getset(skip)]
        pub time_to_live_ms: Option<NonZeroU64>,
        /// Random value to make different hashes for transactions which occur repeatedly and simultaneously.
        // TODO: Only temporary
        #[getset(skip)]
        pub nonce: Option<NonZeroU32>,
        /// Store for additional information.
        #[getset(skip)]
        pub metadata: UnlimitedMetadata,
    }

    /// Container for limits that transactions must obey.
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "{max_instruction_number},{max_wasm_size_bytes}_TL")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct TransactionLimits {
        /// Maximum number of instructions per transaction
        pub max_instruction_number: u64,
        /// Maximum size of wasm binary
        pub max_wasm_size_bytes: u64,
    }

    /// Transaction that contains at least one signature
    ///
    /// `Iroha` and its clients use [`Self`] to send transactions over the network.
    /// After a transaction is signed and before it can be processed any further,
    /// the transaction must be accepted by the `Iroha` peer.
    /// The peer verifies the signatures and checks the limits.
    #[version(version = 1, versioned_alias = "VersionedSignedTransaction")]
    #[derive(
        Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Serialize, IntoSchema,
    )]
    #[cfg_attr(not(feature = "std"), display(fmt = "Signed transaction"))]
    #[cfg_attr(feature = "std", display(fmt = "{}", "self.hash()"))]
    #[ffi_type]
    // TODO: All fields in this struct should be private
    pub struct SignedTransaction {
        /// [`iroha_crypto::SignatureOf`]<[`TransactionPayload`]>.
        pub signatures: SignaturesOf<TransactionPayload>,
        /// [`Transaction`] payload.
        pub payload: TransactionPayload,
    }

    /// Transaction Value used in Instructions and Queries
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    #[ffi_type]
    pub struct TransactionValue {
        /// Committed transaction
        pub value: VersionedSignedTransaction,
        /// Reason of rejection
        pub error: Option<error::TransactionRejectionReason>,
    }
}

impl TransactionLimits {
    /// Construct [`Self`]
    pub const fn new(max_instruction_number: u64, max_wasm_size_bytes: u64) -> Self {
        Self {
            max_instruction_number,
            max_wasm_size_bytes,
        }
    }
}

impl<A: Instruction> FromIterator<A> for Executable {
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        Self::Instructions(iter.into_iter().map(Into::into).collect())
    }
}

impl<T: IntoIterator<Item = impl Instruction>> From<T> for Executable {
    fn from(collection: T) -> Self {
        collection.into_iter().collect()
    }
}

impl From<WasmSmartContract> for Executable {
    fn from(source: WasmSmartContract) -> Self {
        Self::Wasm(source)
    }
}

impl AsRef<[u8]> for WasmSmartContract {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl WasmSmartContract {
    /// Create [`Self`] from raw wasm bytes
    #[inline]
    pub const fn from_compiled(blob: Vec<u8>) -> Self {
        Self(blob)
    }

    /// Size of the smart contract in bytes
    pub fn size_bytes(&self) -> usize {
        self.0.len()
    }
}

impl TransactionPayload {
    /// Calculate transaction payload [`Hash`](`iroha_crypto::HashOf`).
    #[cfg(feature = "std")]
    pub fn hash(&self) -> iroha_crypto::HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }

    /// Metadata.
    // TODO: Should implement `HasMetadata` instead
    pub fn metadata(&self) -> impl ExactSizeIterator<Item = (&Name, &Value)> {
        self.metadata.iter()
    }

    /// Creation timestamp
    pub fn creation_time(&self) -> Duration {
        Duration::from_millis(self.creation_time_ms)
    }

    /// If transaction is not committed by this time it will be dropped.
    pub fn time_to_live(&self) -> Option<Duration> {
        self.time_to_live_ms
            .map(|ttl| Duration::from_millis(ttl.into()))
    }
}

#[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
declare_versioned!(VersionedSignedTransaction 1..2, Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
declare_versioned!(VersionedSignedTransaction 1..2, Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, IntoSchema);

impl VersionedSignedTransaction {
    /// Return transaction payload
    // FIXME: Leaking concrete type TransactionPayload from Versioned container. Payload should be versioned
    pub fn payload(&self) -> &TransactionPayload {
        let VersionedSignedTransaction::V1(tx) = self;
        &tx.payload
    }

    /// Return transaction signatures
    pub fn signatures(&self) -> &SignaturesOf<TransactionPayload> {
        let VersionedSignedTransaction::V1(tx) = self;
        &tx.signatures
    }

    /// Calculate transaction [`Hash`](`iroha_crypto::HashOf`).
    #[cfg(feature = "std")]
    pub fn hash(&self) -> iroha_crypto::HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }

    /// Sign transaction with provided key pair.
    ///
    /// # Errors
    ///
    /// Fails if signature creation fails
    #[cfg(feature = "std")]
    pub fn sign(
        self,
        key_pair: iroha_crypto::KeyPair,
    ) -> Result<VersionedSignedTransaction, iroha_crypto::error::Error> {
        let VersionedSignedTransaction::V1(mut tx) = self;
        let signature = iroha_crypto::SignatureOf::new(key_pair, &tx.payload)?;
        tx.signatures.insert(signature);

        Ok(SignedTransaction {
            payload: tx.payload,
            signatures: tx.signatures,
        }
        .into())
    }

    /// Add additional signatures to this transaction
    #[cfg(feature = "std")]
    #[cfg(feature = "transparent_api")]
    pub fn merge_signatures(&mut self, other: Self) -> bool {
        if self.payload().hash() != other.payload().hash() {
            return false;
        }

        let VersionedSignedTransaction::V1(tx1) = self;
        let VersionedSignedTransaction::V1(tx2) = other;
        tx1.signatures.extend(tx2.signatures);

        true
    }
}

#[cfg(feature = "transparent_api")]
impl From<VersionedSignedTransaction> for (AccountId, Executable) {
    fn from(source: VersionedSignedTransaction) -> Self {
        let VersionedSignedTransaction::V1(tx) = source;
        (tx.payload.authority, tx.payload.instructions)
    }
}

impl SignedTransaction {
    #[cfg(feature = "std")]
    fn hash(&self) -> iroha_crypto::HashOf<VersionedSignedTransaction> {
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::HashOf::new(self).into())
    }
}

impl TransactionValue {
    /// Calculate transaction [`Hash`](`iroha_crypto::HashOf`).
    #[cfg(feature = "std")]
    pub fn hash(&self) -> iroha_crypto::HashOf<VersionedSignedTransaction> {
        self.value.hash()
    }

    /// [`Transaction`] payload.
    #[inline]
    pub fn payload(&self) -> &TransactionPayload {
        self.value.payload()
    }

    /// [`iroha_crypto::SignatureOf`]<[`TransactionPayload`]>.
    #[inline]
    pub fn signatures(&self) -> &SignaturesOf<TransactionPayload> {
        self.value.signatures()
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
            .creation_time_ms
            .cmp(&other.payload().creation_time_ms)
    }
}

mod candidate {
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode, Deserialize)]
    struct SignedTransactionCandidate {
        signatures: SignaturesOf<TransactionPayload>,
        payload: TransactionPayload,
    }

    impl SignedTransactionCandidate {
        #[cfg(feature = "std")]
        fn validate(self) -> Result<SignedTransaction, &'static str> {
            self.validate_signatures()?;
            self.validate_instructions()
        }

        #[cfg(not(feature = "std"))]
        fn validate(self) -> Result<SignedTransaction, &'static str> {
            self.validate_instructions()
        }

        fn validate_instructions(self) -> Result<SignedTransaction, &'static str> {
            if let Executable::Instructions(instructions) = &self.payload.instructions {
                if instructions.is_empty() {
                    return Err("Transaction is empty");
                }
            }

            Ok(SignedTransaction {
                payload: self.payload,
                signatures: self.signatures,
            })
        }

        #[cfg(feature = "std")]
        fn validate_signatures(&self) -> Result<(), &'static str> {
            self.signatures
                .verify(&self.payload)
                .map_err(|_| "Transaction contains invalid signatures")
        }
    }

    impl Decode for SignedTransaction {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            SignedTransactionCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
    impl<'de> Deserialize<'de> for SignedTransaction {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            use serde::de::Error as _;

            SignedTransactionCandidate::deserialize(deserializer)?
                .validate()
                .map_err(D::Error::custom)
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
    pub use self::model::*;
    use super::*;

    #[model]
    pub mod model {
        use super::*;

        /// Error which indicates max instruction count was reached
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `TransactionLimitError` has no trap representation in `String`
        #[ffi_type(unsafe {robust})]
        pub struct TransactionLimitError {
            /// Reason why transaction exceeds limits
            pub reason: String,
        }

        /// Transaction was rejected because of one of its instructions failing.
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Getters,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[ffi_type]
        pub struct InstructionExecutionFail {
            /// Instruction for which execution failed
            #[getset(get = "pub")]
            pub instruction: InstructionBox,
            /// Error which happened during execution
            pub reason: String,
        }

        /// Transaction was rejected because execution of `WebAssembly` binary failed
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[display(fmt = "Failed to execute wasm binary: {reason}")]
        #[serde(transparent)]
        #[repr(transparent)]
        // SAFETY: `WasmExecutionFail` has no trap representation in `String`
        #[ffi_type(unsafe {robust})]
        pub struct WasmExecutionFail {
            /// Error which happened during execution
            pub reason: String,
        }

        /// The reason for rejecting transaction which happened because of transaction.
        #[derive(
            Debug,
            displaydoc::Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            FromVariant,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[ignore_extra_doc_attributes]
        #[cfg_attr(feature = "std", derive(thiserror::Error))]
        // TODO: Temporarily opaque
        #[ffi_type(opaque)]
        pub enum TransactionRejectionReason {
            /// Account does not exist
            AccountDoesNotExist(
                #[skip_from] // NOTE: Such implicit conversions would be too unreadable
                #[skip_try_from]
                #[cfg_attr(feature = "std", source)]
                crate::query::error::FindError,
            ),
            /// Failed to validate transaction limits
            ///
            /// e.g. number of instructions
            LimitCheck(#[cfg_attr(feature = "std", source)] error::TransactionLimitError),
            /// Validation failed
            Validation(#[cfg_attr(feature = "std", source)] crate::ValidationFail),
            /// Failure in instruction execution
            ///
            /// In practice should be fully replaced by [`ValidationFail::Execution`]
            /// and will be removed soon.
            InstructionExecution(#[cfg_attr(feature = "std", source)] InstructionExecutionFail),
            /// Failure in WebAssembly execution
            WasmExecution(#[cfg_attr(feature = "std", source)] WasmExecutionFail),
            /// Transaction rejected due to being expired
            Expired,
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
                Upgrade(_) => "upgrade",
                Log(_) => "log",
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
    impl std::error::Error for InstructionExecutionFail {}

    #[cfg(feature = "std")]
    impl std::error::Error for WasmExecutionFail {}

    pub mod prelude {
        //! The prelude re-exports most commonly used traits, structs and macros from this module.

        pub use super::{InstructionExecutionFail, TransactionRejectionReason, WasmExecutionFail};
    }
}

#[cfg(feature = "http")]
mod http {
    pub use self::model::*;
    use super::*;

    #[model]
    pub mod model {
        use super::*;

        /// Structure that represents the initial state of a transaction before the transaction receives any signatures.
        #[derive(Debug, Clone)]
        #[repr(transparent)]
        #[must_use]
        pub struct TransactionBuilder {
            /// [`Transaction`] payload.
            pub(super) payload: TransactionPayload,
        }
    }

    impl TransactionBuilder {
        /// Construct [`Self`].
        #[inline]
        #[cfg(feature = "std")]
        pub fn new(authority: AccountId) -> Self {
            let creation_time_ms = crate::current_time()
                .as_millis()
                .try_into()
                .expect("Unix timestamp exceedes u64::MAX");

            Self {
                payload: TransactionPayload {
                    authority,
                    creation_time_ms,
                    nonce: None,
                    time_to_live_ms: None,
                    instructions: Vec::<InstructionBox>::new().into(),
                    metadata: UnlimitedMetadata::new(),
                },
            }
        }
    }

    impl TransactionBuilder {
        /// Set instructions for this transaction
        pub fn with_instructions(
            mut self,
            instructions: impl IntoIterator<Item = impl Instruction>,
        ) -> Self {
            self.payload.instructions = instructions
                .into_iter()
                .map(Into::into)
                .collect::<Vec<InstructionBox>>()
                .into();
            self
        }

        /// Add wasm to this transaction
        pub fn with_wasm(mut self, wasm: WasmSmartContract) -> Self {
            self.payload.instructions = wasm.into();
            self
        }

        /// Adds metadata to the `Transaction`
        pub fn with_metadata(mut self, metadata: UnlimitedMetadata) -> Self {
            self.payload.metadata = metadata;
            self
        }

        /// Set nonce for [`Transaction`]
        pub fn set_nonce(&mut self, nonce: NonZeroU32) -> &mut Self {
            self.payload.nonce = Some(nonce);
            self
        }

        /// Set time-to-live for [`Transaction`]
        pub fn set_ttl(&mut self, time_to_live: Duration) -> &mut Self {
            let ttl: u64 = time_to_live
                .as_millis()
                .try_into()
                .expect("Unix timestamp exceedes u64::MAX");

            self.payload.time_to_live_ms = if ttl == 0 {
                // TODO: This is not correct, 0 is not the same as None
                None
            } else {
                Some(NonZeroU64::new(ttl).expect("Can't be 0"))
            };

            self
        }

        /// Sign transaction with provided key pair.
        ///
        /// # Errors
        ///
        /// Fails if signature creation fails
        #[cfg(feature = "std")]
        pub fn sign(
            self,
            key_pair: iroha_crypto::KeyPair,
        ) -> Result<VersionedSignedTransaction, iroha_crypto::error::Error> {
            let signatures = SignaturesOf::new(key_pair, &self.payload)?;

            Ok(SignedTransaction {
                payload: self.payload,
                signatures,
            }
            .into())
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::http::TransactionBuilder;
    pub use super::{
        error::prelude::*, Executable, TransactionPayload, TransactionValue,
        VersionedSignedTransaction, WasmSmartContract,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::restriction)]

    use super::*;

    #[test]
    fn wasm_smart_contract_debug_repr_should_contain_just_len() {
        let contract = WasmSmartContract::from_compiled(vec![0, 1, 2, 3, 4]);
        assert_eq!(format!("{contract:?}"), "WASM binary(len = 5)");
    }
}
