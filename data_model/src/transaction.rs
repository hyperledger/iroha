//! [`Transaction`] structures and related implementations.
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::{
    fmt::{Display, Formatter, Result as FmtResult},
    iter::IntoIterator,
    num::{NonZeroU32, NonZeroU64},
    time::Duration,
};

use derive_more::{DebugCustom, Display};
#[cfg(feature = "http")]
pub use http::*;
use iroha_crypto::{Signature, SignatureOf};
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
    metadata::Metadata,
    ChainId,
};

#[model]
mod model {
    use getset::Getters;

    use super::*;
    use crate::account::AccountId;

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
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    pub(crate) struct TransactionPayload {
        /// Unique id of the blockchain. Used for simple replay attack protection.
        pub chain: ChainId,
        /// Account ID of transaction creator.
        /// TODO dedup public keys in transaction #4410
        pub authority: AccountId,
        /// Creation timestamp (unix time in milliseconds).
        pub creation_time_ms: u64,
        /// ISI or a `WebAssembly` smart contract.
        pub instructions: Executable,
        /// If transaction is not committed by this time it will be dropped.
        pub time_to_live_ms: Option<NonZeroU64>,
        /// Random value to make different hashes for transactions which occur repeatedly and simultaneously.
        pub nonce: Option<NonZeroU32>,
        /// Store for additional information.
        pub metadata: Metadata,
    }

    /// Signature of transaction
    #[derive(
        Debug,
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
    pub struct TransactionSignature(pub SignatureOf<TransactionPayload>);

    /// Transaction that contains a signature
    ///
    /// `Iroha` and its clients use [`Self`] to send transactions over the network.
    /// After a transaction is signed and before it can be processed any further,
    /// the transaction must be accepted by the `Iroha` peer.
    /// The peer verifies the signature and checks the limits.
    #[version(version = 1, versioned_alias = "SignedTransaction")]
    #[derive(
        Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Serialize, IntoSchema,
    )]
    #[cfg_attr(not(feature = "std"), display(fmt = "Signed transaction"))]
    #[cfg_attr(feature = "std", display(fmt = "{}", "self.hash()"))]
    #[ffi_type]
    pub struct SignedTransactionV1 {
        /// Signature of [`Self::payload`].
        pub(super) signature: TransactionSignature,
        /// Payload of the transaction.
        pub(super) payload: TransactionPayload,
    }

    /// Transaction Value used in Instructions and Queries
    #[derive(
        Debug,
        PartialOrd,
        Ord,
        Getters,
        Clone,
        PartialEq,
        Eq,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[ffi_type]
    #[getset(get = "pub")]
    pub struct CommittedTransaction {
        /// Committed transaction
        #[getset(skip)]
        pub value: SignedTransaction,
        /// Reason of rejection
        pub error: Option<error::TransactionRejectionReason>,
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

#[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
declare_versioned!(SignedTransaction 1..2, Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, iroha_ffi::FfiType, IntoSchema);
#[cfg(all(not(feature = "ffi_export"), not(feature = "ffi_import")))]
declare_versioned!(SignedTransaction 1..2, Debug, Display, Clone, PartialEq, Eq, PartialOrd, Ord, FromVariant, IntoSchema);

impl SignedTransaction {
    /// Transaction payload. Used for tests
    #[cfg(feature = "transparent_api")]
    pub fn payload(&self) -> &TransactionPayload {
        let SignedTransaction::V1(tx) = self;
        &tx.payload
    }

    /// Return transaction instructions
    #[inline]
    pub fn instructions(&self) -> &Executable {
        let SignedTransaction::V1(tx) = self;
        &tx.payload.instructions
    }

    /// Return transaction authority
    #[inline]
    pub fn authority(&self) -> &AccountId {
        let SignedTransaction::V1(tx) = self;
        &tx.payload.authority
    }

    /// Return transaction metadata.
    #[inline]
    pub fn metadata(&self) -> &Metadata {
        let SignedTransaction::V1(tx) = self;
        &tx.payload.metadata
    }

    /// Creation timestamp as [`core::time::Duration`]
    #[inline]
    pub fn creation_time(&self) -> Duration {
        let SignedTransaction::V1(tx) = self;
        Duration::from_millis(tx.payload.creation_time_ms)
    }

    /// If transaction is not committed by this time it will be dropped.
    #[inline]
    pub fn time_to_live(&self) -> Option<Duration> {
        let SignedTransaction::V1(tx) = self;
        tx.payload
            .time_to_live_ms
            .map(|ttl| Duration::from_millis(ttl.into()))
    }

    /// Transaction nonce
    #[inline]
    pub fn nonce(&self) -> Option<NonZeroU32> {
        let SignedTransaction::V1(tx) = self;
        tx.payload.nonce
    }

    /// Transaction chain id
    #[inline]
    pub fn chain(&self) -> &ChainId {
        let SignedTransaction::V1(tx) = self;
        &tx.payload.chain
    }

    /// Return the transaction signature
    #[inline]
    pub fn signature(&self) -> &TransactionSignature {
        let SignedTransaction::V1(tx) = self;
        &tx.signature
    }

    /// Calculate transaction [`Hash`](`iroha_crypto::HashOf`).
    #[inline]
    pub fn hash(&self) -> iroha_crypto::HashOf<Self> {
        iroha_crypto::HashOf::new(self)
    }
}

#[cfg(feature = "transparent_api")]
impl From<SignedTransaction> for (AccountId, Executable) {
    fn from(source: SignedTransaction) -> Self {
        let SignedTransaction::V1(tx) = source;
        (tx.payload.authority, tx.payload.instructions)
    }
}

impl SignedTransactionV1 {
    #[cfg(feature = "std")]
    fn hash(&self) -> iroha_crypto::HashOf<SignedTransaction> {
        iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::HashOf::new(self).into())
    }
}

impl AsRef<SignedTransaction> for CommittedTransaction {
    fn as_ref(&self) -> &SignedTransaction {
        &self.value
    }
}

impl TransactionSignature {
    /// Signature itself
    pub fn payload(&self) -> &Signature {
        &self.0
    }
}

mod candidate {
    use parity_scale_codec::Input;

    use super::*;

    #[derive(Decode, Deserialize)]
    struct SignedTransactionCandidate {
        signature: TransactionSignature,
        payload: TransactionPayload,
    }

    impl SignedTransactionCandidate {
        fn validate(self) -> Result<SignedTransactionV1, &'static str> {
            self.validate_instructions()?;
            self.validate_signature()?;

            Ok(SignedTransactionV1 {
                signature: self.signature,
                payload: self.payload,
            })
        }

        fn validate_instructions(&self) -> Result<(), &'static str> {
            if let Executable::Instructions(instructions) = &self.payload.instructions {
                if instructions.is_empty() {
                    return Err("Transaction is empty");
                }
            }

            Ok(())
        }

        fn validate_signature(&self) -> Result<(), &'static str> {
            let TransactionSignature(signature) = &self.signature;

            signature
                .verify(&self.payload.authority.signatory, &self.payload)
                .map_err(|_| "Transaction signature is invalid")?;

            Ok(())
        }
    }

    impl Decode for SignedTransactionV1 {
        fn decode<I: Input>(input: &mut I) -> Result<Self, parity_scale_codec::Error> {
            SignedTransactionCandidate::decode(input)?
                .validate()
                .map_err(Into::into)
        }
    }
    impl<'de> Deserialize<'de> for SignedTransactionV1 {
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
        let engine = base64::engine::general_purpose::STANDARD;
        serializer.collect_str(&base64::display::Base64Display::new(bytes, &engine))
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
                let engine = base64::engine::general_purpose::STANDARD;
                base64::engine::Engine::decode(&engine, v).map_err(serde::de::Error::custom)
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
    mod model {
        use getset::Getters;

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
        }
    }

    impl Display for InstructionExecutionFail {
        fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
            use InstructionBox::*;
            let kind = match self.instruction {
                Burn(_) => "burn",
                Mint(_) => "mint",
                Register(_) => "register",
                Transfer(_) => "transfer",
                Unregister(_) => "un-register",
                SetKeyValue(_) => "set key-value pair",
                RemoveKeyValue(_) => "remove key-value pair",
                Grant(_) => "grant",
                Revoke(_) => "revoke",
                ExecuteTrigger(_) => "execute trigger",
                SetParameter(_) => "set parameter",
                Upgrade(_) => "upgrade",
                Log(_) => "log",
                Custom(_) => "custom",
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
    mod model {
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
        #[cfg(feature = "std")]
        fn new_with_time(chain: ChainId, authority: AccountId, creation_time_ms: u64) -> Self {
            Self {
                payload: TransactionPayload {
                    chain,
                    authority,
                    creation_time_ms,
                    nonce: None,
                    time_to_live_ms: None,
                    instructions: Vec::<InstructionBox>::new().into(),
                    metadata: Metadata::default(),
                },
            }
        }

        /// Construct [`Self`], using the time from [`TimeSource`]
        // we don't want to expose this to non-tests
        #[inline]
        #[cfg(all(feature = "std", feature = "transparent_api"))]
        pub fn new_with_time_source(
            chain_id: ChainId,
            authority: AccountId,
            time_source: &iroha_primitives::time::TimeSource,
        ) -> Self {
            let creation_time_ms = time_source
                .get_unix_time()
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");

            Self::new_with_time(chain_id, authority, creation_time_ms)
        }

        /// Construct [`Self`].
        #[inline]
        #[cfg(feature = "std")]
        pub fn new(chain_id: ChainId, authority: AccountId) -> Self {
            use std::time::SystemTime;

            // can't delegate to `new_with_time_source`, because it's gated behind "transparent_api"
            let creation_time_ms = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to get the current system time")
                .as_millis()
                .try_into()
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
            Self::new_with_time(chain_id, authority, creation_time_ms)
        }
    }

    impl TransactionBuilder {
        /// Set instructions for this transaction
        pub fn with_instructions<T: Instruction>(
            mut self,
            instructions: impl IntoIterator<Item = T>,
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

        /// Set executable for this transaction
        pub fn with_executable(mut self, executable: Executable) -> Self {
            self.payload.instructions = executable;
            self
        }

        /// Adds metadata to the `Transaction`
        pub fn with_metadata(mut self, metadata: Metadata) -> Self {
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
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");

            self.payload.time_to_live_ms = if ttl == 0 {
                // TODO: This is not correct, 0 is not the same as None
                None
            } else {
                Some(NonZeroU64::new(ttl).expect("Can't be 0"))
            };

            self
        }

        /// Set creation time of transaction
        pub fn set_creation_time(&mut self, value: Duration) -> &mut Self {
            self.payload.creation_time_ms = u64::try_from(value.as_millis())
                .expect("INTERNAL BUG: Unix timestamp exceedes u64::MAX");
            self
        }

        /// Sign transaction with provided key pair.
        #[must_use]
        pub fn sign(self, private_key: &iroha_crypto::PrivateKey) -> SignedTransaction {
            let signature = TransactionSignature(SignatureOf::new(private_key, &self.payload));

            SignedTransactionV1 {
                signature,
                payload: self.payload,
            }
            .into()
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this module.
pub mod prelude {
    #[cfg(feature = "http")]
    pub use super::http::TransactionBuilder;
    pub use super::{
        error::prelude::*, CommittedTransaction, Executable, SignedTransaction, WasmSmartContract,
    };
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    use super::*;

    #[test]
    fn wasm_smart_contract_debug_repr_should_contain_just_len() {
        let contract = WasmSmartContract::from_compiled(vec![0, 1, 2, 3, 4]);
        assert_eq!(format!("{contract:?}"), "WASM binary(len = 5)");
    }
}
