//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

#![allow(
    clippy::module_name_repetitions,
    clippy::unwrap_in_result,
    clippy::std_instead_of_alloc,
    clippy::arithmetic_side_effects,
    clippy::trait_duplication_in_bounds,
    clippy::extra_unused_lifetimes, // Thanks to `EnumKind` not knowing how to write a derive macro.
    clippy::items_after_test_module, // Clippy bug
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::{
    convert::AsRef,
    fmt,
    fmt::Debug,
    ops::{ControlFlow, RangeInclusive},
    str::FromStr,
};

use block::VersionedSignedBlock;
#[cfg(not(target_arch = "aarch64"))]
use derive_more::Into;
use derive_more::{AsRef, DebugCustom, Deref, Display, From, FromStr};
use events::TriggeringFilterBox;
use getset::Getters;
use iroha_crypto::{HashOf, PublicKey};
use iroha_data_model_derive::{
    model, IdEqOrdHash, PartiallyTaggedDeserialize, PartiallyTaggedSerialize,
};
use iroha_macro::{error::ErrorTryFromEnum, FromVariant};
use iroha_primitives::{
    fixed,
    small::{Array as SmallArray, SmallVec},
};
use iroha_schema::IntoSchema;
pub use numeric::model::NumericValue;
use parity_scale_codec::{Decode, Encode};
use prelude::{Executable, TransactionQueryOutput, VersionedSignedTransaction};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use strum::FromRepr;

pub use self::model::*;
use crate::{account::SignatureCheckCondition, name::Name};

pub mod account;
pub mod asset;
pub mod block;
pub mod domain;
pub mod evaluate;
pub mod events;
pub mod expression;
pub mod ipfs;
pub mod isi;
pub mod metadata;
pub mod name;
pub mod numeric;
pub mod peer;
pub mod permission;
#[cfg(feature = "http")]
pub mod predicate;
pub mod query;
pub mod role;
pub mod transaction;
pub mod trigger;
pub mod validator;
pub mod visit;
pub mod wasm;

mod seal {
    use crate::{isi::prelude::*, query::prelude::*};

    pub trait Sealed {}

    macro_rules! impl_sealed {
        ($($ident:ident),+ $(,)?) => { $(
            impl Sealed for $ident {} )+
        };
    }

    impl_sealed! {
        // Boxed instructions
        InstructionBox,
        SetKeyValueBox,
        RemoveKeyValueBox,
        RegisterBox,
        UnregisterBox,
        MintBox,
        BurnBox,
        TransferBox,
        GrantBox,
        RevokeBox,
        SetParameterBox,
        NewParameterBox,
        UpgradeBox,
        ExecuteTriggerBox,
        LogBox,

        // Composite instructions
        SequenceBox,
        Conditional,
        Pair,

        FailBox,

        // Boxed queries
        QueryBox,
        FindAllAccounts,
        FindAccountById,
        FindAccountKeyValueByIdAndKey,
        FindAccountsByName,
        FindAccountsByDomainId,
        FindAccountsWithAsset,
        FindAllAssets,
        FindAllAssetsDefinitions,
        FindAssetById,
        FindAssetDefinitionById,
        FindAssetsByName,
        FindAssetsByAccountId,
        FindAssetsByAssetDefinitionId,
        FindAssetsByDomainId,
        FindAssetsByDomainIdAndAssetDefinitionId,
        FindAssetQuantityById,
        FindTotalAssetQuantityByAssetDefinitionId,
        IsAssetDefinitionOwner,
        FindAssetKeyValueByIdAndKey,
        FindAssetDefinitionKeyValueByIdAndKey,
        FindAllDomains,
        FindDomainById,
        FindDomainKeyValueByIdAndKey,
        FindAllPeers,
        FindAllBlocks,
        FindAllBlockHeaders,
        FindBlockHeaderByHash,
        FindAllTransactions,
        FindTransactionsByAccountId,
        FindTransactionByHash,
        FindPermissionTokensByAccountId,
        FindPermissionTokenSchema,
        FindAllActiveTriggerIds,
        FindTriggerById,
        FindTriggerKeyValueByIdAndKey,
        FindTriggersByDomainId,
        FindAllRoles,
        FindAllRoleIds,
        FindRoleByRoleId,
        FindRolesByAccountId,
        FindAllParameters,
    }
}

/// Error which occurs when parsing string into a data model entity
#[derive(Debug, Display, Clone, Copy)]
#[repr(transparent)]
pub struct ParseError {
    reason: &'static str,
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError {}

#[allow(clippy::missing_errors_doc)]
/// [`AsMut`] but reference conversion can fail.
pub trait TryAsMut<T> {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Perform the conversion.
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error>;
}

#[allow(clippy::missing_errors_doc)]
/// Similar to [`AsRef`] but indicating that this reference conversion can fail.
pub trait TryAsRef<T> {
    /// The type returned in the event of a conversion error.
    type Error;

    /// Perform the conversion.
    fn try_as_ref(&self) -> Result<&T, Self::Error>;
}

/// Error which occurs when converting an enum reference to a variant reference
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct EnumTryAsError<EXPECTED, GOT> {
    expected: core::marker::PhantomData<EXPECTED>,
    /// Actual enum variant which was being converted
    pub got: GOT,
}

// Manual implementation because this allow annotation does not affect `Display` derive
#[allow(clippy::use_debug)]
impl<EXPECTED, GOT: Debug> fmt::Display for EnumTryAsError<EXPECTED, GOT> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Expected: {}\nGot: {:?}",
            core::any::type_name::<EXPECTED>(),
            self.got,
        )
    }
}

impl<EXPECTED, GOT> EnumTryAsError<EXPECTED, GOT> {
    const fn got(got: GOT) -> Self {
        Self {
            expected: core::marker::PhantomData,
            got,
        }
    }
}

#[cfg(feature = "std")]
impl<EXPECTED: Debug, GOT: Debug> std::error::Error for EnumTryAsError<EXPECTED, GOT> {}

pub mod parameter {
    //! Structures, traits and impls related to `Paramater`s.

    use core::borrow::Borrow;

    pub use self::model::*;
    use super::*;

    /// Set of parameter names currently used by iroha
    #[allow(missing_docs)]
    pub mod default {
        pub const MAX_TRANSACTIONS_IN_BLOCK: &str = "MaxTransactionsInBlock";
        pub const BLOCK_TIME: &str = "BlockTime";
        pub const COMMIT_TIME_LIMIT: &str = "CommitTimeLimit";
        pub const TRANSACTION_LIMITS: &str = "TransactionLimits";
        pub const WSV_ASSET_METADATA_LIMITS: &str = "WSVAssetMetadataLimits";
        pub const WSV_ASSET_DEFINITION_METADATA_LIMITS: &str = "WSVAssetDefinitionMetadataLimits";
        pub const WSV_ACCOUNT_METADATA_LIMITS: &str = "WSVAccountMetadataLimits";
        pub const WSV_DOMAIN_METADATA_LIMITS: &str = "WSVDomainMetadataLimits";
        pub const WSV_IDENT_LENGTH_LIMITS: &str = "WSVIdentLengthLimits";
        pub const WASM_FUEL_LIMIT: &str = "WASMFuelLimit";
        pub const WASM_MAX_MEMORY: &str = "WASMMaxMemory";
    }

    #[model]
    pub mod model {
        use super::*;

        /// Identification of a [`Parameter`].
        #[derive(
            Debug,
            Display,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            Getters,
            FromStr,
            Decode,
            Encode,
            Deserialize,
            Serialize,
            IntoSchema,
        )]
        #[display(fmt = "{name}")]
        #[getset(get = "pub")]
        #[serde(transparent)]
        #[repr(transparent)]
        #[ffi_type(opaque)]
        pub struct ParameterId {
            /// [`Name`] unique to a [`Parameter`].
            pub name: Name,
        }

        #[derive(
            Debug,
            Display,
            Clone,
            IdEqOrdHash,
            Getters,
            Decode,
            Encode,
            DeserializeFromStr,
            SerializeDisplay,
            IntoSchema,
        )]
        #[display(fmt = "?{id}={val}")]
        /// A chain-wide configuration parameter and its value.
        #[ffi_type]
        pub struct Parameter {
            /// Unique [`Id`] of the [`Parameter`].
            pub id: ParameterId,
            /// Current value of the [`Parameter`].
            #[getset(get = "pub")]
            pub val: Box<Value>,
        }
    }

    impl Parameter {
        fn new(id: ParameterId, val: Value) -> Self {
            Self {
                id,
                val: Box::new(val),
            }
        }
    }

    impl Borrow<str> for ParameterId {
        fn borrow(&self) -> &str {
            self.name.borrow()
        }
    }

    impl Borrow<str> for Parameter {
        fn borrow(&self) -> &str {
            self.id.borrow()
        }
    }

    impl FromStr for Parameter {
        type Err = ParseError;

        fn from_str(string: &str) -> Result<Self, Self::Err> {
            if let Some((parameter_id_candidate, val_candidate)) = string.rsplit_once('=') {
                if let Some(parameter_id_candidate) = parameter_id_candidate.strip_prefix('?') {
                    let param_id: ParameterId =
                        parameter_id_candidate.parse().map_err(|_| ParseError {
                            reason: "Failed to parse the `param_id` part of the `Parameter`.",
                        })?;
                    if let Some((val, ty)) = val_candidate.rsplit_once('_') {
                        let val = match ty {
                            // Shorthand for `LengthLimits`
                            "LL" => {
                                let (lower, upper) = val.rsplit_once(',').ok_or( ParseError {
                                        reason:
                                            "Failed to parse the `val` part of the `Parameter` as `LengthLimits`. Two comma-separated values are expected.",
                                    })?;
                                let lower = lower.parse::<u32>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `LengthLimits`. Invalid lower `u32` bound.",
                                })?;
                                let upper = upper.parse::<u32>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `LengthLimits`. Invalid upper `u32` bound.",
                                })?;
                                Value::LengthLimits(LengthLimits::new(lower, upper))
                            }
                            // Shorthand for `TransactionLimits`
                            "TL" => {
                                let (max_instr, max_wasm_size) = val.rsplit_once(',').ok_or( ParseError {
                                        reason:
                                            "Failed to parse the `val` part of the `Parameter` as `TransactionLimits`. Two comma-separated values are expected.",
                                    })?;
                                let max_instr = max_instr.parse::<u64>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `TransactionLimits`. `max_instruction_number` field should be a valid `u64`.",
                                })?;
                                let max_wasm_size = max_wasm_size.parse::<u64>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `TransactionLimits`. `max_wasm_size_bytes` field should be a valid `u64`.",
                                })?;
                                Value::TransactionLimits(transaction::TransactionLimits::new(
                                    max_instr,
                                    max_wasm_size,
                                ))
                            }
                            // Shorthand for `MetadataLimits`
                            "ML" => {
                                let (lower, upper) = val.rsplit_once(',').ok_or( ParseError {
                                        reason:
                                            "Failed to parse the `val` part of the `Parameter` as `MetadataLimits`. Two comma-separated values are expected.",
                                    })?;
                                let lower = lower.parse::<u32>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `MetadataLimits`. Invalid `u32` in `max_len` field.",
                                })?;
                                let upper = upper.parse::<u32>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `MetadataLimits`. Invalid `u32` in `max_entry_byte_size` field.",
                                })?;
                                Value::MetadataLimits(metadata::Limits::new(lower, upper))
                            }
                            _ => return Err(ParseError {
                                reason:
                                    "Unsupported type provided for the `val` part of the `Parameter`.",
                            }),
                        };
                        Ok(Self::new(param_id, val))
                    } else {
                        let val = val_candidate.parse::<u64>().map_err(|_| ParseError {
                            reason: "Failed to parse the `val` part of the `Parameter` as `u64`.",
                        })?;
                        Ok(Self::new(param_id, Value::Numeric(NumericValue::from(val))))
                    }
                } else {
                    Err(ParseError {
                        reason: "`param_id` part of `Parameter` must start with `?`",
                    })
                }
            } else {
                Err(ParseError {
                    reason: "The `Parameter` string did not contain the `=` character.",
                })
            }
        }
    }

    /// Convenience tool for setting parameters
    #[derive(Default)]
    #[must_use]
    pub struct ParametersBuilder {
        parameters: Vec<Parameter>,
    }

    /// Error associated with parameters builder
    #[derive(From, Debug, Display, Copy, Clone)]
    pub enum ParametersBuilderError {
        /// Error emerged during parsing of parameter id
        Parse(ParseError),
    }

    #[cfg(feature = "std")]
    impl std::error::Error for ParametersBuilderError {}

    impl ParametersBuilder {
        /// Construct [`Self`]
        pub fn new() -> Self {
            Self::default()
        }

        /// Add [`Parameter`] to self
        ///
        /// # Errors
        /// - [`ParameterId`] parsing failed
        pub fn add_parameter(
            mut self,
            parameter_id: &str,
            val: impl Into<Value>,
        ) -> Result<Self, ParametersBuilderError> {
            let parameter = Parameter {
                id: parameter_id.parse()?,
                val: Box::new(val.into()),
            };
            self.parameters.push(parameter);
            Ok(self)
        }

        /// Create sequence isi for setting parameters
        pub fn into_set_parameters(self) -> isi::SequenceBox {
            isi::SequenceBox {
                instructions: self
                    .parameters
                    .into_iter()
                    .map(isi::SetParameterBox::new)
                    .map(Into::into)
                    .collect(),
            }
        }

        /// Create sequence isi for creating parameters
        pub fn into_create_parameters(self) -> isi::SequenceBox {
            isi::SequenceBox {
                instructions: self
                    .parameters
                    .into_iter()
                    .map(isi::NewParameterBox::new)
                    .map(Into::into)
                    .collect(),
            }
        }
    }

    pub mod prelude {
        //! Prelude: re-export of most commonly used traits, structs and macros in this crate.

        pub use super::{Parameter, ParameterId};
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{prelude::MetadataLimits, transaction::TransactionLimits};

        const INVALID_PARAM: [&str; 4] = [
            "",
            "Block?SyncGossipPeriod=20000",
            "?BlockSyncGossipPeriod20000",
            "?BlockSyncGossipPeriod=20000_u32",
        ];

        #[test]
        fn test_invalid_parameter_str() {
            assert!(matches!(
                parameter::Parameter::from_str(INVALID_PARAM[0]),
                Err(err) if err.reason == "The `Parameter` string did not contain the `=` character."
            ));
            assert!(matches!(
                parameter::Parameter::from_str(INVALID_PARAM[1]),
                Err(err) if err.reason == "`param_id` part of `Parameter` must start with `?`"
            ));
            assert!(matches!(
                parameter::Parameter::from_str(INVALID_PARAM[2]),
                Err(err) if err.to_string() == "The `Parameter` string did not contain the `=` character."
            ));
            assert!(matches!(
                parameter::Parameter::from_str(INVALID_PARAM[3]),
                Err(err) if err.to_string() == "Unsupported type provided for the `val` part of the `Parameter`."
            ));
        }

        #[test]
        fn test_parameter_serialize_deserialize_consistent() {
            let parameters = [
                Parameter::new(
                    ParameterId::from_str("TransactionLimits")
                        .expect("Failed to parse `ParameterId`"),
                    Value::TransactionLimits(TransactionLimits::new(42, 24)),
                ),
                Parameter::new(
                    ParameterId::from_str("MetadataLimits").expect("Failed to parse `ParameterId`"),
                    Value::MetadataLimits(MetadataLimits::new(42, 24)),
                ),
                Parameter::new(
                    ParameterId::from_str("LengthLimits").expect("Failed to parse `ParameterId`"),
                    Value::LengthLimits(LengthLimits::new(24, 42)),
                ),
                Parameter::new(
                    ParameterId::from_str("Int").expect("Failed to parse `ParameterId`"),
                    Value::Numeric(NumericValue::U64(42)),
                ),
            ];

            for parameter in parameters {
                assert_eq!(
                    parameter,
                    serde_json::to_string(&parameter)
                        .and_then(|parameter| serde_json::from_str(&parameter))
                        .unwrap_or_else(|_| panic!(
                            "Failed to de/serialize parameter {:?}",
                            &parameter
                        ))
                );
            }
        }
    }
}

#[model]
#[allow(irrefutable_let_patterns)] // Triggered from derives macros
pub mod model {
    use super::*;

    /// Sized container for all possible identifications.
    #[derive(
        Debug,
        Display,
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
    #[allow(clippy::enum_variant_names)]
    #[ffi_type(local)]
    pub enum IdBox {
        /// [`DomainId`](`domain::DomainId`) variant.
        DomainId(domain::DomainId),
        /// [`AccountId`](`account::AccountId`) variant.
        #[display(fmt = "{_0}")]
        AccountId(account::AccountId),
        /// [`AssetDefinitionId`](`asset::AssetDefinitionId`) variant.
        #[display(fmt = "{_0}")]
        AssetDefinitionId(asset::AssetDefinitionId),
        /// [`AssetId`](`asset::AssetId`) variant.
        #[display(fmt = "{_0}")]
        AssetId(asset::AssetId),
        /// [`PeerId`](`peer::PeerId`) variant.
        PeerId(peer::PeerId),
        /// [`TriggerId`](trigger::TriggerId) variant.
        TriggerId(trigger::TriggerId),
        /// [`RoleId`](`role::RoleId`) variant.
        RoleId(role::RoleId),
        /// [`PermissionToken`](`permission::PermissionToken`) variant.
        PermissionTokenId(permission::PermissionTokenId),
        /// [`ParameterId`](`parameter::ParameterId`) variant.
        ParameterId(parameter::ParameterId),
    }

    /// Sized container for constructors of all [`Identifiable`]s that can be registered via transaction
    #[derive(
        Debug,
        Display,
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
    #[ffi_type]
    pub enum RegistrableBox {
        /// [`Peer`](`peer::Peer`) variant.
        #[display(fmt = "Peer {_0}")]
        Peer(<peer::Peer as Registered>::With),
        /// [`Domain`](`domain::Domain`) variant.
        #[display(fmt = "Domain {_0}")]
        Domain(<domain::Domain as Registered>::With),
        /// [`Account`](`account::Account`) variant.
        #[display(fmt = "Account {_0}")]
        Account(<account::Account as Registered>::With),
        /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
        #[display(fmt = "AssetDefinition {_0}")]
        AssetDefinition(<asset::AssetDefinition as Registered>::With),
        /// [`Asset`](`asset::Asset`) variant.
        #[display(fmt = "Asset {_0}")]
        Asset(<asset::Asset as Registered>::With),
        /// [`Trigger`](`trigger::Trigger`) variant.
        #[display(fmt = "Trigger {_0}")]
        Trigger(<trigger::Trigger<TriggeringFilterBox, Executable> as Registered>::With),
        /// [`Role`](`role::Role`) variant.
        #[display(fmt = "Role {_0}")]
        Role(<role::Role as Registered>::With),
    }

    /// Sized container for all possible entities.
    #[derive(
        Debug,
        Display,
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
    #[ffi_type]
    pub enum IdentifiableBox {
        /// [`NewDomain`](`domain::NewDomain`) variant.
        NewDomain(<domain::Domain as Registered>::With),
        /// [`NewAccount`](`account::NewAccount`) variant.
        NewAccount(<account::Account as Registered>::With),
        /// [`NewAssetDefinition`](`asset::NewAssetDefinition`) variant.
        NewAssetDefinition(<asset::AssetDefinition as Registered>::With),
        /// [`NewRole`](`role::NewRole`) variant.
        NewRole(<role::Role as Registered>::With),
        /// [`Peer`](`peer::Peer`) variant.
        Peer(peer::Peer),
        /// [`Domain`](`domain::Domain`) variant.
        Domain(domain::Domain),
        /// [`Account`](`account::Account`) variant.
        Account(account::Account),
        /// [`AssetDefinition`](`asset::AssetDefinition`) variant.
        AssetDefinition(asset::AssetDefinition),
        /// [`Asset`](`asset::Asset`) variant.
        Asset(asset::Asset),
        /// [`TriggerBox`] variant.
        Trigger(TriggerBox),
        /// [`Role`](`role::Role`) variant.
        Role(role::Role),
        /// [`Parameter`](`parameter::Parameter`) variant.
        Parameter(parameter::Parameter),
    }

    /// Sized container for triggers with different executables.
    #[derive(
        Debug,
        Display,
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
    #[ffi_type]
    pub enum TriggerBox {
        /// Un-optimized [`Trigger`](`trigger::Trigger`) submitted from client to Iroha.
        #[display(fmt = "{_0}")]
        Raw(trigger::Trigger<TriggeringFilterBox, Executable>),
        /// Optimized [`Trigger`](`trigger::Trigger`) returned from Iroha to client.
        #[display(fmt = "{_0} (optimised)")]
        Optimized(trigger::Trigger<TriggeringFilterBox, trigger::OptimizedExecutable>),
    }

    /// Sized container for all possible upgradable entities.
    #[derive(
        Debug,
        Display,
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
    // SAFETY: `UpgradableBox` has no trap representations in `validator::Validator`
    #[ffi_type(unsafe {robust})]
    #[serde(untagged)] // Unaffected by #3330, because stores binary data with no `u128`
    #[repr(transparent)]
    pub enum UpgradableBox {
        /// [`Validator`](`validator::Validator`) variant.
        #[display(fmt = "Validator")]
        Validator(validator::Validator),
    }

    /// Sized container for all possible values.
    #[derive(
        DebugCustom,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        FromVariant,
        Decode,
        Encode,
        PartiallyTaggedDeserialize,
        PartiallyTaggedSerialize,
        IntoSchema,
    )]
    #[allow(clippy::enum_variant_names, missing_docs)]
    #[ffi_type(opaque)]
    pub enum Value {
        Bool(bool),
        String(String),
        Name(Name),
        Vec(
            #[skip_from]
            #[skip_try_from]
            Vec<Value>,
        ),
        LimitedMetadata(metadata::Metadata),
        MetadataLimits(metadata::Limits),
        TransactionLimits(transaction::TransactionLimits),
        LengthLimits(LengthLimits),
        #[serde_partially_tagged(untagged)]
        Id(IdBox),
        #[serde_partially_tagged(untagged)]
        Identifiable(IdentifiableBox),
        PublicKey(PublicKey),
        SignatureCheckCondition(SignatureCheckCondition),
        TransactionQueryOutput(TransactionQueryOutput),
        PermissionToken(permission::PermissionToken),
        PermissionTokenSchema(permission::PermissionTokenSchema),
        Hash(HashValue),
        Block(VersionedSignedBlockWrapper),
        BlockHeader(block::BlockHeader),
        Ipv4Addr(iroha_primitives::addr::Ipv4Addr),
        Ipv6Addr(iroha_primitives::addr::Ipv6Addr),
        #[serde_partially_tagged(untagged)]
        #[debug(fmt = "{_0:?}")]
        Numeric(NumericValue),
        Validator(validator::Validator),
        LogLevel(Level),
    }

    /// Enum for all supported hash types
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
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
    #[ffi_type]
    pub enum HashValue {
        /// Transaction hash
        Transaction(HashOf<VersionedSignedTransaction>),
        /// Block hash
        Block(HashOf<VersionedSignedBlock>),
    }

    /// Cross-platform wrapper for [`VersionedSignedBlock`].
    #[cfg(not(target_arch = "aarch64"))]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        AsRef,
        Deref,
        From,
        Into,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    // SAFETY: VersionedSignedBlockWrapper has no trap representations in VersionedSignedBlock
    #[schema(transparent)]
    #[ffi_type(unsafe {robust})]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct VersionedSignedBlockWrapper(VersionedSignedBlock);

    /// Cross-platform wrapper for `BlockValue`.
    #[cfg(target_arch = "aarch64")]
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        AsRef,
        Deref,
        From,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[schema(transparent)]
    #[as_ref(forward)]
    #[deref(forward)]
    #[from(forward)]
    // SAFETY: VersionedSignedBlockWrapper has no trap representations in Box<VersionedSignedBlock>
    #[ffi_type(unsafe {robust})]
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct VersionedSignedBlockWrapper(pub(super) Box<VersionedSignedBlock>);

    /// Limits of length of the identifiers (e.g. in [`domain::Domain`], [`account::Account`], [`asset::AssetDefinition`]) in number of chars
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
    #[display(fmt = "{min},{max}_LL")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct LengthLimits {
        /// Minimal length in number of chars (inclusive).
        pub(super) min: u32,
        /// Maximal length in number of chars (inclusive).
        pub(super) max: u32,
    }

    /// Operation validation failed.
    ///
    /// # Note
    ///
    /// Keep in mind that *Validation* is not the right term
    /// (because *Runtime Validator* actually does execution too) and other names
    /// (like *Verification* or *Execution*) are being discussed.
    ///
    /// TODO: Move to `validator` module
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
    #[ffi_type(opaque)]
    #[cfg_attr(feature = "std", derive(thiserror::Error))]
    pub enum ValidationFail {
        /// Operation is not permitted: {0}
        NotPermitted(
            #[skip_from]
            #[skip_try_from]
            String,
        ),
        /// Instruction execution failed
        InstructionFailed(
            #[cfg_attr(feature = "std", source)] isi::error::InstructionExecutionError,
        ),
        /// Query execution failed
        QueryFailed(#[cfg_attr(feature = "std", source)] query::error::QueryExecutionFail),
        /// Operation is too complex, perhaps `WASM_RUNTIME_CONFIG` blockchain parameters should be increased
        ///
        /// For example it's a very big WASM binary.
        ///
        /// It's different from [`TransactionRejectionReason::LimitCheck`] because it depends on
        /// validator.
        TooComplex,
        /// Internal error occurred, please contact the support or check the logs if you are the node owner
        ///
        /// Usually means a bug inside **Runtime Validator** or **Iroha** implementation.
        InternalError(
            /// Contained error message if its used internally. Empty for external users.
            /// Never serialized to not to expose internal errors to the end user.
            #[codec(skip)]
            #[serde(skip)]
            #[skip_from]
            #[skip_try_from]
            String,
        ),
    }

    /// Log level for reading from environment and (de)serializing
    #[derive(
        Debug,
        Display,
        Clone,
        Copy,
        Default,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Deserialize,
        Serialize,
        Encode,
        Decode,
        FromRepr,
        IntoSchema,
    )]
    #[allow(clippy::upper_case_acronyms)]
    #[repr(u8)]
    pub enum Level {
        /// Trace
        TRACE,
        /// Debug
        DEBUG,
        /// Info (Default)
        #[default]
        INFO,
        /// Warn
        WARN,
        /// Error
        ERROR,
    }
}

impl Identifiable for TriggerBox {
    type Id = trigger::TriggerId;

    fn id(&self) -> &Self::Id {
        match self {
            TriggerBox::Raw(trigger) => trigger.id(),
            TriggerBox::Optimized(trigger) => trigger.id(),
        }
    }
}

// TODO: think of a way to `impl Identifiable for IdentifiableBox`.
// The main problem is lifetimes and conversion cost.

#[cfg(feature = "http")]
impl IdentifiableBox {
    fn id_box(&self) -> IdBox {
        match self {
            IdentifiableBox::NewDomain(a) => a.id().clone().into(),
            IdentifiableBox::NewAccount(a) => a.id().clone().into(),
            IdentifiableBox::NewAssetDefinition(a) => a.id().clone().into(),
            IdentifiableBox::NewRole(a) => a.id().clone().into(),
            IdentifiableBox::Peer(a) => a.id().clone().into(),
            IdentifiableBox::Domain(a) => a.id().clone().into(),
            IdentifiableBox::Account(a) => a.id().clone().into(),
            IdentifiableBox::AssetDefinition(a) => a.id().clone().into(),
            IdentifiableBox::Asset(a) => a.id().clone().into(),
            IdentifiableBox::Trigger(a) => a.id().clone().into(),
            IdentifiableBox::Role(a) => a.id().clone().into(),
            IdentifiableBox::Parameter(a) => a.id().clone().into(),
        }
    }
}

impl<'idbox> TryFrom<&'idbox IdentifiableBox> for &'idbox dyn HasMetadata {
    type Error = ();

    fn try_from(
        v: &'idbox IdentifiableBox,
    ) -> Result<&'idbox (dyn HasMetadata + 'idbox), Self::Error> {
        match v {
            IdentifiableBox::NewDomain(v) => Ok(v),
            IdentifiableBox::NewAccount(v) => Ok(v),
            IdentifiableBox::NewAssetDefinition(v) => Ok(v),
            IdentifiableBox::Domain(v) => Ok(v),
            IdentifiableBox::Account(v) => Ok(v),
            IdentifiableBox::AssetDefinition(v) => Ok(v),
            _ => Err(()),
        }
    }
}

/// Create a [`Vec`] containing the arguments, which should satisfy `Into<Value>` bound.
///
/// Syntax is the same as in [`vec`](macro@vec)
#[macro_export]
macro_rules! val_vec {
    () => { Vec::new() };
    ($elem:expr; $n:expr) => { vec![$crate::Value::from($elem); $n] };
    ($($x:expr),+ $(,)?) => { vec![$($crate::Value::from($x),)+] };
}

#[cfg(target_arch = "aarch64")]
impl From<VersionedSignedBlockWrapper> for VersionedSignedBlock {
    fn from(block_value: VersionedSignedBlockWrapper) -> Self {
        *block_value.0
    }
}

impl fmt::Display for Value {
    // TODO: Maybe derive
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Bool(v) => fmt::Display::fmt(&v, f),
            Value::String(v) => fmt::Display::fmt(&v, f),
            Value::Name(v) => fmt::Display::fmt(&v, f),
            #[allow(clippy::use_debug)]
            Value::Vec(v) => {
                // TODO: Remove so we can derive.
                let list_of_display: Vec<_> = v.iter().map(ToString::to_string).collect();
                // this prints with quotation marks, which is fine 90%
                // of the time, and helps delineate where a display of
                // one value stops and another one begins.
                write!(f, "{list_of_display:?}")
            }
            Value::LimitedMetadata(v) => fmt::Display::fmt(&v, f),
            Value::Id(v) => fmt::Display::fmt(&v, f),
            Value::Identifiable(v) => fmt::Display::fmt(&v, f),
            Value::PublicKey(v) => fmt::Display::fmt(&v, f),
            Value::SignatureCheckCondition(v) => fmt::Display::fmt(&v, f),
            Value::TransactionQueryOutput(_) => write!(f, "TransactionQueryOutput"),
            Value::PermissionToken(v) => fmt::Display::fmt(&v, f),
            Value::PermissionTokenSchema(v) => fmt::Display::fmt(&v, f),
            Value::Hash(v) => fmt::Display::fmt(&v, f),
            Value::Block(v) => fmt::Display::fmt(&**v, f),
            Value::BlockHeader(v) => fmt::Display::fmt(&v, f),
            Value::Ipv4Addr(v) => fmt::Display::fmt(&v, f),
            Value::Ipv6Addr(v) => fmt::Display::fmt(&v, f),
            Value::Numeric(v) => fmt::Display::fmt(&v, f),
            Value::MetadataLimits(v) => fmt::Display::fmt(&v, f),
            Value::TransactionLimits(v) => fmt::Display::fmt(&v, f),
            Value::LengthLimits(v) => fmt::Display::fmt(&v, f),
            Value::Validator(v) => write!(f, "Validator({} bytes)", v.wasm.as_ref().len()),
            Value::LogLevel(v) => fmt::Display::fmt(&v, f),
        }
    }
}

#[allow(clippy::len_without_is_empty)]
impl Value {
    /// Number of underneath expressions.
    pub fn len(&self) -> usize {
        use Value::*;

        match self {
            Id(_)
            | PublicKey(_)
            | Bool(_)
            | Identifiable(_)
            | String(_)
            | Name(_)
            | TransactionQueryOutput(_)
            | PermissionToken(_)
            | PermissionTokenSchema(_)
            | Hash(_)
            | Block(_)
            | Ipv4Addr(_)
            | Ipv6Addr(_)
            | BlockHeader(_)
            | MetadataLimits(_)
            | TransactionLimits(_)
            | LengthLimits(_)
            | Numeric(_)
            | Validator(_)
            | LogLevel(_)
            | SignatureCheckCondition(_) => 1_usize,
            Vec(v) => v.iter().map(Self::len).sum::<usize>() + 1_usize,
            LimitedMetadata(data) => data.nested_len() + 1_usize,
        }
    }
}

impl From<VersionedSignedBlock> for Value {
    fn from(block_value: VersionedSignedBlock) -> Self {
        Value::Block(block_value.into())
    }
}

impl<A: SmallArray> From<SmallVec<A>> for Value
where
    A::Item: Into<Value>,
{
    fn from(sv: SmallVec<A>) -> Self {
        // This looks inefficient, but `Value` can only hold a
        // heap-allocated `Vec` (it's recursive) and the vector
        // conversions only do a heap allocation (if that).
        let vec: Vec<_> = sv.into_vec();
        vec.into()
    }
}

// TODO: The following macros looks very similar. Try to generalize them under one macro
macro_rules! from_and_try_from_value_idbox {
    ( $($variant:ident( $ty:ty ),)+ $(,)? ) => { $(
        impl TryFrom<Value> for $ty {
            type Error = ErrorTryFromEnum<Value, Self>;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                if let Value::Id(IdBox::$variant(id)) = value {
                    Ok(id)
                } else {
                    Err(Self::Error::default())
                }
            }
        }

        impl From<$ty> for Value {
            fn from(id: $ty) -> Self {
                Value::Id(IdBox::$variant(id))
            }
        })+
    };
}

macro_rules! from_and_try_from_value_identifiable {
    ( $( $variant:ident( $ty:ty ), )+ $(,)? ) => { $(
        impl TryFrom<Value> for $ty {
            type Error = ErrorTryFromEnum<Value, Self>;

            fn try_from(value: Value) -> Result<Self, Self::Error> {
                if let Value::Identifiable(IdentifiableBox::$variant(id)) = value {
                    Ok(id)
                } else {
                    Err(Self::Error::default())
                }
            }
        }

        impl From<$ty> for Value {
            fn from(id: $ty) -> Self {
                Value::Identifiable(IdentifiableBox::$variant(id))
            }
        } )+
    };
}

macro_rules! from_and_try_from_and_try_as_value_hash {
    ( $( $variant:ident($ty:ty)),+ $(,)? ) => { $(
        impl TryFrom<Value> for $ty {
            type Error = ErrorTryFromEnum<Value, Self>;

            #[inline]
            fn try_from(value: Value) -> Result<Self, Self::Error> {
                if let Value::Hash(HashValue::$variant(value)) = value {
                    Ok(value)
                } else {
                    Err(Self::Error::default())
                }
            }
        }

        impl From<$ty> for Value {
            #[inline]
            fn from(value: $ty) -> Self {
                Value::Hash(HashValue::$variant(value))
            }
        }

        impl TryAsMut<$ty> for HashValue {
            type Error = crate::EnumTryAsError<$ty, HashValue>;

            #[inline]
            fn try_as_mut(&mut self) -> Result<&mut $ty, Self::Error> {
                if let HashValue::$variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(*self))
                }
            }
        }

        impl TryAsRef<$ty> for HashValue {
            type Error = crate::EnumTryAsError<$ty, HashValue>;

            #[inline]
            fn try_as_ref(&self) -> Result<& $ty, Self::Error> {
                if let HashValue::$variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(*self))
                }
            }
        })+
    };
}

macro_rules! from_and_try_from_and_try_as_value_numeric {
    ( $( $variant:ident($ty:ty),)+ $(,)? ) => { $(
        impl TryFrom<Value> for $ty {
            type Error = ErrorTryFromEnum<Value, Self>;

            #[inline]
            fn try_from(value: Value) -> Result<Self, Self::Error> {
                if let Value::Numeric(NumericValue::$variant(value)) = value {
                    Ok(value)
                } else {
                    Err(Self::Error::default())
                }
            }
        }

        impl From<$ty> for Value {
            #[inline]
            fn from(value: $ty) -> Self {
                Value::Numeric(NumericValue::$variant(value))
            }
        }

        impl TryAsMut<$ty> for NumericValue {
            type Error = crate::EnumTryAsError<$ty, NumericValue>;

            #[inline]
            fn try_as_mut(&mut self) -> Result<&mut $ty, Self::Error> {
                if let NumericValue:: $variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(*self))
                }
            }
        }

        impl TryAsRef<$ty> for NumericValue {
            type Error = crate::EnumTryAsError<$ty, NumericValue>;

            #[inline]
            fn try_as_ref(&self) -> Result<& $ty, Self::Error> {
                if let NumericValue:: $variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(*self))
                }
            }
        })+
    };
}

from_and_try_from_value_idbox!(
    PeerId(peer::PeerId),
    DomainId(domain::DomainId),
    AccountId(account::AccountId),
    AssetId(asset::AssetId),
    AssetDefinitionId(asset::AssetDefinitionId),
    TriggerId(trigger::TriggerId),
    RoleId(role::RoleId),
    ParameterId(parameter::ParameterId),
    // TODO: Should we wrap String with new type in order to convert like here?
    //from_and_try_from_value_idbox!((DomainName(Name), ErrorValueTryFromDomainName),);
);

from_and_try_from_value_identifiable!(
    NewDomain(domain::NewDomain),
    NewAccount(account::NewAccount),
    NewAssetDefinition(asset::NewAssetDefinition),
    NewRole(role::NewRole),
    Peer(peer::Peer),
    Domain(domain::Domain),
    Account(account::Account),
    AssetDefinition(asset::AssetDefinition),
    Asset(asset::Asset),
    Trigger(TriggerBox),
    Role(role::Role),
    Parameter(parameter::Parameter),
);

from_and_try_from_and_try_as_value_hash! {
    Transaction(HashOf<VersionedSignedTransaction>),
    Block(HashOf<VersionedSignedBlock>),
}

from_and_try_from_and_try_as_value_numeric! {
    U32(u32),
    U64(u64),
    U128(u128),
    Fixed(fixed::Fixed),
}

impl TryFrom<Value> for RegistrableBox {
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(source: Value) -> Result<Self, Self::Error> {
        if let Value::Identifiable(identifiable) = source {
            identifiable
                .try_into()
                .map_err(|_err| Self::Error::default())
        } else {
            Err(Self::Error::default())
        }
    }
}

impl From<RegistrableBox> for Value {
    fn from(source: RegistrableBox) -> Self {
        let identifiable = source.into();
        Value::Identifiable(identifiable)
    }
}

impl TryFrom<IdentifiableBox> for RegistrableBox {
    type Error = ErrorTryFromEnum<IdentifiableBox, Self>;

    fn try_from(source: IdentifiableBox) -> Result<Self, Self::Error> {
        use IdentifiableBox::*;

        match source {
            Peer(peer) => Ok(RegistrableBox::Peer(peer)),
            NewDomain(domain) => Ok(RegistrableBox::Domain(domain)),
            NewAccount(account) => Ok(RegistrableBox::Account(account)),
            NewAssetDefinition(asset_definition) => {
                Ok(RegistrableBox::AssetDefinition(asset_definition))
            }
            NewRole(role) => Ok(RegistrableBox::Role(role)),
            Asset(asset) => Ok(RegistrableBox::Asset(asset)),
            Trigger(TriggerBox::Raw(trigger)) => Ok(RegistrableBox::Trigger(trigger)),
            Domain(_)
            | Account(_)
            | AssetDefinition(_)
            | Role(_)
            | Parameter(_)
            | Trigger(TriggerBox::Optimized(_)) => Err(Self::Error::default()),
        }
    }
}

impl From<RegistrableBox> for IdentifiableBox {
    fn from(registrable: RegistrableBox) -> Self {
        use RegistrableBox::*;

        match registrable {
            Peer(peer) => IdentifiableBox::Peer(peer),
            Domain(domain) => IdentifiableBox::NewDomain(domain),
            Account(account) => IdentifiableBox::NewAccount(account),
            AssetDefinition(asset_definition) => {
                IdentifiableBox::NewAssetDefinition(asset_definition)
            }
            Role(role) => IdentifiableBox::NewRole(role),
            Asset(asset) => IdentifiableBox::Asset(asset),
            Trigger(trigger) => IdentifiableBox::Trigger(TriggerBox::Raw(trigger)),
        }
    }
}

impl<V: Into<Value>> From<Vec<V>> for Value {
    fn from(values: Vec<V>) -> Value {
        Value::Vec(values.into_iter().map(Into::into).collect())
    }
}

impl<V> TryFrom<Value> for Vec<V>
where
    Value: TryInto<V>,
{
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Vec(vec) = value {
            return vec
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_e| Self::Error::default());
        }

        Err(Self::Error::default())
    }
}

impl TryFrom<Value> for VersionedSignedBlock {
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Block(block_value) = value {
            return Ok(block_value.into());
        }

        Err(Self::Error::default())
    }
}

impl<A: SmallArray> TryFrom<Value> for SmallVec<A>
where
    Value: TryInto<A::Item>,
{
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Vec(vec) = value {
            return vec
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<SmallVec<_>, _>>()
                .map_err(|_e| Self::Error::default());
        }
        Err(Self::Error::default())
    }
}

impl TryFrom<f64> for Value {
    type Error = <f64 as TryInto<fixed::Fixed>>::Error;
    fn try_from(value: f64) -> Result<Self, Self::Error> {
        value
            .try_into()
            .map(NumericValue::Fixed)
            .map(Value::Numeric)
    }
}

impl From<trigger::Trigger<TriggeringFilterBox, Executable>> for Value {
    fn from(trigger: trigger::Trigger<TriggeringFilterBox, Executable>) -> Self {
        Value::Identifiable(IdentifiableBox::Trigger(TriggerBox::Raw(trigger)))
    }
}

impl From<trigger::Trigger<TriggeringFilterBox, trigger::OptimizedExecutable>> for Value {
    fn from(trigger: trigger::Trigger<TriggeringFilterBox, trigger::OptimizedExecutable>) -> Self {
        Value::Identifiable(IdentifiableBox::Trigger(TriggerBox::Optimized(trigger)))
    }
}

impl TryFrom<Value> for trigger::Trigger<TriggeringFilterBox, Executable> {
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Identifiable(IdentifiableBox::Trigger(TriggerBox::Raw(trigger))) = value {
            return Ok(trigger);
        }

        Err(Self::Error::default())
    }
}

impl TryFrom<Value> for trigger::Trigger<TriggeringFilterBox, trigger::OptimizedExecutable> {
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        if let Value::Identifiable(IdentifiableBox::Trigger(TriggerBox::Optimized(trigger))) = value
        {
            return Ok(trigger);
        }

        Err(Self::Error::default())
    }
}

impl TryFrom<Value> for UpgradableBox {
    type Error = ErrorTryFromEnum<Value, Self>;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Validator(validator) => Ok(Self::Validator(validator)),
            _ => Err(Self::Error::default()),
        }
    }
}

/// Represent type which can be converted into [`Value`] infallibly.
/// This trait can be used when type inference can't properly inference desired type.
pub trait ToValue {
    /// Convert [`Self`] into [`Value`].
    fn to_value(self) -> Value;
}

/// Represent type which can be converted into `Value` with possibility of failure.
/// This trait can be used when type inference can't properly inference desired type.
pub trait TryToValue {
    /// Type which represents conversation error.
    type Error;
    /// Try convert [`Self`] into [`Value`].
    ///
    /// # Errors
    /// Fail when it is not possible to convert [`Self`] into `Value`
    fn try_to_value(self) -> Result<Value, Self::Error>;
}

impl<T: Into<Value>> ToValue for T {
    #[inline]
    fn to_value(self) -> Value {
        self.into()
    }
}

impl<T: TryInto<Value>> TryToValue for T {
    type Error = T::Error;

    #[inline]
    fn try_to_value(self) -> Result<Value, Self::Error> {
        self.try_into()
    }
}

/// Uniquely identifiable entity ([`Domain`], [`Account`], etc.).
/// This trait should always be derived with [`IdEqOrdHash`]
pub trait Identifiable: Ord + Eq {
    /// Type of the entity identifier
    type Id: Into<IdBox> + Ord + Eq + core::hash::Hash;

    /// Get reference to the type identifier
    fn id(&self) -> &Self::Id;
}

/// Trait that marks the entity as having metadata.
pub trait HasMetadata {
    // type Metadata = metadata::Metadata;
    // Uncomment when stable.

    /// The metadata associated to this object.
    fn metadata(&self) -> &metadata::Metadata;
}

/// Trait for objects that are registered by proxy.
pub trait Registered: Identifiable {
    /// The proxy type that is used to register this entity. Usually
    /// `Self`, but if you have a complex structure where most fields
    /// would be empty, to save space you create a builder for it, and
    /// set `With` to the builder's type.
    type With: Into<RegistrableBox>;
}

impl LengthLimits {
    /// Constructor.
    pub const fn new(min: u32, max: u32) -> Self {
        Self { min, max }
    }
}

impl From<LengthLimits> for RangeInclusive<u32> {
    #[inline]
    fn from(limits: LengthLimits) -> Self {
        RangeInclusive::new(limits.min, limits.max)
    }
}

/// Trait for boolean-like values
///
/// [`or`](`Self::or`) and [`and`](`Self::and`) must satisfy De Morgan's laws, commutativity and associativity
/// [`Not`](`core::ops::Not`) implementation should satisfy double negation elimintation.
///
/// Short-circuiting behaviour for `and` and `or` can be controlled by returning
/// `ControlFlow::Break` when subsequent application of the same operation
/// won't change the end result, no matter what operands.
///
/// When implementing, it's recommended to generate exhaustive tests with
/// [`test_conformity`](`Self::test_conformity`).
pub trait PredicateSymbol
where
    Self: Sized + core::ops::Not<Output = Self>,
{
    /// Conjunction (e.g. boolean and)
    #[must_use]
    fn and(self, other: Self) -> ControlFlow<Self, Self>;
    /// Disjunction (e.g. boolean or)
    #[must_use]
    fn or(self, other: Self) -> ControlFlow<Self, Self>;

    #[doc(hidden)]
    #[must_use]
    fn unwrapped_and(self, other: Self) -> Self {
        match self.and(other) {
            ControlFlow::Continue(val) | ControlFlow::Break(val) => val,
        }
    }

    #[doc(hidden)]
    #[must_use]
    fn unwrapped_or(self, other: Self) -> Self {
        match self.or(other) {
            ControlFlow::Continue(val) | ControlFlow::Break(val) => val,
        }
    }

    /// Given a list of all possible values of a type implementing [`PredicateSymbol`]
    /// which are different in predicate context, exhaustively tests for:
    /// - commutativity of `and` and `or`
    /// - associativity of `and` and `or`
    /// - De Mornan duality of `and` and `or`
    /// - double negation elimination
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_data_model::PredicateSymbol;
    ///
    /// fn test() {
    ///     PredicateSymbol::test_conformity(vec![true, false]);
    /// }
    /// ```
    ///
    fn test_conformity(values: Vec<Self>)
    where
        Self: PartialEq + Clone,
    {
        Self::test_conformity_with_eq(values, <Self as PartialEq>::eq);
    }

    /// Same as [`test_conformity`](`PredicateSymbol::test_conformity`), but
    /// if type implementing [`PredicateSymbol`] carries some internal state
    /// that isn't associative, one can provide custom `shallow_eq` function
    /// that will be called instead of [`PartialEq::eq`]
    ///
    /// # Examples
    ///
    ///
    /// ```rust
    /// use std::ops::ControlFlow;
    /// use iroha_data_model::PredicateSymbol;
    ///
    /// #[derive(Clone, PartialEq)]
    /// enum Check {
    ///    Good,
    ///    // Encapsulates reason for badness which
    ///    // doesn't behave associatively
    ///    // (but if we ignore it, Check as a whole does)
    ///    Bad(String),
    /// }
    ///
    /// impl core::ops::Not for Check {
    ///   type Output = Self;
    ///   fn not(self) -> Self {
    ///     // ...
    ///     todo!()
    ///   }
    /// }
    ///
    /// impl PredicateSymbol for Check {
    ///   fn and(self, other: Self) -> ControlFlow<Self, Self> {
    ///     // ...
    ///     todo!()
    ///   }
    ///
    ///   fn or(self, other: Self) -> ControlFlow<Self, Self> {
    ///     // ...
    ///     todo!()
    ///   }
    /// }
    ///
    /// fn shallow_eq(left: &Check, right: &Check) -> bool {
    ///    match (left, right) {
    ///      (Check::Good, Check::Good) | (Check::Bad(_), Check::Bad(_)) => true,
    ///      _ => false
    ///    }
    /// }
    ///
    /// #[test]
    /// fn test() {
    ///    let good = Check::Good;
    ///    let bad = Check::Bad("example".to_owned());
    ///    // Would fail some assertions, since derived PartialEq is "deep"
    ///    // PredicateSymbol::test_conformity(vec![good, bad]);
    ///
    ///    // Works as expected
    ///    PredicateSymbol::test_conformity_with_eq(vec![good, bad], shallow_eq);
    /// }
    /// ```
    fn test_conformity_with_eq(values: Vec<Self>, shallow_eq: impl FnMut(&Self, &Self) -> bool)
    where
        Self: Clone,
    {
        let mut eq = shallow_eq;
        let values = values
            .into_iter()
            .map(|val| move || val.clone())
            .collect::<Vec<_>>();

        let typ = core::any::type_name::<Self>();

        for a in &values {
            assert!(
                eq(&a().not().not(), &a()),
                "Double negation elimination doesn't hold for {typ}",
            )
        }

        for a in &values {
            for b in &values {
                assert!(
                eq(
                    &PredicateSymbol::unwrapped_and(a(), b()),
                    &PredicateSymbol::unwrapped_and(b(), a())
                ),
                "Commutativity doesn't hold for `PredicateSymbol::and` implementation for {typ}"
            );

                assert!(
                    eq(
                        &PredicateSymbol::unwrapped_or(a(), b()),
                        &PredicateSymbol::unwrapped_or(b(), a())
                    ),
                    "Commutativity doesn't hold for `PredicateSymbol::or` implementation for {typ}"
                );

                assert!(
                    eq(
                        &PredicateSymbol::unwrapped_or(!a(), !b()),
                        &!PredicateSymbol::unwrapped_and(a(), b())
                    ),
                    "De Morgan's law doesn't hold for {typ}",
                );

                assert!(
                    eq(
                        &PredicateSymbol::unwrapped_and(!a(), !b()),
                        &!PredicateSymbol::unwrapped_or(a(), b())
                    ),
                    "De Morgan's law doesn't hold for {typ}",
                );
            }
        }

        for a in &values {
            for b in &values {
                for c in &values {
                    assert!(
                    eq(
                        &PredicateSymbol::unwrapped_and(
                            PredicateSymbol::unwrapped_and(a(), b()),
                            c()
                        ),
                        &PredicateSymbol::unwrapped_and(
                            a(),
                            PredicateSymbol::unwrapped_and(b(), c()),
                        ),
                    ),
                    "Associativity doesn't hold for `PredicateSymbol::or` implementation for {typ}",
                );

                    assert!(
                    eq(
                        &PredicateSymbol::unwrapped_or(
                            PredicateSymbol::unwrapped_or(a(), b()),
                            c()
                        ),
                        &PredicateSymbol::unwrapped_or(
                            a(),
                            PredicateSymbol::unwrapped_or(b(), c()),
                        ),
                    ),
                    "Associativity doesn't hold for `PredicateSymbol::and` implementation for {typ}",
                );
                }
            }
        }
    }
}

impl PredicateSymbol for bool {
    fn and(self, other: Self) -> ControlFlow<Self, Self> {
        if self && other {
            ControlFlow::Continue(true)
        } else {
            ControlFlow::Break(false)
        }
    }

    fn or(self, other: Self) -> ControlFlow<Self, Self> {
        if self || other {
            ControlFlow::Break(true)
        } else {
            ControlFlow::Continue(false)
        }
    }
}

/// Trait for generic predicates.
pub trait PredicateTrait<T: ?Sized + Copy> {
    /// Type the predicate evaluates to.
    type EvaluatesTo: PredicateSymbol;

    /// The result of applying the predicate to a value.
    fn applies(&self, input: T) -> Self::EvaluatesTo;
}

/// Get the current system time as `Duration` since the unix epoch.
#[cfg(feature = "std")]
pub fn current_time() -> core::time::Duration {
    use std::time::SystemTime;

    #[allow(clippy::expect_used)]
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get the current system time")
}

#[cfg(feature = "http")]
pub mod http {
    //! Structures related to HTTP communication

    use iroha_data_model_derive::model;
    use iroha_schema::IntoSchema;
    use iroha_version::declare_versioned_with_scale;

    pub use self::model::*;
    use crate::prelude::QueryOutput;

    declare_versioned_with_scale!(VersionedBatchedResponse<T> 1..2, Debug, Clone, iroha_macro::FromVariant, IntoSchema);

    #[model]
    pub mod model {
        use getset::Getters;
        use iroha_version::version_with_scale;
        use parity_scale_codec::{Decode, Encode};
        use serde::{Deserialize, Serialize};

        use super::*;

        /// Batched response of a query sent to torii
        #[derive(Debug, Clone, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema)]
        #[version_with_scale(version = 1, versioned_alias = "VersionedBatchedResponse")]
        #[getset(get = "pub")]
        #[must_use]
        pub struct BatchedResponse<T> {
            /// Current batch
            pub batch: T,
            /// Index of the next element in the result set. Client will use this value
            /// in the next request to continue fetching results of the original query
            pub cursor: crate::query::cursor::ForwardCursor,
        }
    }

    impl From<BatchedResponse<Self>> for QueryOutput {
        #[inline]
        fn from(source: BatchedResponse<Self>) -> Self {
            source.batch
        }
    }

    impl<T> From<BatchedResponse<T>> for (T, crate::query::cursor::ForwardCursor) {
        fn from(source: BatchedResponse<T>) -> Self {
            let BatchedResponse { batch, cursor } = source;

            (batch, cursor)
        }
    }
}

mod ffi {
    //! Definitions and implementations of FFI related functionalities

    #[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
    use super::*;

    #[cfg(any(feature = "ffi_export", feature = "ffi_import"))]
    iroha_ffi::handles! {
        account::Account,
        asset::Asset,
        domain::Domain,
        metadata::Metadata,
        permission::PermissionToken,
        role::Role,
    }

    #[cfg(feature = "ffi_import")]
    iroha_ffi::decl_ffi_fns! { link_prefix="iroha_data_model" Drop, Clone, Eq, Ord }
    #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
    iroha_ffi::def_ffi_fns! { link_prefix="iroha_data_model"
        Drop: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::PermissionToken, role::Role },
        Clone: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::PermissionToken, role::Role },
        Eq: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::PermissionToken, role::Role },
        Ord: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::PermissionToken, role::Role },
    }

    // NOTE: Makes sure that only one `dealloc` is exported per generated dynamic library
    #[cfg(any(crate_type = "dylib", crate_type = "cdylib"))]
    #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
    mod dylib {
        #[cfg(not(feature = "std"))]
        use alloc::alloc;
        #[cfg(feature = "std")]
        use std::alloc;

        iroha_ffi::def_ffi_fns! {dealloc}
    }
}

#[allow(ambiguous_glob_reexports)]
pub mod prelude {
    //! Prelude: re-export of most commonly used traits, structs and macros in this crate.
    pub use iroha_crypto::PublicKey;
    pub use iroha_primitives::fixed::Fixed;

    #[cfg(feature = "std")]
    pub use super::current_time;
    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, evaluate::prelude::*,
        events::prelude::*, expression::prelude::*, isi::prelude::*, metadata::prelude::*,
        name::prelude::*, parameter::prelude::*, peer::prelude::*, permission::prelude::*,
        query::prelude::*, role::prelude::*, transaction::prelude::*, trigger::prelude::*,
        validator::prelude::*, EnumTryAsError, HasMetadata, IdBox, Identifiable, IdentifiableBox,
        LengthLimits, NumericValue, PredicateTrait, RegistrableBox, ToValue, TriggerBox, TryAsMut,
        TryAsRef, TryToValue, UpgradableBox, ValidationFail, Value,
    };
}
