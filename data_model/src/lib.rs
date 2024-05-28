//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

// Clippy bug
#![allow(clippy::items_after_test_module)]
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
use core::{fmt, fmt::Debug, ops::RangeInclusive, str::FromStr};

use derive_more::{Constructor, Display, From, FromStr};
use getset::Getters;
use iroha_crypto::PublicKey;
use iroha_data_model_derive::{model, EnumRef, IdEqOrdHash};
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use iroha_version::{declare_versioned, version_with_scale};
use parity_scale_codec::{Decode, Encode};
use prelude::Executable;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use strum::FromRepr;

pub use self::model::*;
use crate::name::Name;

pub mod account;
pub mod asset;
pub mod block;
pub mod domain;
pub mod events;
pub mod executor;
pub mod ipfs;
pub mod isi;
pub mod metadata;
pub mod name;
pub mod peer;
pub mod permission;
pub mod query;
pub mod role;
pub mod smart_contract;
pub mod transaction;
pub mod trigger;
pub mod visit;

mod seal {
    use iroha_primitives::numeric::Numeric;

    use crate::prelude::*;

    pub trait Sealed {}

    macro_rules! impl_sealed {
        ($($ident:ident $(< $($generic:ident $(< $inner_generic:ident >)?),+ >)?),+ $(,)?) => { $(
            impl Sealed for $ident $(< $($generic $(< $inner_generic >)?),+ >)? {} )+
        };
    }

    impl_sealed! {
        // Boxed instructions
        InstructionBox,

        SetKeyValue<Domain>,
        SetKeyValue<AssetDefinition>,
        SetKeyValue<Account>,
        SetKeyValue<Asset>,
        SetKeyValue<Trigger>,

        RemoveKeyValue<Domain>,
        RemoveKeyValue<AssetDefinition>,
        RemoveKeyValue<Account>,
        RemoveKeyValue<Asset>,
        RemoveKeyValue<Trigger>,

        Register<Peer>,
        Register<Domain>,
        Register<Account>,
        Register<AssetDefinition>,
        Register<Asset>,
        Register<Role>,
        Register<Trigger>,

        Unregister<Peer>,
        Unregister<Domain>,
        Unregister<Account>,
        Unregister<AssetDefinition>,
        Unregister<Asset>,
        Unregister<Role>,
        Unregister<Trigger>,

        Mint<Numeric, Asset>,
        Mint<u32, Trigger>,

        Burn<Numeric, Asset>,
        Burn<u32, Trigger>,

        Transfer<Account, DomainId, Account>,
        Transfer<Account, AssetDefinitionId, Account>,
        Transfer<Asset, Numeric, Account>,
        Transfer<Asset, Metadata, Account>,

        Grant<Permission, Account>,
        Grant<RoleId, Account>,
        Grant<Permission, Role>,

        Revoke<Permission, Account>,
        Revoke<RoleId, Account>,
        Revoke<Permission, Role>,

        SetParameter,
        NewParameter,
        Upgrade,
        ExecuteTrigger,
        Log,
        Fail,

        // Boxed queries
        QueryBox,
        FindAllAccounts,
        FindAccountById,
        FindAccountKeyValueByIdAndKey,
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
        FindPermissionsByAccountId,
        FindExecutorDataModel,
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

/// Error which occurs when converting an enum reference to a variant reference
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct EnumTryAsError<EXPECTED, GOT> {
    expected: core::marker::PhantomData<EXPECTED>,
    /// Actual enum variant which was being converted
    pub got: GOT,
}

// Manual implementation because this allow annotation does not affect `Display` derive
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
    #[allow(missing_docs)]
    pub const fn got(got: GOT) -> Self {
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

    use iroha_primitives::numeric::Numeric;

    pub use self::model::*;
    use super::*;
    use crate::isi::InstructionBox;

    /// Set of parameter names currently used by iroha
    #[allow(missing_docs)]
    pub mod default {
        pub const MAX_TRANSACTIONS_IN_BLOCK: &str = "MaxTransactionsInBlock";
        pub const BLOCK_TIME: &str = "BlockTime";
        pub const COMMIT_TIME_LIMIT: &str = "CommitTimeLimit";
        pub const TRANSACTION_LIMITS: &str = "TransactionLimits";
        pub const WSV_DOMAIN_METADATA_LIMITS: &str = "WSVDomainMetadataLimits";
        pub const WSV_ASSET_DEFINITION_METADATA_LIMITS: &str = "WSVAssetDefinitionMetadataLimits";
        pub const WSV_ACCOUNT_METADATA_LIMITS: &str = "WSVAccountMetadataLimits";
        pub const WSV_ASSET_METADATA_LIMITS: &str = "WSVAssetMetadataLimits";
        pub const WSV_TRIGGER_METADATA_LIMITS: &str = "WSVTriggerMetadataLimits";
        pub const WSV_IDENT_LENGTH_LIMITS: &str = "WSVIdentLengthLimits";
        pub const EXECUTOR_FUEL_LIMIT: &str = "ExecutorFuelLimit";
        pub const EXECUTOR_MAX_MEMORY: &str = "ExecutorMaxMemory";
        pub const WASM_FUEL_LIMIT: &str = "WASMFuelLimit";
        pub const WASM_MAX_MEMORY: &str = "WASMMaxMemory";
    }

    #[model]
    mod model {
        use super::*;

        #[derive(
            Debug,
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
        #[ffi_type(local)]
        pub enum ParameterValueBox {
            TransactionLimits(transaction::TransactionLimits),
            MetadataLimits(metadata::Limits),
            LengthLimits(LengthLimits),
            Numeric(
                #[skip_from]
                #[skip_try_from]
                Numeric,
            ),
        }

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
            Constructor,
            IdEqOrdHash,
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
            pub val: ParameterValueBox,
        }
    }

    // TODO: Maybe derive
    impl core::fmt::Display for ParameterValueBox {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::MetadataLimits(v) => core::fmt::Display::fmt(&v, f),
                Self::TransactionLimits(v) => core::fmt::Display::fmt(&v, f),
                Self::LengthLimits(v) => core::fmt::Display::fmt(&v, f),
                Self::Numeric(v) => core::fmt::Display::fmt(&v, f),
            }
        }
    }

    impl<T: Into<Numeric>> From<T> for ParameterValueBox {
        fn from(value: T) -> Self {
            Self::Numeric(value.into())
        }
    }

    impl TryFrom<ParameterValueBox> for u32 {
        type Error = iroha_macro::error::ErrorTryFromEnum<ParameterValueBox, Self>;

        fn try_from(value: ParameterValueBox) -> Result<Self, Self::Error> {
            use iroha_macro::error::ErrorTryFromEnum;

            let ParameterValueBox::Numeric(numeric) = value else {
                return Err(ErrorTryFromEnum::default());
            };

            numeric.try_into().map_err(|_| ErrorTryFromEnum::default())
        }
    }

    impl TryFrom<ParameterValueBox> for u64 {
        type Error = iroha_macro::error::ErrorTryFromEnum<ParameterValueBox, Self>;

        fn try_from(value: ParameterValueBox) -> Result<Self, Self::Error> {
            use iroha_macro::error::ErrorTryFromEnum;

            let ParameterValueBox::Numeric(numeric) = value else {
                return Err(ErrorTryFromEnum::default());
            };

            numeric.try_into().map_err(|_| ErrorTryFromEnum::default())
        }
    }

    impl Parameter {
        /// Current value of the [`Parameter`].
        pub fn val(&self) -> &ParameterValueBox {
            &self.val
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
                                LengthLimits::new(lower, upper).into()
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
                                transaction::TransactionLimits::new(
                                    max_instr,
                                    max_wasm_size,
                                ).into()
                            }
                            // Shorthand for `MetadataLimits`
                            "ML" => {
                                let (lower, upper) = val.rsplit_once(',').ok_or( ParseError {
                                        reason:
                                            "Failed to parse the `val` part of the `Parameter` as `MetadataLimits`. Two comma-separated values are expected.",
                                    })?;
                                let lower = lower.parse::<u32>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `MetadataLimits`. Invalid `u32` in `capacity` field.",
                                })?;
                                let upper = upper.parse::<u32>().map_err(|_| ParseError {
                                    reason:
                                        "Failed to parse the `val` part of the `Parameter` as `MetadataLimits`. Invalid `u32` in `max_entry_len` field.",
                                })?;
                                metadata::Limits::new(lower, upper).into()
                            }
                            _ => return Err(ParseError {
                                reason:
                                    "Unsupported type provided for the `val` part of the `Parameter`.",
                            }),
                        };
                        Ok(Self::new(param_id, val))
                    } else {
                        let val = val_candidate.parse::<Numeric>().map_err(|_| ParseError {
                            reason:
                                "Failed to parse the `val` part of the `Parameter` as `Numeric`.",
                        })?;

                        Ok(Self::new(param_id, val.into()))
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
            val: impl Into<ParameterValueBox>,
        ) -> Result<Self, ParametersBuilderError> {
            let parameter = Parameter {
                id: parameter_id.parse()?,
                val: val.into(),
            };
            self.parameters.push(parameter);
            Ok(self)
        }

        /// Create sequence isi for setting parameters
        pub fn into_set_parameters(self) -> Vec<InstructionBox> {
            self.parameters
                .into_iter()
                .map(isi::SetParameter::new)
                .map(Into::into)
                .collect()
        }

        /// Create sequence isi for creating parameters
        pub fn into_create_parameters(self) -> Vec<InstructionBox> {
            self.parameters
                .into_iter()
                .map(isi::NewParameter::new)
                .map(Into::into)
                .collect()
        }
    }

    pub mod prelude {
        //! Prelude: re-export of most commonly used traits, structs and macros in this crate.

        pub use super::{Parameter, ParameterId};
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::{
            prelude::{numeric, MetadataLimits},
            transaction::TransactionLimits,
        };

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
                    TransactionLimits::new(42, 24).into(),
                ),
                Parameter::new(
                    ParameterId::from_str("MetadataLimits").expect("Failed to parse `ParameterId`"),
                    MetadataLimits::new(42, 24).into(),
                ),
                Parameter::new(
                    ParameterId::from_str("LengthLimits").expect("Failed to parse `ParameterId`"),
                    LengthLimits::new(24, 42).into(),
                ),
                Parameter::new(
                    ParameterId::from_str("Int").expect("Failed to parse `ParameterId`"),
                    numeric!(42).into(),
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
#[allow(clippy::redundant_pub_crate)]
mod model {
    use super::*;

    /// Unique id of blockchain
    #[derive(
        Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[repr(transparent)]
    #[serde(transparent)]
    #[ffi_type(unsafe {robust})]
    pub struct ChainId(Box<str>);

    impl<T> From<T> for ChainId
    where
        T: Into<Box<str>>,
    {
        fn from(value: T) -> Self {
            ChainId(value.into())
        }
    }

    /// Sized container for all possible identifications.
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        EnumRef,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[enum_ref(derive(Encode, FromVariant))]
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
        /// [`Permission`](`permission::Permission`) variant.
        PermissionId(permission::PermissionId),
        /// [`ParameterId`](`parameter::ParameterId`) variant.
        ParameterId(parameter::ParameterId),
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
        EnumRef,
        FromVariant,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[enum_ref(derive(Encode, FromVariant))]
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
        /// [`Trigger`](`trigger::Trigger`) variant.
        Trigger(trigger::Trigger),
        /// [`Role`](`role::Role`) variant.
        Role(role::Role),
        /// [`Parameter`](`parameter::Parameter`) variant.
        Parameter(parameter::Parameter),
    }

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
    /// (because *Runtime Executor* actually does execution too) and other names
    /// (like *Verification* or *Execution*) are being discussed.
    ///
    /// TODO: Move to `executor` module
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
        /// executor.
        TooComplex,
        /// Internal error occurred, please contact the support or check the logs if you are the node owner
        ///
        /// Usually means a bug inside **Runtime Executor** or **Iroha** implementation.
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
        strum::Display,
        strum::EnumString,
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

    /// Batched response of a query sent to torii
    #[derive(
        Debug, Clone, Constructor, Getters, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[version_with_scale(version = 1, versioned_alias = "BatchedResponse")]
    #[getset(get = "pub")]
    #[must_use]
    pub struct BatchedResponseV1<T> {
        /// Current batch
        pub batch: T,
        /// Index of the next element in the result set. Client will use this value
        /// in the next request to continue fetching results of the original query
        pub cursor: crate::query::cursor::ForwardCursor,
    }

    /// String containing serialized valid JSON.
    ///
    /// This string is guaranteed to be parsed as JSON.
    #[derive(Display, Default, Debug, Clone, Eq, Encode, Decode, Ord, PartialOrd, IntoSchema)]
    #[ffi_type(unsafe {robust})]
    #[repr(transparent)]
    #[display(fmt = "{}", "0")]
    pub struct JsonString(pub(super) String);
}

impl JsonString {
    /// Deserialize JSON into something
    /// # Errors
    /// See [`serde_json::from_str`].
    pub fn deserialize<'a, T>(&'a self) -> serde_json::Result<T>
    where
        T: Deserialize<'a>,
    {
        serde_json::from_str(&self.0)
    }

    /// Serializes a value into [`JsonString`]
    /// # Errors
    /// See [`serde_json::to_string`].
    pub fn serialize<T: serde::Serialize>(value: &T) -> serde_json::Result<Self> {
        let serialized = serde_json::to_string(value)?;
        // the string was obtained from serde_json serialization,
        // so it should be a valid JSON string
        Ok(Self(serialized))
    }

    /// Create without checking whether the input is a valid JSON string.
    ///
    /// The caller must guarantee that the value is valid.
    pub fn from_json_string_unchecked(value: String) -> Self {
        Self(value)
    }
}

impl From<&serde_json::Value> for JsonString {
    fn from(value: &serde_json::Value) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Value> for JsonString {
    fn from(value: serde_json::Value) -> Self {
        Self::from(&value)
    }
}

impl PartialEq for JsonString {
    fn eq(&self, other: &Self) -> bool {
        serde_json::from_str::<serde_json::Value>(&self.0).unwrap()
            == serde_json::from_str::<serde_json::Value>(&other.0).unwrap()
    }
}

impl<'de> serde::de::Deserialize<'de> for JsonString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = serde_json::Value::deserialize(deserializer)?;
        Ok(Self::from(&json))
    }
}

impl serde::ser::Serialize for JsonString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = serde_json::Value::from_str(&self.0).map_err(serde::ser::Error::custom)?;
        json.serialize(serializer)
    }
}

macro_rules! impl_encode_as_id_box {
    ($($ty:ty),+ $(,)?) => { $(
        impl $ty {
            /// [`Encode`] [`Self`] as [`IdBox`].
            ///
            /// Used to avoid an unnecessary clone
            pub fn encode_as_id_box(&self) -> Vec<u8> {
                IdBoxRef::from(self).encode()
            }
        } )+
    }
}

macro_rules! impl_encode_as_identifiable_box {
    ($($ty:ty),+ $(,)?) => { $(
        impl $ty {
            /// [`Encode`] [`Self`] as [`IdentifiableBox`].
            ///
            /// Used to avoid an unnecessary clone
            pub fn encode_as_identifiable_box(&self) -> Vec<u8> {
                IdentifiableBoxRef::from(self).encode()
            }
        } )+
    }
}

impl_encode_as_id_box! {
    peer::PeerId,
    domain::DomainId,
    account::AccountId,
    asset::AssetDefinitionId,
    asset::AssetId,
    trigger::TriggerId,
    permission::PermissionId,
    role::RoleId,
    parameter::ParameterId,
}

impl_encode_as_identifiable_box! {
    peer::Peer,
    domain::NewDomain,
    account::NewAccount,
    asset::NewAssetDefinition,
    role::NewRole,
    domain::Domain,
    account::Account,
    asset::AssetDefinition,
    asset::Asset,
    trigger::Trigger,
    role::Role,
    parameter::Parameter,
}

impl Decode for ChainId {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        let boxed: String = parity_scale_codec::Decode::decode(input)?;
        Ok(Self::from(boxed))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_level_from_str() {
        assert_eq!("INFO".parse::<Level>().unwrap(), Level::INFO);
    }
}

// TODO: think of a way to `impl Identifiable for IdentifiableBox`.
// The main problem is lifetimes and conversion cost.

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
    type With;
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

declare_versioned!(
    BatchedResponse<T: serde::Serialize + for<'de> serde::Deserialize<'de>> 1..2,
    Debug, Clone, iroha_macro::FromVariant, IntoSchema
);

impl<T> From<BatchedResponse<T>> for (T, crate::query::cursor::ForwardCursor) {
    fn from(source: BatchedResponse<T>) -> Self {
        let BatchedResponse::V1(batch) = source;
        (batch.batch, batch.cursor)
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
        permission::Permission,
        role::Role,
    }

    #[cfg(feature = "ffi_import")]
    iroha_ffi::decl_ffi_fns! { link_prefix="iroha_data_model" Drop, Clone, Eq, Ord }
    #[cfg(all(feature = "ffi_export", not(feature = "ffi_import")))]
    iroha_ffi::def_ffi_fns! { link_prefix="iroha_data_model"
        Drop: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::Permission, role::Role },
        Clone: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::Permission, role::Role },
        Eq: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::Permission, role::Role },
        Ord: { account::Account, asset::Asset, domain::Domain, metadata::Metadata, permission::Permission, role::Role },
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
    pub use iroha_primitives::numeric::{numeric, Numeric, NumericSpec};

    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, events::prelude::*,
        executor::prelude::*, isi::prelude::*, metadata::prelude::*, name::prelude::*,
        parameter::prelude::*, peer::prelude::*, permission::prelude::*, query::prelude::*,
        role::prelude::*, transaction::prelude::*, trigger::prelude::*, ChainId, EnumTryAsError,
        HasMetadata, IdBox, Identifiable, IdentifiableBox, LengthLimits, ValidationFail,
    };
}
