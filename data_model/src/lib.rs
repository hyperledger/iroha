//! Iroha Data Model contains structures for Domains, Peers, Accounts and Assets with simple,
//! non-specific functions like serialization.

// Clippy bug
#![allow(clippy::items_after_test_module)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec::Vec};

use derive_more::Display;
use iroha_crypto::PublicKey;
use iroha_data_model_derive::{model, EnumRef};
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
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
pub mod parameter;
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
        Upgrade,
        ExecuteTrigger,
        Log,

        // Boxed queries
        SingularQueryBox,
        FindAccounts,
        FindAccountMetadata,
        FindAccountsWithAsset,
        FindAssets,
        FindAssetsDefinitions,
        FindAssetQuantityById,
        FindTotalAssetQuantityByAssetDefinitionId,
        FindAssetMetadata,
        FindAssetDefinitionMetadata,
        FindDomains,
        FindDomainMetadata,
        FindPeers,
        FindBlocks,
        FindBlockHeaders,
        FindBlockHeaderByHash,
        FindTransactions,
        FindTransactionsByAccountId,
        FindTransactionByHash,
        FindPermissionsByAccountId,
        FindExecutorDataModel,
        FindActiveTriggerIds,
        FindTriggerById,
        FindTriggerMetadata,
        FindRoles,
        FindRoleIds,
        FindRolesByAccountId,
        FindParameters,
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
impl<EXPECTED, GOT: core::fmt::Debug> core::fmt::Display for EnumTryAsError<EXPECTED, GOT> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
impl<EXPECTED: core::fmt::Debug, GOT: core::fmt::Debug> std::error::Error
    for EnumTryAsError<EXPECTED, GOT>
{
}

#[model]
#[allow(clippy::redundant_pub_crate)]
mod model {
    use super::*;

    /// Unique id of blockchain
    #[derive(
        Debug,
        Display,
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
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
        Permission(permission::Permission),
        /// [`CustomParameter`](`parameter::CustomParameter`) variant.
        CustomParameterId(parameter::CustomParameterId),
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

impl_encode_as_id_box! {
    peer::PeerId,
    domain::DomainId,
    account::AccountId,
    asset::AssetDefinitionId,
    asset::AssetId,
    trigger::TriggerId,
    permission::Permission,
    role::RoleId,
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
    pub use iroha_crypto::{HashOf, PublicKey};
    pub use iroha_primitives::{
        json::*,
        numeric::{numeric, Numeric, NumericSpec},
    };

    pub use super::{
        account::prelude::*, asset::prelude::*, domain::prelude::*, events::prelude::*,
        executor::prelude::*, isi::prelude::*, metadata::prelude::*, name::prelude::*,
        parameter::prelude::*, peer::prelude::*, permission::prelude::*, query::prelude::*,
        role::prelude::*, transaction::prelude::*, trigger::prelude::*, ChainId, EnumTryAsError,
        HasMetadata, IdBox, Identifiable, ValidationFail,
    };
}
