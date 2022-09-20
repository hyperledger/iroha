//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.
#![allow(clippy::std_instead_of_alloc)]

#[cfg(not(feature = "std"))]
use alloc::{alloc::alloc, boxed::Box, collections::btree_map, format, string::String, vec::Vec};
use core::{cmp::Ordering, str::FromStr};
#[cfg(feature = "std")]
use std::alloc::alloc;
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::Display;
use getset::{Getters, MutGetters};
use iroha_data_model_derive::IdOrdEqHash;
use iroha_ffi::{IntoFfi, TryFromReprC};
use iroha_macro::FromVariant;
use iroha_primitives::{fixed, fixed::Fixed};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use strum::EnumString;

use crate::{
    account::prelude::*, domain::prelude::*, ffi::ffi_item, metadata::Metadata, HasMetadata,
    Identifiable, Name, ParseError, Registered, TryAsMut, TryAsRef, Value,
};

/// [`AssetsMap`] provides an API to work with collection of key ([`Id`]) - value
/// ([`Asset`]) pairs.
pub type AssetsMap = btree_map::BTreeMap<<Asset as Identifiable>::Id, Asset>;

/// [`AssetDefinitionsMap`] provides an API to work with collection of key ([`DefinitionId`]) - value
/// (`AssetDefinition`) pairs.
pub type AssetDefinitionsMap =
    btree_map::BTreeMap<<AssetDefinition as Identifiable>::Id, AssetDefinitionEntry>;

/// Mintability logic error
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq)]
pub enum MintabilityError {
    /// Tried to mint an Un-mintable asset.
    #[display(fmt = "This asset cannot be minted more than once and it was already minted.")]
    MintUnmintable,
    /// Tried to forbid minting on assets that should be mintable.
    #[display(fmt = "This asset was set as infinitely mintable. You cannot forbid its minting.")]
    ForbidMintOnMintable,
}

#[cfg(feature = "std")]
impl std::error::Error for MintabilityError {}

ffi_item! {
    /// An entry in [`AssetDefinitionsMap`].
    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        Getters,
        MutGetters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoFfi,
        TryFromReprC,
        IntoSchema,
    )]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), iroha_ffi::ffi_export)]
    #[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
    #[allow(clippy::multiple_inherent_impl)]
    #[getset(get = "pub")]
    pub struct AssetDefinitionEntry {
        /// Asset definition.
        #[cfg_attr(feature = "mutable_api", getset(get_mut = "pub"))]
        definition: AssetDefinition,
        /// The account that registered this asset.
        registered_by: <Account as Identifiable>::Id,
    }
}

impl PartialOrd for AssetDefinitionEntry {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssetDefinitionEntry {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.definition().cmp(other.definition())
    }
}

#[cfg_attr(
    all(feature = "ffi_export", not(feature = "ffi_import")),
    iroha_ffi::ffi_export
)]
#[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
impl AssetDefinitionEntry {
    /// Constructor.
    pub const fn new(
        definition: AssetDefinition,
        registered_by: <Account as Identifiable>::Id,
    ) -> Self {
        Self {
            definition,
            registered_by,
        }
    }
}

#[cfg(feature = "mutable_api")]
impl AssetDefinitionEntry {
    /// Turn off minting for this asset.
    ///
    /// # Errors
    /// If the asset was declared as `Mintable::Infinitely`
    pub fn forbid_minting(&mut self) -> Result<(), MintabilityError> {
        self.definition.forbid_minting()
    }
}

ffi_item! {
    /// Asset definition defines type of that asset.
    #[derive(
        Debug,
        Display,
        Clone,
        IdOrdEqHash,
        Getters,
        MutGetters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoFfi,
        TryFromReprC,
        IntoSchema,
    )]
    #[display(fmt = "{id} {value_type}{mintable}")]
    #[allow(clippy::multiple_inherent_impl)]
    #[id(type = "DefinitionId")]
    pub struct AssetDefinition {
        /// An Identification of the [`AssetDefinition`].
        id: <Self as Identifiable>::Id,
        /// Type of [`AssetValue`]
        #[getset(get = "pub")]
        value_type: AssetValueType,
        /// Is the asset mintable
        #[getset(get = "pub")]
        mintable: Mintable,
        /// Metadata of this asset definition as a key-value store.
        #[cfg_attr(feature = "mutable_api", getset(get_mut = "pub"))]
        metadata: Metadata,
    }
}

impl HasMetadata for AssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

/// An assets mintability scheme. `Infinitely` means elastic
/// supply. `Once` is what you want to use. Don't use `Not` explicitly
/// outside of smartcontracts.
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
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[repr(u8)]
pub enum Mintable {
    /// Regular asset with elastic supply. Can be minted and burned.
    #[display(fmt = "+")]
    Infinitely,
    /// Non-mintable asset (token), with a fixed supply. Can be burned, and minted **once**.
    #[display(fmt = "=")]
    Once,
    /// Non-mintable asset (token), with a fixed supply. Can be burned, but not minted.
    #[display(fmt = "-")]
    Not,
    // TODO: Support more variants using bit-compacted tag, and `u32` mintability tokens.
}

ffi_item! {
    /// Asset represents some sort of commodity or value.
    /// All possible variants of [`Asset`] entity's components.
    #[derive(
        Debug,
        Display,
        Clone,
        IdOrdEqHash,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoFfi,
        TryFromReprC,
        IntoSchema,
    )]
    #[cfg_attr(all(feature = "ffi_export", not(feature = "ffi_import")), iroha_ffi::ffi_export)]
    #[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
    #[display(fmt = "{id}: {value}")]
    #[getset(get = "pub")]
    #[id(type = "Id")]
    pub struct Asset {
        /// Component Identification.
        #[getset(skip)]
        id: <Self as Identifiable>::Id,
        /// Asset's Quantity.
        value: AssetValue,
    }
}

/// Asset's inner value type.
#[derive(
    Debug,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    EnumString,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[repr(u8)]
pub enum AssetValueType {
    /// Asset's Quantity.
    #[display(fmt = "q")]
    Quantity,
    /// Asset's Big Quantity.
    #[display(fmt = "Q")]
    BigQuantity,
    /// Decimal quantity with fixed precision
    #[display(fmt = "f")]
    Fixed,
    /// Asset's key-value structured data.
    #[display(fmt = "s")]
    Store,
}

/// Asset's inner value.
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
    FromVariant,
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[repr(u8)]
pub enum AssetValue {
    /// Asset's Quantity.
    #[display(fmt = "{_0}q")]
    Quantity(u32),
    /// Asset's Big Quantity
    #[display(fmt = "{_0}Q")]
    BigQuantity(u128),
    /// Asset's Decimal Quantity.
    #[display(fmt = "{_0}f")]
    Fixed(fixed::Fixed),
    /// Asset's key-value structured data.
    Store(Metadata),
}

impl AssetValue {
    /// Returns the asset type as a string.
    pub const fn value_type(&self) -> AssetValueType {
        match *self {
            Self::Quantity(_) => AssetValueType::Quantity,
            Self::BigQuantity(_) => AssetValueType::BigQuantity,
            Self::Fixed(_) => AssetValueType::Fixed,
            Self::Store(_) => AssetValueType::Store,
        }
    }
    /// Returns true if this value is zero, false if it contains [`Metadata`] or positive value
    pub const fn is_zero_value(&self) -> bool {
        match *self {
            Self::Quantity(q) => q == 0_u32,
            Self::BigQuantity(q) => q == 0_u128,
            Self::Fixed(ref q) => q.is_zero(),
            Self::Store(_) => false,
        }
    }
}

macro_rules! impl_try_as_for_asset_value {
    ( $($variant:ident( $ty:ty ),)* ) => {$(
        impl TryAsMut<$ty> for AssetValue {
            type Error = crate::EnumTryAsError<$ty, AssetValueType>;

            fn try_as_mut(&mut self) -> Result<&mut $ty, Self::Error> {
                if let AssetValue:: $variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(self.value_type()))
                }
            }
        }

        impl TryAsRef<$ty> for AssetValue {
            type Error = crate::EnumTryAsError<$ty, AssetValueType>;

            fn try_as_ref(&self) -> Result<& $ty, Self::Error> {
                if let AssetValue:: $variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(self.value_type()))
                }
            }
        }
    )*}
}

impl_try_as_for_asset_value! {
    Quantity(u32),
    BigQuantity(u128),
    Fixed(Fixed),
    Store(Metadata),
}

/// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
///
/// # Examples
///
/// ```rust
/// use iroha_data_model::asset::DefinitionId;
///
/// let definition_id = "xor#soramitsu".parse::<DefinitionId>().expect("Valid");
/// ```
#[derive(
    Debug,
    Clone,
    Display,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    DeserializeFromStr,
    SerializeDisplay,
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[display(fmt = "{name}#{domain_id}")]
pub struct DefinitionId {
    /// Asset's name.
    pub name: Name,
    /// Domain's id.
    pub domain_id: <Domain as Identifiable>::Id,
}

/// Asset Definition Identification is represented by `name#domain_name` string.
impl FromStr for DefinitionId {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut split = string.split('#');
        match (split.next(), split.next(), split.next()) {
            (Some(""), _, _) => Err(ParseError {
                reason: "Asset Definition ID cannot be empty",
            }),
            (Some(name), Some(domain_id), None) if !domain_id.is_empty() => Ok(Self {
                name: name.parse()?,
                domain_id: domain_id.parse()?,
            }),
            _ => Err(ParseError {
                reason: "Asset Definition ID should have format `asset#domain`",
            }),
        }
    }
}

/// Identification of an Asset's components include Entity Id ([`Asset::Id`]) and [`Account::Id`].
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    DeserializeFromStr,
    SerializeDisplay,
    IntoFfi,
    TryFromReprC,
    IntoSchema,
)]
#[display(fmt = "{}#{}", "self.definition_id.name", "self.account_id")]
pub struct Id {
    /// Entity Identification.
    pub definition_id: <AssetDefinition as Identifiable>::Id,
    /// Account Identification.
    pub account_id: <Account as Identifiable>::Id,
}

/// Asset Identification is represented by `name#account@domain` string.
impl FromStr for Id {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut split = string.split('#');
        match (split.next(), split.next(), split.next()) {
            (Some(""), _, _) => Err(ParseError {
                reason: "Asset ID cannot be empty",
            }),
            (Some(name), Some(account_id), None) if !account_id.is_empty() => {
                let name = name.parse()?;
                let account_id = <Account as Identifiable>::Id::from_str(account_id)?;
                let definition_id =
                    <AssetDefinition as Identifiable>::Id::new(name, account_id.domain_id.clone());
                Ok(Self {
                    definition_id,
                    account_id,
                })
            }
            _ => Err(ParseError {
                reason: "Asset ID should have format `asset#account@domain`",
            }),
        }
    }
}

ffi_item! {
    /// Builder which can be submitted in a transaction to create a new [`AssetDefinition`]
    #[derive(
        Debug,
        Display,
        Clone,
        IdOrdEqHash,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoFfi,
        TryFromReprC,
        IntoSchema,
    )]
    #[id(type = "<AssetDefinition as Identifiable>::Id")]
    #[display(fmt = "{id} {mintable}{value_type}")]
    pub struct NewAssetDefinition {
        id: <AssetDefinition as Identifiable>::Id,
        value_type: AssetValueType,
        mintable: Mintable,
        metadata: Metadata,
    }
}

#[cfg(feature = "mutable_api")]
impl crate::Registrable for NewAssetDefinition {
    type Target = AssetDefinition;

    #[must_use]
    #[inline]
    fn build(self) -> Self::Target {
        Self::Target {
            id: self.id,
            value_type: self.value_type,
            mintable: self.mintable,
            metadata: self.metadata,
        }
    }
}

impl HasMetadata for NewAssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

#[cfg_attr(
    all(feature = "ffi_export", not(feature = "ffi_import")),
    iroha_ffi::ffi_export
)]
#[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
impl NewAssetDefinition {
    /// Create a [`NewAssetDefinition`], reserved for internal use.
    fn new(id: <AssetDefinition as Identifiable>::Id, value_type: AssetValueType) -> Self {
        Self {
            id,
            value_type,
            mintable: Mintable::Infinitely,
            metadata: Metadata::default(),
        }
    }

    /// Identification
    #[inline]
    pub(crate) fn id(&self) -> &<AssetDefinition as Identifiable>::Id {
        &self.id
    }

    /// Set mintability to [`Mintable::Once`]
    #[inline]
    #[must_use]
    pub fn mintable_once(mut self) -> Self {
        self.mintable = Mintable::Once;
        self
    }

    /// Add [`Metadata`] to the asset definition replacing previously defined value
    #[inline]
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

#[cfg_attr(
    all(feature = "ffi_export", not(feature = "ffi_import")),
    iroha_ffi::ffi_export
)]
#[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
impl AssetDefinition {
    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn quantity(id: <Self as Identifiable>::Id) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, AssetValueType::Quantity)
    }

    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn big_quantity(id: <Self as Identifiable>::Id) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, AssetValueType::BigQuantity)
    }

    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn fixed(id: <Self as Identifiable>::Id) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, AssetValueType::Fixed)
    }

    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn store(id: <Self as Identifiable>::Id) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, AssetValueType::Store)
    }
}

#[cfg(feature = "mutable_api")]
impl AssetDefinition {
    /// Stop minting on the [`AssetDefinition`] globally.
    ///
    /// # Errors
    /// If the [`AssetDefinition`] is not `Mintable::Once`.
    #[inline]
    pub fn forbid_minting(&mut self) -> Result<(), MintabilityError> {
        if self.mintable == Mintable::Once {
            self.mintable = Mintable::Not;
            Ok(())
        } else {
            Err(MintabilityError::ForbidMintOnMintable)
        }
    }
}

#[cfg_attr(
    all(feature = "ffi_export", not(feature = "ffi_import")),
    iroha_ffi::ffi_export
)]
#[cfg_attr(feature = "ffi_import", iroha_ffi::ffi_import)]
impl Asset {
    /// Constructor
    pub fn new(
        id: <Asset as Identifiable>::Id,
        value: impl Into<AssetValue>,
    ) -> <Self as Registered>::With {
        Self {
            id,
            value: value.into(),
        }
    }
}

impl<T> TryAsMut<T> for Asset
where
    AssetValue: TryAsMut<T>,
{
    type Error = <AssetValue as TryAsMut<T>>::Error;

    #[inline]
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error> {
        self.value.try_as_mut()
    }
}

impl<T> TryAsRef<T> for Asset
where
    AssetValue: TryAsRef<T>,
{
    type Error = <AssetValue as TryAsRef<T>>::Error;

    #[inline]
    fn try_as_ref(&self) -> Result<&T, Self::Error> {
        self.value.try_as_ref()
    }
}

impl DefinitionId {
    /// Construct [`Id`] from an asset definition `name` and a `domain_name` if these names are valid.
    ///
    /// # Errors
    /// Fails if any sub-construction fails
    #[inline]
    pub const fn new(name: Name, domain_id: <Domain as Identifiable>::Id) -> Self {
        Self { name, domain_id }
    }
}

impl Id {
    /// Construct [`Id`] from [`DefinitionId`] and [`AccountId`].
    #[inline]
    pub const fn new(
        definition_id: <AssetDefinition as Identifiable>::Id,
        account_id: <Account as Identifiable>::Id,
    ) -> Self {
        Self {
            definition_id,
            account_id,
        }
    }
}

impl Registered for Asset {
    type With = Self;
}

impl Registered for AssetDefinition {
    type With = NewAssetDefinition;
}

impl FromIterator<Asset> for Value {
    fn from_iter<T: IntoIterator<Item = Asset>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

impl FromIterator<AssetDefinition> for Value {
    fn from_iter<T: IntoIterator<Item = AssetDefinition>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Asset, AssetDefinition, AssetDefinitionEntry, AssetValue, AssetValueType,
        DefinitionId as AssetDefinitionId, Id as AssetId, MintabilityError, Mintable,
    };
}
