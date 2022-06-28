//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, format, string::String, vec::Vec};
use core::{cmp::Ordering, str::FromStr};
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::Display;
use getset::{Getters, MutGetters, Setters};
use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use strum::EnumString;

use crate::{
    account::prelude::*, domain::prelude::*, fixed, fixed::Fixed, metadata::Metadata, HasMetadata,
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
    IntoSchema,
)]
#[getset(get = "pub")]
#[allow(clippy::multiple_inherent_impl)]
#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
pub struct AssetDefinitionEntry {
    /// Asset definition.
    #[cfg_attr(feature = "mutable_api", getset(get_mut = "pub"))]
    definition: AssetDefinition,
    /// The account that registered this asset.
    registered_by: <Account as Identifiable>::Id,
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

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
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

/// Asset definition defines type of that asset.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Getters,
    MutGetters,
    Setters,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[allow(clippy::multiple_inherent_impl)]
#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
#[display(fmt = "{id} {value_type}{mintable}")]
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

impl HasMetadata for AssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl PartialOrd for AssetDefinition {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AssetDefinition {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(other.id())
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
    IntoSchema,
)]
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

/// Asset represents some sort of commodity or value.
/// All possible variants of [`Asset`] entity's components.
#[derive(
    Debug,
    Display,
    Clone,
    PartialEq,
    Eq,
    Getters,
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[getset(get = "pub")]
#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
#[display(fmt = "{id}: {value}")]
pub struct Asset {
    /// Component Identification.
    #[getset(skip)]
    id: <Self as Identifiable>::Id,
    /// Asset's Quantity.
    value: AssetValue,
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
    Decode,
    Encode,
    Deserialize,
    Serialize,
    IntoSchema,
    EnumString,
)]
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
    IntoSchema,
)]
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

impl PartialOrd for Asset {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Asset {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(other.id())
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
/// # Example
///
/// ```
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
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[display(fmt = "{name}#{domain_id}")]
pub struct DefinitionId {
    /// Asset's name.
    pub name: Name,
    /// Domain's id.
    pub domain_id: <Domain as Identifiable>::Id,
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
    Deserialize,
    Serialize,
    IntoSchema,
)]
#[display(fmt = "{definition_id}@{account_id}")] // TODO: change this?
pub struct Id {
    /// Entity Identification.
    pub definition_id: <AssetDefinition as Identifiable>::Id,
    /// Account Identification.
    pub account_id: <Account as Identifiable>::Id,
}

/// Builder which can be submitted in a transaction to create a new [`AssetDefinition`]
#[allow(clippy::multiple_inherent_impl)]
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "{id} {mintable}{value_type}")]
pub struct NewAssetDefinition {
    id: <AssetDefinition as Identifiable>::Id,
    value_type: AssetValueType,
    mintable: Mintable,
    metadata: Metadata,
}

impl Identifiable for NewAssetDefinition {
    type Id = <AssetDefinition as Identifiable>::Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl HasMetadata for NewAssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl PartialOrd for NewAssetDefinition {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NewAssetDefinition {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

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

    /// Construct [`AssetDefinition`]
    #[inline]
    #[must_use]
    #[cfg(feature = "mutable_api")]
    pub fn build(self) -> AssetDefinition {
        AssetDefinition {
            id: self.id,
            value_type: self.value_type,
            mintable: self.mintable,
            metadata: self.metadata,
        }
    }
}

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
impl NewAssetDefinition {
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

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
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

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
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

impl Identifiable for Asset {
    type Id = Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl Registered for Asset {
    type With = Self;
}

impl Identifiable for AssetDefinition {
    type Id = DefinitionId;

    fn id(&self) -> &Self::Id {
        &self.id
    }
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

/// Asset Identification is represented by `name#domain_name` string.
impl FromStr for DefinitionId {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.is_empty() {
            return Err(ParseError {
                reason: "`DefinitionId` cannot be empty",
            });
        }

        let vector: Vec<&str> = string.split('#').collect();
        if vector.len() != 2 {
            return Err(ParseError {
                reason: "Asset definition ID should have format `name#domain_name`",
            });
        }
        Ok(Self {
            name: Name::from_str(vector[0])?,
            domain_id: DomainId::from_str(vector[1])?,
        })
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Asset, AssetDefinition, AssetDefinitionEntry, AssetValue, AssetValueType,
        DefinitionId as AssetDefinitionId, Id as AssetId, MintabilityError, Mintable,
    };
}
