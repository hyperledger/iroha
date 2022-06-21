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
pub type AssetsMap<const HASH_LENGTH: usize> =
    btree_map::BTreeMap<<Asset<HASH_LENGTH> as Identifiable>::Id, Asset<HASH_LENGTH>>;

/// [`AssetDefinitionsMap`] provides an API to work with collection of key ([`DefinitionId`]) - value
/// (`AssetDefinition`) pairs.
pub type AssetDefinitionsMap<const HASH_LENGTH: usize> = btree_map::BTreeMap<
    <AssetDefinition<HASH_LENGTH> as Identifiable>::Id,
    AssetDefinitionEntry<HASH_LENGTH>,
>;

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
pub struct AssetDefinitionEntry<const HASH_LENGTH: usize> {
    /// Asset definition.
    #[cfg_attr(feature = "mutable_api", getset(get_mut = "pub"))]
    definition: AssetDefinition<HASH_LENGTH>,
    /// The account that registered this asset.
    registered_by: <Account<HASH_LENGTH> as Identifiable>::Id,
}

impl<const HASH_LENGTH: usize> PartialOrd for AssetDefinitionEntry<HASH_LENGTH> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const HASH_LENGTH: usize> Ord for AssetDefinitionEntry<HASH_LENGTH> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.definition().cmp(other.definition())
    }
}

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
impl<const HASH_LENGTH: usize> AssetDefinitionEntry<HASH_LENGTH> {
    /// Constructor.
    pub const fn new(
        definition: AssetDefinition<HASH_LENGTH>,
        registered_by: <Account<HASH_LENGTH> as Identifiable>::Id,
    ) -> Self {
        Self {
            definition,
            registered_by,
        }
    }
}

#[cfg(feature = "mutable_api")]
impl<const HASH_LENGTH: usize> AssetDefinitionEntry<HASH_LENGTH> {
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
pub struct AssetDefinition<const HASH_LENGTH: usize> {
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
    metadata: Metadata<HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> HasMetadata for AssetDefinition<HASH_LENGTH> {
    fn metadata(&self) -> &Metadata<HASH_LENGTH> {
        &self.metadata
    }
}

impl<const HASH_LENGTH: usize> PartialOrd for AssetDefinition<HASH_LENGTH> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const HASH_LENGTH: usize> Ord for AssetDefinition<HASH_LENGTH> {
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
pub struct Asset<const HASH_LENGTH: usize> {
    /// Component Identification.
    #[getset(skip)]
    id: <Self as Identifiable>::Id,
    /// Asset's Quantity.
    value: AssetValue<HASH_LENGTH>,
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
pub enum AssetValue<const HASH_LENGTH: usize> {
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
    Store(Metadata<HASH_LENGTH>),
}

impl<const HASH_LENGTH: usize> AssetValue<HASH_LENGTH> {
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

impl<const HASH_LENGTH: usize> PartialOrd for Asset<HASH_LENGTH> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const HASH_LENGTH: usize> Ord for Asset<HASH_LENGTH> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(other.id())
    }
}

macro_rules! impl_try_as_for_asset_value {
    ( $($variant:ident( $ty:ty ),)* ) => {$(
        impl<const HASH_LENGTH: usize> TryAsMut<$ty> for AssetValue<HASH_LENGTH> {
            type Error = crate::EnumTryAsError<$ty, AssetValueType>;

            fn try_as_mut(&mut self) -> Result<&mut $ty, Self::Error> {
                if let AssetValue:: $variant (value) = self {
                    Ok(value)
                } else {
                    Err(crate::EnumTryAsError::got(self.value_type()))
                }
            }
        }

        impl<const HASH_LENGTH: usize> TryAsRef<$ty> for AssetValue<HASH_LENGTH> {
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
    Store(Metadata<{ HASH_LENGTH }>),
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
pub struct DefinitionId<const HASH_LENGTH: usize> {
    /// Asset's name.
    pub name: Name,
    /// Domain's id.
    pub domain_id: <Domain<HASH_LENGTH> as Identifiable>::Id,
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
pub struct Id<const HASH_LENGTH: usize> {
    /// Entity Identification.
    pub definition_id: <AssetDefinition<HASH_LENGTH> as Identifiable>::Id,
    /// Account Identification.
    pub account_id: <Account<HASH_LENGTH> as Identifiable>::Id,
}

/// Builder which can be submitted in a transaction to create a new [`AssetDefinition`]
#[allow(clippy::multiple_inherent_impl)]
#[derive(
    Debug, Display, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
#[display(fmt = "{id} {mintable}{value_type}")]
pub struct NewAssetDefinition<const HASH_LENGTH: usize> {
    id: <AssetDefinition<HASH_LENGTH> as Identifiable>::Id,
    value_type: AssetValueType,
    mintable: Mintable,
    metadata: Metadata<HASH_LENGTH>,
}

impl<const HASH_LENGTH: usize> Identifiable for NewAssetDefinition<HASH_LENGTH> {
    type Id = <AssetDefinition<HASH_LENGTH> as Identifiable>::Id;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl<const HASH_LENGTH: usize> HasMetadata for NewAssetDefinition<HASH_LENGTH> {
    fn metadata(&self) -> &Metadata<HASH_LENGTH> {
        &self.metadata
    }
}

impl<const HASH_LENGTH: usize> PartialOrd for NewAssetDefinition<HASH_LENGTH> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<const HASH_LENGTH: usize> Ord for NewAssetDefinition<HASH_LENGTH> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl<const HASH_LENGTH: usize> NewAssetDefinition<HASH_LENGTH> {
    /// Create a [`NewAssetDefinition`], reserved for internal use.
    fn new(
        id: <AssetDefinition<HASH_LENGTH> as Identifiable>::Id,
        value_type: AssetValueType,
    ) -> Self {
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
    pub fn build(self) -> AssetDefinition<HASH_LENGTH> {
        AssetDefinition {
            id: self.id,
            value_type: self.value_type,
            mintable: self.mintable,
            metadata: self.metadata,
        }
    }
}

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
impl<const HASH_LENGTH: usize> NewAssetDefinition<HASH_LENGTH> {
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
    pub fn with_metadata(mut self, metadata: Metadata<HASH_LENGTH>) -> Self {
        self.metadata = metadata;
        self
    }
}

#[cfg_attr(feature = "ffi_api", iroha_ffi::ffi_bindgen)]
impl<const HASH_LENGTH: usize> AssetDefinition<HASH_LENGTH> {
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
impl<const HASH_LENGTH: usize> AssetDefinition<HASH_LENGTH> {
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
impl<const HASH_LENGTH: usize> Asset<HASH_LENGTH> {
    /// Constructor
    pub fn new(
        id: <Asset<HASH_LENGTH> as Identifiable>::Id,
        value: impl Into<AssetValue<HASH_LENGTH>>,
    ) -> <Self as Registered>::With {
        Self {
            id,
            value: value.into(),
        }
    }
}

impl<T, const HASH_LENGTH: usize> TryAsMut<T> for Asset<HASH_LENGTH>
where
    AssetValue<HASH_LENGTH>: TryAsMut<T>,
{
    type Error = <AssetValue<HASH_LENGTH> as TryAsMut<T>>::Error;

    #[inline]
    fn try_as_mut(&mut self) -> Result<&mut T, Self::Error> {
        self.value.try_as_mut()
    }
}

impl<T, const HASH_LENGTH: usize> TryAsRef<T> for Asset<HASH_LENGTH>
where
    AssetValue<HASH_LENGTH>: TryAsRef<T>,
{
    type Error = <AssetValue<HASH_LENGTH> as TryAsRef<T>>::Error;

    #[inline]
    fn try_as_ref(&self) -> Result<&T, Self::Error> {
        self.value.try_as_ref()
    }
}

impl<const HASH_LENGTH: usize> DefinitionId<HASH_LENGTH> {
    /// Construct [`Id`] from an asset definition `name` and a `domain_name` if these names are valid.
    ///
    /// # Errors
    /// Fails if any sub-construction fails
    #[inline]
    pub const fn new(name: Name, domain_id: <Domain<HASH_LENGTH> as Identifiable>::Id) -> Self {
        Self { name, domain_id }
    }

    pub(crate) const fn empty() -> Self {
        Self {
            name: Name::empty(),
            domain_id: DomainId::empty(),
        }
    }
}

impl<const HASH_LENGTH: usize> Id<HASH_LENGTH> {
    /// Construct [`Id`] from [`DefinitionId`] and [`AccountId`].
    #[inline]
    pub const fn new(
        definition_id: <AssetDefinition<HASH_LENGTH> as Identifiable>::Id,
        account_id: <Account<HASH_LENGTH> as Identifiable>::Id,
    ) -> Self {
        Self {
            definition_id,
            account_id,
        }
    }
}

impl<const HASH_LENGTH: usize> Identifiable for Asset<HASH_LENGTH> {
    type Id = Id<HASH_LENGTH>;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl<const HASH_LENGTH: usize> Registered for Asset<HASH_LENGTH> {
    type With = Self;
}

impl<const HASH_LENGTH: usize> Identifiable for AssetDefinition<HASH_LENGTH> {
    type Id = DefinitionId<HASH_LENGTH>;

    fn id(&self) -> &Self::Id {
        &self.id
    }
}

impl<const HASH_LENGTH: usize> Registered for AssetDefinition<HASH_LENGTH> {
    type With = NewAssetDefinition<HASH_LENGTH>;
}

impl<const HASH_LENGTH: usize> FromIterator<Asset<HASH_LENGTH>> for Value<HASH_LENGTH> {
    fn from_iter<T: IntoIterator<Item = Asset<HASH_LENGTH>>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

impl<const HASH_LENGTH: usize> FromIterator<AssetDefinition<HASH_LENGTH>> for Value<HASH_LENGTH> {
    fn from_iter<T: IntoIterator<Item = AssetDefinition<HASH_LENGTH>>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// Asset Identification is represented by `name#domain_name` string.
impl<const HASH_LENGTH: usize> FromStr for DefinitionId<HASH_LENGTH> {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        if string.is_empty() {
            return Ok(Self::empty());
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
