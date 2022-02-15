//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, format, string::String, vec::Vec};
use core::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
#[cfg(feature = "std")]
use std::collections::btree_map;

use iroha_macro::FromVariant;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::prelude::*,
    domain::prelude::*,
    fixed,
    fixed::Fixed,
    metadata::{Error as MetadataError, Limits as MetadataLimits, Metadata},
    Identifiable, Name, ParseError, TryAsMut, TryAsRef, Value,
};

/// [`AssetsMap`] provides an API to work with collection of key ([`Id`]) - value
/// ([`Asset`]) pairs.
pub type AssetsMap = btree_map::BTreeMap<Id, Asset>;
/// [`AssetDefinitionsMap`] provides an API to work with collection of key ([`DefinitionId`]) - value
/// (`AssetDefinition`) pairs.
pub type AssetDefinitionsMap = btree_map::BTreeMap<DefinitionId, AssetDefinitionEntry>;

/// An entry in [`AssetDefinitionsMap`].
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct AssetDefinitionEntry {
    /// Asset definition.
    pub definition: AssetDefinition,
    /// The account that registered this asset.
    pub registered_by: AccountId,
}

impl PartialOrd for AssetDefinitionEntry {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.definition.cmp(&other.definition))
    }
}

impl Ord for AssetDefinitionEntry {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.definition.cmp(&other.definition)
    }
}

impl AssetDefinitionEntry {
    /// Constructor.
    pub const fn new(definition: AssetDefinition, registered_by: AccountId) -> Self {
        Self {
            definition,
            registered_by,
        }
    }
}

/// Asset definition defines type of that asset.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Decode, Encode, Deserialize, Serialize, IntoSchema,
)]
pub struct AssetDefinition {
    /// Type of [`AssetValue`]
    pub value_type: AssetValueType,
    /// An Identification of the [`AssetDefinition`].
    pub id: DefinitionId,
    /// Metadata of this asset definition as a key-value store.
    pub metadata: Metadata,
    /// Is the asset mintable
    pub mintable: bool,
}

/// Asset represents some sort of commodity or value.
/// All possible variants of [`Asset`] entity's components.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Asset {
    /// Component Identification.
    pub id: Id,
    /// Asset's Quantity.
    pub value: AssetValue,
}

/// Asset's inner value type.
#[derive(
    Debug,
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
pub enum AssetValueType {
    /// Asset's Quantity.
    Quantity,
    /// Asset's Big Quantity.
    BigQuantity,
    /// Decimal quantity with fixed precision
    Fixed,
    /// Asset's key-value structured data.
    Store,
}

impl FromStr for AssetValueType {
    type Err = &'static str;

    fn from_str(value_type: &str) -> Result<Self, Self::Err> {
        // TODO: Could be implemented with some macro
        match value_type {
            "Quantity" => Ok(AssetValueType::Quantity),
            "BigQuantity" => Ok(AssetValueType::BigQuantity),
            "Fixed" => Ok(AssetValueType::Fixed),
            "Store" => Ok(AssetValueType::Store),
            _ => Err("Unknown variant"),
        }
    }
}

/// Asset's inner value.
#[derive(
    Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, FromVariant, IntoSchema,
)]
pub enum AssetValue {
    /// Asset's Quantity.
    Quantity(u32),
    /// Asset's Big Quantity.
    BigQuantity(u128),
    /// Asset's Decimal Quantity.
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

impl PartialOrd for Asset {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.id.cmp(&other.id))
    }
}

impl Ord for Asset {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

/// Identification of an Asset Definition. Consists of Asset's name and Domain's name.
///
/// # Example
///
/// ```
/// use iroha_data_model::asset::DefinitionId;
///
/// let definition_id = DefinitionId::new("xor", "soramitsu");
/// ```
#[derive(
    Debug,
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
pub struct DefinitionId {
    /// Asset's name.
    pub name: Name,
    /// Domain's id.
    pub domain_id: DomainId,
}

/// Identification of an Asset's components include Entity Id ([`Asset::Id`]) and [`Account::Id`].
#[derive(
    Debug,
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
pub struct Id {
    /// Entity Identification.
    pub definition_id: DefinitionId,
    /// Account Identification.
    pub account_id: AccountId,
}

impl AssetDefinition {
    /// Construct [`AssetDefinition`].
    #[inline]
    pub fn new(id: DefinitionId, value_type: AssetValueType, mintable: bool) -> Self {
        Self {
            value_type,
            id,
            metadata: Metadata::new(),
            mintable,
        }
    }

    /// Asset definition with quantity asset value type.
    #[inline]
    pub fn new_quantity(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::Quantity, true)
    }

    /// Token definition with quantity asset value type.
    #[inline]
    pub fn new_quantity_token(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::BigQuantity, true)
    }

    /// Asset definition with big quantity asset value type.
    #[inline]
    pub fn new_big_quantity(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::BigQuantity, true)
    }

    /// Token definition with big quantity asset value type.
    #[inline]
    pub fn new_bin_quantity_token(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::BigQuantity, false)
    }

    /// Asset definition with decimal quantity asset value type.
    #[inline]
    pub fn with_precision(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::Fixed, true)
    }

    /// Token definition with decimal quantity asset value type.
    #[inline]
    pub fn with_precision_token(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::Fixed, true)
    }

    /// Asset definition with store asset value type.
    #[inline]
    pub fn new_store(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::Store, true)
    }

    /// Token definition with store asset value type.
    #[inline]
    pub fn new_store_token(id: DefinitionId) -> Self {
        AssetDefinition::new(id, AssetValueType::Store, false)
    }
}

impl Asset {
    /// Constructor
    pub fn new<V: Into<AssetValue>>(id: Id, value: V) -> Self {
        Self {
            id,
            value: value.into(),
        }
    }

    /// `Asset` with `quantity` value constructor.
    #[inline]
    pub fn with_quantity(id: Id, quantity: u32) -> Self {
        Self {
            id,
            value: quantity.into(),
        }
    }

    /// `Asset` with `big_quantity` value constructor.
    #[inline]
    pub fn with_big_quantity(id: Id, big_quantity: u128) -> Self {
        Self {
            id,
            value: big_quantity.into(),
        }
    }

    /// `Asset` with a `parameter` inside `store` value constructor.
    ///
    /// # Errors
    /// Fails if limit check fails
    pub fn with_parameter(
        id: Id,
        key: Name,
        value: Value,
        limits: MetadataLimits,
    ) -> Result<Self, MetadataError> {
        let mut store = Metadata::new();
        store.insert_with_limits(key, value, limits)?;

        Ok(Self {
            id,
            value: store.into(),
        })
    }

    /// Returns the asset type as a string.
    pub const fn value_type(&self) -> AssetValueType {
        self.value.value_type()
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
    pub fn new(name: &str, domain_name: &str) -> Result<Self, ParseError> {
        Ok(Self {
            name: Name::new(name)?,
            domain_id: DomainId::new(domain_name)?,
        })
    }

    /// Instantly construct [`Id`] from an asset definition `name` and a `domain_name` assuming these names are valid.
    #[inline]
    #[cfg(any(test, feature = "cross_crate_testing"))]
    pub fn test(name: &str, domain_name: &str) -> Self {
        Self {
            name: Name::test(name),
            domain_id: DomainId::test(domain_name),
        }
    }
}

impl Id {
    /// Construct [`Id`] from [`DefinitionId`] and [`AccountId`].
    #[inline]
    pub const fn new(definition_id: DefinitionId, account_id: AccountId) -> Self {
        Self {
            definition_id,
            account_id,
        }
    }

    /// Instantly construct [`Id`] from names which constitute
    /// [`DefinitionId`] and [`AccountId`] assuming these names are
    /// valid.
    #[inline]
    #[cfg(any(test, feature = "cross_crate_testing"))]
    pub fn test(
        asset_definition_name: &str,
        asset_definition_domain_name: &str,
        account_name: &str,
        account_domain_name: &str,
    ) -> Self {
        Self {
            definition_id: DefinitionId::test(asset_definition_name, asset_definition_domain_name),
            account_id: AccountId::test(account_name, account_domain_name),
        }
    }
}

impl Identifiable for Asset {
    type Id = Id;
}

impl Identifiable for AssetDefinition {
    type Id = DefinitionId;
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
        let vector: Vec<&str> = string.split('#').collect();
        if vector.len() != 2 {
            return Err(ParseError {
                reason: "Asset definition ID should have format `name#domain_name`",
            });
        }
        Ok(Self {
            name: Name::new(vector[0])?,
            domain_id: DomainId::new(vector[1])?,
        })
    }
}

impl Display for DefinitionId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}#{}", self.name, self.domain_id)
    }
}

impl Display for Id {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.definition_id, self.account_id)
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Asset, AssetDefinition, AssetDefinitionEntry, AssetValue, AssetValueType,
        DefinitionId as AssetDefinitionId, Id as AssetId,
    };
}
