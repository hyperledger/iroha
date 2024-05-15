//! This module contains [`Asset`] structure, it's implementation and related traits and
//! instructions implementations.
#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, format, string::String, vec::Vec};
use core::{fmt, str::FromStr};
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::{Constructor, DebugCustom, Display};
use getset::{CopyGetters, Getters};
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_primitives::numeric::{Numeric, NumericSpec, NumericSpecParseError};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    account::prelude::*, domain::prelude::*, ipfs::IpfsPath, metadata::Metadata, HasMetadata,
    Identifiable, Name, ParseError, Registered,
};

/// API to work with collections of [`Id`] : [`Asset`] mappings.
pub type AssetsMap = btree_map::BTreeMap<AssetId, Asset>;

/// [`AssetDefinitionsMap`] provides an API to work with collection of key([`AssetDefinitionId`])-value([`AssetDefinition`])
/// pairs.
pub type AssetDefinitionsMap = btree_map::BTreeMap<AssetDefinitionId, AssetDefinition>;

/// [`AssetTotalQuantityMap`] provides an API to work with collection of key([`AssetDefinitionId`])-value([`AssetValue`])
/// pairs.
pub type AssetTotalQuantityMap = btree_map::BTreeMap<AssetDefinitionId, Numeric>;

#[model]
mod model {
    use iroha_macro::FromVariant;

    use super::*;

    /// Identification of an Asset Definition. Consists of Asset name and Domais name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_data_model::asset::AssetDefinitionId;
    ///
    /// let definition_id = "xor#soramitsu".parse::<AssetDefinitionId>().expect("Valid");
    /// ```
    #[derive(
        DebugCustom,
        Clone,
        Display,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[display(fmt = "{name}#{domain_id}")]
    #[debug(fmt = "{name}#{domain_id}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct AssetDefinitionId {
        /// Domain id.
        pub domain_id: DomainId,
        /// Asset name.
        pub name: Name,
    }

    /// Identification of an Asset's components include Entity Id ([`Asset::Id`]) and [`Account::Id`].
    #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Constructor,
        Getters,
        Decode,
        Encode,
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct AssetId {
        /// Entity Identification.
        pub definition_id: AssetDefinitionId,
        /// Account Identification.
        pub account_id: AccountId,
    }

    /// Asset definition defines the type of that asset.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        CopyGetters,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "{id} {value_type}{mintable}")]
    #[allow(clippy::multiple_inherent_impl)]
    #[ffi_type]
    pub struct AssetDefinition {
        /// An Identification of the [`AssetDefinition`].
        pub id: AssetDefinitionId,
        /// Type of [`AssetValue`]
        #[getset(get_copy = "pub")]
        pub value_type: AssetValueType,
        /// Is the asset mintable
        pub mintable: Mintable,
        /// IPFS link to the [`AssetDefinition`] logo
        #[getset(get = "pub")]
        pub logo: Option<IpfsPath>,
        /// Metadata of this asset definition as a key-value store.
        pub metadata: Metadata,
        /// The account that owns this asset. Usually the [`Account`] that registered it.
        #[getset(get = "pub")]
        pub owned_by: AccountId,
    }

    /// Asset represents some sort of commodity or value.
    /// All possible variants of [`Asset`] entity's components.
    #[derive(
        Debug,
        Display,
        Clone,
        IdEqOrdHash,
        Getters,
        Decode,
        Encode,
        Deserialize,
        Serialize,
        IntoSchema,
    )]
    #[display(fmt = "{id}: {value}")]
    #[ffi_type]
    pub struct Asset {
        /// Component Identification.
        pub id: AssetId,
        /// Asset's Quantity.
        #[getset(get = "pub")]
        pub value: AssetValue,
    }

    /// Builder which can be submitted in a transaction to create a new [`AssetDefinition`]
    #[derive(
        Debug, Display, Clone, IdEqOrdHash, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    #[display(fmt = "{id} {mintable}{value_type}")]
    #[ffi_type]
    pub struct NewAssetDefinition {
        /// The identification associated with the asset definition builder.
        pub id: AssetDefinitionId,
        /// The type value associated with the asset definition builder.
        pub value_type: AssetValueType,
        /// The mintablility associated with the asset definition builder.
        pub mintable: Mintable,
        /// IPFS link to the [`AssetDefinition`] logo
        pub logo: Option<IpfsPath>,
        /// Metadata associated with the asset definition builder.
        pub metadata: Metadata,
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
        DeserializeFromStr,
        SerializeDisplay,
        IntoSchema,
    )]
    #[ffi_type]
    #[repr(u8)]
    pub enum AssetValueType {
        /// Asset's qualitative value.
        #[display(fmt = "{_0}")]
        Numeric(NumericSpec),
        /// Asset's key-value structured data.
        #[display(fmt = "Store")]
        Store,
    }

    /// Asset's inner value.
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
    pub enum AssetValue {
        /// Asset's qualitative value.
        #[display(fmt = "{_0}")]
        Numeric(
            #[skip_from]
            #[skip_try_from]
            Numeric,
        ),
        /// Asset's key-value structured data.
        Store(Metadata),
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
    #[ffi_type]
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
}

/// Error occurred while parsing `AssetValueType`
#[derive(Debug, displaydoc::Display, Clone)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[repr(u8)]
pub enum AssetValueTypeParseError {
    /// `AssetValueType` should be either `Store` or `Numeric`
    WrongVariant,
    /// Error occurred while parsing `Numeric` variant: {_0}
    Numeric(#[cfg_attr(feature = "std", source)] NumericSpecParseError),
}

impl AssetDefinition {
    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn new(id: AssetDefinitionId, value_type: AssetValueType) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, value_type)
    }

    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn numeric(id: AssetDefinitionId) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, AssetValueType::Numeric(NumericSpec::default()))
    }

    /// Construct builder for [`AssetDefinition`] identifiable by [`Id`].
    #[must_use]
    #[inline]
    pub fn store(id: AssetDefinitionId) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, AssetValueType::Store)
    }
}

impl Asset {
    /// Constructor
    pub fn new(id: AssetId, value: impl Into<AssetValue>) -> <Self as Registered>::With {
        Self {
            id,
            value: value.into(),
        }
    }
}

impl NewAssetDefinition {
    /// Create a [`NewAssetDefinition`], reserved for internal use.
    fn new(id: AssetDefinitionId, value_type: AssetValueType) -> Self {
        Self {
            id,
            value_type,
            mintable: Mintable::Infinitely,
            logo: None,
            metadata: Metadata::default(),
        }
    }

    /// Set mintability to [`Mintable::Once`]
    #[inline]
    #[must_use]
    pub fn mintable_once(mut self) -> Self {
        self.mintable = Mintable::Once;
        self
    }

    /// Add [`logo`](IpfsPath) to the asset definition replacing previously defined value
    #[must_use]
    pub fn with_logo(mut self, logo: IpfsPath) -> Self {
        self.logo = Some(logo);
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

impl HasMetadata for AssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl AssetValue {
    /// Returns the asset type as a string.
    pub const fn value_type(&self) -> AssetValueType {
        match *self {
            Self::Numeric(numeric) => {
                AssetValueType::Numeric(NumericSpec::fractional(numeric.scale()))
            }
            Self::Store(_) => AssetValueType::Store,
        }
    }
    /// Returns true if this value is zero, false if it contains [`Metadata`] or positive value
    pub const fn is_zero_value(&self) -> bool {
        match *self {
            Self::Numeric(q) => q.is_zero(),
            Self::Store(_) => false,
        }
    }
}

impl<T: Into<Numeric>> From<T> for AssetValue {
    fn from(value: T) -> Self {
        Self::Numeric(value.into())
    }
}

/// Asset Definition Identification is represented by `name#domain_name` string.
impl FromStr for AssetDefinitionId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once('#') {
            None => Err(ParseError {
                reason: "Asset Definition ID should have format `name#domain`",
            }),
            Some(("", _)) => Err(ParseError {
                reason: "Empty `name` part in `name#domain`",
            }),
            Some((_, "")) => Err(ParseError {
                reason: "Empty `domain` part in `name#domain`",
            }),
            Some((name_candidate, domain_id_candidate)) => {
                let name = name_candidate.parse().map_err(|_| ParseError {
                    reason: "Failed to parse `name` part in `name#domain`",
                })?;
                let domain_id = domain_id_candidate.parse().map_err(|_| ParseError {
                    reason: "Failed to parse `domain` part in `name#domain`",
                })?;
                Ok(Self::new(domain_id, name))
            }
        }
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.definition_id.domain_id == self.account_id.domain_id {
            write!(f, "{}##{}", self.definition_id.name, self.account_id)
        } else {
            write!(f, "{}#{}", self.definition_id, self.account_id)
        }
    }
}

impl fmt::Debug for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for AssetId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (definition_id_candidate, account_id_candidate) =
            s.rsplit_once('#').ok_or(ParseError {
                reason: "Asset ID should have format `asset#domain#account@domain`, or `asset##account@domain` for the same domains",
            })?;
        let account_id = account_id_candidate.parse::<AccountId>().map_err(|_| ParseError {
                reason: "Failed to parse `account@domain` part in `asset#domain#account@domain`. `account` should have multihash format e.g. `ed0120...`"
            })?;
        let domain_complement = if definition_id_candidate.ends_with('#') {
            account_id.domain_id.name.as_ref()
        } else {
            ""
        };
        let definition_id = format!("{definition_id_candidate}{domain_complement}").parse().map_err(|_| ParseError {
            reason: "Failed to parse `asset#domain` (or `asset#`) part in `asset#domain#account@domain` (or `asset##account@domain`)",
        })?;
        Ok(Self::new(definition_id, account_id))
    }
}

impl FromStr for AssetValueType {
    type Err = AssetValueTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Store" => Ok(Self::Store),
            s if s.starts_with("Numeric") => s
                .parse::<NumericSpec>()
                .map(Self::Numeric)
                .map_err(AssetValueTypeParseError::Numeric),
            _ => Err(AssetValueTypeParseError::WrongVariant),
        }
    }
}

impl HasMetadata for NewAssetDefinition {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl Registered for Asset {
    type With = Self;
}

impl Registered for AssetDefinition {
    type With = NewAssetDefinition;
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{
        Asset, AssetDefinition, AssetDefinitionId, AssetId, AssetValue, AssetValueType, Mintable,
        NewAssetDefinition,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_definition_id() {
        let _ok = "asset#domain"
            .parse::<AssetDefinitionId>()
            .expect("should be valid");
        let _err_empty_asset = "#domain"
            .parse::<AssetDefinitionId>()
            .expect_err("#domain should not be valid");
        let _err_empty_domain = "asset#"
            .parse::<AssetDefinitionId>()
            .expect_err("asset# should not be valid");
        let _err_violates_format = "asset@domain"
            .parse::<AssetDefinitionId>()
            .expect_err("asset@domain should not be valid");
    }

    #[test]
    fn parse_asset_id() {
        const SIGNATORY: &str =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
        let _account_id = format!("{SIGNATORY}@domain")
            .parse::<AccountId>()
            .expect("should be valid");
        let _ok = format!("asset#domain#{SIGNATORY}@domain")
            .parse::<AssetId>()
            .expect("should be valid");
        let _ok_short = format!("asset##{SIGNATORY}@domain")
            .parse::<AssetId>()
            .expect("should be valid");
        let _err = format!("asset#{SIGNATORY}@domain")
            .parse::<AssetId>()
            .expect_err("asset#signatory@domain should not be valid");
    }
}
