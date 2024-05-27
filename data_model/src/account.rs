//! Structures, traits and impls related to `Account`s.
#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, format, string::String, vec::Vec};
use core::str::FromStr;
#[cfg(feature = "std")]
use std::collections::btree_map;

use derive_more::{Constructor, DebugCustom, Display};
use getset::Getters;
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    asset::{Asset, AssetDefinitionId, AssetsMap},
    domain::prelude::*,
    metadata::Metadata,
    HasMetadata, Identifiable, ParseError, PublicKey, Registered,
};

/// API to work with collections of [`Id`] : [`Account`] mappings.
pub type AccountsMap = btree_map::BTreeMap<AccountId, Account>;

#[model]
mod model {
    use super::*;

    /// Identification of [`Account`] by the combination of the [`PublicKey`] as its sole signatory and the [`Domain`](crate::domain::Domain) it belongs to.
    /// TODO #4373 include multi-signatory use.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_data_model::account::AccountId;
    ///
    /// let id: AccountId =
    ///     "ed0120BDF918243253B1E731FA096194C8928DA37C4D3226F97EEBD18CF5523D758D6C@domain"
    ///         .parse()
    ///         .expect("multihash@domain should be valid format");
    /// ```
    #[derive(
        DebugCustom,
        Display,
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
    #[display(fmt = "{signatory}@{domain_id}")]
    #[debug(fmt = "{signatory}@{domain_id}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct AccountId {
        /// [`Domain`](crate::domain::Domain) that the [`Account`] belongs to.
        pub domain_id: DomainId,
        /// Sole signatory of the [`Account`].
        pub signatory: PublicKey,
    }

    /// Account entity is an authority which is used to execute `Iroha Special Instructions`.
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
    #[allow(clippy::multiple_inherent_impl)]
    #[display(fmt = "({id})")] // TODO: Add more?
    #[ffi_type]
    pub struct Account {
        /// Identification of the [`Account`].
        pub id: AccountId,
        /// Assets in this [`Account`].
        pub assets: AssetsMap,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
        /// Whether the account can exercise authority or not.
        pub is_active: bool,
    }

    /// Builder which should be submitted in a transaction to create a new [`Account`]
    #[derive(
        DebugCustom, Display, Clone, IdEqOrdHash, Decode, Encode, Serialize, Deserialize, IntoSchema,
    )]
    #[display(fmt = "[{id}]")]
    #[debug(fmt = "[{id:?}] {{ metadata: {metadata} }}")]
    #[ffi_type]
    pub struct NewAccount {
        /// Identification
        pub id: AccountId,
        /// Metadata that should be submitted with the builder
        pub metadata: Metadata,
    }
}

impl AccountId {
    /// Return `true` if the account signatory matches the given `public_key`.
    #[inline]
    #[cfg(feature = "transparent_api")]
    pub fn signatory_matches(&self, public_key: &PublicKey) -> bool {
        self.signatory() == public_key
    }
}

impl Account {
    /// Construct builder for [`Account`] identifiable by [`Id`] containing the given signatory.
    #[inline]
    #[must_use]
    pub fn new(id: AccountId) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id)
    }

    /// Return a reference to the `Account` signatory.
    #[inline]
    pub fn signatory(&self) -> &PublicKey {
        &self.id.signatory
    }

    /// Return a reference to the [`Asset`] corresponding to the asset id.
    #[inline]
    pub fn asset(&self, asset_id: &AssetDefinitionId) -> Option<&Asset> {
        self.assets.get(asset_id)
    }

    /// Get an iterator over [`Asset`]s of the `Account`
    #[inline]
    pub fn assets(&self) -> impl ExactSizeIterator<Item = &Asset> {
        self.assets.values()
    }
}

#[cfg(feature = "transparent_api")]
impl Account {
    /// Add [`Asset`] into the [`Account`] returning previous asset stored under the same id
    #[inline]
    pub fn add_asset(&mut self, asset: Asset) -> Option<Asset> {
        assert_eq!(self.id, asset.id.account_id);
        self.assets.insert(asset.id.definition_id.clone(), asset)
    }

    /// Remove asset from the [`Account`] and return it
    #[inline]
    pub fn remove_asset(&mut self, asset_id: &AssetDefinitionId) -> Option<Asset> {
        self.assets.remove(asset_id)
    }

    /// Activate the account to enable its authority
    #[inline]
    pub fn activate(&mut self) {
        self.is_active = true
    }
}

impl NewAccount {
    fn new(id: AccountId) -> Self {
        Self {
            id,
            metadata: Metadata::default(),
        }
    }

    /// Add [`Metadata`] to the account replacing any previously defined metadata
    #[inline]
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

#[cfg(feature = "transparent_api")]
impl NewAccount {
    /// Convert into [`Account`].
    pub fn into_account(self) -> Account {
        Account {
            id: self.id,
            assets: AssetsMap::default(),
            metadata: self.metadata,
            is_active: false,
        }
    }
}

impl HasMetadata for NewAccount {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl HasMetadata for Account {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

impl Registered for Account {
    type With = NewAccount;
}

impl FromStr for AccountId {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.rsplit_once('@') {
            None => Err(ParseError {
                reason: "Account ID should have format `signatory@domain`",
            }),
            Some(("", _)) => Err(ParseError {
                reason: "Empty `signatory` part in `signatory@domain`",
            }),
            Some((_, "")) => Err(ParseError {
                reason: "Empty `domain` part in `signatory@domain`",
            }),
            Some((signatory_candidate, domain_id_candidate)) => {
                let signatory = signatory_candidate.parse().map_err(|_| ParseError {
                    reason: r#"Failed to parse `signatory` part in `signatory@domain`. `signatory` should have multihash format e.g. "ed0120...""#,
                })?;
                let domain_id = domain_id_candidate.parse().map_err(|_| ParseError {
                    reason: "Failed to parse `domain` part in `signatory@domain`",
                })?;
                Ok(Self::new(domain_id, signatory))
            }
        }
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Account, AccountId};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "transparent_api")]
    #[test]
    fn parse_account_id() {
        const SIGNATORY: &str =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
        let _ok = format!("{SIGNATORY}@domain")
            .parse::<AccountId>()
            .expect("should be valid");
        let _err_empty_signatory = "@domain"
            .parse::<AccountId>()
            .expect_err("@domain should not be valid");
        let _err_empty_domain = format!("{SIGNATORY}@")
            .parse::<AccountId>()
            .expect_err("signatory@ should not be valid");
        let _err_violates_format = format!("{SIGNATORY}#domain")
            .parse::<AccountId>()
            .expect_err("signatory#domain should not be valid");
    }
}
