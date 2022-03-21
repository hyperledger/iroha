//! This module contains [`Domain`](`crate::domain::Domain`) structure and related implementations and trait implementations.

#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map, format, string::String, vec::Vec};
use core::{cmp::Ordering, fmt, str::FromStr};
#[cfg(feature = "std")]
use std::collections::btree_map;

use getset::{Getters, MutGetters};
use iroha_crypto::PublicKey;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::{Account, AccountsMap, GenesisAccount},
    asset::AssetDefinitionsMap,
    metadata::Metadata,
    prelude::{AssetDefinition, AssetDefinitionEntry},
    Identifiable, Name, ParseError,
};

/// Genesis domain name. Genesis domain should contain only genesis account.
pub const GENESIS_DOMAIN_NAME: &str = "genesis";

/// Genesis domain. It will contain only one `genesis` account.
#[derive(Debug, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct GenesisDomain {
    genesis_key: PublicKey,
}

impl GenesisDomain {
    /// Returns `GenesisDomain`.
    #[inline]
    #[must_use]
    pub const fn new(genesis_key: PublicKey) -> Self {
        Self { genesis_key }
    }
}

impl From<GenesisDomain> for Domain {
    fn from(domain: GenesisDomain) -> Self {
        #[allow(clippy::expect_used)]
        Self {
            id: Id::new(GENESIS_DOMAIN_NAME).expect("Programmer error. Should pass verification"),
            accounts: core::iter::once((
                <Account as Identifiable>::Id::genesis(),
                GenesisAccount::new(domain.genesis_key).into(),
            ))
            .collect(),
            asset_definitions: btree_map::BTreeMap::default(),
            metadata: Metadata::default(),
            logo: None,
        }
    }
}

/// Builder which can be submitted in a transaction to create a new [`Domain`]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct NewDomain {
    id: <Domain as Identifiable>::Id,
    logo: Option<IpfsPath>,
    metadata: Metadata,
}

impl PartialOrd for NewDomain {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.id.cmp(&other.id))
    }
}

impl Ord for NewDomain {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl NewDomain {
    #[must_use]
    fn new(id: <Domain as Identifiable>::Id) -> Self {
        Self {
            id,
            logo: None,
            metadata: Metadata::default(),
        }
    }

    /// Add [`logo`](IpfsPath) to the domain replacing previously defined value
    #[must_use]
    pub fn with_logo(mut self, logo: IpfsPath) -> Self {
        self.logo = Some(logo);
        self
    }

    /// Add [`Metadata`] to the domain replacing previously defined value
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Named group of [`Account`] and [`Asset`](`crate::asset::Asset`) entities.
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
pub struct Domain {
    /// Identification of this [`Domain`].
    id: Id,
    /// [`Account`]s of the domain.
    #[getset(skip)]
    accounts: AccountsMap,
    /// [`Asset`](AssetDefinition)s defined of the `Domain`.
    #[getset(skip)]
    asset_definitions: AssetDefinitionsMap,
    /// IPFS link to the `Domain` logo
    logo: Option<IpfsPath>,
    /// [`Metadata`] of this `Domain` as a key-value store.
    #[cfg_attr(feature = "mutable_api", getset(get_mut = "pub"))]
    metadata: Metadata,
}

impl Identifiable for Domain {
    type Id = Id;
    type Constructor = NewDomain;
}

impl PartialOrd for Domain {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.id().cmp(&other.id))
    }
}

impl Ord for Domain {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id().cmp(&other.id)
    }
}

impl Domain {
    /// Construct builder for [`Domain`] identifiable by [`Id`].
    pub fn new(id: Id) -> <Self as Identifiable>::Constructor {
        <Self as Identifiable>::Constructor::new(id)
    }

    /// Return a reference to the [`Account`] corresponding to the account id.
    #[inline]
    pub fn account(&self, account_id: &<Account as Identifiable>::Id) -> Option<&Account> {
        self.accounts.get(account_id)
    }

    /// Return a reference to the asset definition corresponding to the asset definition id
    #[inline]
    pub fn asset_definition(
        &self,
        asset_definition_id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<&AssetDefinitionEntry> {
        self.asset_definitions.get(asset_definition_id)
    }

    /// Get an iterator over [`Account`] of the `Domain`
    #[inline]
    pub fn accounts(&self) -> impl ExactSizeIterator<Item = &Account> {
        self.accounts.values()
    }

    /// Return `true` if the `Domain` contains [`Account`]
    #[inline]
    pub fn contains_account(&self, account_id: &<Account as Identifiable>::Id) -> bool {
        self.accounts.contains_key(account_id)
    }

    /// Get an iterator over asset definitions of the `Domain`
    #[inline]
    pub fn asset_definitions(&self) -> impl ExactSizeIterator<Item = &AssetDefinitionEntry> {
        self.asset_definitions.values()
    }
}

#[cfg(feature = "mutable_api")]
impl Domain {
    /// Return a mutable reference to the [`Account`] corresponding to the account id.
    #[inline]
    pub fn account_mut(
        &mut self,
        account_id: &<Account as Identifiable>::Id,
    ) -> Option<&mut Account> {
        self.accounts.get_mut(account_id)
    }

    /// Add [`Account`] into the [`Domain`] returning previous account stored under the same id
    #[inline]
    pub fn add_account(&mut self, account: impl Into<Account>) -> Option<Account> {
        let account = account.into();
        self.accounts.insert(account.id().clone(), account)
    }

    /// Remove account from the [`Domain`] and return it
    #[inline]
    pub fn remove_account(
        &mut self,
        account_id: &<Account as Identifiable>::Id,
    ) -> Option<Account> {
        self.accounts.remove(account_id)
    }

    /// Get a mutable iterator over accounts of the domain
    #[inline]
    pub fn accounts_mut(&mut self) -> impl ExactSizeIterator<Item = &mut Account> {
        self.accounts.values_mut()
    }

    /// Get a mutable iterator over asset definitions of the [`Domain`]
    #[inline]
    pub fn asset_definition_mut(
        &mut self,
        asset_definition_id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<&mut AssetDefinitionEntry> {
        self.asset_definitions.get_mut(asset_definition_id)
    }

    /// Add asset definition into the [`Domain`] returning previous asset definition stored under
    /// the same id
    #[inline]
    pub fn add_asset_definition(
        &mut self,
        asset_definition: impl Into<AssetDefinition>,
        registered_by: <Account as Identifiable>::Id,
    ) -> Option<AssetDefinitionEntry> {
        let asset_definition = AssetDefinitionEntry::new(asset_definition.into(), registered_by);

        self.asset_definitions
            .insert(asset_definition.definition().id().clone(), asset_definition)
    }

    /// Remove asset definition from the [`Domain`] and return it
    #[inline]
    pub fn remove_asset_definition(
        &mut self,
        asset_definition_id: &<AssetDefinition as Identifiable>::Id,
    ) -> Option<AssetDefinitionEntry> {
        self.asset_definitions.remove(asset_definition_id)
    }
}

impl From<<Self as Identifiable>::Constructor> for Domain {
    fn from(source: <Self as Identifiable>::Constructor) -> Self {
        Self {
            id: source.id,
            accounts: AccountsMap::default(),
            asset_definitions: AssetDefinitionsMap::default(),
            metadata: source.metadata,
            logo: source.logo,
        }
    }
}

impl FromIterator<Domain> for crate::Value {
    fn from_iter<T: IntoIterator<Item = Domain>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// Represents path in IPFS. Performs some checks to ensure path validity.
///
/// Should be constructed with `from_str()` method.
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
pub struct IpfsPath(String);

impl FromStr for IpfsPath {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let mut subpath = string.split('/');
        let path_segment = subpath.next().ok_or(ParseError {
            reason: "Impossible error: first value of str::split() always has value",
        })?;

        if path_segment.is_empty() {
            let root_type = subpath.next().ok_or(ParseError {
                reason: "Expected root type, but nothing found",
            })?;
            let key = subpath.next().ok_or(ParseError {
                reason: "Expected at least one content id",
            })?;

            match root_type {
                "ipfs" | "ipld" => Self::check_cid(key)?,
                "ipns" => (),
                _ => {
                    return Err(ParseError {
                        reason: "Unexpected root type. Expected `ipfs`, `ipld` or `ipns`",
                    })
                }
            }
        } else {
            // by default if there is no prefix it's an ipfs or ipld path
            Self::check_cid(path_segment)?;
        }

        for path in subpath {
            Self::check_cid(path)?;
        }

        Ok(IpfsPath(String::from(string)))
    }
}

impl AsRef<str> for IpfsPath {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl IpfsPath {
    /// Superficially checks IPFS `cid` (Content Identifier)
    #[inline]
    const fn check_cid(cid: &str) -> Result<(), ParseError> {
        if cid.len() < 2 {
            return Err(ParseError {
                reason: "IPFS cid is too short",
            });
        }

        Ok(())
    }
}

/// Identification of a [`Domain`].
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
    /// [`Name`] unique to a [`Domain`] e.g. company name
    pub name: Name,
}

impl Id {
    /// Construct [`Id`] if the given domain `name` is valid.
    ///
    /// # Errors
    /// Fails if any sub-construction fails
    #[inline]
    pub fn new(name: &str) -> Result<Self, ParseError> {
        Ok(Self {
            name: Name::from_str(name)?,
        })
    }
}

impl FromStr for Id {
    type Err = ParseError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::new(name)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Domain, GenesisDomain, Id as DomainId, GENESIS_DOMAIN_NAME};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_ipfs_path() {
        assert!(matches!(
            IpfsPath::from_str(""),
            Err(err) if err.to_string() == "Expected root type, but nothing found"
        ));
        assert!(matches!(
            IpfsPath::from_str("/ipld"),
            Err(err) if err.to_string() == "Expected at least one content id"
        ));
        assert!(matches!(
            IpfsPath::from_str("/ipfs/a"),
            Err(err) if err.to_string() == "IPFS cid is too short"
        ));
        assert!(matches!(
            IpfsPath::from_str("/ipfsssss/QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE"),
            Err(err) if err.to_string() == "Unexpected root type. Expected `ipfs`, `ipld` or `ipns`"
        ));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_valid_ipfs_path() {
        // Valid paths
        IpfsPath::from_str("QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE")
            .expect("Path without root should be valid");
        IpfsPath::from_str("/ipfs/QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE")
            .expect("Path with ipfs root should be valid");
        IpfsPath::from_str("/ipld/QmQqzMTavQgT4f4T5v6PWBp7XNKtoPmC9jvn12WPT3gkSE")
            .expect("Path with ipld root should be valid");
        IpfsPath::from_str("/ipns/QmSrPmbaUKA3ZodhzPWZnpFgcPMFWF4QsxXbkWfEptTBJd")
            .expect("Path with ipns root should be valid");
        IpfsPath::from_str("/ipfs/SomeFolder/SomeImage")
            .expect("Path with folders should be valid");
    }
}
