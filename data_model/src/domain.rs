//! This module contains [`Domain`](`crate::domain::Domain`) structure and related implementations and trait implementations.

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, collections::btree_map, format, string::String, vec::Vec};
use core::{cmp::Ordering, fmt, str::FromStr};
#[cfg(feature = "std")]
use std::collections::btree_map;

use iroha_crypto::PublicKey;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::{
    account::{Account, AccountsMap, GenesisAccount},
    asset::AssetDefinitionsMap,
    metadata::Metadata,
    Identifiable, Name, ParseError, Value,
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
    pub const fn new(genesis_key: PublicKey) -> Self {
        Self { genesis_key }
    }
}

impl From<GenesisDomain> for Domain {
    fn from(domain: GenesisDomain) -> Self {
        Self {
            id: Id::test(GENESIS_DOMAIN_NAME),
            accounts: core::iter::once((
                <Account as Identifiable>::Id::genesis(),
                GenesisAccount::new(domain.genesis_key).into(),
            ))
            .collect(),
            asset_definitions: btree_map::BTreeMap::default(),
            metadata: Metadata::new(),
            logo: None,
        }
    }
}

/// Named group of [`Account`] and [`Asset`](`crate::asset::Asset`) entities.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub struct Domain {
    /// Identification of this [`Domain`].
    pub id: <Self as Identifiable>::Id,
    /// Accounts of the domain.
    pub accounts: AccountsMap,
    /// Assets of the domain.
    pub asset_definitions: AssetDefinitionsMap,
    /// Metadata of this domain as a key-value store.
    pub metadata: Metadata,
    /// IPFS link to domain logo
    pub logo: Option<IpfsPath>,
}

impl PartialOrd for Domain {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.id.cmp(&other.id))
    }
}

impl Ord for Domain {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl Domain {
    /// Construct [`Domain`] from [`Id`].
    pub fn new(id: Id) -> Self {
        Self {
            id,
            accounts: AccountsMap::new(),
            asset_definitions: AssetDefinitionsMap::new(),
            metadata: Metadata::new(),
            logo: None,
        }
    }

    /// Instantly construct [`Domain`] assuming `name` is valid.
    pub fn test(name: &str) -> Self {
        Self {
            id: Id::test(name),
            accounts: AccountsMap::new(),
            asset_definitions: AssetDefinitionsMap::new(),
            metadata: Metadata::new(),
            logo: None,
        }
    }

    /// Domain constructor with pre-setup accounts. Useful for testing purposes.
    pub fn with_accounts(name: &str, accounts: impl IntoIterator<Item = Account>) -> Self {
        let accounts_map = accounts
            .into_iter()
            .map(|account| (account.id.clone(), account))
            .collect();
        Self {
            id: Id::test(name),
            accounts: accounts_map,
            asset_definitions: AssetDefinitionsMap::new(),
            metadata: Metadata::new(),
            logo: None,
        }
    }
}

impl Identifiable for Domain {
    type Id = Id;
}

impl FromIterator<Domain> for Value {
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

        Ok(IpfsPath(string.to_owned()))
    }
}

impl AsRef<str> for IpfsPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl IpfsPath {
    /// Instantly construct [`IpfsPath`] assuming the given `path` is valid.
    #[inline]
    pub fn test(path: String) -> Self {
        Self(path)
    }

    /// Superficially checks IPFS `cid` (Content Identifier)
    #[inline]
    fn check_cid(cid: &str) -> Result<(), ParseError> {
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
            name: Name::new(name)?,
        })
    }

    /// Instantly construct [`Id`] assuming the given domain `name` is valid.
    #[inline]
    pub fn test(name: &str) -> Self {
        Self {
            name: Name::test(name),
        }
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
