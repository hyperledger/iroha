//! Structures, traits and impls related to `Account`s.
#[cfg(not(feature = "std"))]
use alloc::{
    collections::{btree_map, btree_set},
    format,
    string::String,
    vec::Vec,
};
use core::str::FromStr;
#[cfg(feature = "std")]
use std::collections::{btree_map, btree_set};

use derive_more::{Constructor, DebugCustom, Display};
use getset::Getters;
use iroha_data_model_derive::{model, IdEqOrdHash};
use iroha_primitives::{const_vec::ConstVec, must_use::MustUse};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};

pub use self::model::*;
use crate::{
    asset::{
        prelude::{Asset, AssetId},
        AssetsMap,
    },
    domain::prelude::*,
    metadata::Metadata,
    name::Name,
    HasMetadata, Identifiable, ParseError, PublicKey, Registered,
};

/// API to work with collections of [`Id`] : [`Account`] mappings.
pub type AccountsMap = btree_map::BTreeMap<AccountId, Account>;

type Signatories = btree_set::BTreeSet<PublicKey>;

#[model]
pub mod model {
    use super::*;

    /// Identification of an [`Account`]. Consists of Account name and Domain name.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use iroha_data_model::account::AccountId;
    ///
    /// let id = "user@company".parse::<AccountId>().expect("Valid");
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
    #[display(fmt = "{name}@{domain_id}")]
    #[debug(fmt = "{name}@{domain_id}")]
    #[getset(get = "pub")]
    #[ffi_type]
    pub struct AccountId {
        /// [`Account`]'s [`Domain`](`crate::domain::Domain`) id.
        pub domain_id: DomainId,
        /// [`Account`]'s name.
        pub name: Name,
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
        /// An Identification of the [`Account`].
        pub id: AccountId,
        /// Assets in this [`Account`].
        pub assets: AssetsMap,
        /// [`Account`]'s signatories.
        pub signatories: Signatories,
        /// Condition which checks if the account has the right signatures.
        #[getset(get = "pub")]
        pub signature_check_condition: SignatureCheckCondition,
        /// Metadata of this account as a key-value store.
        pub metadata: Metadata,
    }

    /// Builder which should be submitted in a transaction to create a new [`Account`]
    #[derive(
        DebugCustom, Display, Clone, IdEqOrdHash, Decode, Encode, Serialize, Deserialize, IntoSchema,
    )]
    #[display(fmt = "[{id}]")]
    #[debug(fmt = "[{id:?}] {{ signatories: {signatories:?}, metadata: {metadata} }}")]
    #[ffi_type]
    pub struct NewAccount {
        /// Identification
        pub id: AccountId,
        /// Signatories, i.e. signatures attached to this message.
        pub signatories: Signatories,
        /// Metadata that should be submitted with the builder
        pub metadata: Metadata,
    }

    /// Condition which checks if the account has the right signatures.
    #[derive(
        Debug,
        Display,
        Clone,
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
    #[ffi_type(opaque)]
    #[allow(clippy::enum_variant_names)]
    pub enum SignatureCheckCondition {
        #[display(fmt = "AnyAccountSignatureOr({_0:?})")]
        AnyAccountSignatureOr(ConstVec<PublicKey>),
        #[display(fmt = "AllAccountSignaturesAnd({_0:?})")]
        AllAccountSignaturesAnd(ConstVec<PublicKey>),
    }
}

impl Account {
    /// Construct builder for [`Account`] identifiable by [`Id`] containing the given signatories.
    #[inline]
    #[must_use]
    pub fn new(
        id: AccountId,
        signatories: impl IntoIterator<Item = PublicKey>,
    ) -> <Self as Registered>::With {
        <Self as Registered>::With::new(id, signatories)
    }

    /// Get an iterator over [`signatories`](PublicKey) of the `Account`
    #[inline]
    pub fn signatories(&self) -> impl ExactSizeIterator<Item = &PublicKey> {
        self.signatories.iter()
    }

    /// Return a reference to the [`Asset`] corresponding to the asset id.
    #[inline]
    pub fn asset(&self, asset_id: &AssetId) -> Option<&Asset> {
        self.assets.get(asset_id)
    }

    /// Get an iterator over [`Asset`]s of the `Account`
    #[inline]
    pub fn assets(&self) -> impl ExactSizeIterator<Item = &Asset> {
        self.assets.values()
    }

    /// Return `true` if the `Account` contains the given signatory
    #[inline]
    pub fn contains_signatory(&self, signatory: &PublicKey) -> bool {
        self.signatories.contains(signatory)
    }
}

#[cfg(feature = "transparent_api")]
impl Account {
    /// Add [`Asset`] into the [`Account`] returning previous asset stored under the same id
    #[inline]
    pub fn add_asset(&mut self, asset: Asset) -> Option<Asset> {
        self.assets.insert(asset.id().clone(), asset)
    }

    /// Remove asset from the [`Account`] and return it
    #[inline]
    pub fn remove_asset(&mut self, asset_id: &AssetId) -> Option<Asset> {
        self.assets.remove(asset_id)
    }
    /// Add [`signatory`](PublicKey) into the [`Account`].
    ///
    /// If `Account` did not have this signatory present, `true` is returned.
    /// If `Account` did have this signatory present, `false` is returned.
    #[inline]
    pub fn add_signatory(&mut self, signatory: PublicKey) -> bool {
        self.signatories.insert(signatory)
    }

    /// Remove a signatory from the `Account` and return whether the signatory was present in the `Account`
    #[inline]
    pub fn remove_signatory(&mut self, signatory: &PublicKey) -> bool {
        self.signatories.remove(signatory)
    }
}

impl NewAccount {
    fn new(id: AccountId, signatories: impl IntoIterator<Item = PublicKey>) -> Self {
        Self {
            id,
            signatories: signatories.into_iter().collect(),
            metadata: Metadata::default(),
        }
    }

    /// Add [`Metadata`] to the account replacing any previously defined metadata
    #[must_use]
    pub fn with_metadata(mut self, metadata: Metadata) -> Self {
        self.metadata = metadata;
        self
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

#[cfg(feature = "transparent_api")]
impl FromIterator<Account> for crate::Value {
    fn from_iter<T: IntoIterator<Item = Account>>(iter: T) -> Self {
        iter.into_iter()
            .map(Into::into)
            .collect::<Vec<Self>>()
            .into()
    }
}

/// Account Identification is represented by `name@domain_name` string.
impl FromStr for AccountId {
    type Err = ParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        let split = string.rsplit_once('@');
        match split {
            Some(("", _)) => Err(ParseError {
                reason: "`AccountId` cannot be empty",
            }),
            Some((name, domain_id)) if !name.is_empty() && !domain_id.is_empty() => Ok(AccountId {
                name: name.parse()?,
                domain_id: domain_id.parse()?,
            }),
            _ => Err(ParseError {
                reason: "`AccountId` should have format `name@domain_name`",
            }),
        }
    }
}

impl Default for SignatureCheckCondition {
    fn default() -> Self {
        Self::AnyAccountSignatureOr(ConstVec::new_empty())
    }
}

impl SignatureCheckCondition {
    /// Shorthand to create a [`SignatureCheckCondition::AnyAccountSignatureOr`] variant without additional allowed signatures.
    #[inline]
    pub fn any_account_signature() -> Self {
        Self::AnyAccountSignatureOr(ConstVec::new_empty())
    }

    /// Shorthand to create a [`SignatureCheckCondition::AllAccountSignaturesAnd`] variant without additional required signatures.
    #[inline]
    pub fn all_account_signatures() -> Self {
        Self::AllAccountSignaturesAnd(ConstVec::new_empty())
    }

    /// Checks whether the transaction contains all the signatures required by the `SignatureCheckCondition`.
    pub fn check(
        &self,
        account_signatories: &btree_set::BTreeSet<PublicKey>,
        transaction_signatories: &btree_set::BTreeSet<PublicKey>,
    ) -> MustUse<bool> {
        let result = match &self {
            SignatureCheckCondition::AnyAccountSignatureOr(additional_allowed_signatures) => {
                account_signatories
                    .iter()
                    .chain(additional_allowed_signatures.as_ref())
                    .any(|allowed| transaction_signatories.contains(allowed))
            }
            SignatureCheckCondition::AllAccountSignaturesAnd(additional_required_signatures) => {
                account_signatories
                    .iter()
                    .chain(additional_required_signatures.as_ref())
                    .all(|required_signature| transaction_signatories.contains(required_signature))
            }
        };

        MustUse::new(result)
    }
}

/// The prelude re-exports most commonly used traits, structs and macros from this crate.
pub mod prelude {
    pub use super::{Account, AccountId, SignatureCheckCondition};
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use iroha_crypto::{KeyPair, PublicKey};

    use super::{AccountId, SignatureCheckCondition};
    use crate::{domain::DomainId, name::Name};

    fn make_key() -> PublicKey {
        KeyPair::generate().unwrap().public_key().clone()
    }

    fn check_signature_check_condition(
        condition: &SignatureCheckCondition,
        account_signatories: &[&PublicKey],
        tx_signatories: &[&PublicKey],
        result: bool,
    ) {
        let account_signatories = account_signatories.iter().copied().cloned().collect();
        let tx_signatories = tx_signatories.iter().copied().cloned().collect();

        assert_eq!(
            condition.check(&account_signatories, &tx_signatories,).0,
            result
        );
    }

    #[test]
    fn signature_check_condition_default() {
        let key1 = make_key();
        let key2 = make_key();
        let key3 = make_key();
        let condition = SignatureCheckCondition::default();

        check_signature_check_condition(&condition, &[], &[], false);
        check_signature_check_condition(&condition, &[&key1], &[], false);
        check_signature_check_condition(&condition, &[], &[&key1], false);
        check_signature_check_condition(&condition, &[&key1], &[&key1], true);
        check_signature_check_condition(&condition, &[&key1], &[&key2], false);
        check_signature_check_condition(&condition, &[&key1, &key2, &key3], &[&key1], true);
        check_signature_check_condition(&condition, &[&key1, &key2, &key3], &[&key2], true);
        check_signature_check_condition(&condition, &[&key1, &key2, &key3], &[&key3], true);
    }

    #[test]
    fn signature_check_condition_all() {
        let key1 = make_key();
        let key2 = make_key();
        let key3 = make_key();
        let condition = SignatureCheckCondition::all_account_signatures();

        // technically, `\forall x \in \emptyset, check(x)` is true for any `check`, so this evaluate to true
        // maybe not the logic we want?
        check_signature_check_condition(&condition, &[], &[], true);
        check_signature_check_condition(&condition, &[], &[&key1], true);

        check_signature_check_condition(&condition, &[&key1], &[], false);
        check_signature_check_condition(&condition, &[&key1], &[&key1], true);
        check_signature_check_condition(&condition, &[&key1], &[&key2], false);
        check_signature_check_condition(&condition, &[&key1, &key2, &key3], &[&key1], false);
        check_signature_check_condition(&condition, &[&key1, &key2, &key3], &[&key2], false);
        check_signature_check_condition(&condition, &[&key1, &key2, &key3], &[&key3], false);
        check_signature_check_condition(&condition, &[&key1, &key2], &[&key1, &key2, &key3], true);
        check_signature_check_condition(&condition, &[&key1, &key2], &[&key1, &key2], true);
        check_signature_check_condition(&condition, &[&key1, &key2], &[&key2, &key3], false);
    }

    #[test]
    fn signature_check_condition_any_or() {
        let key1 = make_key();
        let key2 = make_key();
        let key3 = make_key();
        let condition = SignatureCheckCondition::AnyAccountSignatureOr(vec![key3.clone()].into());

        check_signature_check_condition(&condition, &[], &[], false);
        check_signature_check_condition(&condition, &[], &[&key3], true);
        check_signature_check_condition(&condition, &[], &[&key2], false);
        check_signature_check_condition(&condition, &[], &[&key1, &key2], false);
        check_signature_check_condition(&condition, &[&key2], &[&key2], true);
        check_signature_check_condition(&condition, &[&key2, &key3], &[&key2], true);
        check_signature_check_condition(&condition, &[&key1, &key2], &[&key2], true);
    }

    #[test]
    fn signature_check_condition_all_and() {
        let key1 = make_key();
        let key2 = make_key();
        let key3 = make_key();
        let condition = SignatureCheckCondition::AllAccountSignaturesAnd(vec![key3.clone()].into());

        check_signature_check_condition(&condition, &[], &[], false);
        check_signature_check_condition(&condition, &[], &[&key3], true);
        check_signature_check_condition(&condition, &[&key1], &[&key3], false);
        check_signature_check_condition(&condition, &[&key1], &[&key1, &key3], true);
        check_signature_check_condition(&condition, &[&key2], &[&key1, &key3], false);
        check_signature_check_condition(&condition, &[&key2], &[&key1, &key2, &key3], true);
    }

    #[test]
    fn cmp_account_id() {
        let domain_id_a: DomainId = "a".parse().expect("failed to parse DomainId");
        let domain_id_b: DomainId = "b".parse().expect("failed to parse DomainId");
        let name_a: Name = "a".parse().expect("failed to parse Name");
        let name_b: Name = "b".parse().expect("failed to parse Name");

        let mut account_ids = Vec::new();
        for name in [&name_a, &name_b] {
            for domain_id in [&domain_id_a, &domain_id_b] {
                account_ids.push(AccountId::new(domain_id.clone(), name.clone()));
            }
        }

        for account_id_1 in &account_ids {
            for account_id_2 in &account_ids {
                match (
                    account_id_1.domain_id.cmp(&account_id_2.domain_id),
                    account_id_1.name.cmp(&account_id_2.name),
                ) {
                    // `DomainId` take precedence in comparison
                    // if `DomainId`s are equal than comparison based on `Name`s
                    (Ordering::Equal, ordering) | (ordering, _) => assert_eq!(
                        account_id_1.cmp(account_id_2),
                        ordering,
                        "{account_id_1:?} and {account_id_2:?} are expected to be {ordering:?}"
                    ),
                }
            }
        }
    }
}
