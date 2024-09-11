//! Account-related prototypes, mirroring types in [`crate::account`].

use super::impl_prototype;
use crate::{
    account::AccountId,
    query::{
        predicate::{
            predicate_atoms::account::{AccountIdPredicateBox, AccountPredicateBox},
            projectors::{
                AccountIdDomainIdProjector, AccountIdProjector, AccountIdSignatoryProjector,
                AccountMetadataProjector, ObjectProjector,
            },
            prototypes::{domain::DomainIdPrototype, MetadataPrototype, PublicKeyPrototype},
        },
        AstPredicate, HasPrototype,
    },
};

/// A prototype of [`AccountId`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AccountIdPrototype<Projector> {
    /// Build a predicate on domain ID of this [`AccountId`]
    pub domain_id: DomainIdPrototype<AccountIdDomainIdProjector<Projector>>,
    /// Build a predicate on signatory of this [`AccountId`]
    pub signatory: PublicKeyPrototype<AccountIdSignatoryProjector<Projector>>,
}

impl_prototype!(AccountIdPrototype: AccountIdPredicateBox);

impl<Projector> AccountIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = AccountIdPredicateBox>,
{
    /// Creates a predicate that checks if the account ID equals the expected value.
    pub fn eq(&self, expected: AccountId) -> Projector::ProjectedPredicate<AccountIdPredicateBox> {
        Projector::project_predicate(AccountIdPredicateBox::Equals(expected))
    }
}

/// A prototype of [`crate::account::Account`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AccountPrototype<Projector> {
    /// Build a predicate on ID of this [`crate::account::Account`]
    pub id: AccountIdPrototype<AccountIdProjector<Projector>>,
    /// Build a predicate on metadata of this [`crate::account::Account`]
    pub metadata: MetadataPrototype<AccountMetadataProjector<Projector>>,
}

impl_prototype!(AccountPrototype: AccountPredicateBox);
