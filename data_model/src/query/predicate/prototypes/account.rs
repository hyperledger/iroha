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

#[derive(Default, Copy, Clone)]
pub struct AccountIdPrototype<Projector> {
    pub domain_id: DomainIdPrototype<AccountIdDomainIdProjector<Projector>>,
    pub signatory: PublicKeyPrototype<AccountIdSignatoryProjector<Projector>>,
}

impl_prototype!(AccountIdPrototype: AccountIdPredicateBox);

impl<Projector> AccountIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = AccountIdPredicateBox>,
{
    pub fn eq(&self, expected: AccountId) -> Projector::ProjectedPredicate<AccountIdPredicateBox> {
        Projector::project_predicate(AccountIdPredicateBox::Equals(expected))
    }
}

#[derive(Default, Copy, Clone)]
pub struct AccountPrototype<Projector> {
    pub id: AccountIdPrototype<AccountIdProjector<Projector>>,
    pub metadata: MetadataPrototype<AccountMetadataProjector<Projector>>,
}

impl_prototype!(AccountPrototype: AccountPredicateBox);
