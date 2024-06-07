use std::marker::PhantomData;

use super::impl_prototype;
use crate::{
    account::AccountId,
    asset::AssetDefinitionId,
    query::{
        predicate::{
            predicate_atoms::account::{
                AccountIdPredicateBox, AccountPredicateBox, AssetsMapPredicateBox,
            },
            projectors::{
                AccountAssetsProjector, AccountIdDomainIdProjector, AccountIdProjector,
                AccountIdSignatoryProjector, AccountMetadataProjector, ObjectProjector,
            },
            prototypes::{domain::DomainIdPrototype, MetadataPrototype, PublicKeyPrototype},
        },
        AstPredicate, HasPrototype,
    },
};

#[derive(Default, Copy, Clone)]
pub struct AssetsMapPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(AssetsMapPrototype: AssetsMapPredicateBox);

impl<Projector> AssetsMapPrototype<Projector>
where
    Projector: ObjectProjector<Input = AssetsMapPredicateBox>,
{
    pub fn has(
        &self,
        asset_id: AssetDefinitionId,
    ) -> Projector::ProjectedPredicate<AssetsMapPredicateBox> {
        Projector::project_predicate(AssetsMapPredicateBox::Has(asset_id))
    }
}

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
    pub assets: AssetsMapPrototype<AccountAssetsProjector<Projector>>,
}

impl_prototype!(AccountPrototype: AccountPredicateBox);
