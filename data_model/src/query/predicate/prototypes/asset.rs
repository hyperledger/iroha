use std::marker::PhantomData;

use super::{impl_prototype, MetadataPrototype, StringPrototype};
use crate::{
    asset::{AssetDefinitionId, AssetId},
    query::{
        predicate::{
            predicate_atoms::asset::{
                AssetDefinitionIdPredicateBox, AssetDefinitionPredicateBox, AssetIdPredicateBox,
                AssetPredicateBox, AssetValuePredicateBox,
            },
            projectors::{
                AssetDefinitionIdDomainIdProjector, AssetDefinitionIdNameProjector,
                AssetDefinitionIdProjector, AssetDefinitionMetadataProjector,
                AssetIdAccountIdProjector, AssetIdDefinitionIdProjector, AssetIdProjector,
                AssetValueProjector,
            },
            prototypes::{account::AccountIdPrototype, domain::DomainIdPrototype, ObjectProjector},
        },
        AstPredicate, HasPrototype,
    },
};

#[derive(Default, Copy, Clone)]
pub struct AssetDefinitionIdPrototype<Projector> {
    pub domain_id: DomainIdPrototype<AssetDefinitionIdDomainIdProjector<Projector>>,
    pub name: StringPrototype<AssetDefinitionIdNameProjector<Projector>>,
}

impl_prototype!(AssetDefinitionIdPrototype: AssetDefinitionIdPredicateBox);

impl<Projector> AssetDefinitionIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = AssetDefinitionIdPredicateBox>,
{
    pub fn eq(
        &self,
        expected: AssetDefinitionId,
    ) -> Projector::ProjectedPredicate<AssetDefinitionIdPredicateBox> {
        Projector::project_predicate(AssetDefinitionIdPredicateBox::Equals(expected))
    }
}

#[derive(Default, Copy, Clone)]
pub struct AssetIdPrototype<Projector> {
    pub definition_id: AssetDefinitionIdPrototype<AssetIdDefinitionIdProjector<Projector>>,
    pub account: AccountIdPrototype<AssetIdAccountIdProjector<Projector>>,
}

impl_prototype!(AssetIdPrototype: AssetIdPredicateBox);

impl<Projector> AssetIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = AssetIdPredicateBox>,
{
    pub fn eq(&self, expected: AssetId) -> Projector::ProjectedPredicate<AssetIdPredicateBox> {
        Projector::project_predicate(AssetIdPredicateBox::Equals(expected))
    }
}

#[derive(Default, Copy, Clone)]
pub struct AssetDefinitionPrototype<Projector> {
    pub id: AssetDefinitionIdPrototype<AssetDefinitionIdProjector<Projector>>,
    pub metadata: MetadataPrototype<AssetDefinitionMetadataProjector<Projector>>,
}

impl_prototype!(AssetDefinitionPrototype: AssetDefinitionPredicateBox);

#[derive(Default, Copy, Clone)]
pub struct AssetPrototype<Projector> {
    pub id: AssetIdPrototype<AssetIdProjector<Projector>>,
    pub value: AssetValuePrototype<AssetValueProjector<Projector>>,
}

impl_prototype!(AssetPrototype: AssetPredicateBox);

#[derive(Default, Copy, Clone)]
pub struct AssetValuePrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(AssetValuePrototype: AssetValuePredicateBox);
