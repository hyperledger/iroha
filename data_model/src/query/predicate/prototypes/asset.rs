//! Account-related prototypes, mirroring types in [`crate::asset`].

use core::marker::PhantomData;

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

/// A prototype of [`AssetDefinitionId`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AssetDefinitionIdPrototype<Projector> {
    /// Build a predicate on domain ID of this [`AssetDefinitionId`]
    pub domain_id: DomainIdPrototype<AssetDefinitionIdDomainIdProjector<Projector>>,
    /// Build a predicate on name of this [`AssetDefinitionId`]
    pub name: StringPrototype<AssetDefinitionIdNameProjector<Projector>>,
}

impl_prototype!(AssetDefinitionIdPrototype: AssetDefinitionIdPredicateBox);

impl<Projector> AssetDefinitionIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = AssetDefinitionIdPredicateBox>,
{
    /// Creates a predicate that checks if the asset definition ID equals the expected value.
    pub fn eq(
        &self,
        expected: AssetDefinitionId,
    ) -> Projector::ProjectedPredicate<AssetDefinitionIdPredicateBox> {
        Projector::project_predicate(AssetDefinitionIdPredicateBox::Equals(expected))
    }
}

/// A prototype of [`AssetId`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AssetIdPrototype<Projector> {
    /// Build a predicate on definition ID of this [`AssetId`]
    pub definition_id: AssetDefinitionIdPrototype<AssetIdDefinitionIdProjector<Projector>>,
    /// Build a predicate on account ID of this [`AssetId`]
    pub account: AccountIdPrototype<AssetIdAccountIdProjector<Projector>>,
}

impl_prototype!(AssetIdPrototype: AssetIdPredicateBox);

impl<Projector> AssetIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = AssetIdPredicateBox>,
{
    /// Creates a predicate that checks if the asset ID equals the expected value.
    pub fn eq(&self, expected: AssetId) -> Projector::ProjectedPredicate<AssetIdPredicateBox> {
        Projector::project_predicate(AssetIdPredicateBox::Equals(expected))
    }
}

/// A prototype of [`crate::asset::AssetDefinition`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AssetDefinitionPrototype<Projector> {
    /// Build a predicate on ID of this [`crate::asset::AssetDefinition`]
    pub id: AssetDefinitionIdPrototype<AssetDefinitionIdProjector<Projector>>,
    /// Build a predicate on metadata of this [`crate::asset::AssetDefinition`]
    pub metadata: MetadataPrototype<AssetDefinitionMetadataProjector<Projector>>,
}

impl_prototype!(AssetDefinitionPrototype: AssetDefinitionPredicateBox);

/// A prototype of [`crate::asset::Asset`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AssetPrototype<Projector> {
    /// Build a predicate on ID of this [`crate::asset::Asset`]
    pub id: AssetIdPrototype<AssetIdProjector<Projector>>,
    /// Build a predicate on value of this [`crate::asset::Asset`]
    pub value: AssetValuePrototype<AssetValueProjector<Projector>>,
}

impl_prototype!(AssetPrototype: AssetPredicateBox);

/// A prototype of [`crate::asset::AssetValue`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct AssetValuePrototype<Projector> {
    phantom: PhantomData<Projector>,
}

impl_prototype!(AssetValuePrototype: AssetValuePredicateBox);
