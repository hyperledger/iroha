//! Account-related prototypes, mirroring types in [`crate::domain`].

use super::{impl_prototype, MetadataPrototype, StringPrototype};
use crate::{
    domain::DomainId,
    query::predicate::{
        predicate_atoms::domain::{DomainIdPredicateBox, DomainPredicateBox},
        projectors::{
            DomainIdNameProjector, DomainIdProjector, DomainMetadataProjector, ObjectProjector,
        },
        AstPredicate, HasPrototype,
    },
};

/// A prototype of [`DomainId`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct DomainIdPrototype<Projector> {
    /// Build a predicate on name of this [`DomainId`]
    pub name: StringPrototype<DomainIdNameProjector<Projector>>,
}

impl_prototype!(DomainIdPrototype: DomainIdPredicateBox);

impl<Projector> DomainIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = DomainIdPredicateBox>,
{
    /// Creates a predicate that checks if the domain ID is equal to the expected value.
    pub fn eq(&self, expected: DomainId) -> Projector::ProjectedPredicate<DomainIdPredicateBox> {
        Projector::project_predicate(DomainIdPredicateBox::Equals(expected))
    }
}

/// A prototype of [`crate::domain::Domain`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct DomainPrototype<Projector> {
    /// Build a predicate on ID of this [`crate::domain::Domain`]
    pub id: DomainIdPrototype<DomainIdProjector<Projector>>,
    /// Build a predicate on metadata of this [`crate::domain::Domain`]
    pub metadata: MetadataPrototype<DomainMetadataProjector<Projector>>,
}

impl_prototype!(DomainPrototype: DomainPredicateBox);
