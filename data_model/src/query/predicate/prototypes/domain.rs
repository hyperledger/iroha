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

#[derive(Default, Copy, Clone)]
pub struct DomainIdPrototype<Projector> {
    pub name: StringPrototype<DomainIdNameProjector<Projector>>,
}

impl_prototype!(DomainIdPrototype: DomainIdPredicateBox);

impl<Projector> DomainIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = DomainIdPredicateBox>,
{
    pub fn eq(&self, expected: DomainId) -> Projector::ProjectedPredicate<DomainIdPredicateBox> {
        Projector::project_predicate(DomainIdPredicateBox::Equals(expected))
    }
}

#[derive(Default, Copy, Clone)]
pub struct DomainPrototype<Projector> {
    pub id: DomainIdPrototype<DomainIdProjector<Projector>>,
    pub metadata: MetadataPrototype<DomainMetadataProjector<Projector>>,
}

impl_prototype!(DomainPrototype: DomainPredicateBox);
