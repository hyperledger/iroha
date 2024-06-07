use super::impl_prototype;
use crate::{
    query::predicate::{
        predicate_atoms::role::{RoleIdPredicateBox, RolePredicateBox},
        projectors::{ObjectProjector, RoleIdNameProjector, RoleIdProjector},
        prototypes::StringPrototype,
        AstPredicate, HasPrototype,
    },
    role::RoleId,
};

#[derive(Default, Copy, Clone)]
pub struct RoleIdPrototype<Projector> {
    pub name: StringPrototype<RoleIdNameProjector<Projector>>,
}

impl_prototype!(RoleIdPrototype: RoleIdPredicateBox);

impl<Projector> RoleIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = RoleIdPredicateBox>,
{
    pub fn eq(&self, expected: RoleId) -> Projector::ProjectedPredicate<RoleIdPredicateBox> {
        Projector::project_predicate(RoleIdPredicateBox::Equals(expected))
    }
}

#[derive(Default, Copy, Clone)]
pub struct RolePrototype<Projector> {
    pub id: RoleIdPrototype<RoleIdProjector<Projector>>,
}

impl_prototype!(RolePrototype: RolePredicateBox);
