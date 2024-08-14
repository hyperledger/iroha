//! Account-related prototypes, mirroring types in [`crate::role`].

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

/// A prototype of [`RoleId`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct RoleIdPrototype<Projector> {
    /// Build a predicate on name of this [`RoleId`].
    pub name: StringPrototype<RoleIdNameProjector<Projector>>,
}

impl_prototype!(RoleIdPrototype: RoleIdPredicateBox);

impl<Projector> RoleIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = RoleIdPredicateBox>,
{
    /// Creates a predicate that checks if the role ID is equal to the expected value.
    pub fn eq(&self, expected: RoleId) -> Projector::ProjectedPredicate<RoleIdPredicateBox> {
        Projector::project_predicate(RoleIdPredicateBox::Equals(expected))
    }
}

/// A prototype of [`crate::role::Role`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct RolePrototype<Projector> {
    /// Build a predicate on ID of this [`crate::role::Role`].
    pub id: RoleIdPrototype<RoleIdProjector<Projector>>,
}

impl_prototype!(RolePrototype: RolePredicateBox);
