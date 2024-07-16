//! Account-related prototypes, mirroring types in [`crate::trigger`].

use super::impl_prototype;
use crate::{
    prelude::TriggerId,
    query::predicate::{
        predicate_atoms::trigger::{TriggerIdPredicateBox, TriggerPredicateBox},
        projectors::{ObjectProjector, TriggerIdProjector},
        prototypes::StringPrototype,
        AstPredicate, HasPrototype,
    },
};

/// A prototype of [`TriggerId`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct TriggerIdPrototype<Projector> {
    /// Build a predicate on name of this [`TriggerId`]
    pub name: StringPrototype<TriggerIdProjector<Projector>>,
}

impl_prototype!(TriggerIdPrototype: TriggerIdPredicateBox);

impl<Projector> TriggerIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = TriggerIdPredicateBox>,
{
    /// Creates a predicate that checks if the trigger ID is equal to the expected value.
    pub fn eq(&self, expected: TriggerId) -> Projector::ProjectedPredicate<TriggerIdPredicateBox> {
        Projector::project_predicate(TriggerIdPredicateBox::Equals(expected))
    }
}

/// A prototype of [`crate::trigger::Trigger`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct TriggerPrototype<Projector> {
    /// Build a predicate on ID of this [`crate::trigger::Trigger`]
    pub id: TriggerIdPrototype<TriggerIdProjector<Projector>>,
}

impl_prototype!(TriggerPrototype: TriggerPredicateBox);
