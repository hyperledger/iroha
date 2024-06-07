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

#[derive(Default, Copy, Clone)]
pub struct TriggerIdPrototype<Projector> {
    pub name: StringPrototype<TriggerIdProjector<Projector>>,
}

impl_prototype!(TriggerIdPrototype: TriggerIdPredicateBox);

impl<Projector> TriggerIdPrototype<Projector>
where
    Projector: ObjectProjector<Input = TriggerIdPredicateBox>,
{
    pub fn eq(&self, expected: TriggerId) -> Projector::ProjectedPredicate<TriggerIdPredicateBox> {
        Projector::project_predicate(TriggerIdPredicateBox::Equals(expected))
    }
}

#[derive(Default, Copy, Clone)]
pub struct TriggerPrototype<Projector> {
    pub id: TriggerIdPrototype<TriggerIdProjector<Projector>>,
}

impl_prototype!(TriggerPrototype: TriggerPredicateBox);
