use core::marker::PhantomData;

use super::impl_prototype;
use crate::query::{
    predicate::{predicate_atoms::permission::PermissionPredicateBox, projectors::ObjectProjector},
    AstPredicate, HasPrototype,
};

#[derive(Default, Copy, Clone)]
pub struct PermissionPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(PermissionPrototype: PermissionPredicateBox);
