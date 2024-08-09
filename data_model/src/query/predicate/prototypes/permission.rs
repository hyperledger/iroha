//! Account-related prototypes, mirroring types in [`crate::permission`].

use core::marker::PhantomData;

use super::impl_prototype;
use crate::query::{
    predicate::{predicate_atoms::permission::PermissionPredicateBox, projectors::ObjectProjector},
    AstPredicate, HasPrototype,
};

/// A prototype of [`crate::permission::Permission`] for predicate construction.
#[derive(Default, Copy, Clone)]
pub struct PermissionPrototype<Projector> {
    phantom: PhantomData<Projector>,
}
impl_prototype!(PermissionPrototype: PermissionPredicateBox);
