#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, format, string::String, vec, vec::Vec};

use derive_where::derive_where;
use iroha_macro::serde_where;
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::query::dsl::{
    BaseProjector, EvaluatePredicate, HasProjection, HasPrototype, PredicateMarker,
};

#[derive_where(Debug, Eq, PartialEq, Clone; T::Projection)]
#[serde_where(T::Projection)]
#[derive(Decode, Encode, Deserialize, Serialize, IntoSchema)]
pub enum CompoundPredicate<T: HasProjection<PredicateMarker>> {
    Atom(T::Projection),
    Not(Box<CompoundPredicate<T>>),
    And(Vec<CompoundPredicate<T>>),
    Or(Vec<CompoundPredicate<T>>),
}

impl<T: HasProjection<PredicateMarker>> CompoundPredicate<T> {
    pub const PASS: Self = Self::And(Vec::new());

    // aliases for logical operations
    /// Negate the predicate.
    #[must_use]
    pub fn not(self) -> Self {
        !self
    }

    /// Combine two predicates with an "and" operation.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        self & other
    }

    /// Combine two predicates with an "or" operation.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        self | other
    }
}

impl<T> CompoundPredicate<T>
where
    T: HasProjection<PredicateMarker>,
    T::Projection: EvaluatePredicate<T>,
{
    pub fn applies(&self, input: &T) -> bool {
        match self {
            CompoundPredicate::Atom(projection) => projection.applies(input),
            CompoundPredicate::Not(expr) => !expr.applies(input),
            CompoundPredicate::And(and_list) => and_list.iter().all(|expr| expr.applies(input)),
            CompoundPredicate::Or(or_list) => or_list.iter().any(|expr| expr.applies(input)),
        }
    }
}

impl<T: HasProjection<PredicateMarker>> core::ops::Not for CompoundPredicate<T> {
    type Output = CompoundPredicate<T>;

    fn not(self) -> Self::Output {
        match self {
            // if the top-level predicate is a negation, we can just remove it
            CompoundPredicate::Not(expr) => *expr,
            this => CompoundPredicate::Not(Box::new(this)),
        }
    }
}

impl<T: HasProjection<PredicateMarker>> core::ops::BitAnd for CompoundPredicate<T> {
    type Output = CompoundPredicate<T>;

    fn bitand(self, other: Self) -> Self::Output {
        match (self, other) {
            // if any of the predicates is an and - flatten it
            (CompoundPredicate::And(mut and_list), other) => {
                and_list.push(other);
                CompoundPredicate::And(and_list)
            }
            (this, CompoundPredicate::And(mut and_list)) => {
                // push to front to preserve user-specified order (our predicates are short-circuiting)
                and_list.insert(0, this);
                CompoundPredicate::And(and_list)
            }
            (this, other) => CompoundPredicate::And(vec![this, other]),
        }
    }
}

impl<T: HasProjection<PredicateMarker>> core::ops::BitOr for CompoundPredicate<T> {
    type Output = CompoundPredicate<T>;

    fn bitor(self, other: Self) -> Self::Output {
        match (self, other) {
            // if any of the predicates is an or - flatten it
            (CompoundPredicate::Or(mut or_list), other) => {
                or_list.push(other);
                CompoundPredicate::Or(or_list)
            }
            (this, CompoundPredicate::Or(mut or_list)) => {
                // push to front to preserve user-specified order (our predicates are short-circuiting)
                or_list.insert(0, this);
                CompoundPredicate::Or(or_list)
            }
            (this, other) => CompoundPredicate::Or(vec![this, other]),
        }
    }
}

impl<T: HasProjection<PredicateMarker>> CompoundPredicate<T> {
    pub fn build<F>(f: F) -> Self
    where
        T: HasPrototype,
        F: FnOnce(
            <T as HasPrototype>::Prototype<PredicateMarker, BaseProjector<PredicateMarker, T>>,
        ) -> CompoundPredicate<T>,
        <T as HasPrototype>::Prototype<PredicateMarker, BaseProjector<PredicateMarker, T>>: Default,
    {
        f(Default::default())
    }
}
