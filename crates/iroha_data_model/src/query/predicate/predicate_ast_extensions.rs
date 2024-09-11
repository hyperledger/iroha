//! A module providing extensions to the [`AstPredicate`] trait.

use super::{AstPredicate, CompoundPredicate};
use crate::query::predicate::predicate_combinators::{
    AndAstPredicate, NotAstPredicate, OrAstPredicate,
};

/// Extension trait for [`AstPredicate`].
pub trait AstPredicateExt<PredType>: AstPredicate<PredType>
where
    Self: Sized,
{
    /// Normalize this predicate without applying additional projections.
    fn normalize(self) -> CompoundPredicate<PredType> {
        self.normalize_with_proj(|p| p)
    }

    /// Negate this AST predicate.
    fn not(self) -> NotAstPredicate<Self> {
        NotAstPredicate(self)
    }

    /// Combine this AST predicate with another AST predicate using logical AND.
    fn and<PLhs>(self, other: PLhs) -> AndAstPredicate<Self, PLhs>
    where
        PLhs: AstPredicate<PredType>,
    {
        AndAstPredicate(self, other)
    }

    /// Combine this AST predicate with another AST predicate using logical OR.
    fn or<PLhs>(self, other: PLhs) -> OrAstPredicate<Self, PLhs>
    where
        PLhs: AstPredicate<PredType>,
    {
        OrAstPredicate(self, other)
    }
}

impl<PredType, P> AstPredicateExt<PredType> for P where P: AstPredicate<PredType> {}
