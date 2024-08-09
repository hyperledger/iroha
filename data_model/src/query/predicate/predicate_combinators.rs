//! Module containing AST predicate combinators, implementing logical operations.

use super::{AstPredicate, CompoundPredicate};

/// Overrides the `Not`, `BitAnd`, and `BitOr` operators for easier predicate composition.
macro_rules! impl_ops {
    ($name:ident<$($generic_name:ident),*>) => {
        impl<$($generic_name),*> core::ops::Not for $name<$($generic_name),*>
        // it would be nice to have a `Self: AstPredicate<PredType>` bound here, but it is not possible due to `E0207`: unconstrained type parameter
        {
            type Output = NotAstPredicate<Self>;

            fn not(self) -> Self::Output {
                NotAstPredicate(self)
            }
        }

        impl<PRhs, $($generic_name),*> core::ops::BitAnd<PRhs> for $name<$($generic_name),*>
        {
            type Output = AndAstPredicate<Self, PRhs>;

            fn bitand(self, rhs: PRhs) -> Self::Output {
                AndAstPredicate(self, rhs)
            }
        }

        impl<PRhs, $($generic_name),*> core::ops::BitOr<PRhs> for $name<$($generic_name),*>
        {
            type Output = OrAstPredicate<Self, PRhs>;

            fn bitor(self, rhs: PRhs) -> Self::Output {
                OrAstPredicate(self, rhs)
            }
        }
    };
}

/// Invert the AST predicate - apply not operation.
pub struct NotAstPredicate<P>(pub P);

impl_ops!(NotAstPredicate<P>);

impl<PredType, P> AstPredicate<PredType> for NotAstPredicate<P>
where
    P: AstPredicate<PredType>,
{
    fn normalize_with_proj<OutputType, Proj>(self, proj: Proj) -> CompoundPredicate<OutputType>
    where
        Proj: Fn(PredType) -> OutputType + Copy,
    {
        let NotAstPredicate(inner) = self;

        // project the inner predicate and negate it
        // use `CompoundPredicate` combinator methods that have flattening optimization
        inner.normalize_with_proj(proj).not()
    }
}

/// Combine two AST predicates with logical OR.
pub struct OrAstPredicate<P1, P2>(pub P1, pub P2);

impl<PredType, P1, P2> AstPredicate<PredType> for OrAstPredicate<P1, P2>
where
    P1: AstPredicate<PredType>,
    P2: AstPredicate<PredType>,
{
    fn normalize_with_proj<OutputType, Proj>(self, proj: Proj) -> CompoundPredicate<OutputType>
    where
        Proj: Fn(PredType) -> OutputType + Copy,
    {
        let OrAstPredicate(lhs, rhs) = self;

        // project the inner predicates and combine them with an or
        // use `CompoundPredicate` combinator methods that have flattening optimization
        lhs.normalize_with_proj(proj)
            .or(rhs.normalize_with_proj(proj))
    }
}

impl_ops!(OrAstPredicate<P1, P2>);

/// Combine two AST predicates with logical AND.
pub struct AndAstPredicate<P1, P2>(pub P1, pub P2);

impl<PredType, P1, P2> AstPredicate<PredType> for AndAstPredicate<P1, P2>
where
    P1: AstPredicate<PredType>,
    P2: AstPredicate<PredType>,
{
    fn normalize_with_proj<OutputType, Proj>(self, proj: Proj) -> CompoundPredicate<OutputType>
    where
        Proj: Fn(PredType) -> OutputType + Copy,
    {
        let AndAstPredicate(lhs, rhs) = self;

        // project the inner predicates and combine them with an and
        // use `CompoundPredicate` combinator methods that have flattening optimization
        lhs.normalize_with_proj(proj)
            .and(rhs.normalize_with_proj(proj))
    }
}

impl_ops!(AndAstPredicate<P1, P2>);
