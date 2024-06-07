use super::{AstPredicate, CompoundPredicate};
use crate::query::predicate::predicate_combinators::{
    AndAstPredicate, NotAstPredicate, OrAstPredicate,
};

pub trait AstPredicateExt<PredType>: AstPredicate<PredType>
where
    Self: Sized,
{
    fn normalize(self) -> CompoundPredicate<PredType> {
        self.normalize_with_proj(|p| p)
    }

    fn not(self) -> NotAstPredicate<Self> {
        NotAstPredicate(self)
    }

    fn and<PLhs>(self, other: PLhs) -> AndAstPredicate<Self, PLhs>
    where
        PLhs: AstPredicate<PredType>,
    {
        AndAstPredicate(self, other)
    }

    fn or<PLhs>(self, other: PLhs) -> OrAstPredicate<Self, PLhs>
    where
        PLhs: AstPredicate<PredType>,
    {
        OrAstPredicate(self, other)
    }
}

impl<PredType, P> AstPredicateExt<PredType> for P where P: AstPredicate<PredType> {}
