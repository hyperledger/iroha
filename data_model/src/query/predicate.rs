//! Predicate-related logic. Should contain predicate-related `impl`s.

#[cfg(not(feature = "std"))]
use alloc::vec;
use core::{
    fmt::Display,
    ops::{ControlFlow, Not},
};

use iroha_data_model_derive::{PartiallyTaggedDeserialize, PartiallyTaggedSerialize};

use super::*;
use crate::{IdBox, Name};

/// Trait for boolean-like values
///
/// [`or`](`Self::or`) and [`and`](`Self::and`) must satisfy De Morgan's laws, commutativity and associativity
/// [`Not`](`core::ops::Not`) implementation should satisfy double negation elimintation.
///
/// Short-circuiting behaviour for `and` and `or` can be controlled by returning
/// `ControlFlow::Break` when subsequent application of the same operation
/// won't change the end result, no matter what operands.
///
/// When implementing, it's recommended to generate exhaustive tests with
/// [`test_conformity`](`Self::test_conformity`).
pub trait PredicateSymbol
where
    Self: Sized + core::ops::Not<Output = Self>,
{
    /// Conjunction (e.g. boolean and)
    #[must_use]
    fn and(self, other: Self) -> ControlFlow<Self, Self>;
    /// Disjunction (e.g. boolean or)
    #[must_use]
    fn or(self, other: Self) -> ControlFlow<Self, Self>;

    #[doc(hidden)]
    #[must_use]
    fn unwrapped_and(self, other: Self) -> Self {
        match self.and(other) {
            ControlFlow::Continue(val) | ControlFlow::Break(val) => val,
        }
    }

    #[doc(hidden)]
    #[must_use]
    fn unwrapped_or(self, other: Self) -> Self {
        match self.or(other) {
            ControlFlow::Continue(val) | ControlFlow::Break(val) => val,
        }
    }

    /// Given a list of all possible values of a type implementing [`PredicateSymbol`]
    /// which are different in predicate context, exhaustively tests for:
    /// - commutativity of `and` and `or`
    /// - associativity of `and` and `or`
    /// - De Mornan duality of `and` and `or`
    /// - double negation elimination
    ///
    /// # Examples
    ///
    /// ```
    /// use iroha_data_model::query::predicate::PredicateSymbol;
    ///
    /// fn test() {
    ///     PredicateSymbol::test_conformity(vec![true, false]);
    /// }
    /// ```
    fn test_conformity(values: Vec<Self>)
    where
        Self: PartialEq + Clone,
    {
        Self::test_conformity_with_eq(values, <Self as PartialEq>::eq);
    }

    /// Same as [`test_conformity`](`PredicateSymbol::test_conformity`), but
    /// if type implementing [`PredicateSymbol`] carries some internal state
    /// that isn't associative, one can provide custom `shallow_eq` function
    /// that will be called instead of [`PartialEq::eq`]
    ///
    /// # Examples
    ///
    ///
    /// ```
    /// use std::ops::ControlFlow;
    ///
    /// use iroha_data_model::query::predicate::PredicateSymbol;
    ///
    /// #[derive(Clone, PartialEq)]
    /// enum Check {
    ///     Good,
    ///     // Encapsulates reason for badness which
    ///     // doesn't behave associatively
    ///     // (but if we ignore it, Check as a whole does)
    ///     Bad(String),
    /// }
    ///
    /// impl core::ops::Not for Check {
    ///     type Output = Self;
    ///     fn not(self) -> Self {
    ///         // ...
    ///         todo!()
    ///     }
    /// }
    ///
    /// impl PredicateSymbol for Check {
    ///     fn and(self, other: Self) -> ControlFlow<Self, Self> {
    ///         // ...
    ///         todo!()
    ///     }
    ///
    ///     fn or(self, other: Self) -> ControlFlow<Self, Self> {
    ///         // ...
    ///         todo!()
    ///     }
    /// }
    ///
    /// fn shallow_eq(left: &Check, right: &Check) -> bool {
    ///     match (left, right) {
    ///         (Check::Good, Check::Good) | (Check::Bad(_), Check::Bad(_)) => true,
    ///         _ => false,
    ///     }
    /// }
    ///
    /// fn test() {
    ///     let good = Check::Good;
    ///     let bad = Check::Bad("example".to_owned());
    ///     // Would fail some assertions, since derived PartialEq is "deep"
    ///     // PredicateSymbol::test_conformity(vec![good, bad]);
    ///
    ///     // Works as expected
    ///     PredicateSymbol::test_conformity_with_eq(vec![good, bad], shallow_eq);
    /// }
    /// ```
    fn test_conformity_with_eq(values: Vec<Self>, shallow_eq: impl FnMut(&Self, &Self) -> bool)
    where
        Self: Clone,
    {
        let mut eq = shallow_eq;
        let values = values
            .into_iter()
            .map(|val| move || val.clone())
            .collect::<Vec<_>>();

        let typ = core::any::type_name::<Self>();

        for a in &values {
            assert!(
                eq(&a().not().not(), &a()),
                "Double negation elimination doesn't hold for {typ}",
            );
        }

        for a in &values {
            for b in &values {
                assert!(
                eq(
                    &PredicateSymbol::unwrapped_and(a(), b()),
                    &PredicateSymbol::unwrapped_and(b(), a())
                ),
                "Commutativity doesn't hold for `PredicateSymbol::and` implementation for {typ}"
            );

                assert!(
                    eq(
                        &PredicateSymbol::unwrapped_or(a(), b()),
                        &PredicateSymbol::unwrapped_or(b(), a())
                    ),
                    "Commutativity doesn't hold for `PredicateSymbol::or` implementation for {typ}"
                );

                assert!(
                    eq(
                        &PredicateSymbol::unwrapped_or(!a(), !b()),
                        &!PredicateSymbol::unwrapped_and(a(), b())
                    ),
                    "De Morgan's law doesn't hold for {typ}",
                );

                assert!(
                    eq(
                        &PredicateSymbol::unwrapped_and(!a(), !b()),
                        &!PredicateSymbol::unwrapped_or(a(), b())
                    ),
                    "De Morgan's law doesn't hold for {typ}",
                );
            }
        }

        for a in &values {
            for b in &values {
                for c in &values {
                    assert!(
                    eq(
                        &PredicateSymbol::unwrapped_and(
                            PredicateSymbol::unwrapped_and(a(), b()),
                            c()
                        ),
                        &PredicateSymbol::unwrapped_and(
                            a(),
                            PredicateSymbol::unwrapped_and(b(), c()),
                        ),
                    ),
                    "Associativity doesn't hold for `PredicateSymbol::or` implementation for {typ}",
                );

                    assert!(
                    eq(
                        &PredicateSymbol::unwrapped_or(
                            PredicateSymbol::unwrapped_or(a(), b()),
                            c()
                        ),
                        &PredicateSymbol::unwrapped_or(
                            a(),
                            PredicateSymbol::unwrapped_or(b(), c()),
                        ),
                    ),
                    "Associativity doesn't hold for `PredicateSymbol::and` implementation for {typ}",
                );
                }
            }
        }
    }
}

impl PredicateSymbol for bool {
    fn and(self, other: Self) -> ControlFlow<Self, Self> {
        if self && other {
            ControlFlow::Continue(true)
        } else {
            ControlFlow::Break(false)
        }
    }

    fn or(self, other: Self) -> ControlFlow<Self, Self> {
        if self || other {
            ControlFlow::Break(true)
        } else {
            ControlFlow::Continue(false)
        }
    }
}

/// Trait for generic predicates.
pub trait PredicateTrait<T: ?Sized + Copy> {
    /// Type the predicate evaluates to.
    type EvaluatesTo: PredicateSymbol;

    /// The result of applying the predicate to a value.
    fn applies(&self, input: T) -> Self::EvaluatesTo;
}

mod nontrivial {
    use super::*;
    /// Struct representing a sequence with at least three elements.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct NonTrivial<T>(Vec<T>);

    impl<T> NonTrivial<T> {
        /// Constructor
        #[inline]
        pub fn new(first: T, second: T) -> Self {
            Self(vec![first, second])
        }

        /// Extend the sequence with elements of another non-empty sequence
        #[inline]
        pub fn extend(&mut self, other: Self) {
            self.0.extend(other.0);
        }

        /// Append `value` to the end of the sequence
        #[inline]
        pub fn push(&mut self, value: T) {
            self.0.push(value);
        }

        /// Apply the provided function to every element of the sequence
        #[must_use]
        #[inline]
        pub fn map<U>(self, f: impl FnMut(T) -> U) -> NonTrivial<U> {
            NonTrivial(self.0.into_iter().map(f).collect())
        }

        /// Get reference to first element of the sequence
        #[inline]
        pub fn head(&self) -> &T {
            self.0.first().expect("Shouldn't be empty by construction")
        }

        /// Produce an iterator over the sequence
        #[inline]
        pub fn iter(&self) -> impl Iterator<Item = &T> {
            self.0.iter()
        }
    }

    impl<'item, T> IntoIterator for &'item NonTrivial<T> {
        type Item = &'item T;

        type IntoIter = <&'item Vec<T> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.0.iter()
        }
    }
}
pub use nontrivial::NonTrivial;

macro_rules! nontrivial {
    ($first:expr, $second:expr $(, $( $t:expr ),*)? ) => {{
        let res = NonTrivial::new(($first), ($second));
        $({ res.push($t); })*
        res
    }};
}

/// Predicate combinator enum.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Decode,
    Encode,
    PartiallyTaggedSerialize,
    PartiallyTaggedDeserialize,
    IntoSchema,
)]
// Ideally we would enforce `P: PredicateTrait<Input>` here, but I
// couldn't find a way to do it without polluting everything
// downstream with explicit lifetimes, since we would need to
// store PhantomData<Input> here, and `Input`s are most often
// references (e.g. &QueryOutputBox).
pub enum GenericPredicateBox<P> {
    /// Logically `&&` the results of applying the predicates.
    And(NonTrivial<Self>),
    /// Logically `||` the results of applying the predicats.
    Or(NonTrivial<Self>),
    /// Negate the result of applying the predicate.
    Not(Box<Self>),
    /// The raw predicate that must be applied.
    #[serde_partially_tagged(untagged)]
    Raw(P),
}

impl<P> Display for GenericPredicateBox<P>
where
    P: Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GenericPredicateBox::And(predicates) => {
                write!(f, "AND(")?;
                for predicate in predicates {
                    predicate.fmt(f)?;
                }
                write!(f, ")")
            }
            GenericPredicateBox::Or(predicates) => {
                write!(f, "OR(")?;
                for predicate in predicates {
                    predicate.fmt(f)?;
                }
                write!(f, ")")
            }
            GenericPredicateBox::Not(predicate) => write!(f, "NOT({predicate})"),
            GenericPredicateBox::Raw(predicate) => predicate.fmt(f),
        }
    }
}

impl<P> GenericPredicateBox<P> {
    /// Construct [`PredicateBox::Raw`] variant.
    #[inline]
    pub fn new<Input>(pred: impl Into<P>) -> Self
    where
        P: PredicateTrait<Input>,
        Input: Copy,
    {
        Self::Raw(pred.into())
    }

    /// Construct [`PredicateBox::And`] variant.
    #[inline]
    pub fn and(left: impl Into<Self>, right: impl Into<Self>) -> Self {
        match (left.into(), right.into()) {
            (Self::And(mut left), Self::And(right)) => {
                left.extend(right);
                Self::And(left)
            }
            (Self::And(mut and), other) => {
                and.push(other);
                Self::And(and)
            }
            (left, right) => Self::And(nontrivial![left, right]),
        }
    }

    /// Construct [`PredicateBox::Or`] variant.
    #[inline]
    pub fn or(left: impl Into<Self>, right: impl Into<Self>) -> Self {
        match (left.into(), right.into()) {
            (Self::Or(mut left), Self::Or(right)) => {
                left.extend(right);
                Self::Or(left)
            }
            (Self::Or(mut and), other) => {
                and.push(other);
                Self::Or(and)
            }
            (left, right) => Self::Or(nontrivial![left, right]),
        }
    }

    /// Convert instance into its negation.
    #[must_use]
    #[inline]
    pub fn negate(self) -> Self {
        match self {
            Self::And(preds) => Self::Or(preds.map(Self::negate)),
            Self::Or(preds) => Self::And(preds.map(Self::negate)),
            Self::Not(pred) => *pred, // TODO: should we recursively simplify?
            Self::Raw(pred) => Self::Not(Box::new(Self::Raw(pred))),
        }
    }
}

impl<Pred, Input> PredicateTrait<Input> for GenericPredicateBox<Pred>
where
    Input: ?Sized + Copy,
    Pred: PredicateTrait<Input>,
{
    type EvaluatesTo = Pred::EvaluatesTo;

    #[inline] // This is not a simple function, but it allows you to inline the logic and optimise away the logical operations.
    fn applies(&self, input: Input) -> Self::EvaluatesTo {
        match self {
            Self::Raw(predicate) => predicate.applies(input),
            Self::And(predicates) => {
                let initial = predicates.head().applies(input);
                let mut operands = predicates
                    .iter()
                    .skip(1)
                    .map(|predicate| predicate.applies(input));
                match operands.try_fold(initial, PredicateSymbol::and) {
                    ControlFlow::Continue(value) | ControlFlow::Break(value) => value,
                }
            }
            Self::Or(predicates) => {
                let initial = predicates.head().applies(input);
                let mut operands = predicates
                    .iter()
                    .skip(1)
                    .map(|predicate| predicate.applies(input));
                match operands.try_fold(initial, PredicateSymbol::or) {
                    ControlFlow::Continue(value) | ControlFlow::Break(value) => value,
                }
            }
            Self::Not(predicate) => predicate.applies(input).not(),
        }
    }
}

/// Predicate combinator for predicates operating on `QueryOutputBox`
pub type PredicateBox = GenericPredicateBox<value::QueryOutputPredicate>;

impl Default for PredicateBox {
    fn default() -> Self {
        PredicateBox::Raw(value::QueryOutputPredicate::Pass)
    }
}

#[cfg(test)]
pub mod test {
    use super::{value, PredicateBox, PredicateSymbol, PredicateTrait as _};
    use crate::metadata::MetadataValueBox;

    #[test]
    fn boolean_predicate_symbol_conformity() {
        PredicateSymbol::test_conformity(vec![true, false]);
    }

    #[test]
    fn pass() {
        let t = PredicateBox::new(value::QueryOutputPredicate::Pass);
        let f = t.clone().negate();
        let v_t = MetadataValueBox::from(true).into();
        let v_f = MetadataValueBox::from(false).into();
        println!("t: {t:?}, f: {f:?}");

        assert!(t.applies(&v_t));
        assert!(t.applies(&v_f));
        assert!(!f.applies(&v_t));
        assert!(!f.applies(&v_f));
    }

    #[test]
    fn truth_table() {
        let t = PredicateBox::new(value::QueryOutputPredicate::Pass);
        let f = t.clone().negate();
        let v = MetadataValueBox::from(true).into();

        assert!(!PredicateBox::and(t.clone(), f.clone()).applies(&v));
        assert!(PredicateBox::and(t.clone(), t.clone()).applies(&v));
        assert!(!PredicateBox::and(f.clone(), f.clone()).applies(&v));
        assert!(!PredicateBox::and(f.clone(), t.clone()).applies(&v));

        assert!(PredicateBox::or(t.clone(), t.clone()).applies(&v));
        assert!(PredicateBox::or(t.clone(), f.clone()).applies(&v));
        assert!(PredicateBox::or(f.clone(), t).applies(&v));
        assert!(!PredicateBox::or(f.clone(), f).applies(&v));
    }

    #[test]
    fn negation() {
        let t = PredicateBox::default();

        assert!(matches!(t.clone().negate().negate(), PredicateBox::Raw(_)));
        // De-morgan identities
        assert!(matches!(
            PredicateBox::and(t.clone(), t.clone()).negate(),
            PredicateBox::Or(_)
        ));
        assert!(matches!(
            PredicateBox::or(t.clone(), t).negate(),
            PredicateBox::And(_)
        ));
    }
}

pub mod string {
    //! String-related predicates and implementations.
    use super::*;

    /// Predicate useful for processing [`String`]s and [`Name`]s.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum StringPredicate {
        /// Forward to [`str::contains()`]
        Contains(String),
        /// Forward to [`str::starts_with()`]
        StartsWith(String),
        /// Forward to [`str::ends_with()`]
        EndsWith(String),
        /// Forward to [`String`] equality.
        Is(String),
    }

    impl StringPredicate {
        /// Construct the [`Self::Contains`] variant
        #[inline]
        pub fn contains(predicate: &str) -> Self {
            Self::Contains(predicate.to_owned())
        }

        /// Construct the [`Self::StartsWith`] variant
        #[inline]
        pub fn starts_with(predicate: &str) -> Self {
            Self::StartsWith(predicate.to_owned())
        }

        /// Construct the [`Self::EndsWith`] variant
        #[inline]
        pub fn ends_with(predicate: &str) -> Self {
            Self::EndsWith(predicate.to_owned())
        }

        /// Construct the [`Self::Is`] variant
        #[inline]
        pub fn is(predicate: &str) -> Self {
            Self::Is(predicate.to_owned())
        }
    }

    // TODO: Case insensitive variants?

    impl<T: AsRef<str> + ?Sized> PredicateTrait<&T> for StringPredicate {
        type EvaluatesTo = bool;

        #[inline] // Jump table. Needs inline.
        fn applies(&self, input: &T) -> Self::EvaluatesTo {
            match self {
                StringPredicate::Contains(content) => input.as_ref().contains(content),
                StringPredicate::StartsWith(content) => input.as_ref().starts_with(content),
                StringPredicate::EndsWith(content) => input.as_ref().ends_with(content),
                StringPredicate::Is(content) => *(input.as_ref()) == *content,
            }
        }
    }

    impl PredicateTrait<&IdBox> for StringPredicate {
        type EvaluatesTo = bool;

        #[inline] // Jump table. Needs inline.
        fn applies(&self, input: &IdBox) -> Self::EvaluatesTo {
            match input {
                IdBox::DomainId(id) => self.applies(&id.to_string()),
                IdBox::AccountId(id) => self.applies(&id.to_string()),
                IdBox::AssetDefinitionId(id) => self.applies(&id.to_string()),
                IdBox::AssetId(id) => self.applies(&id.to_string()),
                IdBox::PeerId(id) => self.applies(&id.to_string()),
                IdBox::TriggerId(id) => self.applies(&id.to_string()),
                IdBox::RoleId(id) => self.applies(&id.to_string()),
                IdBox::PermissionTokenId(id) => self.applies(&id.to_string()),
                IdBox::ParameterId(id) => self.applies(&id.to_string()),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use iroha_primitives::addr::socket_addr;

        use super::*;

        mod id_box {
            use iroha_crypto::KeyPair;

            use super::*;
            use crate::peer::PeerId;

            #[test]
            fn simple_name_wrappers() {
                let starts_with = StringPredicate::starts_with("Curiouser");
                let contains = StringPredicate::contains("Curiouser");
                let ends_with = StringPredicate::ends_with("Curiouser");
                let pred_is = StringPredicate::is("Curiouser");

                // What do you think about explicit scoping in tests?
                {
                    // Domain
                    let curiouser = IdBox::DomainId("curiouser".parse().expect("Valid"));
                    // Negatives.
                    assert!(!starts_with.applies(&curiouser));
                    assert!(!contains.applies(&curiouser));
                    assert!(!ends_with.applies(&curiouser));
                    assert!(!pred_is.applies(&curiouser));

                    let cap_curiouser =
                        IdBox::DomainId("Curiouser_and_Curiouser".parse().expect("Valid"));
                    // Some positives
                    assert!(starts_with.applies(&cap_curiouser));
                    assert!(contains.applies(&cap_curiouser));
                    assert!(ends_with.applies(&cap_curiouser));
                    assert!(!pred_is.applies(&cap_curiouser));
                }

                {
                    // Role
                    let curiouser = IdBox::RoleId("curiouser".parse().expect("Valid"));
                    // Negatives.
                    assert!(!starts_with.applies(&curiouser));
                    assert!(!contains.applies(&curiouser));
                    assert!(!ends_with.applies(&curiouser));
                    assert!(!pred_is.applies(&curiouser));

                    let cap_curiouser =
                        IdBox::RoleId("Curiouser_and_Curiouser".parse().expect("Valid"));
                    // Some positives
                    assert!(starts_with.applies(&cap_curiouser));
                    assert!(contains.applies(&cap_curiouser));
                    assert!(ends_with.applies(&cap_curiouser));
                    assert!(!pred_is.applies(&cap_curiouser));
                }
            }

            #[test]
            fn trigger() {
                let starts_with = StringPredicate::starts_with("Curiouser");
                let contains = StringPredicate::contains("Curiouser");
                let ends_with = StringPredicate::ends_with("Curiouser");
                let pred_is = StringPredicate::is("Curiouser");

                let curiouser = IdBox::TriggerId("curiouser".parse().expect("Valid"));
                // Negatives.
                assert!(!starts_with.applies(&curiouser));
                assert!(!contains.applies(&curiouser));
                assert!(!ends_with.applies(&curiouser));
                assert!(!pred_is.applies(&curiouser));

                let cap_curiouser =
                    IdBox::TriggerId("Curiouser_and_Curiouser".parse().expect("Valid"));
                // Some positives
                assert!(starts_with.applies(&cap_curiouser));
                assert!(contains.applies(&cap_curiouser));
                assert!(ends_with.applies(&cap_curiouser));
                assert!(!pred_is.applies(&cap_curiouser));

                // TODO: Once #2302 and #1889 are merged, add more cases.
            }

            #[test]
            fn account_id() {
                let alice: PublicKey = KeyPair::random().into_parts().0;
                let id = IdBox::AccountId(format!("{alice}@wonderland").parse().expect("Valid"));
                assert!(StringPredicate::starts_with(&*format!("{alice}@")).applies(&id));
                assert!(StringPredicate::ends_with("@wonderland").applies(&id));
                assert!(StringPredicate::is(&*format!("{alice}@wonderland")).applies(&id));
                // Should we also include a check into string
                // predicates? If the internal predicate starts with
                // whitespace, it can't possibly match any Id, but
                // there's no way to enforce this at both type level
                // and run-time.
                assert!(!StringPredicate::starts_with(&*format!(" {alice}@")).applies(&id));
                assert!(!StringPredicate::ends_with("@wonderland ").applies(&id));
                assert!(!StringPredicate::is(&*format!("{alice}@@wonderland ")).applies(&id));
                assert!(!StringPredicate::contains("#").applies(&id));
                assert!(!StringPredicate::is(&*format!("{alice}#wonderland")).applies(&id));
            }

            #[test]
            fn asset_id() {
                let alice: PublicKey = KeyPair::random().into_parts().0;
                let id =
                    IdBox::AssetId(format!("rose##{alice}@wonderland").parse().expect("Valid"));
                assert!(StringPredicate::starts_with("rose##").applies(&id));
                assert!(StringPredicate::ends_with(&*format!("#{alice}@wonderland")).applies(&id));
                assert!(StringPredicate::is(&*format!("rose##{alice}@wonderland")).applies(&id));
                assert!(StringPredicate::contains(&*format!("#{alice}@")).applies(&id));
            }

            #[test]
            fn asset_def_id() {
                let id = IdBox::AssetDefinitionId("rose#wonderland".parse().expect("Valid"));
                assert!(StringPredicate::starts_with("rose#").applies(&id));
                assert!(StringPredicate::ends_with("#wonderland").applies(&id));
                assert!(StringPredicate::is("rose#wonderland").applies(&id));
                // Should we also include a check into string
                // predicates? If the internal predicate starts with
                // whitespace, it can't possibly match any Id, but
                // there's no way to enforce this at both type level
                // and run-time.
                assert!(!StringPredicate::starts_with(" rose#").applies(&id));
                assert!(!StringPredicate::ends_with("#wonderland ").applies(&id));
                assert!(!StringPredicate::is("alice##wonderland ").applies(&id));
                assert!(!StringPredicate::contains("@").applies(&id));
                assert!(!StringPredicate::is("rose@wonderland").applies(&id));
            }

            #[test]
            fn peer_id() {
                let (public_key, _) = iroha_crypto::KeyPair::random().into_parts();
                let id = IdBox::PeerId(PeerId::new(socket_addr!(127.0.0.1:123), public_key));
                assert!(StringPredicate::contains("123").applies(&id));
            }
        }

        mod string {
            use super::*;

            #[test]
            fn contains() {
                let pred = StringPredicate::Contains("believed as many".to_owned());
                assert!(pred.applies(
                    "sometimes I've believed as many as six impossible things before breakfast!"
                ));
                assert!(!pred.applies("hello world"));
                assert!(pred.applies("believed as many"));
                assert!(pred.applies(" believed as many"));
                assert!(pred.applies("believed as many "));
                assert!(!pred.applies("believed"));
            }

            #[test]
            fn starts_with() {
                let pred = StringPredicate::StartsWith("Curiouser".to_owned());
                assert!(pred.applies("Curiouser and Curiouser"));
                assert!(!pred.applies(" Curiouser and Curiouser"));
                assert!(!pred.applies("curiouser and curiouser"));
                assert!(!pred.applies("More Curiouser"));
                assert!(!pred.applies("Curiouse"));
            }

            #[test]
            fn ends_with() {
                let pred = StringPredicate::EndsWith("How long is forever?".to_owned());
                assert!(pred.applies("How long is forever?"));
                assert!(!pred.applies("how long is forever?"));
                assert!(pred.applies(" How long is forever?"));
                assert!(pred.applies("I asked: How long is forever?"));
                assert!(!pred.applies("How long is forever"));
            }

            #[test]
            fn is() {
                let pred = StringPredicate::Is("writing-desk".to_owned());
                assert!(!pred.applies("Why is a raven like a writing-desk"));
                assert!(pred.applies("writing-desk"));
                assert!(!pred.applies("Writing-desk"));
                assert!(!pred.applies("writing-des"));
            }

            #[test]
            fn empty_predicate() {
                let pred = StringPredicate::contains("");
                assert!(pred.applies(""));
                assert!(pred.applies("asd")); // TODO: is this the correct behaviour that we want
            }
        }
    }
}

pub mod numerical {
    //! Numerical predicates.
    use core::cmp::{max, min};

    use iroha_primitives::numeric::Numeric;

    use super::*;
    use crate::query::QueryOutputBox;

    /// A lower-inclusive range predicate.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct SemiInterval<T: Copy + Ord> {
        /// The start of the range (inclusive)
        start: T,
        /// The end of the range
        limit: T,
    }

    impl<T: Copy + Ord> From<(T, T)> for SemiInterval<T> {
        #[inline]
        fn from((start, limit): (T, T)) -> Self {
            Self {
                start: min(start, limit),
                limit: max(limit, start),
            }
        }
    }

    impl Copy for SemiInterval<u8> {}
    impl Copy for SemiInterval<u16> {}
    impl Copy for SemiInterval<u32> {}
    impl Copy for SemiInterval<u64> {}

    /// A both-inclusive range predicate
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct Interval<T: Copy + Ord> {
        /// The start of the range (inclusive)
        start: T,
        /// The limit of the range (inclusive)
        limit: T,
    }

    impl<T: Copy + Ord> From<(T, T)> for Interval<T> {
        #[inline]
        fn from((start, limit): (T, T)) -> Self {
            Self {
                start: min(start, limit),
                limit: max(limit, start),
            }
        }
    }

    impl<T: Copy + Ord> From<T> for Interval<T> {
        #[inline]
        fn from(single_value: T) -> Self {
            Self {
                start: single_value,
                limit: single_value,
            }
        }
    }

    impl Copy for Interval<u8> {}
    impl Copy for Interval<u16> {}
    impl Copy for Interval<u32> {}
    impl Copy for Interval<u64> {}

    /// General purpose predicate for working with Iroha numerical type.
    ///
    /// # Type checking
    ///
    /// [`Self`] only applies to `Values` that are variants of
    /// compatible types. If the [`Range`] variant and the [`Value`]
    /// variant don't match defaults to `false`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum SemiRange {
        /// Numeric
        Numeric(SemiInterval<Numeric>),
    }

    /// General-purpose predicate for working with Iroha numerical
    /// type, both-ends inclusive variant.
    ///
    /// # Type checking
    ///
    /// [`Self`] only applies to `Values` that are variants of
    /// compatible types. If the [`Range`] variant and the [`Value`]
    /// variant don't match defaults to `false`.
    #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum Range {
        /// Numeric
        Numeric(Interval<Numeric>),
    }

    /// A trait to mark objects which should be treated as bounded unsigned values.
    pub trait UnsignedMarker {
        /// The maximum attainable value
        const MAX: Self;
        /// The additive neutral element, a.k.a zero, nil, null,
        /// 'nada, zilch, etc.  Be advised that since this trait is
        /// used to mark unsigned values, it coincides with what would
        /// be `MIN`. However, do not implement it for types that are
        /// non-zero (e.g. `NonZeroU64`), because `ZERO` is not `MIN`.
        const ZERO: Self;
    }

    impl UnsignedMarker for u8 {
        const MAX: Self = u8::MAX;
        const ZERO: Self = 0_u8;
    }

    impl UnsignedMarker for u32 {
        const MAX: Self = u32::MAX;
        const ZERO: Self = 0_u32;
    }

    impl UnsignedMarker for u128 {
        const MAX: Self = u128::MAX;
        const ZERO: Self = 0_u128;
    }

    impl UnsignedMarker for Numeric {
        const MAX: Self = Numeric::MAX;
        const ZERO: Self = Numeric::ZERO;
    }

    impl<T: Copy + Ord + UnsignedMarker> SemiInterval<T> {
        /// Construct a semi-interval starting at `start` and ending
        /// at `T::MAX`.
        #[inline]
        #[must_use]
        pub fn starting(start: T) -> Self {
            Self {
                start,
                limit: T::MAX,
            }
        }

        /// Construct a semi-interval that ends at `end` and starts at
        /// `T::ZERO`.
        #[inline]
        #[must_use]
        pub fn ending(end: T) -> Self {
            Self {
                start: T::ZERO,
                limit: end,
            }
        }
    }

    impl<T: Copy + Ord + UnsignedMarker> Interval<T> {
        /// Construct a semi-interval starting at `start` and ending
        /// at `T::MAX`.
        #[inline]
        #[must_use]
        pub fn starting(start: T) -> Self {
            Self {
                start,
                limit: T::MAX,
            }
        }

        /// Construct a semi-interval that ends at `end` and starts at
        /// `T::ZERO`.
        #[inline]
        #[must_use]
        pub fn ending(end: T) -> Self {
            Self {
                start: T::ZERO,
                limit: end,
            }
        }
    }

    impl<T: Copy + Ord> PredicateTrait<T> for SemiInterval<T> {
        type EvaluatesTo = bool;

        #[inline]
        fn applies(&self, input: T) -> Self::EvaluatesTo {
            input < self.limit && input >= self.start
        }
    }

    impl<T: Copy + Ord> PredicateTrait<T> for Interval<T> {
        type EvaluatesTo = bool;

        #[inline]
        fn applies(&self, input: T) -> Self::EvaluatesTo {
            input <= self.limit && input >= self.start
        }
    }

    impl PredicateTrait<&QueryOutputBox> for SemiRange {
        type EvaluatesTo = bool;

        #[inline]
        fn applies(&self, input: &QueryOutputBox) -> Self::EvaluatesTo {
            match input {
                QueryOutputBox::Numeric(quantity) => match self {
                    SemiRange::Numeric(predicate) => predicate.applies(*quantity),
                },
                _ => false,
            }
        }
    }

    impl PredicateTrait<&QueryOutputBox> for Range {
        type EvaluatesTo = bool;

        #[inline]
        fn applies(&self, input: &QueryOutputBox) -> Self::EvaluatesTo {
            match input {
                QueryOutputBox::Numeric(quantity) => match self {
                    Range::Numeric(predicate) => predicate.applies(*quantity),
                },
                _ => false,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::print_stdout, clippy::use_debug)]

        use iroha_primitives::numeric::numeric;

        use super::*;

        #[test]
        fn semi_interval_semantics_numeric() {
            let pred = SemiRange::Numeric((numeric!(1), numeric!(100)).into());
            println!("semi_interval range predicate: {pred:?}");

            assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(1))));
            assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(0))));
            assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(99))));
            assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(100))));
            assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(0.99))));
            assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(99.9999))));
            assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(99.9_999_999_999))));
        }

        #[test]
        fn interval_semantics_numeric() {
            {
                let pred = Range::Numeric((numeric!(1), numeric!(100)).into());
                println!("semi_interval range predicate: {pred:?}");

                assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(1))));
                assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(0))));
                assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(100))));
                assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(101))));
                assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(0.99))));
                assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(99.9999))));
                assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(100.000000001))));
            }

            {
                let pred = Range::Numeric((numeric!(127), numeric!(127)).into());
                assert!(pred.applies(&QueryOutputBox::Numeric(numeric!(127))));
                assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(126))));
                assert!(!pred.applies(&QueryOutputBox::Numeric(numeric!(128))));
            }
        }

        #[test]
        fn invalid_types_false() {
            {
                let pred = SemiRange::Numeric(SemiInterval::ending(numeric!(100)));
                assert!(!pred.applies(&QueryOutputBox::Vec(Vec::new())));
            }
            {
                let pred = Range::Numeric(Interval::ending(numeric!(100)));
                assert!(!pred.applies(&QueryOutputBox::Vec(Vec::new())));
            }
        }

        #[test]
        fn upper_bounds() {
            {
                let pred = SemiRange::Numeric(SemiInterval::starting(Numeric::ZERO));
                // Technically the maximum itself is never included in the semi range.
                assert!(!pred.applies(&Numeric::MAX.into()));
            }
            {
                let pred = SemiRange::Numeric(SemiInterval::ending(numeric!(100)));
                assert!(pred.applies(&numeric!(1).into()));
                assert!(pred.applies(&numeric!(99).into()));
                assert!(!pred.applies(&numeric!(100).into()));
            }

            {
                let pred = Range::Numeric(Interval::starting(Numeric::ZERO));
                // Technically the maximum itself is included in the range.
                assert!(pred.applies(&Numeric::MAX.into()));
            }
            {
                let pred = Range::Numeric(Interval::ending(numeric!(100)));
                assert!(pred.applies(&numeric!(1).into()));
                assert!(pred.applies(&numeric!(100).into()));
                assert!(!pred.applies(&numeric!(101).into()));
            }
        }
    }
}

pub mod value {
    //!  raw predicates applied to `QueryOutputBox`.
    use super::*;
    use crate::query::QueryOutputBox;

    /// A predicate designed for general processing of `QueryOutputBox`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum QueryOutputPredicate {
        /// Apply predicate to the [`Identifiable::Id`] and/or [`IdBox`].
        Identifiable(string::StringPredicate),
        /// Apply predicate to the container.
        Container(Container),
        /// Apply predicate to the [`<QueryOutputBox as Display>::to_string`](ToString::to_string()) representation.
        Display(string::StringPredicate),
        /// Apply predicate to the numerical value.
        Numerical(numerical::SemiRange),
        /// Timestamp (currently for [`SignedBlock`] only).
        TimeStamp(numerical::SemiInterval<u128>),
        /// Always return true.
        Pass,
    }

    impl PredicateTrait<&QueryOutputBox> for QueryOutputPredicate {
        type EvaluatesTo = bool;

        fn applies(&self, input: &QueryOutputBox) -> Self::EvaluatesTo {
            // Large jump table. Do not inline.
            match self {
                QueryOutputPredicate::Identifiable(pred) => match input {
                    QueryOutputBox::Id(id_box) => pred.applies(id_box),
                    QueryOutputBox::Identifiable(identifiable_box) => {
                        pred.applies(&identifiable_box.id_box())
                    }
                    _ => false,
                },
                QueryOutputPredicate::Container(Container::Any(pred)) => match input {
                    QueryOutputBox::Vec(vec) => vec.iter().any(|val| pred.applies(val)),
                    _ => false,
                },
                QueryOutputPredicate::Container(Container::All(pred)) => match input {
                    QueryOutputBox::Vec(vec) => vec.iter().all(|val| pred.applies(val)),
                    _ => false,
                },
                QueryOutputPredicate::Container(Container::AtIndex(AtIndex {
                    index: idx,
                    predicate: pred,
                })) => match input {
                    QueryOutputBox::Vec(vec) => vec
                        .get(*idx as usize) // Safe, since this is only executed server-side and servers are 100% going to be 64-bit.
                        .map_or(false, |val| pred.applies(val)),
                    _ => false,
                },
                QueryOutputPredicate::Numerical(pred) => pred.applies(input),
                QueryOutputPredicate::Display(pred) => pred.applies(&input.to_string()),
                QueryOutputPredicate::TimeStamp(pred) => match input {
                    QueryOutputBox::Block(block) => {
                        pred.applies(block.header().timestamp().as_millis())
                    }
                    _ => false,
                },
                QueryOutputPredicate::Pass => true,
            }
        }
    }

    impl QueryOutputPredicate {
        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn any(pred: impl Into<QueryOutputPredicate>) -> Self {
            Self::Container(Container::Any(Box::new(pred.into())))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn all(pred: impl Into<QueryOutputPredicate>) -> Self {
            Self::Container(Container::All(Box::new(pred.into())))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn at_index(index: u32, pred: impl Into<QueryOutputPredicate>) -> Self {
            Self::Container(Container::AtIndex(AtIndex {
                index,
                predicate: Box::new(pred.into()),
            }))
        }
    }

    /// A predicate that targets the particular `index` of a collection.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct AtIndex {
        index: u32,
        predicate: Box<QueryOutputPredicate>,
    }

    /// Predicate that targets specific elements or groups; useful for
    /// working with containers. Currently only [`Vec<Value>`] is supported.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum Container {
        /// Forward to [`Iterator::any`]
        Any(Box<QueryOutputPredicate>),
        /// Forward to [`Iterator::all`]
        All(Box<QueryOutputPredicate>),
        /// Apply predicate to the [`Value`] element at the index.
        AtIndex(AtIndex),
    }

    impl From<QueryOutputPredicate> for PredicateBox {
        fn from(value: QueryOutputPredicate) -> Self {
            PredicateBox::Raw(value)
        }
    }

    #[cfg(test)]
    mod test {
        use iroha_crypto::KeyPair;
        use iroha_primitives::{addr::socket_addr, numeric::numeric};

        use super::*;
        use crate::{
            account::{Account, AccountId},
            domain::{Domain, DomainId},
            metadata::{Metadata, MetadataValueBox},
            peer::{Peer, PeerId},
        };

        #[test]
        fn typing() {
            let alice: PublicKey = KeyPair::random().into_parts().0;
            let alice_id: AccountId = format!("{alice}@wonderland").parse().expect("Valid");
            {
                let pred = QueryOutputPredicate::Identifiable(string::StringPredicate::is(
                    &*alice_id.to_string(),
                ));
                println!("{pred:?}");
                assert!(pred.applies(&QueryOutputBox::Id(IdBox::AccountId(alice_id.clone()))));
                assert!(
                    pred.applies(&QueryOutputBox::Identifiable(IdentifiableBox::NewAccount(
                        Account::new(alice_id.clone())
                    )))
                );
                assert!(!pred.applies(&MetadataValueBox::from(alice_id.to_string()).into()));
                assert!(!pred.applies(&QueryOutputBox::Vec(Vec::new())));
            }
            {
                let pred = QueryOutputPredicate::Pass;
                println!("{pred:?}");
                assert!(pred.applies(&MetadataValueBox::from(alice_id.to_string()).into()));
            }
            {
                let pred = QueryOutputPredicate::TimeStamp(numerical::SemiInterval::starting(0));
                println!("{pred:?}");
                assert!(!pred.applies(&MetadataValueBox::from(alice_id.to_string()).into()));
            }
            {
                let pred = QueryOutputPredicate::Display(string::StringPredicate::is(
                    &*alice_id.to_string(),
                ));
                println!("{pred:?}");

                assert!(
                    !pred.applies(&QueryOutputBox::Identifiable(IdentifiableBox::Peer(Peer {
                        id: PeerId::new(
                            socket_addr!(127.0.0.1:123),
                            KeyPair::random().into_parts().0
                        )
                    })))
                );
            }
            let pred = QueryOutputPredicate::Numerical(numerical::SemiRange::Numeric(
                (numeric!(0), numeric!(42)).into(),
            ));
            assert!(!pred.applies(&MetadataValueBox::from(alice_id.to_string()).into()));
            assert!(pred.applies(&numeric!(41).into()));
        }

        #[test]
        fn container_vec() {
            let wonderland: DomainId = "wonderland".parse().expect("Valid");
            let alice: PublicKey = KeyPair::random().into_parts().0;
            let alice_id = AccountId::new(wonderland.clone(), alice.clone());
            let list = QueryOutputBox::Vec(vec![
                QueryOutputBox::Identifiable(Domain::new(wonderland.clone()).into()),
                QueryOutputBox::Id(alice_id.into()),
                QueryOutputBox::Id(wonderland.clone().into()),
            ]);

            let wonderland_pred =
                QueryOutputPredicate::Display(string::StringPredicate::contains("wonderland"));

            {
                let pred = QueryOutputPredicate::any(wonderland_pred.clone());
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(!pred.applies(&QueryOutputBox::Vec(Vec::new())));
            }

            {
                let pred = QueryOutputPredicate::all(wonderland_pred.clone());
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(pred.applies(&QueryOutputBox::Vec(Vec::new())));
            }

            {
                let wonderland_id_pred = QueryOutputPredicate::Identifiable(
                    string::StringPredicate::contains("wonderland"),
                );
                let pred = QueryOutputPredicate::all(wonderland_id_pred);
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(pred.applies(&QueryOutputBox::Vec(Vec::new())));
            }

            assert!(QueryOutputPredicate::at_index(0, wonderland_pred.clone()).applies(&list));

            let idx_pred = QueryOutputPredicate::at_index(3, wonderland_pred); // Should be out of bounds.
            println!("{idx_pred:?}");
            assert!(!idx_pred.applies(&list));
        }
    }
}
