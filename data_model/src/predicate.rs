//! Predicate-related logic. Should contain predicate-related `impl`s.

#[cfg(not(feature = "std"))]
use alloc::vec;
use core::{fmt::Display, ops::Not};

use super::*;
use crate::{IdBox, Name, Value};

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
            self.0.extend(other.0)
        }

        /// Append `value` to the end of the sequence
        #[inline]
        pub fn push(&mut self, value: T) {
            self.0.push(value)
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
// references (e.g. &Value).
pub enum GenericPredicateBox<P> {
    /// Logically `&&` the results of applying the predicates.
    And(NonTrivial<GenericPredicateBox<P>>),
    /// Logically `||` the results of applying the predicats.
    Or(NonTrivial<GenericPredicateBox<P>>),
    /// Negate the result of applying the predicate.
    Not(Box<GenericPredicateBox<P>>),
    /// The raw predicate that must be applied.
    #[serde_partially_tagged(untagged)]
    Raw(P),
}

impl<P> Display for GenericPredicateBox<P>
where
    P: Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// Predicate combinator for predicates operating on `Value`
pub type PredicateBox = GenericPredicateBox<value::ValuePredicate>;

impl Default for PredicateBox {
    fn default() -> Self {
        PredicateBox::Raw(value::ValuePredicate::Pass)
    }
}

#[cfg(test)]
pub mod test {
    #![allow(clippy::print_stdout, clippy::use_debug)]

    use super::{value, PredicateBox};
    use crate::{PredicateSymbol, PredicateTrait as _, ToValue};

    #[test]
    fn boolean_predicate_symbol_conformity() {
        PredicateSymbol::test_conformity(vec![true, false]);
    }

    #[test]
    fn pass() {
        let t = PredicateBox::new(value::ValuePredicate::Pass);
        let f = t.clone().negate();
        let v_t = true.to_value();
        let v_f = false.to_value();
        println!("t: {t:?}, f: {f:?}");

        assert!(t.applies(&v_t));
        assert!(t.applies(&v_f));
        assert!(!f.applies(&v_t));
        assert!(!f.applies(&v_f));
    }

    #[test]
    fn truth_table() {
        let t = PredicateBox::new(value::ValuePredicate::Pass);
        let f = t.clone().negate();
        let v = true.to_value();

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
        use super::*;

        mod id_box {
            use super::*;

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
                let id = IdBox::AccountId("alice@wonderland".parse().expect("Valid"));
                assert!(StringPredicate::starts_with("alice@").applies(&id));
                assert!(StringPredicate::ends_with("@wonderland").applies(&id));
                assert!(StringPredicate::is("alice@wonderland").applies(&id));
                // Should we also include a check into string
                // predicates? If the internal predicate starts with
                // whitespace, it can't possibly match any Id, but
                // there's no way to enforce this at both type level
                // and run-time.
                assert!(!StringPredicate::starts_with(" alice@").applies(&id));
                assert!(!StringPredicate::ends_with("@wonderland ").applies(&id));
                assert!(!StringPredicate::is("alice@@wonderland ").applies(&id));
                assert!(!StringPredicate::contains("#").applies(&id));
                assert!(!StringPredicate::is("alice#wonderland").applies(&id));
            }

            #[test]
            fn asset_id() {
                let definition_id = "rose#wonderland".parse().expect("Valid");
                let account_id = "alice@wonderland".parse().expect("Valid");
                let id = IdBox::AssetId(crate::asset::AssetId {
                    definition_id,
                    account_id,
                });
                assert!(StringPredicate::starts_with("rose##").applies(&id));
                assert!(StringPredicate::ends_with("#alice@wonderland").applies(&id));
                assert!(StringPredicate::is("rose##alice@wonderland").applies(&id));
                assert!(StringPredicate::contains("#alice@").applies(&id));
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
                let (public_key, _) = iroha_crypto::KeyPair::generate()
                    .expect("Should not panic")
                    .into();
                let id = IdBox::PeerId(peer::PeerId {
                    address: "localhost:123".parse().unwrap(),
                    public_key,
                });
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

    use iroha_primitives::fixed::Fixed;

    use super::*;

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

    /// General purpose predicate for working with Iroha numerical
    /// types.
    ///
    /// # Type checking
    ///
    /// [`Self`] only applies to `Values` that are variants of
    /// compatible types. If the [`Range`] variant and the [`Value`]
    /// variant don't match defaults to `false`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum SemiRange {
        /// 32-bit
        U32(SemiInterval<u32>),
        /// 128-bit
        U128(SemiInterval<u128>),
        /// Fixed-precision
        Fixed(SemiInterval<Fixed>),
    }

    /// General-purpose predicate for working with Iroha numerical
    /// types, both-ends inclusive variant.
    ///
    /// # Type checking
    ///
    /// [`Self`] only applies to `Values` that are variants of
    /// compatible types. If the [`Range`] variant and the [`Value`]
    /// variant don't match defaults to `false`.
    #[derive(Debug, Clone, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum Range {
        /// 32-bit
        U32(Interval<u32>),
        /// 128-bit
        U128(Interval<u128>),
        /// Fixed-precision
        Fixed(Interval<Fixed>),
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

    impl UnsignedMarker for Fixed {
        const MAX: Self = Fixed::MAX; // Inherent impl
        const ZERO: Self = Fixed::ZERO; // Inherent impl
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

    impl PredicateTrait<&Value> for SemiRange {
        type EvaluatesTo = bool;

        #[inline]
        fn applies(&self, input: &Value) -> Self::EvaluatesTo {
            match input {
                Value::Numeric(NumericValue::U32(quantity)) => match self {
                    SemiRange::U32(predicate) => predicate.applies(*quantity),
                    _ => false,
                },
                Value::Numeric(NumericValue::U128(big_quantity)) => match self {
                    SemiRange::U128(predicate) => predicate.applies(*big_quantity),
                    _ => false,
                },
                Value::Numeric(NumericValue::Fixed(fixd)) => match self {
                    SemiRange::Fixed(predicate) => predicate.applies(*fixd),
                    _ => false,
                },
                _ => false,
            }
        }
    }

    impl PredicateTrait<&Value> for Range {
        type EvaluatesTo = bool;

        #[inline]
        fn applies(&self, input: &Value) -> Self::EvaluatesTo {
            match input {
                Value::Numeric(NumericValue::U32(quantity)) => match self {
                    Range::U32(predicate) => predicate.applies(*quantity),
                    _ => false,
                },
                Value::Numeric(NumericValue::U128(big_quantity)) => match self {
                    Range::U128(predicate) => predicate.applies(*big_quantity),
                    _ => false,
                },
                Value::Numeric(NumericValue::Fixed(fixd)) => match self {
                    Range::Fixed(predicate) => predicate.applies(*fixd),
                    _ => false,
                },
                _ => false,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::print_stdout, clippy::use_debug)]

        use iroha_primitives::fixed::Fixed;

        use super::*;

        #[test]
        fn semi_interval_semantics_u32() {
            use NumericValue::U32;
            use Value::Numeric;
            let pred = SemiRange::U32((1_u32, 100_u32).into());
            println!("semi_interval range predicate: {pred:?}");

            assert!(pred.applies(&Numeric(U32(1_u32))));
            assert!(!pred.applies(&Numeric(U32(0_u32))));
            assert!(pred.applies(&Numeric(U32(99_u32))));
            assert!(!pred.applies(&Numeric(U32(100_u32))));
        }

        #[test]
        fn semi_interval_semantics_u128() {
            use NumericValue::U128;
            use Value::Numeric;
            let pred = SemiRange::U128((1_u128, 100_u128).into());

            assert!(pred.applies(&Numeric(U128(1_u128))));
            assert!(!pred.applies(&Numeric(U128(0_u128))));
            assert!(pred.applies(&Numeric(U128(99_u128))));
            assert!(!pred.applies(&Numeric(U128(100_u128))));
        }

        #[test]
        #[allow(clippy::panic_in_result_fn)] // ? for syntax simplicity.
        fn semi_interval_semantics_fixed() -> Result<(), fixed::FixedPointOperationError> {
            let pred =
                SemiRange::Fixed((Fixed::try_from(1_f64)?, Fixed::try_from(100_f64)?).into());

            assert!(
                pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    1_f64
                )?)))
            );
            assert!(
                !pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    0.99_f64
                )?)))
            );
            assert!(
                pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    99.9999_f64
                )?)))
            );
            assert!(
                !pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    99.999_999_999_9_f64
                )?)))
            ); // Rounding is still a problem.
            Ok(())
        }

        #[test]
        fn interval_semantics_u32() {
            use NumericValue::U32;
            use Value::Numeric;
            {
                let pred = Range::U32((1_u32, 100_u32).into());
                println!("semi_interval range predicate: {pred:?}");

                assert!(pred.applies(&Numeric(U32(1_u32))));
                assert!(!pred.applies(&Numeric(U32(0_u32))));
                assert!(pred.applies(&Numeric(U32(100_u32))));
                assert!(!pred.applies(&Numeric(U32(101_u32))));
            }
            {
                let pred = Range::U32((127_u32, 127_u32).into());
                assert!(pred.applies(&Numeric(U32(127_u32))));
                assert!(!pred.applies(&Numeric(U32(126_u32))));
                assert!(!pred.applies(&Numeric(U32(128_u32))));
            }
        }

        #[test]
        fn interval_semantics_u128() {
            use NumericValue::U128;
            use Value::Numeric;
            let pred = Range::U128((1_u128, 100_u128).into());

            assert!(pred.applies(&Numeric(U128(1_u128))));
            assert!(!pred.applies(&Numeric(U128(0_u128))));
            assert!(pred.applies(&Numeric(U128(100_u128))));
            assert!(!pred.applies(&Numeric(U128(101_u128))));
        }

        #[test]
        #[allow(clippy::panic_in_result_fn)] // ? for syntax simplicity.
        fn interval_semantics_fixed() -> Result<(), fixed::FixedPointOperationError> {
            let pred = Range::Fixed((Fixed::try_from(1_f64)?, Fixed::try_from(100_f64)?).into());

            assert!(
                pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    1_f64
                )?)))
            );
            assert!(
                !pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    0.99_f64
                )?)))
            );
            assert!(
                pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    99.9999_f64
                )?)))
            );
            assert!(
                !pred.applies(&Value::Numeric(NumericValue::Fixed(Fixed::try_from(
                    100.000_000_001_f64
                )?)))
            ); // Rounding is still a problem.
            Ok(())
        }

        #[test]
        fn invalid_types_false() {
            {
                let pred = SemiRange::U32(SemiInterval::ending(100_u32));
                assert!(!pred.applies(&0_u128.to_value()));
                assert!(!pred.applies(&Fixed::ZERO.to_value()));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
            }
            {
                let pred = Range::U32(Interval::ending(100_u32));
                assert!(!pred.applies(&0_u128.to_value()));
                assert!(!pred.applies(&Fixed::ZERO.to_value()));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
            }
            let pred = SemiRange::U128(SemiInterval::starting(0_u128));
            assert!(!pred.applies(&0_u32.to_value()));
        }

        #[test]
        fn upper_bounds() {
            {
                let pred = SemiRange::Fixed(SemiInterval::starting(Fixed::ZERO));
                // Technically the maximum itself is never included in the range.
                assert!(!pred.applies(&Fixed::MAX.to_value()));
            }
            {
                let pred = SemiRange::U32(SemiInterval::ending(100_u32));
                assert!(pred.applies(&0_u32.to_value()));
                assert!(pred.applies(&99_u32.to_value()));
                assert!(!pred.applies(&100_u32.to_value()));
            }

            {
                let pred = Range::Fixed(Interval::starting(Fixed::ZERO));
                // Technically the maximum itself is never included in the range.
                assert!(pred.applies(&Fixed::MAX.to_value()));
            }
            {
                let pred = Range::U32(Interval::ending(100_u32));
                assert!(pred.applies(&0_u32.to_value()));
                assert!(pred.applies(&100_u32.to_value()));
                assert!(!pred.applies(&101_u32.to_value()));
            }
        }
    }
}

pub mod value {
    //!  raw predicates applied to `Value`.
    use super::*;

    /// A predicate designed for general processing of `Value`.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum ValuePredicate {
        /// Apply predicate to the [`Identifiable::Id`] and/or [`IdBox`].
        Identifiable(string::StringPredicate),
        /// Apply predicate to the container.
        Container(Container),
        /// Apply predicate to the [`<Value as Display>::to_string`](ToString::to_string()) representation.
        Display(string::StringPredicate),
        /// Apply predicate to the numerical value.
        Numerical(numerical::SemiRange),
        /// Timestamp (currently for [`VersionedSignedBlock`] only).
        TimeStamp(numerical::SemiInterval<u128>),
        /// IpAddress enumerable by `u32`
        Ipv4Addr(ip_addr::Ipv4Predicate),
        /// IpAddress extended to use wide range `u128` enumerable addresses.
        Ipv6Addr(ip_addr::Ipv6Predicate),
        /// Always return true.
        Pass,
    }

    impl PredicateTrait<&Value> for ValuePredicate {
        type EvaluatesTo = bool;

        fn applies(&self, input: &Value) -> Self::EvaluatesTo {
            // Large jump table. Do not inline.
            match self {
                ValuePredicate::Identifiable(pred) => match input {
                    Value::String(s) => pred.applies(s),
                    Value::Name(n) => pred.applies(n),
                    Value::Id(id_box) => pred.applies(id_box),
                    Value::Identifiable(identifiable_box) => {
                        pred.applies(&identifiable_box.id_box())
                    }
                    _ => false,
                },
                ValuePredicate::Container(Container::Any(pred)) => match input {
                    Value::Vec(vec) => vec.iter().any(|val| pred.applies(val)),
                    Value::LimitedMetadata(map) => {
                        map.iter().map(|(_, val)| val).any(|val| pred.applies(val))
                    }
                    _ => false,
                },
                ValuePredicate::Container(Container::All(pred)) => match input {
                    Value::Vec(vec) => vec.iter().all(|val| pred.applies(val)),
                    Value::LimitedMetadata(map) => {
                        map.iter().map(|(_, val)| val).all(|val| pred.applies(val))
                    }
                    _ => false,
                },
                ValuePredicate::Container(Container::AtIndex(AtIndex {
                    index: idx,
                    predicate: pred,
                })) => match input {
                    Value::Vec(vec) => vec
                        .get(*idx as usize) // Safe, since this is only executed server-side and servers are 100% going to be 64-bit.
                        .map_or(false, |val| pred.applies(val)),
                    _ => false,
                },
                ValuePredicate::Container(Container::ValueOfKey(ValueOfKey {
                    key,
                    predicate: pred,
                })) => {
                    match input {
                        Value::LimitedMetadata(map) => {
                            map.get(key).map_or(false, |val| pred.applies(val))
                        }
                        _ => false, // TODO: Do we need more?
                    }
                }
                ValuePredicate::Container(Container::HasKey(key)) => match input {
                    Value::LimitedMetadata(map) => map.contains(key),
                    _ => false,
                },
                ValuePredicate::Numerical(pred) => pred.applies(input),
                ValuePredicate::Display(pred) => pred.applies(&input.to_string()),
                ValuePredicate::TimeStamp(pred) => match input {
                    Value::Block(block) => {
                        pred.applies(block.payload().header.timestamp().as_millis())
                    }
                    _ => false,
                },
                ValuePredicate::Ipv4Addr(pred) => match input {
                    Value::Ipv4Addr(addr) => pred.applies(*addr),
                    _ => false,
                },
                ValuePredicate::Ipv6Addr(pred) => match input {
                    Value::Ipv6Addr(addr) => pred.applies(*addr),
                    _ => false,
                },
                ValuePredicate::Pass => true,
            }
        }
    }

    impl ValuePredicate {
        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn any(pred: impl Into<ValuePredicate>) -> Self {
            Self::Container(Container::Any(Box::new(pred.into())))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn all(pred: impl Into<ValuePredicate>) -> Self {
            Self::Container(Container::All(Box::new(pred.into())))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn has_key(key: Name) -> Self {
            Self::Container(Container::HasKey(key))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn value_of(key: Name, pred: impl Into<ValuePredicate>) -> Self {
            Self::Container(Container::ValueOfKey(ValueOfKey {
                key,
                predicate: Box::new(pred.into()),
            }))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn at_index(index: u32, pred: impl Into<ValuePredicate>) -> Self {
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
        predicate: Box<ValuePredicate>,
    }

    /// A predicate that targets the particular `key` of a collection.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub struct ValueOfKey {
        key: Name,
        predicate: Box<ValuePredicate>,
    }

    /// Predicate that targets specific elements or groups; useful for
    /// working with containers. Currently only
    /// [`Metadata`](crate::metadata::Metadata) and [`Vec<Value>`] are
    /// supported.
    #[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema)]
    pub enum Container {
        /// Forward to [`Iterator::any`]
        Any(Box<ValuePredicate>),
        /// Forward to [`Iterator::all`]
        All(Box<ValuePredicate>),
        /// Apply predicate to the [`Value`] element at the index.
        AtIndex(AtIndex),
        /// Apply the predicate to the [`Value`] keyed by the index.
        ValueOfKey(ValueOfKey),
        /// Forward to [`Metadata::contains`](crate::metadata::Metadata::contains()).
        HasKey(Name),
    }

    impl From<ValuePredicate> for PredicateBox {
        fn from(value: ValuePredicate) -> Self {
            PredicateBox::Raw(value)
        }
    }

    #[cfg(test)]
    #[allow(clippy::print_stdout, clippy::use_debug)]
    mod test {
        use peer::Peer;
        use prelude::Metadata;

        use super::*;
        use crate::account::Account;

        #[test]
        fn typing() {
            {
                let pred =
                    ValuePredicate::Identifiable(string::StringPredicate::is("alice@wonderland"));
                println!("{pred:?}");
                assert!(pred.applies(&Value::String("alice@wonderland".to_owned())));
                assert!(pred.applies(&Value::Id(IdBox::AccountId(
                    "alice@wonderland".parse().expect("Valid")
                ))));
                assert!(
                    pred.applies(&Value::Identifiable(IdentifiableBox::NewAccount(
                        Account::new("alice@wonderland".parse().expect("Valid"), [])
                    )))
                );
                assert!(!pred.applies(&Value::Name("alice".parse().expect("Valid"))));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
            }
            {
                let pred = ValuePredicate::Pass;
                println!("{pred:?}");
                assert!(pred.applies(&Value::String("alice@wonderland".to_owned())));
            }
            {
                let pred = ValuePredicate::TimeStamp(numerical::SemiInterval::starting(0));
                println!("{pred:?}");
                assert!(!pred.applies(&Value::String("alice@wonderland".to_owned())));
            }
            {
                let key_pair = iroha_crypto::KeyPair::generate().expect("Should not fail");
                let (public_key, _) = key_pair.into();
                let pred = ValuePredicate::Display(string::StringPredicate::is("alice@wonderland"));
                println!("{pred:?}");

                assert!(
                    !pred.applies(&Value::Identifiable(IdentifiableBox::Peer(Peer {
                        id: peer::PeerId {
                            address: "localhost:123".parse().unwrap(),
                            public_key
                        }
                    })))
                );
            }
            let pred = ValuePredicate::Numerical(numerical::SemiRange::U32((0_u32, 42_u32).into()));
            assert!(!pred.applies(&Value::String("alice".to_owned())));
            assert!(pred.applies(&41_u32.to_value()));
        }

        #[test]
        fn container_vec() {
            let list = Value::Vec(vec![
                Value::String("alice".to_owned()),
                Value::Name("alice_at_wonderland".parse().expect("Valid")),
                Value::String("aliceee!".to_owned()),
            ]);
            let meta = Value::LimitedMetadata(Metadata::default());
            let alice = Value::Name("alice".parse().expect("Valid"));

            let alice_pred = ValuePredicate::Display(string::StringPredicate::contains("alice"));

            {
                let pred = ValuePredicate::any(alice_pred.clone());
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
                assert!(!pred.applies(&meta));
                assert!(!pred.applies(&alice));
            }

            {
                let pred = ValuePredicate::all(alice_pred.clone());
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(pred.applies(&Value::Vec(Vec::new())));
                assert!(pred.applies(&meta)); // Not bug. Same convention as std lib.
                assert!(!pred.applies(&alice));
            }

            {
                let alice_id_pred =
                    ValuePredicate::Identifiable(string::StringPredicate::contains("alice"));
                let pred = ValuePredicate::all(alice_id_pred);
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(pred.applies(&Value::Vec(Vec::new())));
                assert!(pred.applies(&meta)); // Not bug. Same convention as std lib.
                assert!(!pred.applies(&alice));
            }

            assert!(ValuePredicate::at_index(0, alice_pred.clone()).applies(&list));

            let idx_pred = ValuePredicate::at_index(3, alice_pred); // Should be out of bounds.
            println!("{idx_pred:?}");
            assert!(!idx_pred.applies(&list));
            assert!(!idx_pred.applies(&meta));
            assert!(!idx_pred.applies(&alice));

            let has_key = ValuePredicate::has_key("alice".parse().expect("Valid"));
            println!("{has_key:?}");
            assert!(!has_key.applies(&list));
            assert!(!has_key.applies(&meta));
            // TODO: case with non-empty meta

            let value_key = ValuePredicate::value_of("alice".parse().expect("Valid"), has_key);
            println!("{value_key:?}");
            assert!(!value_key.applies(&list));
            assert!(!value_key.applies(&meta));
            // TODO: case with non-empty meta
        }
    }
}

pub mod ip_addr {
    //! Predicates for IP address processing.
    use iroha_primitives::addr::{Ipv4Addr, Ipv6Addr};

    use super::{numerical::Interval as Mask, *};

    /// A Predicate containing independent octuplet masks to be
    /// applied to all elements of an IP version 4 address.
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    pub struct Ipv4Predicate([Mask<u8>; 4]);

    impl PredicateTrait<Ipv4Addr> for Ipv4Predicate {
        type EvaluatesTo = bool;

        fn applies(&self, input: Ipv4Addr) -> Self::EvaluatesTo {
            self.0
                .iter()
                .copied()
                .zip(input.into_iter())
                .all(|(myself, other)| myself.applies(other))
        }
    }

    impl Ipv4Predicate {
        /// Construct a new predicate.
        pub fn new(
            octet_0: impl Into<Mask<u8>>,
            octet_1: impl Into<Mask<u8>>,
            octet_2: impl Into<Mask<u8>>,
            octet_3: impl Into<Mask<u8>>,
        ) -> Self {
            Self([
                octet_0.into(),
                octet_1.into(),
                octet_2.into(),
                octet_3.into(),
            ])
        }
    }

    /// A Predicate containing independent _hexadecuplets_ (u16
    /// groups) masks to be applied to all elements of an IP version 6
    /// address.
    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, Deserialize, Serialize, IntoSchema,
    )]
    pub struct Ipv6Predicate([Mask<u16>; 8]);

    impl PredicateTrait<Ipv6Addr> for Ipv6Predicate {
        type EvaluatesTo = bool;

        fn applies(&self, input: Ipv6Addr) -> Self::EvaluatesTo {
            self.0
                .iter()
                .copied()
                .zip(input.into_iter())
                .all(|(myself, other)| myself.applies(other))
        }
    }

    // Could do this with a macro, but it doesn't seem to shorten much.
    #[allow(clippy::too_many_arguments)]
    impl Ipv6Predicate {
        /// Construct a new predicate. The 8 arguments must match a
        /// mask that filters on all 8 of the _hexadecuplets_ (u16
        /// groups) in a normal IP version 6 address.
        pub fn new(
            hexadecuplet_0: impl Into<Mask<u16>>,
            hexadecuplet_1: impl Into<Mask<u16>>,
            hexadecuplet_2: impl Into<Mask<u16>>,
            hexadecuplet_3: impl Into<Mask<u16>>,
            hexadecuplet_4: impl Into<Mask<u16>>,
            hexadecuplet_5: impl Into<Mask<u16>>,
            hexadecuplet_6: impl Into<Mask<u16>>,
            hexadecuplet_7: impl Into<Mask<u16>>,
        ) -> Self {
            Self([
                hexadecuplet_0.into(),
                hexadecuplet_1.into(),
                hexadecuplet_2.into(),
                hexadecuplet_3.into(),
                hexadecuplet_4.into(),
                hexadecuplet_5.into(),
                hexadecuplet_6.into(),
                hexadecuplet_7.into(),
            ])
        }
    }

    #[cfg(test)]
    mod test {
        #![allow(clippy::restriction)]
        use super::*;

        #[test]
        fn ipv4_filter_example() {
            {
                let pred = Ipv4Predicate::new(127, 0, 0, (0, 10));
                println!("{pred:?}");
                assert!(pred.applies(Ipv4Addr::from([127, 0, 0, 1])));
                assert!(pred.applies(Ipv4Addr::from([127, 0, 0, 3])));
                assert!(pred.applies(Ipv4Addr::from([127, 0, 0, 4])));
                assert!(pred.applies(Ipv4Addr::from([127, 0, 0, 10])));
                assert!(!pred.applies(Ipv4Addr::from([127, 0, 0, 11])));
                assert!(!pred.applies(Ipv4Addr::from([125, 0, 0, 1])));
                assert!(!pred.applies(Ipv4Addr::from([128, 0, 0, 1])));
                assert!(!pred.applies(Ipv4Addr::from([127, 1, 0, 1])));
                assert!(!pred.applies(Ipv4Addr::from([127, 0, 1, 1])));
            }

            {
                let pred = Ipv4Predicate::new(Mask::starting(0), 0, 0, (0, 10));
                println!("{pred:?}");
                assert!(pred.applies(Ipv4Addr::from([0, 0, 0, 1])));
                assert!(pred.applies(Ipv4Addr::from([255, 0, 0, 1])));
                assert!(pred.applies(Ipv4Addr::from([127, 0, 0, 4])));
                assert!(pred.applies(Ipv4Addr::from([127, 0, 0, 10])));
                assert!(pred.applies(Ipv4Addr::from([128, 0, 0, 1])));
                assert!(pred.applies(Ipv4Addr::from([128, 0, 0, 1])));
                assert!(!pred.applies(Ipv4Addr::from([127, 0, 0, 11])));
                assert!(pred.applies(Ipv4Addr::from([126, 0, 0, 1])));
                assert!(pred.applies(Ipv4Addr::from([128, 0, 0, 1])));
                assert!(!pred.applies(Ipv4Addr::from([127, 1, 0, 1])));
                assert!(!pred.applies(Ipv4Addr::from([127, 0, 1, 1])));
            }
        }

        #[test]
        fn ipv6_filter_example() {
            let pred = Ipv6Predicate::new(12700, 0, 0, (0, 10), 0, 0, 0, 0);
            println!("{pred:?}");
            assert!(pred.applies(Ipv6Addr::from([12700, 0, 0, 1, 0, 0, 0, 0])));
            assert!(pred.applies(Ipv6Addr::from([12700, 0, 0, 3, 0, 0, 0, 0])));
            assert!(pred.applies(Ipv6Addr::from([12700, 0, 0, 4, 0, 0, 0, 0])));
            assert!(pred.applies(Ipv6Addr::from([12700, 0, 0, 10, 0, 0, 0, 0])));
            assert!(!pred.applies(Ipv6Addr::from([12700, 0, 0, 11, 0, 0, 0, 0])));
            assert!(!pred.applies(Ipv6Addr::from([12500, 0, 0, 1, 0, 0, 0, 0])));
            assert!(!pred.applies(Ipv6Addr::from([12800, 0, 0, 1, 0, 0, 0, 0])));
            assert!(!pred.applies(Ipv6Addr::from([12700, 1, 0, 1, 0, 0, 0, 0])));
            assert!(!pred.applies(Ipv6Addr::from([12700, 0, 1, 1, 0, 0, 0, 0])));
        }
    }
}
