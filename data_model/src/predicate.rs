//! Predicate-related logic. Should contain predicate-related `impl`s.

#[cfg(not(feature = "std"))]
use alloc::vec;

use super::*;
use crate::{IdBox, Name, Value};

/// Predicate combinator enum.
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
pub enum PredicateBox {
    /// Logically `&&` the results of applying the two predicates.
    And(Vec<PredicateBox>),
    /// Logically `||` the results of applying the two predicates.
    Or(Vec<PredicateBox>),
    /// Negate the result of applying the predicate.
    Not(Box<PredicateBox>),
    /// The raw predicate that must be applied.
    Raw(value::Predicate),
}

impl PredicateBox {
    /// Construct [`PredicateBox::Raw`] variant.
    #[inline]
    pub fn new(pred: impl Into<value::Predicate>) -> Self {
        Self::Raw(pred.into())
    }

    /// Construct [`PredicateBox::And`] variant.
    #[inline]
    pub fn and(left: impl Into<PredicateBox>, right: impl Into<PredicateBox>) -> Self {
        Self::And(vec![left.into(), right.into()])
    }

    /// Construct [`PredicateBox::Or`] variant.
    #[inline]
    pub fn or(left: impl Into<PredicateBox>, right: impl Into<PredicateBox>) -> Self {
        Self::Or(vec![left.into(), right.into()])
    }

    /// Convert instance into its negation.
    #[must_use]
    #[inline]
    pub fn negate(self) -> Self {
        match self {
            Self::And(preds) => Self::Or(preds.into_iter().map(Self::negate).collect()),
            Self::Or(preds) => Self::And(preds.into_iter().map(Self::negate).collect()),
            Self::Not(pred) => *pred, // TODO: should we recursively simplify?
            Self::Raw(pred) => Self::Not(Box::new(PredicateBox::Raw(pred))),
        }
    }

    #[must_use]
    #[inline]
    /// Filter [`Value`] using `self`.
    pub fn filter(&self, value: Value) -> Value {
        match value {
            Value::Vec(v) => Value::Vec(v.into_iter().filter(|val| self.applies(val)).collect()),
            other => other,
            // We're not handling the LimitedMetadata case, because
            // the predicate when applied to it is ambiguous. We could
            // pattern match on that case, but we should assume that
            // metadata (since it's limited) isn't going to be too
            // difficult to filter client-side. I actually think that
            // Metadata should be restricted in what types it can
            // contain.
        }
    }
}

impl Default for PredicateBox {
    fn default() -> Self {
        PredicateBox::Raw(value::Predicate::Pass)
    }
}

impl PredicateTrait<Value> for PredicateBox {
    #[inline] // This is not a simple function, but it allows you to inline the logic and optimise away the logical operations.
    fn applies(&self, input: &Value) -> bool {
        match self {
            PredicateBox::And(vector) => vector.iter().all(|pred| pred.applies(input)),
            PredicateBox::Or(vector) => vector.iter().any(|pred| pred.applies(input)),
            PredicateBox::Not(predicate) => !predicate.applies(input),
            PredicateBox::Raw(predicate) => predicate.applies(input),
        }
    }
}

#[cfg(test)]
pub mod test {
    #![allow(clippy::print_stdout, clippy::use_debug)]

    use super::{value, PredicateBox};
    use crate::{PredicateTrait as _, Value};

    #[test]
    fn pass() {
        let t = PredicateBox::new(value::Predicate::Pass);
        let f = t.clone().negate();
        let v_t = Value::from(true);
        let v_f = Value::from(false);
        println!("t: {t:?}, f: {f:?}");

        assert!(t.applies(&v_t));
        assert!(t.applies(&v_f));
        assert!(!f.applies(&v_t));
        assert!(!f.applies(&v_f));
    }

    #[test]
    fn truth_table() {
        let t = PredicateBox::new(value::Predicate::Pass);
        let f = t.clone().negate();
        let v = Value::from(true);

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
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub enum Predicate {
        /// Forward to [`str::contains()`]
        Contains(String),
        /// Forward to [`str::starts_with()`]
        StartsWith(String),
        /// Forward to [`str::ends_with()`]
        EndsWith(String),
        /// Forward to [`String`] equality.
        Is(String),
    }

    impl Predicate {
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

    impl<T: AsRef<str> + ?Sized> PredicateTrait<T> for Predicate {
        #[inline] // Jump table. Needs inline.
        fn applies(&self, input: &T) -> bool {
            match self {
                Predicate::Contains(content) => input.as_ref().contains(content),
                Predicate::StartsWith(content) => input.as_ref().starts_with(content),
                Predicate::EndsWith(content) => input.as_ref().ends_with(content),
                Predicate::Is(content) => *(input.as_ref()) == *content,
            }
        }
    }

    impl PredicateTrait<IdBox> for Predicate {
        #[inline] // Jump table. Needs inline.
        fn applies(&self, input: &IdBox) -> bool {
            match input {
                IdBox::DomainId(id) => self.applies(&id.to_string()),
                IdBox::AccountId(id) => self.applies(&id.to_string()),
                IdBox::AssetDefinitionId(id) => self.applies(&id.to_string()),
                IdBox::AssetId(id) => self.applies(&id.to_string()),
                IdBox::PeerId(id) => self.applies(&id.to_string()),
                IdBox::TriggerId(id) => self.applies(&id.to_string()),
                IdBox::RoleId(id) => self.applies(&id.to_string()),
                IdBox::PermissionTokenDefinitionId(id) => self.applies(&id.to_string()),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::expect_used)]

        use super::*;

        mod id_box {
            use super::*;

            #[test]
            fn simple_name_wrappers() {
                let starts_with = Predicate::starts_with("Curiouser");
                let contains = Predicate::contains("Curiouser");
                let ends_with = Predicate::ends_with("Curiouser");
                let pred_is = Predicate::is("Curiouser");

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
                let starts_with = Predicate::starts_with("Curiouser");
                let contains = Predicate::contains("Curiouser"); //
                let ends_with = Predicate::ends_with("Curiouser");
                let pred_is = Predicate::is("Curiouser");

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
                assert!(Predicate::starts_with("alice@").applies(&id));
                assert!(Predicate::ends_with("@wonderland").applies(&id));
                assert!(Predicate::is("alice@wonderland").applies(&id));
                // Should we also include a check into string
                // predicates? If the internal predicate starts with
                // whitespace, it can't possibly match any Id, but
                // there's no way to enforce this at both type leve
                // and run-time.
                assert!(!Predicate::starts_with(" alice@").applies(&id));
                assert!(!Predicate::ends_with("@wonderland ").applies(&id));
                assert!(!Predicate::is("alice@@wonderland ").applies(&id));
                assert!(!Predicate::contains("#").applies(&id));
                assert!(!Predicate::is("alice#wonderland").applies(&id));
            }

            #[test]
            fn asset_id() {
                let definition_id = "rose#wonderland".parse().expect("Valid");
                let account_id = "alice@wonderland".parse().expect("Valid");
                let id = IdBox::AssetId(crate::asset::Id {
                    definition_id,
                    account_id,
                });
                assert!(Predicate::starts_with("rose#wonderland").applies(&id));
                assert!(Predicate::ends_with("@alice@wonderland").applies(&id));
                assert!(Predicate::is("rose#wonderland@alice@wonderland").applies(&id)); // Feels weird
                assert!(Predicate::contains("wonderland@alice").applies(&id));
            }

            #[test]
            fn asset_def_id() {
                let id = IdBox::AssetDefinitionId("rose#wonderland".parse().expect("Valid"));
                assert!(Predicate::starts_with("rose#").applies(&id));
                assert!(Predicate::ends_with("#wonderland").applies(&id));
                assert!(Predicate::is("rose#wonderland").applies(&id));
                // Should we also include a check into string
                // predicates? If the internal predicate starts with
                // whitespace, it can't possibly match any Id, but
                // there's no way to enforce this at both type leve
                // and run-time.
                assert!(!Predicate::starts_with(" rose#").applies(&id));
                assert!(!Predicate::ends_with("#wonderland ").applies(&id));
                assert!(!Predicate::is("alice##wonderland ").applies(&id));
                assert!(!Predicate::contains("@").applies(&id));
                assert!(!Predicate::is("rose@wonderland").applies(&id));
            }

            #[test]
            fn peer_id() {
                let (public_key, _) = iroha_crypto::KeyPair::generate()
                    .expect("Should not panic")
                    .into();
                let id = IdBox::PeerId(peer::Id {
                    address: "123".to_owned(),
                    public_key,
                });
                assert!(Predicate::contains("123").applies(&id));
            }
        }

        mod string {
            use super::*;

            #[test]
            fn contains() {
                let pred = Predicate::Contains("believed as many".to_owned());
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
                let pred = Predicate::StartsWith("Curiouser".to_owned());
                assert!(pred.applies("Curiouser and Curiouser"));
                assert!(!pred.applies(" Curiouser and Curiouser"));
                assert!(!pred.applies("curiouser and curiouser"));
                assert!(!pred.applies("More Curiouser"));
                assert!(!pred.applies("Curiouse"));
            }

            #[test]
            fn ends_with() {
                let pred = Predicate::EndsWith("How long is forever?".to_owned());
                assert!(pred.applies("How long is forever?"));
                assert!(!pred.applies("how long is forever?"));
                assert!(pred.applies(" How long is forever?"));
                assert!(pred.applies("I asked: How long is forever?"));
                assert!(!pred.applies("How long is forever"));
            }

            #[test]
            fn is() {
                let pred = Predicate::Is("writing-desk".to_owned());
                assert!(!pred.applies("Why is a raven like a writing-desk"));
                assert!(pred.applies("writing-desk"));
                assert!(!pred.applies("Writing-desk"));
                assert!(!pred.applies("writing-des"));
            }

            #[test]
            fn empty_predicate() {
                let pred = Predicate::contains("");
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
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
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

    /// General purpose predicate for working with Iroha numerical
    /// types.
    ///
    /// # Type checking
    ///
    /// [`Self`] only applies to `Values` that have the same type. If
    /// the type of the `Range` and the type of the type do not match,
    /// it will default to `false`.
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub enum Range {
        /// 32-bit
        U32(SemiInterval<u32>),
        /// 128-bit
        U128(SemiInterval<u128>),
        /// Fixed-precision
        Fixed(SemiInterval<Fixed>),
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

    impl UnsignedMarker for u32 {
        const MAX: Self = Self::MAX;
        const ZERO: Self = 0_u32;
    }

    impl UnsignedMarker for u128 {
        const MAX: Self = Self::MAX;
        const ZERO: Self = 0_u128;
    }

    impl UnsignedMarker for Fixed {
        const MAX: Self = Fixed::MAX;
        const ZERO: Self = Fixed::ZERO;
    }

    impl<T: Copy + Ord + UnsignedMarker> SemiInterval<T> {
        /// Construct a semi-interval starting at
        #[inline]
        #[must_use]
        pub fn starting(start: T) -> Self {
            Self {
                start,
                limit: T::MAX,
            }
        }

        /// Construct a semi-interval that ends at
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
        #[inline]
        fn applies(&self, input: &T) -> bool {
            *input < self.limit && *input >= self.start
        }
    }

    impl PredicateTrait<Value> for Range {
        #[inline]
        fn applies(&self, input: &Value) -> bool {
            match input {
                Value::U32(quantity) => match self {
                    Range::U32(predicate) => predicate.applies(quantity),
                    _ => false,
                },
                Value::U128(big_quantity) => match self {
                    Range::U128(predicate) => predicate.applies(big_quantity),
                    _ => false,
                },
                Value::Fixed(fixd) => match self {
                    Range::Fixed(predicate) => predicate.applies(fixd),
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
            use Value::U32;
            let pred = Range::U32((1_u32, 100_u32).into());
            println!("semi_interval range predicate: {pred:?}");

            assert!(pred.applies(&U32(1_u32)));
            assert!(!pred.applies(&U32(0_u32)));
            assert!(pred.applies(&U32(99_u32)));
            assert!(!pred.applies(&U32(100_u32)));
        }

        #[test]
        fn semi_interval_semantics_u128() {
            use Value::U128;
            let pred = Range::U128((1_u128, 100_u128).into());

            assert!(pred.applies(&U128(1_u128)));
            assert!(!pred.applies(&U128(0_u128)));
            assert!(pred.applies(&U128(99_u128)));
            assert!(!pred.applies(&U128(100_u128)));
        }

        #[test]
        #[allow(clippy::panic_in_result_fn)] // ? for syntax simplicity.
        fn semi_interval_semantics_fixed() -> Result<(), fixed::FixedPointOperationError> {
            let pred = Range::Fixed((Fixed::try_from(1_f64)?, Fixed::try_from(100_f64)?).into());

            assert!(pred.applies(&Value::Fixed(Fixed::try_from(1_f64)?)));
            assert!(!pred.applies(&Value::Fixed(Fixed::try_from(0.99_f64)?)));
            assert!(pred.applies(&Value::Fixed(Fixed::try_from(99.9999_f64)?)));
            assert!(!pred.applies(&Value::Fixed(Fixed::try_from(99.999_999_999_9_f64)?))); // Rounding is still a problem.
            Ok(())
        }

        #[test]
        fn invalid_types_false() {
            {
                let pred = Range::U32((0_u32, 100_u32).into());
                assert!(!pred.applies(&Value::U128(0_u128)));
                assert!(!pred.applies(&Value::Fixed(Fixed::ZERO)));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
            }
            let pred = Range::U128(SemiInterval::starting(0_u128));
            assert!(!pred.applies(&Value::U32(0_u32)));
        }

        #[test]
        fn upper_bounds() {
            {
                let pred = Range::Fixed(SemiInterval::starting(Fixed::ZERO));
                // Technically the maximum itself is never included in the range.
                assert!(!pred.applies(&Value::Fixed(Fixed::MAX)));
            }
            let pred = Range::U32(SemiInterval::ending(100_u32));
            assert!(pred.applies(&Value::U32(0_u32)));
            assert!(pred.applies(&Value::U32(99_u32)));
            assert!(!pred.applies(&Value::U32(100_u32)));
        }
    }
}

pub mod value {
    //!  raw predicates applied to `Value`.
    use super::*;

    /// A predicate designed for general processing of `Value`.
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub enum Predicate {
        /// Apply predicate to the [`Identifiable::Id`] and/or [`IdBox`].
        Identifiable(string::Predicate),
        /// Apply predicate to the container.
        Container(Container),
        /// Apply predicate to the [`<Value as Display>::to_string`](ToString::to_string()) representation.
        Display(string::Predicate),
        /// Apply predicate to the numerical value.
        Numerical(numerical::Range),
        /// Timestamp (currently for `BlockValue` only).
        TimeStamp(numerical::SemiInterval<u128>),
        /// Always return true.
        Pass,
    }

    impl PredicateTrait<Value> for Predicate {
        fn applies(&self, input: &Value) -> bool {
            // Large jump table. Do not inline.
            match self {
                Predicate::Identifiable(pred) => match input {
                    Value::String(s) => pred.applies(s),
                    Value::Name(n) => pred.applies(n),
                    Value::Id(id_box) => pred.applies(id_box),
                    Value::Identifiable(identifiable_box) => {
                        pred.applies(&identifiable_box.id_box())
                    }
                    _ => false,
                },
                Predicate::Container(Container::Any(pred)) => match input {
                    Value::Vec(vec) => vec.iter().any(|val| pred.applies(val)),
                    Value::LimitedMetadata(map) => {
                        map.iter().map(|(_, val)| val).any(|val| pred.applies(val))
                    }
                    _ => false,
                },
                Predicate::Container(Container::All(pred)) => match input {
                    Value::Vec(vec) => vec.iter().all(|val| pred.applies(val)),
                    Value::LimitedMetadata(map) => {
                        map.iter().map(|(_, val)| val).all(|val| pred.applies(val))
                    }
                    _ => false,
                },
                Predicate::Container(Container::AtIndex(AtIndex {
                    index: idx,
                    predicate: pred,
                })) => match input {
                    Value::Vec(vec) => vec
                        .get(*idx as usize) // Safe, since this is only executed server-side and servers are 100% going to be 64-bit.
                        .map_or(false, |val| pred.applies(val)),
                    _ => false,
                },
                Predicate::Container(Container::ValueOfKey(ValueOfKey {
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
                Predicate::Container(Container::HasKey(key)) => match input {
                    Value::LimitedMetadata(map) => map.contains(key),
                    _ => false,
                },
                Predicate::Numerical(pred) => pred.applies(input),
                Predicate::Display(pred) => pred.applies(&input.to_string()),
                Predicate::TimeStamp(pred) => match input {
                    Value::Block(block) => pred.applies(&block.header.timestamp),
                    _ => false,
                },
                Predicate::Pass => true,
            }
        }
    }

    impl Predicate {
        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn any(pred: impl Into<Predicate>) -> Self {
            Self::Container(Container::Any(Box::new(pred.into())))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn all(pred: impl Into<Predicate>) -> Self {
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
        pub fn value_of(key: Name, pred: impl Into<Predicate>) -> Self {
            Self::Container(Container::ValueOfKey(ValueOfKey {
                key,
                predicate: Box::new(pred.into()),
            }))
        }

        /// Construct [`Predicate::Container`] variant.
        #[inline]
        #[must_use]
        pub fn at_index(index: u32, pred: impl Into<Predicate>) -> Self {
            Self::Container(Container::AtIndex(AtIndex {
                index,
                predicate: Box::new(pred.into()),
            }))
        }
    }

    /// A predicate that targets the particular `index` of a collection.
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub struct AtIndex {
        index: u32,
        predicate: Box<Predicate>,
    }

    /// A predicate that targets the particular `key` of a collection.
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub struct ValueOfKey {
        key: Name,
        predicate: Box<Predicate>,
    }

    /// Predicate that targets specific elements or groups; useful for
    /// working with containers. Currently only
    /// [`Metadata`](crate::metadata::Metadata) and [`Vec<Value>`] are
    /// supported.
    #[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, IntoSchema)]
    pub enum Container {
        /// Forward to [`Iterator::any`]
        Any(Box<Predicate>),
        /// Forward to [`Iterator::all`]
        All(Box<Predicate>),
        /// Apply predicate to the [`Value`] element at the index.
        AtIndex(AtIndex),
        /// Apply the predicate to the [`Value`] keyed by the index.
        ValueOfKey(ValueOfKey),
        /// Forward to [`Metadata::contains`](crate::metadata::Metadata::contains()).
        HasKey(Name),
    }

    #[cfg(test)]
    #[allow(clippy::print_stdout, clippy::use_debug, clippy::expect_used)]
    mod test {
        use peer::Peer;
        use prelude::Metadata;

        use super::*;
        use crate::account::Account;

        #[test]
        fn typing() {
            {
                let pred = Predicate::Identifiable(string::Predicate::is("alice@wonderland"));
                println!("{pred:?}");
                assert!(pred.applies(&Value::String("alice@wonderland".to_owned())));
                assert!(pred.applies(&Value::Id(IdBox::AccountId(
                    "alice@wonderland".parse().expect("Valid")
                ))));
                assert!(
                    pred.applies(&Value::Identifiable(IdentifiableBox::NewAccount(Box::new(
                        Account::new("alice@wonderland".parse().expect("Valid"), [])
                    ))))
                );
                assert!(!pred.applies(&Value::Name("alice".parse().expect("Valid"))));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
            }
            {
                let pred = Predicate::Pass;
                println!("{pred:?}");
                assert!(pred.applies(&Value::String("alice@wonderland".to_owned())));
            }
            {
                let pred = Predicate::TimeStamp(numerical::SemiInterval::starting(0));
                println!("{pred:?}");
                assert!(!pred.applies(&Value::String("alice@wonderland".to_owned())));
            }
            {
                let key_pair = iroha_crypto::KeyPair::generate().expect("Should not fail");
                let (public_key, _) = key_pair.into();
                let pred = Predicate::Display(string::Predicate::is("alice@wonderland"));
                println!("{pred:?}");

                assert!(
                    !pred.applies(&Value::Identifiable(IdentifiableBox::Peer(Box::new(
                        Peer {
                            id: peer::Id {
                                address: "123".to_owned(),
                                public_key
                            }
                        }
                    ))))
                );
            }
            let pred = Predicate::Numerical(numerical::Range::U32((0_u32, 42_u32).into()));
            assert!(!pred.applies(&Value::String("alice".to_owned())));
            assert!(pred.applies(&Value::U32(41_u32)));
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

            let alice_pred = Predicate::Display(string::Predicate::contains("alice"));

            {
                let pred = Predicate::any(alice_pred.clone());
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(!pred.applies(&Value::Vec(Vec::new())));
                assert!(!pred.applies(&meta));
                assert!(!pred.applies(&alice));
            }

            {
                let pred = Predicate::all(alice_pred.clone());
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(pred.applies(&Value::Vec(Vec::new())));
                assert!(pred.applies(&meta)); // Not bug. Same convention as std lib.
                assert!(!pred.applies(&alice));
            }

            {
                let alice_id_pred = Predicate::Identifiable(string::Predicate::contains("alice"));
                let pred = Predicate::all(alice_id_pred);
                println!("{pred:?}");
                assert!(pred.applies(&list));
                assert!(pred.applies(&Value::Vec(Vec::new())));
                assert!(pred.applies(&meta)); // Not bug. Same convention as std lib.
                assert!(!pred.applies(&alice));
            }

            assert!(Predicate::at_index(0, alice_pred.clone()).applies(&list));

            let idx_pred = Predicate::at_index(3, alice_pred); // Should be out of bounds.
            println!("{idx_pred:?}");
            assert!(!idx_pred.applies(&list));
            assert!(!idx_pred.applies(&meta));
            assert!(!idx_pred.applies(&alice));

            let has_key = Predicate::has_key("alice".parse().expect("Valid"));
            println!("{has_key:?}");
            assert!(!has_key.applies(&list));
            assert!(!has_key.applies(&meta));
            // TODO: case with non-empty meta

            let value_key = Predicate::value_of("alice".parse().expect("Valid"), has_key);
            println!("{value_key:?}");
            assert!(!value_key.applies(&list));
            assert!(!value_key.applies(&meta));
            // TODO: case with non-empty meta
        }
    }
}
