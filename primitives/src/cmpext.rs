//! Utilities to work with [`BTreeMap`]/[`BTreeSet`] `get`/`range` functions.

use core::cmp::Ordering;

/// Type which adds two additional values for any type:
/// - `Min` which is smaller that any value of this type
/// - `Max` which is greater that any value of this type
///
/// Used to enable query over prefix of the given key in the b-tree e.g. by account id in the asset id.
///
/// Suppose compound key of three parts: `K = (A, B, C)`.
/// So that in sorting order keys will be sorted firstly by `A` then `B` and `C`.
/// This keys are stored in `BTreeMap` and it's required to extract all keys which have `A == a`.
/// To do this it's possible to use `range` provided by `BTreeMap`,
/// but it would't be enough to simply use `(a..=a)` bound for `K` because ranges bounds are found by binary search
/// and this way any key which has `A == a` can be treated as bound.
/// So `MinMaxExt` is used to express precise bound for such query: `(a, MIN, MIN)..(a, MAX, MAX)`.
#[derive(Debug, Clone, Copy)]
pub enum MinMaxExt<T> {
    /// Value that is greater than any value
    Min,
    /// Value that is smaller than any value
    Max,
    /// Regular value
    Value(T),
}

impl<T: PartialEq> PartialEq for MinMaxExt<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Value(lhs), Self::Value(rhs)) => lhs.eq(rhs),
            (Self::Min, Self::Min) | (Self::Max, Self::Max) => true,
            _ => false,
        }
    }
}

impl<T: Eq> Eq for MinMaxExt<T> {}

impl<T: PartialOrd> PartialOrd for MinMaxExt<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match (self, other) {
            (Self::Value(lhs), Self::Value(rhs)) => lhs.partial_cmp(rhs),
            (lhs, rhs) if lhs == rhs => Some(Ordering::Equal),
            (Self::Min, _) | (_, Self::Max) => Some(Ordering::Less),
            (Self::Max, _) | (_, Self::Min) => Some(Ordering::Greater),
        }
    }
}

impl<T: Ord> Ord for MinMaxExt<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Value(lhs), Self::Value(rhs)) => lhs.cmp(rhs),
            (lhs, rhs) if lhs == rhs => Ordering::Equal,
            (Self::Min, _) | (_, Self::Max) => Ordering::Less,
            (Self::Max, _) | (_, Self::Min) => Ordering::Greater,
        }
    }
}

impl<T> From<T> for MinMaxExt<T> {
    fn from(value: T) -> Self {
        MinMaxExt::Value(value)
    }
}

/// Helper macro to enable cast of key to dyn object and derive required traits for it.
/// Used to bypass limitation of [`Borrow`] which wouldn't allow to create object and return reference to it.
#[macro_export]
macro_rules! impl_as_dyn_key {
    (target: $ty:ident, key: $key:ty, trait: $trait:ident) => {
        /// Trait to key from type
        pub trait $trait {
            /// Extract key
            fn as_key(&self) -> $key;
        }

        impl $trait for $key {
            fn as_key(&self) -> $key {
                *self
            }
        }

        impl PartialEq for dyn $trait + '_ {
            fn eq(&self, other: &Self) -> bool {
                self.as_key() == other.as_key()
            }
        }

        impl Eq for dyn $trait + '_ {}

        impl PartialOrd for dyn $trait + '_ {
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                self.as_key().partial_cmp(&other.as_key())
            }
        }

        impl Ord for dyn $trait + '_ {
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                self.as_key().cmp(&other.as_key())
            }
        }

        impl<'lt> ::core::borrow::Borrow<dyn $trait + 'lt> for $ty {
            fn borrow(&self) -> &(dyn $trait + 'lt) {
                self
            }
        }
    };
}

/// TODO: good candidate for `prop_test`
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_larger_min() {
        let values = [u64::MIN, u64::MAX];

        for value in values {
            assert!(MinMaxExt::Min < value.into());
        }
    }

    #[test]
    fn any_smaller_max() {
        let values = [u64::MIN, u64::MAX];

        for value in values {
            assert!(MinMaxExt::Max > value.into());
        }
    }

    #[test]
    fn eq_still_eq() {
        let values = [u64::MIN, u64::MAX];

        for value in values {
            assert!(MinMaxExt::from(value) == MinMaxExt::from(value));
        }
    }
}
