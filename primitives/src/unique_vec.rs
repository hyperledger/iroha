//! Module with [`UniqueVec`] type and related functional.

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned as _, format, string::String, vec::Vec};
use core::{
    borrow::Borrow,
    fmt::{Debug, Display},
};

use derive_more::{AsRef, Deref};
use iroha_schema::IntoSchema;
use parity_scale_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Creates a [`UniqueVec`](unique_vec::UniqueVec) from a list of values.
///
/// Works like [`vec!`] macro, but does not accept syntax for repeated values
/// and might return [`Result`].
#[macro_export]
macro_rules! unique_vec {
    () => {
        $crate::unique_vec::UniqueVec::new()
    };
    ($($x:expr),+ $(,)?) => {{
        let mut v = $crate::unique_vec::UniqueVec::new();
        $(v.push($x);)+
        v
    }};
}

/// Wrapper type for [`Vec`] which ensures that all elements are unique.
#[derive(
    Debug,
    Deref,
    AsRef,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    Encode,
    Decode,
    IntoSchema,
)]
#[repr(transparent)]
#[serde(transparent)]
#[schema(transparent)]
pub struct UniqueVec<T>(Vec<T>);

impl<T> UniqueVec<T> {
    /// Create new [`UniqueVec`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Removes the element at the given `index` and returns it.
    ///
    /// # Panics
    ///
    /// Panics if the `index` is out of bounds.
    pub fn remove(&mut self, index: usize) -> T {
        self.0.remove(index)
    }

    /// Clears the [`UniqueVec`], removing all values.
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// A result for [`UniqueVec::push`]
pub enum PushResult<T> {
    /// The element was pushed into the vec
    Ok,
    /// The element is already contained in the vec
    Duplicate(T),
}

impl<T: PartialEq> UniqueVec<T> {
    /// Push `value` to [`UniqueVec`] if it is not already present.
    pub fn push(&mut self, value: T) -> PushResult<T> {
        if self.contains(&value) {
            PushResult::Duplicate(value)
        } else {
            self.0.push(value);
            PushResult::Ok
        }
    }
}

impl<T> Default for UniqueVec<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T: PartialEq> FromIterator<T> for UniqueVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut unique_vec = Self::new();
        unique_vec.extend(iter);
        unique_vec
    }
}

impl<T: PartialEq> Extend<T> for UniqueVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        for value in iter {
            self.push(value);
        }
    }
}

impl<T: PartialEq> From<UniqueVec<T>> for Vec<T> {
    fn from(value: UniqueVec<T>) -> Self {
        value.0
    }
}

impl<T: PartialEq> Borrow<[T]> for UniqueVec<T> {
    fn borrow(&self) -> &[T] {
        self.0.borrow()
    }
}

impl<T: PartialEq> IntoIterator for UniqueVec<T> {
    type Item = T;
    type IntoIter = <Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'ve, T: PartialEq> IntoIterator for &'ve UniqueVec<T> {
    type Item = &'ve T;
    type IntoIter = <&'ve Vec<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'de, T: PartialEq + Deserialize<'de>> UniqueVec<T> {
    /// Deserialize [`UniqueVec`], failing on first duplicate.
    ///
    /// Default implementation of [`Deserialize`] for [`UniqueVec`] ignores duplicates.
    ///
    /// # Errors
    ///
    /// - If deserialization of `T` fails.
    /// - If there are duplicates in the sequence.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_primitives::unique_vec::UniqueVec;
    /// use serde::{de::Error as _, Deserialize};
    ///
    /// #[derive(Debug, PartialEq, Deserialize)]
    /// pub struct Config {
    ///     #[serde(deserialize_with = "UniqueVec::deserialize_failing_on_duplicates")]
    ///     numbers: UniqueVec<u32>,
    /// }
    ///
    /// let err = serde_json::from_str::<Config>(r#"{"numbers": [1, 2, 3, 2, 4, 5]}"#).unwrap_err();
    /// assert_eq!(err.to_string(), "Duplicated value at line 1 column 25",);
    /// ```
    pub fn deserialize_failing_on_duplicates<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::fail_on_duplicate_deserialize_impl(deserializer, |_value| {
            "Duplicated value".to_owned()
        })
    }
}

impl<'de, T: Debug + PartialEq + Deserialize<'de>> UniqueVec<T> {
    /// Deserialize [`UniqueVec`], failing on first duplicate and printing it's [`Debug`]
    /// representation.
    ///
    /// Default implementation of [`Deserialize`] for [`UniqueVec`] ignores duplicates.
    ///
    /// # Errors
    ///
    /// - If deserialization of `T` fails.
    /// - If there are duplicates in the sequence.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_primitives::unique_vec::UniqueVec;
    /// use serde::{de::Error as _, Deserialize};
    ///
    /// #[derive(Debug, PartialEq, Deserialize)]
    /// pub struct Config {
    ///     #[serde(deserialize_with = "UniqueVec::debug_deserialize_failing_on_duplicates")]
    ///     arrays: UniqueVec<Vec<u32>>,
    /// }
    ///
    /// let err = serde_json::from_str::<Config>(r#"{"arrays": [[1, 2, 3], [9, 8], [1, 2, 3]]}"#)
    ///     .unwrap_err();
    /// assert_eq!(
    ///     err.to_string(),
    ///     "Duplicated value `[1, 2, 3]` at line 1 column 41",
    /// );
    /// ```
    pub fn debug_deserialize_failing_on_duplicates<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::fail_on_duplicate_deserialize_impl(deserializer, |value| {
            format!("Duplicated value `{value:?}`")
        })
    }
}

impl<'de, T: Display + PartialEq + Deserialize<'de>> UniqueVec<T> {
    /// Deserialize [`UniqueVec`], failing on first duplicate and printing it's [`Display`]
    /// representation.
    ///
    /// Default implementation of [`Deserialize`] for [`UniqueVec`] ignores duplicates.
    ///
    /// # Errors
    ///
    /// - If deserialization of `T` fails.
    /// - If there are duplicates in the sequence.
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_primitives::unique_vec::UniqueVec;
    /// use serde::{de::Error as _, Deserialize};
    ///
    /// #[derive(Debug, PartialEq, Deserialize)]
    /// pub struct Config {
    ///     #[serde(deserialize_with = "UniqueVec::display_deserialize_failing_on_duplicates")]
    ///     numbers: UniqueVec<u32>,
    /// }
    ///
    /// let err = serde_json::from_str::<Config>(r#"{"numbers": [1, 2, 3, 2, 4, 5]}"#).unwrap_err();
    /// assert_eq!(err.to_string(), "Duplicated value `2` at line 1 column 25",);
    /// ```
    pub fn display_deserialize_failing_on_duplicates<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::fail_on_duplicate_deserialize_impl(deserializer, |value| {
            format!("Duplicated value `{value}`")
        })
    }
}

impl<'de, T: PartialEq + Deserialize<'de>> UniqueVec<T> {
    /// Deserialize [`UniqueVec`] calling `f` on duplicated value to get error message.
    fn fail_on_duplicate_deserialize_impl<D, F>(deserializer: D, f: F) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
        F: FnOnce(&T) -> String,
    {
        /// Helper, for constructing a unique visitor that errors whenever
        /// a duplicate entry is found.
        struct UniqueVisitor<T, F: FnOnce(&T) -> String> {
            _marker: core::marker::PhantomData<T>,
            f: F,
        }

        impl<'de, T, F> serde::de::Visitor<'de> for UniqueVisitor<T, F>
        where
            T: Deserialize<'de> + PartialEq,
            F: FnOnce(&T) -> String,
        {
            type Value = Vec<T>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("a set of unique items.")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Vec<T>, S::Error>
            where
                S: serde::de::SeqAccess<'de>,
            {
                let mut result = Vec::with_capacity(seq.size_hint().unwrap_or(0));

                while let Some(value) = seq.next_element()? {
                    if result.contains(&value) {
                        return Err(serde::de::Error::custom((self.f)(&value)));
                    }
                    result.push(value);
                }

                Ok(result)
            }
        }

        let inner = deserializer.deserialize_seq(UniqueVisitor::<T, F> {
            _marker: core::marker::PhantomData,
            f,
        })?;
        Ok(UniqueVec(inner))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_creates_empty_vec() {
        let unique_vec = UniqueVec::<u32>::default();
        assert!(unique_vec.is_empty());
    }

    #[test]
    fn new_creates_empty_vec() {
        let unique_vec = UniqueVec::<u32>::new();
        assert!(unique_vec.is_empty());
    }

    #[test]
    fn push_returns_true_if_value_is_unique() {
        let mut unique_vec = unique_vec![1, 3, 4];
        assert!(matches!(unique_vec.push(2), PushResult::Ok));
    }

    #[test]
    fn push_returns_false_if_value_is_not_unique() {
        let mut unique_vec = unique_vec![1, 2, 3];
        assert!(matches!(unique_vec.push(1), PushResult::Duplicate(1)));
    }

    #[test]
    fn remove_returns_value_at_index() {
        let mut unique_vec = unique_vec![1, 2, 3];
        assert_eq!(unique_vec.remove(1), 2);
    }

    #[test]
    #[should_panic(expected = "removal index (is 3) should be < len (is 3)")]
    fn remove_out_of_bounds_panics() {
        let mut unique_vec = unique_vec![1, 2, 3];
        unique_vec.remove(3);
    }

    #[test]
    fn clear_removes_all_values() {
        let mut unique_vec = unique_vec![1, 2, 3];
        unique_vec.clear();
        assert!(unique_vec.is_empty());
    }

    #[test]
    fn from_iter_creates_unique_vec() {
        let unique_vec = UniqueVec::from_iter([1, 1, 2, 3, 2]);
        assert_eq!(unique_vec, unique_vec![1, 2, 3]);
    }

    #[test]
    fn extend_adds_unique_values() {
        let mut unique_vec = unique_vec![1, 2, 3];
        unique_vec.extend([1, 2, 3, 4, 5]);
        assert_eq!(unique_vec, unique_vec![1, 2, 3, 4, 5]);
    }
}
