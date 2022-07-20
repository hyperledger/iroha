//! Small-string optimisation-related implementations and
//! structs. Thin wrapper around the `smallstr` crate. The array type
//! `[u8; 32]` should be the standard for strings. The size of the
//! `SmallVec` should be determined based on the average case size of
//! the collection.
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use core::fmt;

use iroha_schema::{IntoSchema, MetaMap};
use parity_scale_codec::{WrapperTypeDecode, WrapperTypeEncode};
use serde::{Deserialize, Serialize};
pub use small_string::SmallStr;
pub use small_vector::SmallVec;
use smallstr::SmallString;
pub use smallvec::{smallvec, Array};

/// The go-to size for `SmallVec`. When in doubt, use this.
pub const SMALL_SIZE: usize = 8_usize;

mod small_string {
    use super::*;

    #[derive(Debug, Clone, derive_more::Display, Deserialize, Serialize)]
    /// Wrapper around the [`smallstr::SmallString`] type, enforcing a
    /// specific size of stack-based strings.
    #[serde(transparent)]
    #[repr(transparent)]
    pub struct SmallStr(SmallString<[u8; 32]>);

    impl SmallStr {
        #[must_use]
        #[inline]
        /// Construct [`Self`] by taking ownership of a [`String`].
        pub fn from_string(other: String) -> Self {
            Self(SmallString::from_string(other))
        }

        #[must_use]
        #[inline]
        #[allow(clippy::should_implement_trait)]
        /// Construct [`Self`] infallibly without taking ownership of a
        /// string slice. This is not an implementation of [`FromStr`](core::str::FromStr),
        /// because the latter implies **fallible** conversion, while this
        /// particular conversion is **infallible**.
        pub fn from_str(other: &str) -> Self {
            Self(SmallString::from_str(other))
        }

        #[inline]
        /// Checks if the specified pattern is the prefix of given string.
        pub fn starts_with(&self, pattern: &str) -> bool {
            self.0.starts_with(pattern)
        }
    }

    impl<A: Array<Item = u8>> From<SmallString<A>> for SmallStr {
        fn from(string: SmallString<A>) -> Self {
            Self(SmallString::from_str(SmallString::as_str(&string)))
        }
    }

    impl IntoSchema for SmallStr {
        fn type_name() -> String {
            String::type_name()
        }
        fn schema(map: &mut MetaMap) {
            String::schema(map);
        }
    }
}

mod small_vector {
    use super::*;

    /// Wrapper struct around [`smallvec::SmallVec`] type. Keeps `N`
    /// elements on the stack if `self.len()` is less than `N`, if not,
    /// produces a heap-allocated vector.
    ///
    /// To instantiate a vector with `N` stack elements,
    /// ```ignore
    /// use iroha_data_model::small::SmallVec;
    ///
    /// let a: SmallVec<[u8; 24]> = SmallVec(smallvec::smallvec![32]);
    /// ```
    #[derive(Deserialize, Serialize)]
    #[serde(
        bound(
            serialize = "A::Item: Serialize",
            deserialize = "A::Item: Deserialize<'de>"
        ),
        transparent
    )]
    #[repr(transparent)]
    pub struct SmallVec<A: Array>(pub smallvec::SmallVec<A>);

    impl<A: Array> Default for SmallVec<A> {
        fn default() -> Self {
            Self(smallvec::SmallVec::new())
        }
    }

    impl<A: Array> Clone for SmallVec<A>
    where
        A::Item: Clone,
    {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }

    impl<A: Array> fmt::Debug for SmallVec<A>
    where
        A::Item: fmt::Debug,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_tuple("SmallVec").field(&self.0).finish()
        }
    }

    impl<A: Array> FromIterator<A::Item> for SmallVec<A> {
        fn from_iter<T: IntoIterator<Item = A::Item>>(iter: T) -> Self {
            Self(iter.into_iter().collect())
        }
    }

    impl<A: Array> PartialEq for SmallVec<A>
    where
        A::Item: PartialEq,
    {
        fn eq(&self, other: &Self) -> bool {
            self.0.eq(&other.0)
        }
    }

    impl<A: Array> PartialOrd for SmallVec<A>
    where
        A::Item: PartialOrd,
    {
        fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
            self.0.partial_cmp(&other.0)
        }
    }

    impl<A: Array> Ord for SmallVec<A>
    where
        A::Item: Ord,
    {
        fn cmp(&self, other: &Self) -> core::cmp::Ordering {
            self.0.cmp(&other.0)
        }
    }

    impl<A: Array> core::ops::Deref for SmallVec<A> {
        type Target = <smallvec::SmallVec<A> as core::ops::Deref>::Target;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<A: Array> core::ops::DerefMut for SmallVec<A> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<A: Array> Eq for SmallVec<A> where A::Item: Eq {}

    impl<A: Array> SmallVec<A> {
        /// Construct new empty [`SmallVec`]
        #[inline]
        #[must_use]
        pub fn new() -> Self {
            Self(smallvec::SmallVec::new())
        }

        /// Append an item to the vector.
        #[inline]
        pub fn push(&mut self, value: A::Item) {
            self.0.push(value)
        }

        /// Remove and return the element at position `index`, shifting all elements after it to the
        /// left.
        ///
        /// Panics if `index` is out of bounds.
        #[inline]
        pub fn remove(&mut self, index: usize) -> A::Item {
            self.0.remove(index)
        }

        /// Convert a [`SmallVec`] to a [`Vec`], without reallocating if the [`SmallVec`]
        /// has already spilled onto the heap.
        #[inline]
        #[must_use]
        pub fn into_vec(self) -> Vec<A::Item> {
            self.0.into_vec()
        }
    }

    impl<A: Array> From<Vec<A::Item>> for SmallVec<A> {
        fn from(vec: Vec<A::Item>) -> Self {
            Self(vec.into_iter().collect())
        }
    }

    impl<A: Array> IntoIterator for SmallVec<A> {
        type Item = <A as smallvec::Array>::Item;

        type IntoIter = <smallvec::SmallVec<A> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl<T: IntoSchema, A: smallvec::Array<Item = T>> IntoSchema for SmallVec<A> {
        fn type_name() -> String {
            Vec::<T>::type_name()
        }

        fn schema(map: &mut MetaMap) {
            Vec::<T>::schema(map)
        }
    }

    impl<A: smallvec::Array> Extend<A::Item> for SmallVec<A> {
        fn extend<T: IntoIterator<Item = A::Item>>(&mut self, iter: T) {
            self.0.extend(iter)
        }
    }

    impl<A: Array> WrapperTypeEncode for SmallVec<A> {}

    // Decodes into Vec and then converts into SmallVec.
    // TODO: Maybe this conversion can be optimized?
    impl<A: Array> WrapperTypeDecode for SmallVec<A> {
        type Wrapped = Vec<A::Item>;
    }
}
