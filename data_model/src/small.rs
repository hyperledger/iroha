//! Small-string optimisation-related implementations and
//! structs. Thin wrapper around the `smallstr` crate, using the
//! `Slavic` conventions. For general use, the array type `[u8; 32]`
//! should be the standard. It's the best bang-for-the-buck in terms
//! of stack-based strings.
use core::fmt;

use iroha_schema::{IntoSchema, MetaMap, Metadata};
use parity_scale_codec::{Decode, Encode, Output};
use serde::{Deserialize, Deserializer, Serialize};
use smallstr::SmallString;
use smallvec::Array;

use crate::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Wrapper around the [`smallstr::SmallString`] type, enforcing a
/// specific size of stack-based strings.
pub struct SmallStr(SmallString<[u8; 32]>);

impl SmallStr {
    #[must_use]
    #[inline]
    /// Construct [`Self`] by taking ownership of a [`String`].
    pub fn from_string(s: String) -> Self {
        Self(SmallString::from_string(s))
    }
}

impl<A: Array<Item = u8>> From<SmallString<A>> for SmallStr {
    fn from(string: SmallString<A>) -> Self {
        Self(SmallString::from_str(SmallString::as_str(&string)))
    }
}

impl<A: Array<Item = super::peer::Id>> Extend<A::Item> for SmallVec<A> {
    fn extend<T: IntoIterator<Item = A::Item>>(&mut self, iter: T) {
        self.0.extend(iter)
    }
}

/// Wrapper struct around [`smallvec::SmallVec`] type. Keeps `N`
/// elements on the stack if `self.len()` is less than `N`, if not,
/// produces a heap-allocated vector.
///
/// To instantiate a vector with `N` stack elements,
/// ```rust
/// use iroha_data_model::small::SmallVec;
///
/// let a: SmallVec<[u8; 24]> = SmallVec(smallvec::smallvec![32]);
/// ```
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

impl<A: Array> Serialize for SmallVec<A>
where
    A::Item: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de, A: Array> Deserialize<'de> for SmallVec<A>
where
    A::Item: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_from_smallvec(deserializer)
    }
}

impl<A: Array> PartialEq for SmallVec<A>
where
    A::Item: PartialEq + Eq,
{
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<A: Array> PartialOrd for SmallVec<A>
where
    A::Item: PartialOrd + Ord,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<A: Array> Ord for SmallVec<A>
where
    A::Item: PartialOrd + Ord,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<A: Array> core::ops::Deref for SmallVec<A> {
    type Target = smallvec::SmallVec<A>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<A: Array> core::ops::DerefMut for SmallVec<A> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<A: Array> Eq for SmallVec<A> where A::Item: PartialEq + Eq {}

impl<A: Array> SmallVec<A> {
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self(smallvec::SmallVec::new())
    }
}

impl<A: Array> From<Vec<A::Item>> for SmallVec<A> {
    fn from(vec: Vec<A::Item>) -> Self {
        Self(vec.into_iter().collect())
    }
}

impl<A: Array> From<SmallVec<A>> for Value
where
    A::Item: Into<Value>,
{
    fn from(sv: SmallVec<A>) -> Self {
        // This looks inefficient, but `Value` can only hold a
        // heap-allocated `Vec` (it's recursive) and the vector
        // conversions only do a heap allocation (if that).
        let vec: Vec<_> = sv.0.into_vec();
        vec.into()
    }
}

fn deserialize_from_smallvec<'de, A, T, D>(deserializer: D) -> Result<SmallVec<A>, D::Error>
where
    A: Array<Item = T>,
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    let sv: smallvec::SmallVec<A> = Deserialize::deserialize(deserializer)?;
    Ok(SmallVec(sv))
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
        format!("Vec<{}>", T::type_name())
    }

    fn schema(map: &mut MetaMap) {
        let _ = map
            .entry(Self::type_name())
            .or_insert_with(|| Metadata::Vec(T::type_name()));
        if !map.contains_key(&T::type_name()) {
            T::schema(map);
        }
    }
}

impl IntoSchema for SmallStr {
    fn type_name() -> String {
        "String".to_owned()
    }
    fn schema(map: &mut MetaMap) {
        let _ = map.entry(Self::type_name()).or_insert(Metadata::String);
    }
}

impl<A: Array> Encode for SmallVec<A>
where
    A::Item: Encode + Clone,
{
    fn size_hint(&self) -> usize {
        core::mem::size_of::<A::Item>() * A::size()
    }

    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        // TODO: Delegating to `vec` might not be the most efficient
        // thing in the world.
        Encode::encode_to(&self.0.to_vec(), dest)
    }
}

impl<A: Array> Decode for SmallVec<A>
where
    A::Item: Decode,
{
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        Ok(Vec::<A::Item>::decode(input)?.into_iter().collect())
    }
}
