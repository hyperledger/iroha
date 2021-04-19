//! Module with concurent lock-free hash set

use std::{
    collections::{hash_map::RandomState, BTreeSet as StdBTreeSet, HashSet as StdHashSet},
    fmt::{self, Debug},
    hash::Hash,
    iter::FromIterator,
    ops::{Deref, DerefMut},
};

use dashmap::iter_set::OwningIter;
use dashmap::DashSet;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Concurent lock-free hash set
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
#[serde(bound(
    deserialize = "K: DeserializeOwned + Eq + Hash",
    serialize = "K: Serialize + Eq + Hash"
))]
pub struct HashSet<K>(pub DashSet<K>);

impl<K: Eq + Hash + Debug> Debug for HashSet<K> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<K: Eq + Hash> Default for HashSet<K> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Eq + Hash> HashSet<K> {
    /// Default constructor
    pub fn new() -> Self {
        Self(DashSet::new())
    }
}

impl<K: Eq + Hash + Clone> HashSet<K> {
    /// Clears hashset by removing all its keys
    pub fn clear(&self) {
        for key in self
            .iter()
            .map(|guard| (&*guard).clone())
            .collect::<Vec<_>>()
        {
            drop(self.remove(&key));
        }
    }
}

impl<K: Hash + Eq> Eq for HashSet<K> {}
impl<K: Hash + Eq> PartialEq for HashSet<K> {
    fn eq(&self, other: &Self) -> bool {
        for readguard in self.iter() {
            if other.get(&*readguard).is_none() {
                return false;
            }
        }
        true
    }
}

impl<K: Eq + Hash> From<StdHashSet<K>> for HashSet<K> {
    fn from(hs: StdHashSet<K>) -> Self {
        hs.into_iter().collect()
    }
}

impl<K: Eq + Hash> From<HashSet<K>> for StdHashSet<K, RandomState> {
    fn from(HashSet(hs): HashSet<K>) -> Self {
        hs.into_iter().collect()
    }
}

impl<K: Eq + Hash + Clone> Clone for HashSet<K> {
    fn clone(&self) -> Self {
        let new = self.iter().map(|readguard| (&*readguard).clone()).collect();
        Self(new)
    }
}

impl<K: Decode + Ord + Eq + Hash> Decode for HashSet<K> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        <StdBTreeSet<K> as Decode>::decode(input).map(|tree| Self(tree.into_iter().collect()))
    }

    fn skip<I: Input>(input: &mut I) -> Result<(), Error> {
        <StdBTreeSet<K> as Decode>::skip(input)
    }

    fn encoded_fixed_size() -> Option<usize> {
        <StdBTreeSet<K> as Decode>::encoded_fixed_size()
    }
}

impl<K: Encode + Ord + Eq + Hash + Clone> Encode for HashSet<K> {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.iter()
            .map(|readguard| (&*readguard).clone())
            .collect::<StdBTreeSet<K>>()
            .encode_to(dest)
    }
    fn encode(&self) -> Vec<u8> {
        self.iter()
            .map(|readguard| (&*readguard).clone())
            .collect::<StdBTreeSet<K>>()
            .encode()
    }
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.iter()
            .map(|readguard| (&*readguard).clone())
            .collect::<StdBTreeSet<K>>()
            .using_encoded(f)
    }
}

impl<K> Deref for HashSet<K> {
    type Target = DashSet<K>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K> DerefMut for HashSet<K> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K: Eq + Hash> FromIterator<K> for HashSet<K> {
    fn from_iter<T: IntoIterator<Item = K>>(iter: T) -> Self {
        Self(DashSet::from_iter(iter))
    }
}

impl<K: Eq + Hash> IntoIterator for HashSet<K> {
    type Item = K;
    type IntoIter = OwningIter<K, RandomState>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
