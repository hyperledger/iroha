//! hash map module

use std::{
    collections::{hash_map::RandomState, BTreeMap as StdBTreeMap, HashMap as StdHashMap},
    fmt::{self, Debug},
    hash::Hash,
    iter::FromIterator,
    ops::{Deref, DerefMut},
};

use dashmap::iter::OwningIter;
pub use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parity_scale_codec::{Decode, Encode, Error, Input, Output};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Concurent lock-free hash map
#[derive(Deserialize, Serialize)]
#[serde(transparent)]
#[serde(bound(
    deserialize = "
    K: DeserializeOwned + Eq + Hash,
    V: DeserializeOwned,
",
    serialize = "
    K: Serialize + Eq + Hash,
    V: Serialize,
"
))]
pub struct HashMap<K, V>(pub DashMap<K, V>);

impl<K: Eq + Hash + Debug, V: Debug> Debug for HashMap<K, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<K: Hash + Eq, V: Eq> Eq for HashMap<K, V> {}
impl<K: Hash + Eq, V: PartialEq> PartialEq for HashMap<K, V> {
    fn eq(&self, other: &Self) -> bool {
        for readguard in &self.0 {
            match other.get(readguard.key()) {
                Some(guard) if *guard == *readguard.value() => (),
                _ => return false,
            }
        }
        true
    }
}

impl<K: Hash + Eq, V> HashMap<K, V> {
    /// Constructor for hashmap
    pub fn new() -> Self {
        Self(DashMap::new())
    }
}

impl<K: Hash + Eq, V> Default for HashMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: Decode + Ord + Eq + Hash, V: Decode> Decode for HashMap<K, V> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        <StdBTreeMap<K, V> as Decode>::decode(input).map(|tree| Self(tree.into_iter().collect()))
    }

    fn skip<I: Input>(input: &mut I) -> Result<(), Error> {
        <StdBTreeMap<K, V> as Decode>::skip(input)
    }

    fn encoded_fixed_size() -> Option<usize> {
        <StdBTreeMap<K, V> as Decode>::encoded_fixed_size()
    }
}

impl<K: Encode + Eq + Ord + Hash + Clone, V: Encode + Clone> Encode for HashMap<K, V> {
    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        self.iter()
            .map(|readguard| (readguard.key().clone(), readguard.value().clone()))
            .collect::<StdBTreeMap<K, V>>()
            .encode_to(dest)
    }
    fn encode(&self) -> Vec<u8> {
        self.iter()
            .map(|readguard| (readguard.key().clone(), readguard.value().clone()))
            .collect::<StdBTreeMap<K, V>>()
            .encode()
    }
    fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        self.iter()
            .map(|readguard| (readguard.key().clone(), readguard.value().clone()))
            .collect::<StdBTreeMap<K, V>>()
            .using_encoded(f)
    }
}

impl<K, V> Deref for HashMap<K, V> {
    type Target = DashMap<K, V>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<K, V> DerefMut for HashMap<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<K: Eq + Hash, V> From<StdHashMap<K, V>> for HashMap<K, V> {
    fn from(hm: StdHashMap<K, V>) -> Self {
        Self(hm.into_iter().collect())
    }
}

impl<K: Eq + Hash, V> From<HashMap<K, V>> for StdHashMap<K, V, RandomState> {
    fn from(HashMap(iroha_map): HashMap<K, V>) -> Self {
        iroha_map.into_iter().collect()
    }
}

impl<K: Eq + Hash + Clone, V: Clone> Clone for HashMap<K, V> {
    fn clone(&self) -> Self {
        let new = self
            .iter()
            .map(|readguard| (readguard.key().clone(), readguard.value().clone()))
            .collect();
        Self(new)
    }
}

impl<K: Eq + Hash, V> FromIterator<(K, V)> for HashMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self(DashMap::from_iter(iter))
    }
}

impl<'a, K: Eq + Hash, V> IntoIterator for HashMap<K, V> {
    type Item = (K, V);
    type IntoIter = OwningIter<K, V, RandomState>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
