//! Immutable Patricia indexes: one bounded path per access, with a source-anchored root.

use super::{Error, archive};
use crate::kagemusha_wallet_advance_v1::kagemusha_wallet_archive_object_digest_v1 as digest;

/// Largest value stored directly in an index leaf. Capsules/proofs live in separate objects;
/// index leaves hold their digests or fixed replay/tree metadata.
pub const INDEX_VALUE_LIMIT: usize = 512;
const NODE_LIMIT: usize = INDEX_VALUE_LIMIT + archive::METADATA_BOUND;

/// Content-addressed durable storage. Production implementations use the scoped G2 archive
/// capability; the authenticated current marker chooses the manifest containing index roots.
pub trait ObjectStore {
    /// Read an existing object with an explicit decoder allocation bound.
    ///
    /// # Errors
    /// Missing/corrupt content, another digest, size mismatch or storage unavailability.
    fn read_object(&mut self, digest: &[u8; 32], max_bytes: usize) -> Result<Vec<u8>, Error>;
    /// Publish redundant immutable bytes and return their G2 archive object digest.
    ///
    /// # Errors
    /// Storage failure or uncertain publication; a returned digest implies durable copies.
    fn write_object(&mut self, bytes: &[u8], max_bytes: usize) -> Result<[u8; 32], Error>;
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::IndexNode")]
enum Node {
    Leaf {
        key: [u8; 32],
        value: Vec<u8>,
    },
    Branch {
        bit: u16,
        prefix: [u8; 32],
        left: [u8; 32],
        right: [u8; 32],
    },
}

impl Node {
    fn representative(&self) -> [u8; 32] {
        match self {
            Self::Leaf { key, .. } => *key,
            Self::Branch { prefix, .. } => *prefix,
        }
    }
}

/// Authenticated immutable map root. The zero root denotes an empty map.
///
/// Child nodes are addressed by the hash of their complete canonical bytes. Branch bits
/// strictly increase, so reads and updates retain at most 256 bounded nodes, regardless of
/// wallet history. Updates return a new root; old roots remain valid until safely collected.
#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::IndexRoot")]
pub struct IndexRoot(pub [u8; 32]);

fn bit(key: &[u8; 32], index: u16) -> bool {
    key[usize::from(index / 8)] & (0x80 >> (index % 8)) != 0
}

fn common(a: &[u8; 32], b: &[u8; 32]) -> u16 {
    for (index, (&a, &b)) in a.iter().zip(b).enumerate() {
        if a != b {
            return u16::try_from(index * 8).expect("32-byte index")
                + u16::try_from((a ^ b).leading_zeros()).expect("u8 leading zeros");
        }
    }
    256
}

fn prefix(key: &[u8; 32], length: u16) -> [u8; 32] {
    let mut result = *key;
    for index in length..256 {
        result[usize::from(index / 8)] &= !(0x80 >> (index % 8));
    }
    result
}

fn load(store: &mut impl ObjectStore, root: [u8; 32], minimum: u16) -> Result<Node, Error> {
    let bytes = store.read_object(&root, NODE_LIMIT)?;
    if digest(&bytes) != root {
        return Err(Error::WitnessLost("index node hash"));
    }
    let node: Node = archive::decode(&bytes)?;
    match &node {
        Node::Leaf { value, .. } if value.len() > INDEX_VALUE_LIMIT => {
            return Err(Error::WitnessLost("index leaf size"));
        }
        Node::Branch {
            bit,
            prefix: p,
            left,
            right,
        } if *bit < minimum
            || *bit >= 256
            || prefix(p, *bit) != *p
            || *left == [0; 32]
            || *right == [0; 32] =>
        {
            return Err(Error::WitnessLost("index branch"));
        }
        _ => {}
    }
    Ok(node)
}

fn save(store: &mut impl ObjectStore, node: &Node) -> Result<[u8; 32], Error> {
    let bytes = archive::encode(node)?;
    let expected = digest(&bytes);
    let saved = store.write_object(&bytes, NODE_LIMIT)?;
    if saved != expected {
        return Err(Error::WitnessLost("index publication digest"));
    }
    Ok(saved)
}

impl IndexRoot {
    /// Look up one key using bounded working memory.
    ///
    /// # Errors
    /// Any unavailable, corrupt or oversized node on the authenticated path.
    pub fn get(
        self,
        store: &mut impl ObjectStore,
        key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut root = self.0;
        let mut minimum = 0;
        while root != [0; 32] {
            match load(store, root, minimum)? {
                Node::Leaf { key: held, value } => return Ok((held == *key).then_some(value)),
                Node::Branch {
                    bit: branch,
                    prefix,
                    left,
                    right,
                } => {
                    if common(key, &prefix) < branch {
                        return Ok(None);
                    }
                    root = if bit(key, branch) { right } else { left };
                    minimum = branch + 1;
                }
            }
        }
        Ok(None)
    }

    /// Insert or replace one value and return a new durable root. Publication alone changes no
    /// authority; the caller commits the resulting manifest through the source provider.
    ///
    /// # Errors
    /// Oversized values, corrupted/unavailable paths or uncertain publication.
    pub fn set(
        self,
        store: &mut impl ObjectStore,
        key: [u8; 32],
        value: &[u8],
    ) -> Result<Self, Error> {
        if value.len() > INDEX_VALUE_LIMIT {
            return Err(Error::Invalid("index value size"));
        }
        let leaf = Node::Leaf {
            key,
            value: value.to_vec(),
        };
        let mut path = Vec::new();
        let mut root = self.0;
        let mut minimum = 0;
        let mut replacement;
        loop {
            if root == [0; 32] {
                replacement = save(store, &leaf)?;
                break;
            }
            let node = load(store, root, minimum)?;
            let shared = common(&key, &node.representative());
            let split = match &node {
                Node::Leaf { key: held, .. } => *held != key,
                Node::Branch { bit, .. } => shared < *bit,
            };
            if split {
                let new = save(store, &leaf)?;
                let (left, right) = if bit(&key, shared) {
                    (root, new)
                } else {
                    (new, root)
                };
                replacement = save(
                    store,
                    &Node::Branch {
                        bit: shared,
                        prefix: prefix(&key, shared),
                        left,
                        right,
                    },
                )?;
                break;
            }
            match node {
                Node::Leaf { value: held, .. } => {
                    replacement = if held == value {
                        root
                    } else {
                        save(store, &leaf)?
                    };
                    break;
                }
                Node::Branch {
                    bit: branch,
                    prefix,
                    left,
                    right,
                } => {
                    let go_right = bit(&key, branch);
                    path.push((branch, prefix, left, right, go_right));
                    root = if go_right { right } else { left };
                    minimum = branch + 1;
                }
            }
        }
        for (branch, prefix, mut left, mut right, go_right) in path.into_iter().rev() {
            if go_right {
                right = replacement;
            } else {
                left = replacement;
            }
            replacement = save(
                store,
                &Node::Branch {
                    bit: branch,
                    prefix,
                    left,
                    right,
                },
            )?;
        }
        Ok(Self(replacement))
    }

    /// Remove one key and return a new immutable root, preserving all older roots.
    /// Removing an absent key is idempotent. Every selected node remains authenticated;
    /// unavailable or corrupt content is never treated as absence.
    ///
    /// # Errors
    /// Corrupted/unavailable paths or uncertain publication.
    pub fn remove(self, store: &mut impl ObjectStore, key: &[u8; 32]) -> Result<Self, Error> {
        let mut path = Vec::new();
        let mut root = self.0;
        let mut minimum = 0;
        let mut replacement;
        loop {
            if root == [0; 32] {
                return Ok(self);
            }
            match load(store, root, minimum)? {
                Node::Leaf { key: held, .. } => {
                    if held != *key {
                        return Ok(self);
                    }
                    replacement = [0; 32];
                    break;
                }
                Node::Branch {
                    bit: branch,
                    prefix,
                    left,
                    right,
                } => {
                    if common(key, &prefix) < branch {
                        return Ok(self);
                    }
                    let go_right = bit(key, branch);
                    path.push((branch, prefix, left, right, go_right));
                    root = if go_right { right } else { left };
                    minimum = branch + 1;
                }
            }
        }
        for (branch, prefix, mut left, mut right, go_right) in path.into_iter().rev() {
            if go_right {
                right = replacement;
            } else {
                left = replacement;
            }
            replacement = if left == [0; 32] {
                right
            } else if right == [0; 32] {
                left
            } else {
                save(
                    store,
                    &Node::Branch {
                        bit: branch,
                        prefix,
                        left,
                        right,
                    },
                )?
            };
        }
        Ok(Self(replacement))
    }

    /// Largest stored key strictly below `key`; useful for indexed-tree predecessor leaves.
    ///
    /// # Errors
    /// Any unavailable, corrupt or oversized node on the selected authenticated paths.
    pub fn predecessor(
        self,
        store: &mut impl ObjectStore,
        key: &[u8; 32],
    ) -> Result<Option<([u8; 32], Vec<u8>)>, Error> {
        let mut root = self.0;
        let mut minimum = 0;
        let mut candidate = None;
        while root != [0; 32] {
            match load(store, root, minimum)? {
                Node::Leaf { key: held, value } => {
                    if held < *key {
                        return Ok(Some((held, value)));
                    }
                    break;
                }
                Node::Branch {
                    bit: branch,
                    prefix,
                    left,
                    right,
                } => {
                    if common(key, &prefix) < branch {
                        if prefix < *key {
                            candidate = Some((root, minimum));
                        }
                        break;
                    }
                    if bit(key, branch) {
                        candidate = Some((left, branch + 1));
                        root = right;
                    } else {
                        root = left;
                    }
                    minimum = branch + 1;
                }
            }
        }
        let Some((mut root, mut minimum)) = candidate else {
            return Ok(None);
        };
        loop {
            match load(store, root, minimum)? {
                Node::Leaf { key, value } => return Ok(Some((key, value))),
                Node::Branch { bit, right, .. } => {
                    root = right;
                    minimum = bit + 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct Memory {
        objects: BTreeMap<[u8; 32], Vec<u8>>,
        reads: usize,
    }
    impl ObjectStore for Memory {
        fn read_object(&mut self, key: &[u8; 32], max: usize) -> Result<Vec<u8>, Error> {
            self.reads += 1;
            let bytes = self
                .objects
                .get(key)
                .ok_or(Error::WitnessLost("test missing node"))?
                .clone();
            if bytes.len() > max {
                return Err(Error::WitnessLost("test node bound"));
            }
            Ok(bytes)
        }
        fn write_object(&mut self, bytes: &[u8], max: usize) -> Result<[u8; 32], Error> {
            assert!(bytes.len() <= max);
            let key = digest(bytes);
            self.objects.insert(key, bytes.to_vec());
            Ok(key)
        }
    }

    #[test]
    fn immutable_index_matches_ordered_map_and_keeps_lookup_memory_bounded() {
        let mut store = Memory::default();
        let mut root = IndexRoot::default();
        let mut expected = BTreeMap::new();
        for i in 0_u64..512 {
            let key = digest(&i.to_le_bytes());
            let value = i.to_le_bytes().to_vec();
            root = root.set(&mut store, key, &value).expect("insert");
            expected.insert(key, value);
        }
        let old = root;
        for (&key, value) in &expected {
            store.reads = 0;
            assert_eq!(
                root.get(&mut store, &key).expect("lookup"),
                Some(value.clone())
            );
            assert!(store.reads <= 257);
            let lower = expected
                .range(..key)
                .next_back()
                .map(|(k, v)| (*k, v.clone()));
            assert_eq!(
                root.predecessor(&mut store, &key).expect("predecessor"),
                lower
            );
        }
        for i in 512_u64..640 {
            let key = digest(&i.to_le_bytes());
            assert_eq!(
                root.predecessor(&mut store, &key)
                    .expect("missing predecessor"),
                expected
                    .range(..key)
                    .next_back()
                    .map(|(k, v)| (*k, v.clone()))
            );
            assert!(root.get(&mut store, &key).expect("absent").is_none());
        }
        let key = *expected.keys().next().expect("key");
        root = root.set(&mut store, key, b"changed").expect("replacement");
        assert_eq!(
            root.get(&mut store, &key).expect("new"),
            Some(b"changed".to_vec())
        );
        assert_eq!(
            old.get(&mut store, &key).expect("old"),
            expected.get(&key).cloned()
        );
        assert!(
            root.set(&mut store, key, &[0; INDEX_VALUE_LIMIT + 1])
                .is_err()
        );
        store.objects.remove(&root.0);
        assert!(
            root.get(&mut store, &key).is_err(),
            "missing authenticated nodes are never absence"
        );
    }

    #[test]
    fn removal_collapses_only_its_path_and_preserves_old_snapshots() {
        let mut store = Memory::default();
        let mut root = IndexRoot::default();
        let mut expected = BTreeMap::new();
        for i in 0_u64..96 {
            let key = digest(&i.to_le_bytes());
            let value = i.to_le_bytes().to_vec();
            root = root.set(&mut store, key, &value).unwrap();
            expected.insert(key, value);
        }
        let original = root;
        assert_eq!(root.remove(&mut store, &[0xff; 32]).unwrap(), root);
        let keys: Vec<_> = expected.keys().copied().collect();
        for key in keys {
            store.reads = 0;
            root = root.remove(&mut store, &key).unwrap();
            assert!(store.reads <= 257);
            expected.remove(&key);
            assert_eq!(root.get(&mut store, &key).unwrap(), None);
            assert!(original.get(&mut store, &key).unwrap().is_some());
            assert_eq!(root.remove(&mut store, &key).unwrap(), root);
            for (held, value) in &expected {
                assert_eq!(root.get(&mut store, held).unwrap(), Some(value.clone()));
            }
        }
        assert_eq!(root, IndexRoot::default());
        let bytes = store.objects.remove(&original.0).unwrap();
        assert!(original.remove(&mut store, &[0; 32]).is_err());
        store.objects.insert(original.0, bytes);
        store.objects.get_mut(&original.0).unwrap().push(0);
        assert!(original.remove(&mut store, &[0; 32]).is_err());
    }
}
