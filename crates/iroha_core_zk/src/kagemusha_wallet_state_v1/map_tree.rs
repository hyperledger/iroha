//! Bounded persistent wallet IMT, including genuine intermediate insertion/removal paths.

use super::{Error, IndexRoot, ObjectStore, archive, valid};
use iroha_data_model::kagemusha::*;

/// Fixed immutable description; selecting it belongs to the authenticated source owner.
/// Old roots remain usable after an update, and removed physical slots are never reused.
#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::PersistentMap")]
pub(crate) struct PersistentMapV1 {
    version: u16,
    leaves: IndexRoot,
    nodes: IndexRoot,
    next_slot: u64,
    root: [u8; 32],
}

#[derive(Debug, Clone, norito::Encode, norito::Decode, norito::NoritoSchema)]
#[norito_schema(name = "iroha_core_zk::kagemusha_wallet_state_v1::PersistentMapEntry")]
struct Entry {
    slot: u32,
    key: [u8; 32],
    value: [u8; 32],
    next_key: [u8; 32],
}
impl Entry {
    fn leaf(&self) -> KagemushaWalletIndexedLeafV1 {
        KagemushaWalletIndexedLeafV1 {
            key: self.key,
            value: self.value,
            next_key: self.next_key,
        }
    }
    fn sentinel() -> Self {
        Self {
            slot: 0,
            key: [0; 32],
            value: [0; 32],
            next_key: [0; 32],
        }
    }
}
fn ordered(mut key: [u8; 32]) -> [u8; 32] {
    key.reverse();
    key
}
fn location(height: usize, slot: u32) -> [u8; 32] {
    let mut key = [0; 32];
    key[0] = u8::try_from(height).expect("bounded tree height");
    key[1..5].copy_from_slice(&slot.to_be_bytes());
    key
}
fn node(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], Error> {
    valid(kagemusha_wallet_indexed_node_v1(left, right))
}
fn key_valid(key: &[u8; 32]) -> Result<(), Error> {
    if *key == [0; 32] || !kagemusha_wallet_is_canonical_field_v1(key) {
        return Err(Error::Invalid("map field key"));
    }
    Ok(())
}

impl Default for PersistentMapV1 {
    fn default() -> Self {
        Self {
            version: 1,
            leaves: IndexRoot::default(),
            nodes: IndexRoot::default(),
            next_slot: 1,
            root: kagemusha_wallet_empty_map_root_v1(),
        }
    }
}

impl PersistentMapV1 {
    pub(crate) fn root(&self) -> [u8; 32] {
        self.root
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.version != 1
            || self.next_slot == 0
            || self.next_slot > (1u64 << 32)
            || !kagemusha_wallet_is_canonical_field_v1(&self.root)
        {
            return Err(Error::WitnessLost("map descriptor"));
        }
        Ok(())
    }
    fn defaults() -> Result<[[u8; 32]; 33], Error> {
        let mut roots = [[0; 32]; 33];
        roots[0] = valid(KagemushaWalletIndexedLeafV1::SENTINEL.hash())?;
        for height in 0..32 {
            roots[height + 1] = node(
                &roots[height],
                &valid(kagemusha_wallet_indexed_empty_subtree_v1(height))?,
            )?;
        }
        Ok(roots)
    }
    fn hash(
        &self,
        store: &mut impl ObjectStore,
        height: usize,
        slot: u32,
        defaults: &[[u8; 32]; 33],
    ) -> Result<[u8; 32], Error> {
        match self.nodes.get(store, &location(height, slot))? {
            Some(bytes) => {
                let hash: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| Error::WitnessLost("map node length"))?;
                if !kagemusha_wallet_is_canonical_field_v1(&hash) {
                    return Err(Error::WitnessLost("map node field"));
                }
                Ok(hash)
            }
            None if slot == 0 => Ok(defaults[height]),
            None => valid(kagemusha_wallet_indexed_empty_subtree_v1(height)),
        }
    }
    fn opening(
        &self,
        store: &mut impl ObjectStore,
        slot: u32,
    ) -> Result<KagemushaWalletIndexedOpeningV1, Error> {
        let defaults = Self::defaults()?;
        let mut siblings = [[0; 32]; 32];
        let mut index = slot;
        for (height, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.hash(store, height, index ^ 1, &defaults)?;
            index >>= 1;
        }
        Ok(KagemushaWalletIndexedOpeningV1 { slot, siblings })
    }
    fn entry(&self, store: &mut impl ObjectStore, key: &[u8; 32]) -> Result<Option<Entry>, Error> {
        self.validate()?;
        let Some(bytes) = self.leaves.get(store, &ordered(*key))? else {
            return Ok((*key == [0; 32]).then(Entry::sentinel));
        };
        let entry: Entry = archive::decode(&bytes)?;
        if entry.key != *key
            || u64::from(entry.slot) >= self.next_slot
            || (entry.slot == 0) != (entry.key == [0; 32])
        {
            return Err(Error::WitnessLost("map entry binding"));
        }
        valid(entry.leaf().hash())?;
        Ok(Some(entry))
    }
    fn require_opening(
        &self,
        store: &mut impl ObjectStore,
        entry: &Entry,
    ) -> Result<KagemushaWalletIndexedOpeningV1, Error> {
        let opening = self.opening(store, entry.slot)?;
        if valid(opening.leaf_root(&entry.leaf()))? != self.root {
            return Err(Error::WitnessLost("map selected root"));
        }
        Ok(opening)
    }
    fn low(&self, store: &mut impl ObjectStore, key: &[u8; 32]) -> Result<Entry, Error> {
        key_valid(key)?;
        let entry = match self.leaves.predecessor(store, &ordered(*key))? {
            Some((held, bytes)) => {
                let entry: Entry = archive::decode(&bytes)?;
                if held != ordered(entry.key) {
                    return Err(Error::WitnessLost("map ordered key"));
                }
                self.entry(store, &entry.key)?
                    .ok_or(Error::WitnessLost("map low entry"))?
            }
            None => self
                .entry(store, &[0; 32])?
                .ok_or(Error::WitnessLost("map sentinel"))?,
        };
        self.require_opening(store, &entry)?;
        Ok(entry)
    }
    /// Exact current-root member, without collecting the map or wallet history.
    pub(crate) fn member_or_low(
        &self,
        store: &mut impl ObjectStore,
        key: &[u8; 32],
    ) -> Result<
        (
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        key_valid(key)?;
        let entry = if let Some(entry) = self.entry(store, key)? {
            entry
        } else {
            self.low(store, key)?
        };
        let opening = self.require_opening(store, &entry)?;
        Ok((entry.leaf(), opening))
    }

    /// Exact current-root member, without collecting the map or wallet history.
    pub(crate) fn membership(
        &self,
        store: &mut impl ObjectStore,
        key: &[u8; 32],
    ) -> Result<
        (
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        key_valid(key)?;
        let entry = self
            .entry(store, key)?
            .ok_or(Error::WitnessLost("selected map member absent"))?;
        let opening = self.require_opening(store, &entry)?;
        Ok((entry.leaf(), opening))
    }
    /// Absence is established by an actual authenticated low-leaf path, never a null lookup.
    pub(crate) fn non_membership(
        &self,
        store: &mut impl ObjectStore,
        key: &[u8; 32],
    ) -> Result<
        (
            KagemushaWalletIndexedLeafV1,
            KagemushaWalletIndexedOpeningV1,
        ),
        Error,
    > {
        let entry = self.low(store, key)?;
        let opening = self.require_opening(store, &entry)?;
        valid(kagemusha_wallet_indexed_verify_non_membership_v1(
            &self.root,
            key,
            &entry.leaf(),
            &opening,
        ))?;
        Ok((entry.leaf(), opening))
    }
    fn write_slot(
        &mut self,
        store: &mut impl ObjectStore,
        slot: u32,
        leaf: Option<&Entry>,
    ) -> Result<(), Error> {
        let defaults = Self::defaults()?;
        let mut hash = match leaf {
            Some(e) => valid(e.leaf().hash())?,
            None => valid(kagemusha_wallet_indexed_empty_subtree_v1(0))?,
        };
        self.nodes = self.nodes.set(store, location(0, slot), &hash)?;
        let mut index = slot;
        for height in 0..32 {
            let sibling = self.hash(store, height, index ^ 1, &defaults)?;
            hash = if index & 1 == 0 {
                node(&hash, &sibling)?
            } else {
                node(&sibling, &hash)?
            };
            index >>= 1;
            self.nodes = self.nodes.set(store, location(height + 1, index), &hash)?;
        }
        self.root = hash;
        if let Some(entry) = leaf {
            self.leaves = self
                .leaves
                .set(store, ordered(entry.key), &archive::encode(entry)?)?;
        }
        Ok(())
    }
    fn insertion_source(
        &self,
        store: &mut impl ObjectStore,
        key: [u8; 32],
    ) -> Result<(Self, Entry, u32, KagemushaWalletIndexedInsertV1), Error> {
        let low = self.low(store, &key)?;
        let low_opening = self.require_opening(store, &low)?;
        valid(kagemusha_wallet_indexed_verify_non_membership_v1(
            &self.root,
            &key,
            &low.leaf(),
            &low_opening,
        ))?;
        let slot = u32::try_from(self.next_slot).map_err(|_| Error::Invalid("map full"))?;
        let mut next = self.clone();
        let linked = Entry {
            next_key: key,
            ..low.clone()
        };
        next.write_slot(store, linked.slot, Some(&linked))?;
        let slot_opening = next.opening(store, slot)?;
        if valid(slot_opening.empty_root())? != next.root {
            return Err(Error::WitnessLost("map insertion slot"));
        }
        let witness = KagemushaWalletIndexedInsertV1 {
            low: low.leaf(),
            low_opening,
            slot_opening,
        };
        Ok((next, low, slot, witness))
    }
    /// Make both durable paths before returning the new descriptor and witness.
    /// Failed publication leaves this descriptor unchanged; unreachable objects have no authority.
    pub(crate) fn insert(
        &mut self,
        store: &mut impl ObjectStore,
        key: [u8; 32],
        value: [u8; 32],
    ) -> Result<KagemushaWalletIndexedInsertV1, Error> {
        if value == [0; 32] || !kagemusha_wallet_is_canonical_field_v1(&value) {
            return Err(Error::Invalid("map field value"));
        }
        let (mut next, low, slot, witness) = self.insertion_source(store, key)?;
        let entry = Entry {
            slot,
            key,
            value,
            next_key: low.next_key,
        };
        next.write_slot(store, slot, Some(&entry))?;
        next.next_slot += 1;
        if valid(witness.verify(&self.root, &key, &value))? != next.root {
            return Err(Error::WitnessLost("map insertion result"));
        }
        *self = next;
        Ok(witness)
    }
    /// Actual predecessor opening, followed by the removed leaf's intermediate-root opening.
    pub(crate) fn remove(
        &mut self,
        store: &mut impl ObjectStore,
        key: &[u8; 32],
    ) -> Result<KagemushaWalletIndexedRemoveV1, Error> {
        key_valid(key)?;
        let entry = self
            .entry(store, key)?
            .ok_or(Error::WitnessLost("selected map removal absent"))?;
        self.require_opening(store, &entry)?;
        let predecessor = self.low(store, key)?;
        let predecessor_opening = self.require_opening(store, &predecessor)?;
        if predecessor.next_key != *key {
            return Err(Error::WitnessLost("map removal predecessor"));
        }
        let mut next = self.clone();
        let relinked = Entry {
            next_key: entry.next_key,
            ..predecessor.clone()
        };
        next.write_slot(store, relinked.slot, Some(&relinked))?;
        let leaf_opening = next.require_opening(store, &entry)?;
        next.write_slot(store, entry.slot, None)?;
        next.leaves = next.leaves.remove(store, &ordered(*key))?;
        let witness = KagemushaWalletIndexedRemoveV1 {
            predecessor: predecessor.leaf(),
            predecessor_opening,
            leaf: entry.leaf(),
            leaf_opening,
        };
        if valid(witness.verify(&self.root, key))? != next.root {
            return Err(Error::WitnessLost("map removal result"));
        }
        *self = next;
        Ok(witness)
    }
}

#[cfg(test)]
mod tests;
