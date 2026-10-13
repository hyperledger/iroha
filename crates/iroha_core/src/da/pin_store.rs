//! In-memory DA pin intent index mirrored from the on-chain registry.
//!
//! Pin intents are persisted into WSV during block application. This cache provides fast lookups
//! for Torii/query paths and can be rebuilt from the block log or WSV indexes after restart.
use iroha_data_model::{
    da::{
        commitment::DaCommitmentLocation,
        pin_intent::{DaPinIntent, DaPinIntentWithLocation},
        types::StorageTicketId,
    },
    sorafs::pin_registry::ManifestDigest,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound::{Excluded, Unbounded},
};
/// Simple index over DA pin intents with stable block locations.
#[derive(Clone, Debug, Default)]
pub struct DaPinStore {
    by_ticket: BTreeMap<StorageTicketId, DaPinIntentWithLocation>,
    by_alias: BTreeMap<String, StorageTicketId>,
    by_manifest: BTreeMap<ManifestDigest, DaPinIntentWithLocation>,
    by_lane_epoch: BTreeMap<(u32, u64, u64), DaPinIntentWithLocation>,
    by_location: BTreeMap<(u64, u32), DaPinIntentWithLocation>,
    seen_keys: BTreeSet<(u32, u64, u64)>,
}
impl DaPinStore {
    /// Build a store from an existing set of intents, preserving deterministic order.
    #[must_use]
    pub fn from_intents(intents: &[DaPinIntentWithLocation]) -> Self {
        let mut store = Self::default();
        for intent in intents.iter().cloned() {
            store.insert_with_location(intent);
        }
        store
    }
    /// Insert a pin intent with its originating block location, updating alias mapping if present.
    ///
    /// Returns `true` when the intent was newly inserted and `false` when it was
    /// dropped due to a duplicate index key.
    pub fn insert(&mut self, intent: DaPinIntent, location: DaCommitmentLocation) -> bool {
        self.insert_with_location(DaPinIntentWithLocation { intent, location })
    }
    /// Insert a pin intent that already carries its location metadata.
    ///
    /// Returns `true` when the intent was newly inserted.
    pub fn insert_with_location(&mut self, entry: DaPinIntentWithLocation) -> bool {
        let DaPinIntentWithLocation { intent, location } = entry;
        let key = (intent.lane_id.as_u32(), intent.epoch, intent.sequence);
        let location_key = (location.block_height, location.index_in_bundle);
        if self.seen_keys.contains(&key)
            || self.by_ticket.contains_key(&intent.storage_ticket)
            || self.by_manifest.contains_key(&intent.manifest_hash)
            || self.by_location.contains_key(&location_key)
        {
            return false;
        }
        self.seen_keys.insert(key);
        let stored = DaPinIntentWithLocation {
            intent: intent.clone(),
            location,
        };
        if let Some(alias) = intent.alias.clone() {
            self.by_alias.insert(alias, intent.storage_ticket);
        }
        self.by_ticket.insert(intent.storage_ticket, stored.clone());
        self.by_manifest
            .insert(intent.manifest_hash, stored.clone());
        self.by_lane_epoch.insert(
            (intent.lane_id.as_u32(), intent.epoch, intent.sequence),
            stored.clone(),
        );
        self.by_location.insert(location_key, stored);
        true
    }
    /// Install the exact authoritative alias projection after a cold WSV rebuild.
    /// Historical record aliases need not remain bound after retirement or rebinding.
    pub(crate) fn replace_alias_bindings(&mut self, aliases: BTreeMap<String, StorageTicketId>) {
        self.by_alias = aliases;
    }
    /// Lookup by storage ticket.
    #[must_use]
    pub fn get_by_ticket(&self, ticket: &StorageTicketId) -> Option<&DaPinIntentWithLocation> {
        self.by_ticket.get(ticket)
    }
    /// Lookup by alias.
    #[must_use]
    pub fn get_by_alias(
        &self,
        alias: &str,
    ) -> Option<(&StorageTicketId, &DaPinIntentWithLocation)> {
        self.by_alias
            .get(alias)
            .and_then(|ticket| self.by_ticket.get_key_value(ticket))
    }
    /// Lookup by manifest hash.
    #[must_use]
    pub fn get_by_manifest(&self, digest: &ManifestDigest) -> Option<&DaPinIntentWithLocation> {
        self.by_manifest.get(digest)
    }
    /// Lookup by `(lane_id, epoch, sequence)`.
    #[must_use]
    pub fn get_by_lane_epoch_sequence(
        &self,
        lane_id: u32,
        epoch: u64,
        sequence: u64,
    ) -> Option<&DaPinIntentWithLocation> {
        self.by_lane_epoch.get(&(lane_id, epoch, sequence))
    }
    #[cfg(test)]
    /// Return whether a pin intent collides with any committed pin intent identity.
    ///
    /// Aliases are intentionally excluded: they are mutable shortcuts and may
    /// be reassigned by later pin intents.
    #[must_use]
    pub fn contains_intent_identity(&self, intent: &DaPinIntent) -> bool {
        self.get_by_lane_epoch_sequence(intent.lane_id.as_u32(), intent.epoch, intent.sequence)
            .is_some()
            || self.get_by_manifest(&intent.manifest_hash).is_some()
            || self.get_by_ticket(&intent.storage_ticket).is_some()
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Return all intents ordered by `(block_height, index_in_bundle)`.
    pub fn all_sorted(&self) -> impl Iterator<Item = &DaPinIntentWithLocation> {
        self.by_location.values()
    }
    /// Return intents in canonical location order strictly after `cursor`.
    ///
    /// The ordered map seeks directly to the cursor in logarithmic time. Callers should separately
    /// require [`Self::contains_query_location`] before accepting a client-supplied cursor so
    /// removed or foreign locations fail closed.
    pub fn all_sorted_after(
        &self,
        cursor: Option<DaCommitmentLocation>,
    ) -> impl Iterator<Item = &DaPinIntentWithLocation> {
        let lower_bound = cursor.map_or(Unbounded, |location| {
            Excluded((location.block_height, location.index_in_bundle))
        });
        self.by_location
            .range((lower_bound, Unbounded))
            .map(|(_, record)| record)
    }
    /// Return whether the active query index contains `location`.
    #[must_use]
    pub fn contains_query_location(&self, location: DaCommitmentLocation) -> bool {
        self.by_location
            .contains_key(&(location.block_height, location.index_in_bundle))
    }
    /// Number of currently queryable pin intents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_location.len()
    }
    /// Whether the store has no currently queryable pin intents.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_location.is_empty()
    }
    /// Drop pin intents belonging to retired lanes.
    pub fn prune_lanes(&mut self, retired: &BTreeSet<iroha_model_base::topology::LaneId>) {
        if retired.is_empty() {
            return;
        }
        let mut rebuilt = DaPinStore::default();
        for entry in self.by_location.values() {
            if retired.contains(&entry.intent.lane_id) {
                continue;
            }
            rebuilt.insert_with_location(entry.clone());
        }
        rebuilt.by_alias = self
            .by_alias
            .iter()
            .filter(|(_, ticket)| rebuilt.by_ticket.contains_key(ticket))
            .map(|(alias, ticket)| (alias.clone(), *ticket))
            .collect();
        *self = rebuilt;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sorafs::pin_registry::ManifestDigest;
    use iroha_model_base::topology::LaneId;
    use std::convert::TryFrom;
    fn sample_intent(lane: u32, seq: u64, alias: Option<&str>) -> DaPinIntent {
        let lane_byte = u8::try_from(lane).expect("lane id fits in byte for test intent");
        let seq_byte = u8::try_from(seq).expect("sequence fits in byte for test intent");
        let key_pair =
            iroha_crypto::KeyPair::try_from_seed(vec![0xD3; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("valid deterministic DA pin store key");
        let network_id = iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
            iroha_data_model::block::BlockHeader,
        >::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([0xD4; 32]),
        ));
        let authorization = crate::da::signed_test_ingest_authorization(
            network_id,
            &key_pair,
            LaneId::new(lane),
            1,
            seq,
            1,
        );
        crate::da::signed_test_pin_intent(
            authorization,
            &key_pair,
            StorageTicketId::new([lane_byte; 32]),
            ManifestDigest::new([seq_byte; 32]),
            alias.map(ToOwned::to_owned),
        )
    }
    fn located(intent: DaPinIntent, height: u64, idx: u32) -> DaPinIntentWithLocation {
        DaPinIntentWithLocation {
            intent,
            location: DaCommitmentLocation {
                block_height: height,
                index_in_bundle: idx,
            },
        }
    }
    #[test]
    fn alias_projection_preserves_unbinding_and_pruning_does_not_restore_old_owner() {
        let older = located(sample_intent(0, 1, Some("shared")), 1, 0);
        let newer = located(sample_intent(1, 2, Some("shared")), 2, 0);
        let mut store = DaPinStore::from_intents(&[older.clone(), newer]);
        store.prune_lanes(&BTreeSet::from([LaneId::new(1)]));
        assert!(store.get_by_ticket(&older.intent.storage_ticket).is_some());
        assert!(store.get_by_alias("shared").is_none());
        store.replace_alias_bindings(BTreeMap::from([(
            "shared".into(),
            older.intent.storage_ticket,
        )]));
        assert_eq!(
            store.get_by_alias("shared").unwrap().0,
            &older.intent.storage_ticket
        );
        store.replace_alias_bindings(BTreeMap::new());
        assert!(store.get_by_alias("shared").is_none());
        assert_eq!(store.len(), 1);
    }
    #[test]
    fn inserts_and_overwrites_alias() {
        let mut store = DaPinStore::default();
        assert!(store.is_empty());
        let a = located(sample_intent(1, 1, Some("alias-a")), 5, 0);
        let b = located(sample_intent(2, 2, Some("alias-b")), 5, 1);
        assert!(store.insert_with_location(a.clone()));
        assert!(store.insert_with_location(b.clone()));
        assert_eq!(store.all_sorted().count(), 2);
        assert!(!store.is_empty());
        assert_eq!(store.len(), 2);
        assert_eq!(
            store
                .get_by_alias("alias-a")
                .map(|(ticket, record)| (ticket, &record.location)),
            Some((&a.intent.storage_ticket, &a.location))
        );
        assert_eq!(
            store
                .get_by_alias("alias-b")
                .map(|(ticket, record)| (ticket, &record.location)),
            Some((&b.intent.storage_ticket, &b.location))
        );
    }
    #[test]
    fn builds_from_intents() {
        let intents = vec![
            located(sample_intent(1, 1, Some("alias-a")), 1, 0),
            located(sample_intent(2, 0, None), 2, 3),
        ];
        let store = DaPinStore::from_intents(&intents);
        assert_eq!(store.all_sorted().count(), 2);
        assert_eq!(store.len(), 2);
        assert!(
            store
                .get_by_ticket(&intents[1].intent.storage_ticket)
                .is_some()
        );
        let ordered: Vec<_> = store
            .all_sorted()
            .map(|rec| (rec.location.block_height, rec.location.index_in_bundle))
            .collect();
        assert_eq!(ordered, vec![(1, 0), (2, 3)]);
    }
    #[test]
    fn seeks_strictly_after_query_location() {
        let intents = vec![
            located(sample_intent(1, 1, None), 1, 0),
            located(sample_intent(2, 2, None), 2, 0),
            located(sample_intent(3, 3, None), 3, 0),
        ];
        let store = DaPinStore::from_intents(&intents);
        let cursor = intents[1].location;
        assert!(store.contains_query_location(cursor));
        let remaining = store
            .all_sorted_after(Some(cursor))
            .map(|entry| entry.location)
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec![intents[2].location]);
        assert!(!store.contains_query_location(DaCommitmentLocation {
            block_height: 99,
            index_in_bundle: 99,
        }));
    }
    #[test]
    fn prunes_retired_lanes() {
        let mut store = DaPinStore::default();
        let lane0 = located(sample_intent(0, 1, Some("keep")), 1, 0);
        let lane1 = located(sample_intent(1, 2, Some("drop-me")), 1, 1);
        assert!(store.insert_with_location(lane0.clone()));
        assert!(store.insert_with_location(lane1.clone()));
        let retired = BTreeSet::from([LaneId::new(1)]);
        store.prune_lanes(&retired);
        assert_eq!(store.len(), 1);
        assert!(store.get_by_alias("keep").is_some(), "lane 0 alias remains");
        assert!(
            store.get_by_alias("drop-me").is_none(),
            "retired lane alias removed"
        );
        let ordered: Vec<_> = store
            .all_sorted()
            .map(|rec| rec.intent.lane_id.as_u32())
            .collect();
        assert_eq!(ordered, vec![0]);
    }
    #[test]
    fn ignores_duplicates_by_key() {
        let mut store = DaPinStore::default();
        let first = located(sample_intent(3, 4, Some("alias-dup")), 9, 0);
        let mut second = first.clone();
        second.intent.manifest_hash = ManifestDigest::new([0xAA; 32]);
        second.intent.storage_ticket = StorageTicketId::new([0xBB; 32]);
        second.location.index_in_bundle = 1;
        assert!(store.insert_with_location(first.clone()));
        assert!(!store.insert_with_location(second.clone()));
        let stored = store
            .get_by_ticket(&first.intent.storage_ticket)
            .expect("stored intent present");
        assert_eq!(stored.intent.manifest_hash, first.intent.manifest_hash);
        assert_eq!(
            stored.location.index_in_bundle,
            first.location.index_in_bundle
        );
        assert!(
            store.get_by_ticket(&second.intent.storage_ticket).is_none(),
            "conflicting ticket should be ignored"
        );
    }
    #[test]
    fn rejects_duplicate_ticket_without_index_skew() {
        let mut store = DaPinStore::default();
        let first = located(sample_intent(1, 1, None), 9, 0);
        let mut second = located(sample_intent(2, 2, None), 10, 0);
        second.intent.storage_ticket = first.intent.storage_ticket;
        assert!(store.insert_with_location(first.clone()));
        assert!(!store.insert_with_location(second.clone()));
        assert_eq!(store.all_sorted().count(), 1);
        assert!(store.get_by_ticket(&first.intent.storage_ticket).is_some());
        assert!(
            store
                .get_by_lane_epoch_sequence(
                    second.intent.lane_id.as_u32(),
                    second.intent.epoch,
                    second.intent.sequence
                )
                .is_none(),
            "duplicate ticket must not leave a lane/epoch index entry"
        );
        assert!(
            store
                .get_by_manifest(&second.intent.manifest_hash)
                .is_none(),
            "duplicate ticket must not leave a manifest index entry"
        );
    }
    #[test]
    fn rejects_duplicate_manifest_without_index_skew() {
        let mut store = DaPinStore::default();
        let first = located(sample_intent(1, 1, None), 9, 0);
        let mut second = located(sample_intent(2, 2, None), 10, 0);
        second.intent.manifest_hash = first.intent.manifest_hash;
        assert!(store.insert_with_location(first.clone()));
        assert!(!store.insert_with_location(second.clone()));
        assert_eq!(store.all_sorted().count(), 1);
        assert!(store.get_by_manifest(&first.intent.manifest_hash).is_some());
        assert!(
            store.get_by_ticket(&second.intent.storage_ticket).is_none(),
            "duplicate manifest must not leave a ticket index entry"
        );
        assert!(
            store
                .get_by_lane_epoch_sequence(
                    second.intent.lane_id.as_u32(),
                    second.intent.epoch,
                    second.intent.sequence
                )
                .is_none(),
            "duplicate manifest must not leave a lane/epoch index entry"
        );
    }
    #[test]
    fn rejects_duplicate_location_without_index_skew() {
        let mut store = DaPinStore::default();
        let first = located(sample_intent(1, 1, None), 9, 0);
        let second = located(sample_intent(2, 2, None), 9, 0);
        assert!(store.insert_with_location(first.clone()));
        assert!(!store.insert_with_location(second.clone()));
        assert_eq!(store.all_sorted().count(), 1);
        assert!(store.get_by_ticket(&first.intent.storage_ticket).is_some());
        assert!(
            store.get_by_ticket(&second.intent.storage_ticket).is_none(),
            "duplicate location must not leave a ticket index entry"
        );
        assert!(
            store
                .get_by_manifest(&second.intent.manifest_hash)
                .is_none(),
            "duplicate location must not leave a manifest index entry"
        );
    }
    #[test]
    fn contains_intent_identity_detects_key_manifest_and_ticket_collisions() {
        let mut store = DaPinStore::default();
        let first = located(sample_intent(1, 1, Some("first-alias")), 9, 0);
        assert!(store.insert_with_location(first.clone()));
        let mut duplicate_key = sample_intent(1, 1, Some("fresh-alias"));
        duplicate_key.storage_ticket = StorageTicketId::new([0x90; 32]);
        duplicate_key.manifest_hash = ManifestDigest::new([0x91; 32]);
        assert!(store.contains_intent_identity(&duplicate_key));
        let mut duplicate_ticket = sample_intent(2, 2, Some("fresh-ticket-alias"));
        duplicate_ticket.storage_ticket = first.intent.storage_ticket;
        duplicate_ticket.manifest_hash = ManifestDigest::new([0x92; 32]);
        assert!(store.contains_intent_identity(&duplicate_ticket));
        let mut duplicate_manifest = sample_intent(3, 3, Some("fresh-manifest-alias"));
        duplicate_manifest.storage_ticket = StorageTicketId::new([0x93; 32]);
        duplicate_manifest.manifest_hash = first.intent.manifest_hash;
        assert!(store.contains_intent_identity(&duplicate_manifest));
        let mut alias_reassignment = sample_intent(4, 4, Some("first-alias"));
        alias_reassignment.storage_ticket = StorageTicketId::new([0x94; 32]);
        alias_reassignment.manifest_hash = ManifestDigest::new([0x95; 32]);
        assert!(
            !store.contains_intent_identity(&alias_reassignment),
            "alias reassignment alone should not be treated as an identity collision"
        );
    }
}
