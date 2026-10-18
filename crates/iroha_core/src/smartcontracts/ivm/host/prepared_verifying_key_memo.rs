//! Process-local memo of verifying-key registry entries that passed the
//! complete production validation.
//!
//! Host hydration validates the World's verifying-key registry before every
//! VM run. That validation is a pure function of the registry id and the
//! complete record, so an entry equal to an already validated pair, every key
//! byte included, reuses the prepared result instead of re-hashing the key
//! and re-preparing its backend material. A pair whose id, metadata or key
//! bytes changed is always validated again. The memo never admits a key on
//! its own, never holds a rejected or locally deferred entry, and carries no
//! consensus state: removing it changes only the cost of hydration.

use std::{
    collections::BTreeMap,
    sync::{LazyLock, Mutex},
};

use iroha_data_model::proof::{VerifyingKeyId, VerifyingKeyRecord};

use super::PreparedVerifyingKey;

/// Maximum number of memoized registry entries.
///
/// The bound keeps short-lived registrations from growing the memo without
/// limit; an evicted entry is simply validated again on its next use.
const CAPACITY: usize = 128;

type Memo = BTreeMap<VerifyingKeyId, PreparedVerifyingKey>;

static MEMO: LazyLock<Mutex<Memo>> = LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Return the prepared entry memoized for exactly this registry pair.
pub(super) fn lookup(
    id: &VerifyingKeyId,
    record: &VerifyingKeyRecord,
) -> Option<PreparedVerifyingKey> {
    // Clone the shared entry under the lock and compare outside it, so a
    // large key comparison never serializes concurrent hydration.
    let candidate = MEMO.lock().ok()?.get(id).cloned()?;
    exact_match(candidate, record)
}

/// Keep a memoized entry only when its complete record equals `record`.
fn exact_match(
    candidate: PreparedVerifyingKey,
    record: &VerifyingKeyRecord,
) -> Option<PreparedVerifyingKey> {
    (candidate.record.as_ref() == record).then_some(candidate)
}

/// Remember an entry that passed the complete validation.
pub(super) fn remember(id: &VerifyingKeyId, prepared: &PreparedVerifyingKey) {
    // A poisoned memo is skipped: every caller validates on a miss.
    if let Ok(mut memo) = MEMO.lock() {
        insert_bounded(&mut memo, id, prepared, CAPACITY);
    }
}

/// Insert one entry, evicting the lowest ids while a new id would exceed `capacity`.
fn insert_bounded(
    memo: &mut Memo,
    id: &VerifyingKeyId,
    prepared: &PreparedVerifyingKey,
    capacity: usize,
) {
    if !memo.contains_key(id) {
        while memo.len() >= capacity {
            let Some(evicted) = memo.keys().next().cloned() else {
                break;
            };
            memo.remove(&evicted);
        }
    }
    memo.insert(id.clone(), prepared.clone());
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iroha_data_model::zk::BackendTag;

    use super::*;

    fn record(commitment: u8) -> VerifyingKeyRecord {
        VerifyingKeyRecord::new(
            1,
            "memo-test-circuit",
            BackendTag::Stark,
            "goldilocks",
            [0x51; 32],
            [commitment; 32],
        )
    }

    fn prepared(record: VerifyingKeyRecord) -> PreparedVerifyingKey {
        PreparedVerifyingKey {
            record: Arc::new(record),
            backend_label: Arc::from("memo-test-backend"),
            material: None,
        }
    }

    #[test]
    fn exact_match_requires_the_complete_validated_record() {
        let validated = record(0x11);
        let memoized = prepared(validated.clone());
        let hit = exact_match(memoized.clone(), &validated)
            .expect("an identical record reuses its validation");
        assert!(Arc::ptr_eq(&hit.record, &memoized.record));

        let mut changed_length = validated.clone();
        changed_length.vk_len = changed_length.vk_len.wrapping_add(1);
        assert!(
            exact_match(memoized.clone(), &changed_length).is_none(),
            "a changed record must be validated again"
        );
        let mut changed_key = validated;
        changed_key.key = Some(iroha_data_model::proof::VerifyingKeyBox::new(
            "memo-test-backend".into(),
            vec![0x01],
        ));
        assert!(
            exact_match(memoized, &changed_key).is_none(),
            "changed key bytes must be validated again"
        );
    }

    #[test]
    fn lookup_is_keyed_by_registry_id() {
        let id = VerifyingKeyId::new("memo-test", "keyed-by-id");
        let validated = record(0x12);
        remember(&id, &prepared(validated.clone()));
        assert!(
            lookup(
                &VerifyingKeyId::new("memo-test", "never-validated"),
                &validated
            )
            .is_none(),
            "a record validated under another id is not reused"
        );
    }

    #[test]
    fn insert_bounded_evicts_lowest_ids_and_replaces_in_place() {
        let mut memo = Memo::new();
        for index in 0..4_u8 {
            let id = VerifyingKeyId::new("memo-test", format!("bounded-{index}"));
            insert_bounded(&mut memo, &id, &prepared(record(index)), 3);
        }
        assert_eq!(memo.len(), 3);
        assert!(!memo.contains_key(&VerifyingKeyId::new("memo-test", "bounded-0")));

        let replaced = VerifyingKeyId::new("memo-test", "bounded-3");
        insert_bounded(&mut memo, &replaced, &prepared(record(0x77)), 3);
        assert_eq!(memo.len(), 3, "replacing an existing id evicts nothing");
        assert_eq!(memo[&replaced].record.commitment, [0x77; 32]);
    }
}
