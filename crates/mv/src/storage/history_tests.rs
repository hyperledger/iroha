//! Retained images and derived indexes survive inspection, projection and revert.

use super::*;
use norito::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

fn source() -> Storage<u64, bool> {
    let storage: Storage<_, _> = [(1, true), (3, false), (5, true), (7, true)]
        .into_iter()
        .collect();
    {
        let mut block = storage.block();
        block.insert(1, false);
        block.insert(2, true);
        block.insert(3, true);
        block.remove(5);
        block.remove(99);
        block.commit();
    }
    storage
}

fn values<K: Key, V: Value + Copy>(view: &impl StorageReadOnly<K, V>) -> Vec<(K, V)> {
    view.iter()
        .map(|(key, value)| (key.clone(), *value))
        .collect()
}

#[test]
fn current_and_prior_images_merge_in_key_order_without_changing_history() {
    let mut storage = source();
    let before = json::to_json(&storage).unwrap();
    {
        let history = storage.history();
        assert_eq!(
            values(history.current()),
            vec![(1, false), (2, true), (3, true), (7, true)]
        );
        let previous: Vec<_> = history
            .iter_before_block()
            .map(|(key, value)| (*key, *value))
            .collect();
        assert_eq!(previous, vec![(1, true), (3, false), (5, true), (7, true)]);
        for (key, expected) in [
            (0, None),
            (1, Some(true)),
            (2, None),
            (3, Some(false)),
            (5, Some(true)),
            (7, Some(true)),
            (99, None),
        ] {
            assert_eq!(history.get_before_block(&key).copied(), expected);
        }
        assert_eq!(history.revert_map().get(&2), Some(&None));
        assert_eq!(history.revert_map().get(&99), Some(&None));
    }
    assert_eq!(json::to_json(&storage).unwrap(), before);
}

#[test]
fn current_only_storage_has_no_invented_undo_image() {
    let mut storage: Storage<String, u32> = [("b".to_owned(), 2), ("a".to_owned(), 1)]
        .into_iter()
        .collect();
    {
        let history = storage.history();
        assert!(history.revert_map().is_empty());
        assert_eq!(history.get_before_block("a"), Some(&1));
        assert_eq!(history.get_before_block("absent"), None);
        let current = values(history.current());
        let previous: Vec<_> = history
            .iter_before_block()
            .map(|(key, value)| (key.clone(), *value))
            .collect();
        assert_eq!(previous, current);
    }
    storage.block_and_revert().commit();
    assert_eq!(
        values(&storage.view()),
        vec![("a".into(), 1), ("b".into(), 2)]
    );
}

#[test]
fn projection_reverts_active_membership_and_retains_noop_tombstones() {
    let mut storage = source();
    let before = json::to_json(&storage).unwrap();
    let mut active = {
        let history = storage.history();
        history.project(|active| active.then_some(()))
    };
    assert_eq!(values(&active.view()), vec![(2, ()), (3, ()), (7, ())]);
    {
        let history = active.history();
        assert_eq!(
            history.revert_map().keys().copied().collect::<Vec<_>>(),
            vec![1, 2, 3, 5, 99]
        );
        assert_eq!(history.revert_map().get(&99), Some(&None));
        assert_eq!(history.revert_map().get(&3), Some(&None));
        assert_eq!(
            history
                .iter_before_block()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            vec![(1, ()), (5, ()), (7, ())]
        );
    }
    active.block_and_revert().commit();
    assert_eq!(values(&active.view()), vec![(1, ()), (5, ()), (7, ())]);
    assert_eq!(json::to_json(&storage).unwrap(), before);
}

#[test]
fn projection_preserves_replacement_values_in_both_images() {
    let mut storage: Storage<u64, u32> = [(1, 10), (4, 40)].into_iter().collect();
    {
        let mut block = storage.block();
        block.insert(1, 11);
        block.insert(2, 20);
        block.remove(4);
        block.commit();
    }
    let derived = storage.history().project(|value| Some(value * 2));
    assert_eq!(values(&derived.view()), vec![(1, 22), (2, 40)]);
    derived.block_and_revert().commit();
    assert_eq!(values(&derived.view()), vec![(1, 20), (4, 80)]);
}

#[test]
fn json_history_roundtrip_and_projection_retain_the_same_prior_image() {
    let original = source();
    let encoded = json::to_json(&original).unwrap();
    let mut restored: Storage<u64, bool> = json::from_json(&encoded).unwrap();
    let active = restored.history().project(|value| value.then_some(()));
    assert_eq!(json::to_json(&restored).unwrap(), encoded);
    active.block_and_revert().commit();
    restored.block_and_revert().commit();
    assert_eq!(
        values(&restored.view()),
        vec![(1, true), (3, false), (5, true), (7, true)]
    );
    assert_eq!(values(&active.view()), vec![(1, ()), (5, ()), (7, ())]);
}

struct Counted {
    value: u32,
    clones: Arc<AtomicUsize>,
}

impl Clone for Counted {
    fn clone(&self) -> Self {
        self.clones.fetch_add(1, AtomicOrdering::Relaxed);
        Self {
            value: self.value,
            clones: Arc::clone(&self.clones),
        }
    }
}

#[test]
fn ordinary_block_opening_does_not_clone_old_undo_and_retained_reader_keeps_it() {
    let clones = Arc::new(AtomicUsize::new(0));
    let make = |value| Counted {
        value,
        clones: Arc::clone(&clones),
    };
    let storage: Storage<u64, Counted> = (0..128).map(|key| (key, make(key as u32))).collect();
    let mut tip = storage.block();
    tip.insert(1, make(1001));
    tip.remove(126);
    tip.commit();
    let old = storage.snapshot();
    let original = old.revert_map().get(&1).unwrap().as_ref().unwrap() as *const _;
    clones.store(0, AtomicOrdering::SeqCst);

    let ordinary = storage.block();
    assert_eq!(clones.load(AtomicOrdering::SeqCst), 0);
    assert!(ordinary.revert_map().is_empty());
    assert_eq!(old.revert_map().get(&1).unwrap().as_ref().unwrap().value, 1);
    assert_eq!(
        old.revert_map().get(&126).unwrap().as_ref().unwrap().value,
        126
    );
    assert_eq!(
        old.revert_map().get(&1).unwrap().as_ref().unwrap() as *const _,
        original
    );
    ordinary.commit();

    assert_eq!(clones.load(AtomicOrdering::SeqCst), 0);
    assert!(storage.snapshot().revert_map().is_empty());
    assert_eq!(storage.view().get(&1).unwrap().value, 1001);
    assert!(storage.view().get(&126).is_none());
    assert_eq!(
        old.revert_map().get(&1).unwrap().as_ref().unwrap() as *const _,
        original
    );
    assert_eq!(
        old.revert_map().get(&126).unwrap().as_ref().unwrap().value,
        126
    );
}

#[test]
fn inspection_and_projection_do_not_clone_source_values() {
    let clones = Arc::new(AtomicUsize::new(0));
    let make = |value| Counted {
        value,
        clones: Arc::clone(&clones),
    };
    let mut storage: Storage<u64, Counted> = [(1, make(10)), (3, make(30))].into_iter().collect();
    {
        let mut block = storage.block();
        block.insert(1, make(11));
        block.insert(2, make(20));
        block.remove(3);
        block.commit();
    }
    clones.store(0, AtomicOrdering::Relaxed);
    let derived = {
        let history = storage.history();
        assert_eq!(history.current().get(&1).unwrap().value, 11);
        assert_eq!(history.get_before_block(&1).unwrap().value, 10);
        assert_eq!(
            history
                .iter_before_block()
                .map(|(_, value)| value.value)
                .collect::<Vec<_>>(),
            vec![10, 30]
        );
        history.project(|value| Some(value.value))
    };
    assert_eq!(clones.load(AtomicOrdering::Relaxed), 0);
    assert_eq!(values(&derived.view()), vec![(1, 11), (2, 20)]);
    derived.block_and_revert().commit();
    assert_eq!(values(&derived.view()), vec![(1, 10), (3, 30)]);
}

#[test]
fn transaction_prior_iteration_includes_siblings_and_replacement_baseline() {
    let storage: Storage<u64, u64> = [(1, 10), (3, 30), (5, 50)].into_iter().collect();
    let expected = vec![(1, 10), (3, 30), (5, 50)];
    {
        let mut block = storage.block();
        let mut first = block.transaction();
        first.remove(1);
        first.insert(2, 20);
        first.insert(3, 31);
        first.apply();
        let mut second = block.transaction();
        second.insert(3, 32);
        second.remove(5);
        second.insert(6, 60);
        assert_eq!(
            second
                .iter_before_block()
                .map(|(k, v)| (*k, *v))
                .collect::<Vec<_>>(),
            expected,
        );
        second.apply();
        block.commit();
    }
    let mut replacement = storage.block_and_revert();
    let mut tx = replacement.transaction();
    tx.insert(1, 11);
    tx.insert(2, 20);
    tx.remove(3);
    assert_eq!(
        tx.iter_before_block()
            .map(|(k, v)| (*k, *v))
            .collect::<Vec<_>>(),
        expected,
    );
    drop(tx);
    drop(replacement);
    assert_eq!(values(&storage.view()), vec![(2, 20), (3, 32), (6, 60)]);
}
