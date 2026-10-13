//! Membership admission, detached custody and exact predecessor identity.

use super::*;

fn key(n: u64) -> Key {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(n.to_le_bytes()))
}

fn height(n: usize) -> Value {
    NonZeroUsize::new(n).unwrap()
}

fn stage<'storage>(
    storage: &'storage TransactionsStorage,
    at: usize,
    keys: &[Key],
) -> TransactionsBlock<'storage> {
    let mut block = storage.block();
    block.insert_block(keys.iter().copied().collect(), height(at));
    block
}

#[test]
fn prepared_membership_retains_writer_and_drop_preserves_storage() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(1)]).commit().unwrap();
    let before = norito::json::to_json(&storage).unwrap();
    let prepared = stage(&storage, 2, &[key(2)]).prepare_commit().unwrap();
    assert!(storage.write_lock.try_lock().is_none());
    assert_eq!(prepared.get(&key(1)), Some(height(1)));
    assert_eq!(prepared.get(&key(2)), Some(height(2)));
    assert!(
        prepared
            .as_block()
            .has_exact_staged_block(height(2), &HashSet::from([key(2)]))
    );
    assert_eq!(storage.view().get(&key(2)), None);
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
    drop(prepared);
    assert!(storage.write_lock.try_lock().is_some());
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
    stage(&storage, 2, &[key(3)]).commit().unwrap();
    assert_eq!(storage.view().get(&key(2)), None);
    assert_eq!(storage.view().get(&key(3)), Some(height(2)));
}

#[test]
fn prepared_membership_publishes_exact_snapshot_and_releases_writer() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(10), key(11)]).commit().unwrap();
    let prepared = stage(&storage, 2, &[key(11), key(12)])
        .prepare_commit()
        .unwrap();
    let expected = norito::json::to_json(&prepared).unwrap();
    assert_eq!(
        expected,
        norito::json::to_json(prepared.as_block()).unwrap()
    );
    assert_eq!(prepared.get(&key(10)), Some(height(1)));
    assert_eq!(prepared.get(&key(11)), Some(height(2)));
    assert_eq!(prepared.get(&key(12)), Some(height(2)));
    assert_eq!(storage.view().get(&key(11)), Some(height(1)));
    assert!(storage.write_lock.try_lock().is_none());
    prepared.publish();
    assert!(storage.write_lock.try_lock().is_some());
    assert_eq!(norito::json::to_json(&storage).unwrap(), expected);
    assert_eq!(storage.view().get(&key(10)), Some(height(1)));
    assert_eq!(storage.view().get(&key(11)), Some(height(2)));
    assert_eq!(storage.view().get(&key(12)), Some(height(2)));
}

#[test]
fn prepared_repeat_and_replacement_preserve_actual_older_membership() {
    let storage = TransactionsStorage::new();
    let (older, shared, abandoned, replacement) = (key(20), key(21), key(22), key(23));
    stage(&storage, 1, &[older, shared]).commit().unwrap();
    stage(&storage, 2, &[shared, abandoned]).commit().unwrap();
    let before_repeat = norito::json::to_json(&storage).unwrap();
    let repeated = stage(&storage, 2, &[shared, abandoned])
        .prepare_commit()
        .unwrap();
    assert_eq!(norito::json::to_json(&repeated).unwrap(), before_repeat);
    repeated.publish();
    assert_eq!(norito::json::to_json(&storage).unwrap(), before_repeat);

    let mut block = storage.block_and_revert();
    block.insert_block(HashSet::from([replacement]), height(2));
    let prepared = block.prepare_commit().unwrap();
    assert_eq!(prepared.get(&older), Some(height(1)));
    assert_eq!(prepared.get(&shared), Some(height(1)));
    assert_eq!(prepared.get(&abandoned), None);
    assert_eq!(prepared.get(&replacement), Some(height(2)));
    let expected = norito::json::to_json(&prepared).unwrap();
    prepared.publish();
    assert_eq!(norito::json::to_json(&storage).unwrap(), expected);
    assert_eq!(storage.view().get(&shared), Some(height(1)));
    assert_eq!(storage.view().get(&abandoned), None);

    // A subsequent ordinary publication and replacement use the same retained
    // history; the first replacement must never resurrect its abandoned tip.
    stage(&storage, 3, &[shared])
        .prepare_commit()
        .unwrap()
        .publish();
    let mut block = storage.block_and_revert();
    block.insert_block(HashSet::new(), height(3));
    block.prepare_commit().unwrap().publish();
    assert_eq!(storage.view().get(&shared), Some(height(1)));
    assert_eq!(storage.view().get(&replacement), Some(height(2)));
    assert_eq!(storage.view().get(&abandoned), None);
}

#[test]
fn membership_admission_errors_drop_writer_without_publication() {
    let storage = TransactionsStorage::new();
    let empty = norito::json::to_json(&storage).unwrap();
    assert!(matches!(
        storage.block().prepare_commit(),
        Err(TransactionsBlockError::MissingInsertBlock)
    ));
    assert!(storage.write_lock.try_lock().is_some());
    assert!(matches!(
        stage(&storage, 2, &[key(30)]).prepare_commit(),
        Err(TransactionsBlockError::HeightMismatch {
            expected_current_height: 1,
            actual_current_height: 2
        })
    ));
    assert!(storage.write_lock.try_lock().is_some());
    let mut replacement = storage.block_and_revert();
    replacement.insert_block(HashSet::from([key(30)]), height(1));
    assert!(matches!(
        replacement.prepare_commit(),
        Err(TransactionsBlockError::HeightMismatch {
            expected_current_height: 0,
            actual_current_height: 1
        })
    ));
    assert_eq!(norito::json::to_json(&storage).unwrap(), empty);
    stage(&storage, 1, &[key(31)]).commit().unwrap();
    let before = norito::json::to_json(&storage).unwrap();
    assert!(matches!(
        stage(&storage, 1, &[key(32)]).prepare_commit(),
        Err(TransactionsBlockError::HeightMismatch {
            expected_current_height: 2,
            actual_current_height: 1
        })
    ));
    assert!(storage.write_lock.try_lock().is_some());
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
}

#[test]
fn prepared_maximum_height_repeat_and_replacement_do_not_require_advance() {
    let storage = TransactionsStorage::new();
    let (older, tip, replacement) = (key(40), key(41), key(42));
    // Seed only the storage representational boundary, not consensus finality.
    storage.record_committed_entrypoint_membership_for_tests([older], height(usize::MAX - 1));
    stage(&storage, usize::MAX, &[older, tip])
        .prepare_commit()
        .unwrap()
        .publish();
    let before = norito::json::to_json(&storage).unwrap();
    assert!(matches!(
        stage(&storage, usize::MAX, &[replacement]).prepare_commit(),
        Err(TransactionsBlockError::HeightOverflow)
    ));
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
    stage(&storage, usize::MAX, &[older, tip])
        .prepare_commit()
        .unwrap()
        .publish();
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
    let mut block = storage.block_and_revert();
    block.insert_block(HashSet::from([replacement]), height(usize::MAX));
    block.prepare_commit().unwrap().publish();
    assert_eq!(storage.view().get(&older), Some(height(usize::MAX - 1)));
    assert_eq!(storage.view().get(&tip), None);
    assert_eq!(storage.view().get(&replacement), Some(height(usize::MAX)));
}

#[test]
fn detached_membership_releases_writer_without_copying_or_publishing() {
    fn assert_send<T: Send + 'static>() {}
    assert_send::<DetachedTransactionsBlock>();
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(50)]).commit().unwrap();
    let before = norito::json::to_json(&storage).unwrap();
    let prepared = stage(&storage, 2, &[key(51)]).prepare_commit().unwrap();
    let allocation: *const TipKeys = &raw const prepared
        .as_block()
        .current_block
        .as_ref()
        .unwrap()
        .transactions;
    let detached = prepared.detach();
    assert!(storage.write_lock.try_lock().is_some());
    assert_eq!(detached.predecessor_height(), 1);
    assert!(!detached.replaces_tip());
    let (staged_height, staged_keys) = detached.staged_membership();
    assert_eq!(staged_height, height(2));
    assert_eq!(staged_keys, &HashSet::from([key(51)]));
    assert_eq!(
        detached.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
    // Compare the retained set itself: admission moves the existing immutable
    // payload allocation rather than rebuilding a second membership journal.
    let held: *const TipKeys = detached.staged_membership().1;
    assert_eq!(held, allocation);
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
    drop(detached);
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
}

#[test]
fn detached_candidates_share_a_cut_and_observe_busy_without_waiting() {
    let storage = TransactionsStorage::new();
    let first = stage(&storage, 1, &[key(60)])
        .prepare_commit()
        .unwrap()
        .detach();
    let second = stage(&storage, 1, &[key(61)])
        .prepare_commit()
        .unwrap()
        .detach();
    assert_eq!(first.predecessor_height(), 0);
    assert_eq!(
        second.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
    let abandoned = stage(&storage, 1, &[key(62)]);
    assert_eq!(
        first.observe_predecessor(&storage),
        MembershipPredecessorStatus::Busy
    );
    drop(abandoned);
    assert_eq!(
        first.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
    stage(&storage, 1, &[key(63)]).commit().unwrap();
    assert_eq!(
        first.observe_predecessor(&storage),
        MembershipPredecessorStatus::Changed
    );
    assert_eq!(
        second.observe_predecessor(&storage),
        MembershipPredecessorStatus::Changed
    );
    assert_eq!(first.staged_membership().1, &HashSet::from([key(60)]));
}

#[test]
fn detached_replacement_retains_mode_and_rejects_same_height_aba() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(70)]).commit().unwrap();
    stage(&storage, 2, &[key(71)]).commit().unwrap();
    let mut replacement = storage.block_and_revert();
    replacement.insert_block(HashSet::from([key(72)]), height(2));
    let detached = replacement.prepare_commit().unwrap().detach();
    assert!(detached.replaces_tip());
    assert_eq!(detached.predecessor_height(), 2);
    assert_eq!(detached.staged_membership().1, &HashSet::from([key(72)]));
    assert_eq!(storage.view().get(&key(71)), Some(height(2)));
    for keys in [HashSet::from([key(73)]), HashSet::from([key(71)])] {
        let mut replacement = storage.block_and_revert();
        replacement.insert_block(keys, height(2));
        replacement.commit().unwrap();
    }
    assert_eq!(
        detached.observe_predecessor(&storage),
        MembershipPredecessorStatus::Changed
    );
    assert_eq!(storage.view().get(&key(71)), Some(height(2)));
    assert_eq!(storage.view().get(&key(72)), None);
}

#[test]
fn detached_membership_noop_and_refusal_preserve_identity() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(80)]).commit().unwrap();
    let detached = stage(&storage, 2, &[key(81)])
        .prepare_commit()
        .unwrap()
        .detach();
    stage(&storage, 1, &[key(80)]).commit().unwrap();
    assert!(stage(&storage, 3, &[key(82)]).prepare_commit().is_err());
    assert_eq!(
        detached.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
}

#[test]
fn detached_membership_identity_covers_history_without_a_height_change() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(90)]).commit().unwrap();
    stage(&storage, 2, &[key(91)]).commit().unwrap();
    let detached = stage(&storage, 3, &[key(92)])
        .prepare_commit()
        .unwrap()
        .detach();
    storage.record_committed_entrypoint_membership_for_tests([key(93)], height(1));
    assert_eq!(storage.latest_height(), 2);
    assert_eq!(
        detached.observe_predecessor(&storage),
        MembershipPredecessorStatus::Changed
    );
    let detached = stage(&storage, 3, &[key(92)])
        .prepare_commit()
        .unwrap()
        .detach();
    storage.overwrite_committed_entrypoint_membership_for_tests(key(90), height(2));
    assert_eq!(storage.latest_height(), 2);
    assert_eq!(
        detached.observe_predecessor(&storage),
        MembershipPredecessorStatus::Changed
    );
}

#[test]
fn restored_membership_mints_a_distinct_process_local_identity() {
    let storage = TransactionsStorage::new();
    stage(&storage, 1, &[key(100)]).commit().unwrap();
    let encoded = norito::json::to_json(&storage).unwrap();
    let restored: TransactionsStorage = norito::json::from_str(&encoded).unwrap();
    assert_eq!(norito::json::to_json(&restored).unwrap(), encoded);
    assert!(!Identity::ptr_eq(
        &storage.write_lock.lock(),
        &restored.write_lock.lock(),
    ));
    let original = stage(&storage, 2, &[key(101)])
        .prepare_commit()
        .unwrap()
        .detach();
    assert_eq!(
        original.observe_predecessor(&restored),
        MembershipPredecessorStatus::Changed
    );
    stage(&restored, 2, &[key(102)]).commit().unwrap();
    assert_eq!(
        original.observe_predecessor(&storage),
        MembershipPredecessorStatus::Current
    );
}
