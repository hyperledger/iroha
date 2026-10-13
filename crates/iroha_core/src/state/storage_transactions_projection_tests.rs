//! Actual replay-membership cuts, incremental updates and publication controls.
//!
//! Hashes are opaque identities already staged by the carrier owner. These tests
//! exercise storage publication, not sealed-reveal authentication or execution.

use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

type Membership = BTreeMap<Key, Value>;
type Changes = BTreeMap<Key, (Option<Value>, Option<Value>)>;

fn key(n: u64) -> Key {
    HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(n.to_le_bytes()))
}

fn height(n: usize) -> Value {
    NonZeroUsize::new(n).unwrap()
}

fn commit(storage: &TransactionsStorage, at: usize, keys: &[Key]) {
    let mut block = storage.block();
    block.insert_block(keys.iter().copied().collect(), height(at));
    block.commit().unwrap();
}

fn record(map: &mut Membership, key: &Key, at: Value) -> Result<(), ()> {
    assert!(map.insert(*key, at).is_none(), "logical key visited twice");
    Ok(())
}

fn committed(block: &TransactionsBlock<'_>) -> Membership {
    let mut map = Membership::new();
    block
        .visit_committed_membership(|key, at| record(&mut map, key, at))
        .unwrap();
    map
}

fn predecessor(block: &TransactionsBlock<'_>) -> Membership {
    let mut map = Membership::new();
    block
        .visit_predecessor_membership(|key, at| record(&mut map, key, at))
        .unwrap();
    map
}

fn staged(transition: &TransactionsMembershipTransition<'_>) -> Membership {
    let mut map = Membership::new();
    transition
        .visit_staged_membership(|key, at| record(&mut map, key, at))
        .unwrap();
    map
}

fn changes(transition: &TransactionsMembershipTransition<'_>, from_committed: bool) -> Changes {
    let mut changes = Changes::new();
    let mut record = |key: &Key, before, after| {
        assert_ne!(before, after, "net changes must exclude logical no-ops");
        assert!(changes.insert(*key, (before, after)).is_none());
        Ok::<(), ()>(())
    };
    if from_committed {
        transition.visit_committed_changes(&mut record).unwrap();
    } else {
        transition.visit_predecessor_changes(&mut record).unwrap();
    }
    changes
}

fn apply(mut before: Membership, changes: &Changes) -> Membership {
    for (key, (expected, after)) in changes {
        assert_eq!(before.get(key).copied(), *expected, "exact preimage");
        match after {
            Some(at) => {
                before.insert(*key, *at);
            }
            None => {
                before.remove(key);
            }
        }
    }
    before
}

#[test]
fn first_staged_carrier_and_alias_are_borrowed_without_publishing_or_inventing_members() {
    let storage = TransactionsStorage::new();
    let (carrier, signed_alias, unrelated) = (key(1), key(2), key(3));
    let mut block = storage.block();
    assert!(committed(&block).is_empty());
    assert!(predecessor(&block).is_empty());
    assert!(matches!(
        block.membership_transition(),
        Err(TransactionsBlockError::MissingInsertBlock)
    ));
    // The canonical carrier owner decides whether this distinct signed alias is
    // authenticated. Storage must retain exactly its staged identities.
    block.insert_block(HashSet::from([carrier, signed_alias]), height(1));
    let transition = block.membership_transition().unwrap();
    assert_eq!(transition.committed_height(), 0);
    assert_eq!(transition.predecessor_height(), 0);
    assert_eq!(transition.staged_height(), height(1));
    let expected = Membership::from([(carrier, height(1)), (signed_alias, height(1))]);
    assert_eq!(staged(&transition), expected);
    assert_eq!(
        apply(Membership::new(), &changes(&transition, false)),
        expected
    );
    assert_eq!(changes(&transition, false), changes(&transition, true));
    assert_eq!(storage.view().get(&carrier), None);
    assert_eq!(storage.view().get(&signed_alias), None);
    assert_eq!(storage.view().get(&unrelated), None);
    drop(transition);
    block.commit().unwrap();
    assert_eq!(committed(&storage.block()), expected);
    assert_eq!(storage.view().get(&unrelated), None);
}

#[test]
fn promotion_and_latest_shadowing_have_exact_cold_and_incremental_membership() {
    let storage = TransactionsStorage::new();
    let (older, repeated, latest, new) = (key(10), key(11), key(12), key(13));
    commit(&storage, 1, &[older, repeated]);
    commit(&storage, 2, &[repeated, latest]);
    let mut block = storage.block();
    let before = committed(&block);
    assert_eq!(
        before,
        Membership::from([
            (older, height(1)),
            (repeated, height(2)),
            (latest, height(2))
        ])
    );
    assert_eq!(predecessor(&block), before);
    block.insert_block(HashSet::from([older, new]), height(3));
    let transition = block.membership_transition().unwrap();
    let expected = Membership::from([
        (older, height(3)),
        (repeated, height(2)),
        (latest, height(2)),
        (new, height(3)),
    ]);
    assert_eq!(staged(&transition), expected);
    let updates = changes(&transition, true);
    assert_eq!(updates.len(), 2, "promotion is not a logical update");
    assert_eq!(updates, changes(&transition, false));
    assert_eq!(apply(before, &updates), expected);
    drop(transition);
    block.commit().unwrap();
    assert_eq!(committed(&storage.block()), expected);
    for (key, at) in expected {
        assert_eq!(storage.view().get(&key), Some(at));
    }
}

#[test]
fn replacement_distinguishes_tip_removals_from_the_logical_predecessor() {
    let storage = TransactionsStorage::new();
    let (restored, old_only, shared, retained, new) = (key(20), key(21), key(22), key(23), key(24));
    commit(&storage, 1, &[restored, retained]);
    commit(&storage, 2, &[restored, old_only, shared]);
    let mut block = storage.block_and_revert();
    let tip = committed(&block);
    let parent = predecessor(&block);
    assert_eq!(
        parent,
        Membership::from([(restored, height(1)), (retained, height(1))])
    );
    assert_eq!(tip.get(&restored), Some(&height(2)));
    block.insert_block(HashSet::from([shared, new]), height(2));
    let transition = block.membership_transition().unwrap();
    assert_eq!(transition.committed_height(), 2);
    assert_eq!(transition.predecessor_height(), 1);
    assert_eq!(transition.staged_height(), height(2));
    let expected = Membership::from([
        (restored, height(1)),
        (retained, height(1)),
        (shared, height(2)),
        (new, height(2)),
    ]);
    assert_eq!(staged(&transition), expected);
    let parent_changes = changes(&transition, false);
    assert_eq!(
        parent_changes,
        Changes::from([
            (shared, (None, Some(height(2)))),
            (new, (None, Some(height(2))))
        ])
    );
    let tip_changes = changes(&transition, true);
    assert_eq!(tip_changes.get(&old_only), Some(&(Some(height(2)), None)));
    assert_eq!(
        tip_changes.get(&restored),
        Some(&(Some(height(2)), Some(height(1))))
    );
    assert!(!tip_changes.contains_key(&shared));
    assert_eq!(apply(parent, &parent_changes), expected);
    assert_eq!(apply(tip, &tip_changes), expected);
    drop(transition);
    block.commit().unwrap();
    assert_eq!(committed(&storage.block()), expected);
    assert_eq!(storage.view().get(&old_only), None);
}

#[test]
fn repeated_identical_publication_preserves_history_for_later_replacement() {
    let storage = TransactionsStorage::new();
    let (prior, tip_only) = (key(30), key(31));
    commit(&storage, 1, &[prior]);
    commit(&storage, 2, &[prior, tip_only]);
    let original_latest = storage.latest_block.load_full().unwrap();
    for _ in 0..3 {
        let mut block = storage.block();
        let before = committed(&block);
        block.insert_block(HashSet::from([tip_only, prior]), height(2));
        let transition = block.membership_transition().unwrap();
        assert_eq!(
            transition.predecessor_height(),
            2,
            "same-height ordinary publication is a no-op"
        );
        assert_eq!(staged(&transition), before);
        assert!(changes(&transition, true).is_empty());
        assert!(changes(&transition, false).is_empty());
        drop(transition);
        block.commit().unwrap();
        assert!(Tip::ptr_eq(
            &original_latest,
            &storage.latest_block.load_full().unwrap()
        ));
        assert_eq!(storage.blocks.read().get(&prior).copied(), Some(height(1)));
        assert!(storage.blocks.read().get(&tip_only).is_none());
    }
    let mut replacement = storage.block_and_revert();
    let parent = predecessor(&replacement);
    assert_eq!(parent, Membership::from([(prior, height(1))]));
    replacement.insert_block(HashSet::new(), height(2));
    let transition = replacement.membership_transition().unwrap();
    assert_eq!(staged(&transition), parent);
    assert!(changes(&transition, false).is_empty());
    assert_eq!(
        apply(committed(&replacement), &changes(&transition, true)),
        parent
    );
    drop(transition);
    replacement.commit().unwrap();
    assert_eq!(storage.view().get(&prior), Some(height(1)));
    assert_eq!(storage.view().get(&tip_only), None);
    assert_eq!(committed(&storage.block()), parent);
}

#[test]
fn wrong_height_and_missing_stage_refuse_transition_without_mutating_membership() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[key(40)]);
    let original = committed(&storage.block());
    for (revert, wrong) in [(false, 3), (true, 2)] {
        let mut block = if revert {
            storage.block_and_revert()
        } else {
            storage.block()
        };
        assert!(matches!(
            block.membership_transition(),
            Err(TransactionsBlockError::MissingInsertBlock)
        ));
        block.insert_block(HashSet::from([key(41)]), height(wrong));
        assert!(matches!(
            block.membership_transition(),
            Err(TransactionsBlockError::HeightMismatch { .. })
        ));
        assert_eq!(committed(&block), original);
        assert!(matches!(
            block.commit(),
            Err(TransactionsBlockError::HeightMismatch { .. })
        ));
        assert_eq!(committed(&storage.block()), original);
    }
    let mut changed_same_height = storage.block();
    changed_same_height.insert_block(HashSet::from([key(42)]), height(1));
    assert!(matches!(
        changed_same_height.membership_transition(),
        Err(TransactionsBlockError::HeightMismatch { .. })
    ));
    drop(changed_same_height);
    assert_eq!(committed(&storage.block()), original);
}

#[test]
fn borrowed_visit_error_and_unwind_cannot_publish_or_poison_storage() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[key(50), key(51)]);
    let mut block = storage.block();
    let original = committed(&block);
    block.insert_block(HashSet::from([key(52), key(53)]), height(2));
    let transition = block.membership_transition().unwrap();
    let expected = staged(&transition);
    let mut calls = 0;
    assert_eq!(
        transition.visit_staged_membership(|_, _| {
            calls += 1;
            Err::<(), _>("stop")
        }),
        Err("stop")
    );
    assert_eq!(calls, 1);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _: Result<(), ()> =
                transition.visit_committed_changes(|_, _, _| panic!("consumer unwind"));
        }))
        .is_err()
    );
    assert_eq!(committed(&block), original);
    assert_eq!(staged(&transition), expected);
    drop(transition);
    drop(block);
    assert_eq!(committed(&storage.block()), original);
    // The block's write guard is released even after the consumer unwind.
    commit(&storage, 2, &[key(54)]);
    assert_eq!(storage.view().get(&key(54)), Some(height(2)));
    assert_eq!(storage.view().get(&key(52)), None);
}

#[test]
fn incremental_changes_do_not_emit_untouched_history_or_current_tip_promotion() {
    let storage = TransactionsStorage::new();
    let historical = (100..612).map(key).collect::<Vec<_>>();
    commit(&storage, 1, &historical);
    commit(&storage, 2, &[key(900)]);
    let mut block = storage.block();
    let original = committed(&block);
    block.insert_block(HashSet::from([key(100), key(901)]), height(3));
    let transition = block.membership_transition().unwrap();
    let updates = changes(&transition, true);
    assert_eq!(updates.len(), 2);
    assert_eq!(updates, changes(&transition, false));
    assert_eq!(apply(original, &updates), staged(&transition));
}

#[test]
fn staged_snapshot_matches_actual_forward_idempotent_and_replacement_publication() {
    let storage = TransactionsStorage::new();
    let (older, repeated, tip_only, replacement) = (key(1000), key(1001), key(1002), key(1003));
    commit(&storage, 1, &[older, repeated]);
    let mut forward = storage.block();
    forward.insert_block(HashSet::from([repeated, tip_only]), height(2));
    let encoded = norito::json::to_json(&forward).unwrap();
    forward.commit().unwrap();
    assert_eq!(encoded, norito::json::to_json(&storage).unwrap());
    let before_repeat = encoded;
    let mut repeated_commit = storage.block();
    repeated_commit.insert_block(HashSet::from([tip_only, repeated]), height(2));
    let repeated_snapshot = norito::json::to_json(&repeated_commit).unwrap();
    assert_eq!(
        before_repeat, repeated_snapshot,
        "staged no-op cannot promote the hot set"
    );
    repeated_commit.commit().unwrap();
    assert_eq!(before_repeat, norito::json::to_json(&storage).unwrap());
    let mut reverted = storage.block_and_revert();
    reverted.insert_block(HashSet::from([replacement]), height(2));
    let projection = reverted.membership_transition().unwrap();
    let expected = staged(&projection);
    drop(projection);
    let replacement_snapshot = norito::json::to_json(&reverted).unwrap();
    reverted.commit().unwrap();
    assert_eq!(
        replacement_snapshot,
        norito::json::to_json(&storage).unwrap()
    );
    let restored: TransactionsStorage = norito::json::from_str(&replacement_snapshot).unwrap();
    assert_eq!(committed(&restored.block()), expected);
    assert_eq!(committed(&storage.block()), expected);
    assert_eq!(restored.view().get(&repeated), Some(height(1)));
    assert_eq!(restored.view().get(&tip_only), None);
}

#[test]
fn failed_borrowed_history_visit_releases_shard_guards_and_keeps_all_entries() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[key(1100), key(1101)]);
    commit(&storage, 2, &[]);
    let block = storage.block();
    let expected = committed(&block);
    let mut calls = 0;
    assert_eq!(
        block.visit_committed_membership(|_, _| {
            calls += 1;
            Err::<(), _>("history stop")
        }),
        Err("history stop")
    );
    assert_eq!(calls, 1);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _: Result<(), ()> =
                block.visit_predecessor_membership(|_, _| panic!("history unwind"));
        }))
        .is_err()
    );
    assert_eq!(committed(&block), expected);
    drop(block);
    commit(&storage, 3, &[key(1100)]);
    assert_eq!(storage.view().get(&key(1100)), Some(height(3)));
    assert_eq!(storage.view().get(&key(1101)), Some(height(1)));
}

#[test]
fn maximum_height_allows_exact_repeat_and_replacement_but_refuses_advance() {
    let storage = TransactionsStorage::new();
    let (older, tip, new) = (key(1200), key(1201), key(1202));
    // Seed the representational boundary, then use actual publication for the
    // final height. This is a storage boundary, not execution of usize::MAX blocks.
    storage.record_committed_entrypoint_membership_for_tests([older], height(usize::MAX - 1));
    commit(&storage, usize::MAX, &[older, tip]);
    let expected = committed(&storage.block());
    let mut repeated = storage.block();
    repeated.insert_block(HashSet::from([older, tip]), height(usize::MAX));
    assert!(repeated.validate_commit().is_ok());
    let transition = repeated.membership_transition().unwrap();
    assert_eq!(transition.predecessor_height(), usize::MAX);
    assert!(changes(&transition, true).is_empty());
    drop(transition);
    repeated.commit().unwrap();
    assert_eq!(committed(&storage.block()), expected);
    let mut impossible_advance = storage.block();
    impossible_advance.insert_block(HashSet::from([new]), height(usize::MAX));
    assert!(matches!(
        impossible_advance.membership_transition(),
        Err(TransactionsBlockError::HeightOverflow)
    ));
    assert!(matches!(
        impossible_advance.commit(),
        Err(TransactionsBlockError::HeightOverflow)
    ));
    assert_eq!(committed(&storage.block()), expected);
    let mut replacement = storage.block_and_revert();
    assert_eq!(
        predecessor(&replacement),
        Membership::from([(older, height(usize::MAX - 1))])
    );
    replacement.insert_block(HashSet::from([new]), height(usize::MAX));
    let transition = replacement.membership_transition().unwrap();
    assert_eq!(transition.predecessor_height(), usize::MAX - 1);
    let after = staged(&transition);
    assert_eq!(
        apply(committed(&replacement), &changes(&transition, true)),
        after
    );
    drop(transition);
    replacement.commit().unwrap();
    assert_eq!(committed(&storage.block()), after);
    assert_eq!(storage.view().get(&older), Some(height(usize::MAX - 1)));
    assert_eq!(storage.view().get(&tip), None);
}

#[test]
fn replacement_lookup_matches_actual_predecessor_and_staged_membership() {
    let storage = TransactionsStorage::new();
    let keys = [key(801), key(802), key(803), key(804), key(805)];
    let [historical, shadowed, abandoned, replacement, absent] = keys;
    assert_eq!(storage.block_and_revert().get(&absent), None);
    commit(&storage, 1, &[historical, shadowed]);
    commit(&storage, 2, &[shadowed, abandoned]);
    let committed_view = storage.view();
    for publish in [false, true] {
        let mut block = storage.block_and_revert();
        let parent = predecessor(&block);
        for key in keys {
            assert_eq!(block.get(&key), parent.get(&key).copied());
        }
        assert_eq!(block.get(&shadowed), Some(height(1)));
        assert_eq!(block.get(&abandoned), None);
        assert_eq!(committed_view.get(&shadowed), Some(height(2)));
        assert_eq!(committed_view.get(&abandoned), Some(height(2)));
        block.insert_block(HashSet::from([shadowed, replacement]), height(2));
        let after = staged(&block.membership_transition().unwrap());
        for key in keys {
            assert_eq!(block.get(&key), after.get(&key).copied());
        }
        assert_eq!(block.get(&shadowed), Some(height(2)));
        assert_eq!(block.get(&abandoned), None);
        if publish {
            block.commit().unwrap();
            for key in keys {
                assert_eq!(storage.view().get(&key), after.get(&key).copied());
            }
        } else {
            drop(block);
            assert_eq!(storage.view().get(&abandoned), Some(height(2)));
            assert_eq!(storage.view().get(&replacement), None);
        }
    }
    let ordinary = storage.block();
    assert_eq!(ordinary.get(&historical), Some(height(1)));
    assert_eq!(ordinary.get(&shadowed), Some(height(2)));
    assert_eq!(ordinary.get(&replacement), Some(height(2)));
    assert_eq!(ordinary.get(&abandoned), None);
    assert_eq!(ordinary.get(&absent), None);
}
