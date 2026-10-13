//! Actual membership publication identity, external root and failure controls.
//! Opaque aliases here are already staged by the canonical carrier owner; these
//! tests do not substitute for sealed-transaction admission authentication.

use super::*;
use iroha_crypto::{MerkleMap, MerkleMapNode, MerkleMapNodeRef};

#[derive(Clone, Default)]
struct Store {
    // Physical reads use only these numeric locations. The test-only allocation
    // registries preserve issued locations across idempotent writes and injected
    // payload loss; they are not a production content-index implementation.
    nodes: BTreeMap<u64, MerkleMapNode<u64, u64>>,
    heights: BTreeMap<u64, u64>,
    node_allocations: BTreeMap<Digest, u64>,
    height_allocations: BTreeMap<Digest, u64>,
    next_node: u64,
    next_height: u64,
    height_reads: usize,
    height_writes: usize,
    fail_height_read: Option<usize>,
    fail_height_write: Option<usize>,
    panic_height_write: Option<usize>,
    reads: usize,
    writes: usize,
    fail_read: Option<usize>,
    fail_write: Option<usize>,
}

impl MerkleMapNodeStore for Store {
    type NodeLocation = u64;
    type ValueLocation = u64;
    type Error = &'static str;

    fn read(
        &mut self,
        reference: &MerkleMapNodeRef<u64>,
    ) -> Result<Option<MerkleMapNode<u64, u64>>, Self::Error> {
        self.reads += 1;
        if self.fail_read == Some(self.reads) {
            return Err("read refused");
        }
        Ok(self.nodes.get(&reference.location).copied())
    }

    fn write(&mut self, node: MerkleMapNode<u64, u64>) -> Result<u64, Self::Error> {
        self.writes += 1;
        let reference = node.hash();
        if let MerkleMapNode::Leaf { value, .. } = node {
            let height = *self
                .heights
                .get(&value.location)
                .expect("value retained before leaf");
            assert!(height > 0);
            assert_eq!(value.hash, canonical_height_digest(height));
        }
        if let MerkleMapNode::Branch { left, right, .. } = node {
            assert_eq!(self.nodes[&left.location].hash(), left.hash);
            assert_eq!(self.nodes[&right.location].hash(), right.hash);
        }
        let retained = self
            .node_allocations
            .get(&reference)
            .copied()
            .filter(|at| self.nodes.get(at).is_some_and(|previous| *previous == node));
        let location = retained.unwrap_or_else(|| {
            let location = self.next_node;
            self.next_node += 1;
            self.node_allocations.insert(reference, location);
            location
        });
        if let Some(previous) = self.nodes.get(&location) {
            assert_eq!(*previous, node, "immutable node and original locations");
        } else {
            self.nodes.insert(location, node);
        }
        if self.fail_write == Some(self.writes) {
            return Err("write refused after persistence");
        }
        Ok(location)
    }
}

impl MembershipStore for Store {
    fn read_height(
        &mut self,
        reference: &MerkleMapValueRef<u64>,
    ) -> Result<Option<u64>, Self::Error> {
        self.height_reads += 1;
        if self.fail_height_read == Some(self.height_reads) {
            return Err("height read refused");
        }
        Ok(self.heights.get(&reference.location).copied())
    }

    fn write_height(&mut self, reference: Digest, height: u64) -> Result<u64, Self::Error> {
        self.height_writes += 1;
        assert!(height > 0);
        assert_eq!(reference, canonical_height_digest(height));
        let location = *self.height_allocations.entry(reference).or_insert_with(|| {
            let location = self.next_height;
            self.next_height += 1;
            location
        });
        if let Some(previous) = self.heights.insert(location, height) {
            assert_eq!(previous, height, "immutable height binding");
        }
        assert_ne!(
            self.panic_height_write,
            Some(self.height_writes),
            "height write unwind"
        );
        if self.fail_height_write == Some(self.height_writes) {
            return Err("height write refused after persistence");
        }
        Ok(location)
    }
}

fn key(n: u64) -> Key {
    HashOf::from_untyped_unchecked(Digest::new(n.to_le_bytes()))
}
fn height(n: usize) -> Value {
    NonZeroUsize::new(n).unwrap()
}
fn commit(storage: &TransactionsStorage, at: usize, keys: &[u64]) {
    let mut block = storage.block();
    block.insert_block(keys.iter().copied().map(key).collect(), height(at));
    block.commit().unwrap();
}
fn cold(
    storage: &TransactionsStorage,
    store: &mut Store,
    workspace: &mut MerkleMapUpdateWorkspace<u64, u64>,
) -> CommittedMembershipRoot<u64> {
    storage
        .block()
        .capture_committed_root(100_000, store, workspace)
        .unwrap()
}
fn assert_members(
    root: &CommittedMembershipRoot<u64>,
    store: &mut Store,
    expected: &[(u64, usize)],
) {
    for n in 0..80 {
        let value = expected
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, h)| height(*h));
        assert_eq!(root.read(&key(n), store).unwrap(), value, "key {n}");
    }
    let mut reference = MerkleMap::new(&iroha_allocation::AllocationBudget::new(64 * 1024 * 1024));
    for &(n, h) in expected.iter().rev() {
        reference
            .replace(
                key_digest(&key(n)),
                None,
                Some(value_digest::<()>(height(h)).unwrap()),
            )
            .unwrap();
    }
    assert_eq!(root.root.hash(), reference.root());
    assert_eq!(root.root.parts().0, reference.len());
}

#[test]
fn actual_cold_capture_and_incremental_publication_have_identical_roots() {
    let storage = TransactionsStorage::new();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let empty = cold(&storage, &mut store, &mut workspace);
    commit(&storage, 1, &[1, 2]);
    commit(&storage, 2, &[2, 3]);
    let before = cold(&storage, &mut store, &mut workspace);
    assert_members(&before, &mut store, &[(1, 1), (2, 2), (3, 2)]);
    let mut block = storage.block();
    block.insert_block([key(1), key(4)].into_iter().collect(), height(3));
    let mut prepared = block.prepare_commit().unwrap();
    let candidate = prepared
        .prepare_membership_root(&before, &mut store, &mut workspace)
        .unwrap();
    assert_eq!(
        storage.view().get(&key(4)),
        None,
        "preparation never publishes"
    );
    assert_members(&before, &mut store, &[(1, 1), (2, 2), (3, 2)]);
    prepared.try_prepare_physical().unwrap();
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("original preparation"));
    drop(retirement);
    assert_members(&after, &mut store, &[(1, 3), (2, 2), (3, 2), (4, 3)]);
    assert_eq!(
        after.commitment(),
        cold(&storage, &mut store, &mut workspace).commitment()
    );
    assert_members(&empty, &mut store, &[]);
    assert_members(&before, &mut store, &[(1, 1), (2, 2), (3, 2)]);
}

#[test]
fn replacement_restores_older_alias_values_and_removes_abandoned_tip_members() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1, 2]);
    commit(&storage, 2, &[1, 3, 4]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let before = cold(&storage, &mut store, &mut workspace);
    let mut block = storage.block_and_revert();
    block.insert_block([key(4), key(5)].into_iter().collect(), height(2));
    let mut prepared = block.prepare_commit().unwrap();
    let candidate = prepared
        .prepare_membership_root(&before, &mut store, &mut workspace)
        .unwrap();
    prepared.try_prepare_physical().unwrap();
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("original replacement"));
    drop(retirement);
    assert_members(&before, &mut store, &[(1, 2), (2, 1), (3, 2), (4, 2)]);
    assert_members(&after, &mut store, &[(1, 1), (2, 1), (4, 2), (5, 2)]);
    assert_eq!(
        after.commitment(),
        cold(&storage, &mut store, &mut workspace).commitment()
    );
}

#[test]
fn foreign_and_untouched_changed_baselines_fail_before_store_access() {
    let original = TransactionsStorage::new();
    let foreign = TransactionsStorage::new();
    for storage in [&original, &foreign] {
        commit(storage, 1, &[1, 2]);
        commit(storage, 2, &[3]);
    }
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&original, &mut store, &mut workspace);
    let foreign_root = cold(&foreign, &mut store, &mut workspace);
    assert_eq!(
        baseline.commitment(),
        foreign_root.commitment(),
        "equal bytes do not transfer publication custody"
    );
    let mut block = foreign.block();
    block.insert_block([key(4)].into_iter().collect(), height(3));
    let prepared = block.prepare_commit().unwrap();
    store.reads = 0;
    store.writes = 0;
    store.height_reads = 0;
    store.height_writes = 0;
    assert!(matches!(
        prepared.prepare_membership_root(&baseline, &mut store, &mut workspace),
        Err(MembershipRootError::PredecessorChanged)
    ));
    assert_eq!(
        (
            store.reads,
            store.writes,
            store.height_reads,
            store.height_writes
        ),
        (0, 0, 0, 0)
    );
    drop(prepared);
    original.overwrite_committed_entrypoint_membership_for_tests(key(1), height(2));
    let mut block = original.block();
    block.insert_block([key(4)].into_iter().collect(), height(3));
    let prepared = block.prepare_commit().unwrap();
    assert!(matches!(
        prepared.prepare_membership_root(&baseline, &mut store, &mut workspace),
        Err(MembershipRootError::PredecessorChanged)
    ));
    assert_eq!(
        (
            store.reads,
            store.writes,
            store.height_reads,
            store.height_writes
        ),
        (0, 0, 0, 0),
        "untouched corruption is rejected without a history scan"
    );
}

#[test]
fn repeated_publication_preserves_identity_and_empty_frontiers_are_committed() {
    let storage = TransactionsStorage::new();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let empty = cold(&storage, &mut store, &mut workspace);
    let mut block = storage.block();
    block.insert_block(BTreeSet::new(), height(1));
    let mut prepared = block.prepare_commit().unwrap();
    let candidate = prepared
        .prepare_membership_root(&empty, &mut store, &mut workspace)
        .unwrap();
    prepared.try_prepare_physical().unwrap();
    let (first, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("first empty publication"));
    drop(retirement);
    assert_eq!(first.root, empty.root);
    assert_ne!(
        first.commitment(),
        empty.commitment(),
        "frontier is part of the logical commitment"
    );
    let mut block = storage.block();
    block.insert_block(BTreeSet::new(), height(1));
    let mut prepared = block.prepare_commit().unwrap();
    store.reads = 0;
    store.writes = 0;
    store.height_reads = 0;
    store.height_writes = 0;
    let candidate = prepared
        .prepare_membership_root(&first, &mut store, &mut workspace)
        .unwrap();
    prepared.try_prepare_physical().unwrap();
    let (again, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("repeated publication"));
    drop(retirement);
    assert!(Identity::ptr_eq(&first.identity, &again.identity));
    assert_eq!(first.commitment(), again.commitment());
    assert_eq!(
        (
            store.reads,
            store.writes,
            store.height_reads,
            store.height_writes
        ),
        (0, 0, 0, 0)
    );
}

#[test]
fn every_external_failure_retains_original_state_and_retries_the_same_preparation() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &(0..64).collect::<Vec<_>>());
    let mut original = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut original, &mut workspace);
    let mut block = storage.block();
    block.insert_block([key(5), key(65), key(66)].into_iter().collect(), height(2));
    let prepared = block.prepare_commit().unwrap();
    let mut successful = original.clone();
    successful.reads = 0;
    successful.writes = 0;
    let expected = prepared
        .prepare_membership_root(&baseline, &mut successful, &mut workspace)
        .unwrap();
    for (read_failure, count) in [(true, successful.reads), (false, successful.writes)] {
        for cut in 1..=count {
            let mut failed = original.clone();
            failed.reads = 0;
            failed.writes = 0;
            if read_failure {
                failed.fail_read = Some(cut);
            } else {
                failed.fail_write = Some(cut);
            }
            assert!(matches!(
                prepared.prepare_membership_root(&baseline, &mut failed, &mut workspace),
                Err(MembershipRootError::Update(_))
            ));
            assert_eq!(storage.view().get(&key(65)), None);
            assert_eq!(storage.view().get(&key(5)), Some(height(1)));
            for (reference, node) in &original.nodes {
                assert_eq!(failed.nodes.get(reference), Some(node));
            }
            failed.fail_read = None;
            failed.fail_write = None;
            let retried = prepared
                .prepare_membership_root(&baseline, &mut failed, &mut workspace)
                .unwrap();
            assert_eq!(retried.after.commitment(), expected.after.commitment());
        }
    }
    drop(expected);
    drop(prepared);
    assert_eq!(
        baseline.commitment(),
        cold(&storage, &mut original, &mut workspace).commitment()
    );
}

#[test]
fn only_the_original_preparation_can_publish_a_root_after_detachment_and_abort() {
    let original = TransactionsStorage::new();
    let foreign = TransactionsStorage::new();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&original, &mut store, &mut workspace);
    let mut block = original.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    let prepared = block.prepare_commit().unwrap();
    let candidate = prepared
        .prepare_membership_root(&baseline, &mut store, &mut workspace)
        .unwrap();
    let detached = prepared.detach();
    let mut block = foreign.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    let wrong = block.prepare_commit().unwrap();
    let (wrong, candidate) = wrong
        .publish_with_membership_root(candidate)
        .err()
        .expect("different original preparation");
    assert_eq!(foreign.view().get(&key(1)), None);
    drop(wrong);
    // The same storage, unchanged predecessor, height and payload still do not
    // make a newly prepared owner the original issuer of this candidate root.
    let mut retry = original.block();
    retry.insert_block([key(1)].into_iter().collect(), height(1));
    let recreated = retry.prepare_commit().unwrap();
    let (recreated, candidate) = recreated
        .publish_with_membership_root(candidate)
        .err()
        .expect("reconstructed preparation cannot steal the root");
    assert_eq!(original.view().get(&key(1)), None);
    drop(recreated);
    let reacquired = detached
        .try_prepare_publication(&original, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("original predecessor"));
    let (detached, cleanup) = reacquired.abort();
    drop(cleanup);
    assert_eq!(original.view().get(&key(1)), None);
    let reacquired = detached
        .try_prepare_publication(&original, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("same original predecessor"));
    let (after, retirement) = reacquired
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("original detached preparation"));
    drop(retirement);
    assert_members(&after, &mut store, &[(1, 1)]);
    assert_eq!(
        after.commitment(),
        cold(&original, &mut store, &mut workspace).commitment()
    );
}

#[test]
fn fixed_vectors_bind_canonical_key_height_and_frontier_domains() {
    // Independent Python hashlib.blake2b(digest_size=32) calculations, applying
    // the existing Iroha low-bit marker after each hash.
    assert_eq!(
        key_digest(&key(1)).to_string(),
        "d96951760b26f04ee022673b496a5a51f3b80aafa8bbeae7a9abc87796ce77cd"
    );
    assert_eq!(
        value_digest::<()>(height(1)).unwrap().to_string(),
        "2535490b391cd4d072382686a40e5297c53b9fa6e59fe1966bb2daa09d53880f"
    );
    let storage = TransactionsStorage::new();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    assert_eq!(
        cold(&storage, &mut store, &mut workspace)
            .commitment()
            .to_string(),
        "d970b8cfc1e3c32510ba3f458bfaa0c1afa47eccc05c0658aa7117dccd4f7ad1"
    );
    commit(&storage, 1, &[1]);
    assert_eq!(
        cold(&storage, &mut store, &mut workspace)
            .commitment()
            .to_string(),
        "cbb96e709e9de9a8c6c8b6c234d0c50c5aaa233b8b7cb23bb1b8f898bae0b04d"
    );
}

#[test]
fn failed_cold_capture_keeps_state_and_restoration_requires_its_own_identity() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &(0..24).collect::<Vec<_>>());
    commit(&storage, 2, &[2, 3, 24]);
    let bytes = norito::json::to_json(&storage).unwrap();
    let restored: TransactionsStorage = norito::json::from_str(&bytes).unwrap();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    assert!(store.writes > 24 && store.reads > 24);
    // A populated current root and populated predecessor ensure the failure
    // matrix crosses the handoff between their two cold reconstructions.
    assert!(baseline.root.parts().0 > 0 && baseline.predecessor.parts().0 > 0);
    for (read_failure, count) in [(true, store.reads), (false, store.writes)] {
        for cut in 1..=count {
            let mut failed = Store::default();
            if read_failure {
                failed.fail_read = Some(cut);
            } else {
                failed.fail_write = Some(cut);
            }
            {
                let block = storage.block();
                assert!(matches!(
                    block.capture_committed_root(100_000, &mut failed, &mut workspace),
                    Err(MembershipRootError::Update(_))
                ));
            }
            assert_eq!(norito::json::to_json(&storage).unwrap(), bytes);
            failed.fail_read = None;
            failed.fail_write = None;
            assert_eq!(
                cold(&storage, &mut failed, &mut workspace).commitment(),
                baseline.commitment()
            );
        }
    }
    let restored_root = cold(&restored, &mut store, &mut workspace);
    assert_eq!(restored_root.commitment(), baseline.commitment());
    assert!(!Identity::ptr_eq(
        &restored_root.identity,
        &baseline.identity
    ));
    let mut block = restored.block();
    block.insert_block([key(25)].into_iter().collect(), height(3));
    let mut prepared = block.prepare_commit().unwrap();
    store.reads = 0;
    store.writes = 0;
    store.height_reads = 0;
    store.height_writes = 0;
    assert!(matches!(
        prepared.prepare_membership_root(&baseline, &mut store, &mut workspace),
        Err(MembershipRootError::PredecessorChanged)
    ));
    assert_eq!(
        (
            store.reads,
            store.writes,
            store.height_reads,
            store.height_writes
        ),
        (0, 0, 0, 0)
    );
    let candidate = prepared
        .prepare_membership_root(&restored_root, &mut store, &mut workspace)
        .unwrap();
    prepared.try_prepare_physical().unwrap();
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("restored original publication"));
    drop(retirement);
    assert_eq!(
        after.commitment(),
        cold(&restored, &mut store, &mut workspace).commitment()
    );
}

#[test]
fn equal_current_membership_cannot_hide_different_rollback_values() {
    let first = TransactionsStorage::new();
    let second = TransactionsStorage::new();
    commit(&first, 1, &[1]);
    commit(&first, 2, &[]);
    commit(&first, 3, &[1]);
    commit(&second, 1, &[]);
    commit(&second, 2, &[1]);
    commit(&second, 3, &[1]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let a = cold(&first, &mut store, &mut workspace);
    let b = cold(&second, &mut store, &mut workspace);
    assert_eq!(
        (a.root.hash(), a.root.parts().0, a.height),
        (b.root.hash(), b.root.parts().0, b.height),
        "current membership cannot distinguish these actual histories"
    );
    assert_ne!(
        a.commitment(),
        b.commitment(),
        "the portable commitment must bind rollback values too"
    );
    assert_eq!(a.read(&key(1), &mut store).unwrap(), Some(height(3)));
    assert_eq!(b.read(&key(1), &mut store).unwrap(), Some(height(3)));
    assert_eq!(
        a.read_predecessor(&key(1), &mut store).unwrap(),
        Some(height(1))
    );
    assert_eq!(
        b.read_predecessor(&key(1), &mut store).unwrap(),
        Some(height(2))
    );
    for (storage, baseline, expected) in [(&first, a, 1), (&second, b, 2)] {
        let mut replacement = storage.block_and_revert();
        replacement.insert_block(BTreeSet::new(), height(3));
        let mut prepared = replacement.prepare_commit().unwrap();
        let candidate = prepared
            .prepare_membership_root(&baseline, &mut store, &mut workspace)
            .unwrap();
        prepared.try_prepare_physical().unwrap();
        let (after, retirement) = prepared
            .publish_with_membership_root(candidate)
            .unwrap_or_else(|_| panic!("original replacement"));
        drop(retirement);
        assert_eq!(storage.view().get(&key(1)), Some(height(expected)));
        assert_eq!(
            after.read(&key(1), &mut store).unwrap(),
            Some(height(expected))
        );
        assert_eq!(after.predecessor, baseline.predecessor);
        assert_eq!(
            after.commitment(),
            cold(storage, &mut store, &mut workspace).commitment()
        );
    }
}

#[test]
fn all_publication_modes_retain_the_exact_original_rollback_cut() {
    let storage = TransactionsStorage::new();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let mut baseline = cold(&storage, &mut store, &mut workspace);
    for (revert, at, keys) in [
        (false, 1, [1, 2]),
        (false, 2, [2, 3]),
        (true, 2, [3, 4]),
        (false, 2, [3, 4]),
        (false, 3, [4, 5]),
    ] {
        let expected = if !revert && at as u64 > baseline.height {
            baseline.root
        } else {
            baseline.predecessor
        };
        let mut block = if revert {
            storage.block_and_revert()
        } else {
            storage.block()
        };
        block.insert_block(keys.into_iter().map(key).collect(), height(at));
        let mut prepared = block.prepare_commit().unwrap();
        let candidate = prepared
            .prepare_membership_root(&baseline, &mut store, &mut workspace)
            .unwrap();
        assert_eq!(candidate.after.predecessor, expected);
        prepared.try_prepare_physical().unwrap();
        let (after, retirement) = prepared
            .publish_with_membership_root(candidate)
            .unwrap_or_else(|_| panic!("original mode"));
        drop(retirement);
        assert_eq!(
            after.commitment(),
            cold(&storage, &mut store, &mut workspace).commitment()
        );
        let rollback = storage.block_and_revert();
        let cold_from_replacement = rollback
            .capture_committed_root(100_000, &mut store, &mut workspace)
            .unwrap();
        assert_eq!(
            cold_from_replacement.commitment(),
            after.commitment(),
            "cold capture must not depend on caller mode"
        );
        for n in 0..8 {
            let expected = rollback.get(&key(n));
            assert_eq!(
                after.read_predecessor(&key(n), &mut store).unwrap(),
                expected
            );
        }
        drop(rollback);
        baseline = after;
    }
}

#[test]
fn current_and_rollback_values_require_exact_authenticated_preimages() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1]);
    commit(&storage, 2, &[1]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    for (rollback, at) in [(false, 2), (true, 1)] {
        let read = |store: &mut Store| {
            if rollback {
                baseline.read_predecessor(&key(1), store)
            } else {
                baseline.read(&key(1), store)
            }
        };
        let reference = canonical_height_digest(at);
        let location = store.height_allocations[&reference];
        assert_eq!(
            read(&mut store).unwrap(),
            Some(height(
                usize::try_from(at).expect("fixture value fits usize")
            ))
        );
        store.heights.remove(&location);
        assert_eq!(
            read(&mut store),
            Err(MembershipReadError::MissingValue(reference))
        );
        for corrupt in [0, 3 - at, 3, u64::MAX] {
            store.heights.insert(location, corrupt);
            assert_eq!(
                read(&mut store),
                Err(MembershipReadError::InvalidValue(reference))
            );
        }
        store.heights.insert(location, at);
        store.fail_height_read = Some(store.height_reads + 1);
        assert_eq!(
            read(&mut store),
            Err(MembershipReadError::ValueSource("height read refused"))
        );
        store.fail_height_read = None;
        assert_eq!(
            read(&mut store).unwrap(),
            Some(height(
                usize::try_from(at).expect("fixture value fits usize")
            ))
        );
    }
    // Even a matching preimage cannot place a leaf beyond its retained cut.
    let mut wrong_frontier = baseline.clone();
    wrong_frontier.height = 1;
    assert_eq!(
        wrong_frontier.read(&key(1), &mut store),
        Err(MembershipReadError::InvalidValue(canonical_height_digest(
            2
        )))
    );
}

#[test]
fn authenticated_absence_and_path_failures_never_read_a_height() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1, 2]);
    commit(&storage, 2, &[1, 3]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    for rollback in [false, true] {
        let read = |key: &Key, store: &mut Store| {
            if rollback {
                baseline.read_predecessor(key, store)
            } else {
                baseline.read(key, store)
            }
        };
        let mut failed = store.clone();
        failed.heights.clear();
        failed.height_reads = 0;
        assert_eq!(read(&key(77), &mut failed).unwrap(), None);
        assert_eq!(
            failed.height_reads, 0,
            "authenticated absence needs no value"
        );
        let root = if rollback {
            baseline.predecessor
        } else {
            baseline.root
        };
        let reference = root.parts().1.unwrap();
        let original = failed.nodes.remove(&reference.location).unwrap();
        assert!(matches!(
            read(&key(1), &mut failed),
            Err(MembershipReadError::Tree(MerkleMapReadError::MissingNode(
                _
            )))
        ));
        failed.nodes.insert(
            reference.location,
            MerkleMapNode::Leaf {
                key: key_digest(&key(99)),
                value: MerkleMapValueRef {
                    hash: canonical_height_digest(1),
                    location: u64::MAX,
                },
            },
        );
        assert!(matches!(
            read(&key(1), &mut failed),
            Err(MembershipReadError::Tree(
                MerkleMapReadError::NodeHashMismatch(_)
            ))
        ));
        failed.nodes.insert(reference.location, original);
        failed.fail_read = Some(failed.reads + 1);
        assert!(matches!(
            read(&key(1), &mut failed),
            Err(MembershipReadError::Tree(MerkleMapReadError::Source(
                "read refused"
            )))
        ));
        assert_eq!(
            failed.height_reads, 0,
            "authenticate the path before value I/O"
        );
    }
}

#[test]
fn every_height_write_failure_retains_original_cold_and_prepared_custody() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1, 2, 3]);
    commit(&storage, 2, &[1, 4]);
    let before = norito::json::to_json(&storage).unwrap();
    let mut original = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut original, &mut workspace);
    assert!(original.height_writes > original.heights.len());
    for cut in 1..=original.height_writes {
        let mut failed = Store {
            fail_height_write: Some(cut),
            ..Store::default()
        };
        assert!(matches!(
            storage
                .block()
                .capture_committed_root(100_000, &mut failed, &mut workspace),
            Err(MembershipRootError::ValueWrite(
                "height write refused after persistence"
            ))
        ));
        assert_eq!(norito::json::to_json(&storage).unwrap(), before);
        failed.fail_height_write = None;
        let recovered = cold(&storage, &mut failed, &mut workspace);
        assert_eq!(recovered.commitment(), baseline.commitment());
        assert_members(&recovered, &mut failed, &[(1, 2), (2, 1), (3, 1), (4, 2)]);
    }
    let mut block = storage.block_and_revert();
    block.insert_block([key(5), key(6)].into_iter().collect(), height(2));
    let prepared = block.prepare_commit().unwrap();
    let mut successful = original.clone();
    successful.height_writes = 0;
    let expected = prepared
        .prepare_membership_root(&baseline, &mut successful, &mut workspace)
        .unwrap();
    assert_eq!(
        successful.height_writes, 3,
        "two new aliases and one restored height"
    );
    for cut in 1..=successful.height_writes {
        let mut failed = original.clone();
        failed.height_writes = 0;
        failed.fail_height_write = Some(cut);
        assert!(matches!(
            prepared.prepare_membership_root(&baseline, &mut failed, &mut workspace),
            Err(MembershipRootError::ValueWrite(
                "height write refused after persistence"
            ))
        ));
        for (reference, height) in &original.heights {
            assert_eq!(failed.heights.get(reference), Some(height));
        }
        assert_eq!(storage.view().get(&key(1)), Some(height(2)));
        assert_eq!(storage.view().get(&key(5)), None);
        failed.fail_height_write = None;
        let retried = prepared
            .prepare_membership_root(&baseline, &mut failed, &mut workspace)
            .unwrap();
        assert_eq!(retried.after.commitment(), expected.after.commitment());
    }
    drop(prepared);
    assert_eq!(norito::json::to_json(&storage).unwrap(), before);
}

#[test]
fn height_write_unwind_keeps_the_original_preparation_and_store_for_retry() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1, 2]);
    commit(&storage, 2, &[1, 3]);
    let mut original = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut original, &mut workspace);
    let mut block = storage.block_and_revert();
    block.insert_block([key(4), key(5)].into_iter().collect(), height(2));
    let mut prepared = block.prepare_commit().unwrap();
    let mut successful = original.clone();
    successful.height_writes = 0;
    let expected = prepared
        .prepare_membership_root(&baseline, &mut successful, &mut workspace)
        .unwrap();
    assert_eq!(successful.height_writes, 3);
    let mut last_retry = None;
    // Later cuts follow complete persisted paths for earlier changed aliases;
    // the final height write restores the old value shadowed by the abandoned tip.
    for cut in 1..=successful.height_writes {
        let mut failed = original.clone();
        failed.height_writes = 0;
        failed.panic_height_write = Some(cut);
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prepared.prepare_membership_root(&baseline, &mut failed, &mut workspace)
        }));
        assert!(failure.is_err());
        assert_eq!(storage.view().get(&key(4)), None);
        assert_eq!(
            baseline.read(&key(1), &mut failed).unwrap(),
            Some(height(2))
        );
        assert_eq!(
            baseline.read_predecessor(&key(1), &mut failed).unwrap(),
            Some(height(1))
        );
        for (reference, node) in &original.nodes {
            assert_eq!(failed.nodes.get(reference), Some(node));
        }
        for (reference, height) in &original.heights {
            assert_eq!(failed.heights.get(reference), Some(height));
        }
        if cut > 1 {
            assert!(
                failed.nodes.len() > original.nodes.len(),
                "unwind follows persisted path progress"
            );
        }
        failed.panic_height_write = None;
        let retried = prepared
            .prepare_membership_root(&baseline, &mut failed, &mut workspace)
            .unwrap();
        assert_eq!(retried.after.commitment(), expected.after.commitment());
        last_retry = Some((retried, failed));
    }
    let (candidate, mut store) = last_retry.unwrap();
    prepared.try_prepare_physical().unwrap();
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("same original preparation"));
    drop(retirement);
    assert_members(&after, &mut store, &[(1, 1), (2, 1), (4, 2), (5, 2)]);
    assert_members(&baseline, &mut store, &[(1, 2), (2, 1), (3, 2)]);
}

#[test]
fn replacement_repairs_a_missing_old_height_from_the_original_state() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1]);
    commit(&storage, 2, &[1]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    let old_value = canonical_height_digest(1);
    // This fault removes payload bytes but retains their original allocation.
    // Recreating a value at a different location would not repair old roots.
    let old_location = store.height_allocations[&old_value];
    store.heights.remove(&old_location);
    assert_eq!(
        baseline.read_predecessor(&key(1), &mut store),
        Err(MembershipReadError::MissingValue(old_value))
    );
    let mut block = storage.block_and_revert();
    block.insert_block(BTreeSet::new(), height(2));
    let mut prepared = block.prepare_commit().unwrap();
    store.fail_height_write = Some(store.height_writes + 1);
    assert!(matches!(
        prepared.prepare_membership_root(&baseline, &mut store, &mut workspace),
        Err(MembershipRootError::ValueWrite(_))
    ));
    assert_eq!(
        storage.view().get(&key(1)),
        Some(height(2)),
        "a local refusal cannot publish absence"
    );
    store.fail_height_write = None;
    let candidate = prepared
        .prepare_membership_root(&baseline, &mut store, &mut workspace)
        .unwrap();
    prepared.try_prepare_physical().unwrap();
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("original replacement"));
    drop(retirement);
    assert_eq!(after.read(&key(1), &mut store).unwrap(), Some(height(1)));
    assert_eq!(
        after.read_predecessor(&key(1), &mut store).unwrap(),
        Some(height(1))
    );
    assert_eq!(baseline.read(&key(1), &mut store).unwrap(), Some(height(2)));
    assert_eq!(store.heights.get(&old_location), Some(&1));
}

#[test]
fn explicit_node_and_value_locations_are_required_for_both_membership_cuts() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1]);
    commit(&storage, 2, &[1]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    let mut relocated = Store {
        next_node: 10_000,
        next_height: 20_000,
        ..Store::default()
    };
    let elsewhere = cold(&storage, &mut relocated, &mut workspace);
    assert_eq!(baseline.commitment(), elsewhere.commitment());
    assert_ne!(baseline.root.parts().1, elsewhere.root.parts().1);
    assert_ne!(
        baseline.predecessor.parts().1,
        elsewhere.predecessor.parts().1
    );
    assert_eq!(
        elsewhere.read(&key(1), &mut relocated).unwrap(),
        Some(height(2))
    );
    assert_eq!(
        elsewhere.read_predecessor(&key(1), &mut relocated).unwrap(),
        Some(height(1))
    );

    for rollback in [false, true] {
        let (root, other) = if rollback {
            (baseline.predecessor, baseline.root)
        } else {
            (baseline.root, baseline.predecessor)
        };
        let top = root.parts().1.unwrap();
        let other_top = other.parts().1.unwrap();
        let MerkleMapNode::Leaf { value, .. } = store.nodes[&top.location] else {
            panic!("single-member cut has one leaf");
        };
        let MerkleMapNode::Leaf {
            value: other_value, ..
        } = store.nodes[&other_top.location]
        else {
            panic!("single-member other cut has one leaf");
        };
        let read = |owner: &CommittedMembershipRoot<u64>, source: &mut Store| {
            if rollback {
                owner.read_predecessor(&key(1), source)
            } else {
                owner.read(&key(1), source)
            }
        };
        for (location, expected) in [
            (u64::MAX, MerkleMapReadError::MissingNode(top.hash)),
            (
                other_top.location,
                MerkleMapReadError::NodeHashMismatch(top.hash),
            ),
        ] {
            let mut misplaced = baseline.clone();
            let changed = MerkleMapRoot::from_parts(
                root.parts().0,
                Some(MerkleMapNodeRef {
                    hash: top.hash,
                    location,
                }),
            );
            if rollback {
                misplaced.predecessor = changed;
            } else {
                misplaced.root = changed;
            }
            assert_eq!(misplaced.commitment(), baseline.commitment());
            let mut failed = store.clone();
            failed.height_reads = 0;
            assert_eq!(
                read(&misplaced, &mut failed),
                Err(MembershipReadError::Tree(expected))
            );
            assert_eq!(failed.height_reads, 0, "node authority precedes value I/O");
        }
        for (location, expected) in [
            (u64::MAX, MembershipReadError::MissingValue(value.hash)),
            (
                other_value.location,
                MembershipReadError::InvalidValue(value.hash),
            ),
        ] {
            let mut failed = store.clone();
            let MerkleMapNode::Leaf { value: stored, .. } =
                failed.nodes.get_mut(&top.location).unwrap()
            else {
                unreachable!("the original leaf remains installed");
            };
            stored.location = location;
            assert_eq!(failed.nodes[&top.location].hash(), top.hash);
            failed.height_reads = 0;
            assert_eq!(read(&baseline, &mut failed), Err(expected));
            assert_eq!(failed.height_reads, 1, "load only the explicit leaf value");
        }
    }
}

#[test]
fn writing_a_new_height_location_does_not_repair_an_original_rollback_location() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1]);
    commit(&storage, 2, &[1]);
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    let old_value = canonical_height_digest(1);
    let old_location = store.height_allocations.remove(&old_value).unwrap();
    store.heights.remove(&old_location);
    assert_eq!(
        baseline.read_predecessor(&key(1), &mut store),
        Err(MembershipReadError::MissingValue(old_value))
    );

    let mut block = storage.block_and_revert();
    block.insert_block(BTreeSet::new(), height(2));
    let mut prepared = block.prepare_commit().unwrap();
    let candidate = prepared
        .prepare_membership_root(&baseline, &mut store, &mut workspace)
        .unwrap();
    let new_location = store.height_allocations[&old_value];
    assert_ne!(new_location, old_location);
    assert_eq!(store.heights.get(&new_location), Some(&1));
    assert_eq!(store.heights.get(&old_location), None);
    prepared.try_prepare_physical().unwrap();
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("original replacement"));
    drop(retirement);
    assert_eq!(storage.view().get(&key(1)), Some(height(1)));
    assert_eq!(after.read(&key(1), &mut store).unwrap(), Some(height(1)));
    assert_eq!(after.predecessor, baseline.predecessor);
    for original in [&baseline, &after] {
        assert_eq!(
            original.read_predecessor(&key(1), &mut store),
            Err(MembershipReadError::MissingValue(old_value))
        );
    }
    assert_eq!(baseline.read(&key(1), &mut store).unwrap(), Some(height(2)));

    // Only the owner of the exact lost slot can restore these retained readers.
    store.heights.insert(old_location, 1);
    for original in [&baseline, &after] {
        assert_eq!(
            original.read_predecessor(&key(1), &mut store).unwrap(),
            Some(height(1))
        );
    }
    assert_eq!(after.read(&key(1), &mut store).unwrap(), Some(height(1)));
}

#[test]
fn matching_root_requires_original_physical_preparation_before_publication() {
    let storage = TransactionsStorage::new();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    let baseline = cold(&storage, &mut store, &mut workspace);
    let mut block = storage.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    let prepared = block.prepare_commit().unwrap();
    let candidate = prepared
        .prepare_membership_root(&baseline, &mut store, &mut workspace)
        .unwrap();
    let original_identity = prepared.next_identity.clone();
    let reserved = storage.budget.reserved_bytes();
    let sequence = storage.publication_sequence.load(Ordering::Acquire);
    let (mut prepared, candidate) = prepared
        .publish_with_membership_root(candidate)
        .err()
        .expect("matching root cannot acquire physical authority in publication");
    assert!(Identity::ptr_eq(
        &prepared.next_identity,
        &original_identity
    ));
    assert!(Identity::ptr_eq(&candidate.preparation, &original_identity));
    assert!(!prepared.publication_started);
    assert!(!prepared.published);
    assert!(!prepared.is_physically_prepared());
    assert_eq!(
        storage.publication_sequence.load(Ordering::Acquire),
        sequence
    );
    assert_eq!(storage.budget.reserved_bytes(), reserved);
    assert_eq!(storage.view().get(&key(1)), None);
    prepared.try_prepare_physical().unwrap();
    assert!(prepared.is_physically_prepared());
    assert_eq!(storage.budget.reserved_bytes(), reserved);
    let (after, retirement) = prepared
        .publish_with_membership_root(candidate)
        .unwrap_or_else(|_| panic!("same original physical preparation"));
    assert!(Identity::ptr_eq(&after.identity, &original_identity));
    assert_eq!(storage.view().get(&key(1)), Some(height(1)));
    drop(retirement);
    assert_members(&after, &mut store, &[(1, 1)]);
}

#[test]
fn cold_root_admits_complete_source_work_before_store_io() {
    let storage = TransactionsStorage::new();
    commit(&storage, 1, &[1, 2]);
    commit(&storage, 2, &[2, 3]);
    let owner = storage.block();
    let mut store = Store::default();
    let mut workspace = MerkleMapUpdateWorkspace::new();
    assert!(matches!(
        owner.capture_committed_root(5, &mut store, &mut workspace),
        Err(MembershipRootError::Authority(
            TransactionMembershipAuthorityError::TraversalRefused {
                required: 6,
                limit: 5
            }
        ))
    ));
    assert_eq!(
        store.reads + store.writes + store.height_reads + store.height_writes,
        0
    );
    let bounded = owner
        .capture_committed_root(6, &mut store, &mut workspace)
        .unwrap();
    let repeated = owner
        .capture_committed_root(6, &mut store, &mut workspace)
        .unwrap();
    assert_eq!(bounded.commitment(), repeated.commitment());
    assert!(Identity::ptr_eq(&bounded.identity, &repeated.identity));
}
