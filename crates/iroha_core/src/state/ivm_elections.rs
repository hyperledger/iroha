//! Immutable IVM election projections, shared only across unchanged storage.

use super::*;

pub(super) type SnapshotCache =
    SyncOnceCell<Result<Arc<IvmElectionsSnapshot>, InvalidIvmElectionSnapshot>>;

/// Storage evidence that the block-start projection is still exact.
pub(super) trait UnchangedElections: WorldReadOnly {
    fn elections_unchanged(&self) -> bool;
}

impl UnchangedElections for WorldView<'_> {
    fn elections_unchanged(&self) -> bool {
        true
    }
}

impl UnchangedElections for WorldBlock<'_> {
    fn elections_unchanged(&self) -> bool {
        !self.elections.is_dirty()
    }
}

impl UnchangedElections for WorldTransaction<'_, '_> {
    fn elections_unchanged(&self) -> bool {
        self.elections.changed_keys_in_block().next().is_none()
    }
}

impl UnchangedElections for Box<WorldTransaction<'_, '_>> {
    fn elections_unchanged(&self) -> bool {
        (**self).elections_unchanged()
    }
}

pub(super) fn cached_snapshot(
    cache: &SnapshotCache,
    world: &impl UnchangedElections,
) -> Result<Arc<IvmElectionsSnapshot>, InvalidIvmElectionSnapshot> {
    if world.elections_unchanged() {
        cache.get_or_init(|| project(world.elections())).clone()
    } else {
        // A changed projection is invocation-local. It must not replace the
        // block-start cache: rollback can make that exact baseline usable again.
        project(world.elections())
    }
}

/// Validate borrowed elections in hydration order, then build their visible fields.
///
/// # Errors
/// Rejects invalid tally geometry, overflowing totals or malformed selectors.
pub fn project(
    elections: &impl StorageReadOnly<String, ElectionState>,
) -> Result<Arc<IvmElectionsSnapshot>, InvalidIvmElectionSnapshot> {
    // Keep hydration's original order: all shapes precede all selectors.
    // Validate borrowed data before allocating a projection.
    for (_, election) in elections.iter() {
        validate_tally(election.options, &election.tally)?;
    }
    for (id, _) in elections.iter() {
        if !iroha_data_model::governance::is_valid_governance_selector_v1(id) {
            return Err(InvalidIvmElectionSnapshot);
        }
    }
    Ok(Arc::new(
        elections
            .iter()
            .map(|(id, election)| {
                (
                    id.clone(),
                    (election.options, election.finalized, election.tally.clone()),
                )
            })
            .collect(),
    ))
}

/// Check V1 option geometry and overflow before exposing a tally.
///
/// # Errors
/// Rejects invalid option counts, tally lengths or overflowing totals.
pub fn validate_tally(options: u32, tally: &[u128]) -> Result<(), InvalidIvmElectionSnapshot> {
    iroha_data_model::isi::zk::validate_election_tally_v1(options, tally.len())
        .map_err(|_| InvalidIvmElectionSnapshot)?;
    tally
        .iter()
        .try_fold(0_u128, |total, weight| total.checked_add(*weight))
        .ok_or(InvalidIvmElectionSnapshot)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn election(weight: u128) -> ElectionState {
        ElectionState {
            options: 2,
            finalized: true,
            tally: vec![weight, 0],
            ..ElectionState::default()
        }
    }

    fn state() -> State {
        let mut world = World::new();
        world.elections.insert("election-1".into(), election(3));
        State::new_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            crate::query::store::LiveQueryStore::start_test(),
        )
    }

    #[test]
    fn immutable_views_share_their_exact_validated_projection() {
        let state = state();
        let view = state.view();
        let first = view.ivm_elections_snapshot().unwrap();
        assert!(Arc::ptr_eq(&first, &view.ivm_elections_snapshot().unwrap()));
        assert_eq!(first["election-1"], (2, true, vec![3, 0]));
        let query = state.query_view();
        let first_query = query.ivm_elections_snapshot().unwrap();
        assert!(Arc::ptr_eq(
            &first_query,
            &query.ivm_elections_snapshot().unwrap()
        ));
        assert_eq!(first, first_query);
    }

    #[test]
    fn untouched_siblings_share_cache_but_edits_apply_and_rollback_exactly() {
        let state = state();
        let mut block = state.block(BlockHeader::new(
            NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let baseline = block.ivm_elections_snapshot().unwrap();
        {
            let mut tx = block.transaction();
            assert!(Arc::ptr_eq(
                &baseline,
                &tx.ivm_elections_snapshot().unwrap()
            ));
            tx.world.elections.insert("election-1".into(), election(7));
            let changed = tx.ivm_elections_snapshot().unwrap();
            assert_eq!(changed["election-1"].2, vec![7, 0]);
            assert_eq!(baseline["election-1"].2, vec![3, 0]);
            assert!(!Arc::ptr_eq(&baseline, &changed));
            // Drop rolls the election update back; it must not poison baseline.
        }
        assert!(Arc::ptr_eq(
            &baseline,
            &block.ivm_elections_snapshot().unwrap()
        ));
        {
            let tx = block.transaction();
            assert!(Arc::ptr_eq(
                &baseline,
                &tx.ivm_elections_snapshot().unwrap()
            ));
            tx.apply();
        }
        assert!(Arc::ptr_eq(
            &baseline,
            &block.ivm_elections_snapshot().unwrap()
        ));
        {
            let mut tx = block.transaction();
            tx.world.elections.insert("election-1".into(), election(9));
            tx.apply();
        }
        assert_eq!(
            block.ivm_elections_snapshot().unwrap()["election-1"].2,
            vec![9, 0]
        );
        {
            let mut tx = block.transaction();
            assert_eq!(
                tx.ivm_elections_snapshot().unwrap()["election-1"].2,
                vec![9, 0]
            );
            tx.world.elections.remove("election-1".into());
            assert!(tx.ivm_elections_snapshot().unwrap().is_empty());
        }
        assert_eq!(
            block.ivm_elections_snapshot().unwrap()["election-1"].2,
            vec![9, 0]
        );
    }

    #[test]
    fn cached_success_never_hides_invalid_edits_or_repaired_state() {
        let mut world = World::new();
        world.elections.insert("election-1".into(), election(3));
        let mut block = world.block();
        let cache = SnapshotCache::new();
        let baseline = cached_snapshot(&cache, &block).unwrap();
        let mut invalid = election(u128::MAX);
        invalid.tally[1] = 1;
        block.elections.insert("election-1".into(), invalid);
        assert!(cached_snapshot(&cache, &block).is_err());
        block.elections.insert("election-1".into(), election(4));
        assert_eq!(
            cached_snapshot(&cache, &block).unwrap()["election-1"].2,
            vec![4, 0]
        );
        block.elections.insert("bad/selector".into(), election(0));
        assert!(cached_snapshot(&cache, &block).is_err());
        block.elections.remove("bad/selector".into());
        assert_eq!(
            cached_snapshot(&cache, &block).unwrap()["election-1"].2,
            vec![4, 0]
        );
        assert_eq!(baseline["election-1"].2, vec![3, 0]);
    }

    #[test]
    fn invalid_baseline_is_cached_only_while_storage_remains_unchanged() {
        let mut world = World::new();
        let mut invalid = election(0);
        invalid.tally.pop();
        world.elections.insert("election-1".into(), invalid);
        let mut block = world.block();
        let cache = SnapshotCache::new();
        assert!(cached_snapshot(&cache, &block).is_err());
        assert!(cache.get().unwrap().is_err());
        {
            let mut tx = block
                .try_transaction(
                    #[cfg(feature = "telemetry")]
                    None,
                    LaneConfig::default(),
                    0,
                )
                .unwrap();
            tx.elections.insert("election-1".into(), election(1));
            assert_eq!(
                cached_snapshot(&cache, &tx).unwrap()["election-1"].2,
                vec![1, 0]
            );
        }
        assert!(cached_snapshot(&cache, &block).is_err());
    }
}
