// Actual execution-pool scratch release must follow every retained State writer.

#[derive(Clone, Copy)]
enum ExecutionRefundCase {
    Commit,
    InvalidDirectory,
    RetainedDrop,
}

#[test]
fn direct_musubi_scratch_refund_waits_for_successful_or_refused_commit_retirement() {
    // Exact retirement accounting must not share the global EBR collector with
    // unrelated parallel tests and their reader lifetimes.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::acquisition_fixture_tests::direct_commit_refusal_tests::direct_musubi_scratch_refund_waits_for_successful_or_refused_commit_retirement",
    ) {
        return;
    }
    check_execution_refund_retirement(ExecutionRefundCase::Commit);
    check_execution_refund_retirement(ExecutionRefundCase::InvalidDirectory);
}

#[test]
fn musubi_scratch_wake_stays_with_retained_state_until_original_writers_drop() {
    // This sibling exercises the same exact release callback and global EBR state.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::acquisition_fixture_tests::direct_commit_refusal_tests::musubi_scratch_wake_stays_with_retained_state_until_original_writers_drop",
    ) {
        return;
    }
    check_execution_refund_retirement(ExecutionRefundCase::RetainedDrop);
}

fn check_execution_refund_retirement(case: ExecutionRefundCase) {
    use mv::storage::StorageReadOnly as _;

    let (state, proposal) = fixture();
    let state: Arc<State> = Arc::from(state);
    let before = crate::snapshot::canonical_state_snapshot_hash(&state).unwrap();
    let parameters = state
        .world
        .parameters
        .block()
        .try_detach(|_| Ok::<_, ()>(()))
        .unwrap();
    let budget = state.ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let occupied = budget.try_reserve_bytes(1).unwrap();
    let mut block = super::direct_commit_musubi_scratch_tests::staged_block(
        &state,
        proposal.header(),
        false,
        true,
    );
    if matches!(case, ExecutionRefundCase::InvalidDirectory) {
        let (key, mut value) = block
            .world
            .musubi_public_directory
            .iter()
            .next()
            .map(|(key, value)| (key.clone(), value.clone()))
            .unwrap();
        // Live revision scratch is allocated and retired before universal
        // equality rejects this otherwise structurally valid directory entry.
        value.metadata_revision += 1;
        block.world.musubi_public_directory.insert(key, value);
    }
    let iroha_allocation::AllocationRefusal::Capacity { release, .. } =
        budget.try_reserve_bytes(budget.limit_bytes()).unwrap_err()
    else {
        panic!("original occupied pool has a capacity observer");
    };
    let (parameters, error, initial_world_cleanup) = parameters
        .try_prepare_publication(&state.world.parameters, |_, _| Ok::<_, ()>(()))
        .err()
        .expect("the original State holds its actual World writer");
    assert!(matches!(error, PublicationPreparationError::Busy(_)));
    let callback = Arc::new(ProbeOriginalStateOnMembershipRelease {
        state: Arc::clone(&state),
        original: Mutex::new(OriginalProbe {
            parameters: Some(parameters),
            world_cleanup: None,
            fence_cleanup: [None, None],
            observed: PhysicalObservations::default(),
        }),
        calls: AtomicUsize::new(0),
        unavailable: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&callback));
    let mut wait = release.wait_for_release(&mut registration);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    if matches!(case, ExecutionRefundCase::RetainedDrop) {
        let fields = block.fields.as_mut().unwrap();
        let effects = fields
            ._ivm_refunds
            .with_scope(|_| {
                crate::state::world_commit::PreparedWorldCommit::prepare_overlay(
                    &mut fields.world,
                    &budget,
                    proposal.header().height().get(),
                    &fields.nexus,
                    &fields.lane_incarnation_activation_heights,
                    None,
                    None,
                )
            })
            .unwrap();
        drop(effects);
        assert_eq!(callback.calls.load(Ordering::SeqCst), 0);
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(&waker))
                .is_pending()
        );
        drop(block);
    } else {
        let result = block.commit();
        if matches!(case, ExecutionRefundCase::Commit) {
            result.expect("actual populated World commits");
        } else {
            assert!(
                matches!(
                    result,
                    Err(storage_transactions::TransactionsBlockError::WorldCommitPreparation)
                ),
                "{result:?}"
            );
        }
    }
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_ready()
    );
    assert_eq!(callback.calls.load(Ordering::SeqCst), 1);
    assert_eq!(callback.unavailable.load(Ordering::SeqCst), 0);
    let (parameters, world_cleanup, fence_cleanup, observed) = {
        let mut original = callback.original.lock().unwrap();
        (
            original.parameters.take().unwrap(),
            original.world_cleanup.take(),
            std::mem::take(&mut original.fence_cleanup),
            std::mem::take(&mut original.observed),
        )
    };
    drop((world_cleanup, fence_cleanup, initial_world_cleanup));
    assert_eq!(observed.commit_busy, 0);
    assert_eq!(observed.write_busy, 0);
    assert_eq!(observed.world_busy, 0);
    assert_eq!(observed.world_other, 0);
    assert_eq!(observed.generation_odd, 0);
    assert_eq!(observed.commit_free, 1);
    assert_eq!(observed.write_free, 1);
    if matches!(case, ExecutionRefundCase::Commit) {
        assert_eq!(observed.world_changed, 1);
        assert_ne!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    } else {
        assert_eq!(observed.world_admitted, 1);
        assert_eq!(observed.world_acquired, 1);
        assert_eq!(observed.world_changed, 0);
        assert_eq!(
            crate::snapshot::canonical_state_snapshot_hash(&state).unwrap(),
            before
        );
    }
    drop((parameters, occupied));
}
