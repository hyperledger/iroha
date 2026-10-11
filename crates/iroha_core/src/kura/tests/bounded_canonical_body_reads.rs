// Native authenticated reads retain the original executed graph and refuse unpaid I/O.
// Exact prepaid length and occupied-frame substitution are covered alongside
// native_execution_reads; these checks add DA-file bounds and State query charging.

#[test]
fn canonical_cold_read_control_refusal_retains_release_owner_and_exact_retry() {
    use crate::execution_attempt::ExecutionAttemptError;
    use iroha_allocation::{AllocationBudget, AllocationRefusal};
    use iroha_data_model::block::SharedSignedBlock;
    use std::{
        future::Future as _,
        task::{Context, Poll, Waker},
    };

    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    let kura = chain.kura();
    let height = nonzero!(1_usize);
    let original_wire = chain.committed(1).block().encode_wire().unwrap();
    kura.block_data.lock()[0].1 = None;
    // This independent cold reader has a finite allowance for exactly one shared control.
    let bytes = SharedSignedBlock::allocation_layout().size();
    let waiter_bytes = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let budget = AllocationBudget::new(bytes + waiter_bytes);
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let held = budget.try_reserve_bytes(bytes).unwrap();
    let error = kura
        .get_block(height, &budget)
        .expect_err("occupied reader pool must defer");
    let ExecutionAttemptError::Deferred(local) = error else {
        panic!("local control refusal became a completed storage error");
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = local.allocation_refusal() else {
        panic!("original pool release source must survive Kura");
    };
    let mut wake = std::pin::pin!(release.clone().wait_for_release(&mut registration));
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(wake.as_mut().poll(&mut context), Poll::Pending));
    assert!(!kura.canonical_storage_poisoned.load(Ordering::Acquire));
    assert!(kura.block_data.lock().cached_body(0).is_none());
    drop(held);
    assert!(matches!(wake.as_mut().poll(&mut context), Poll::Ready(_)));
    let admitted = kura.get_block(height, &budget).unwrap().unwrap();
    assert!(admitted.belongs_to(&budget));
    assert_eq!(admitted.encode_wire().unwrap(), original_wire);
    let retained = admitted.clone();
    kura.block_data.lock()[0].1 = None;
    drop(admitted);
    assert_eq!(budget.reserved_bytes(), bytes + waiter_bytes);
    assert!(matches!(
        kura.get_block(height, &budget),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    drop(retained);
    assert_eq!(budget.reserved_bytes(), waiter_bytes);
    assert_eq!(
        kura.get_block(height, &budget)
            .unwrap()
            .unwrap()
            .encode_wire()
            .unwrap(),
        original_wire
    );
}

#[test]
fn canonical_cold_read_budget_refusal_preserves_storage_and_retry() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    let kura = chain.kura();
    let height = nonzero!(1_usize);
    let budget = chain.state().view().execution_budget();
    let expected = chain.committed(1).block().clone();
    kura.block_data.lock()[0].1 = None;
    let before = kura.canonical_block_wire_bytes_for_testing(height).unwrap();
    let limits = norito::DecodeLimits::new(1, 1, 1, 1, 1);
    let refused = norito::with_decode_limits_scope(limits, || kura.get_block(height, &budget));
    assert!(
        matches!(
            refused,
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(_))
        ),
        "cold read must respect its caller's budget"
    );
    assert!(!kura.canonical_storage_poisoned.load(Ordering::Acquire));
    assert!(kura.block_data.lock().cached_body(0).is_none());
    assert_eq!(
        kura.canonical_block_wire_bytes_for_testing(height).unwrap(),
        before
    );
    assert_eq!(
        kura.get_block(height, &budget).unwrap().unwrap().as_ref(),
        expected.as_ref()
    );

    // A real stored-wire fault must still close admission; a budget refusal is
    // not a license to ignore independently detected canonical corruption.
    kura.corrupt_native_frame_for_test(height);
    kura.block_data.lock()[0].1 = None;
    assert!(matches!(
        kura.get_block(height, &budget),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(_))
    ));
    assert!(kura.canonical_storage_poisoned.load(Ordering::Acquire));
}

#[test]
fn authenticated_da_body_read_refuses_oversized_occupied_file_without_repair() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit(Vec::new());
    chain.commit(Vec::new());
    let view = chain.state().view();
    let receipt = CertifiedChain::new(&view)
        .unwrap()
        .authenticated_execution(2)
        .unwrap();
    let original = receipt.block();
    let wire = original.encode_wire().unwrap();
    let wire_len = wire.len() as u64;
    let blocks = (1..=3)
        .map(|height| (chain.committed(height).block()).clone())
        .collect::<Vec<_>>();
    let kura = chain.kura();
    canonical_physical_seed_da_suffix(kura, &blocks);
    let (retained, bytes) = kura
        .read_authenticated_execution_wire(
            &receipt,
            wire_len,
            &chain.state().ivm_execution_budget(),
        )
        .unwrap()
        .unwrap();
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        &retained, original
    ));
    assert_eq!(bytes.as_slice(), wire);
    let path = kura.block_store.lock().da_block_path(2);
    let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(&[0]).unwrap();
    file.sync_all().unwrap();
    assert_eq!(fs::metadata(&path).unwrap().len(), wire_len + 1);
    assert!(
        kura.read_authenticated_execution_wire(
            &receipt,
            wire_len,
            &chain.state().ivm_execution_budget()
        )
        .is_err()
    );
    assert_eq!(
        fs::metadata(path).unwrap().len(),
        wire_len + 1,
        "authenticated reads refuse occupied corruption without repairing it"
    );
}

#[test]
fn executed_history_denial_precedes_cold_body_decode_and_projection() {
    use crate::{
        state::{StateReadOnly as _, World},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    for corrupt in [false, true] {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        chain.commit(Vec::new());
        let kura = chain.kura();
        let expected = chain.committed(2).block().clone();
        let tip = chain.committed(3).block().clone();
        let target_len = expected.encode_wire().unwrap().len() as u64;
        let tip_len = tip.encode_wire().unwrap().len() as u64;
        if corrupt {
            kura.corrupt_native_frame_for_test(nonzero!(3_usize));
        }
        kura.mark_transaction_entrypoint_index_incomplete(2, 3);
        kura.block_data.lock()[1].1 = None;
        kura.block_data.lock()[2].1 = None;
        let index_before = format!("{:?}", *kura.transaction_entrypoint_index.lock());
        let raw_before = {
            let mut store = kura.block_store.lock();
            let slot = store.read_block_index(2).unwrap();
            let mut bytes = vec![0; usize::try_from(slot.length).unwrap()];
            store.read_block_data(slot.start, &mut bytes).unwrap();
            bytes
        };
        kura.reset_canonical_query_reads_for_test();
        let view = chain.state().view();
        let source = view.canonical_history();
        let mut charged = Vec::new();
        let denied = source.executed_block(nonzero!(2_usize), |blocks, bytes| {
            charged.push((blocks, bytes));
            assert_eq!((blocks, bytes), (1, tip_len));
            Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                ivm::error::ExecutionDeferral::CanonicalHistoryCapacity.into(),
            ))
        });
        let Err(crate::execution_attempt::ExecutionAttemptError::Deferred(local)) = denied else {
            panic!("original source allowance must defer before reading");
        };
        assert_eq!(
            local.reason(),
            ivm::error::ExecutionDeferral::CanonicalHistoryCapacity
        );
        assert_eq!(charged, vec![(1, tip_len)]);
        assert_eq!(
            kura.canonical_query_reads_for_test(),
            (0, 0),
            "denial precedes any source-body read, including corrupt occupied frames"
        );
        assert!(!kura.canonical_storage_poisoned.load(Ordering::Acquire));
        assert!(kura.block_data.lock().cached_body(1).is_none());
        assert!(kura.block_data.lock().cached_body(2).is_none());
        assert_eq!(
            format!("{:?}", *kura.transaction_entrypoint_index.lock()),
            index_before
        );

        charged.clear();
        let admitted = source.executed_block(nonzero!(2_usize), |blocks, bytes| {
            charged.push((blocks, bytes));
            Ok(())
        });
        if corrupt {
            assert!(
                admitted.is_err(),
                "occupied corruption cannot authenticate the State tip"
            );
            assert_eq!(charged, vec![(1, tip_len)]);
            assert_eq!(kura.canonical_query_reads_for_test(), (1, tip_len));
        } else {
            assert_eq!(admitted.unwrap().as_ref(), expected.as_ref());
            assert_eq!(charged, vec![(1, tip_len), (1, target_len)]);
            assert_eq!(
                kura.canonical_query_reads_for_test(),
                (2, tip_len + target_len)
            );
        }
        assert!(
            kura.block_data.lock().cached_body(1).is_none(),
            "historical authentication does not publish caches"
        );
        assert!(kura.block_data.lock().cached_body(2).is_none());
        assert_eq!(
            format!("{:?}", *kura.transaction_entrypoint_index.lock()),
            index_before
        );
        let raw_after = {
            let mut store = kura.block_store.lock();
            let slot = store.read_block_index(2).unwrap();
            let mut bytes = vec![0; usize::try_from(slot.length).unwrap()];
            store.read_block_data(slot.start, &mut bytes).unwrap();
            bytes
        };
        assert_eq!(
            raw_after, raw_before,
            "queries never repair occupied source bytes"
        );
    }
}

#[test]
fn startup_history_retains_original_cold_kura_refusal_and_exact_retry() {
    use crate::{
        execution_attempt::ExecutionAttemptError as Attempt,
        state::WorldReadOnly as _,
        sumeragi::{
            block_store::{KuraBlockStore, Staging},
            crypto::BlsCrypto,
            driver::{StartupHistoryError, assemble_init},
            node::NodeError,
            runtime_availability::NativeGlobalAvailability,
        },
    };
    use iroha_allocation::AllocationRefusal;
    use iroha_data_model::block::SharedSignedBlock;
    use std::task::{Context, Poll, Waker};

    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    // The fixture adds a genuinely signed clock transaction when no user work is supplied.
    chain.commit(Vec::new());
    let kura = chain.kura();
    let budget = chain.state().ivm_execution_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let genesis = chain.committed(1);
    let tip = chain.committed(2);
    let original_wire = tip.block().encode_wire().unwrap();
    let expected_header = tip.header().unwrap().clone();
    let configs = chain
        .state()
        .view()
        .world()
        .consensus_schedule()
        .init_configs(1)
        .unwrap();
    let crypto = Arc::new(BlsCrypto::new());
    crypto
        .admit_committee(
            chain
                .validators()
                .iter()
                .map(|(peer, pop)| (peer.public_key(), pop.as_slice())),
        )
        .unwrap();
    let schedule = Arc::new(
        NativeGlobalAvailability::new(chain.state().clone(), chain.instance(), crypto.clone())
            .unwrap(),
    );
    let store = KuraBlockStore::new(
        kura.clone(),
        crypto,
        1,
        Staging::new(),
        budget.clone(),
        schedule,
    );
    let assemble = || {
        assemble_init(
            &store,
            chain.instance(),
            1,
            (genesis.core_hash(), genesis.result()),
            128,
            Vec::new(),
            configs.clone(),
            19,
        )
    };
    let _epoch = crossbeam_epoch::pin();
    kura.block_data.lock()[1].1 = None;
    assert!(kura.block_data.lock().cached_body(1).is_none());
    let bytes_read = kura.canonical_body_bytes_read_for_test();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let original = budget
        .try_reserve(SharedSignedBlock::allocation_layout())
        .unwrap_err();
    let AllocationRefusal::Capacity { ref release, .. } = original else {
        panic!("the actual original State pool is occupied");
    };
    let mut context = Context::from_waker(Waker::noop());
    assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
    for _ in 0..2 {
        let error = assemble().unwrap_err();
        let NodeError::History(Attempt::Deferred(retained)) = NodeError::from(error) else {
            panic!("a cold original-Kura refusal cannot become invalid startup configuration");
        };
        assert_eq!(retained.allocation_refusal(), Some(&original));
        assert_eq!(registration.poll_wait(release, &mut context), Poll::Pending);
        assert!(kura.block_data.lock().cached_body(1).is_none());
        assert!(
            kura.canonical_body_bytes_read_for_test() > bytes_read,
            "this is the actual cold canonical read, not a substituted refusal"
        );
        assert_eq!(kura.blocks_count(), 2);
        assert!(!kura.canonical_storage_poisoned.load(Ordering::Acquire));
    }
    drop(pressure);
    assert_eq!(
        registration.poll_wait(release, &mut context),
        Poll::Ready(())
    );
    registration.cancel();
    let init = assemble().unwrap();
    assert_eq!(init.tip.height, 2);
    assert_eq!(init.tip.block_hash, tip.core_hash());
    assert_eq!(init.tip.result, tip.result());
    assert_eq!(init.tip.header.as_ref(), Some(&expected_header));
    assert_eq!(init.recent_headers, vec![expected_header]);
    assert_eq!(
        init.tip.commit_qc.as_ref().unwrap().block_hash,
        tip.core_hash()
    );
    assert_eq!(init.tip.commit_qc.as_ref().unwrap().result, tip.result());
    assert_eq!(init.nonce, 19);
    assert_eq!(kura.blocks_count(), 2);
    assert_eq!(
        kura.get_block(nonzero!(2_usize), &budget)
            .unwrap()
            .unwrap()
            .encode_wire()
            .unwrap(),
        original_wire
    );
    assert!(
        kura.canonical_body_bytes_read_for_test() > bytes_read,
        "retry actually restores the original cold body"
    );

    kura.corrupt_canonical_body_for_testing(nonzero!(2_usize))
        .unwrap();
    let NodeError::History(Attempt::Rejected(StartupHistoryError::Read { height, source })) =
        NodeError::from(assemble().unwrap_err())
    else {
        panic!("actual corrupt committed bytes must remain a completed typed read error");
    };
    assert_eq!(height, 2);
    assert_ne!(source.kind(), std::io::ErrorKind::WouldBlock);
}
