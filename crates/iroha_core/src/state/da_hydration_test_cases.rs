//! DA hydration atomicity and committed-Kura body authentication regressions.

use super::*;

state_test! { sync block_by_height_reads_committed_kura_body_without_state_view
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let_row! { block = iroha_data_model::block::builder::BlockBuilder::new(header) .build_with_signature(0, keypair.private_key()) };
    let block_hash = block.hash();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(block))
        .expect("store block in kura");
    assert!(
        state.block_by_height(nonzero!(1_usize)).expect("completed history read").is_none(),
        "a Kura body outside the committed WSV prefix must stay hidden"
    );
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(block_hash);
        block_hashes.commit_for_tests();
    }
    let_row! { loaded = state .block_by_height(nonzero!(1_usize)) .expect("completed history read").expect("block should be available") };
    assert_eq!(loaded.hash(), block_hash);
    assert!(state.block_by_height(nonzero!(2_usize)).expect("completed history read").is_none());
}
state_test! { sync block_by_hash_reads_committed_kura_body_without_state_view
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let_row! { block = iroha_data_model::block::builder::BlockBuilder::new(header) .build_with_signature(0, keypair.private_key()) };
    let block_hash = block.hash();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(block))
        .expect("store block in kura");
    assert!(state.block_height_by_hash(block_hash).is_none());
    assert!(
        state.block_by_hash(block_hash).expect("completed history read").is_none(),
        "a Kura body outside the committed WSV prefix must stay hidden"
    );
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(block_hash);
        block_hashes.commit_for_tests();
    }
    assert_eq!(
        state.block_height_by_hash(block_hash),
        Some(nonzero!(1_usize))
    );
    let_row! { loaded = state .block_by_hash(block_hash) .expect("completed history read").expect("block should be available") };
    assert_eq!(loaded.hash(), block_hash);
    let missing = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new("missing-block"));
    assert!(state.block_by_hash(missing).expect("completed history read").is_none());
}
state_test! { sync block_query_consumers_reject_kura_body_not_committed_by_wsv
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let_row! { block = iroha_data_model::block::builder::BlockBuilder::new(header) .build_with_signature(0, keypair.private_key()) };
    let actual = block.hash();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(block))
        .expect("store mismatched Kura body");
    let expected = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xA7; 32]));
    assert_ne!(actual, expected);
    {
        let mut block_hashes = state.block_hashes.block();
        block_hashes.push_for_tests(expected);
        block_hashes.commit_for_tests();
    }
    assert!(matches!(state.block_by_height(nonzero!(1_usize)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(CanonicalHistoryError::BlockHashMismatch { .. }))));
    assert!(state.block_by_hash(actual).expect("uncommitted hash is absent").is_none());
    let view = state.view();
    assert!(matches!(view.block_by_height(nonzero!(1_usize)), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(CanonicalHistoryError::BlockHashMismatch { .. }))));
    assert_eq!(
        view.block_height_by_hash(expected),
        Some(nonzero!(1_usize)),
        "the WSV journal remains the canonical hash-to-height source"
    );
    assert!(matches!(
        view.canonical_block_by_height(nonzero!(1_usize)),
        Err(crate::execution_attempt::ExecutionAttemptError::Rejected(CanonicalHistoryError::BlockHashMismatch {
            height: 1,
            expected_hash,
            actual_hash,
        })) if expected_hash == expected && actual_hash == actual
    ));
    assert!(matches!(view.latest_block(), Err(crate::execution_attempt::ExecutionAttemptError::Rejected(CanonicalHistoryError::BlockHashMismatch { .. }))));
    assert!(matches!(
        view.all_blocks(nonzero!(1_usize)).next(),
        Some(Err(crate::execution_attempt::ExecutionAttemptError::Rejected(CanonicalHistoryError::BlockHashMismatch { height: 1, .. })))
    ));
}
fn da_index_debug_snapshot(state: &State) -> (String, String, String, String, String) {
    (
        format!("{:?}", state.da_commitments.read()),
        format!("{:?}", state.da_confidential_compute.read()),
        format!("{:?}", state.da_receipt_cursors.read()),
        format!("{:?}", state.da_shard_cursors.read()),
        format!("{:?}", state.da_pin_intents.read()),
    )
}
state_test! { sync replay_private_da_hydration_reconstructs_exact_prefix_and_rejects_wrong_body
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let record = sample_da_commitment_record(LaneId::new(0), 1, 1, 0x91);
    let_row! { block: SignedBlock = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, None) .with_da_commitments(Some(DaCommitmentBundle::new(vec![record.clone()]))) .sign(keypair.private_key()) .unpack(|_| {}) .into() };
    kura.store_block(crate::block::reserve_block_for_tests().initialize(block.clone())).expect("store exact DA prefix");
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(block.hash());
        hashes.commit_for_tests();
    }
    assert!(state.da_indexes_hydrated.read().is_none());
    let before = da_index_debug_snapshot(&state);
    state.ensure_da_indexes_hydrated_for_replay_prevalidation()
        .expect("authenticate and reconstruct private DA prefix");
    assert!(matches!(&(*state.da_indexes_hydrated.read()), Some(Ok(()))));
    assert_ne!(da_index_debug_snapshot(&state), before,
        "private hydration must rebuild real DA indexes, not mark an empty cache ready");
    assert_eq!(state.da_commitments.read().get_committed_by_key(&DaCommitmentKey::from_record(&record))
        .expect("reconstructed exact commitment").location.block_height, 1);
    let published = da_index_debug_snapshot(&state);
    let expected = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"wrong DA prefix hash"));
    {
        let mut hashes = state.block_hashes.block_and_revert();
        hashes.push(expected);
        hashes.commit_for_tests();
    }
    *state.da_indexes_hydrated.write() = None;
    let error = state.ensure_da_indexes_hydrated_for_replay_prevalidation()
        .expect_err("private hydration cannot accept an unauthenticated Kura body");
    assert!(matches!(error, DaIndexHydrationError::Completed(DaIndexHydrationFailure::BlockHashMismatch {
        height, expected: found_expected, actual,
    }) if height == nonzero!(1_u64) && found_expected == expected && actual == block.hash()));
    assert_eq!(da_index_debug_snapshot(&state), published,
        "failed private hydration cannot publish partial DA indexes");
    let DaIndexHydrationError::Completed(failure) = error else { panic!("exact completed mismatch") };
    assert_eq!(*state.da_indexes_hydrated.read(), Some(Err(failure.clone())));
    // Repeated invalid reads reuse the completed verdict and never read Kura again.
    kura.reset_canonical_query_reads_for_test();
    for _ in 0..2 {
        let DaIndexHydrationError::Completed(repeated) = state.ensure_da_indexes_hydrated_for_replay_prevalidation().unwrap_err() else { panic!("cached completed mismatch remains completed") };
        assert_eq!(repeated, failure);
        assert_eq!(kura.canonical_query_reads_for_test(), (0, 0));
        assert_eq!(da_index_debug_snapshot(&state), published);
    }
}
state_test! { sync failed_da_rewind_on_missing_body_preserves_all_published_indexes
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let first_record = sample_da_commitment_record(LaneId::new(0), 1, 1, 0x31);
    let_row! { first_block: SignedBlock = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, None) .with_da_commitments(Some(DaCommitmentBundle::new(vec![first_record]))) .sign(keypair.private_key()) .unpack(|_| {}) .into() };
    kura.store_block(crate::block::reserve_block_for_tests().initialize(first_block.clone()))
        .expect("store first block");
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(first_block.hash());
        hashes.commit_for_tests();
    }
    state
        .ensure_da_indexes_hydrated()
        .expect("hydrate the first committed prefix");
    let sentinel = sample_da_commitment_record(LaneId::new(0), 2, 0, 0x41);
    let_row! { sentinel_location = DaCommitmentLocation { block_height: 77, index_in_bundle: 3 } };
    state
        .da_commitments
        .write()
        .insert(&sentinel, sentinel_location);
    state.da_confidential_compute.write().insert(
        &sentinel,
        sentinel_location,
        &ConfidentialComputePolicy::new(
            ConfidentialComputeMechanism::Encryption,
            NonZeroU32::new(7).expect("non-zero test key version"),
            BTreeSet::new(),
        ),
    );
    state
        .advance_da_receipt_cursors_from_bundle(77, std::slice::from_ref(&sentinel))
        .expect("seed published receipt cursor sentinel");
    state
        .advance_da_shard_cursors_from_bundle(77, std::slice::from_ref(&sentinel))
        .expect("seed published shard cursor sentinel");
    let_row! { mut pin = test_da_pin_intent( *state.network_id_ref(), LaneId::new(0), 2, 1, StorageTicketId::new([0x51; 32]), ManifestDigest::new([0x52; 32]), ) };
    set_test_da_pin_intent_alias(
        &mut pin,
        &ALICE_KEYPAIR,
        Some("atomic-rebuild-sentinel".to_owned()),
    );
    state.da_pin_intents.write().insert(pin, sentinel_location);
    let before = da_index_debug_snapshot(&state);
    let missing_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x61; 32]));
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(missing_hash);
        hashes.commit_for_tests();
    }
    let_row! { error = state .rewind_da_indexes_to_height(2) .expect_err("a non-hash-only committed body must exist") };
    assert!(matches!(
        error,
        DaIndexHydrationError::Completed(DaIndexHydrationFailure::MissingBlock { height }) if height == nonzero!(2_u64)
    ));
    assert_eq!(
        da_index_debug_snapshot(&state),
        before,
        "a failed local rebuild must not publish any of its five partial indexes"
    );
}
state_test! { sync hydrate_da_indexes_rejects_kura_body_hash_mismatch
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let_row! { block: SignedBlock = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, None) .sign(keypair.private_key()) .unpack(|_| {}) .into() };
    let actual = block.hash();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(block)).expect("store mismatched body");
    let expected = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x71; 32]));
    assert_ne!(actual, expected);
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(expected);
        hashes.commit_for_tests();
    }
    let_row! { error = state .ensure_da_indexes_hydrated() .expect_err("Kura body must authenticate against the WSV prefix") };
    assert!(matches!(
        error,
        DaIndexHydrationError::Completed(DaIndexHydrationFailure::BlockHashMismatch {
            height,
            expected: observed_expected,
            actual: observed_actual,
        }) if height == nonzero!(1_u64)
            && observed_expected == expected
            && observed_actual == actual
    ));
}
state_test! { sync hydrate_da_indexes_rejects_cursor_regression
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let_row! { make_record = |sequence: u64| { DaCommitmentRecord::new( LaneId::new(0), 1, sequence, BlobDigest::new([0xAA; 32]), iroha_data_model::sorafs::pin_registry::ManifestDigest::new([0xBB; 32]), DaProofScheme::MerkleSha256, Hash::prehashed([0xCC; 32]), None, RetentionClass::default(), StorageTicketId::new([0xEE; 32]), checked_da_ack_signature(0x11), ) } };
    let first_bundle = DaCommitmentBundle::new(vec![make_record(1)]);
    let_row! { first_block = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, None) .with_da_commitments(Some(first_bundle)) .sign(keypair.private_key()) .unpack(|_| {}) };
    let signed_first: SignedBlock = first_block.into();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(signed_first.clone()))
        .expect("store block");
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(signed_first.hash());
        hashes.commit_for_tests();
    }
    let second_bundle = DaCommitmentBundle::new(vec![make_record(0)]);
    let_row! { second_block = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, Some(&signed_first)) .with_da_commitments(Some(second_bundle)) .sign(keypair.private_key()) .unpack(|_| {}) };
    let signed_second: SignedBlock = second_block.into();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(signed_second.clone()))
        .expect("store block");
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(signed_second.hash());
        hashes.commit_for_tests();
    }
    let_row! { err = state .ensure_da_indexes_hydrated() .expect_err("hydration should fail on regression") };
    match err {
        DaIndexHydrationError::Completed(DaIndexHydrationFailure::ShardCursor(DaShardCursorError::Regression {
            shard_id,
            lane_id,
            observed_sequence,
            current_sequence,
            ..
        })) => {
            assert_eq!(shard_id, 0);
            assert_eq!(lane_id, LaneId::new(0));
            assert_eq!(observed_sequence, 0);
            assert_eq!(current_sequence, 1);
            let height_str = signed_second.header().height().get().to_string();
            assert!(
                err.to_string().contains(&height_str),
                "expected error message to include height {height_str}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
state_test! { sync hydrate_da_indexes_rejects_receipt_sequence_gap
    let (state, kura) = blank_test_state_with_kura();
    let keypair = crate::state::checked_keypair();
    let_row! { make_record = |sequence, seed| { DaCommitmentRecord::new( LaneId::new(0), 1, sequence, BlobDigest::new([seed; 32]), iroha_data_model::sorafs::pin_registry::ManifestDigest::new([seed.wrapping_add(1); 32]), DaProofScheme::MerkleSha256, Hash::prehashed([seed.wrapping_add(2); 32]), None, RetentionClass::default(), StorageTicketId::new([seed.wrapping_add(3); 32]), checked_da_ack_signature(seed.wrapping_add(4)), ) } };
    let_row! { first_block: SignedBlock = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, None) .with_da_commitments(Some(DaCommitmentBundle::new(vec![make_record(1, 0x31)]))) .sign(keypair.private_key()) .unpack(|_| {}) .into() };
    kura.store_block(crate::block::reserve_block_for_tests().initialize(first_block.clone()))
        .expect("store first block");
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(first_block.hash());
        hashes.commit_for_tests();
    }
    let_row! { second_block: SignedBlock = BlockBuilder::new(vec![dummy_accepted_transaction()]) .chain(0, Some(&first_block)) .with_da_commitments(Some(DaCommitmentBundle::new(vec![make_record(3, 0x41)]))) .sign(keypair.private_key()) .unpack(|_| {}) .into() };
    kura.store_block(crate::block::reserve_block_for_tests().initialize(second_block.clone()))
        .expect("store second block");
    {
        let mut hashes = state.block_hashes.block();
        hashes.push(second_block.hash());
        hashes.commit_for_tests();
    }
    let_row! { err = state .ensure_da_indexes_hydrated() .expect_err("hydration should fail on receipt cursor gap") };
    assert!(matches!(
        err,
        DaIndexHydrationError::Completed(DaIndexHydrationFailure::ReceiptCursor(DaReceiptCursorError::MissingSequence {
            lane,
            epoch: 1,
            expected: 2,
            observed: 3
        })) if lane == LaneId::new(0)
    ));
}

state_test! { sync da_hydration_capacity_refusal_preserves_indexes_and_original_retry_owner
    // Repeated refusals compare exact reserved bytes; unrelated global EBR
    // retirements must not release fixture credit between those observations.
    if crate::unit_test_support::run_in_isolated_harness(
        "state::tests::da_hydration_test_cases::da_hydration_capacity_refusal_preserves_indexes_and_original_retry_owner",
    ) {
        return;
    }
    use iroha_allocation::AllocationRefusal;
    use std::{future::Future as _, task::{Context, Poll, Waker}};

    for rewind in [false, true] {
        let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(
            crate::sumeragi::test_chain::TestChainConfig::new(World::new(), 1_000),
        ).expect("funded canonical genesis");
        let state = chain.state();
        state.ensure_da_indexes_hydrated().expect("initial complete projection");
        let sentinel = sample_da_commitment_record(LaneId::new(0), 2, 0, 0xB1);
        state.da_commitments.write().insert(&sentinel, DaCommitmentLocation {
            block_height: 77,
            index_in_bundle: 3,
        });
        let published = da_index_debug_snapshot(state);
        let journal = state.da_shard_cursor_journal_path();
        let journal_before = std::fs::read(&journal).expect("initial journal");
        *state.da_indexes_hydrated.write() = None;
        chain.kura().forget_cached_block_for_testing(nonzero!(1_usize))
            .expect("durable original frame remains available");
        let budget = state.ivm_execution_budget();
        let mut registration = crate::unit_test_support::release_registration(&budget);
        let occupied = budget.try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
            .expect("retain the remaining original pool");
        let attempt = if rewind {
            state.rewind_da_indexes_to_height(1)
        } else {
            state.ensure_da_indexes_hydrated()
        };
        let Err(DaIndexHydrationError::Deferred(original)) = attempt else {
            panic!("capacity refusal must stay unfinished: {attempt:?}");
        };
        let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
            panic!("hydration must retain its actual original capacity source");
        };
        let mut retry = std::pin::pin!(release.clone().wait_for_release(&mut registration));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(retry.as_mut().poll(&mut context), Poll::Pending));
        // Every public accessor reports the same unfinished hydration rather than
        // panicking or exposing the old index as a newly authenticated result.
        for refusal in [
            state.da_commitments().err(),
            state.da_confidential_compute().err(),
            state.da_receipt_cursors().err(),
            state.da_shard_cursor_index().err(),
            state.da_pin_intents().err(),
        ] {
            let Some(DaIndexHydrationError::Deferred(repeated)) = refusal else { panic!("each fresh read must return an unfinished original owner") };
            assert_eq!(repeated.reason(), original.reason());
            assert_eq!(repeated.phase(), original.phase());
            assert_eq!(repeated.allocation_refusal(), original.allocation_refusal());
            assert!(repeated.decode_refusal().is_none());
            assert!(repeated.verification_refusal().is_none());
            assert!(state.da_indexes_hydrated.read().is_none());
        }
        assert!(state.da_indexes_hydrated.read().is_none(), "unfinished reads cannot be cached as verdicts");
        assert_eq!(da_index_debug_snapshot(state), published);
        assert_eq!(std::fs::read(&journal).unwrap(), journal_before);
        drop(occupied);
        assert!(matches!(retry.as_mut().poll(&mut context), Poll::Ready(_)));
        if rewind {
            state.rewind_da_indexes_to_height(1).expect("retry the exact committed prefix");
        } else {
            state.ensure_da_indexes_hydrated().expect("retry the exact committed prefix");
        }
        assert!(matches!(&(*state.da_indexes_hydrated.read()), Some(Ok(()))));
        assert!(state.da_commitments().unwrap().get_by_manifest(&sentinel.manifest_hash).is_none(),
            "successful atomic replay replaces the sentinel with authenticated history");
    }
}
