#[test]
fn payment_requires_registered_production_qualification_before_effects() {
    let bootstrap = valid_bootstrap_fixture();
    let payment = valid_payment_instruction();
    let state = state_with_activation(active_lifecycle());
    let mut block = state.block(test_header());
    {
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        bootstrap
            .execute_signed(&ALICE_ID, &mut transaction)
            .expect("native bootstrap is available before production qualification");
        transaction.apply();
    }
    let mut transaction = block.transaction();
    let snapshot = |transaction: &StateTransaction<'_, '_>| {
        (
            transaction
                .world
                .privacy_pgc_pool_invariants
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            transaction
                .world
                .privacy_pgc_accounts
                .iter()
                .map(|(key, value)| (*key, *value))
                .collect::<Vec<_>>(),
            transaction
                .world
                .privacy_roots
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect::<Vec<_>>(),
            transaction
                .world
                .privacy_root_heads
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect::<Vec<_>>(),
            transaction.privacy_budget_for_testing(),
        )
    };
    let before = snapshot(&transaction);
    assert!(
        transaction
            .world
            .privacy_exact12_qualification
            .get()
            .is_none()
    );
    bind_payment_instruction(&mut transaction, &payment);
    let error = payment
        .execute(&ALICE_ID, &mut transaction)
        .expect_err("an active compiled profile cannot authorize production execution");
    assert_eq!(
        smart_contract_parameter_message(&error),
        "privacy Exact12 production qualification is not registered"
    );
    assert_eq!(snapshot(&transaction), before);
}

#[test]
fn payment_rejects_missing_stale_substituted_and_consumed_intent_before_effects() {
    let bootstrap = valid_bootstrap_fixture();
    let payment = valid_payment_instruction();
    let state = state_with_activation(active_lifecycle());
    let mut block = state.block(test_header());
    {
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        bootstrap
            .execute_signed(&ALICE_ID, &mut transaction)
            .expect("complete native bootstrap");
        transaction.apply();
    }
    let assert_unchanged = |transaction: &StateTransaction<'_, '_>,
                            expected_maps: (usize, usize, usize, usize),
                            expected_budget: (u32, u64, u32, u64)| {
        assert_eq!(privacy_map_counts(transaction), expected_maps);
        assert_eq!(
            transaction.privacy_budget_for_testing(),
            expected_budget,
            "intent rejection must not reserve privacy budget"
        );
    };
    {
        let mut transaction = block.transaction();
        let before = privacy_map_counts(&transaction);
        let budget_before = transaction.privacy_budget_for_testing();
        let error = payment
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("contract, trigger, IVM, and ad-hoc paths have no direct binding");
        assert!(
            smart_contract_parameter_message(&error).contains("no bound direct"),
            "{error:?}"
        );
        assert_unchanged(&transaction, before, budget_before);
    }
    {
        let mut transaction = block.transaction();
        let before = privacy_map_counts(&transaction);
        let budget_before = transaction.privacy_budget_for_testing();
        let submission_hash = crate::privacy::privacy_signed_submission_hash_v1(&payment)
            .expect("payment submission hash");
        transaction.bind_privacy_transaction_intent_v1(Some((
            PrivacyTransactionIntentDigestV1::new([0xEE; 32]),
            submission_hash,
        )));
        let error = payment
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("stale signed-payload binding");
        assert!(
            smart_contract_parameter_message(&error).contains("digest differs"),
            "{error:?}"
        );
        assert_unchanged(&transaction, before, budget_before);
    }
    {
        let mut substituted = payment.clone();
        substituted.envelope.proof.bytes_mut().bytes[0] ^= 1;
        let mut transaction = block.transaction();
        let before = privacy_map_counts(&transaction);
        let budget_before = transaction.privacy_budget_for_testing();
        bind_payment_instruction(&mut transaction, &payment);
        let error = substituted
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("child overlay substituted another proof");
        assert!(
            smart_contract_parameter_message(&error).contains("differs from the exact direct"),
            "{error:?}"
        );
        assert_unchanged(&transaction, before, budget_before);
    }
    {
        let mut transaction = block.transaction();
        let before = privacy_map_counts(&transaction);
        let budget_before = transaction.privacy_budget_for_testing();
        bind_payment_instruction(&mut transaction, &payment);
        let digest = payment
            .envelope
            .statement
            .context()
            .transaction_intent_digest;
        let submission_hash = crate::privacy::privacy_signed_submission_hash_v1(&payment)
            .expect("payment submission hash");
        transaction
            .consume_privacy_transaction_intent_v1(&ALICE_ID, digest, submission_hash)
            .expect("simulate prior child consumption");
        let error = payment
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("the exact submission cannot be replayed in a child overlay");
        assert!(
            smart_contract_parameter_message(&error).contains("already been consumed"),
            "{error:?}"
        );
        assert_unchanged(&transaction, before, budget_before);
    }
}
#[test]
fn tampered_pgc_payment_proof_preserves_every_state_map_and_budget() {
    let bootstrap = valid_bootstrap_fixture();
    let mut payment = valid_payment_instruction();
    let PrivacyProofV1::AnonymousPgcKOutOfNV1(proof) = &mut payment.envelope.proof else {
        unreachable!("Anonymous PGC payment fixture")
    };
    let middle = proof.bytes.len() / 2;
    proof.bytes[middle] ^= 1;
    let state = state_with_activation(active_lifecycle());
    let mut block = state.block(test_header());
    {
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        bootstrap
            .execute_signed(&ALICE_ID, &mut transaction)
            .expect("complete native bootstrap");
        transaction.apply();
    }
    let mut transaction = block.transaction();
    let invariants_before = transaction
        .world
        .privacy_pgc_pool_invariants
        .iter()
        .map(|(key, value)| (*key, *value))
        .collect::<Vec<_>>();
    let accounts_before = transaction
        .world
        .privacy_pgc_accounts
        .iter()
        .map(|(key, value)| (*key, *value))
        .collect::<Vec<_>>();
    let roots_before = transaction
        .world
        .privacy_roots
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect::<Vec<_>>();
    let heads_before = transaction
        .world
        .privacy_root_heads
        .iter()
        .map(|(key, value)| (*key, value.clone()))
        .collect::<Vec<_>>();
    let budget_before = transaction.privacy_budget_for_testing();
    bind_payment_instruction(&mut transaction, &payment);
    let error =
        execute_privacy_proof_after_admission_for_test(payment, &ALICE_ID, &mut transaction)
            .expect_err("one-bit proof mutation");
    assert_eq!(
        smart_contract_parameter_message(&error),
        "privacy proof admission rejected: native Anonymous-PGC verification failed: \
             Anonymous-PGC payment proof equation failed",
        "unexpected typed proof rejection: {error:?}"
    );
    assert_eq!(
        transaction
            .world
            .privacy_pgc_pool_invariants
            .iter()
            .map(|(key, value)| (*key, *value))
            .collect::<Vec<_>>(),
        invariants_before
    );
    assert_eq!(
        transaction
            .world
            .privacy_pgc_accounts
            .iter()
            .map(|(key, value)| (*key, *value))
            .collect::<Vec<_>>(),
        accounts_before
    );
    assert_eq!(
        transaction
            .world
            .privacy_roots
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>(),
        roots_before
    );
    assert_eq!(
        transaction
            .world
            .privacy_root_heads
            .iter()
            .map(|(key, value)| (*key, value.clone()))
            .collect::<Vec<_>>(),
        heads_before
    );
    assert_eq!(
        transaction.privacy_budget_for_testing(),
        budget_before,
        "failed native verification cannot reserve transaction or block budget"
    );
}
#[test]
fn verified_pgc_payment_replaces_complete_table_atomically_and_replay_rejects() {
    let bootstrap = valid_bootstrap_fixture();
    let payment = valid_payment_instruction();
    let payment_bytes = u64::try_from(
        norito::to_bytes(&payment.envelope)
            .expect("payment encoding")
            .len(),
    )
    .expect("payment length");
    let state = state_with_activation(active_lifecycle());
    let header = test_header();
    let header_hash = header.hash();
    let mut block = state.block(header);
    {
        let mut transaction = block.transaction();
        grant_governance(&mut transaction);
        bootstrap
            .clone()
            .execute_signed(&ALICE_ID, &mut transaction)
            .expect("complete native bootstrap");
        transaction.apply();
    }
    {
        let mut transaction = block.transaction();
        let invariant_key =
            PrivacyPgcPoolInvariantKeyV1::new(bootstrap.request.bootstrap.namespace)
                .expect("invariant key");
        let invariant_before = *transaction
            .world
            .privacy_pgc_pool_invariants
            .get(&invariant_key)
            .expect("bootstrapped invariant");
        let first_key = PrivacyPgcAccountKeyV1::new(
            bootstrap.request.bootstrap.namespace,
            bootstrap.request.bootstrap.accounts[0].public_key,
        )
        .expect("first account key");
        let first_balance_before = transaction
            .world
            .privacy_pgc_accounts
            .get(&first_key)
            .expect("first account")
            .encrypted_balance();
        bind_payment_instruction(&mut transaction, &payment);
        execute_privacy_proof_after_admission_for_test(
            payment.clone(),
            &ALICE_ID,
            &mut transaction,
        )
        .expect("complete native payment");
        assert_eq!(privacy_map_counts(&transaction), (1, 16, 2, 1));
        assert_eq!(
            transaction
                .world
                .privacy_pgc_pool_invariants
                .get(&invariant_key),
            Some(&invariant_before),
            "payments cannot replace bootstrap supply provenance"
        );
        assert_ne!(
            transaction
                .world
                .privacy_pgc_accounts
                .get(&first_key)
                .expect("updated first account")
                .encrypted_balance(),
            first_balance_before,
            "the complete successor table must replace current ciphertexts"
        );
        let head_key = PrivacyRootHeadKeyV1::new(
            bootstrap.request.bootstrap.namespace,
            PrivacyRootRoleV1::PgcAccountState,
        )
        .expect("head key");
        assert_eq!(
            transaction
                .world
                .privacy_root_heads
                .get(&head_key)
                .expect("payment head")
                .epoch(),
            2
        );
        let budget = transaction.privacy_budget_for_testing();
        assert_eq!(budget.0, 1);
        assert_eq!(budget.1, payment_bytes);
        assert_eq!(budget.2, 2);
        transaction.apply();
    }
    {
        let mut transaction = block.transaction();
        let mut next_limits = PrivacyConsensusLimitsV1::taira_default();
        next_limits.retained_root_count = 1;
        SchedulePrivacyConsensusPolicyTighteningV1::new(TEST_BLOCK_HEIGHT + 300, next_limits)
            .execute(&ALICE_ID, &mut transaction)
            .expect("schedule exact delayed PGC retention tightening");
        transaction.apply();
    }
    block
        .commit_world_overlay_for_testing()
        .expect("commit bootstrap and payment block");
    let next_header = BlockHeader::new(
        NonZeroU64::new(TEST_BLOCK_HEIGHT + 300).expect("effective height"),
        Some(header_hash),
        None,
        1_800_000_000_001,
        0,
    );
    let mut next_block = state.block(next_header);
    let mut transaction = next_block.transaction();
    assert_eq!(
        privacy_map_counts(&transaction),
        (1, 16, 1, 1),
        "effective-height hook must prune PGC history to the tightened cap"
    );
    let head_key = PrivacyRootHeadKeyV1::new(
        bootstrap.request.bootstrap.namespace,
        PrivacyRootRoleV1::PgcAccountState,
    )
    .expect("PGC head key");
    let head = transaction
        .world
        .privacy_root_heads
        .get(&head_key)
        .expect("pruned PGC head");
    let anchor = head
        .retention_anchor()
        .expect("pruning must commit the removed prefix anchor");
    assert_eq!(anchor.epoch(), bootstrap.request.bootstrap.initial_epoch);
    assert_eq!(anchor.root(), bootstrap.request.bootstrap.initial_root);
    assert_eq!(
        transaction
            .world
            .privacy_consensus_policy
            .get()
            .current_limits
            .retained_root_count,
        1
    );
    assert_eq!(
        transaction
            .world
            .privacy_consensus_policy
            .get()
            .pending_tightening,
        None
    );
    let counts_before = privacy_map_counts(&transaction);
    bind_payment_instruction(&mut transaction, &payment);
    let error =
        execute_privacy_proof_after_admission_for_test(payment, &ALICE_ID, &mut transaction)
            .expect_err("stale payment replay");
    assert!(
        smart_contract_parameter_message(&error).contains("StaleHead"),
        "unexpected replay rejection: {error:?}"
    );
    assert_eq!(privacy_map_counts(&transaction), counts_before);
    assert_eq!(
        transaction.privacy_budget_for_testing(),
        (0, 0, 0, 0),
        "failed replay must not consume the new block budget"
    );
}
