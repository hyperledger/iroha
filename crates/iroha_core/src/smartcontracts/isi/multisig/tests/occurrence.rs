// Occurrences are caller identities. Identical reviewed transfer contents remain reusable only
// with a new explicit nonce; every retry of one identity retains its original state.
fn with_occurrence_fixture(
    run: impl FnOnce(&mut StateTransaction<'_, '_>, &AccountId, &AccountId, &AccountId, &AssetId),
) {
    let first = new_account_id(&checked_keypair());
    let second = new_account_id(&checked_keypair());
    let domain = DomainId::try_new("occurrences", "universal").unwrap();
    let definition =
        AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
    let world = World::with(
        [Domain::new(domain).build(&first)],
        [
            Account::new(first.clone()).build(&first),
            Account::new(second.clone()).build(&first),
        ],
        [AssetDefinition::numeric(
            definition.clone(),
            "coin".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&first)],
    );
    let state = runtime_state(world, ChainId::from("multisig-occurrences"), None);
    let mut block = state.block(runtime_header(&state, 1_000));
    block.admit_fastpq_source_for_testing(Hash::prehashed([0x74; 32]));
    let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0x73; 32]));
    let policy = spec(BTreeMap::from([(first.clone(), 2), (second.clone(), 1)]), 2);
    let account = AccountId::new_multisig(multisig_policy_from_spec(&policy).unwrap());
    execute_register(
        &mut tx,
        &first,
        MultisigRegister::new(account.clone(), None, policy),
    )
    .unwrap();
    let asset = AssetId::new(definition, account.clone());
    Mint::asset_quantity(20_u32, asset.clone())
        .execute(&first, &mut tx)
        .unwrap();
    run(&mut tx, &first, &second, &account, &asset);
}

#[test]
fn multisig_occurrence_identical_payments_execute_once_each_and_conflicting_nonce_reuse_refuses() {
    with_occurrence_fixture(|tx, first, second, account, asset| {
        let inner: Vec<InstructionBox> = vec![
            iroha_data_model::isi::Transfer::asset_quantity(asset.clone(), 3_u32, first.clone())
                .into(),
        ];
        let hash = HashOf::new(&inner);
        let first_nonce = MultisigProposalNonce::new([1; 32]).unwrap();
        let id = MultisigProposalId::derive(&tx.network_id, account, &first_nonce);
        let original = MultisigPropose::new(
            account.clone(),
            first_nonce,
            inner.clone(),
            NonZeroU64::new(10_000),
        );
        execute_propose(tx, first, &original).unwrap();
        let original_bytes = tx
            .world
            .smart_contract_state
            .get(&multisig_proposal_state_key(account, &id))
            .unwrap()
            .clone();
        for changed in [
            original.clone(),
            MultisigPropose::new(account.clone(), first_nonce, vec![], None),
            MultisigPropose::new(
                account.clone(),
                first_nonce,
                inner.clone(),
                NonZeroU64::new(20_000),
            ),
        ] {
            assert!(execute_propose(tx, first, &changed).is_err());
            assert_eq!(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_state_key(account, &id)),
                Some(&original_bytes)
            );
        }
        let bad_hash = HashOf::new(&Vec::<InstructionBox>::new());
        assert!(
            execute_approve(
                tx,
                second,
                &MultisigApprove::new(account.clone(), id, bad_hash)
            )
            .is_err()
        );
        execute_approve(tx, second, &MultisigApprove::new(account.clone(), id, hash)).unwrap();
        assert!(
            execute_approve(tx, second, &MultisigApprove::new(account.clone(), id, hash)).is_err()
        );
        assert!(execute_propose(tx, first, &original).is_err());
        let terminal = tx
            .world
            .smart_contract_state
            .get(&multisig_proposal_terminal_state_key(account, &id))
            .unwrap()
            .clone();
        let nonce = MultisigProposalNonce::new([2; 32]).unwrap();
        let second_id = MultisigProposalId::derive(&tx.network_id, account, &nonce);
        assert_ne!(id, second_id);
        tx.tx_call_hash = Some(Hash::prehashed([0x74; 32]));
        execute_propose(
            tx,
            first,
            &MultisigPropose::new(account.clone(), nonce, inner, None),
        )
        .unwrap();
        execute_approve(
            tx,
            second,
            &MultisigApprove::new(account.clone(), second_id, hash),
        )
        .unwrap();
        assert_eq!(
            tx.world.assets.get(asset).unwrap().as_ref(),
            &Quantity::from(14_u32)
        );
        let receiver = AssetId::new(asset.definition().clone(), first.clone());
        assert_eq!(
            tx.world.assets.get(&receiver).unwrap().as_ref(),
            &Quantity::from(6_u32)
        );
        assert_eq!(
            tx.world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(account, &id)),
            Some(&terminal)
        );
        validate_persisted_proposals(&tx.world, Some(&tx.network_id)).unwrap();
    });
}

#[test]
fn multisig_occurrence_controller_changes_require_invalidation_and_never_move_originals() {
    for operation in 0..3 {
        with_occurrence_fixture(|tx, first, second, account, _| {
            let nonce = MultisigProposalNonce::new([0x21; 32]).unwrap();
            let id = MultisigProposalId::derive(&tx.network_id, account, &nonce);
            execute_propose(
                tx,
                first,
                &MultisigPropose::new(account.clone(), nonce, vec![], None),
            )
            .unwrap();
            let added = checked_keypair();
            let change = |tx: &mut StateTransaction<'_, '_>| match operation {
                0 => AddSignatory::new(account.clone(), added.public_key().clone())
                    .execute(first, tx),
                1 => RemoveSignatory::new(
                    account.clone(),
                    second.controller().single_signatory().unwrap().clone(),
                )
                .execute(first, tx),
                _ => SetAccountQuorum::new(account.clone(), nonzero!(1_u16)).execute(first, tx),
            };
            assert!(change(tx).is_err());
            assert!(proposal_state(tx, account, &id).is_ok());
            assert_eq!(
                invalidate_outstanding_proposals(tx, account).unwrap(),
                vec![id]
            );
            let original = tx
                .world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(account, &id))
                .unwrap()
                .clone();
            change(tx).unwrap();
            assert_eq!(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_terminal_state_key(account, &id)),
                Some(&original)
            );
            assert!(
                execute_propose(
                    tx,
                    first,
                    &MultisigPropose::new(account.clone(), nonce, vec![], None)
                )
                .is_err()
            );
        });
    }
}

#[test]
fn multisig_occurrence_expired_and_canceled_history_never_reopens_or_blocks_new_nonce() {
    for expired in [false, true] {
        with_occurrence_fixture(|tx, first, _, account, _| {
            let nonce = MultisigProposalNonce::new([0x31; 32]).unwrap();
            let id = MultisigProposalId::derive(&tx.network_id, account, &nonce);
            let instructions = Vec::<InstructionBox>::new();
            let hash = HashOf::new(&instructions);
            if expired {
                // Retain a valid earlier original, as a restart would, before current block time.
                store_multisig_proposal_state(
                    tx,
                    &MultisigProposalState::new(
                        tx.network_id,
                        account.clone(),
                        nonce,
                        id,
                        hash,
                        NonZeroU64::new(500),
                        instructions.clone(),
                        0,
                        500,
                        BTreeSet::from([first.clone()]),
                    ),
                )
                .unwrap();
                prune_expired(tx, account, &id, account).unwrap();
            } else {
                execute_propose(
                    tx,
                    first,
                    &MultisigPropose::new(account.clone(), nonce, instructions.clone(), None),
                )
                .unwrap();
                execute_cancel(tx, account, &MultisigCancel::new(account.clone(), id, hash))
                    .unwrap();
            }
            let bytes = tx
                .world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(account, &id))
                .unwrap()
                .clone();
            assert!(
                execute_propose(
                    tx,
                    first,
                    &MultisigPropose::new(account.clone(), nonce, instructions.clone(), None)
                )
                .is_err()
            );
            let fresh_nonce = MultisigProposalNonce::new([0x32; 32]).unwrap();
            let fresh_id = MultisigProposalId::derive(&tx.network_id, account, &fresh_nonce);
            execute_propose(
                tx,
                first,
                &MultisigPropose::new(account.clone(), fresh_nonce, instructions, None),
            )
            .unwrap();
            assert!(proposal_state(tx, account, &fresh_id).is_ok());
            assert_eq!(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_terminal_state_key(account, &id)),
                Some(&bytes)
            );
            validate_persisted_proposals(&tx.world, Some(&tx.network_id)).unwrap();
        });
    }
}

#[test]
fn multisig_occurrence_restore_rejects_foreign_network_and_terminal_substitutions() {
    with_occurrence_fixture(|tx, first, second, account, _| {
        let nonce = MultisigProposalNonce::new([0x41; 32]).unwrap();
        let id = MultisigProposalId::derive(&tx.network_id, account, &nonce);
        let instructions = Vec::<InstructionBox>::new();
        let hash = HashOf::new(&instructions);
        execute_propose(
            tx,
            first,
            &MultisigPropose::new(account.clone(), nonce, instructions, None),
        )
        .unwrap();
        let foreign_network = NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
            Hash::prehashed([0x42; 32]),
        ));
        assert_ne!(tx.network_id, foreign_network);
        validate_persisted_proposals(&tx.world, Some(&tx.network_id)).unwrap();
        assert!(validate_persisted_proposals(&tx.world, Some(&foreign_network)).is_err());
        execute_approve(tx, second, &MultisigApprove::new(account.clone(), id, hash)).unwrap();
        validate_persisted_proposals(&tx.world, Some(&tx.network_id)).unwrap();
        assert!(validate_persisted_proposals(&tx.world, Some(&foreign_network)).is_err());

        let key = multisig_proposal_terminal_state_key(account, &id);
        let bytes = tx.world.smart_contract_state.get(&key).unwrap().clone();
        let original: MultisigProposalTerminalState = norito::decode_from_bytes(&bytes).unwrap();
        for mutation in 0..5 {
            let mut changed = original.clone();
            match mutation {
                0 => {
                    changed.proposal.proposal_nonce =
                        MultisigProposalNonce::new([0x43; 32]).unwrap()
                }
                1 => changed.proposal.network_id = foreign_network,
                2 => {
                    changed.instructions_hash = HashOf::new(&vec![InstructionBox::from(Log::new(
                        Level::INFO,
                        "different body".into(),
                    ))])
                }
                3 => {
                    changed.proposal.proposal_id =
                        MultisigProposalId::derive(&foreign_network, account, &nonce)
                }
                _ => changed.proposal.transaction_ttl_ms = NonZeroU64::new(1),
            }
            tx.world
                .smart_contract_state
                .insert(key.clone(), norito::to_bytes(&changed).unwrap());
            assert!(validate_persisted_proposals(&tx.world, Some(&tx.network_id)).is_err());
        }
        tx.world.smart_contract_state.insert(key, bytes.clone());
        let other_key = multisig_proposal_terminal_state_key(
            account,
            &MultisigProposalId::derive(&foreign_network, account, &nonce),
        );
        tx.world
            .smart_contract_state
            .insert(other_key.clone(), bytes);
        assert!(validate_persisted_proposals(&tx.world, Some(&tx.network_id)).is_err());
        tx.world.smart_contract_state.remove(other_key);
        validate_persisted_proposals(&tx.world, Some(&tx.network_id)).unwrap();
    });
}

#[test]
fn multisig_occurrence_cancellation_selects_one_of_identical_pending_bodies() {
    with_occurrence_fixture(|tx, first, second, account, _| {
        let inner = Vec::<InstructionBox>::new();
        let hash = HashOf::new(&inner);
        let first_nonce = MultisigProposalNonce::new([0x51; 32]).unwrap();
        let second_nonce = MultisigProposalNonce::new([0x52; 32]).unwrap();
        let first_id = MultisigProposalId::derive(&tx.network_id, account, &first_nonce);
        let second_id = MultisigProposalId::derive(&tx.network_id, account, &second_nonce);
        for nonce in [first_nonce, second_nonce] {
            execute_propose(
                tx,
                first,
                &MultisigPropose::new(account.clone(), nonce, inner.clone(), None),
            )
            .unwrap();
        }
        let second_key = multisig_proposal_state_key(account, &second_id);
        let untouched_second = tx
            .world
            .smart_contract_state
            .get(&second_key)
            .unwrap()
            .clone();
        let cancel_inner = vec![InstructionBox::from(MultisigCancel::new(
            account.clone(),
            first_id,
            hash,
        ))];
        let cancel_hash = HashOf::new(&cancel_inner);
        let cancel_nonce = MultisigProposalNonce::new([0x53; 32]).unwrap();
        let cancel_id = MultisigProposalId::derive(&tx.network_id, account, &cancel_nonce);
        execute_propose(
            tx,
            first,
            &MultisigPropose::new(account.clone(), cancel_nonce, cancel_inner, None),
        )
        .unwrap();
        execute_approve(
            tx,
            second,
            &MultisigApprove::new(account.clone(), cancel_id, cancel_hash),
        )
        .unwrap();
        assert!(proposal_state(tx, account, &first_id).is_err());
        assert_eq!(
            tx.world.smart_contract_state.get(&second_key),
            Some(&untouched_second)
        );
        for (id, status) in [
            (first_id, MultisigProposalTerminalStatus::Canceled),
            (cancel_id, MultisigProposalTerminalStatus::Finalized),
        ] {
            let bytes = tx
                .world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(account, &id))
                .unwrap();
            let terminal: MultisigProposalTerminalState = norito::decode_from_bytes(bytes).unwrap();
            assert_eq!(terminal.proposal_id, id);
            assert_eq!(terminal.status, status);
            let execution_key = multisig_proposal_terminal_execution_state_key(
                *tx.tx_call_hash.as_ref().unwrap().as_ref(),
                account,
                &id,
            );
            let execution: MultisigProposalTerminalExecutionStateV1 = norito::decode_from_bytes(
                tx.world.smart_contract_state.get(&execution_key).unwrap(),
            )
            .unwrap();
            assert_eq!(execution.terminal, terminal);
        }
        let outcome_key = multisig_approval_outcome_state_key(
            *tx.tx_call_hash.as_ref().unwrap().as_ref(),
            account,
            &cancel_id,
        );
        let outcome: MultisigApprovalOutcomeV1 =
            norito::decode_from_bytes(tx.world.smart_contract_state.get(&outcome_key).unwrap())
                .unwrap();
        assert_eq!(outcome.status, MultisigApprovalOutcomeStatusV1::Executed);
        assert_eq!(outcome.proposal_id, cancel_id);
        assert_eq!(outcome.instructions_hash, cancel_hash);
        validate_persisted_proposals(&tx.world, Some(&tx.network_id)).unwrap();
    });
}

#[test]
fn multisig_occurrence_refuses_nested_cancellation_before_any_original_mutation() {
    with_occurrence_fixture(|tx, first, _, account, _| {
        let target_nonce = MultisigProposalNonce::new([0x61; 32]).unwrap();
        let target_id = MultisigProposalId::derive(&tx.network_id, account, &target_nonce);
        let target = Vec::<InstructionBox>::new();
        let target_hash = HashOf::new(&target);
        execute_propose(
            tx,
            first,
            &MultisigPropose::new(account.clone(), target_nonce, target, None),
        )
        .unwrap();
        let cancel_nonce = MultisigProposalNonce::new([0x62; 32]).unwrap();
        let cancel_id = MultisigProposalId::derive(&tx.network_id, account, &cancel_nonce);
        let cancellation = vec![InstructionBox::from(MultisigCancel::new(
            account.clone(),
            target_id,
            target_hash,
        ))];
        let cancel_hash = HashOf::new(&cancellation);
        execute_propose(
            tx,
            first,
            &MultisigPropose::new(account.clone(), cancel_nonce, cancellation, None),
        )
        .unwrap();
        let originals = tx
            .world
            .smart_contract_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        let refusal = execute_cancel(
            tx,
            account,
            &MultisigCancel::new(account.clone(), cancel_id, cancel_hash),
        )
        .unwrap_err();
        assert!(
            matches!(refusal, ValidationFail::NotPermitted(message) if message.contains("cannot target another cancellation proposal"))
        );
        assert_eq!(
            tx.world
                .smart_contract_state
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<Vec<_>>(),
            originals
        );
        assert!(proposal_state(tx, account, &target_id).is_ok());
        assert!(proposal_state(tx, account, &cancel_id).is_ok());
        assert!(!tx.is_execution_deferred());
    });
}
