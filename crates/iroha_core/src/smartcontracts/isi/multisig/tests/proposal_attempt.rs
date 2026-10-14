//! Original live proposal reads remain retryable under a local decoder ceiling.

use super::*;
use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
use iroha_data_model::{
    asset::Asset,
    isi::Transfer,
    transaction::{FeePaymentIntent, TransactionBuilder},
};

fn limited<T>(read: impl FnOnce() -> T) -> T {
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        read,
    )
}

#[test]
fn live_multisig_proposal_decode_refusal_retries_original_signed_xor_transfer() {
    signed_xor_transfer_retry(false);
}

#[test]
fn live_multisig_proposal_body_binding_rolls_back_original_signed_xor_transfer() {
    signed_xor_transfer_retry(true);
}

fn signed_xor_transfer_retry(check_body_binding: bool) {
    crate::validation_fee::tests::with_validation_fee_payout_block_at_time(
        2,
        2_000,
        |block, authority, _, _| {
            let network_id = block.network_id;
            let signer = KeyPair::from_seed(vec![55; 32], Algorithm::Ed25519);
            assert_eq!(*authority, AccountId::new(signer.public_key().clone()));
            let spec = MultisigSpec::new(
                BTreeMap::from([(authority.clone(), 1)]),
                nonzero!(1_u16),
                nonzero!(60_000_u64),
            );
            let multisig = AccountId::new_multisig(multisig_policy_from_spec(&spec).unwrap());
            let xor = iroha_data_model::parameter::system::SumeragiNposParameters::default()
                .xor_asset_definition_id;
            let source = AssetId::new(xor.clone(), multisig.clone());
            let destination = AssetId::new(xor, authority.clone());
            let instructions: Vec<InstructionBox> = vec![
                Transfer::asset_quantity(source.clone(), Quantity::from(10_u32), authority.clone())
                    .into(),
            ];
            let hash = HashOf::new(&instructions);
            let approval = MultisigApprove::new(
                multisig.clone(),
                test_id(&network_id, &multisig.clone(), &hash),
                hash,
            );
            let key =
                multisig_proposal_state_key(&multisig, &test_id(&network_id, &multisig, &hash));
            let original = MultisigProposalState {
                network_id,
                multisig_account_id: multisig.clone(),
                proposal_nonce: test_nonce(&hash),
                proposal_id: test_id(&network_id, &multisig.clone(), &hash),
                instructions_hash: hash,
                transaction_ttl_ms: None,
                instructions: instructions.clone(),
                proposed_at_ms: 1_000,
                expires_at_ms: 60_000,
                approvals: BTreeSet::new(),
            };
            let bytes = norito::to_bytes(&original).unwrap();
            {
                let mut setup = block.transaction_for_callback_testing();
                setup.world.accounts.insert(
                    multisig.clone(),
                    Account::new(multisig.clone())
                        .build(authority)
                        .into_key_value()
                        .1,
                );
                persist_multisig_account_state(
                    &mut setup,
                    None,
                    &MultisigAccountState::new(multisig.clone(), None, spec),
                )
                .unwrap();
                store_multisig_proposal_state(&mut setup, &original).unwrap();
                for (asset, amount) in [(&source, 20_u32), (&destination, 0)] {
                    let (_, value) =
                        Asset::new(asset.clone(), Quantity::from(amount)).into_key_value();
                    setup.world.assets.insert(asset.clone(), value);
                }
                // Reserved principal survives both decoder refusals and the successful transfer.
                setup
                    .world
                    .public_lane_stake_reserves
                    .insert(source.clone(), Quantity::from(10_u32));
                setup.apply();
            }
            let signed_payload = TransactionBuilder::new(
                block.network_id,
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), nonzero!(100_000_000_u64).into()),
            )
            .with_instructions(vec![InstructionBox::from(approval.clone())])
            .sign(signer.private_key());
            let call = Hash::from(signed_payload.hash_as_entrypoint());
            let fragments = block.committed_fragment_count();
            if check_body_binding {
                let mut tx = block.transaction_for_fastpq_testing(call);
                tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                let mut altered = original.clone();
                altered.instructions =
                    vec![Log::new(Level::INFO, "unapproved replacement body".into()).into()];
                let altered_bytes = norito::to_bytes(&altered).unwrap();
                tx.world
                    .smart_contract_state
                    .insert(key.clone(), altered_bytes.clone());
                let error = Executor::Initial
                    .execute_transaction(
                        &mut tx,
                        authority,
                        signed_payload.clone(),
                        &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                    )
                    .expect_err("the signed hash cannot authorize a substituted retained body");
                assert!(
                    matches!(error, ExecutionAttemptError::Rejected(actual) if actual == invalid_proposal_binding())
                );
                assert!(!tx.is_execution_deferred());
                assert_eq!(
                    tx.world.smart_contract_state.get(&key),
                    Some(&altered_bytes)
                );
                assert_eq!(
                    tx.world.assets.get(&source).unwrap().as_ref(),
                    &Quantity::from(20_u32)
                );
                assert_eq!(
                    tx.world.assets.get(&destination).unwrap().as_ref(),
                    &Quantity::zero()
                );
                assert_eq!(
                    tx.world.public_lane_stake_reserves.get(&source),
                    Some(&Quantity::from(10_u32))
                );
                // Drop this actual rejected transaction, including its substituted read source.
            }
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(
                block
                    .transaction_for_callback_testing()
                    .world
                    .smart_contract_state
                    .get(&key),
                Some(&bytes)
            );
            let expected: ExecutionDeferred =
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into();
            {
                let mut tx = block.transaction_for_fastpq_testing(call);
                tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                // The exact retained bytes refuse in the real cumulative decoder scope.
                limited(|| {
                    assert!(matches!(
                        norito::decode_from_bytes::<MultisigProposalState>(&bytes),
                        Err(norito::Error::TotalAllocationExceeded { limit: 0, .. })
                    ));
                    {
                        let ExecutionAttemptError::Deferred(actual) =
                            (live_proposal_instructions_for_approval(&tx, &approval))
                                .expect_err("the original operation must defer")
                        else {
                            panic!("expected an unfinished local attempt")
                        };
                        assert_original_allocation_refusal(&actual, 0);
                    };
                });
                let opaque: InstructionBox = approval.clone().into();
                limited(|| {
                    let error = MultisigInstructionBox::try_from(&opaque).expect_err(
                        "canonical CustomInstruction parsing uses the actual decoder scope",
                    );
                    {
                        let ExecutionAttemptError::Deferred(actual) =
                            multisig_instruction_decode_attempt(error, |_| ())
                        else {
                            panic!("expected an unfinished local attempt")
                        };
                        assert_instruction_decode_deferral(&actual, expected.reason());
                    };
                });
                let projected = limited(|| {
                    crate::deferred_authority::reject_opaque_instruction_authority(
                        std::iter::once(&opaque),
                        &tx,
                    )
                });
                {
                    let ExecutionAttemptError::Deferred(actual) =
                        (projected).expect_err("the original operation must defer")
                    else {
                        panic!("expected an unfinished local attempt")
                    };
                    assert_instruction_decode_deferral(&actual, expected.reason());
                };
                // The native approval entry point retains the same read refusal in
                // its model-owned error bridge, before recording an approval outcome.
                limited(|| execute_approve(&mut tx, authority, &approval))
                    .expect_err("an unfinished native read must stop approval");
                assert_original_allocation_refusal(&tx.borrow_execution_deferral().unwrap(), 0);
                assert!(
                    expected.allocation_refusal().is_none(),
                    "a Norito ceiling has no invented pool notification"
                );
                assert_eq!(tx.world.smart_contract_state.get(&key), Some(&bytes));
                assert_eq!(
                    tx.world.assets.get(&source).unwrap().as_ref(),
                    &Quantity::from(20_u32)
                );
                assert_eq!(
                    tx.world.public_lane_stake_reserves.get(&source),
                    Some(&Quantity::from(10_u32))
                );
                // Discard the actual refused overlay, including its sticky retry owner.
            }
            assert_eq!(block.committed_fragment_count(), fragments);
            {
                let tx = block.transaction_for_callback_testing();
                assert_eq!(tx.world.smart_contract_state.get(&key), Some(&bytes));
                assert_eq!(
                    live_proposal_instructions_for_approval(&tx, &approval).unwrap(),
                    Some((multisig.clone(), instructions))
                );
                assert_eq!(
                    tx.world.assets.get(&destination).unwrap().as_ref(),
                    &Quantity::zero()
                );
            }
            // Retry the identical signed approval, now with sufficient local decode capacity.
            let mut tx = block.transaction_for_fastpq_testing(call);
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            Executor::Initial
                .execute_transaction(
                    &mut tx,
                    authority,
                    signed_payload,
                    &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                )
                .unwrap();
            assert!(tx.complete_direct_callbacks(call).unwrap().is_empty());
            tx.apply();
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            let tx = block.transaction_for_callback_testing();
            assert_eq!(
                tx.world.assets.get(&source).unwrap().as_ref(),
                &Quantity::from(10_u32)
            );
            assert_eq!(
                tx.world.assets.get(&destination).unwrap().as_ref(),
                &Quantity::from(10_u32)
            );
            assert_eq!(
                tx.world.public_lane_stake_reserves.get(&source),
                Some(&Quantity::from(10_u32))
            );
            assert!(tx.world.smart_contract_state.get(&key).is_none());
        },
    );
}

#[test]
fn live_multisig_proposal_missing_malformed_and_rebound_state_are_not_deferrals() {
    let authority = new_account_id(&checked_keypair());
    let state = runtime_state(
        World::with([], [Account::new(authority.clone()).build(&authority)], []),
        ChainId::from("multisig-proposal-read-binding"),
        None,
    );
    let mut block = state.block(runtime_header(&state, 2_000));
    let mut tx = block.transaction_for_callback_testing();
    let network_id = tx.network_id;
    let instructions = vec![InstructionBox::from(Log::new(
        Level::INFO,
        "reviewed".into(),
    ))];
    let hash = HashOf::new(&instructions);
    let approval = MultisigApprove::new(
        authority.clone(),
        test_id(&network_id, &authority.clone(), &hash),
        hash,
    );
    let key = multisig_proposal_state_key(&authority, &test_id(&network_id, &authority, &hash));
    assert_eq!(
        live_proposal_instructions_for_approval(&tx, &approval).unwrap(),
        None
    );
    tx.world
        .smart_contract_state
        .insert(key.clone(), vec![1, 2, 3]);
    assert!(matches!(
        live_proposal_instructions_for_approval(&tx, &approval),
        Err(ExecutionAttemptError::Rejected(
            ValidationFail::QueryFailed(QueryExecutionFail::Conversion(_))
        ))
    ));
    let original = MultisigProposalState {
        network_id,
        multisig_account_id: authority.clone(),
        proposal_nonce: test_nonce(&hash),
        proposal_id: test_id(&network_id, &authority.clone(), &hash),
        instructions_hash: hash,
        transaction_ttl_ms: None,
        instructions,
        proposed_at_ms: 1_000,
        expires_at_ms: 60_000,
        approvals: BTreeSet::new(),
    };
    for mutation in 0..6 {
        let mut altered = original.clone();
        match mutation {
            0 => altered.multisig_account_id = new_account_id(&checked_keypair()),
            1 => altered.instructions_hash = HashOf::new(&Vec::<InstructionBox>::new()),
            2 => altered.proposal_nonce = MultisigProposalNonce::new([0x81; 32]).unwrap(),
            3 => {
                altered.proposal_id = MultisigProposalId::derive(
                    &network_id,
                    &authority,
                    &MultisigProposalNonce::new([0x82; 32]).unwrap(),
                )
            }
            4 => {
                altered.network_id = iroha_data_model::NetworkId::from_genesis_hash(
                    HashOf::from_untyped_unchecked(Hash::prehashed([0x83; 32])),
                )
            }
            _ => altered.transaction_ttl_ms = NonZeroU64::new(1),
        }
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&altered).unwrap());
        assert!(
            matches!(live_proposal_instructions_for_approval(&tx, &approval), Err(ExecutionAttemptError::Rejected(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(ref message)))) if message.contains("exact network, account, occurrence key"))
        );
    }
    assert!(!tx.is_execution_deferred());
    let ordinary: InstructionBox = Log::new(Level::INFO, "ordinary non-multisig".into()).into();
    limited(|| {
        crate::deferred_authority::reject_opaque_instruction_authority(
            std::iter::once(&ordinary),
            &tx,
        )
        .unwrap();
    });
}

fn proposal_decode_allocation_used(operation: impl FnOnce()) -> usize {
    const CEILING: usize = 8 * 1024 * 1024;
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, usize::MAX),
        || {
            operation();
            let norito::Error::TotalAllocationExceeded { attempted, limit } =
                norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
            else {
                panic!("over-limit probe must report the original cumulative decoder usage");
            };
            assert_eq!(limit, CEILING as u64);
            usize::try_from(attempted).unwrap() - CEILING - 1
        },
    )
}

#[test]
fn cancel_wrapper_decode_refusal_rolls_back_and_retries_original_signed_approval() {
    terminal_decode_retry(false);
}

#[test]
fn expiry_child_decode_refusal_rolls_back_and_retries_original_signed_approval() {
    terminal_decode_retry(true);
}

fn terminal_decode_retry(expired: bool) {
    crate::validation_fee::tests::with_validation_fee_payout_block_at_time(
        2,
        2_000,
        |block, authority, _, _| {
            let network_id = block.network_id;
            let signer = KeyPair::from_seed(vec![55; 32], Algorithm::Ed25519);
            assert_eq!(*authority, AccountId::new(signer.public_key().clone()));
            let spec = MultisigSpec::new(
                BTreeMap::from([(authority.clone(), 1)]),
                nonzero!(1_u16),
                nonzero!(60_000_u64),
            );
            let account = AccountId::new_multisig(multisig_policy_from_spec(&spec).unwrap());
            let leaf_instructions = vec![InstructionBox::from(Log::new(
                Level::INFO,
                "unchanged terminal target".into(),
            ))];
            let leaf_hash = HashOf::new(&leaf_instructions);
            let instructions = vec![if expired {
                InstructionBox::from(MultisigApprove::new(
                    account.clone(),
                    test_id(&network_id, &account.clone(), &leaf_hash),
                    leaf_hash,
                ))
            } else {
                InstructionBox::from(MultisigCancel::new(
                    account.clone(),
                    test_id(&network_id, &account.clone(), &leaf_hash),
                    leaf_hash,
                ))
            }];
            let hash = HashOf::new(&instructions);
            let expiry = if expired { 1_500 } else { 60_000 };
            let proposal = MultisigProposalState {
                network_id,
                multisig_account_id: account.clone(),
                proposal_nonce: test_nonce(&hash),
                proposal_id: test_id(&network_id, &account.clone(), &hash),
                instructions_hash: hash,
                transaction_ttl_ms: None,
                instructions,
                proposed_at_ms: 1_000,
                expires_at_ms: expiry,
                approvals: BTreeSet::new(),
            };
            let leaf = MultisigProposalState {
                network_id,
                multisig_account_id: account.clone(),
                proposal_nonce: test_nonce(&leaf_hash),
                proposal_id: test_id(&network_id, &account.clone(), &leaf_hash),
                instructions_hash: leaf_hash,
                transaction_ttl_ms: None,
                instructions: leaf_instructions,
                proposed_at_ms: 1_000,
                expires_at_ms: expiry,
                approvals: BTreeSet::new(),
            };
            {
                let mut tx = block.transaction_for_callback_testing();
                tx.world.accounts.insert(
                    account.clone(),
                    Account::new(account.clone())
                        .build(authority)
                        .into_key_value()
                        .1,
                );
                persist_multisig_account_state(
                    &mut tx,
                    None,
                    &MultisigAccountState::new(account.clone(), None, spec),
                )
                .unwrap();
                store_multisig_proposal_state(&mut tx, &leaf).unwrap();
                store_multisig_proposal_state(&mut tx, &proposal).unwrap();
                tx.apply();
            }
            let approval = MultisigApprove::new(
                account.clone(),
                test_id(&network_id, &account.clone(), &hash),
                hash,
            );
            let signed_payload = TransactionBuilder::new(
                block.network_id,
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), nonzero!(100_000_000_u64).into()),
            )
            .with_instructions(vec![InstructionBox::from(approval)])
            .sign(signer.private_key());
            let call = Hash::from(signed_payload.hash_as_entrypoint());
            let before: BTreeMap<_, _> = block
                .transaction_for_callback_testing()
                .world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            let fragments = block.committed_fragment_count();
            let expected: ExecutionDeferred =
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into();
            {
                let mut tx = block.transaction_for_fastpq_testing(call);
                let network_id = tx.network_id;
                if expired {
                    let read_budget = proposal_decode_allocation_used(|| {
                        proposal_state_attempt(
                            &tx,
                            &account,
                            &test_id(&network_id, &account, &hash),
                        )
                        .unwrap();
                    });
                    let limits = norito::DecodeLimits::new(
                        usize::MAX,
                        usize::MAX,
                        usize::MAX,
                        read_budget,
                        usize::MAX,
                    );
                    norito::with_decode_limits_scope(limits, || {
                        let exact = proposal_state_attempt(
                            &tx,
                            &account,
                            &test_id(&network_id, &account, &hash),
                        )
                        .expect("the funded retained row read completes first");
                        let child = proposal_instruction_attempt(&exact.instructions[0])
                            .expect_err("the child proposal instruction must defer");
                        let ExecutionAttemptError::Deferred(actual) = child else {
                            panic!("expected an unfinished local attempt");
                        };
                        assert_instruction_decode_deferral(&actual, expected.reason());
                    });
                    norito::with_decode_limits_scope(limits, || {
                        prune_expired(
                            &mut tx,
                            &account,
                            &test_id(&network_id, &account, &hash),
                            &account,
                        )
                    })
                    .expect_err(
                        "expiry cannot skip its child approval when local decoding refuses",
                    );
                }
                if expired {
                    let actual = tx
                        .borrow_execution_deferral()
                        .expect("expired traversal retains its original refusal");
                    assert_instruction_decode_deferral(&actual, expected.reason());
                }
                assert_eq!(
                    tx.world
                        .smart_contract_state
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect::<BTreeMap<_, _>>(),
                    before
                );
                // Discard this actual transaction and its original retry owner.
            }
            {
                let mut tx = block.transaction_for_fastpq_testing(call);
                tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
                // Admit the real child first. Bound recursive decoding only after proving
                // that the same immutable root metadata can complete at this depth. A zero
                // whole-Executor allocation budget would instead poison the block's root
                // admission and test a different boundary than multisig traversal.
                let root = crate::sumeragi::lanes::routing::read_committed_root_scope(&tx.world)
                    .unwrap()
                    .expect("the fixture has an authenticated root");
                let depth = (1..=64)
                    .find(|&depth| {
                        norito::with_decode_limits_scope(
                            norito::DecodeLimits::new(
                                usize::MAX,
                                usize::MAX,
                                usize::MAX,
                                usize::MAX,
                                depth,
                            ),
                            || {
                                crate::sumeragi::lanes::routing::read_committed_root_scope(
                                    &tx.world,
                                )
                                .is_ok_and(|scope| scope == Some(root))
                            },
                        )
                    })
                    .expect("the original root has a finite decoder depth");
                let limits = norito::DecodeLimits::new(
                    usize::MAX,
                    usize::MAX,
                    usize::MAX,
                    usize::MAX,
                    depth,
                );
                norito::with_decode_limits_scope(limits, || {
                    crate::executor::root_scope::ensure_executable_scope(
                        &mut tx,
                        signed_payload.instructions(),
                    )
                })
                .expect("the signed attempt reaches past immutable root admission");
                let error = norito::with_decode_limits_scope(limits, || {
                    Executor::Initial.execute_transaction(
                        &mut tx,
                        authority,
                        signed_payload.clone(),
                        &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                    )
                })
                .expect_err("the unchanged signed operation also preserves its local read refusal");
                {
                    let ExecutionAttemptError::Deferred(actual) = error else {
                        panic!("expected an unfinished local attempt")
                    };
                    assert_original_depth_refusal(&actual, depth);
                    let original = actual.decode_refusal().unwrap().clone();
                    let transferred = ExecutionDeferred::try_from_vm_error(actual.into_vm_error())
                        .expect("the original terminal refusal crosses the host boundary");
                    assert_eq!(transferred.decode_refusal(), Some(&original));
                    assert_original_depth_refusal(&transferred, depth);
                };
                assert!(tx.require_storage_admission().is_ok());
                assert!(tx.is_execution_deferred());
                assert!(
                    tx.borrow_execution_deferral().is_none(),
                    "outer terminal transferred the sole cause"
                );
            }
            assert_eq!(block.committed_fragment_count(), fragments);
            assert_eq!(
                block
                    .transaction_for_callback_testing()
                    .world
                    .smart_contract_state
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<BTreeMap<_, _>>(),
                before
            );
            let mut tx = block.transaction_for_fastpq_testing(call);
            let network_id = tx.network_id;
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            Executor::Initial
                .execute_transaction(
                    &mut tx,
                    authority,
                    signed_payload,
                    &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                )
                .unwrap();
            assert!(tx.complete_direct_callbacks(call).unwrap().is_empty());
            tx.apply();
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            let tx = block.transaction_for_callback_testing();
            for proposal_hash in if expired {
                vec![hash]
            } else {
                vec![hash, leaf_hash]
            } {
                assert!(
                    tx.world
                        .smart_contract_state
                        .get(&multisig_proposal_state_key(
                            &account,
                            &test_id(&network_id, &account, &proposal_hash)
                        ))
                        .is_none()
                );
            }
            let leaf_key = multisig_proposal_state_key(&account, &leaf.proposal_id);
            let leaf_terminal_key =
                multisig_proposal_terminal_state_key(&account, &leaf.proposal_id);
            if expired {
                assert_eq!(
                    tx.world.smart_contract_state.get(&leaf_key),
                    before.get(&leaf_key),
                    "an expired parent never executes or expires its child approval"
                );
                assert!(
                    tx.world
                        .smart_contract_state
                        .get(&leaf_terminal_key)
                        .is_none()
                );
            } else {
                let leaf_terminal = tx
                    .world
                    .smart_contract_state
                    .get(&leaf_terminal_key)
                    .expect("the selected cancellation target receives its terminal status");
                let terminal: MultisigProposalTerminalState =
                    norito::decode_from_bytes(leaf_terminal).unwrap();
                assert_eq!(terminal.status, MultisigProposalTerminalStatus::Canceled);
            }
            let parent_terminal: MultisigProposalTerminalState = norito::decode_from_bytes(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_terminal_state_key(
                        &account,
                        &proposal.proposal_id,
                    ))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                parent_terminal.status,
                if expired {
                    MultisigProposalTerminalStatus::Expired
                } else {
                    MultisigProposalTerminalStatus::Finalized
                }
            );
            let outcome: MultisigApprovalOutcomeV1 = norito::decode_from_bytes(
                tx.world
                    .smart_contract_state
                    .get(&multisig_approval_outcome_state_key(
                        *call.as_ref(),
                        &account,
                        &proposal.proposal_id,
                    ))
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                outcome.status,
                if expired {
                    MultisigApprovalOutcomeStatusV1::NotExecuted
                } else {
                    MultisigApprovalOutcomeStatusV1::Executed
                }
            );
        },
    );
}

#[test]
fn outstanding_occurrence_invalidation_preserves_original_decode_refusal() {
    with_occurrence_fixture(|tx, first, _, account, _| {
        let nonce = MultisigProposalNonce::new([0x55; 32]).unwrap();
        let id = MultisigProposalId::derive(&tx.network_id, account, &nonce);
        execute_propose(
            tx,
            first,
            &MultisigPropose::new(account.clone(), nonce, vec![], None),
        )
        .unwrap();
        let key = multisig_proposal_state_key(account, &id);
        let original = tx.world.smart_contract_state.get(&key).unwrap().clone();
        assert!(limited(|| invalidate_outstanding_proposals(tx, account)).is_err());
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&original));
        assert!(require_no_outstanding_proposals(tx, account).is_err());
        assert_eq!(
            invalidate_outstanding_proposals(tx, account).unwrap(),
            vec![id]
        );
        assert!(tx.world.smart_contract_state.get(&key).is_none());
    });
}

/// Direct custom-instruction parsing reports its local reason without a canonical owner.
fn assert_instruction_decode_deferral(
    actual: &ExecutionDeferred,
    expected: ivm::error::ExecutionDeferral,
) {
    assert_eq!(actual.reason(), expected);
    assert_eq!(actual.phase(), None);
    assert!(actual.allocation_refusal().is_none());
    assert!(actual.allocator_refusal().is_none());
    assert!(actual.decode_refusal().is_none());
    assert!(actual.verification_refusal().is_none());
}

/// Canonical retained-row reads preserve their original scope without inventing a pool wake.
fn original_decode_refusal(actual: &ExecutionDeferred) -> &norito::core::DecodeLocalRefusal {
    assert_eq!(
        actual.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert_eq!(actual.phase(), None);
    assert!(actual.allocation_refusal().is_none());
    assert!(actual.allocator_refusal().is_none());
    assert!(actual.verification_refusal().is_none());
    let original = actual
        .decode_refusal()
        .expect("canonical decode retains its original cause");
    assert_eq!(
        original.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert_eq!(original.allocation_bytes(), None);
    original
}

fn assert_original_allocation_refusal(actual: &ExecutionDeferred, expected_limit: u64) {
    assert!(matches!(
        original_decode_refusal(actual).resource_error(),
        norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit }
            if limit == expected_limit && attempted > limit
    ));
}

fn assert_original_depth_refusal(actual: &ExecutionDeferred, expected_limit: usize) {
    assert!(matches!(
        original_decode_refusal(actual).resource_error(),
        norito::core::DecodeResourceError::NestingDepthExceeded { depth, limit, .. }
            if limit == expected_limit && depth > limit
    ));
}
