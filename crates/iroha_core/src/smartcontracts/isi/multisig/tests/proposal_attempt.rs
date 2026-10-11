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
            let approval = MultisigApprove::new(multisig.clone(), hash);
            let key = multisig_proposal_state_key(&multisig, &hash);
            let original = MultisigProposalState::new(
                multisig.clone(),
                hash,
                instructions.clone(),
                1_000,
                60_000,
                BTreeSet::new(),
                None,
            );
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
            let signed = TransactionBuilder::new(
                block.network_id,
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), nonzero!(100_000_000_u64).into()),
            )
            .with_instructions(vec![InstructionBox::from(approval.clone())])
            .sign(signer.private_key());
            let call = Hash::from(signed.hash_as_entrypoint());
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
                        signed.clone(),
                        &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                    )
                    .expect_err("the signed hash cannot authorize a substituted retained body");
                assert_eq!(
                    error,
                    ExecutionAttemptError::Rejected(invalid_proposal_binding())
                );
                assert!(tx.execution_deferral().is_none());
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
                    assert_eq!(
                        live_proposal_instructions_for_approval(&tx, &approval),
                        Err(ExecutionAttemptError::Deferred(expected.clone()))
                    );
                });
                let opaque: InstructionBox = approval.clone().into();
                limited(|| {
                    let error = MultisigInstructionBox::try_from(&opaque).expect_err(
                        "canonical CustomInstruction parsing uses the actual decoder scope",
                    );
                    assert_eq!(
                        multisig_instruction_decode_attempt(error, |_| ()),
                        ExecutionAttemptError::Deferred(expected.clone()),
                    );
                });
                let projected = limited(|| {
                    crate::deferred_authority::reject_opaque_instruction_authority(
                        std::iter::once(&opaque),
                        &tx,
                    )
                });
                assert_eq!(
                    projected,
                    Err(ExecutionAttemptError::Deferred(expected.clone()))
                );
                // The native approval entry point retains the same read refusal in
                // its model-owned error bridge, before recording an approval outcome.
                limited(|| execute_approve(&mut tx, authority, &approval))
                    .expect_err("an unfinished native read must stop approval");
                assert_eq!(tx.execution_deferral(), Some(expected.clone()));
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
                    signed,
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
    let instructions = vec![InstructionBox::from(Log::new(
        Level::INFO,
        "reviewed".into(),
    ))];
    let hash = HashOf::new(&instructions);
    let approval = MultisigApprove::new(authority.clone(), hash);
    let key = multisig_proposal_state_key(&authority, &hash);
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
    let original = MultisigProposalState::new(
        authority.clone(),
        hash,
        instructions,
        1_000,
        60_000,
        BTreeSet::new(),
        None,
    );
    for account_mismatch in [true, false] {
        let mut altered = original.clone();
        if account_mismatch {
            altered.multisig_account_id = new_account_id(&checked_keypair());
        } else {
            altered.instructions_hash = HashOf::new(&Vec::<InstructionBox>::new());
        }
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&altered).unwrap());
        assert!(
            matches!(live_proposal_instructions_for_approval(&tx, &approval), Err(ExecutionAttemptError::Rejected(ValidationFail::QueryFailed(QueryExecutionFail::Conversion(ref message)))) if message.contains("exact account and instruction-hash key"))
        );
    }
    assert!(tx.execution_deferral().is_none());
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
                InstructionBox::from(MultisigApprove::new(account.clone(), leaf_hash))
            } else {
                InstructionBox::from(MultisigCancel::new(account.clone(), leaf_hash))
            }];
            let hash = HashOf::new(&instructions);
            let expiry = if expired { 1_500 } else { 60_000 };
            let proposal = MultisigProposalState::new(
                account.clone(),
                hash,
                instructions,
                1_000,
                expiry,
                BTreeSet::new(),
                None,
            );
            let leaf = MultisigProposalState::new(
                account.clone(),
                leaf_hash,
                leaf_instructions,
                1_000,
                expiry,
                BTreeSet::new(),
                None,
            );
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
            let approval = MultisigApprove::new(account.clone(), hash);
            let signed = TransactionBuilder::new(
                block.network_id,
                authority.clone(),
                FeePaymentIntent::authority(Vec::new(), nonzero!(100_000_000_u64).into()),
            )
            .with_instructions(vec![InstructionBox::from(approval)])
            .sign(signer.private_key());
            let call = Hash::from(signed.hash_as_entrypoint());
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
                if expired {
                    let read_budget = proposal_decode_allocation_used(|| {
                        proposal_state_attempt(&tx, &account, &hash).unwrap();
                    });
                    let limits = norito::DecodeLimits::new(
                        usize::MAX,
                        usize::MAX,
                        usize::MAX,
                        read_budget,
                        usize::MAX,
                    );
                    norito::with_decode_limits_scope(limits, || {
                        let exact = proposal_state_attempt(&tx, &account, &hash)
                            .expect("the funded retained row read completes first");
                        assert_eq!(
                            proposal_instruction_attempt(&exact.instructions[0]),
                            Err(ExecutionAttemptError::Deferred(expected.clone()))
                        );
                    });
                    norito::with_decode_limits_scope(limits, || {
                        prune_expired(&mut tx, &account, &hash, &account)
                    })
                    .expect_err(
                        "expiry cannot skip its child approval when local decoding refuses",
                    );
                } else {
                    limited(|| {
                        assert_eq!(
                            proposal_is_cancel_wrapper(&proposal),
                            Err(ExecutionAttemptError::Deferred(expected.clone()))
                        );
                        maybe_store_terminal_proposal_state(
                            &mut tx,
                            &proposal,
                            MultisigProposalTerminalStatus::Finalized,
                            &account,
                        )
                        .expect_err(
                            "an unfinished cancel-wrapper read cannot create a terminal record",
                        );
                    });
                }
                assert_eq!(tx.execution_deferral(), Some(expected.clone()));
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
                        signed.instructions(),
                    )
                })
                .expect("the signed attempt reaches past immutable root admission");
                let error = norito::with_decode_limits_scope(limits, || {
                    Executor::Initial.execute_transaction(
                        &mut tx,
                        authority,
                        signed.clone(),
                        &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                    )
                })
                .expect_err("the unchanged signed operation also preserves its local read refusal");
                assert_eq!(error, ExecutionAttemptError::Deferred(expected.clone()));
                assert!(tx.require_storage_admission().is_ok());
                assert_eq!(tx.execution_deferral(), Some(expected));
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
            tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
            Executor::Initial
                .execute_transaction(
                    &mut tx,
                    authority,
                    signed,
                    &mut crate::smartcontracts::ivm::cache::IvmCache::new(),
                )
                .unwrap();
            assert!(tx.complete_direct_callbacks(call).unwrap().is_empty());
            tx.apply();
            assert_eq!(block.committed_fragment_count(), fragments + 1);
            let tx = block.transaction_for_callback_testing();
            for proposal_hash in [hash, leaf_hash] {
                assert!(
                    tx.world
                        .smart_contract_state
                        .get(&multisig_proposal_state_key(&account, &proposal_hash))
                        .is_none()
                );
            }
            let leaf_terminal = tx
                .world
                .smart_contract_state
                .get(&multisig_proposal_terminal_state_key(&account, &leaf_hash))
                .expect("the exact target receives its terminal status");
            let terminal: MultisigProposalTerminalState =
                norito::decode_from_bytes(leaf_terminal).unwrap();
            assert_eq!(
                terminal.status,
                if expired {
                    MultisigProposalTerminalStatus::Expired
                } else {
                    MultisigProposalTerminalStatus::Canceled
                }
            );
            assert_eq!(
                tx.world
                    .smart_contract_state
                    .get(&multisig_proposal_terminal_state_key(&account, &hash))
                    .is_some(),
                expired,
                "a cancel wrapper never creates a terminal proposal record"
            );
        },
    );
}

#[test]
fn proposal_migration_validates_original_physical_key_and_body_before_writes() {
    let owner = new_account_id(&checked_keypair());
    let next = new_account_id(&checked_keypair());
    let state = runtime_state(
        World::with([], [Account::new(owner.clone()).build(&owner)], []),
        ChainId::from("multisig-proposal-migration-binding"),
        None,
    );
    let mut block = state.block(runtime_header(&state, 2_000));
    let instructions = vec![InstructionBox::from(Log::new(
        Level::INFO,
        "original approved body".into(),
    ))];
    let hash = HashOf::new(&instructions);
    let original = MultisigProposalState::new(
        owner.clone(),
        hash,
        instructions,
        1_000,
        60_000,
        BTreeSet::from([owner.clone()]),
        Some(true),
    );
    let key = multisig_proposal_state_key(&owner, &hash);
    let next_key = multisig_proposal_state_key(&next, &hash);
    let bytes = norito::to_bytes(&original).unwrap();
    {
        let mut tx = block.transaction_for_callback_testing();
        store_multisig_proposal_state(&mut tx, &original).unwrap();
        tx.apply();
    }
    for rebound in [false, true] {
        let mut tx = block.transaction_for_callback_testing();
        let mut altered = original.clone();
        if rebound {
            altered.multisig_account_id = next.clone();
        } else {
            altered.instructions = Vec::new();
        }
        tx.world
            .smart_contract_state
            .insert(key.clone(), norito::to_bytes(&altered).unwrap());
        let before: BTreeMap<_, _> = tx
            .world
            .smart_contract_state
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        assert_eq!(
            move_multisig_proposals(&mut tx, &owner, &next),
            Err(invalid_proposal_binding())
        );
        assert_eq!(
            invalidate_outstanding_proposals(&mut tx, &owner),
            Err(invalid_proposal_binding())
        );
        assert!(matches!(
            validate_persisted_proposals(&tx.world),
            Err(ExecutionAttemptError::Rejected(_))
        ));
        assert!(tx.execution_deferral().is_none());
        assert_eq!(
            tx.world
                .smart_contract_state
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
            before
        );
        drop(tx);
        let tx = block.transaction_for_callback_testing();
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&bytes));
        assert!(tx.world.smart_contract_state.get(&next_key).is_none());
    }
    {
        let mut tx = block.transaction_for_callback_testing();
        limited(|| move_multisig_proposals(&mut tx, &owner, &next))
            .expect_err("original decode refusal cannot become migration corruption");
        assert_eq!(
            tx.execution_deferral(),
            Some(ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into())
        );
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&bytes));
        assert!(tx.world.smart_contract_state.get(&next_key).is_none());
    }
    {
        let mut tx = block.transaction_for_callback_testing();
        let mut destination = original.clone();
        destination.multisig_account_id = next.clone();
        store_multisig_proposal_state(&mut tx, &destination).unwrap();
        move_multisig_proposals(&mut tx, &owner, &next)
            .expect_err("migration must not overwrite an existing destination row");
        assert_eq!(tx.world.smart_contract_state.get(&key), Some(&bytes));
        assert_eq!(
            tx.world.smart_contract_state.get(&next_key),
            Some(&norito::to_bytes(&destination).unwrap())
        );
    }
    let mut tx = block.transaction_for_callback_testing();
    move_multisig_proposals(&mut tx, &owner, &next).unwrap();
    validate_persisted_proposals(&tx.world).unwrap();
    let mut expected = original;
    expected.multisig_account_id = next;
    assert_eq!(
        decode_proposal_state_at_key(
            &next_key,
            tx.world.smart_contract_state.get(&next_key).unwrap()
        )
        .unwrap(),
        expected
    );
    assert!(tx.world.smart_contract_state.get(&key).is_none());
    tx.apply();
}
