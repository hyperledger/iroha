//! Cancellation regression tests for multisig proposal quorum and pruning.
use super::*;
#[test]
fn multisig_cancel_requires_quorum_and_prunes_target_proposal() {
    let state = runtime_state(
        World::new(),
        ChainId::from("multisig-cancel-prunes-target"),
        None,
    );
    let block_header = runtime_header(&state, 0);
    let mut block = state.block(block_header);
    let mut state_transaction = block.transaction_for_callback_testing();
    let network_id = state_transaction.network_id;
    let domain_id: iroha_model_base::domain::DomainId =
        DomainId::try_new("cancel", "universal").unwrap();
    let owner_key = checked_keypair();
    let owner_id = new_account_id(&owner_key);
    register_domain_with_name_lease(
        &mut state_transaction,
        &owner_id,
        &domain_id,
        "domain registration",
    );
    register_account_in_domain(
        &mut state_transaction,
        &owner_id,
        &domain_id,
        &owner_id,
        "register owner",
    );
    let signer1_key = checked_keypair();
    let signer1_id = new_account_id(&signer1_key);
    register_account_in_domain(
        &mut state_transaction,
        &owner_id,
        &domain_id,
        &signer1_id,
        "register signer1",
    );
    let signer2_key = checked_keypair();
    let signer2_id = new_account_id(&signer2_key);
    register_account_in_domain(
        &mut state_transaction,
        &owner_id,
        &domain_id,
        &signer2_id,
        "register signer2",
    );
    let spec = MultisigSpec {
        signatories: BTreeMap::from([(signer1_id.clone(), 1), (signer2_id.clone(), 1)]),
        quorum: NonZeroU16::new(2).unwrap(),
        transaction_ttl_ms: NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
    };
    let multisig_id = register_multisig_account(
        &mut state_transaction,
        &owner_id,
        &domain_id,
        &spec,
        "register multisig account",
    );
    let target_instructions: Vec<InstructionBox> = Vec::new();
    let target_hash = HashOf::new(&target_instructions);
    let target_proposal = MultisigPropose::new(
        multisig_id.clone(),
        test_nonce(&HashOf::new(&target_instructions.clone())),
        target_instructions.clone(),
        None,
    );
    Executor::Initial
        .execute_instruction(
            &mut state_transaction,
            &signer1_id,
            InstructionBox::from(target_proposal),
        )
        .expect("create target proposal");
    let cancel = MultisigCancel::new(
        multisig_id.clone(),
        test_id(&network_id, &multisig_id.clone(), &target_hash),
        target_hash,
    );
    let direct_err = Executor::Initial
        .execute_instruction(
            &mut state_transaction,
            &signer1_id,
            InstructionBox::from(cancel.clone()),
        )
        .expect_err("direct cancel by signer must be rejected");
    match direct_err {
        ValidationFail::NotPermitted(message) => {
            assert!(
                message.contains("must execute as the multisig account"),
                "unexpected cancel rejection: {message}"
            );
        }
        other => panic!("unexpected direct cancel error: {other:?}"),
    }
    assert!(
        proposal_value(
            &state_transaction,
            &multisig_id,
            &test_id(&network_id, &multisig_id, &target_hash)
        )
        .is_ok(),
        "target proposal should remain after rejected direct cancel"
    );
    let cancel_instructions = vec![InstructionBox::from(cancel)];
    let cancel_hash = HashOf::new(&cancel_instructions);
    let cancel_proposal = MultisigPropose::new(
        multisig_id.clone(),
        test_nonce(&HashOf::new(&cancel_instructions)),
        cancel_instructions,
        None,
    );
    Executor::Initial
        .execute_instruction(
            &mut state_transaction,
            &signer1_id,
            InstructionBox::from(cancel_proposal),
        )
        .expect("create cancel proposal");
    Executor::Initial
        .execute_instruction(
            &mut state_transaction,
            &signer2_id,
            InstructionBox::from(MultisigApprove::new(
                multisig_id.clone(),
                test_id(&network_id, &multisig_id.clone(), &cancel_hash),
                cancel_hash,
            )),
        )
        .expect("approve cancel proposal");
    assert!(
        proposal_value(
            &state_transaction,
            &multisig_id,
            &test_id(&network_id, &multisig_id, &target_hash)
        )
        .is_err(),
        "target proposal should be pruned once cancel reaches quorum"
    );
    assert!(
        proposal_value(
            &state_transaction,
            &multisig_id,
            &test_id(&network_id, &multisig_id, &cancel_hash)
        )
        .is_err(),
        "cancel proposal should also be pruned after execution"
    );
}
