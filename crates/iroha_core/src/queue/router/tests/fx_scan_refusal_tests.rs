//! FX classification must preserve original nested multisig decode deferrals.

use super::*;

#[test]
fn multisig_fx_projection_rejects_changed_hash_and_conflicting_nonce_reuse() {
    let (account, _) = gen_account_in("fx_occurrence");
    let network = super::super::super::queue_test_network_id();
    let nonce =
        iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x73; 32]).unwrap();
    let id = iroha_executor_data_model::isi::multisig::MultisigProposalId::derive(
        &network, &account, &nonce,
    );
    let inner = Vec::<InstructionBox>::new();
    let hash = HashOf::new(&inner);
    let propose: InstructionBox = MultisigPropose::new(account.clone(), nonce, inner, None).into();
    let state = blank_state();
    let view = state.view();
    let mut overlay = FxCorridorRoutingOverlay::for_network(Some(&network));
    observe_top_level_instruction_fx_effects(&mut overlay, &*propose, 0, &[], view.world())
        .unwrap();
    let original = overlay.executed_multisig_proposals.clone();
    let changed_hash = HashOf::new(&vec![propose.clone()]);
    let changed: InstructionBox = MultisigApprove::new(account.clone(), id, changed_hash).into();
    assert!(matches!(
        observe_top_level_instruction_fx_effects(&mut overlay, &*changed, 1, &[], view.world()),
        Err(RoutingResolveError::InvalidMultisigProposal { .. })
    ));
    assert_eq!(overlay.executed_multisig_proposals, original);
    let duplicate: InstructionBox =
        MultisigPropose::new(account.clone(), nonce, vec![propose], None).into();
    assert!(matches!(
        observe_top_level_instruction_fx_effects(&mut overlay, &*duplicate, 1, &[], view.world()),
        Err(RoutingResolveError::InvalidMultisigProposal { .. })
    ));
    assert_eq!(overlay.executed_multisig_proposals, original);
    let exact: InstructionBox = MultisigApprove::new(account, id, hash).into();
    observe_top_level_instruction_fx_effects(&mut overlay, &*exact, 1, &[], view.world()).unwrap();
    assert_eq!(overlay.executed_multisig_proposals, original);
}

#[test]
fn fx_scan_keeps_nested_custom_decode_refusal_through_transaction_and_retries() {
    let (authority, signer) = gen_account_in("fx_scan_refusal");
    let custom = CustomInstruction::new(iroha_primitives::json::Json::new(
        MultisigInstructionBox::Propose(MultisigPropose::new(
            authority.clone(),
            iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x71; 32])
                .unwrap(),
            vec![],
            None,
        )),
    ));
    let nested: InstructionBox = MultisigPropose::new(
        authority.clone(),
        iroha_executor_data_model::isi::multisig::MultisigProposalNonce::new([0x72; 32]).unwrap(),
        vec![custom.clone().into()],
        None,
    )
    .into();
    let executable = Executable::Instructions(vec![nested.clone()].into());
    let tx = sample_transaction(&authority, signer.private_key(), vec![nested.clone()]);
    let check = |result: Result<bool, RoutingResolveError>| {
        assert!(
            matches!(result, Err(RoutingResolveError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
            "unfinished FX classification became a routing verdict: {result:?}"
        );
    };
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
        || {
            check(instruction_contains_fx_corridor_settlement(&custom));
            check(instruction_contains_fx_corridor_settlement(&*nested));
            check(executable_contains_fx_corridor_settlement(&executable));
            check(transaction_contains_fx_corridor_settlement(&tx));
        },
    );
    assert!(!instruction_contains_fx_corridor_settlement(&custom).unwrap());
    assert!(!instruction_contains_fx_corridor_settlement(&*nested).unwrap());
    assert!(!executable_contains_fx_corridor_settlement(&executable).unwrap());
    assert!(!transaction_contains_fx_corridor_settlement(&tx).unwrap());
}
