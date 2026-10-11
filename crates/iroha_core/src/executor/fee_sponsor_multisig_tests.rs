//! Component tests for exact enrolled-controller rule admission and unchanged budgets.
use super::*;
use crate::{
    executor::tests::sponsored_pipeline_fee_fixture,
    smartcontracts::isi::multisig::multisig_account_state_key,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::prelude::Level;
use iroha_data_model::{
    IntoKeyValue, Registrable,
    account::{MultisigMember, MultisigPolicy},
    isi::Log,
    nexus::{FeeSponsorEnrollment, FeeSponsorRule},
    smart_contract::{ContractAlias, multisig_call::build_multisig_contract_call},
};
use iroha_executor_data_model::isi::multisig::{
    MultisigAccountState, MultisigApprove, MultisigPropose, MultisigSpec,
};
use std::num::{NonZeroU16, NonZeroU64};

struct Fixture {
    beneficiary: AccountId,
    program: FeeSponsorProgramId,
    revision: FeeSponsorProgramRevision,
    selector: FeeSponsorContractSelector,
    alias: ContractAlias,
    payload: TransactionPayload,
}
fn with_fixture(test: impl FnOnce(&mut StateTransaction<'_, '_>, &Fixture)) {
    let (state, transaction, beneficiary, _, _, _, program, _) =
        sponsored_pipeline_fee_fixture(None);
    let mut block = state.block(BlockHeader::new(
        NonZeroU64::new(10).unwrap(),
        None,
        None,
        500,
        0,
    ));
    let mut tx = block.transaction_for_callback_testing();
    let selector = FeeSponsorContractSelector {
        contract_address: "irohac1qyqqqqqqqqqqqqputuv64zhf0a0a4hhlqdj2lhnwuzq4xjq3qexfh"
            .parse()
            .unwrap(),
        code_hash: Hash::new(b"exact company contract"),
        entrypoints: vec!["request_issuance".into()],
    };
    let alias: ContractAlias = "dpn::universal".parse().unwrap();
    tx.world
        .contract_aliases
        .insert(alias.clone(), selector.contract_address.clone());
    tx.world
        .contract_instances
        .insert(selector.contract_address.clone(), selector.code_hash);
    let mut revision = tx
        .world
        .fee_sponsor_program_revisions
        .get(&FeeSponsorProgramRevisionKey::new(program.clone(), 1))
        .unwrap()
        .clone();
    revision.rules = vec![FeeSponsorRule {
        id: "company_calls".parse().unwrap(),
        effect: FeeSponsorRuleEffect::Allow,
        selectors: vec![FeeSponsorRuleSelector::EnrolledMultisigContractCall(
            selector.clone(),
        )],
    }];
    tx.world.fee_sponsor_program_revisions.insert(
        FeeSponsorProgramRevisionKey::new(program.clone(), 1),
        revision.clone(),
    );
    let mut payload = transaction.payload().clone();
    payload.creation_time_ms = 100;
    let fixture = Fixture {
        beneficiary,
        program,
        revision,
        selector,
        alias,
        payload,
    };
    test(&mut tx, &fixture);
}
fn enroll(tx: &mut StateTransaction<'_, '_>, program: &FeeSponsorProgramId, account: &AccountId) {
    let key = FeeSponsorEnrollmentKey {
        program_id: program.clone(),
        beneficiary: account.clone(),
    };
    tx.world.fee_sponsor_enrollments.insert(
        key.clone(),
        FeeSponsorEnrollment {
            key,
            enrolled_at_height: 1,
        },
    );
}
fn company(tx: &mut StateTransaction<'_, '_>, f: &Fixture, seed: u8) -> AccountId {
    let other = KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519);
    let other_account = AccountId::new(other.public_key().clone());
    let policy = MultisigPolicy::new(
        1,
        vec![
            MultisigMember::new(
                f.beneficiary
                    .controller()
                    .single_signatory()
                    .unwrap()
                    .clone(),
                1,
            )
            .unwrap(),
            MultisigMember::new(other.public_key().clone(), 1).unwrap(),
        ],
    )
    .unwrap();
    let target = AccountId::new_multisig(policy);
    let spec = MultisigSpec::new(
        BTreeMap::from([(f.beneficiary.clone(), 1), (other_account.clone(), 1)]),
        NonZeroU16::new(1).unwrap(),
        NonZeroU64::new(1_000).unwrap(),
    );
    tx.world.accounts.insert(
        other_account.clone(),
        Account::new(other_account.clone())
            .build(&f.beneficiary)
            .into_key_value()
            .1,
    );
    let native = MultisigAccountState::new(target.clone(), None, spec);
    tx.world.accounts.insert(
        target.clone(),
        Account::new(target.clone())
            .build(&f.beneficiary)
            .into_key_value()
            .1,
    );
    // Component fixture seeds the exact canonical native row, not metadata or alias authority.
    tx.world.smart_contract_state.insert(
        multisig_account_state_key(&target),
        norito::to_bytes(&native).unwrap(),
    );
    target
}
fn inner(f: &Fixture, target: &AccountId) -> Vec<InstructionBox> {
    build_multisig_contract_call(
        target,
        &f.selector.contract_address,
        &f.alias,
        &f.selector.entrypoints[0],
        &Json::new(norito::json!({"document":"test"})),
        None,
        &f.selector.code_hash,
        NonZeroU64::new(100).unwrap(),
    )
    .unwrap()
    .instructions
}
fn propose_payload(
    f: &Fixture,
    target: &AccountId,
    body: Vec<InstructionBox>,
    approve: bool,
) -> TransactionPayload {
    let hash = HashOf::try_new(&body).unwrap();
    let mut items = vec![MultisigPropose::new(target.clone(), body, None).into()];
    if approve {
        items.push(MultisigApprove::new(target.clone(), hash).into());
    }
    let mut payload = f.payload.clone();
    payload.instructions = Executable::Instructions(items.into());
    payload
}
fn admitted(
    tx: &StateTransaction<'_, '_>,
    f: &Fixture,
    payload: &TransactionPayload,
) -> Result<ResolvedSponsorProgram, Attempt<NexusFeeAdmissionError>> {
    resolve_fee_sponsor_program(
        &tx.world,
        &tx.nexus,
        &f.program,
        1,
        &f.beneficiary,
        payload,
        Some(DataSpaceId::UNIVERSAL),
        10,
        RuleContext::admission(500),
    )
}
fn rejection(
    result: Result<ResolvedSponsorProgram, Attempt<NexusFeeAdmissionError>>,
) -> FeeRejectionCode {
    match result {
        Err(Attempt::Rejected(error)) => error.code(),
        other => panic!("expected completed rejection: {other:?}"),
    }
}
#[test]
fn enrolled_multisig_future_third_controller_needs_enrollment_not_revision_rewrite() {
    with_fixture(|tx, f| {
        let before = norito::to_bytes(&f.revision).unwrap();
        for seed in [81, 82, 83] {
            let target = company(tx, f, seed);
            let payload = propose_payload(f, &target, inner(f, &target), true);
            assert_eq!(
                rejection(admitted(tx, f, &payload)),
                FeeRejectionCode::OperationNotAllowed
            );
            enroll(tx, &f.program, &target);
            assert_eq!(admitted(tx, f, &payload).unwrap().revision.revision, 1);
        }
        let retained = tx
            .world
            .fee_sponsor_program_revisions
            .get(&FeeSponsorProgramRevisionKey::new(f.program.clone(), 1))
            .unwrap();
        assert_eq!(norito::to_bytes(retained).unwrap(), before);
    });
}
#[test]
fn enrolled_multisig_requires_both_exact_enrollments_and_canonical_registration() {
    with_fixture(|tx, f| {
        let target = company(tx, f, 84);
        let payload = propose_payload(f, &target, inner(f, &target), true);
        let other = FeeSponsorProgramId::new(f.program.sponsor.clone(), "other".parse().unwrap());
        enroll(tx, &other, &target);
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        enroll(tx, &f.program, &target);
        assert!(admitted(tx, f, &payload).is_ok());
        let key = FeeSponsorEnrollmentKey {
            program_id: f.program.clone(),
            beneficiary: f.beneficiary.clone(),
        };
        let row = tx
            .world
            .fee_sponsor_enrollments
            .remove(key.clone())
            .unwrap();
        // Route-default eligibility must not bypass this selector's explicit enrollment.
        let revision_key = FeeSponsorProgramRevisionKey::new(f.program.clone(), 1);
        tx.world
            .fee_sponsor_program_revisions
            .get_mut(&revision_key)
            .unwrap()
            .eligibility = FeeSponsorEligibility::EnrolledOrRouteDefault;
        tx.nexus
            .dataspace_fee_sponsor_program_ids
            .insert(DataSpaceId::UNIVERSAL, f.program.clone());
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        tx.world.fee_sponsor_enrollments.insert(key, row);
        tx.world
            .smart_contract_state
            .remove(multisig_account_state_key(&target));
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
    });
}
#[test]
fn enrolled_multisig_binds_current_code_alias_entrypoint_and_entire_inner_vector() {
    with_fixture(|tx, f| {
        let target = company(tx, f, 85);
        enroll(tx, &f.program, &target);
        let body = inner(f, &target);
        let payload = propose_payload(f, &target, body.clone(), true);
        assert!(admitted(tx, f, &payload).is_ok());
        let mut extra = body.clone();
        extra.push(Log::new(Level::INFO, "extra".into()).into());
        assert_eq!(
            rejection(admitted(tx, f, &propose_payload(f, &target, extra, true))),
            FeeRejectionCode::OperationNotAllowed
        );
        let nested = vec![MultisigPropose::new(target.clone(), body, None).into()];
        assert_eq!(
            rejection(admitted(tx, f, &propose_payload(f, &target, nested, false))),
            FeeRejectionCode::OperationNotAllowed
        );
        for (entrypoint, code) in [
            ("settle_dpn", f.selector.code_hash),
            ("request_issuance", Hash::new(b"wrong code")),
        ] {
            let body = build_multisig_contract_call(
                &target,
                &f.selector.contract_address,
                &f.alias,
                entrypoint,
                &Json::new(norito::json!({})),
                None,
                &code,
                NonZeroU64::new(100).unwrap(),
            )
            .unwrap()
            .instructions;
            assert_eq!(
                rejection(admitted(tx, f, &propose_payload(f, &target, body, true))),
                FeeRejectionCode::OperationNotAllowed
            );
        }
        tx.world.contract_instances.insert(
            f.selector.contract_address.clone(),
            Hash::new(b"rebound code"),
        );
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        tx.world
            .contract_instances
            .insert(f.selector.contract_address.clone(), f.selector.code_hash);
        tx.world.contract_aliases.remove(f.alias.clone());
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
    });
}
#[test]
fn enrolled_multisig_inline_approval_requires_earlier_exact_proposal_and_rejects_extras() {
    with_fixture(|tx, f| {
        let target = company(tx, f, 86);
        enroll(tx, &f.program, &target);
        let mut payload = propose_payload(f, &target, inner(f, &target), true);
        assert!(admitted(tx, f, &payload).is_ok());
        let Executable::Instructions(items) = &payload.instructions else {
            unreachable!()
        };
        let original = items.to_vec();
        payload.instructions =
            Executable::Instructions(vec![original[1].clone(), original[0].clone()].into());
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        payload.instructions = Executable::Instructions(
            vec![
                original[0].clone(),
                original[0].clone(),
                original[1].clone(),
            ]
            .into(),
        );
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        let mut mixed = original.clone();
        mixed.push(Log::new(Level::INFO, "unrelated native work".into()).into());
        payload.instructions = Executable::Instructions(mixed.into());
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        payload.instructions = Executable::Instructions(original.into());
        payload.creation_time_ms += 1;
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
    });
}
#[test]
fn enrolled_multisig_deny_wins_and_existing_budget_caps_still_apply() {
    with_fixture(|tx, f| {
        let target = company(tx, f, 87);
        enroll(tx, &f.program, &target);
        let payload = propose_payload(f, &target, inner(f, &target), true);
        let resolved = admitted(tx, f, &payload).unwrap();
        let asset = resolved.revision.asset_budgets[0]
            .asset_definition_id
            .clone();
        let charge = FeeChargeBound {
            kind: FeeChargeKind::PipelineGas,
            asset_definition_id: asset,
            max_bound: Quantity::from(11u32),
        };
        let cap =
            evaluate_fee_sponsor_capacity(&tx.world, &resolved, &f.beneficiary, 10, &[charge]);
        assert!(
            matches!(cap, Err(error) if error.code() == FeeRejectionCode::ProgramTransactionLimitExceeded)
        );
        let key = FeeSponsorProgramRevisionKey::new(f.program.clone(), 1);
        tx.world
            .fee_sponsor_program_revisions
            .get_mut(&key)
            .unwrap()
            .rules
            .push(FeeSponsorRule {
                id: "deny_same_call".parse().unwrap(),
                effect: FeeSponsorRuleEffect::Deny,
                selectors: vec![FeeSponsorRuleSelector::EnrolledMultisigContractCall(
                    f.selector.clone(),
                )],
            });
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationDenied
        );
    });
}
#[test]
fn enrolled_multisig_local_refusal_is_deferred_and_settlement_requires_actual_entrypoint() {
    with_fixture(|tx, f| {
        let target = company(tx, f, 88);
        enroll(tx, &f.program, &target);
        let payload = propose_payload(f, &target, inner(f, &target), true);
        let deferred = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || admitted(tx, f, &payload),
        );
        assert!(matches!(deferred, Err(Attempt::Deferred(_))));
        assert!(
            !selector_matches(
                &tx.world,
                &f.program,
                &f.beneficiary,
                &f.selector,
                &payload,
                1,
                RuleContext::settlement(500, None, 10)
            )
            .unwrap()
        );
    });
}

#[test]
fn enrolled_multisig_standalone_approval_uses_native_pending_and_denies_expired_or_canceled() {
    use crate::smartcontracts::isi::multisig::execute_multisig_instruction;
    use iroha_executor_data_model::isi::multisig::MultisigCancel;
    with_fixture(|tx, f| {
        let target = company(tx, f, 89);
        enroll(tx, &f.program, &target);
        let body = inner(f, &target);
        let hash = HashOf::try_new(&body).unwrap();
        let original = propose_payload(f, &target, body.clone(), true);
        let mut approve = f.payload.clone();
        approve.instructions = Executable::Instructions(
            vec![MultisigApprove::new(target.clone(), hash).into()].into(),
        );
        assert_eq!(
            rejection(admitted(tx, f, &approve)),
            FeeRejectionCode::OperationNotAllowed
        );
        execute_multisig_instruction(
            tx,
            &f.beneficiary,
            MultisigPropose::new(target.clone(), body, None).into(),
        )
        .unwrap();
        assert!(admitted(tx, f, &approve).is_ok());
        assert_eq!(
            rejection(admitted(tx, f, &original)),
            FeeRejectionCode::OperationNotAllowed
        );
        assert!(
            !selector_matches(
                &tx.world,
                &f.program,
                &f.beneficiary,
                &f.selector,
                &approve,
                0,
                RuleContext::admission(1_500)
            )
            .unwrap()
        );
        tx.tx_call_hash = Some(Hash::new(b"component native cancellation"));
        execute_multisig_instruction(
            tx,
            &target,
            MultisigCancel::new(target.clone(), hash).into(),
        )
        .unwrap();
        assert_eq!(
            rejection(admitted(tx, f, &approve)),
            FeeRejectionCode::OperationNotAllowed
        );
        assert_eq!(
            rejection(admitted(tx, f, &original)),
            FeeRejectionCode::OperationNotAllowed
        );
        assert!(
            !selector_matches(
                &tx.world,
                &f.program,
                &f.beneficiary,
                &f.selector,
                &approve,
                0,
                RuleContext::settlement(
                    500,
                    Some(*Hash::new(b"component native cancellation").as_ref()),
                    10
                )
            )
            .unwrap()
        );
    });
}

#[test]
fn enrolled_multisig_classifier_never_turns_local_refusal_into_native_allow() {
    use iroha_data_model::nexus::FeeSponsorNativeInstructionSelector;
    with_fixture(|tx, f| {
        let target = company(tx, f, 90);
        let payload = propose_payload(f, &target, inner(f, &target), true);
        let key = FeeSponsorProgramRevisionKey::new(f.program.clone(), 1);
        tx.world
            .fee_sponsor_program_revisions
            .get_mut(&key)
            .unwrap()
            .rules[0]
            .selectors = vec![FeeSponsorRuleSelector::NativeInstruction(
            FeeSponsorNativeInstructionSelector {
                wire_id: "iroha.custom".into(),
                asset_definition_id: None,
            },
        )];
        assert_eq!(
            rejection(admitted(tx, f, &payload)),
            FeeRejectionCode::OperationNotAllowed
        );
        let deferred = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
            || admitted(tx, f, &payload),
        );
        assert!(matches!(deferred, Err(Attempt::Deferred(_))));
    });
}

#[test]
fn enrolled_multisig_standalone_settlement_requires_exact_successful_tx_and_block() {
    use crate::smartcontracts::isi::multisig::install_executed_fee_proposal_fixture;
    use iroha_executor_data_model::isi::multisig::{
        MultisigProposalTerminalState, MultisigProposalTerminalStatus, MultisigProposalValue,
    };
    with_fixture(|tx, f| {
        let target = company(tx, f, 91);
        enroll(tx, &f.program, &target);
        let body = inner(f, &target);
        let hash = HashOf::try_new(&body).unwrap();
        let mut approve = f.payload.clone();
        approve.instructions = Executable::Instructions(
            vec![MultisigApprove::new(target.clone(), hash).into()].into(),
        );
        let terminal = MultisigProposalTerminalState::new(
            target,
            hash,
            MultisigProposalValue::new(
                body,
                100,
                1_100,
                BTreeSet::from([f.beneficiary.clone()]),
                None,
            ),
            MultisigProposalTerminalStatus::Finalized,
            500,
        );
        let entrypoint = *Hash::new(b"component successful fee execution").as_ref();
        // These are canonical seeded component read records, not a claim of contract execution/finality.
        install_executed_fee_proposal_fixture(tx, &terminal, entrypoint).unwrap();
        let matches = |context| {
            selector_matches(
                &tx.world,
                &f.program,
                &f.beneficiary,
                &f.selector,
                &approve,
                0,
                context,
            )
        };
        assert!(matches(RuleContext::settlement(500, Some(entrypoint), 10)).unwrap());
        assert!(!matches(RuleContext::admission(500)).unwrap());
        assert!(!matches(RuleContext::settlement(500, Some([19; 32]), 10)).unwrap());
        assert!(matches!(
            matches(RuleContext::settlement(500, Some(entrypoint), 11)),
            Err(Attempt::Rejected(_))
        ));
    });
}
