//! Actual penalty and following fee refusal preserve their original disposable block owner.
//! Registry/ballot preconditions qualify these consumers, not live policy enactment.

use super::*;
use crate::{
    state::output_capacity::producer::network::{fee_decode_test_scope, penalty_decode_test_scope},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::account::AccountId;
use mv::storage::StorageReadOnly;

struct PenaltyFixture {
    chain: CertifiedTestChain,
    asset: AssetDefinitionId,
    escrow: AccountId,
    receiver: AccountId,
    referendum: String,
}

fn fixture_with_registered_policy() -> PenaltyFixture {
    let signer = KeyPair::from_seed(vec![55; 32], Algorithm::Ed25519);
    let deployer = AccountId::new(signer.public_key().clone());
    let component = state(65_536);
    let asset = AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap();
    let (escrow, _) = gen_account_in("penalty-refusal");
    let (receiver, _) = gen_account_in("penalty-refusal");
    let referendum = "penalty-refusal".to_owned();
    let mut gov = component.gov.clone();
    gov.plain_voting_enabled = true;
    gov.voting_asset_id = asset.clone();
    gov.min_bond_amount = Quantity::from(10_u32);
    gov.citizenship_bond_amount = Quantity::zero();
    gov.bond_escrow_account = escrow.clone();
    gov.slash_receiver_account = receiver.clone();
    gov.slash_double_vote_bps = 2_000;
    gov.conviction_step_blocks = 1;
    let mut nexus = component.nexus_snapshot();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    nexus.fees.fee_asset_id = asset.to_string();
    nexus.fees.fee_sink_account_id = BOB_ID.to_string();
    let mut config = TestChainConfig::new(
        crate::validation_fee::tests::validation_fee_payout_world(&deployer),
        1_000,
    );
    config.governance = Some(gov);
    config.nexus = Some(nexus);
    config.pipeline = component.pipeline;
    let parameters = component.world.parameters.view().block();
    config.genesis_parameters.extend([
        Parameter::Block(BlockParameter::ExecutionOutput(
            parameters.execution_output(),
        )),
        Parameter::Block(BlockParameter::MaxTimeTriggerInvocations(
            parameters.max_time_trigger_invocations(),
        )),
    ]);
    for account in [&*ALICE_ID, &*BOB_ID, &escrow, &receiver] {
        if config.world.accounts.view().get(account).is_none() {
            config
                .genesis_instructions
                .push(Register::account(Account::new(account.clone())).into());
        }
    }
    for (owner, amount) in [(&*ALICE_ID, 1_000_u32), (&deployer, 100_u32)] {
        config.genesis_instructions.push(
            Mint::asset_quantity(
                Quantity::from(amount),
                AssetId::of(asset.clone(), owner.clone()),
            )
            .into(),
        );
    }
    let (mut chain, binding) =
        crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture_with_config(config);
    assert_eq!(binding.xor_asset_id, asset);
    let registry = crate::validation_fee::tests::policy_registry(&[], &[binding.clone()]);
    registry
        .validate()
        .expect("the actual retained certificate validates");
    let enactment_height = registry.payout_policies.entries[0]
        .parliament_authorization
        .enacted_at_height;
    assert!(
        (chain.height()..=64).contains(&enactment_height),
        "bounded genuine enactment predecessor"
    );
    while chain.height() < enactment_height {
        let transaction = crate::validation_fee::tests::sign_paid_fixture(
            &chain,
            &ALICE_KEYPAIR,
            [Log::new(Level::INFO, "paid penalty-refusal predecessor".to_owned()).into()],
            (chain.height() + 1) * 1_000,
        );
        assert_eq!(chain.commit(vec![transaction]), vec![true]);
    }
    let state = chain.state();
    {
        // Retain the real signed root/deployments/prefix. These original component
        // preconditions reuse the reducer-produced certificate at its actual height;
        // they do not claim to execute live policy enactment or rewrite a certificate.
        let (mut setup, _recording) = output_fixture_setup(state);
        let mut transaction = setup.transaction_for_callback_testing();
        crate::validation_fee::tests::install_policy_registry_fixture(&registry, &mut transaction);
        assert_eq!(
            crate::validation_fee::retained_payout_custody_binding(&transaction.world).unwrap(),
            Some(binding)
        );
        transaction.world.governance_referenda_mut().insert(
            referendum.clone(),
            GovernanceReferendumRecord {
                h_start: 1,
                h_end: enactment_height + 50,
                status: GovernanceReferendumStatus::Open,
                mode: GovernanceReferendumMode::Plain,
                plain_context: crate::query::standalone_plain_test_fixture::context(
                    &transaction.gov,
                    0,
                ),
                plain_result:
                    iroha_data_model::governance::conviction::PlainVotingResultV1::Pending,
            },
        );
        let permission: Permission = CanSubmitGovernanceBallot {
            referendum_id: referendum.clone(),
        }
        .into();
        Grant::account_permission(permission, ALICE_ID.clone())
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        transaction.apply();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    PenaltyFixture {
        chain,
        asset,
        escrow,
        receiver,
        referendum,
    }
}

fn ballot_source(fixture: &PenaltyFixture) -> (SignedBlock, u64, u64) {
    let state = fixture.chain.state();
    let mut inputs = Vec::new();
    let mut gas = [0_u64; 2];
    for (index, (direction, amount)) in [(0, 20_u32), (1, 30_u32)].into_iter().enumerate() {
        let body = vec![
            CastPlainBallot {
                referendum_id: fixture.referendum.clone(),
                direction,
                owner: ALICE_ID.clone(),
                amount: Quantity::from(amount),
                duration_blocks: 200,
            }
            .into(),
        ];
        gas[index] = crate::gas::meter_instructions(&body, &state.zk_snapshot().gas);
        inputs.push(input(
            state,
            body,
            FeePaymentIntent::authority(
                vec![FeeChargeLimit::new(
                    FeeChargeKind::Nexus,
                    fixture.asset.clone(),
                    Quantity::from(1_u32),
                )],
                None,
            ),
            false,
        ));
    }
    let context = iroha_data_model::block::BlockExecutionContextBundle::new(
        inputs
            .iter()
            .map(|input| {
                iroha_data_model::block::ExternalExecutionContext::new(
                    input.hash(),
                    iroha_model_base::topology::LaneId::SINGLE,
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                )
            })
            .collect(),
    );
    let view = state.view();
    let mut builder = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(fixture.chain.height() + 1).unwrap(),
        view.latest_block_hash(),
        None,
        output_fixture_parent_time(state) + 2,
        0,
    ));
    for input in inputs {
        let TransactionEntrypoint::External(signed) = input else {
            panic!("signed original ballot")
        };
        builder.push_transaction(signed);
    }
    builder.set_execution_context(Some(context));
    (
        builder.build_with_signature(0, ALICE_KEYPAIR.private_key()),
        gas[0],
        gas[1],
    )
}

fn asset_balance(
    world: &impl WorldReadOnly,
    fixture: &PenaltyFixture,
    owner: &AccountId,
) -> Quantity {
    world
        .assets()
        .get(&AssetId::of(fixture.asset.clone(), owner.clone()))
        .map_or_else(Quantity::zero, |value| value.0.clone())
}

fn assert_slash(world: &impl WorldReadOnly, fixture: &PenaltyFixture, slashed: bool, height: u64) {
    let lock = world
        .governance_locks()
        .get(&fixture.referendum)
        .unwrap()
        .locks
        .get(&*ALICE_ID)
        .unwrap();
    assert_eq!(lock.direction, 0);
    assert_eq!(
        lock.amount,
        Quantity::from(if slashed { 16_u32 } else { 20 })
    );
    assert_eq!(
        lock.slashed,
        Quantity::from(if slashed { 4_u32 } else { 0 })
    );
    let ledger = world.governance_slashes().get(&fixture.referendum);
    if slashed {
        let slash = ledger.unwrap().slashes.get(&*ALICE_ID).unwrap();
        assert_eq!(slash.total_slashed, Quantity::from(4_u32));
        assert_eq!(slash.total_restituted, Quantity::zero());
        assert_eq!(slash.last_reason, GovernanceSlashReason::DoubleVote);
        assert_eq!(slash.last_height, height);
    } else {
        assert!(
            ledger.is_none(),
            "a refused original penalty cannot publish its slash ledger"
        );
    }
    assert_eq!(
        asset_balance(world, fixture, &fixture.escrow),
        Quantity::from(if slashed { 16_u32 } else { 20 })
    );
    assert_eq!(
        asset_balance(world, fixture, &fixture.receiver),
        Quantity::from(if slashed { 4_u32 } else { 0 })
    );
    assert_eq!(asset_balance(world, fixture, &BOB_ID), Quantity::zero());
}

fn assert_no_penalty(world: &impl WorldReadOnly, fixture: &PenaltyFixture) {
    assert!(world.governance_locks().get(&fixture.referendum).is_none());
    assert!(
        world
            .governance_slashes()
            .get(&fixture.referendum)
            .is_none()
    );
    assert_eq!(
        asset_balance(world, fixture, &fixture.escrow),
        Quantity::zero()
    );
    assert_eq!(
        asset_balance(world, fixture, &fixture.receiver),
        Quantity::zero()
    );
}

fn actual_penalty_refusal_and_fresh_retry(fee_phase: bool) {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let fixture = fixture_with_registered_policy();
    let state = fixture.chain.state();
    let (source, first_gas, second_gas) = ballot_source(&fixture);
    assert!(first_gas > 0 && second_gas > 0);
    let hash = source.hash();
    let (payer_before, supply_before) = {
        let view = state.view();
        assert_no_penalty(view.world(), &fixture);
        (
            asset_balance(view.world(), &fixture, &ALICE_ID),
            view.world()
                .asset_definition(&fixture.asset)
                .unwrap()
                .total_quantity()
                .clone(),
        )
    };
    {
        let (mut block, _recording) = recorded_network_block(state, &source);
        let fragments = block.committed_fragment_count();
        let penalty_probe =
            (!fee_phase).then(penalty_decode_test_scope::refuse_actual_penalty_decode);
        let fee_probe = fee_phase.then(fee_decode_test_scope::refuse_actual_fee_decode);
        let result = execute(&mut block, &source);
        let (calls, original) = if let Some(probe) = &penalty_probe {
            probe.observe()
        } else {
            fee_probe.as_ref().unwrap().observe()
        };
        assert_eq!(
            calls, 1,
            "only the original rejection tail reaches its scoped decoder"
        );
        let original =
            original.expect("actual registered-policy/fee JSON refusal stays transaction-local");
        assert_eq!(
            original.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(
            original.allocation_refusal().is_none(),
            "cumulative scope refusal has no physical release owner"
        );
        if fee_phase {
            assert_eq!(
                result,
                Err(ExecutionOutputAttemptError::Deferred(original)),
                "fee refusal after an actual slash must preserve the original deferral"
            );
        } else {
            assert_eq!(
                result,
                Err(ExecutionOutputAttemptError::Deferred(original)),
                "the original penalty-tail deferral must not become a completed Network rejection"
            );
        }
        assert!(block.retained_execution_outputs_for_test().is_err());
        assert!(matches!(
            block.execution_output_plan,
            Some(ExecutionOutputPlanState::Poisoned)
        ));
        assert_eq!(source.hash(), hash);
        assert_eq!(
            block.committed_fragment_count(),
            fragments + 1 + usize::from(fee_phase)
        );
        let gas = first_gas + if fee_phase { second_gas } else { 0 };
        assert_eq!(
            block.gas_used_in_block, gas,
            "penalty refusal precedes rejected-root gas accounting"
        );
        assert_eq!(
            (
                block.zk_confidential_ops_in_block,
                block.zk_verify_calls_in_block,
                block.zk_proof_bytes_in_block,
                block.confidential_gas_used_in_block
            ),
            (0, 0, 0, 0)
        );
        assert_slash(
            &block.world,
            &fixture,
            fee_phase,
            source.header().height().get(),
        );
        assert_eq!(
            asset_balance(&block.world, &fixture, &ALICE_ID),
            payer_before.checked_sub(&Quantity::from(21_u32)).unwrap()
        );
        assert_eq!(
            block
                .world
                .asset_definition(&fixture.asset)
                .unwrap()
                .total_quantity(),
            &supply_before.checked_sub(&Quantity::from(1_u32)).unwrap()
        );
        assert!(
            execute(&mut block, &source).is_err(),
            "poisoned block refuses in-place retry"
        );
        let calls_after_retry = if let Some(probe) = &penalty_probe {
            probe.observe().0
        } else {
            fee_probe.as_ref().unwrap().observe().0
        };
        assert_eq!(
            calls_after_retry, calls,
            "poisoned-block retry cannot repeat the original tail decoder"
        );
        assert_eq!(source.hash(), hash);
        assert_eq!(block.gas_used_in_block, gas);
        assert_eq!(
            block.committed_fragment_count(),
            fragments + 1 + usize::from(fee_phase)
        );
    }
    {
        let view = state.view();
        assert_no_penalty(view.world(), &fixture);
        assert_eq!(
            asset_balance(view.world(), &fixture, &ALICE_ID),
            payer_before
        );
        assert_eq!(
            view.world()
                .asset_definition(&fixture.asset)
                .unwrap()
                .total_quantity(),
            &supply_before
        );
    }
    let (mut retry, _recording) = recorded_network_block(state, &source);
    let fragments = retry.committed_fragment_count();
    execute(&mut retry, &source)
        .expect("unchanged original ballots retry after local decoder recovery");
    assert_eq!(source.hash(), hash);
    let first = network_row(&retry, 0);
    assert!(first.result.is_ok());
    assert!(first.result.nexus_fee_receipt().is_some());
    let second = network_row(&retry, 1);
    assert!(
        matches!(second.result.as_ref(), Err(TransactionRejectionReason::Validation(
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(reason))
    )) if reason.as_ref() == "second plain ballot cannot change direction")
    );
    assert!(second.result.nexus_fee_receipt().is_some());
    assert!(second.completions.is_empty() && second.result.batch_transfer_outcomes().is_empty());
    assert_slash(&retry.world, &fixture, true, source.header().height().get());
    assert_eq!(
        asset_balance(&retry.world, &fixture, &ALICE_ID),
        payer_before.checked_sub(&Quantity::from(22_u32)).unwrap()
    );
    assert_eq!(
        retry
            .world
            .asset_definition(&fixture.asset)
            .unwrap()
            .total_quantity(),
        &supply_before.checked_sub(&Quantity::from(2_u32)).unwrap()
    );
    assert_eq!(retry.committed_fragment_count(), fragments + 3);
    assert_eq!(retry.gas_used_in_block, first_gas + second_gas);
    for slash in [false, true] {
        let count = retry
            .world
            .external_event_buf
            .iter()
            .filter(|event| match event.as_data_event() {
                Some(DataEvent::Governance(GovernanceEvent::BallotRejected(event))) => {
                    !slash && event.referendum_id == fixture.referendum
                }
                Some(DataEvent::Governance(GovernanceEvent::LockSlashed(event))) => {
                    slash
                        && event.referendum_id == fixture.referendum
                        && event.reason == GovernanceSlashReason::DoubleVote
                }
                _ => false,
            })
            .count();
        assert_eq!(
            count, 1,
            "fresh retry emits exactly one real rejection/slash event"
        );
    }
}

#[test]
fn actual_ballot_penalty_decoder_refusal_keeps_original_deferral_and_retry() {
    actual_penalty_refusal_and_fresh_retry(false);
}

#[test]
fn fee_decoder_refusal_after_actual_ballot_penalty_rolls_back_and_retries_once() {
    actual_penalty_refusal_and_fresh_retry(true);
}
