// SCCP call sites of block validation (`specs/sccp.md` §4.3.2, §4.19): the per-block
// exemption cap judged against the committed parent World, and the consensus height inputs the
// post-execution hook receives from the authenticated native schedule, including genesis.

fn sccp_call_site_parameters_committed(state: &State) {
    let mut world = state.world.block();
    *world.sccp_parameters.get_mut() =
        Some(iroha_data_model::sccp::params::SccpParametersV1::taira_default());
    world.commit();
}

fn sccp_call_site_genesis() -> (KeyPair, SignedBlock) {
    let key_pair = KeyPair::try_from_seed(vec![0x51; 32], Algorithm::Ed25519)
        .expect("deterministic genesis key");
    let transaction = crate::smartcontracts::isi::sccp::test_support::sample_signed_transaction();
    let genesis = SignedBlock::genesis(vec![transaction], key_pair.private_key(), None, None);
    (key_pair, genesis)
}

#[test]
fn sccp_exempt_cap_is_judged_against_the_committed_parent_world() {
    let state = crate::smartcontracts::isi::sccp::test_support::blank_state();
    let key_pair = KeyPair::try_from_seed(vec![0x52; 32], Algorithm::Ed25519)
        .expect("deterministic leader key");
    let block = ValidBlock::new_dummy(key_pair.private_key());
    let signed: &SignedBlock = block.as_ref();
    ValidBlock::validate_sccp_exempt_cap_against(signed, &state.world.view())
        .expect("no transaction is exempt without SCCP");
    {
        let mut state_block = state.block(signed.header());
        {
            let mut transaction = state_block.transaction();
            crate::smartcontracts::isi::sccp::store::parameters::set(
                &mut transaction,
                Some(iroha_data_model::sccp::params::SccpParametersV1::taira_default()),
            );
            transaction.apply();
        }
        assert!(
            crate::smartcontracts::isi::sccp::params::exists(&state_block.world),
            "the block overlay holds the uncommitted parameters"
        );
        assert!(
            !crate::smartcontracts::isi::sccp::params::exists(
                &state_block.sccp_parent_world_view()
            ),
            "block-start writes are invisible to the parent view the cap is judged against"
        );
        ValidBlock::validate_sccp_exempt_cap(signed, &state_block)
            .expect("no transaction of the block is fee-exempt");
    }
    sccp_call_site_parameters_committed(&state);
    let state_block = state.block(signed.header());
    assert!(crate::smartcontracts::isi::sccp::params::exists(
        &state_block.sccp_parent_world_view()
    ));
    ValidBlock::validate_sccp_exempt_cap(signed, &state_block)
        .expect("no transaction of the block is fee-exempt");
}

#[test]
fn sccp_exempt_cap_counts_eligible_entry_points_of_the_block() {
    use crate::smartcontracts::isi::sccp::test_support::SampleInstructions;
    let key_pair = KeyPair::try_from_seed(vec![0x54; 32], Algorithm::Ed25519)
        .expect("deterministic authority key");
    let signed = |instruction: InstructionBox| {
        TransactionBuilder::new(
            iroha_data_model::NetworkId::from_genesis_hash(
                iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new([0x54; 32])),
            ),
            AccountId::new(key_pair.public_key().clone()),
            iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([instruction])
        .sign(key_pair.private_key())
    };
    // Fault evidence is eligible whenever SCCP exists.
    let fault = |height| {
        let mut submit = SampleInstructions::fault();
        submit.statement.height = height;
        signed(submit.into())
    };
    let block = SignedBlock::genesis(
        vec![
            fault(9),
            fault(10),
            // An attestation shape from an ordinary account is not eligible: it pays the
            // ordinary fee and is not counted.
            signed(SampleInstructions::attestations().into()),
            crate::smartcontracts::isi::sccp::test_support::sample_signed_transaction(),
        ],
        key_pair.private_key(),
        None,
        None,
    );
    assert_eq!(block.network_entrypoints().count(), 4);
    let with_cap = |cap| {
        let state = crate::smartcontracts::isi::sccp::test_support::blank_state();
        let mut parameters = iroha_data_model::sccp::params::SccpParametersV1::taira_default();
        parameters.max_exempt_transactions_per_block = cap;
        let mut world = state.world.block();
        *world.sccp_parameters.get_mut() = Some(parameters);
        world.commit();
        ValidBlock::validate_sccp_exempt_cap_against(&block, &state.world.view())
    };
    with_cap(2).expect("two eligible transactions fit a cap of two");
    let error = with_cap(1).expect_err("the second eligible transaction exceeds the cap");
    assert!(error.to_string().contains("fee-exempt"), "{error}");
}

#[test]
fn sccp_hook_receives_scheduled_height_inputs_on_the_sumeragi_core_path() {
    use crate::smartcontracts::isi::sccp::{height::SccpHeightInputsV1, hook::observed};
    use crate::sumeragi::{
        startup::GENESIS_HEIGHT,
        test_chain::{CertifiedTestChain, Signers, TestChainConfig},
    };
    use iroha_data_model::parameter::system::ConsensusMode;
    let signer = KeyPair::try_from_seed(vec![0x55; 32], Algorithm::Ed25519)
        .expect("deterministic transaction signer");
    let authority = AccountId::new(signer.public_key().clone());
    let world =
        crate::state::World::with([], [Account::new(authority.clone()).build(&authority)], []);
    {
        let mut block = world.block();
        *block.sccp_parameters.get_mut() =
            Some(iroha_data_model::sccp::params::SccpParametersV1::taira_default());
        block.commit();
    }
    let _ = observed::take();
    let prepared = CertifiedTestChain::prepare(TestChainConfig::new(world, 10_000))
        .expect("the original signed genesis is prepared");
    let preparation_inputs = observed::take();
    assert!(
        !preparation_inputs.is_empty(),
        "policy derivation executes genesis"
    );
    let mut chain = CertifiedTestChain::from_prepared(prepared).expect("the chain starts");
    let state = chain.state();
    let expected = |height: u64| {
        let view = state.view();
        let schedule = view.world().consensus_schedule();
        let scheduled = schedule.ready(height).expect("a scheduled height");
        let epoch = scheduled.epoch.authorization.epoch;
        let epoch_end_height = scheduled.epoch.authorization.last_height;
        let next_roster = (height == epoch_end_height).then(|| {
            schedule
                .ready(height + 1)
                .expect("the next scheduled height")
                .epoch
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect()
        });
        SccpHeightInputsV1 {
            mode: ConsensusMode::Permissioned,
            height,
            epoch,
            epoch_end_height,
            roster: scheduled
                .epoch
                .committee
                .iter()
                .map(|member| member.validator.clone())
                .collect(),
            next_roster,
        }
    };
    let genesis_inputs = expected(GENESIS_HEIGHT);
    assert!(
        preparation_inputs
            .iter()
            .all(|input| input == &(GENESIS_HEIGHT, Some(genesis_inputs.clone()))),
        "each disposable genesis execution uses the original scheduled inputs"
    );
    assert_eq!(
        observed::take(),
        vec![(GENESIS_HEIGHT, Some(genesis_inputs.clone()))],
        "genesis applied by the Sumeragi core feeds its schedule to the hook"
    );
    let validators = chain
        .validators()
        .iter()
        .map(|(peer, _)| peer.clone())
        .collect::<Vec<_>>();
    assert_eq!(genesis_inputs.roster, validators);
    // Block 2 executes exactly as `StateExecutor::run_execution` does.
    let view = state.view();
    let parent = view
        .latest_block()
        .expect("original block read attempt")
        .expect("the applied genesis");
    let scheduled = view
        .world()
        .consensus_schedule()
        .ready(GENESIS_HEIGHT + 1)
        .cloned()
        .expect("the schedule covers the next height");
    drop(view);
    let cadence = Duration::from_millis(scheduled.params.block_time_ms);
    let block_time = parent.header().creation_time() + cadence;
    let transaction = chain.sign(
        &signer,
        [InstructionBox::from(Log::new(
            Level::DEBUG,
            "SCCP scheduled height inputs".to_owned(),
        ))],
        u64::try_from(block_time.as_millis()).expect("fixture time fits") - 1,
    );
    let expected_next = expected(GENESIS_HEIGHT + 1);
    let proposal = chain.proposal(None, vec![transaction]);
    let worker_inputs = observed::for_header(&proposal.header());
    chain.commit_proposal(proposal, Signers::Quorum, Default::default());
    assert_eq!(
        worker_inputs.take(),
        vec![(GENESIS_HEIGHT + 1, Some(expected_next))],
        "a Sumeragi-core block never reaches the hook without height inputs"
    );
}

#[test]
fn sccp_unauthed_genesis_writes_never_supply_roster_authority() {
    use crate::smartcontracts::isi::sccp::height::SccpHeightSourceV1;
    let (_key, genesis) = sccp_call_site_genesis();
    let state = crate::smartcontracts::isi::sccp::test_support::blank_state();
    let block = state.block(genesis.header());
    assert_eq!(
        ValidBlock::sccp_height_inputs(&genesis, &block, SccpHeightSourceV1::Unauthenticated),
        None
    );
    drop(block);
    sccp_call_site_parameters_committed(&state);
    let block = state.block(genesis.header());
    assert_eq!(
        ValidBlock::sccp_height_inputs(&genesis, &block, SccpHeightSourceV1::Unauthenticated),
        None,
        "SCCP initialization cannot turn unauthenticated writes into an epoch authority"
    );
    assert_eq!(
        ValidBlock::sccp_height_inputs(
            &genesis,
            &block,
            SccpHeightSourceV1::SumeragiSchedule {
                genesis_height: 1,
                mode: iroha_data_model::parameter::system::ConsensusMode::Npos
            }
        ),
        None,
        "a missing authenticated native slot must fail closed"
    );
}

#[test]
fn native_execution_rejects_relay_fee_mode_before_source_execution() {
    let (_key, genesis) = sccp_call_site_genesis();
    let state = crate::smartcontracts::isi::sccp::test_support::blank_state();
    let block = state.block(genesis.header());
    ValidBlock::validate_native_fee_settlement_mode(&block).expect("direct fees are admitted");
    drop(block);
    state.nexus.write().fees.settlement_mode =
        iroha_config::parameters::actual::NexusFeeSettlementMode::LaneRelayBurn;
    let block = state.block(genesis.header());
    let error = ValidBlock::validate_staged_execution_controls(&genesis, &block)
        .expect_err("relay receipt settlement is rejected before transactions");
    assert!(
        error.to_string().contains("retired lane-relay-burn"),
        "{error}"
    );
}
