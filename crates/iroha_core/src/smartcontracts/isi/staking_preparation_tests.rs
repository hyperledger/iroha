// Same-scope regression coverage for bounded observational plan construction.

#[test]
fn global_staking_eligibility_uses_unequal_authenticated_intervals() {
    // E has an irregular absolute offset; frozen E+1 is ten blocks, while
    // the next projected/frozen interval is thirty. Genesis modulus is wrong.
    for (ready, expected) in [
        (101, 141),
        (129, 141),
        (130, 171),
        (139, 171),
        (140, 201),
        (169, 201),
        (170, 231),
        (200, 261),
    ] {
        assert_eq!(
            global_eligibility_from_intervals(101, 130, 140, 170, ready, 30).unwrap(),
            expected
        );
    }
    // An existing frozen E+2 keeps its twenty-block interval even after a
    // five-block configuration update; only subsequent unfrozen epochs use five.
    assert_eq!(
        global_eligibility_from_intervals(101, 130, 140, 160, 130, 5).unwrap(),
        161
    );
    assert_eq!(
        global_eligibility_from_intervals(101, 130, 140, 160, 140, 5).unwrap(),
        166
    );
    assert!(global_eligibility_from_intervals(101, 130, 140, 160, 100, 5).is_err());
    assert!(global_eligibility_from_intervals(101, 130, 130, 160, 101, 5).is_err());
    assert!(global_eligibility_from_intervals(1, 10, 20, u64::MAX, 10, 5).is_err());
}

#[test]
fn global_staking_eligibility_follows_the_authenticated_npos_epoch() {
    use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
    use iroha_data_model::parameter::system::{SumeragiConsensusMode, SumeragiParameter};
    let mut config = TestChainConfig::new(World::new(), 10_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config
        .genesis_parameters
        .push(Parameter::Sumeragi(SumeragiParameter::EpochLengthBlocks(
            NonZeroU64::new(10).unwrap(),
        )));
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters {
            epoch_length_blocks: NonZeroU64::new(10).unwrap(),
            evidence_horizon_blocks: 1,
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
    let chain = CertifiedTestChain::start(config).unwrap();
    let view = chain.state().view();
    // The authenticated genesis epoch is [1, 10]. A key ready at its boundary
    // misses that boundary's frozen election, even when its registration is earlier.
    for (ready, expected) in [(2, 21), (9, 21), (10, 31), (15, 31), (20, 41)] {
        assert_eq!(
            validator_eligibility_height(&view, LaneId::SINGLE, 2, ready).unwrap(),
            expected,
            "key ready {ready}"
        );
    }
    assert!(validator_eligibility_height(&view, LaneId::SINGLE, 2, 1).is_err());
    assert!(validator_eligibility_height(&view, LaneId::SINGLE, 0, 0).is_err());
    assert!(validator_eligibility_height(&view, LaneId::SINGLE, 11, 11).is_err());
}

#[test]
fn global_staking_eligibility_requires_committed_npos_parameters() {
    let state = State::new_with_nexus_for_testing(
        World::default(),
        iroha_config::parameters::actual::Nexus::default(),
        LiveQueryStore::start_test(),
    );
    let error = validator_eligibility_height(&state.view(), LaneId::SINGLE, 2, 2).unwrap_err();
    assert!(
        error.to_string().contains("committed NPoS parameters"),
        "{error}"
    );
}

#[test]
fn global_staking_eligibility_rejects_uncertified_preparation_intervals() {
    let network = crate::state::validator_committee::tests::fixture(4)
        .transition
        .preparation
        .network_id;
    let state_on = |network| {
        let world = crate::state::validator_committee::tests::fixture(4).world;
        let mut parameters = world.parameters.block();
        parameters.set_parameter(Parameter::Custom(
            SumeragiNposParameters {
                epoch_length_blocks: NonZeroU64::new(10).unwrap(),
                evidence_horizon_blocks: 1,
                slashing_delay_blocks: 1,
                ..SumeragiNposParameters::default()
            }
            .into_custom_parameter(),
        ));
        parameters.commit();
        State::new_with_chain_and_network_id_for_testing(
            world,
            crate::kura::Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            iroha_model_base::chain::ChainId::from("staking-frozen-preparation"),
            network,
        )
    };
    // Complete local preparation credentials cannot replace the authenticated
    // current epoch from committed history, even when their network matches.
    let state = state_on(network);
    assert!(validator_eligibility_height(&state.view(), LaneId::SINGLE, 15, 15).is_err());
    assert!(validator_eligibility_height(&state.view(), LaneId::SINGLE, 20, 20).is_err());
    // Foreign local credentials likewise grant no interval.
    let foreign = state_on(iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::from_untyped_unchecked(Hash::new(b"staking-foreign-network")),
    ));
    assert!(validator_eligibility_height(&foreign.view(), LaneId::SINGLE, 15, 15).is_err());
}

#[test]
fn global_staking_preparation_rejects_a_zero_validity_window() {
    use iroha_data_model::nexus::{
        PublicLanePreparationOperationV1, PublicLanePreparationRequestV1, PublicLanePrepareClaimV1,
    };
    let state = setup_state();
    let block = new_block();
    let mut state_block = state.block(block.as_ref().header());
    let mut stx = state_block.transaction_for_callback_testing();
    let (_, recipient, _, _) = configure_reward_fixture(&mut stx, LaneId::SINGLE, 100);
    let error = validator_eligibility_height(&stx, LaneId::SINGLE, 2, 2).unwrap_err();
    assert!(matches!(
        error,
        Attempt::Rejected(Error::InvariantViolation(message))
            if message.as_ref() == "height 0 is not committed in this view"
    ));
    let request = PublicLanePreparationRequestV1 {
        lane_id: LaneId::SINGLE,
        valid_for_blocks: 0,
        operation: PublicLanePreparationOperationV1::ClaimRewards(PublicLanePrepareClaimV1 {
            recipient,
        }),
    };
    assert!(
        preparation::prepare_public_lane_plan(&stx, request)
            .unwrap_err()
            .to_string()
            .contains("validity")
    );
}
