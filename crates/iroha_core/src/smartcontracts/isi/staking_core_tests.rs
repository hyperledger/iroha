// Same-scope regression coverage extracted to keep the parent source budget bounded.
#[test]
fn checked_keypair_helpers_preserve_requested_algorithm() {
    assert_eq!(checked_keypair().algorithm(), Algorithm::default());
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::Ed25519).algorithm(),
        Algorithm::Ed25519
    );
    assert_eq!(
        checked_keypair_with_algorithm(Algorithm::BlsNormal).algorithm(),
        Algorithm::BlsNormal
    );
}
#[test]
fn staking_amount_boundary_rejects_negative_and_zero_values() {
    assert!(
        Quantity::try_from_numeric(Numeric::new(-1_i32, 0)).is_err(),
        "negative signed values must not enter the nominal stake domain"
    );
    let error = ensure_positive_amount(&Quantity::zero(), "stake amount")
        .expect_err("zero stake amount must be rejected");
    assert!(matches!(error, Error::InvariantViolation(_)));
}
fn new_block() -> crate::block::CommittedBlock {
    let (_leader_public_key, leader_private_key) = checked_keypair().into_parts();
    ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
        h.set_height(NonZeroU64::new(1).unwrap());
    })
    .commit_unchecked(crate::block::reserve_block_for_tests())
    .unpack(|_| {})
}
// Direct staking component fixtures retain a bounded ordinary invocation before
// opening StateTransaction. Their source is not a signed Network input and grants
// no publication authority; end-to-end fee/finality tests use the real producer.
fn block_header_with_height(height: u64) -> iroha_data_model::block::BlockHeader {
    let mut header = new_block().as_ref().header();
    header.set_height(NonZeroU64::new(height).expect("non-zero height"));
    header
}
fn new_block_with_height(height: u64) -> crate::block::CommittedBlock {
    let (_leader_public_key, leader_private_key) = checked_keypair().into_parts();
    ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
        h.set_height(NonZeroU64::new(height).expect("non-zero height"));
    })
    .commit_unchecked(crate::block::reserve_block_for_tests())
    .unpack(|_| {})
}
fn new_block_with_height_and_time(
    height: u64,
    creation_time_ms: u64,
) -> crate::block::CommittedBlock {
    let (_leader_public_key, leader_private_key) = checked_keypair().into_parts();
    ValidBlock::new_dummy_and_modify_header(&leader_private_key, |h| {
        h.set_height(NonZeroU64::new(height).expect("non-zero height"));
        h.creation_time_ms = creation_time_ms;
    })
    .commit_unchecked(crate::block::reserve_block_for_tests())
    .unpack(|_| {})
}

fn setup_state() -> State {
    let mut nexus = iroha_config::parameters::actual::Nexus {
        ..Default::default()
    };
    nexus.lane_catalog = staking_test_lane_catalog();
    nexus.dataspace_catalog = iroha_data_model::nexus::DataSpaceCatalog::new(
        nexus
            .lane_catalog
            .lanes()
            .iter()
            .map(|lane| iroha_data_model::nexus::DataSpaceMetadata {
                id: lane.dataspace_id,
                alias: if lane.dataspace_id == DataSpaceId::UNIVERSAL {
                    "universal".to_owned()
                } else {
                    format!("staking-test-dataspace-{}", lane.dataspace_id.as_u64())
                },
                description: None,
                fault_tolerance: 1,
            })
            .collect(),
    )
    .expect("staking test dataspace catalog should match its lanes");
    let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let mut parameters = world.parameters.block();
    parameters.set_parameter(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    parameters.commit();
    State::new_with_nexus_for_testing(world, nexus, LiveQueryStore::start_test())
}
fn staking_test_lane_catalog() -> LaneCatalog {
    // Each fixture lane represents a distinct staking authority. Provision only
    // the identities exercised below; unused lane storage adds no coverage.
    let lane_count = nonzero!(213_u32);
    let lanes = [
        0, 1, 2, 3, 4, 5, 7, 8, 10, 11, 12, 13, 14, 15, 16, 17, 22, 23, 24, 31, 32, 34, 35, 42, 43,
        44, 45, 46, 47, 48, 49, 50, 51, 52, 59, 60, 81, 82, 83, 84, 99, 144, 145, 147, 148, 149,
        150, 151, 152, 153, 154, 155, 156, 157, 158, 161, 162, 163, 164, 165, 166, 167, 168, 169,
        170, 171, 172, 173, 174, 175, 210, 211, 212,
    ]
    .into_iter()
    .map(|id| {
        let lane_id = LaneId::new(id);
        LaneConfig {
            id: lane_id,
            dataspace_id: if lane_id == LaneId::SINGLE {
                DataSpaceId::UNIVERSAL
            } else {
                DataSpaceId::new(u64::from(id))
            },
            alias: if lane_id == LaneId::SINGLE {
                "default".to_string()
            } else {
                format!("staking-test-lane-{id}")
            },
            ..LaneConfig::default()
        }
    })
    .collect();
    LaneCatalog::new(lane_count, lanes).expect("valid staking test lane catalog")
}
fn set_transaction_lane_catalog(stx: &mut StateTransaction<'_, '_>, lane_catalog: LaneCatalog) {
    stx.nexus.lane_catalog = lane_catalog;
    stx.nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&stx.nexus.lane_catalog);
}
fn register_peer_for_account(
    stx: &mut StateTransaction<'_, '_>,
    account: &AccountId,
) -> iroha_model_base::peer::PeerId {
    let peer = validator_peer_id(account);
    let _ = stx.world.peers.push(peer.clone());
    seed_validator_consensus_key(stx, &peer, ConsensusKeyStatus::Active);
    peer
}
fn validator_peer_id(account: &AccountId) -> iroha_model_base::peer::PeerId {
    iroha_model_base::peer::PeerId::from(
        account
            .try_signatory()
            .expect("test accounts are single-signatory")
            .clone(),
    )
}
fn seed_validator_consensus_key(
    stx: &mut StateTransaction<'_, '_>,
    peer: &iroha_model_base::peer::PeerId,
    status: ConsensusKeyStatus,
) {
    let activation_height = stx.block_height();
    for role in [ConsensusKeyRole::Validator, ConsensusKeyRole::Committee] {
        seed_consensus_key_for_role_with_heights(stx, peer, role, status, activation_height, None);
    }
}
fn seed_participant_consensus_key(
    stx: &mut StateTransaction<'_, '_>,
    peer: &iroha_model_base::peer::PeerId,
) {
    // Peer-binding fixtures exercise an independent lane committee. They must
    // not accidentally add a candidate to the global election pool.
    clear_consensus_keys_for_peer(stx, peer);
    let activation_height = stx.block_height();
    seed_consensus_key_for_role_with_heights(
        stx,
        peer,
        ConsensusKeyRole::Committee,
        ConsensusKeyStatus::Active,
        activation_height,
        None,
    );
}
fn seed_validator_consensus_key_with_heights(
    stx: &mut StateTransaction<'_, '_>,
    peer: &iroha_model_base::peer::PeerId,
    status: ConsensusKeyStatus,
    activation_height: u64,
    expiry_height: Option<u64>,
) {
    for role in [ConsensusKeyRole::Validator, ConsensusKeyRole::Committee] {
        seed_consensus_key_for_role_with_heights(
            stx,
            peer,
            role,
            status,
            activation_height,
            expiry_height,
        );
    }
}
fn seed_consensus_key_for_role_with_heights(
    stx: &mut StateTransaction<'_, '_>,
    peer: &iroha_model_base::peer::PeerId,
    role: ConsensusKeyRole,
    status: ConsensusKeyStatus,
    activation_height: u64,
    expiry_height: Option<u64>,
) {
    let ident = match role {
        ConsensusKeyRole::Validator => crate::state::derive_validator_key_id(peer.public_key()),
        ConsensusKeyRole::Committee => crate::state::derive_committee_key_id(peer.public_key()),
        ConsensusKeyRole::Endorsement => {
            unreachable!("staking fixtures never use endorsement keys")
        }
    };
    let mut record = ConsensusKeyRecord {
        id: ident,
        public_key: peer.public_key().clone(),
        pop: None,
        activation_height,
        expiry_height,
        replaces: None,
        status,
    };
    if matches!(record.status, ConsensusKeyStatus::Disabled) {
        record.expiry_height = Some(record.expiry_height.unwrap_or(activation_height));
    }
    stx.world
        .consensus_keys
        .insert(record.id.clone(), record.clone());
    let key_label = record.public_key.to_string();
    let mut by_pk = stx
        .world
        .consensus_keys_by_pk
        .get(&key_label)
        .cloned()
        .unwrap_or_default();
    if !by_pk.contains(&record.id) {
        by_pk.push(record.id.clone());
        stx.world.consensus_keys_by_pk.insert(key_label, by_pk);
    }
}
fn clear_consensus_keys_for_peer(
    stx: &mut StateTransaction<'_, '_>,
    peer: &iroha_model_base::peer::PeerId,
) {
    let label = peer.public_key().to_string();
    if let Some(ids) = stx.world.consensus_keys_by_pk.remove(label.clone()) {
        for id in ids {
            stx.world.consensus_keys.remove(id);
        }
    }
}
fn set_epoch_length(state: &mut State, epoch_length_blocks: u64) {
    assert!(
        epoch_length_blocks >= 3,
        "signed NPoS fixtures need disjoint commit/reveal windows before the epoch cutoff"
    );
    let mut wb = state.world.block();
    {
        let params = wb.parameters.get_mut();
        params.set_parameter(Parameter::Custom(
            SumeragiNposParameters {
                epoch_length_blocks: NonZeroU64::new(epoch_length_blocks)
                    .expect("staking test epoch length must be non-zero"),
                evidence_horizon_blocks: 1,
                slashing_delay_blocks: 1,
                ..SumeragiNposParameters::default()
            }
            .into_custom_parameter(),
        ));
    }
    wb.commit();
}
fn set_test_npos_penalty_windows(
    stx: &mut StateTransaction<'_, '_>,
    evidence_horizon_blocks: u64,
    slashing_delay_blocks: u64,
) {
    let mut parameters = stx
        .world
        .sumeragi_npos_parameters()
        .expect("original policy decoder completes")
        .unwrap_or_default();
    parameters.evidence_horizon_blocks = evidence_horizon_blocks;
    parameters.slashing_delay_blocks = slashing_delay_blocks;
    parameters
        .validate()
        .expect("test NPoS penalty windows must be valid");
    stx.world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(parameters.into_custom_parameter()));
}
fn set_fixture_xor_identity(stx: &mut StateTransaction<'_, '_>, asset: &AssetDefinitionId) {
    let parameters = stx
        .world
        .sumeragi_npos_parameters()
        .expect("original policy decoder completes")
        .expect("fixture committed parameters");
    assert_eq!(
        asset, &parameters.xor_asset_definition_id,
        "staking fixtures must use the committed network XOR identity"
    );
    assert_eq!(
        asset,
        &SumeragiNposParameters::default().xor_asset_definition_id,
        "staking fixtures must use the first-release network XOR identity"
    );
}
fn configure_reward_fixture(
    stx: &mut StateTransaction<'_, '_>,
    lane_id: LaneId,
    mint_amount: u32,
) -> (AccountId, AccountId, AssetId, AssetDefinitionId) {
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    Register::domain(Domain::new(domain_id.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    let (sink, _) = gen_account_in("wonderland");
    let (validator, _) = gen_account_in("wonderland");
    let (escrow, _) = gen_account_in("wonderland");
    Register::account(Account::new(escrow.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    Register::account(Account::new(sink.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    Register::account(Account::new(validator.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    let asset_def_id = stx
        .world
        .sumeragi_npos_parameters()
        .expect("original policy decoder completes")
        .expect("fixture committed NPoS parameters")
        .xor_asset_definition_id;
    Register::asset_definition({
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::new(
            __asset_definition_id.clone(),
            "XOR".to_owned(),
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    })
    .execute(&ALICE_ID, stx)
    .unwrap();
    let reward_asset = AssetId::new(asset_def_id.clone(), sink.clone());
    let initial_stake = Quantity::from(u64::from(mint_amount.max(1)));
    Mint::asset_quantity(mint_amount, reward_asset.clone())
        .execute(&ALICE_ID, stx)
        .unwrap();
    let validator_asset = AssetId::new(asset_def_id.clone(), validator.clone());
    Mint::asset_quantity(mint_amount, validator_asset.clone())
        .execute(&ALICE_ID, stx)
        .unwrap();

    stx.nexus.fees.fee_sink_account_id = sink.to_string();
    stx.nexus.fees.fee_asset_id = asset_def_id.to_string();
    stx.nexus.lane_catalog = LaneCatalog::new(
        nonzero!(64_u32),
        vec![LaneConfig {
            id: lane_id,
            alias: "lane-9".to_string(),
            dataspace_id: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            ..LaneConfig::default()
        }],
    )
    .expect("lane catalog");
    stx.nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&stx.nexus.lane_catalog);
    stx.nexus.staking.public_validator_mode =
        iroha_config::parameters::actual::LaneValidatorMode::StakeElected;
    stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
    set_fixture_xor_identity(stx, &asset_def_id);
    stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
    stx.nexus.staking.slash_sink_account_id = sink.to_string();
    register_peer_for_account(stx, &validator);
    RegisterPublicLaneValidator {
        monetary_plan: fixture_registration_plan(
            &stx,
            lane_id,
            &validator,
            (initial_stake.clone()).clone(),
        ),
        lane_id,
        peer_id: validator_peer_id(&validator),
        validator: validator.clone(),
        stake_account: validator.clone(),
        initial_stake: initial_stake.clone(),
        metadata: Metadata::default(),
    }
    .execute(&validator, stx)
    .expect("register validator for rewards");
    (sink, validator, reward_asset, asset_def_id)
}
fn prepare_accounts(
    stx: &mut StateTransaction<'_, '_>,
) -> (AccountId, AccountId, AccountId, AssetDefinitionId) {
    let domain_id: DomainId = DomainId::try_new("nexus", "universal").expect("domain id");
    stx.world.domains.insert(
        domain_id.clone(),
        Domain::new(domain_id.clone()).build(&ALICE_ID),
    );
    // The universal authority account is seeded by setup_state; domain ownership
    // is separate from the canonical account identity.
    let alice_domain_id: DomainId =
        DomainId::try_new("wonderland", "universal").expect("domain id");
    stx.world.domains.insert(
        alice_domain_id.clone(),
        Domain::new(alice_domain_id.clone()).build(&ALICE_ID),
    );
    let (validator, _kp) = gen_account_in("nexus");
    let (delegator, _kp) = gen_account_in("nexus");
    let (escrow, _kp) = gen_account_in("nexus");
    Register::account(Account::new(validator.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    Register::account(Account::new(delegator.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    Register::account(Account::new(escrow.clone()))
        .execute(&ALICE_ID, stx)
        .unwrap();
    register_peer_for_account(stx, &validator);
    register_peer_for_account(stx, &delegator);
    register_peer_for_account(stx, &escrow);
    let asset_def_id = stx
        .world
        .sumeragi_npos_parameters()
        .expect("original policy decoder completes")
        .expect("fixture committed NPoS parameters")
        .xor_asset_definition_id;
    Register::asset_definition({
        let __asset_definition_id = asset_def_id.clone();
        AssetDefinition::new(
            __asset_definition_id.clone(),
            "XOR".to_owned(),
            iroha_primitives::numeric::NumericSpec::fractional(9),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    })
    .execute(&ALICE_ID, stx)
    .unwrap();
    let validator_asset = AssetId::new(asset_def_id.clone(), validator.clone());
    let delegator_asset = AssetId::new(asset_def_id.clone(), delegator.clone());
    Mint::asset_quantity(10_000u32, validator_asset)
        .execute(&ALICE_ID, stx)
        .unwrap();
    Mint::asset_quantity(10_000u32, delegator_asset)
        .execute(&ALICE_ID, stx)
        .unwrap();
    stx.nexus.staking.stake_asset_id = asset_def_id.to_string();
    set_fixture_xor_identity(stx, &asset_def_id);
    stx.nexus.staking.stake_escrow_account_id = escrow.to_string();
    stx.nexus.staking.slash_sink_account_id = escrow.to_string();
    (validator, delegator, escrow, asset_def_id)
}
fn complete_staking_committee(stx: &mut StateTransaction<'_, '_>, lane_id: LaneId) {
    let asset_definition: AssetDefinitionId = stx
        .nexus
        .staking
        .stake_asset_id
        .parse()
        .expect("fixture stake asset");
    for _ in 0..3 {
        let (validator, _) = gen_account_in("nexus");
        Register::account(Account::new(validator.clone()))
            .execute(&ALICE_ID, stx)
            .expect("register committee account");
        let peer_id = register_peer_for_account(stx, &validator);
        Mint::asset_quantity(
            1_000_u32,
            AssetId::new(asset_definition.clone(), validator.clone()),
        )
        .execute(&ALICE_ID, stx)
        .expect("fund committee stake");
        RegisterPublicLaneValidator {
            monetary_plan: fixture_registration_plan(
                &stx,
                lane_id,
                &validator,
                Quantity::from(1_000_u64),
            ),
            lane_id,
            peer_id,
            validator: validator.clone(),
            stake_account: validator.clone(),
            initial_stake: Quantity::from(1_000_u64),
            metadata: Metadata::default(),
        }
        .execute(&validator, stx)
        .expect("register committee validator");
        ActivatePublicLaneValidator { lane_id, validator }
            .execute(&ALICE_ID, stx)
            .expect("activate committee validator");
    }
}

fn insert_validator_record_for_key(
    stx: &mut StateTransaction<'_, '_>,
    key_lane: LaneId,
    record_lane: LaneId,
    validator: &AccountId,
    status: PublicLaneValidatorStatus,
    stake: Quantity,
) {
    let activation_height = match &status {
        PublicLaneValidatorStatus::PendingActivation(height) => *height,
        _ => 1,
    };
    stx.world.public_lane_validators.insert(
        (key_lane, validator.clone()),
        PublicLaneValidatorRecord {
            lane_id: record_lane,
            validator: validator.clone(),
            peer_id: validator_peer_id(validator),
            stake_account: validator.clone(),
            total_stake: stake.clone(),
            self_stake: stake,
            metadata: Metadata::default(),
            status,
            activation_height,
            election_exit_height: None,
            deactivation_height: None,
        },
    );
}

#[test]
fn genesis_monetary_context_requires_initial_height_and_exact_expiry() {
    use iroha_data_model::nexus::PublicLaneMonetaryScopeV1;
    let state = setup_state();
    let genesis = new_block();
    let mut block = state.block(genesis.as_ref().header());
    let mut stx = block.transaction_for_callback_testing();
    effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, 1)
        .expect("NPoS genesis uses the same exact genesis lifetime");
    stx.world
        .parameters
        .get_mut()
        .custom
        .remove(&SumeragiNposParameters::parameter_id());
    assert!(
        stx.world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .is_none()
    );
    effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, 1)
        .expect("initial genesis is its own exact one-height monetary authority");
    for expiry in [0, 2, u64::MAX] {
        assert!(
            effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, expiry)
                .is_err(),
            "genesis authority cannot authenticate expiry {expiry}"
        );
    }
    assert!(
        effects::validate_plan_context(
            &stx,
            &PublicLaneMonetaryScopeV1::Network(*stx.network_id()),
            1,
        )
        .is_err(),
        "network scope must not inherit the separate genesis lifetime authority"
    );
    drop(stx);
    block.block_hashes.push(genesis.as_ref().hash());
    let stx = block.transaction_for_callback_testing();
    assert!(
        effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, 1).is_err(),
        "the height-one scope cannot replay after a block is already committed"
    );
    drop(stx);
    drop(block);
    let mut successor = state.block(block_header_with_height(2));
    let stx = successor.transaction_for_callback_testing();
    assert!(
        effects::validate_plan_context(&stx, &PublicLaneMonetaryScopeV1::Genesis, 2).is_err(),
        "a non-genesis block cannot use genesis scope even with a current expiry"
    );
}

#[test]
fn network_monetary_context_keeps_the_committed_epoch_window() {
    use iroha_data_model::nexus::PublicLaneMonetaryScopeV1;
    let mut state = setup_state();
    set_epoch_length(&mut state, 6);
    let mut block = state.block(block_header_with_height(2));
    let stx = block.transaction_for_callback_testing();
    let scope = PublicLaneMonetaryScopeV1::Network(*stx.network_id());
    for expiry in [2, 8] {
        effects::validate_plan_context(&stx, &scope, expiry)
            .expect("current height through the committed epoch-length bound is valid");
    }
    for expiry in [0, 1, 9, u64::MAX] {
        assert!(effects::validate_plan_context(&stx, &scope, expiry).is_err());
    }
}

#[test]
fn genesis_staking_requires_committed_xor_and_preserves_exact_transfer_and_custody() {
    let state = setup_state();
    let mut block = state.block(block_header_with_height(1));
    let mut stx = block.transaction_for_callback_testing();
    // Genesis scope authenticates height; it cannot replace the committed network
    // currency identity required by an actual monetary staking operation.
    let (validator, _, escrow, definition) = prepare_accounts(&mut stx);
    let committed_parameters = stx
        .world
        .parameters
        .get_mut()
        .custom
        .remove(&SumeragiNposParameters::parameter_id())
        .expect("fixture pins the actual network XOR definition");
    assert!(
        stx.world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .is_none()
    );
    let lane = LaneId::SINGLE;
    let source = AssetId::new(definition.clone(), validator.clone());
    let destination = AssetId::new(definition, escrow);
    let amount = Quantity::from(1_000_u64);
    let registration = RegisterPublicLaneValidator {
        lane_id: lane,
        validator: validator.clone(),
        peer_id: validator_peer_id(&validator),
        stake_account: validator.clone(),
        initial_stake: amount.clone(),
        metadata: Metadata::default(),
        monetary_plan: PublicLaneMonetaryPlanV1::genesis_registration(
            source.clone(),
            destination.clone(),
            amount.clone(),
        ),
    };
    let error = registration
        .clone()
        .execute(&ALICE_ID, &mut stx)
        .expect_err("genesis cannot invent an absent network currency identity");
    assert_eq!(
        error,
        Error::InvariantViolation(
            "staking and rewards require the committed network XOR identity".into()
        )
    );
    assert_eq!(
        stx.world.assets.get(&source).unwrap().as_ref(),
        &Quantity::from(10_000_u64)
    );
    assert!(stx.world.assets.get(&destination).is_none());
    assert!(
        stx.world
            .public_lane_validators
            .get(&(lane, validator.clone()))
            .is_none()
    );
    assert!(
        stx.world
            .public_lane_stake_custody
            .get(&(lane, validator.clone()))
            .is_none()
    );
    assert!(
        stx.world
            .public_lane_stake_reserves
            .get(&destination)
            .is_none()
    );
    stx.world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(committed_parameters));
    let mut invalid_expiry = registration.clone();
    invalid_expiry.monetary_plan.valid_until_height = 2;
    let mut invalid_amount = registration.clone();
    invalid_amount.monetary_plan.amount = Quantity::from(999_u64);
    let mut invalid_custody = registration.clone();
    invalid_custody.monetary_plan.destination_asset = source.clone();
    let mut invalid_precondition = registration.clone();
    invalid_precondition.monetary_plan.precondition =
        PublicLaneMonetaryPreconditionV1::Registration(PublicLaneMonetaryRegistrationV1 {
            activation_height: 2,
        });
    for invalid in [
        invalid_expiry,
        invalid_amount,
        invalid_custody,
        invalid_precondition,
    ] {
        assert!(invalid.execute(&ALICE_ID, &mut stx).is_err());
        assert_eq!(
            stx.world.assets.get(&source).unwrap().as_ref(),
            &Quantity::from(10_000_u64)
        );
        assert!(stx.world.assets.get(&destination).is_none());
        assert!(
            stx.world
                .public_lane_validators
                .get(&(lane, validator.clone()))
                .is_none()
        );
        assert!(
            stx.world
                .public_lane_stake_custody
                .get(&(lane, validator.clone()))
                .is_none()
        );
        assert!(
            stx.world
                .public_lane_stake_reserves
                .get(&destination)
                .is_none()
        );
    }
    registration
        .execute(&ALICE_ID, &mut stx)
        .expect("exact prefunded genesis registration uses the committed network XOR");
    ActivatePublicLaneValidator {
        lane_id: lane,
        validator: validator.clone(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect("the actual genesis-funded validator can activate");
    assert_eq!(
        stx.world.assets.get(&source).unwrap().as_ref(),
        &Quantity::from(9_000_u64)
    );
    assert_eq!(
        stx.world.assets.get(&destination).unwrap().as_ref(),
        &amount
    );
    assert_eq!(
        stx.world
            .public_lane_stake_custody
            .get(&(lane, validator.clone())),
        Some(&(destination.clone(), amount.clone()))
    );
    assert_eq!(
        stx.world.public_lane_stake_reserves.get(&destination),
        Some(&amount)
    );
    let record = stx
        .world
        .public_lane_validators
        .get(&(lane, validator.clone()))
        .unwrap();
    assert!(matches!(record.status, PublicLaneValidatorStatus::Active));
    assert_eq!(record.activation_height, 1);
    assert_eq!(record.self_stake, amount);
    assert_eq!(
        stx.world
            .public_lane_stake_shares
            .get(&stake_key(lane, &validator, &validator))
            .unwrap()
            .bonded,
        amount
    );
    assert_eq!(
        stx.world
            .sumeragi_npos_parameters()
            .expect("original policy decoder completes")
            .unwrap()
            .xor_asset_definition_id,
        SumeragiNposParameters::default().xor_asset_definition_id
    );
}
