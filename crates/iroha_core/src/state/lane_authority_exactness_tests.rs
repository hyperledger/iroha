// First-release exact lane-route committee regressions.

fn exact_manifest_authority_fixture(
    fault_tolerance: u32,
    validator_count: u8,
) -> (State, Vec<KeyPair>) {
    let state = blank_test_state();
    let mut nexus = state.nexus_snapshot();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: DataSpaceId::UNIVERSAL,
        alias: "universal".to_owned(),
        description: None,
        fault_tolerance,
    }])
    .expect("exact-authority dataspace catalog");
    install_existing_nexus_geometry_for_test(&state, nexus);
    let keypairs = (1..=validator_count)
        .map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic exact-authority BLS key")
        })
        .collect::<Vec<_>>();
    seed_consensus_keys_with_pops(&state, &keypairs);
    install_lane_manifest_registry_for_keypairs(&state, &[LaneId::SINGLE], &keypairs);
    (state, keypairs)
}

fn seed_committee_consensus_keys_with_pops(state: &State, keypairs: &[KeyPair]) {
    let mut world = state.world.block();
    for keypair in keypairs {
        let pop = iroha_crypto::bls_normal_pop_prove(keypair.private_key())
            .expect("generate committee key proof of possession");
        let id = derive_committee_key_id(keypair.public_key());
        let record = ConsensusKeyRecord {
            id: id.clone(),
            public_key: keypair.public_key().clone(),
            pop: Some(pop),
            activation_height: 0,
            expiry_height: None,
            replaces: None,
            status: ConsensusKeyStatus::Active,
        };
        world.consensus_keys.insert(id, record.clone());
        let public_key = record.public_key.to_string();
        let mut by_public_key = world
            .consensus_keys_by_pk
            .get(&public_key)
            .cloned()
            .unwrap_or_default();
        if !by_public_key.contains(&record.id) {
            by_public_key.push(record.id.clone());
            world.consensus_keys_by_pk.insert(public_key, by_public_key);
        }
    }
    world.commit();
}

fn private_settlement_native_members(
    keypairs: &[KeyPair],
) -> Vec<iroha_data_model::sumeragi_lanes::SumeragiLaneMember> {
    crate::sumeragi::schedule::canonical_committee(
        keypairs
            .iter()
            .map(|key| PeerId::new(key.public_key().clone())),
    )
    .expect("native canonical committee")
    .into_iter()
    .map(|peer| {
        let key = keypairs
            .iter()
            .find(|key| key.public_key() == peer.public_key())
            .expect("native committee key");
        iroha_data_model::sumeragi_lanes::SumeragiLaneMember {
            peer,
            pop: iroha_crypto::bls_normal_pop_prove(key.private_key())
                .expect("native committee PoP"),
        }
    })
    .collect()
}

fn exact_private_settlement_authority_fixture(validator_count: u8) -> (State, Vec<KeyPair>) {
    use iroha_data_model::sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneRecord};
    let state = blank_test_state();
    let keypairs = (1..=validator_count)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    seed_consensus_keys_with_pops(&state, &keypairs);
    seed_committee_consensus_keys_with_pops(&state, &keypairs);
    let mut world = state.world.block();
    world.sumeragi_lanes.get_mut().upsert(SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane: LaneId::new(1),
        dataspace: DataSpaceId::new(1),
        incarnation: Hash::new(b"private settlement native incarnation").into(),
        params: Default::default(),
        committee: private_settlement_native_members(&keypairs),
        created_at: 1,
        active_from: 3,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 3,
        rescued: 0,
    });
    world.commit();
    (state, keypairs)
}

fn exact_stake_authority_fixture(
    fault_tolerance: u32,
    validator_count: u8,
) -> (State, Vec<KeyPair>) {
    let state = blank_test_state();
    let mut nexus = state.nexus_snapshot();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: DataSpaceId::UNIVERSAL,
        alias: "universal".to_owned(),
        description: None,
        fault_tolerance,
    }])
    .expect("exact stake-authority dataspace catalog");
    install_existing_nexus_geometry_for_test(&state, nexus);
    let keypairs = (1..=validator_count)
        .map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic exact stake-authority BLS key")
        })
        .collect::<Vec<_>>();
    seed_consensus_keys_with_pops(&state, &keypairs);
    let minimum_stake = state.nexus_snapshot().staking.min_validator_stake.clone();
    let mut world = state.world.block();
    for keypair in &keypairs {
        let validator = AccountId::new(keypair.public_key().clone());
        world.public_lane_validators.insert(
            (LaneId::SINGLE, validator.clone()),
            PublicLaneValidatorRecord {
                lane_id: LaneId::SINGLE,
                validator: validator.clone(),
                peer_id: PeerId::new(keypair.public_key().clone()),
                stake_account: validator,
                total_stake: minimum_stake.clone(),
                self_stake: minimum_stake.clone(),
                metadata: Metadata::default(),
                status: PublicLaneValidatorStatus::Active,
                activation_height: 1,
                election_exit_height: None,
                deactivation_height: None,
            },
        );
    }
    world.commit();
    (state, keypairs)
}

fn install_malformed_beacon_cursor(state: &State) {
    // A cursor without its backing pulse must fail verified seed resolution.
    let mut world = state.world.block();
    world.global_beacon_latest_pulse.insert(
        GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY,
        crate::beacon::GlobalThresholdBeaconPulseLinkV1 {
            pulse_id: [0xA1; 32],
            seed: [0xB2; 32],
            height: 0,
            round: 0,
        },
    );
    world.commit();
}

fn resolve_universal_committee_at(
    state: &State,
    height: u64,
) -> Result<LaneAuthorityCommittee, LaneAuthorityError> {
    state.resolve_lane_committee_at_height(
        LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        height,
    )
}

fn resolve_universal_committee(
    state: &State,
) -> Result<LaneAuthorityCommittee, LaneAuthorityError> {
    state.resolve_lane_committee_at_height(
        LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
        1,
    )
}

fn private_settlement_authority_for_keys(
    state: &State,
    keypairs: &[KeyPair],
) -> iroha_data_model::nexus::PrivateSettlementCommitteeAuthorityV1 {
    let members = private_settlement_native_members(keypairs);
    let validators = members
        .iter()
        .map(|member| member.peer.clone())
        .collect::<Vec<_>>();
    let view = state.view();
    let native = view
        .world()
        .sumeragi_lanes()
        .lane(LaneId::new(1))
        .expect("native fixture");
    iroha_data_model::nexus::PrivateSettlementCommitteeAuthorityV1 {
        route: iroha_data_model::nexus::PrivateSettlementRouteV1 {
            dataspace_id: native.dataspace,
            lane_id: native.lane,
            lane_incarnation: Hash::from_marked_bytes(native.incarnation)
                .expect("marked incarnation"),
        },
        validator_set_hash: HashOf::new(&validators),
        validators,
        validator_pops: members.into_iter().map(|member| member.pop).collect(),
    }
}

#[test]
fn private_settlement_authority_accepts_exact_native_f1_roster_without_physical_lane() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(4);
    let authority = private_settlement_authority_for_keys(&state, &keypairs);
    assert!(
        state
            .lane_incarnation_at_height(authority.route.lane_id, 3)
            .is_none()
    );
    crate::private_settlement::validate_private_settlement_committee_authority_v1(
        &state.view(),
        3,
        &authority,
    )
    .expect("exact native four-validator authority without a physical catalog entry");
}

#[test]
fn private_settlement_authority_rejects_validator_only_state_authority() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(4);
    let mut world = state.world.block();
    for keypair in &keypairs {
        let validator_id = derive_validator_key_id(keypair.public_key());
        let committee_id = derive_committee_key_id(keypair.public_key());
        assert!(world.consensus_keys.get(&validator_id).is_some());
        assert!(world.consensus_keys.get(&committee_id).is_some());
        world.consensus_keys.remove(committee_id);
        world
            .consensus_keys_by_pk
            .insert(keypair.public_key().to_string(), vec![validator_id]);
    }
    world.commit();
    let authority = private_settlement_authority_for_keys(&state, &keypairs);
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &authority,
        )
        .is_err(),
        "global Validator-only authority cannot authorize private settlement"
    );
}

#[test]
fn private_settlement_authority_requires_live_committee_keys_at_its_anchor() {
    for (activation, expiry, status, accepted) in [
        (4, None, ConsensusKeyStatus::Active, false),
        (0, Some(3), ConsensusKeyStatus::Active, false),
        (0, None, ConsensusKeyStatus::Disabled, false),
        (3, Some(4), ConsensusKeyStatus::Active, true),
    ] {
        let (state, keypairs) = exact_private_settlement_authority_fixture(4);
        let authority = private_settlement_authority_for_keys(&state, &keypairs);
        let mut world = state.world.block();
        let id = derive_committee_key_id(keypairs[0].public_key());
        let mut record = world.consensus_keys.get(&id).unwrap().clone();
        record.activation_height = activation;
        record.expiry_height = expiry;
        record.status = status;
        world.consensus_keys.insert(id, record);
        world.commit();
        assert_eq!(
            crate::private_settlement::validate_private_settlement_committee_authority_v1(
                &state.view(),
                3,
                &authority,
            )
            .is_ok(),
            accepted,
            "Committee key must be live at the exact authority anchor"
        );
    }
}

#[test]
fn private_settlement_authority_rejects_unmarked_native_incarnation() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(4);
    let authority = private_settlement_authority_for_keys(&state, &keypairs);
    let mut world = state.world.block();
    world
        .sumeragi_lanes
        .get_mut()
        .lane_mut(authority.route.lane_id)
        .unwrap()
        .incarnation[Hash::LENGTH - 1] &= !1;
    world.commit();
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &authority,
        )
        .is_err(),
        "authority must not normalize malformed native incarnation bytes"
    );
}

#[test]
fn private_settlement_authority_rejects_forged_and_reordered_rosters() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(4);
    let valid = private_settlement_authority_for_keys(&state, &keypairs);
    let forged_keys = (0x41_u8..=0x44)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    let forged = private_settlement_authority_for_keys(&state, &forged_keys);
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &forged,
        )
        .is_err(),
        "four attacker-owned BLS keys are not the pinned native authority"
    );
    let mut reordered = valid;
    reordered.validators.swap(0, 1);
    reordered.validator_pops.swap(0, 1);
    reordered.validator_set_hash = HashOf::new(&reordered.validators);
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &reordered,
        )
        .is_err(),
        "receipt roster must preserve native canonical order"
    );
}

#[test]
fn private_settlement_authority_rejects_recreated_roster_and_stale_incarnation() {
    let (state, original_keys) = exact_private_settlement_authority_fixture(4);
    let original = private_settlement_authority_for_keys(&state, &original_keys);
    let replacement_keys = (0x51_u8..=0x54)
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect::<Vec<_>>();
    seed_committee_consensus_keys_with_pops(&state, &replacement_keys);
    let mut world = state.world.block();
    let record = world
        .sumeragi_lanes
        .get_mut()
        .lane_mut(original.route.lane_id)
        .unwrap();
    record.incarnation = Hash::new(b"recreated native lane").into();
    record.committee = private_settlement_native_members(&replacement_keys);
    record.created_at = 5;
    record.active_from = 7;
    record.merged_at = 7;
    world.commit();
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            7,
            &original,
        )
        .is_err(),
        "retired incarnation cannot authorize its replacement"
    );
    let replacement = private_settlement_authority_for_keys(&state, &replacement_keys);
    crate::private_settlement::validate_private_settlement_committee_authority_v1(
        &state.view(),
        7,
        &replacement,
    )
    .expect("new incarnation's exact pinned roster");
    let mut stale = replacement;
    stale.route.lane_incarnation = original.route.lane_incarnation;
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            7,
            &stale,
        )
        .is_err(),
        "current members cannot authorize an old incarnation"
    );
}

#[test]
fn private_settlement_authority_rejects_non_f1_committee_geometry() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(7);
    let subset = private_settlement_authority_for_keys(&state, &keypairs[..4]);
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &subset,
        )
        .is_err(),
        "a seven-validator native committee cannot supply a four-key subset"
    );
}

#[test]
fn private_settlement_authority_uses_native_activation_and_closing_boundaries() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(4);
    let authority = private_settlement_authority_for_keys(&state, &keypairs);
    let mut world = state.world.block();
    world
        .sumeragi_lanes
        .get_mut()
        .lane_mut(authority.route.lane_id)
        .unwrap()
        .closing = Some(9);
    world.commit();
    for (height, authority_accepted, mutation_accepted) in [
        (0, false, false),
        (2, false, false),
        (3, true, false),
        (4, true, true),
        (8, true, true),
        (9, false, true),
        (10, false, false),
    ] {
        let result = crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            height,
            &authority,
        );
        assert_eq!(
            result.is_ok(),
            authority_accepted,
            "authority height {height}"
        );
        if height != 0 {
            let mut block = state.block(BlockHeader::new(
                height.try_into().unwrap(),
                None,
                None,
                0,
                0,
            ));
            let transaction = block.transaction();
            assert_eq!(
                transaction
                    .ensure_private_settlement_route_active_v1(authority.route)
                    .is_ok(),
                mutation_accepted,
                "pool mutation height {height}"
            );
        }
    }
}

#[test]
fn private_settlement_authority_rejects_wrong_dataspace_and_missing_native_record() {
    let (state, keypairs) = exact_private_settlement_authority_fixture(4);
    let mut authority = private_settlement_authority_for_keys(&state, &keypairs);
    let original_route = authority.route;
    authority.route.dataspace_id = DataSpaceId::new(2);
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &authority,
        )
        .is_err()
    );
    authority.route = original_route;
    let mut world = state.world.block();
    world.sumeragi_lanes.get_mut().lanes.clear();
    world.commit();
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &authority,
        )
        .is_err(),
        "live Committee keys alone do not admit a native lane"
    );
}

#[test]
fn private_settlement_authority_rejects_physical_manifest_as_native_authority() {
    let (state, keypairs) = exact_manifest_authority_fixture(1, 4);
    let members = private_settlement_native_members(&keypairs);
    let validators = members
        .iter()
        .map(|member| member.peer.clone())
        .collect::<Vec<_>>();
    let authority = iroha_data_model::nexus::PrivateSettlementCommitteeAuthorityV1 {
        route: iroha_data_model::nexus::PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::UNIVERSAL,
            lane_id: LaneId::SINGLE,
            lane_incarnation: state.lane_incarnation_at_height(LaneId::SINGLE, 3).unwrap(),
        },
        validator_set_hash: HashOf::new(&validators),
        validators,
        validator_pops: members.into_iter().map(|member| member.pop).collect(),
    };
    assert!(resolve_universal_committee_at(&state, 3).is_ok());
    assert!(
        crate::private_settlement::validate_private_settlement_committee_authority_v1(
            &state.view(),
            3,
            &authority,
        )
        .is_err(),
        "physical manifests do not grant private-settlement native authority"
    );
}

#[test]
fn exact_lane_committee_rejects_f1_pools_of_one_and_three() {
    for available in [1_u8, 3] {
        let (state, _) = exact_manifest_authority_fixture(1, available);
        assert_eq!(
            resolve_universal_committee(&state),
            Err(LaneAuthorityError::UndersizedPool {
                lane_id: LaneId::SINGLE,
                dataspace_id: DataSpaceId::UNIVERSAL,
                authority_height: 1,
                required: 4,
                actual: usize::from(available),
            })
        );
    }
}

#[test]
fn exact_lane_committee_accepts_four_and_stably_samples_larger_f1_pool() {
    let (state, four_keys) = exact_manifest_authority_fixture(1, 4);
    install_malformed_beacon_cursor(&state);
    let four = resolve_universal_committee(&state).expect("exact four-validator committee");
    assert_eq!(four.fault_tolerance(), 1);
    assert_eq!(four.validators().len(), 4);
    assert!(four.validators().windows(2).all(|pair| pair[0] < pair[1]));
    let expected_four = four_keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        four.validators().iter().cloned().collect::<BTreeSet<_>>(),
        expected_four
    );

    let (larger_state, larger_keys) = exact_manifest_authority_fixture(1, 9);
    let height = seed_lane_committee_beacon_for_test(&larger_state);
    let first = resolve_universal_committee_at(&larger_state, height).expect("sample larger pool");
    let second =
        resolve_universal_committee_at(&larger_state, height).expect("repeat larger-pool sample");
    assert_eq!(first, second);
    assert_eq!(first.validators().len(), 4);
    assert!(first.validators().windows(2).all(|pair| pair[0] < pair[1]));
    let eligible = larger_keys
        .iter()
        .map(|key| PeerId::new(key.public_key().clone()))
        .collect::<BTreeSet<_>>();
    assert!(
        first
            .validators()
            .iter()
            .all(|peer| eligible.contains(peer))
    );

    let reversed_validators = larger_keys
        .iter()
        .rev()
        .map(|key| AccountId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    install_lane_manifest_registry(
        &larger_state,
        &[(LaneId::SINGLE, DataSpaceId::UNIVERSAL, reversed_validators)],
    );
    assert_eq!(
        resolve_universal_committee_at(&larger_state, height).expect("order-independent sample"),
        first,
        "manifest declaration order must not influence seeded committee membership"
    );

    let (malformed_larger_state, _) = exact_manifest_authority_fixture(1, 9);
    install_malformed_beacon_cursor(&malformed_larger_state);
    assert_eq!(
        resolve_universal_committee(&malformed_larger_state),
        Err(LaneAuthorityError::InvalidAuthoritySource {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority_height: 1,
        }),
        "an oversized pool must still require verified sampling entropy",
    );
}

#[test]
fn exact_stake_elected_committee_does_not_require_sampling_entropy() {
    let (state, keypairs) = exact_stake_authority_fixture(1, 4);
    install_malformed_beacon_cursor(&state);
    let committee = resolve_universal_committee(&state)
        .expect("exact stake-elected committee must not consult sampling entropy");
    let expected = keypairs
        .iter()
        .map(|keypair| PeerId::new(keypair.public_key().clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        committee
            .validators()
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        expected,
    );
}

#[test]
fn exact_lane_committee_selects_seven_for_f2() {
    let (state, _) = exact_manifest_authority_fixture(2, 11);
    let height = seed_lane_committee_beacon_for_test(&state);
    let committee = resolve_universal_committee_at(&state, height).expect("f=2 committee");
    assert_eq!(committee.fault_tolerance(), 2);
    assert_eq!(committee.validators().len(), 7);
    assert!(
        committee
            .validators()
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
}

#[test]
fn exact_lane_committee_rejects_same_lane_on_wrong_dataspace() {
    let (state, _) = exact_manifest_authority_fixture(1, 4);
    let other = DataSpaceId::new(9);
    let mut nexus = state.nexus_snapshot();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: other,
            alias: "other".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("two-dataspace catalog");
    install_existing_nexus_geometry_for_test(&state, nexus);
    assert_eq!(
        state.resolve_lane_committee_at_height(LaneAuthorityRoute::new(LaneId::SINGLE, other), 1,),
        Err(LaneAuthorityError::InactiveRoute {
            lane_id: LaneId::SINGLE,
            dataspace_id: other,
            authority_height: 1,
        })
    );
}

#[test]
fn exact_lane_committee_rejects_manifest_dataspace_mismatch() {
    let (state, keys) = exact_manifest_authority_fixture(1, 4);
    let other = DataSpaceId::new(9);
    let mut nexus = state.nexus_snapshot();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![
        DataSpaceMetadata::default(),
        DataSpaceMetadata {
            id: other,
            alias: "other".to_owned(),
            description: None,
            fault_tolerance: 1,
        },
    ])
    .expect("two-dataspace catalog");
    install_existing_nexus_geometry_for_test(&state, nexus);
    let validators = keys
        .iter()
        .map(|key| AccountId::new(key.public_key().clone()))
        .collect();
    let retained = resolve_universal_committee(&state).expect("valid canonical manifest authority");
    let stale =
        stale_lane_manifest_registry_for_test(&state, &[(LaneId::SINGLE, other, validators)]);
    assert_eq!(
        resolve_universal_committee(&state)
            .expect("a stale process cache cannot replace canonical manifest authority")
            .validators(),
        retained.validators(),
    );
    // Retain the deliberately malformed source in an isolated resolver view.
    let mut view = state.view();
    view.lane_manifests = stale;
    assert!(matches!(
        view.resolve_lane_committee_at_height(
            LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            1,
        ),
        Err(LaneAuthorityError::InvalidAuthoritySource {
            lane_id: LaneId::SINGLE,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority_height: 1,
        })
    ));
}

#[test]
fn exact_stake_committee_reselects_then_fails_closed_across_peer_churn() {
    let state = blank_test_state();
    let height = seed_lane_committee_beacon_for_test(&state);
    let keypairs = (0x31_u8..=0x35)
        .map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic stake-authority BLS key")
        })
        .collect::<Vec<_>>();
    seed_consensus_keys_with_pops(&state, &keypairs);
    for (index, keypair) in keypairs.iter().enumerate() {
        insert_active_public_lane_validator_for_test(
            &state,
            LaneId::SINGLE,
            &AccountId::new(keypair.public_key().clone()),
            keypair,
            1_000_000_u64.saturating_sub(u64::try_from(index).expect("small index")),
        );
    }
    let first = resolve_universal_committee_at(&state, height).expect("initial stake committee");
    assert_eq!(first.validators().len(), 4);
    remove_world_peer_for_test(&state, &first.validators()[0]);
    let replacement =
        resolve_universal_committee_at(&state, height).expect("replacement stake committee");
    assert_eq!(replacement.validators().len(), 4);
    assert_ne!(replacement.validators(), first.validators());
    remove_world_peer_for_test(&state, &replacement.validators()[0]);
    assert!(matches!(
        resolve_universal_committee_at(&state, height),
        Err(LaneAuthorityError::UndersizedPool {
            required: 4,
            actual: 3,
            ..
        })
    ));
}

#[test]
fn exact_stake_committee_rejects_split_dataspace_projections() {
    let state = blank_test_state();
    let second_lane = LaneId::new(1);
    let mut nexus = state.nexus_snapshot();
    nexus.lane_catalog = LaneCatalog::new(
        nonzero!(2_u32),
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: second_lane,
                alias: "universal-sibling".to_owned(),
                dataspace_id: DataSpaceId::UNIVERSAL,
                ..LaneConfig::default()
            },
        ],
    )
    .expect("two-lane shared-dataspace catalog");
    install_existing_nexus_geometry_for_test(&state, nexus);
    let keypairs = (0x41_u8..=0x44)
        .map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic split-projection BLS key")
        })
        .collect::<Vec<_>>();
    seed_consensus_keys_with_pops(&state, &keypairs);
    for (index, keypair) in keypairs.iter().enumerate() {
        let lane_id = if index < 2 {
            LaneId::SINGLE
        } else {
            second_lane
        };
        insert_active_public_lane_validator_for_test(
            &state,
            lane_id,
            &AccountId::new(keypair.public_key().clone()),
            keypair,
            1_000_000,
        );
    }
    assert!(matches!(
        resolve_universal_committee(&state),
        Err(LaneAuthorityError::InvalidAuthoritySource { .. })
    ));
}

#[test]
fn exact_lane_committee_rejects_one_of_one_geometry_and_autoscale_pin() {
    let invalid_geometry = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: DataSpaceId::UNIVERSAL,
        alias: "universal".to_owned(),
        description: None,
        fault_tolerance: 0,
    }])
    .expect_err("f=0 would create a forbidden one-of-one committee");
    assert!(matches!(
        invalid_geometry,
        iroha_data_model::nexus::DataSpaceCatalogError::InvalidFaultTolerance {
            id: DataSpaceId::UNIVERSAL,
            fault_tolerance: 0,
        }
    ));

    let autoscale_state = blank_test_state();
    let lane_id = LaneId::new(1);
    let one_key = KeyPair::try_from_seed(vec![0x55; 32], Algorithm::BlsNormal)
        .expect("deterministic one-member autoscale key");
    let lane = autoscale_elastic_catalog_lane_with_committee_for_test(
        lane_id,
        1,
        std::slice::from_ref(&one_key),
    );
    install_autoscale_elastic_catalog_for_test(&autoscale_state, lane);
    assert_eq!(
        autoscale_state.resolve_lane_committee_at_height(
            LaneAuthorityRoute::new(lane_id, DataSpaceId::UNIVERSAL),
            1,
        ),
        Err(LaneAuthorityError::InactiveRoute {
            lane_id,
            dataspace_id: DataSpaceId::UNIVERSAL,
            authority_height: 1,
        })
    );
}

#[test]
fn exact_autoscale_committee_keeps_its_four_member_incarnation_pin() {
    let state = blank_test_state();
    let lane_id = LaneId::new(1);
    let keypairs = (0x61_u8..=0x64)
        .map(|seed| {
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic autoscale pin BLS key")
        })
        .collect::<Vec<_>>();
    let lane = autoscale_elastic_catalog_lane_with_committee_for_test(lane_id, 1, &keypairs);
    install_autoscale_elastic_catalog_for_test(&state, lane);
    let route = LaneAuthorityRoute::new(lane_id, DataSpaceId::UNIVERSAL);
    let pinned = state
        .resolve_lane_committee_at_height(route, 1)
        .expect("exact autoscale pin");
    assert_eq!(pinned.validators().len(), 4);
    seed_consensus_keys_with_pops(&state, &keypairs);
    remove_world_peer_for_test(&state, &pinned.validators()[0]);
    assert_eq!(
        state
            .resolve_lane_committee_at_height(route, 1)
            .expect("immutable pin survives live churn"),
        pinned
    );
}
