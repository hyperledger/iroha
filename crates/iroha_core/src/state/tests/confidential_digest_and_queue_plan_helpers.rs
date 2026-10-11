// Confidential policy and current State fixture helpers.
state_test! { sync confidential_digest_respects_activation_height
    use iroha_data_model::{
        confidential::ConfidentialStatus,
        proof::{VerifyingKeyId, VerifyingKeyRecord},
        zk::BackendTag,
    };
    let mut world = World::new();
    let id = VerifyingKeyId::new("halo2/ipa", "vk_activation");
    let_row! { mut record = VerifyingKeyRecord::new_with_owner( 1, "circuit_activation", None, "core", BackendTag::NativePipaRPasta, "pallas", [0x11; 32], [0x22; 32], ) };
    record.status = ConfidentialStatus::Proposed;
    record.activation_height = Some(5);
    record.gas_schedule_id = Some("sched_activation".into());
    record.public_inputs_schema_hash = [0x33; 32];
    world.verifying_keys.insert(id.clone(), record.clone());
    world
        .verifying_keys_by_circuit
        .insert((record.circuit_id.clone(), record.version), id.clone());
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new(world, kura, query);
    state.zk.registry_max_delta_per_block = 10;
    let view = state.view();
    let_row! { digest_before = compute_confidential_feature_digest(view.world(), &view.zk, 4) };
    assert_eq!(digest_before.vk_set_hash, None);
    let_row! { digest_at_activation = compute_confidential_feature_digest(view.world(), &view.zk, 5) };
    assert!(digest_at_activation.vk_set_hash.is_some());
}
state_test! { sync confidential_digest_excludes_active_vk_outside_height_window
    use iroha_data_model::{
        confidential::ConfidentialStatus,
        proof::{VerifyingKeyId, VerifyingKeyRecord},
        zk::BackendTag,
    };
    let mut world = World::new();
    let id = VerifyingKeyId::new("halo2/ipa", "vk_windowed_active");
    let_row! { mut record = VerifyingKeyRecord::new_with_owner( 1, "circuit_windowed_active", None, "core", BackendTag::NativePipaRPasta, "pallas", [0x21; 32], [0x42; 32], ) };
    record.status = ConfidentialStatus::Active;
    record.activation_height = Some(5);
    record.withdraw_height = Some(8);
    record.gas_schedule_id = Some("sched_windowed_active".into());
    record.public_inputs_schema_hash = [0x63; 32];
    world.verifying_keys.insert(id.clone(), record.clone());
    world
        .verifying_keys_by_circuit
        .insert((record.circuit_id.clone(), record.version), id);
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let state = State::new(world, kura, query);
    let view = state.view();
    assert_eq!(compute_vk_set_hash_at_height(view.world(), 4), None);
    assert!(compute_vk_set_hash_at_height(view.world(), 5).is_some());
    assert_eq!(compute_vk_set_hash_at_height(view.world(), 8), None);
    let_row! { digest_before = compute_confidential_feature_digest(view.world(), &view.zk, 4) };
    assert_eq!(digest_before.vk_set_hash, None);
    let_row! { digest_active = compute_confidential_feature_digest(view.world(), &view.zk, 5) };
    assert!(digest_active.vk_set_hash.is_some());
    let_row! { digest_withdrawn = compute_confidential_feature_digest(view.world(), &view.zk, 8) };
    assert_eq!(digest_withdrawn.vk_set_hash, None);
}
state_test! { sync confidential_registry_delta_cap_limits_transitions
    use iroha_data_model::{
        confidential::ConfidentialStatus,
        proof::{VerifyingKeyId, VerifyingKeyRecord},
        zk::BackendTag,
    };
    let mut world = World::new();
    let_row! { ids = [ VerifyingKeyId::new("halo2/ipa", "vk_alpha"), VerifyingKeyId::new("halo2/ipa", "vk_beta"), ] };
    for (idx, id) in ids.iter().enumerate() {
        let_row! { mut record = VerifyingKeyRecord::new_with_owner( 1, format!("circuit_{idx}"), None, "core", BackendTag::NativePipaRPasta, "pallas", [0x40 + u8::try_from(idx).expect("vk index fits in u8"); 32], [0x50 + u8::try_from(idx).expect("vk index fits in u8"); 32], ) };
        record.status = ConfidentialStatus::Proposed;
        record.activation_height = Some(2);
        record.gas_schedule_id = Some(format!("sched_{idx}"));
        record.public_inputs_schema_hash =
            [0x60 + u8::try_from(idx).expect("vk index fits in u8"); 32];
        world.verifying_keys.insert(id.clone(), record.clone());
        world
            .verifying_keys_by_circuit
            .insert((record.circuit_id.clone(), record.version), id.clone());
    }
    let kura = Kura::blank_kura_for_testing();
    let query = LiveQueryStore::start_test();
    let mut state = State::new(world, kura, query);
    state.zk.registry_max_delta_per_block = 1;
    let header = BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 0, 0);
    let block = state.block(header);
    let_row! { alpha_status = block .world .verifying_keys .get(&ids[0]) .map(|rec| rec.status) .expect("alpha vk present") };
    let_row! { beta_status = block .world .verifying_keys .get(&ids[1]) .map(|rec| rec.status) .expect("beta vk present") };
    assert_eq!(alpha_status, ConfidentialStatus::Active);
    assert_eq!(beta_status, ConfidentialStatus::Proposed);
}
fn assemble_ivm_header(code: &[u8]) -> Vec<u8> {
    let_row! { mut blob = ivm::ProgramMetadata { version_major: 1, version_minor: 1, mode: 0, vector_length: 0, max_cycles: 1_000_000, abi_version: 1, } .encode() };
    blob.extend_from_slice(code);
    blob
}
/// Used to inject faulty payload for testing
fn new_dummy_block_with_payload(f: impl FnOnce(&mut BlockHeader)) -> CommittedBlock {
    let_row! { (leader_public_key, leader_private_key) = crate::state::checked_keypair_with_algorithm(iroha_crypto::Algorithm::BlsNormal) .into_parts() };
    let peer_id = PeerId::new(leader_public_key);
    let topology = Topology::new(vec![peer_id]);
    let mut block = ValidBlock::new_dummy_and_modify_header(&leader_private_key, f);
    block
        .as_mut()
        .set_execution_outputs(
            Vec::new(),
            0,
            BTreeMap::new(),
            Vec::new(),
            AxtPolicySnapshot::default(),
            Default::default(),
            &crate::execution_output_test_support::structural_output_limits(),
        )
        .expect("empty fixture block has complete execution metadata");
    let signature = iroha_data_model::block::BlockSignature::new(
        0,
        SignatureOf::from_hash(&leader_private_key, block.as_ref().hash()),
    );
    block
        .as_mut()
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([signature])
                .expect("at most 31 block signatures"),
        )
        .expect("replace signature after completing fixture execution metadata");
    block
        .commit(&topology, crate::block::reserve_block_for_tests())
        .unpack(|_| {})
        .unwrap()
}
fn set_commit_topology_from_keypairs(state: &State, keypairs: &[KeyPair]) {
    let mut topo = state.commit_topology.block();
    topo.clear();
    for keypair in keypairs {
        topo.push(PeerId::new(keypair.public_key().clone()));
    }
    topo.commit();
}
fn configure_commit_topology(state: &State, count: usize) -> Vec<KeyPair> {
    let mut peers = Vec::with_capacity(count);
    let mut keypairs = Vec::with_capacity(count);
    for _ in 0..count {
        let_row! { keypair = crate::state::checked_keypair_with_algorithm(iroha_crypto::Algorithm::BlsNormal) };
        peers.push(PeerId::new(keypair.public_key().clone()));
        keypairs.push(keypair);
    }
    let mut topo = state.commit_topology.block();
    topo.clear();
    for peer in peers {
        topo.push(peer);
    }
    topo.commit();
    let_row! { committed_peers: Vec<_> = keypairs .iter() .map(|keypair| PeerId::new(keypair.public_key().clone())) .collect() };
    let mut world_block = state.world.block();
    {
        let mut peers = world_block.peers_mut_for_testing().transaction();
        for peer in committed_peers {
            if !peers.iter().any(|existing| existing == &peer) {
                peers.push(peer);
            }
        }
        peers.apply();
    }
    world_block.commit();
    seed_consensus_keys_with_pops(state, &keypairs);
    keypairs
}
fn configure_commit_topology_preserving_world_peers(state: &State, count: usize) -> Vec<KeyPair> {
    let_row! { keypairs: Vec<_> = (0..count) .map(|_| crate::state::checked_keypair_with_algorithm(iroha_crypto::Algorithm::BlsNormal)) .collect() };
    set_commit_topology_from_keypairs(state, &keypairs);
    // These component-test signing keys are not registered network validators.
    // Adding them to World peers silently changes every route's global committee.
    let mut world = state.world.block();
    seed_consensus_key_records_with_pops(&mut world, &keypairs);
    world.commit();
    keypairs
}

state_test!(consensus_stack component_commit_topology_preserves_scheduled_network_authority
    component_commit_topology_preserves_scheduled_network_authority_on_consensus_stack();
);
fn component_commit_topology_preserves_scheduled_network_authority_on_consensus_stack() {
    let chain = crate::sumeragi::test_chain::CertifiedTestChain::start(
        crate::sumeragi::test_chain::TestChainConfig::new(World::default(), 1_000),
    )
    .expect("authenticated global committee");
    let state = chain.state();
    let before = state
        .view()
        .world
        .peers()
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let expected = crate::sumeragi::schedule::scheduled_committee(state.view().world(), 1)
        .expect("four registered validators have current consensus keys");
    assert_eq!(expected.len(), 4);

    assert_eq!(
        crate::state::lane_authority::resolve_global_route(
            state.view().world(),
            LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            &state.nexus_snapshot(),
            1,
        )
        .expect("original scheduled route authority")
        .into_validators(),
        expected,
    );
    let component_keys = configure_commit_topology_preserving_world_peers(&state, 1);
    let view = state.view();
    assert_eq!(
        view.world.peers().iter().cloned().collect::<Vec<_>>(),
        before
    );
    assert_eq!(
        crate::state::lane_authority::resolve_global_route(
            view.world(),
            LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
            &view.nexus,
            1,
        )
        .expect("component signing metadata does not alter route authority")
        .into_validators(),
        expected,
    );
    assert_eq!(
        view.commit_topology.iter().cloned().collect::<Vec<_>>(),
        component_keys
            .iter()
            .map(|key| PeerId::new(key.public_key().clone()))
            .collect::<Vec<_>>(),
    );
    assert!(
        matches!(
            view.resolve_lane_committee_at_height(
                LaneAuthorityRoute::new(LaneId::SINGLE, DataSpaceId::UNIVERSAL),
                1,
            ),
            Err(LaneAuthorityError::UndersizedPool {
                required: 4,
                actual: 0,
                ..
            })
        ),
        "component signing keys do not invent independent lane authority"
    );
    for key in &component_keys {
        for id in [
            derive_validator_key_id(key.public_key()),
            derive_committee_key_id(key.public_key()),
        ] {
            assert!(view.world.consensus_keys().get(&id).is_some());
        }
    }
}
