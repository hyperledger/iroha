#[test]
fn genesis_preexecution_preserves_selected_profile_across_threads() {
    use iroha_data_model::account::address::{ChainDiscriminantGuard, chain_discriminant};

    let _ambient = ChainDiscriminantGuard::enter(777);
    let network = build_with_isolated_permit(
        NetworkBuilder::new()
            .with_peers(4)
            .with_npos_consensus()
            .with_config_layer(|layer| {
                layer
                    .write("chain", "fc56984b-2be7-431d-840e-21514d1883f0")
                    .write("chain_discriminant", 369_i64);
            }),
    );
    assert_eq!(chain_discriminant(), 777, "builder leaked its profile");
    let genesis = network.genesis();
    assert_eq!(
        chain_discriminant(),
        777,
        "genesis getter leaked its profile"
    );
    let layers = network
        .config_layers()
        .map(Cow::into_owned)
        .collect::<Vec<_>>();
    let actual = resolve_final_actual_config(&network.peers[0], &layers);
    assert_eq!(*actual.common.chain_discriminant.value(), 369);
    let topology = network
        .peers
        .iter()
        .map(NetworkPeer::id)
        .collect::<Vec<_>>();
    let topology_entries = network.topology_entries.clone();
    let genesis_key_pair = network.genesis_key_pair.clone();
    let extra = network.genesis_isi.clone();
    let post_topology = network.genesis_post_topology_isi.clone();
    let chain = network.chain_id();
    let handshake = consensus_handshake_parameter(&network.consensus_profile);
    let expected_nexus = CryptoHash::prehashed(
        network
            .consensus_profile
            .params
            .sumeragi_context
            .nexus_amx_context_hash,
    );
    let expected_execution = CryptoHash::prehashed(
        network
            .consensus_profile
            .params
            .sumeragi_context
            .execution_policy_hash,
    );

    std::thread::spawn(move || {
        let _foreign = ChainDiscriminantGuard::enter(888);
        let genesis_account = AccountId::new(genesis_key_pair.public_key().clone());
        // Call the native executor directly. A validated Network cache cannot satisfy this
        // assertion or mask a missing execution profile after the builder has returned.
        let (executed, staged) = config::preexecute_genesis_with_runtime_config(
            &genesis,
            &genesis_account,
            &topology,
            &genesis_key_pair,
            None,
            None,
            None,
            Some(&actual),
        )
        .expect("selected-profile signed genesis must execute on a foreign-profile thread");
        assert!(
            executed
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        assert_eq!(staged.nexus_amx, expected_nexus);
        assert_eq!(staged.execution_policy, expected_execution);
        assert_eq!(chain_discriminant(), 888, "preexecution leaked its profile");

        // This independent generator constructs the permission JSON on this worker before
        // entering preexecution, so the generation boundary must also own its profile.
        let (generated, generated_staged, _) =
            config::genesis_with_keypair_and_post_topology_with_policies_and_staged_hash(
                extra,
                post_topology,
                topology.iter().cloned().collect(),
                topology_entries,
                genesis_key_pair.clone(),
                chain,
                Some(config::manifest_crypto_from_actual(&actual.crypto)),
                Some(iroha_core::da::proof_policy_bundle(
                    &actual.nexus.lane_config,
                )),
                None,
                Some(actual.nexus.clone()),
                Some(actual.zk.clone()),
                Some(actual.clone()),
                Some(handshake),
                None,
                Some(iroha_core::state::default_genesis_confidential_policy_hash()),
            );
        assert!(
            generated
                .0
                .output_results()
                .all(|result| result.as_ref().is_ok())
        );
        assert_eq!(generated_staged.nexus_amx, expected_nexus);
        assert_eq!(generated_staged.execution_policy, expected_execution);
        assert_eq!(chain_discriminant(), 888, "generation leaked its profile");

        // An explicitly wrong prefix is an error even when the caller's ambient profile
        // agrees with that wrong prefix. The supplied runtime configuration remains authority.
        let mut wrong = actual;
        wrong.nexus.staking.stake_escrow_account_id = ALICE_ID
            .to_i105_for_discriminant(888)
            .expect("foreign literal");
        // Test fresh execution of the signed inputs under the invalid config.
        // Replaying the successful output claim would instead correctly reject
        // its committed fragment count before recording the new rejection.
        let proposal = GenesisBlock(
            genesis
                .0
                .canonical_resultless_proposal()
                .expect("valid original proposal"),
        );
        assert!(proposal.0.is_resultless_proposal());
        assert_eq!(proposal.0.header(), genesis.0.header());
        assert_eq!(proposal.0.hash(), genesis.0.hash());
        assert!(proposal.0.external_transactions().next().is_some());
        let error = config::preexecute_genesis_with_runtime_config(
            &proposal,
            &genesis_account,
            &topology,
            &genesis_key_pair,
            None,
            None,
            None,
            Some(&wrong),
        )
        .expect_err("explicit foreign staking account must remain rejected");
        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("nexus.staking.stake_escrow_account_id"),
            "{diagnostic}"
        );
        assert!(
            diagnostic.contains("ERR_UNEXPECTED_NETWORK_PREFIX"),
            "{diagnostic}"
        );
        assert_eq!(
            chain_discriminant(),
            888,
            "failed execution leaked its profile"
        );
    })
    .join()
    .expect("profile-aware native genesis worker must complete");
    assert_eq!(chain_discriminant(), 777, "worker changed caller profile");
}

fn assert_signed_generation_zero_is_the_voter_roster(network: &Network) {
    let epoch = iroha_data_model::sumeragi_finality::authenticated_genesis(&network.genesis().0)
        .map(|genesis| genesis.into_parts().0)
        .expect("genesis must commit a canonical native epoch");
    let mut expected = network
        .validators()
        .iter()
        .map(|peer| {
            assert!(
                get_nested_value(
                    &peer.base_config_table(),
                    &["sumeragi", "mint_finality_seed_fd"]
                )
                .is_none(),
                "no voter launches with a retired seed descriptor"
            );
            peer.id()
        })
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(epoch.authorization.authority_generation, 0);
    assert_eq!(
        epoch.generation().validators,
        expected,
        "signed generation zero is exactly the ordered voter roster"
    );
    assert_eq!(
        epoch.authorization.authority_id,
        epoch.generation().generation_id().unwrap()
    );
}

#[test]
fn generated_genesis_generation_zero_is_the_signed_voter_roster() {
    let network =
        build_with_isolated_permit(NetworkBuilder::new().with_peers(4).with_npos_consensus());
    assert_signed_generation_zero_is_the_voter_roster(&network);
}

#[test]
fn permissioned_and_custom_npos_genesis_sign_their_voter_roster() {
    init_instruction_registry();
    let permissioned = build_with_isolated_permit(NetworkBuilder::new().with_peers(4));
    assert_signed_generation_zero_is_the_voter_roster(&permissioned);
    let custom_npos = build_with_isolated_permit(
        NetworkBuilder::new()
            .with_peers(4)
            .with_npos_consensus()
            .with_genesis_block(|topology, topology_entries| {
                unexecuted_genesis_factory_with_post_topology(
                    Vec::new(),
                    Vec::new(),
                    topology,
                    topology_entries,
                )
            }),
    );
    assert_signed_generation_zero_is_the_voter_roster(&custom_npos);
}
