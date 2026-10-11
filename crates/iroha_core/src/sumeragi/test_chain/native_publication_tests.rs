// Native signed-genesis, exact-quorum publication and original Worker custody controls.

#[test]
fn original_genesis_and_successor_have_exact_native_execution_authority() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
    let state = Arc::clone(chain.state());
    let first = chain.committed(1);
    assert_eq!(state.committed_height(), 1);
    assert_eq!(state.latest_block_hash_fast(), Some(first.block().hash()));
    assert!(
        first
            .block()
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );
    let initial = &first.commitment().schedule.current;
    assert_eq!(initial.authorization.authority_generation, 0);
    assert_eq!(
        initial.generation().generation_id().unwrap(),
        initial.authorization.authority_id
    );
    assert!(
        startup::apply_genesis(
            &state,
            chain.genesis().clone(),
            chain.genesis_account(),
            ConsensusMode::Permissioned,
            None,
        )
        .is_err(),
        "already applied genesis cannot seed another execution"
    );
    let mut prefix = super::super::super::certified_chain::CertifiedPrefix::new(
        state.chain_id_ref(),
        chain.network_id(),
        first.block().clone(),
    )
    .unwrap();
    chain.commit_at(2000, Vec::new());
    let second = chain.committed(2);
    let (certified, anchor) = prefix.push(second.block().clone()).unwrap().into_parts();
    assert_eq!(certified.core_hash(), second.core_hash());
    assert_eq!(
        anchor
            .expect("actual exact H2 quorum binds original H1 result")
            .into_committed()
            .result(),
        first.result()
    );
    assert_eq!(second.header().unwrap().parent_result, first.result());
    assert_eq!(second.header().unwrap().parent_hash, first.core_hash());

    let (_, qc) = chain.committed_body(2).unwrap().unwrap();
    assert_eq!(qc.signers.count_ones(), 3);

    assert!(
        second
            .block()
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );
    assert_eq!(state.committed_height(), 2);
    assert_eq!(state.latest_block_hash_fast(), Some(second.block().hash()));
}

#[test]
fn foreign_execution_certificate_cannot_prepare_original_worker() {
    let mut source = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
    let mut foreign = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
    foreign.commit_at(3000, Vec::new());
    let foreign_committed = foreign.committed(2);
    let foreign_qc = foreign.commit_qc(
        2,
        foreign_committed.core_hash(),
        foreign_committed.result(),
        Signers::Quorum,
    );
    let state = Arc::clone(source.state());
    let kura = Arc::clone(source.kura());
    let proposal = source.proposal(Some(2000), Vec::new());
    let mut pending = source.begin_proposal(proposal, Default::default()).unwrap();
    let original_result = pending.result();
    assert!(
        pending
            .chain
            .executor
            .prepare(&pending.block, &foreign_qc)
            .is_err()
    );
    assert_eq!(
        kura.blocks_count(),
        1,
        "no different execution may authorize a durable frame"
    );
    assert_eq!(pending.result(), original_result);
    let published = pending.publish(Signers::Quorum).unwrap();
    assert_eq!(published.result(), original_result);
    drop(pending);
    assert_eq!(state.view().height(), 2);
}

#[test]
fn publication_requires_the_original_nonempty_captured_witness() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
    let kura = Arc::clone(chain.kura());
    let proposal = chain.proposal(Some(2000), Vec::new());
    let mut pending = chain.begin_proposal(proposal, Default::default()).unwrap();
    pending
        .inspect(|mut original| {
            assert!(!original.witness.writes.is_empty());
            original.witness.offer_reconstructed_tamper(|offered| {
                *offered = Default::default();
            });
        })
        .unwrap();
    let error = pending.prepare(Signers::Quorum).unwrap_err();
    assert!(error.contains("actual captured witness"));
    assert_eq!(kura.blocks_count(), 1);
}

#[test]
fn original_signed_genesis_refuses_foreign_validator_custody() {
    let mut prepared =
        CertifiedTestChain::prepare(TestChainConfig::new(World::new(), 1000)).unwrap();
    prepared.validator_keys = (0xB0..=0xB3)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect();
    prepared
        .validator_keys
        .sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let state = Arc::clone(&prepared.state);
    let kura = Arc::clone(&prepared.kura);
    let error = CertifiedTestChain::from_prepared(prepared).unwrap_err();
    assert!(
        error
            .error
            .to_string()
            .contains("exact ordered signed genesis seats")
    );
    assert!(Arc::ptr_eq(&error.state, &state));
    assert_eq!(state.view().height(), 0);
    assert_eq!(kura.blocks_count(), 0);
}

#[test]
fn missing_genesis_authority_is_created_by_its_original_signed_registration() {
    let key = KeyPair::from_seed(vec![0xA9; 32], Algorithm::Ed25519);
    let account = AccountId::new(key.public_key().clone());
    let validators = fixture_validators();
    let chain_id = ChainId::from("native-genesis-self-registration");
    let (_, manifest) = build_genesis(
        &chain_id,
        &key,
        &validators,
        Vec::new(),
        Vec::new(),
        SumeragiConsensusMode::Permissioned,
        iroha_data_model::block::consensus::SumeragiRootScope::Global,
        1000,
        std::num::NonZeroU64::MIN,
    )
    .unwrap();
    // Express a supported raw manifest whose first transaction is the exact account
    // self-registration. The original parameter/topology batches remain byte-for-byte source
    // inputs and the complete resulting manifest is independently signed and authenticated.
    let mut value = norito::json::to_value(&manifest).unwrap();
    let registration = iroha_genesis::genesis_instructions_json::instructions_to_value(&[
        iroha_data_model::isi::Register::account(Account::new(account.clone())).into(),
    ]);
    value
        .as_object_mut()
        .unwrap()
        .get_mut("transactions")
        .unwrap()
        .as_array_mut()
        .unwrap()
        .insert(
            0,
            norito::json!({"instructions": registration, "ivm_triggers": [], "topology": []}),
        );
    let manifest: iroha_genesis::RawGenesisTransaction =
        norito::json::from_str(&norito::json::to_json(&value).unwrap()).unwrap();
    let genesis = manifest
        .clone()
        .build_and_sign_with_da_proof_policies_and_confidential_policy_hash_at(
            &key, None, None, 1000,
        )
        .unwrap()
        .0;
    let world = World::with(
        [Domain::new(iroha_genesis::GENESIS_DOMAIN_ID.clone()).build(&account)],
        [],
        [],
    );
    assert!(world.accounts.view().get(&account).is_none());
    let (genesis, manifest, state, kura) = prepare_configured_genesis(
        world,
        &chain_id,
        &key,
        &validators,
        genesis,
        manifest,
        SumeragiConsensusMode::Permissioned,
        1000,
        &iroha_config::parameters::actual::Pipeline::default(),
        &iroha_config::parameters::actual::FraudMonitoring::default(),
        None,
        None,
        None,
        None,
        None,
    )
    .unwrap();
    assert!(
        state.view().world().account(&account).is_err(),
        "unpublished policy derivation must roll registration back"
    );
    let signed = iroha_genesis::validate_prepared_genesis_bundle(
        &genesis.encode_wire().unwrap(),
        &manifest,
        key.public_key(),
        genesis.hash(),
    )
    .unwrap();
    let mut chain = CertifiedTestChain::from_prepared(PreparedTestChainConfig {
        genesis: signed,
        manifest,
        state: Arc::clone(&state),
        kura: Arc::clone(&kura),
        validator_keys: fixture_keys(),
        clock: key,
        lane_blocks: Arc::new(crate::sumeragi::lanes::merge::NoLanes),
    })
    .unwrap();
    assert!(state.view().world().account(&account).is_ok());
    assert_eq!(state.committed_height(), 1);
    assert_eq!(
        state.latest_block_hash_fast(),
        Some(chain.committed(1).block().hash())
    );
    assert!(
        chain
            .committed(1)
            .block()
            .output_results()
            .all(|result| result.as_ref().is_ok())
    );
    chain.commit_at(2000, Vec::new());
    assert_eq!(
        state.committed_height(),
        2,
        "the original newly registered authority signs actual successor work"
    );
}
