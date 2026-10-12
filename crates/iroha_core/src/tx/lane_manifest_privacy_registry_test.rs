#[test]
fn install_lane_manifests_updates_privacy_registry() {
    let chain: ChainId = "lane-privacy-registry".parse().unwrap();
    let world = World::default();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let state = State::new_with_chain(world, kura, query_handle, chain);
    let commitment = LanePrivacyCommitment::merkle(
        LaneCommitmentId::new(9),
        MerkleCommitment::from_root_bytes([0x11; 32], 8),
    );
    let status = LaneManifestStatus {
        lane: TestLaneId::SINGLE,
        alias: "private".to_string(),
        dataspace: TestDataSpaceId::UNIVERSAL,
        visibility: LaneVisibility::Public,
        storage: LaneStorageProfile::CommitmentOnly,
        governance: None,
        manifest_path: Some(PathBuf::from("/tmp/privacy.json")),
        governance_rules: None,
        privacy_commitments: vec![commitment],
    };
    let mut statuses = BTreeMap::new();
    statuses.insert(TestLaneId::SINGLE, status);
    let registry = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    state.install_lane_manifests_for_testing(&registry);
    let snapshot = state.lane_privacy_registry.read().clone();
    assert!(!snapshot.is_empty(), "privacy registry should not be empty");
    assert!(
        snapshot.lane(TestLaneId::SINGLE).is_some(),
        "privacy registry should contain lane entry"
    );
}

#[test]
fn transaction_privacy_admission_uses_manifest_when_cache_is_stale() {
    let chain: ChainId = "lane-privacy-cache-independent".parse().unwrap();
    let (world, authority, keypair) = world_with_authority("wonderland");
    let state = State::new_with_chain(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        chain,
    );
    let commitment_id = LaneCommitmentId::new(17);
    let witness = iroha_crypto::privacy::MerkleWitness::new(
        [0x12; 32],
        MerkleProof::from_audit_path_bytes(0, vec![[0x34; 32]]),
    );
    let root = witness.implied_root(8).unwrap();
    let commitment = LanePrivacyCommitment::merkle(commitment_id, MerkleCommitment::new(root, 8));
    let mut status = LaneManifestStatus {
        lane: TestLaneId::SINGLE,
        alias: "private".to_owned(),
        dataspace: TestDataSpaceId::UNIVERSAL,
        visibility: LaneVisibility::Public,
        storage: LaneStorageProfile::FullReplica,
        governance: None,
        manifest_path: Some(PathBuf::from("/tmp/privacy-cache-independent.json")),
        governance_rules: None,
        privacy_commitments: vec![commitment],
    };
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::from([(
        TestLaneId::SINGLE,
        status.clone(),
    )])));
    let backend = Ident::from_str("halo2/ipa").unwrap();
    let mut attachment = ProofAttachment::new_ref(
        backend.clone(),
        ProofBox::new(backend.clone(), vec![0xAA]),
        VerifyingKeyId::new(backend, "privacy-cache-independent"),
    );
    attachment.lane_privacy = Some(LanePrivacyProof {
        commitment_id,
        witness: LanePrivacyWitness::Merkle(LanePrivacyMerkleWitness {
            leaf: *witness.leaf(),
            proof: witness.proof().clone(),
        }),
    });
    let tx = TransactionBuilder::new(
        test_network_id(),
        authority,
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Log::new(Level::INFO, "privacy admission".into())])
    .with_proof_attachments(vec![attachment])
    .expect("valid proof carriers")
    .sign(keypair.private_key());

    {
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        block.lane_manifests = Arc::clone(&manifests);
        block.lane_privacy_registry = Arc::new(LanePrivacyRegistry::empty());
        let stx = block.transaction();
        let assignment = single_lane_assignment(&stx.nexus.dataspace_catalog);
        assert!(
            super::enforce_lane_policies(&tx, &stx, &assignment).is_ok(),
            "empty cached privacy cannot reject a proof authorized by the manifest"
        );
    }

    status.privacy_commitments.clear();
    let revoked = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::from([(
        TestLaneId::SINGLE,
        status,
    )])));
    let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
    block.lane_manifests = revoked;
    block.lane_privacy_registry = Arc::new(LanePrivacyRegistry::from_manifest_registry(&manifests));
    let stx = block.transaction();
    let assignment = single_lane_assignment(&stx.nexus.dataspace_catalog);
    let error = super::enforce_lane_policies(&tx, &stx, &assignment).unwrap_err();
    assert!(matches!(
        error,
        TransactionRejectionReason::Validation(ValidationFail::NotPermitted(message))
            if message.contains("lane privacy proof rejected")
    ));
}
