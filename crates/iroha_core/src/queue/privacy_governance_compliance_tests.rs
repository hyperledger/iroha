#[test]
fn installing_manifests_populates_privacy_registry() {
    use iroha_crypto::privacy::{LaneCommitmentId, LanePrivacyCommitment, MerkleCommitment};
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let queue = Queue::test(config_factory(), &time_source);
    let mut statuses = BTreeMap::new();
    statuses.insert(
        LaneId::SINGLE,
        LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "default".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::CommitmentOnly,
            governance: None,
            manifest_path: Some(PathBuf::from("/tmp/privacy.json")),
            governance_rules: None,
            privacy_commitments: vec![LanePrivacyCommitment::merkle(
                LaneCommitmentId::new(7),
                MerkleCommitment::from_root_bytes([0x11; 32], 4),
            )],
        },
    );
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    queue.install_lane_manifests_for_testing(&manifests);
    let registry = queue.lane_privacy_registry();
    assert!(
        registry
            .lane(LaneId::SINGLE)
            .expect("lane registry entry")
            .get(LaneCommitmentId::new(7))
            .is_some()
    );
}
#[tokio::test]
async fn governance_manifest_allows_multisig_propose_envelope_from_live_signer() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let signer_key = checked_random_queue_keypair();
    let signer_id = AccountId::new(signer_key.public_key().clone());
    let cosigner_key = checked_random_queue_keypair();
    let cosigner_id = AccountId::new(cosigner_key.public_key().clone());
    let validator_key = checked_random_queue_keypair();
    let validator_id = AccountId::new(validator_key.public_key().clone());
    let multisig_key = checked_random_queue_keypair();
    let multisig_id = AccountId::new(multisig_key.public_key().clone());
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("static domain");
    let mut multisig_metadata = Metadata::default();
    multisig_metadata.insert(
        crate::smartcontracts::isi::multisig::spec_key(),
        Json::new(MultisigSpec {
            signatories: BTreeMap::from([(signer_id.clone(), 1), (cosigner_id.clone(), 1)]),
            quorum: nonzero!(2_u16),
            transaction_ttl_ms: nonzero!(
                iroha_executor_data_model::isi::multisig::DEFAULT_MULTISIG_TTL_MS
            ),
        }),
    );
    let domain = Domain::new(domain_id.clone()).build(&signer_id);
    let signer = Account::new(signer_id.clone()).build(&signer_id);
    let cosigner = Account::new(cosigner_id.clone()).build(&cosigner_id);
    let validator = Account::new(validator_id.clone()).build(&validator_id);
    let multisig = Account::new(multisig_id.clone())
        .with_metadata(multisig_metadata)
        .build(&multisig_id);
    let world = World::with([domain], [signer, cosigner, validator, multisig], []);
    // Explicit Global metadata belongs to this admission component fixture;
    // it does not authenticate signed genesis, native history or publication.
    let mut parameters = world.parameters.block();
    parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ))
        .expect("valid fixture parameters");
    parameters.commit();
    let mut state = State::new(world, kura, query_handle);
    {
        let nexus = state.nexus.get_mut();
        nexus.fees.base_fee = Quantity::zero();
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        nexus.lane_config =
            iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    }
    let state = Arc::new(state);
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    let mut statuses = BTreeMap::new();
    let rules = GovernanceRules {
        validators: vec![validator_id.clone()],
        quorum: Some(3),
        ..GovernanceRules::default()
    };
    let status = LaneManifestStatus {
        lane: LaneId::SINGLE,
        alias: "centralbank".to_string(),
        dataspace: DataSpaceId::UNIVERSAL,
        visibility: LaneVisibility::Public,
        storage: LaneStorageProfile::FullReplica,
        governance: Some("parliament".to_string()),
        manifest_path: Some(PathBuf::from("/tmp/manifest.json")),
        governance_rules: Some(rules),
        privacy_commitments: Vec::new(),
    };
    statuses.insert(LaneId::SINGLE, status);
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    queue.reconfigure_nexus_with_state(&state.nexus_snapshot(), &state, None);
    queue.install_lane_manifests_for_testing(&manifests);
    let tx = accepted_tx_with(
        signer_id,
        &signer_key,
        &time_source,
        vec![InstructionBox::from(MultisigPropose::new(
            multisig_id,
            vec![InstructionBox::from(Log::new(
                Level::INFO,
                "multisig envelope".into(),
            ))],
            None,
        ))],
        Metadata::default(),
    );
    queue
        .push(tx, state.view())
        .expect("multisig propose envelopes from live signers should bypass lane-validator gating");
}
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn lane_compliance_policy_blocks_transactions() {
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    #[cfg(feature = "telemetry")]
    let metrics = Arc::new(Metrics::default());
    #[cfg(feature = "telemetry")]
    let state = Arc::new(State::with_telemetry(
        world_with_test_domains(),
        kura.clone(),
        query_handle.clone(),
        StateTelemetry::new(metrics.clone(), true),
    ));
    #[cfg(not(feature = "telemetry"))]
    let state = Arc::new(State::new(world_with_test_domains(), kura, query_handle));
    let (_time_handle, time_source) = TimeSource::new_mock(Duration::default());
    let (allowed_id, allowed_keypair) = gen_account_in("wonderland");
    register_test_authority(&state, &allowed_id);
    let (denied_id, denied_keypair) = gen_account_in("wonderland");
    register_test_authority(&state, &denied_id);
    let (confidential_id, confidential_keypair) = gen_account_in("wonderland");
    register_test_authority(&state, &confidential_id);
    // Build a Merkle commitment + witness for privacy-gated policies
    let first_leaf = [0x01_u8; 32];
    let proof = MerkleProof::from_audit_path_bytes(0, vec![[0x02_u8; 32]]);
    let merkle_root = MerkleWitness::new(first_leaf, proof.clone())
        .implied_root(8)
        .expect("valid lane proof must produce a root");
    let merkle_commitment = LanePrivacyCommitment::merkle(
        LaneCommitmentId::new(9),
        MerkleCommitment::new(merkle_root, 8),
    );
    let queue_inner = Queue::test(config_factory(), &time_source);
    let policy = LaneCompliancePolicy {
        id: LaneCompliancePolicyId::new(Hash::prehashed([0xAA; 32])),
        version: 1,
        lane_id: LaneId::SINGLE,
        dataspace_id: DataSpaceId::UNIVERSAL,
        jurisdiction: JurisdictionSet::default(),
        deny: vec![LaneComplianceRule {
            selector: ParticipantSelector {
                account: Some(denied_id.clone()),
                ..ParticipantSelector::default()
            },
            reason_code: Some("denied account".to_string()),
            jurisdiction_override: JurisdictionSet::default(),
        }],
        allow: vec![
            LaneComplianceRule {
                selector: ParticipantSelector {
                    account: Some(allowed_id.clone()),
                    ..ParticipantSelector::default()
                },
                reason_code: Some("allowed account".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            },
            LaneComplianceRule {
                selector: ParticipantSelector {
                    account: Some(confidential_id.clone()),
                    privacy_commitments_any_of: vec![LaneCommitmentId::new(9)],
                    ..ParticipantSelector::default()
                },
                reason_code: Some("confidential allowed".to_string()),
                jurisdiction_override: JurisdictionSet::default(),
            },
        ],
        transfer_limits: Vec::new(),
        audit_controls: AuditControls::default(),
        metadata: Metadata::default(),
    };
    let engine = LaneComplianceEngine::from_policies(vec![policy], false).expect("engine");
    *queue_inner.lane_compliance.write() = Some(Arc::new(engine));
    let queue = Arc::new(queue_inner);
    let mut statuses = BTreeMap::new();
    statuses.insert(
        LaneId::SINGLE,
        LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "confidential".to_string(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::CommitmentOnly,
            governance: None,
            manifest_path: Some(PathBuf::from("/tmp/privacy.json")),
            governance_rules: None,
            privacy_commitments: vec![merkle_commitment],
        },
    );
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
    queue.install_lane_manifests_for_testing(&manifests);
    *queue.lane_privacy_registry.write() = Arc::new(LanePrivacyRegistry::empty());
    assert!(
        queue.lane_privacy_registry().is_empty(),
        "test uses a stale cache"
    );
    let denied_tx = accepted_tx_by(denied_id.clone(), &denied_keypair, &time_source);
    let err = queue
        .push(denied_tx, state.view())
        .expect_err("denied account should be rejected");
    assert!(matches!(err.err, Error::LaneComplianceDenied { .. }));
    let allowed_tx = accepted_tx_by(allowed_id.clone(), &allowed_keypair, &time_source);
    queue
        .push(allowed_tx, state.view())
        .expect("allowed account should pass");
    // Confidential account is denied without a privacy witness.
    let confidential_tx =
        accepted_tx_by(confidential_id.clone(), &confidential_keypair, &time_source);
    let err = queue
        .push(confidential_tx, state.view())
        .expect_err("missing privacy proof should be rejected");
    assert!(matches!(
        err.err,
        Error::LanePrivacyProofRejected { .. } | Error::LaneComplianceDenied { .. }
    ));
    // Attach a valid privacy proof to satisfy the policy.
    let proof_attachment = ProofAttachment {
        backend: Ident::from_str("halo2/ipa").expect("ident"),
        proof: ProofBox {
            backend: Ident::from_str("halo2/ipa").expect("ident"),
            bytes: vec![0xAA],
        },
        vk_ref: iroha_data_model::proof::VerifyingKeyId::new("halo2/ipa", "privacy"),
        vk_commitment: None,
        envelope_hash: None,
        lane_privacy: Some(LanePrivacyProof {
            commitment_id: LaneCommitmentId::new(9),
            witness: LanePrivacyWitness::Merkle(LanePrivacyMerkleWitness {
                leaf: first_leaf,
                proof,
            }),
        }),
    };
    let attachments = vec![proof_attachment];
    let confidential_tx = accepted_tx_with_attachments(
        confidential_id.clone(),
        &confidential_keypair,
        &time_source,
        vec![sample_unregister_instruction()],
        Metadata::default(),
        Some(attachments.clone()),
    );
    queue
        .push(confidential_tx, state.view())
        .expect("manifest-backed privacy proof should pass despite an empty local cache");

    let mut revoked_status = manifests.status(LaneId::SINGLE).unwrap().clone();
    revoked_status.privacy_commitments = vec![LanePrivacyCommitment::merkle(
        LaneCommitmentId::new(10),
        MerkleCommitment::new(merkle_root, 8),
    )];
    let revoked = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::from([(
        LaneId::SINGLE,
        revoked_status,
    )])));
    queue.install_lane_manifests_for_testing(&revoked);
    *queue.lane_privacy_registry.write() =
        Arc::new(LanePrivacyRegistry::from_manifest_registry(&manifests));
    let mut revoked_metadata = Metadata::default();
    revoked_metadata.insert(
        "revoked_privacy_test".parse().expect("metadata key"),
        iroha_primitives::json::Json::new(true),
    );
    let unregistered_proof = accepted_tx_with_attachments(
        confidential_id,
        &confidential_keypair,
        &time_source,
        vec![sample_unregister_instruction()],
        revoked_metadata,
        Some(attachments),
    );
    let err = queue
        .push(unregistered_proof, state.view())
        .expect_err("a forged local cache cannot authorize a revoked manifest commitment");
    assert!(
        matches!(&err.err, Error::LanePrivacyProofRejected { .. }),
        "the old commitment must fail against the new manifest despite the stale cache: {:?}",
        err.err
    );
}
