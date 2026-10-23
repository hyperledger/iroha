// Governance inspects the original signed body for both external and revealed entrypoints.
#[test]
fn governance_manifest_checks_share_signed_body_for_external_and_sealed_reveal() {
    fn assert_rejection(result: Result<(), Error>, expected: &str) {
        match result {
            Err(Error::GovernanceNotPermitted { alias, reason }) => {
                assert_eq!(alias, "entrypoint");
                assert_eq!(reason, expected);
            }
            other => panic!("expected completed governance rejection {expected:?}, got {other:?}"),
        }
    }

    let (_clock, time_source) = TimeSource::new_mock(Duration::from_secs(1));
    let (authority, keypair) = gen_account_in("signed-governance");
    let (approver, _) = gen_account_in("signed-governance-approver");
    let address = iroha_data_model::smart_contract::ContractAddress::derive(
        &queue_test_network_id(),
        &authority,
        0,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let upgrade_key: Name = "gov_upgrade_id".parse().unwrap();
    let rules = GovernanceRules {
        validators: vec![authority.clone(), approver.clone()],
        quorum: Some(2),
        protected_namespaces: BTreeSet::from(["apps".parse().unwrap()]),
        hooks: GovernanceHooks {
            runtime_upgrade: Some(RuntimeUpgradeHook {
                allow: true,
                require_metadata: true,
                metadata_key: Some(upgrade_key.clone()),
                allowed_ids: Some(BTreeSet::from([RUNTIME_UPGRADE_ALLOWED_ID.to_owned()])),
            }),
        },
        ..GovernanceRules::default()
    };
    for complete_metadata in [false, true] {
        let mut metadata = Metadata::default();
        if complete_metadata {
            metadata.insert(
                (*GOV_APPROVERS_METADATA_KEY).clone(),
                Json::new(vec![approver.canonical_i105().unwrap()]),
            );
            metadata.insert(
                (*GOV_CONTRACT_ADDRESS_METADATA_KEY).clone(),
                Json::new(address.to_string()),
            );
            metadata.insert(
                upgrade_key.clone(),
                Json::new(RUNTIME_UPGRADE_ALLOWED_ID.to_owned()),
            );
        }
        let code = vec![0x35, 0x71];
        let instructions = vec![
            runtime_upgrade_instruction(),
            InstructionBox::from(RegisterSmartContractBytes {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    DataSpaceId::UNIVERSAL,
                    Hash::new(&code),
                ),
                code,
            }),
        ];
        let signed = TransactionBuilder::new_with_time_source(
            queue_test_network_id(),
            authority.clone(),
            &time_source,
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions(instructions)
        .with_metadata(metadata)
        .sign(keypair.private_key());
        let salt = [0x63; 32];
        let deadline = 9;
        let hash = compute_sealed_transaction_commitment(
            &queue_test_network_id(),
            &signed,
            salt,
            deadline,
        );
        let commitment = SignedSealedTransactionCommitment::sign(
            SealedTransactionCommitmentPayload::new(
                queue_test_network_id(),
                authority.clone(),
                hash,
                2,
                deadline,
                None,
            ),
            keypair.private_key(),
        );
        let accept = |entrypoint| {
            CheckedTransaction::new_unchecked(
                AcceptedTransaction::accept_entrypoint_at_time(
                    entrypoint,
                    &queue_test_network_id(),
                    Duration::ZERO,
                    TransactionParameters::default(),
                    &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
                        iroha_crypto::Algorithm::Ed25519,
                        iroha_crypto::Algorithm::Secp256k1,
                    ])
                    .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
                    signed.creation_time(),
                )
                .expect("real signed Network entrypoint stateless admission"),
            )
        };
        let external = accept(TransactionEntrypoint::External(signed.clone()));
        let revealed = accept(TransactionEntrypoint::SealedReveal(
            SealedTransactionReveal::new(hash, signed.clone(), salt),
        ));
        let committed = accept(TransactionEntrypoint::SealedCommitment(commitment));
        for tx in [&external, &revealed] {
            assert_eq!(tx.as_ref().external(), Some(&signed));
            assert!(Queue::tx_contains_runtime_upgrade_instruction(tx));
            assert!(Queue::tx_touches_manifest_protected_namespace_surface(tx));
            assert!(Queue::tx_requires_manifest_validator_gating(&rules, tx));
            let quorum = Queue::enforce_manifest_quorum("entrypoint", &rules, tx);
            let protected = Queue::enforce_manifest_protected_namespaces("entrypoint", &rules, tx);
            let runtime = Queue::enforce_runtime_upgrade_hook("entrypoint", &rules, tx);
            if complete_metadata {
                quorum.expect("all exact signed approvers are present");
                assert!(protected.expect("the exact contract-address metadata is present"));
                assert!(runtime.expect("the exact allowed upgrade metadata is present"));
            } else {
                assert_rejection(
                    quorum,
                    "lane manifest quorum requires 2 validator approvals but 1 were provided",
                );
                assert_rejection(
                    protected.map(|_| ()),
                    "transactions with contract operations must set `gov_contract_address` metadata when lane governance protects namespaces",
                );
                assert_rejection(
                    runtime.map(|_| ()),
                    "runtime upgrade hook requires metadata `gov_upgrade_id`",
                );
            }
        }
        assert!(committed.as_ref().external().is_none());
        assert!(committed.as_ref().metadata().is_none());
        assert!(!Queue::tx_contains_runtime_upgrade_instruction(&committed));
        assert!(!Queue::tx_touches_manifest_protected_namespace_surface(
            &committed
        ));
        assert!(!Queue::tx_requires_manifest_validator_gating(
            &rules, &committed
        ));
        assert!(
            !Queue::enforce_manifest_protected_namespaces("entrypoint", &rules, &committed)
                .unwrap()
        );
        assert!(!Queue::enforce_runtime_upgrade_hook("entrypoint", &rules, &committed).unwrap());
        assert_rejection(
            Queue::enforce_manifest_quorum("entrypoint", &rules, &committed),
            "lane manifest quorum requires 2 validator approvals but 1 were provided",
        );
    }
}

// A commitment reaches the same manifest branch as other admitted entries, but
// exposes no executable until its separately checked reveal supplies that body.
#[test]
fn governed_queue_push_preserves_sealed_commitment_without_signed_body() {
    let (_clock, time_source) = TimeSource::new_mock(Duration::from_secs(1));
    let state = State::new(
        world_with_test_domains(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let (authority, keypair) = gen_account_in("wonderland");
    let (validator, _) = gen_account_in("governed-validator");
    register_test_authority(&state, &authority);
    let queue = Arc::new(Queue::test(config_factory(), &time_source));
    queue.reconfigure_nexus_with_state(&state.nexus_snapshot(), &state, None);
    let manifests = Arc::new(LaneManifestRegistry::from_statuses(BTreeMap::from([(
        LaneId::SINGLE,
        LaneManifestStatus {
            lane: LaneId::SINGLE,
            alias: "entrypoint".to_owned(),
            dataspace: DataSpaceId::UNIVERSAL,
            visibility: LaneVisibility::Public,
            storage: LaneStorageProfile::FullReplica,
            governance: Some("parliament".to_owned()),
            manifest_path: Some(PathBuf::from("dist/governed-queue-component-fixture.json")),
            governance_rules: Some(GovernanceRules {
                validators: vec![validator],
                quorum: Some(2),
                protected_namespaces: BTreeSet::from(["apps".parse().unwrap()]),
                hooks: GovernanceHooks {
                    runtime_upgrade: Some(RuntimeUpgradeHook {
                        allow: false,
                        require_metadata: true,
                        metadata_key: None,
                        allowed_ids: None,
                    }),
                },
                ..GovernanceRules::default()
            }),
            privacy_commitments: Vec::new(),
        },
    )])));
    queue.install_lane_manifests_for_testing(&manifests);
    let signed = TransactionBuilder::new_with_time_source(
        state.network_id,
        authority.clone(),
        &time_source,
        FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([runtime_upgrade_instruction()])
    .sign(keypair.private_key());
    let salt = [0x64; 32];
    let deadline = 9;
    let hash = compute_sealed_transaction_commitment(&state.network_id, &signed, salt, deadline);
    let commitment = SignedSealedTransactionCommitment::sign(
        SealedTransactionCommitmentPayload::new(
            state.network_id,
            authority,
            hash,
            2,
            deadline,
            None,
        ),
        keypair.private_key(),
    );
    let accepted = AcceptedTransaction::accept_entrypoint_at_time(
        TransactionEntrypoint::SealedCommitment(commitment),
        &state.network_id,
        Duration::ZERO,
        TransactionParameters::default(),
        &iroha_data_model::crypto_admission_policy::CryptoAdmissionPolicyV1::new(vec![
            iroha_crypto::Algorithm::Ed25519,
            iroha_crypto::Algorithm::Secp256k1,
        ])
        .expect("this stateless fixture explicitly selects Ed25519 and Secp256k1"),
        signed.creation_time(),
    )
    .expect("real signed commitment passes stateless admission");
    let entrypoint_hash = accepted.hash_as_entrypoint();
    let original_frame = accepted.entrypoint_bytes();
    let expected_gas = gas::meter_sealed_transaction_commitment(accepted.encoded_len());
    assert!(accepted.external().is_none());
    queue
        .push(accepted, state.view())
        .expect("governed lane admits a commitment without inspecting unrevealed instructions");
    assert_eq!(queue.active_len(), 1);
    assert!(queue.txs.contains_key(&entrypoint_hash));
    assert_eq!(
        *queue.tx_gas_cost.get(&entrypoint_hash).unwrap(),
        expected_gas
    );
    let snapshot = queue
        .bounded_pending_snapshot(&state.view(), nonzero!(1_usize))
        .expect("the original commitment remains selectable");
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].hash_as_entrypoint(), entrypoint_hash);
    assert!(snapshot[0].external().is_none());
    assert!(Arc::ptr_eq(
        &snapshot[0].entrypoint_bytes(),
        &original_frame
    ));
}
