// Exact-due automatic-enactment coverage for the remaining typed Parliament effects.

fn assert_exact_due_parliament_effect_enacted(
    state_transaction: &StateTransaction<'_, '_>,
    fixture: &DueParliamentCertificateFixture,
) {
    assert_eq!(
        state_transaction.block_height(),
        PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
        "the effect must execute at the certificate's exact due height",
    );
    let attempt = state_transaction
        .world
        .parliament_attempts
        .get(&fixture.governance_attempt_id)
        .expect("terminal exact-due Parliament attempt");
    assert_eq!(attempt.attempt().status, GovernanceAttemptStatusV1::Enacted);
    assert_eq!(
        attempt.terminal_height(),
        Some(PARLIAMENT_DUE_CERTIFICATE_HEIGHT)
    );
    assert_eq!(
        attempt
            .certificate()
            .map(|certificate| certificate.enact_at_height),
        Some(PARLIAMENT_DUE_CERTIFICATE_HEIGHT)
    );
    let proposal = state_transaction
        .world
        .governance_proposals
        .get(&fixture.proposal_id)
        .expect("enacted exact-due governance proposal");
    assert_eq!(
        proposal.status,
        crate::state::GovernanceProposalStatus::Enacted
    );
    assert!(
        state_transaction
            .world
            .internal_event_buf
            .iter()
            .any(|event| matches!(
                event.as_ref(),
                iroha_data_model::events::data::DataEvent::Governance(
                    GovernanceEvent::ProposalEnacted(enacted)
                ) if enacted.id == fixture.proposal_id
            )),
        "automatic success must emit the typed ProposalEnacted event",
    );
    assert_automatic_parliament_execution_event(
        state_transaction,
        fixture,
        gov::ParliamentAutomaticExecutionOutcomeV1::Enacted,
    );
}

#[test]
fn parliament_runtime_upgrade_enacts_at_the_exact_due_height() {
    let state = blank_test_state();
    let block = new_dummy_block_at_height(
        NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).expect("due height is nonzero"),
    );
    let mut state_block = state.block(block.as_ref().header());
    let manifest = iroha_data_model::runtime::RuntimeUpgradeManifest {
        name: "exact-due-runtime-upgrade".to_owned(),
        description: "activate the fixed first-release ABI at the certified height".to_owned(),
        abi_version: 1,
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        added_syscalls: Vec::new(),
        added_pointer_types: Vec::new(),
        start_height: PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
        end_height: PARLIAMENT_DUE_CERTIFICATE_HEIGHT + 1,
        sbom_digests: Vec::new(),
        slsa_attestation: Vec::new(),
        provenance: Vec::new(),
    };
    let upgrade_id = manifest.id();
    let fixture = {
        let mut seed = state_block.transaction();
        let fixture = seed_due_parliament_certificate(
            &mut seed,
            ProposalKind::RuntimeUpgrade(RuntimeUpgradeProposal {
                proposal_operator: ALICE_ID.clone(),
                manifest: manifest.clone(),
            }),
        );
        seed.apply();
        fixture
    };

    let mut execution = state_block.transaction();
    execution.world.internal_event_buf.clear();
    assert_eq!(
        execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
            .expect("execute exact-due runtime-upgrade certificate"),
        DueParliamentCertificateExecutionV1::Applied
    );
    let record = execution
        .world
        .runtime_upgrades
        .get(&upgrade_id)
        .expect("runtime-upgrade effect record");
    assert_eq!(record.manifest, manifest);
    assert_eq!(
        record.status,
        iroha_data_model::runtime::RuntimeUpgradeStatus::ActivatedAt(
            PARLIAMENT_DUE_CERTIFICATE_HEIGHT
        )
    );
    assert_eq!(&record.proposer, &*ALICE_ID);
    assert_eq!(record.created_height, PARLIAMENT_DUE_CERTIFICATE_HEIGHT);
    assert_exact_due_parliament_effect_enacted(&execution, &fixture);
}

#[test]
fn parliament_sorafs_provider_owner_enacts_at_the_exact_due_height() {
    use iroha_data_model::isi::sorafs::{
        EstablishSorafsProviderOwnerV1, SorafsProviderGovernanceActionV1,
    };
    use iroha_executor_data_model::permission::sorafs::CanOperateSorafsRepair;

    let state = blank_test_state();
    let block = new_dummy_block_at_height(
        NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).expect("due height is nonzero"),
    );
    let mut state_block = state.block(block.as_ref().header());
    let provider_id = iroha_data_model::sorafs::capacity::ProviderId::new([0xA8; 32]);
    let fixture = {
        let mut seed = state_block.transaction();
        bootstrap_alice_account(&mut seed);
        let fixture = seed_due_parliament_certificate(
            &mut seed,
            ProposalKind::SorafsProviderGovernance(SorafsProviderGovernanceProposal {
                action: Box::new(SorafsProviderGovernanceActionV1::Establish(
                    EstablishSorafsProviderOwnerV1 {
                        provider_id,
                        owner: ALICE_ID.clone(),
                    },
                )),
            }),
        );
        seed.apply();
        fixture
    };

    let mut execution = state_block.transaction();
    execution.world.internal_event_buf.clear();
    assert_eq!(
        execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
            .expect("execute exact-due SoraFS provider certificate"),
        DueParliamentCertificateExecutionV1::Applied
    );
    assert_eq!(
        execution.world.provider_owners.get(&provider_id),
        Some(&*ALICE_ID)
    );
    let repair_permission = Permission::from(CanOperateSorafsRepair { provider_id });
    assert!(
        execution
            .world
            .account_permissions
            .get(&ALICE_ID)
            .is_some_and(|permissions| permissions.contains(&repair_permission)),
        "provider enactment must install its typed repair-worker authorization",
    );
    assert_exact_due_parliament_effect_enacted(&execution, &fixture);
}

#[test]
fn parliament_musubi_action_authorization_enacts_at_the_exact_due_height() {
    use iroha_data_model::musubi::{
        MusubiGovernanceDecisionV1, MusubiPackageIdV1, MusubiPackageScopeV1,
        MusubiParliamentActionV1, MusubiRecoverPackageOwnersV1,
    };

    let state = blank_test_state();
    let block = new_dummy_block_at_height(
        NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).expect("due height is nonzero"),
    );
    let mut state_block = state.block(block.as_ref().header());
    let package = MusubiPackageIdV1::new(
        DataSpaceId::new(7),
        MusubiPackageScopeV1::DataspaceRoot,
        "exact-due-recovery"
            .parse()
            .expect("canonical Musubi package name"),
    );
    let action = MusubiParliamentActionV1::RecoverPackageOwners(MusubiRecoverPackageOwnersV1 {
        package: package.clone(),
        owners: vec![ALICE_ID.clone()],
        expected_revision: 1,
    });
    action.validate().expect("valid exact Musubi action");
    let fixture = {
        let mut seed = state_block.transaction();
        let fixture = seed_due_parliament_certificate(
            &mut seed,
            ProposalKind::MusubiRegistryGovernance(action.clone()),
        );
        seed.apply();
        fixture
    };

    let mut execution = state_block.transaction();
    execution.world.internal_event_buf.clear();
    assert_eq!(
        execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
            .expect("execute exact-due Musubi authorization certificate"),
        DueParliamentCertificateExecutionV1::Applied
    );
    let proposal = execution
        .world
        .governance_proposals
        .get(&fixture.proposal_id)
        .expect("enacted Musubi authorization proposal");
    assert!(matches!(
        &proposal.kind,
        ProposalKind::MusubiRegistryGovernance(enacted) if enacted == &action
    ));
    assert!(
        execution.world.musubi_packages.get(&package).is_none(),
        "enactment authorizes the delayed Musubi mutation without bypassing its target ISI",
    );
    assert!(
        execution
            .world
            .musubi_governance_decisions
            .get(&fixture.proposal_id)
            .is_none(),
        "the enacted authorization must remain unconsumed until the delayed target ISI",
    );
    let decision = MusubiGovernanceDecisionV1 {
        decision_id: fixture.proposal_id,
        action_digest: action.action_digest(),
        enacted_at_height: PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
        execute_after_height: PARLIAMENT_DUE_CERTIFICATE_HEIGHT
            .checked_add(execution.gov.min_enactment_delay.max(1))
            .expect("Musubi execution boundary does not overflow"),
    };
    decision
        .validate()
        .expect("typed delayed Musubi authorization is valid");
    assert_exact_due_parliament_effect_enacted(&execution, &fixture);
}

#[test]
fn parliament_validation_fee_policy_enacts_at_the_exact_due_height() {
    assert_live_pricing_capacity_waits_for_certified_settlement();
    use iroha_data_model::validation_fee::{
        VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS, ValidationFeeChargingMode,
        ValidationFeePolicyV1,
    };
    let ds_asset_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").unwrap(),
        "fee_token".parse().unwrap(),
    );
    crate::validation_fee::tests::with_validation_fee_payout_state_at_time(
        PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
        1_790_859_600_000,
        |execution, deployer, code, code_hash| {
            let mut wrapper = crate::validation_fee::tests::activate_bound_payout_runtime(
                execution,
                deployer,
                code,
                code_hash,
                0,
                ds_asset_id.clone(),
                "exact_due_policy_wrapper",
            );
            let pool = crate::validation_fee::tests::activate_bound_payout_runtime(
                execution,
                deployer,
                code,
                code_hash,
                1,
                ds_asset_id.clone(),
                "exact_due_policy_pool",
            );
            wrapper.binding.pool_vault_account_id = pool.binding.treasury_account_id;
            wrapper.binding.pool_contract_address = pool.binding.contract_address;
            wrapper.binding.pool_code_hash = pool.binding.code_hash;
            let binding = wrapper.binding;
            validate_validation_fee_payout_lifecycle_runtime_before_effect_install(
                &binding, execution,
            )
            .expect("exact-due policy fixture owns authenticated payout runtime scopes");
            let payout_fixture = seed_due_parliament_certificate(
                execution,
                ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                    proposal_operator: ALICE_ID.clone(),
                    payout_binding: binding.clone(),
                }),
            );
            assert_eq!(
                execute_due_parliament_certificate_v1(
                    payout_fixture.governance_attempt_id,
                    execution,
                )
                .unwrap(),
                DueParliamentCertificateExecutionV1::Applied
            );
            let policy = ValidationFeePolicyV1 {
                retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
                effective_from_ms: 1_793_451_600_000,
                notice_published_at_ms: 1_790_859_600_000,
                schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
                network_id: execution.network_id,
                policy_version: 1,
                previous_policy_hash: None,
                ds_asset_id,
                ds_scale: VALIDATION_FEE_DS_SCALE,
                fee: "0.10".parse().unwrap(),
                treasury_account_id: binding.treasury_account_id.clone(),
                charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

                exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.into()],
                reward_custody: binding.custody(),
            };
            validate_validation_fee_policy_proposal(&policy, execution).unwrap();
            let fixture = seed_due_parliament_certificate(
                execution,
                ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
                    proposal_operator: ALICE_ID.clone(),
                    policy: policy.clone(),
                }),
            );
            execution.world.internal_event_buf.clear();
            assert_eq!(
                execute_due_parliament_certificate_v1(fixture.governance_attempt_id, execution,)
                    .unwrap(),
                DueParliamentCertificateExecutionV1::Applied
            );
            let registry = validation_fee_policy_registry(execution)
                .expect("read validation-fee registry")
                .expect("automatic enactment installs validation-fee registry");
            assert_eq!(registry.registered_policies.len(), 1);
            let entry = registry
                .head()
                .expect("validation-fee registry has its enacted head");
            assert_eq!(entry.policy, policy);
            assert_eq!(
                registry.payout_policies.head().unwrap().lifecycle_seal,
                binding.lifecycle_seal().unwrap()
            );
            let proposal = execution
                .world
                .governance_proposals
                .get(&fixture.proposal_id)
                .expect("retained validation-fee policy proposal");
            let authorization = validation_fee_parliament_authorization(
                fixture.proposal_id,
                proposal,
                &fixture.certificate,
                PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
            )
            .expect("derive exact typed validation-fee authorization");
            assert_eq!(entry.parliament_authorization, authorization);
            assert_eq!(&authorization.proposal_operator, &*ALICE_ID);
            assert_eq!(authorization.proposal_fingerprint, fixture.proposal_id);
            assert_eq!(
                authorization.governance_certificate_id,
                GovernanceCertificateId::derive_v1(&fixture.certificate)
            );
            assert_eq!(authorization.invariant_error(), None);
            assert_exact_due_parliament_effect_enacted(execution, &fixture);
        },
    );
}

#[test]
fn parliament_validation_fee_payout_lifecycle_enacts_at_the_exact_due_height() {
    let ds_asset_id = AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").expect("payout fixture asset domain"),
        "fee_token".parse().expect("payout fixture asset name"),
    );
    crate::validation_fee::tests::with_original_validation_fee_payout_state_at_height(
        PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
        original_world_config,
        |execution, deployer, code, code_hash| {
            let mut wrapper = crate::validation_fee::tests::activate_bound_payout_runtime(
                execution,
                deployer,
                code,
                code_hash,
                0,
                ds_asset_id.clone(),
                "exact_due_validation_fee_wrapper",
            );
            let pool = crate::validation_fee::tests::activate_bound_payout_runtime(
                execution,
                deployer,
                code,
                code_hash,
                1,
                ds_asset_id,
                "exact_due_validation_fee_pool",
            );
            wrapper.binding.pool_vault_account_id = pool.binding.treasury_account_id.clone();
            wrapper.binding.pool_contract_address = pool.binding.contract_address.clone();
            wrapper.binding.pool_code_hash = pool.binding.code_hash;
            let binding = wrapper.binding;
            assert_eq!(binding.invariant_error(), None);
            validate_validation_fee_payout_lifecycle_runtime_before_effect_install(
                &binding, execution,
            )
            .expect("exact payout topology is vacant before enactment");
            let fixture = seed_due_parliament_certificate(
                execution,
                ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                    proposal_operator: ALICE_ID.clone(),
                    payout_binding: binding.clone(),
                }),
            );
            execution.world.internal_event_buf.clear();

            assert_eq!(
                execute_due_parliament_certificate_v1(fixture.governance_attempt_id, execution,)
                    .expect("execute exact-due validation-fee payout certificate"),
                DueParliamentCertificateExecutionV1::Applied
            );
            validate_validation_fee_payout_lifecycle_runtime(&binding, execution)
                .expect("automatic enactment installs the exact protected payout topology");
            let pool_contract_address = execution
                .world
                .contract_subject_addresses
                .get(&binding.pool_vault_account_id)
                .cloned()
                .expect("bound payout pool contract address");
            for (permission, required_holder, permission_label) in
                validation_fee_runtime_permissions(execution, &binding, &pool_contract_address)
                    .expect("immutable payout manifests declare exact scoped permissions")
            {
                assert!(
                    execution
                        .world
                        .account_permissions
                        .get(&required_holder)
                        .is_some_and(|permissions| permissions.contains(&permission)),
                    "automatic enactment must install {permission_label}",
                );
            }
            let proposal = execution
                .world
                .governance_proposals
                .get(&fixture.proposal_id)
                .expect("retained validation-fee payout proposal");
            assert!(matches!(
                &proposal.kind,
                ProposalKind::ValidationFeePayoutLifecycle(payload)
                    if payload.payout_binding == binding
            ));
            let authorization = validation_fee_parliament_authorization(
                fixture.proposal_id,
                proposal,
                &fixture.certificate,
                PARLIAMENT_DUE_CERTIFICATE_HEIGHT,
            )
            .expect("derive exact payout-lifecycle Parliament authorization");
            assert_eq!(&authorization.proposal_operator, &*ALICE_ID);
            assert_eq!(authorization.proposal_fingerprint, fixture.proposal_id);
            assert_eq!(
                authorization.governance_certificate_id,
                GovernanceCertificateId::derive_v1(&fixture.certificate)
            );
            assert_eq!(authorization.invariant_error(), None);
            assert_exact_due_parliament_effect_enacted(execution, &fixture);
        },
    );
}

#[test]
fn parliament_sorafs_admission_council_enacts_only_the_exact_certified_effect() {
    use iroha_data_model::{
        isi::sorafs::SorafsProviderGovernanceActionV1,
        sorafs::provider_admission::{
            ProviderAdmissionCouncilPolicyV1, governance::ProviderAdmissionGovernanceActionV1,
        },
    };
    let state = blank_test_state();
    // Provider admission records require a real nonzero observation timestamp.
    let header = BlockHeader::new(
        NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).unwrap(),
        None,
        None,
        1,
        0,
    );
    let mut state_block = state.block(header);
    let mut seed = state_block.transaction();
    bootstrap_alice_account(&mut seed);
    let policy = ProviderAdmissionCouncilPolicyV1 {
        version: 1,
        network_id: *seed.network_id().as_bytes(),
        policy_id: [0xe1; 32],
        revision: 1,
        predecessor_policy_digest: None,
        trusted_signers: vec![ALICE_KEYPAIR.public_key().to_bytes().1.try_into().unwrap()],
        signature_threshold: 1,
        paused: false,
    };
    let kind = ProposalKind::SorafsProviderGovernance(SorafsProviderGovernanceProposal {
        action: Box::new(SorafsProviderGovernanceActionV1::Admission(
            ProviderAdmissionGovernanceActionV1::ConfigureCouncil(
                norito::encode_canonical(&policy).unwrap(),
            ),
        )),
    });
    let fixture = seed_due_parliament_certificate(&mut seed, kind);
    seed.apply();
    let mut execution = state_block.transaction();
    assert_eq!(
        execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
            .unwrap(),
        DueParliamentCertificateExecutionV1::Applied
    );
    assert_eq!(
        crate::query::provider_admission::read_policy(execution.world()).unwrap(),
        Some(policy)
    );
    assert_exact_due_parliament_effect_enacted(&execution, &fixture);
}

#[test]
fn parliament_terminal_effect_failure_retains_atomic_rollback_and_exact_outcome() {
    use iroha_data_model::isi::sorafs::{
        EstablishSorafsProviderOwnerV1, SorafsProviderGovernanceActionV1,
    };
    let state = blank_test_state();
    let block =
        new_dummy_block_at_height(NonZeroU64::new(PARLIAMENT_DUE_CERTIFICATE_HEIGHT).unwrap());
    let mut state_block = state.block(block.as_ref().header());
    let provider_id = iroha_data_model::sorafs::capacity::ProviderId::new([0xE8; 32]);
    let fixture = {
        let mut seed = state_block.transaction();
        assert!(
            seed.world.account(&ALICE_ID).is_err(),
            "the certified target account is absent"
        );
        let fixture = seed_due_parliament_certificate(
            &mut seed,
            ProposalKind::SorafsProviderGovernance(SorafsProviderGovernanceProposal {
                action: Box::new(SorafsProviderGovernanceActionV1::Establish(
                    EstablishSorafsProviderOwnerV1 {
                        provider_id,
                        owner: ALICE_ID.clone(),
                    },
                )),
            }),
        );
        seed.apply();
        fixture
    };
    let failure_root = {
        let mut execution = state_block.transaction();
        let result =
            execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut execution)
                .expect("missing target account is a completed effect failure, not local refusal");
        let DueParliamentCertificateExecutionV1::EffectFailed { failure_root } = result else {
            panic!("an absent account cannot receive the certified provider ownership: {result:?}");
        };
        assert!(!execution.is_execution_deferred());
        assert!(execution.world.provider_owners.get(&provider_id).is_none());
        assert_eq!(
            execution
                .world
                .parliament_attempts
                .get(&fixture.governance_attempt_id)
                .unwrap()
                .attempt()
                .status,
            GovernanceAttemptStatusV1::Certified
        );
        // Drop exactly the failed original transaction before installing its terminal outcome.
        failure_root
    };
    assert!(
        state_block
            .world
            .provider_owners
            .get(&provider_id)
            .is_none()
    );
    let mut failure = state_block.transaction();
    record_due_parliament_execution_failure_v1(
        fixture.governance_attempt_id,
        failure_root,
        &mut failure,
    )
    .expect("record the exact deterministic failure after rollback");
    assert!(!failure.is_execution_deferred());
    assert_eq!(
        failure
            .world
            .governance_proposals
            .get(&fixture.proposal_id)
            .unwrap()
            .status,
        crate::state::GovernanceProposalStatus::ExecutionFailed
    );
    assert_eq!(
        failure
            .world
            .parliament_attempts
            .get(&fixture.governance_attempt_id)
            .unwrap()
            .attempt()
            .status,
        GovernanceAttemptStatusV1::ExecutionFailed
    );
    assert_automatic_parliament_execution_event(
        &failure,
        &fixture,
        gov::ParliamentAutomaticExecutionOutcomeV1::ExecutionFailed(
            gov::ParliamentAutomaticExecutionFailedV1 {
                effect_preimage_hash: fixture.certificate.effect_preimage_hash,
                failure_root,
            },
        ),
    );
    assert!(failure.world.provider_owners.get(&provider_id).is_none());
    failure.apply();
    assert!(
        state_block
            .world
            .provider_owners
            .get(&provider_id)
            .is_none()
    );
    assert_eq!(
        state_block
            .world
            .governance_proposals
            .get(&fixture.proposal_id)
            .unwrap()
            .status,
        crate::state::GovernanceProposalStatus::ExecutionFailed
    );
}

#[test]
fn parliament_validation_fee_payout_json_capacity_rolls_back_permissions_and_events() {
    use crate::validation_fee::tests::{
        install_policy_registry_fixture, payout_registry_entry, register_bound_payout_time_trigger,
        signed_payout_lifecycle_registry_fixture,
    };
    use iroha_data_model::validation_fee::{
        MAX_VALIDATION_FEE_REGISTRY_BYTES, ValidationFeePayoutPolicyEntryV1,
        ValidationFeePayoutPolicyRegistryV1,
    };

    let (mut chain, mut candidate) = signed_payout_lifecycle_registry_fixture();
    while chain.height() < PARLIAMENT_DUE_CERTIFICATE_HEIGHT - 1 {
        chain.commit_at((chain.height() + 1) * 1_000, Vec::new());
    }
    // Original runtime custody comes from signed deployments. The many accepted
    // historical entries below are explicit component prestate, not a claim that
    // this short chain enacted a lifetime of Parliament proposals.
    let mut live = ValidationFeePolicyRegistryV1 {
        history: None,
        registered_policies: Vec::new(),
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: Vec::new(),
        },
    };
    let mut revision = 1_u64;
    loop {
        candidate.min_reward_claim_xor_minor = revision;
        live.payout_policies
            .entries
            .push(payout_registry_entry(&candidate, revision, 20));
        live.validate().unwrap();
        assert!(norito::to_bytes(&live).unwrap().len() < MAX_VALIDATION_FEE_REGISTRY_BYTES);
        match live.clone().into_custom_parameter() {
            Ok(_) => revision = revision.checked_add(1).unwrap(),
            Err(error) => {
                assert!(error.decode_resource_error().is_none(), "{error:?}");
                assert_eq!(
                    error.to_string(),
                    "bounded JSON body exceeds its byte limit"
                );
                live.payout_policies.entries.pop().unwrap();
                break;
            }
        }
    }
    live.validate().unwrap();
    assert!(live.payout_policies.entries.len() > 2);
    let live_parameter = live.clone().into_custom_parameter().unwrap();
    assert!(live_parameter.payload().get().len() <= iroha_primitives::json::MAX_JSON_BYTES);
    let original_state = crate::snapshot::canonical_state_snapshot_bytes(chain.state());
    let original_height = chain.height();
    let original_tip = chain.state().view().latest_block_hash();
    let proposal = chain.proposal(Some(PARLIAMENT_DUE_CERTIFICATE_HEIGHT * 1_000), Vec::new());
    let state = std::sync::Arc::clone(chain.state());
    {
        let mut block = state.block(proposal.header());
        let fixture = {
            let mut setup = block.transaction();
            register_bound_payout_time_trigger(
                &mut setup,
                &candidate,
                Hash::prehashed(candidate.code_hash),
                "json_capacity_validation_fee_wrapper",
            );
            install_policy_registry_fixture(&live, &mut setup);
            let previous = &live.payout_policies.head().unwrap().payout_binding;
            install_derived_validation_fee_runtime_permissions(previous, &mut setup).unwrap();
            validate_validation_fee_payout_lifecycle_runtime(previous, &setup).unwrap();
            validate_validation_fee_payout_lifecycle_runtime_before_effect_install(
                &candidate, &setup,
            )
            .unwrap();
            let fixture = seed_due_parliament_certificate(
                &mut setup,
                ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                    proposal_operator: ALICE_ID.clone(),
                    payout_binding: candidate.clone(),
                }),
            );
            setup.world.internal_event_buf.clear();
            setup.apply();
            fixture
        };
        let staged = crate::snapshot::canonical_staged_state_snapshot_bytes(&block);
        // Canonical WSV snapshots normalize this delivery buffer to committed
        // state, so retain the exact block-local event cut separately.
        let staged_events = block.world.pending_external_events().to_vec();
        {
            let mut attempt = block.transaction();
            let record = attempt
                .world
                .governance_proposals
                .get(&fixture.proposal_id)
                .unwrap()
                .clone();
            let authorization = validation_fee_parliament_authorization(
                fixture.proposal_id,
                &record,
                &fixture.certificate,
                attempt.block_height(),
            )
            .unwrap();
            let mut oversized = live.clone();
            oversized
                .payout_policies
                .entries
                .push(ValidationFeePayoutPolicyEntryV1 {
                    revision,
                    proposal_id: fixture.proposal_id,
                    lifecycle_seal: candidate.lifecycle_seal().unwrap(),
                    payout_binding: candidate.clone(),
                    parliament_authorization: authorization,
                });
            oversized.validate().unwrap();
            assert!(
                norito::to_bytes(&oversized).unwrap().len() < MAX_VALIDATION_FEE_REGISTRY_BYTES
            );
            assert_eq!(
                oversized.into_custom_parameter().unwrap_err().to_string(),
                "bounded JSON body exceeds its byte limit",
                "the exact certified successor must hit the independent JSON capacity"
            );
            let permissions = validation_fee_runtime_permissions(
                &attempt,
                &candidate,
                &candidate.pool_contract_address,
            )
            .unwrap();
            assert!(attempt.world.internal_event_buf.is_empty());
            let error = apply_parliament_proposal_effect_v1(
                fixture.proposal_id,
                &record,
                &fixture.certificate,
                &mut attempt,
            )
            .expect_err("payout append must return its real JSON-capacity rejection");
            assert!(
                error
                    .to_string()
                    .contains("validation-fee registry parameter encoding failed: bounded JSON body exceeds its byte limit"),
                "{error}"
            );
            assert!(attempt.execution_deferral().is_none());
            assert_eq!(
                validation_fee_policy_registry(&attempt).unwrap(),
                Some(live.clone())
            );
            // This successor only changes the claim minimum, so permission values
            // are idempotent. Reinstallation nevertheless emits staged events:
            // observe them to prove execution reached the later encoding refusal.
            assert_eq!(attempt.world.internal_event_buf.len(), permissions.len());
            for (permission, holder, _) in &permissions {
                assert!(
                    attempt
                        .world
                        .account_contains_inherent_permission(holder, permission)
                );
                assert!(
                    attempt
                        .world
                        .internal_event_buf
                        .iter()
                        .any(|event| matches!(
                            event.as_ref(),
                            iroha_data_model::events::data::DataEvent::Account(
                                AccountEvent::PermissionAdded(added)
                            ) if &added.account == holder && &added.permission == permission
                        ))
                );
            }
            // The production owner drops a failed child transaction rather than
            // publishing the staged permission events or any other effect.
        }
        assert_eq!(
            crate::snapshot::canonical_staged_state_snapshot_bytes(&block),
            staged,
            "failed payout append must preserve the full registry and permission snapshot"
        );
        assert_eq!(
            block.world.pending_external_events(),
            staged_events.as_slice(),
            "failed payout append must not publish its staged permission events"
        );
        {
            let mut attempt = block.transaction();
            assert!(matches!(
                execute_due_parliament_certificate_v1(fixture.governance_attempt_id, &mut attempt)
                    .unwrap(),
                DueParliamentCertificateExecutionV1::EffectFailed { .. }
            ));
            assert!(attempt.execution_deferral().is_none());
            assert_eq!(attempt.world.internal_event_buf.len(), 3);
        }
        assert_eq!(
            crate::snapshot::canonical_staged_state_snapshot_bytes(&block),
            staged
        );
        assert_eq!(
            block.world.pending_external_events(),
            staged_events.as_slice(),
            "the refused due-certificate effect must not publish staged events"
        );
    }
    assert_eq!(
        crate::snapshot::canonical_state_snapshot_bytes(chain.state()),
        original_state
    );
    assert_eq!(chain.height(), original_height);
    assert_eq!(chain.state().view().latest_block_hash(), original_tip);
    assert_eq!(
        chain.kura().blocks_count(),
        usize::try_from(original_height).unwrap()
    );
}
