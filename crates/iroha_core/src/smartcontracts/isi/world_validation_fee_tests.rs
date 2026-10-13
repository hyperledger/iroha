#[test]
fn sorafs_provider_owner_transition_uses_canonical_constitutional_parliament_pipeline() {
    let kind = ProposalKind::SorafsProviderGovernance(
        iroha_data_model::governance::types::SorafsProviderGovernanceProposal {
            action: Box::new(
                iroha_data_model::isi::sorafs::SorafsProviderGovernanceActionV1::Establish(
                    iroha_data_model::isi::sorafs::EstablishSorafsProviderOwnerV1 {
                        provider_id: iroha_data_model::sorafs::capacity::ProviderId::new(
                            [0xA7; 32],
                        ),
                        owner: ALICE_ID.clone(),
                    },
                ),
            ),
        },
    );
    let (risk_tier, requirements) = super::parliament_attempt_policy_v1(&kind);
    assert_eq!(
        risk_tier,
        iroha_data_model::governance::types::RiskTierV1::Constitutional,
    );
    assert_eq!(
        requirements,
        vec![
            RequiredParliamentBodyV1 {
                body: ParliamentBody::RulesCommittee,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::AgendaCouncil,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::InterestPanel,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::ReviewPanel,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::CoordinationCouncil,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::OversightCommittee,
                decision_mode: ParliamentDecisionModeV1::PublicFinding,
            },
            RequiredParliamentBodyV1 {
                body: ParliamentBody::PolicyJury,
                decision_mode: ParliamentDecisionModeV1::HiddenBindingBallot,
            },
        ]
    );
}
#[test]
fn sorafs_provider_governance_proposer_must_be_a_fully_bonded_citizen() {
    blank_test_state_transaction!(state, block, state_transaction);
    state_transaction.gov.citizenship_bond_amount = Quantity::from(10_u32);

    assert!(
        super::ensure_sorafs_provider_governance_proposer(&ALICE_ID, &state_transaction).is_err(),
        "an unregistered account must not propose provider governance",
    );

    state_transaction.world.citizens.insert(
        ALICE_ID.clone(),
        crate::state::CitizenshipRecord::new(ALICE_ID.clone(), Quantity::from(9_u32), 1),
    );
    assert!(
        super::ensure_sorafs_provider_governance_proposer(&ALICE_ID, &state_transaction).is_err(),
        "an under-bonded citizen must not propose provider governance",
    );

    state_transaction.world.citizens.insert(
        ALICE_ID.clone(),
        crate::state::CitizenshipRecord::new(ALICE_ID.clone(), Quantity::from(10_u32), 1),
    );
    super::ensure_sorafs_provider_governance_proposer(&ALICE_ID, &state_transaction)
        .expect("a fully bonded citizen may propose provider governance");
}
#[test]
fn contract_subject_binding_materializes_missing_account_and_preserves_existing_account() {
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut state_transaction = block.transaction();
    Register::account(Account::new(ALICE_ID.clone()))
        .execute(&ALICE_ID, &mut state_transaction)
        .expect("seed lifecycle authority");
    let missing_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        41,
        DataSpaceId::UNIVERSAL,
    )
    .expect("missing-subject contract address");
    let missing_subject = missing_address.subject_id();
    assert!(state_transaction.world.account(&missing_subject).is_err());
    let bound_subject = super::ensure_contract_subject_binding(
        &ALICE_ID,
        &mut state_transaction,
        &missing_address,
        Some(
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &missing_address,
                ALICE_ID.clone(),
            ),
        ),
    )
    .expect("bind and materialize missing contract subject");
    assert_eq!(bound_subject, missing_subject);
    assert!(state_transaction.world.account(&missing_subject).is_ok());
    assert!(crate::smartcontracts::code::is_historical_contract_subject(
        &state_transaction.world,
        &missing_subject,
    ));
    let existing_address = ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .expect("canonical test network id"),
        &ALICE_ID,
        42,
        DataSpaceId::UNIVERSAL,
    )
    .expect("existing-subject contract address");
    let existing_subject = existing_address.subject_id();
    let marker: Name = "contract_subject_marker".parse().expect("metadata key");
    let mut metadata = Metadata::default();
    metadata.insert(marker.clone(), Json::new("preserve-me"));
    Register::account(Account::new(existing_subject.clone()).with_metadata(metadata.clone()))
        .execute(&ALICE_ID, &mut state_transaction)
        .expect("seed existing contract subject account");
    let bound_existing = super::ensure_contract_subject_binding(
        &ALICE_ID,
        &mut state_transaction,
        &existing_address,
        Some(
            crate::smartcontracts::code::ContractSubjectBinding::new_direct(
                &existing_address,
                ALICE_ID.clone(),
            ),
        ),
    )
    .expect("bind existing contract subject without replacing it");
    assert_eq!(bound_existing, existing_subject);
    assert_eq!(
        state_transaction
            .world
            .account(&existing_subject)
            .expect("existing subject remains registered")
            .metadata()
            .get(&marker),
        metadata.get(&marker),
        "binding must not replace or repair an existing subject account",
    );
}
#[test]
fn upgrade_execute_enforces_capability_at_the_mutation_boundary() {
    use iroha_data_model::permission::Permissions;
    use iroha_executor_data_model::permission::executor::CanUpgradeExecutor;
    fn invalid_upgrade() -> iroha_data_model::isi::Upgrade {
        iroha_data_model::isi::Upgrade::new(iroha_data_model::executor::Executor::new(
            IvmBytecode::from_compiled(Vec::new()),
        ))
    }
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = BlockHeader::new(
        NonZeroU64::new(2).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut state_transaction = block.transaction();
    let error = invalid_upgrade()
        .execute(&ALICE_ID, &mut state_transaction)
        .expect_err("direct native dispatch must not bypass executor-upgrade authority");
    assert!(
        matches!(error, InstructionExecutionError::InvariantViolation(ref message)
            if message.as_ref().contains("CanUpgradeExecutor")),
        "unexpected upgrade denial: {error:?}"
    );
    state_transaction.world.account_permissions.insert(
        ALICE_ID.clone(),
        Permissions::from([Permission::from(CanUpgradeExecutor)]),
    );
    let error = invalid_upgrade()
        .execute(&ALICE_ID, &mut state_transaction)
        .expect_err("the intentionally empty executor bytecode must fail migration");
    assert!(
        !matches!(error, InstructionExecutionError::InvariantViolation(ref message)
            if message.as_ref().contains("CanUpgradeExecutor")),
        "an exact capability holder must reach migration: {error:?}"
    );
}
#[test]
fn validation_fee_derived_runtime_permission_rejects_preexisting_direct_and_role_holders() {
    use iroha_data_model::permission::Permissions;
    use iroha_executor_data_model::permission::asset::CanTransferAsset;
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    let permission: Permission = CanTransferAsset {
        asset: AssetId::new(asset_definition_id, ALICE_ID.clone()),
    }
    .into();
    super::require_absent_validation_fee_runtime_permission(
        &stx,
        &permission,
        "the wrapper DS asset transfer effect",
    )
    .expect("an absent effect permission is eligible for protected derivation");
    stx.world
        .account_permissions
        .insert(BOB_ID.clone(), Permissions::from([permission.clone()]));
    let direct_error = super::require_absent_validation_fee_runtime_permission(
        &stx,
        &permission,
        "the wrapper DS asset transfer effect",
    )
    .expect_err("a caller-made direct effect grant must fail closed");
    assert!(
        format!("{direct_error:?}").contains("absent before enactment"),
        "unexpected direct-holder error: {direct_error:?}"
    );
    stx.world.account_permissions.remove(BOB_ID.clone());
    let role_id: RoleId = "validation_fee_effect_holder".parse().expect("role id");
    let role = Role::new(role_id.clone(), ALICE_ID.clone())
        .add_permission(permission.clone())
        .build(&ALICE_ID);
    stx.world.roles.insert(role_id, role);
    let role_error = super::require_absent_validation_fee_runtime_permission(
        &stx,
        &permission,
        "the wrapper DS asset transfer effect",
    )
    .expect_err("a role-owned effect grant must fail closed");
    assert!(
        format!("{role_error:?}").contains("forbids role ownership"),
        "unexpected role-holder error: {role_error:?}"
    );
    assert!(
        stx.world
            .account_permissions
            .iter()
            .all(|(_, permissions)| !permissions.contains(&permission)),
        "a failed derivation preflight must leave no direct effect token"
    );
}
#[test]
fn validation_fee_derived_runtime_permissions_roll_back_atomically() {
    use iroha_executor_data_model::permission::asset::CanTransferAsset;
    use iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint;
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    let effect_permission: Permission = CanTransferAsset {
        asset: AssetId::new(asset_definition_id, ALICE_ID.clone()),
    }
    .into();
    let contract_address: iroha_data_model::smart_contract::ContractAddress =
        "irohac1qyqqqqqqqqqqqq95fes93ygegsv5enq9mqsz6x4lv4vp9gg4yxgjw"
            .parse()
            .expect("canonical contract address");
    let wrapper_permission: Permission = CanInvokeContractEntrypoint {
        contract: contract_address.clone(),
        entrypoint: "autonomous_validation_fee_tick".to_owned(),
    }
    .into();
    let pool_permission: Permission = CanInvokeContractEntrypoint {
        contract: contract_address,
        entrypoint: "swap_exact_in_quote_public".to_owned(),
    }
    .into();
    let permissions = vec![
        (
            wrapper_permission.clone(),
            ALICE_ID.clone(),
            "the wrapper payout selector",
        ),
        (
            pool_permission.clone(),
            ALICE_ID.clone(),
            "the pool swap selector",
        ),
        (
            effect_permission.clone(),
            BOB_ID.clone(),
            "the wrapper DS asset transfer effect",
        ),
    ];
    let error = super::install_derived_validation_fee_runtime_permissions_with_validation(
        permissions,
        &mut stx,
        |_| {
            Err(InstructionExecutionError::InvariantViolation(
                "forced post-install topology failure".into(),
            )
            .into())
        },
    )
    .expect_err("post-install validation failure must reject lifecycle derivation");
    assert!(
        format!("{error:?}").contains("forced post-install topology failure"),
        "unexpected rollback error: {error:?}"
    );
    for permission in [wrapper_permission, pool_permission, effect_permission] {
        assert!(
            stx.world
                .account_permissions
                .iter()
                .all(|(_, permissions)| !permissions.contains(&permission)),
            "failed post-install validation must roll back every derived permission"
        );
    }
}
fn fee_sponsor_revision_fixture(
    program_id: iroha_data_model::nexus::FeeSponsorProgramId,
    asset_definition_id: AssetDefinitionId,
    revision: u64,
) -> iroha_data_model::nexus::FeeSponsorProgramRevision {
    use iroha_data_model::nexus::{
        FeeSponsorAssetBudget, FeeSponsorEligibility, FeeSponsorIvmSelector,
        FeeSponsorProgramRevision, FeeSponsorRule, FeeSponsorRuleEffect, FeeSponsorRuleSelector,
    };
    FeeSponsorProgramRevision {
        program_id,
        revision,
        eligibility: FeeSponsorEligibility::EnrolledOnly,
        rules: vec![FeeSponsorRule {
            id: "allow_ivm".parse().expect("rule name"),
            effect: FeeSponsorRuleEffect::Allow,
            selectors: vec![FeeSponsorRuleSelector::Ivm(FeeSponsorIvmSelector {
                code_hash: Hash::new(b"fee-sponsor-global-scope-test"),
            })],
        }],
        asset_budgets: vec![FeeSponsorAssetBudget {
            asset_definition_id,
            per_transaction: Quantity::from(1_u32),
            per_block: Quantity::from(10_u32),
            per_program_epoch: Quantity::from(100_u32),
            per_beneficiary_epoch: Quantity::from(5_u32),
            reserve_floor: Quantity::zero(),
            epoch_length_blocks: NonZeroU64::new(100).expect("nonzero epoch"),
        }],
    }
}
/// Immutable, exact-input proof fixtures owned only by fee-sponsor unit tests.
///
/// The first artifact for each complete request is produced by the unchanged
/// genuine helper. The lookup mutex is released before production, and callers
/// receive owned clones so their negative mutations cannot change shared bytes.
struct VerifiedFeeSponsorProofFixtures {
    entries: std::sync::Mutex<Vec<VerifiedFeeSponsorProofFixture>>,
}

struct VerifiedFeeSponsorProofFixture {
    batch: fastpq_prover::TransitionBatch,
    binding: iroha_data_model::nexus::AxtFastpqBinding,
    proof: std::sync::Arc<std::sync::OnceLock<Vec<u8>>>,
}

impl VerifiedFeeSponsorProofFixtures {
    const fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn get_or_produce(
        &self,
        batch: &fastpq_prover::TransitionBatch,
        binding: &iroha_data_model::nexus::AxtFastpqBinding,
        produce: impl FnOnce() -> Vec<u8>,
    ) -> Vec<u8> {
        let proof = {
            let mut entries = self.entries.lock().expect("fee-sponsor fixture lookup");
            if let Some(entry) = entries
                .iter()
                .find(|entry| &entry.batch == batch && &entry.binding == binding)
            {
                std::sync::Arc::clone(&entry.proof)
            } else {
                let proof = std::sync::Arc::new(std::sync::OnceLock::new());
                entries.push(VerifiedFeeSponsorProofFixture {
                    batch: batch.clone(),
                    binding: binding.clone(),
                    proof: std::sync::Arc::clone(&proof),
                });
                proof
            }
        };
        // OnceLock retains only a successful initialization. A genuine producer
        // panic propagates to its test and leaves this exact request retryable.
        proof.get_or_init(produce).clone()
    }
}

// These values test only cache ownership and complete-key equality. They are
// never passed to a prover, verifier, instruction, or SDK qualification path.
fn verified_fee_sponsor_proof_cache_test_key() -> (
    fastpq_prover::TransitionBatch,
    iroha_data_model::nexus::AxtFastpqBinding,
) {
    let mut batch = fastpq_prover::TransitionBatch::new(
        fastpq_prover::AXT_DEFAULT_PARAMETER,
        fastpq_prover::PublicInputs {
            dsid: [7; 16],
            slot: 1,
            old_root: [1; 32],
            new_root: [2; 32],
            perm_root: [3; 32],
            tx_set_hash: [4; 32],
        },
    );
    batch.push(fastpq_prover::StateTransition::new(
        b"cache-test-account".to_vec(),
        vec![10],
        vec![0],
        fastpq_prover::OperationKind::Transfer,
    ));
    batch.metadata.insert(
        fastpq_prover::AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY.to_owned(),
        vec![0x63; 32],
    );
    batch.metadata.insert(
        fastpq_prover::AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.to_owned(),
        vec![0; 33],
    );
    batch.metadata.insert(
        fastpq_prover::AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY.to_owned(),
        20_u64.to_le_bytes().to_vec(),
    );
    let binding = iroha_data_model::nexus::AxtFastpqBinding {
        parameter: fastpq_prover::AXT_DEFAULT_PARAMETER.to_owned(),
        source_dsid: 7,
        source_dataspace: "cache-test-dataspace".to_owned(),
        source_receipt_id: "cache-test-receipt".to_owned(),
        source_tx_commitment: "11".repeat(32),
        claim_type: "tx_predicate".to_owned(),
        claim_digest: "22".repeat(32),
        witness_commitment: "33".repeat(32),
        policy_commitment: "44".repeat(32),
        verified_effect_type: "fee_sponsor_vault_allocation".to_owned(),
        corridor: "cache-test-corridor".to_owned(),
        verifier_id: "fastpq".to_owned(),
        verifier_version: "v1".to_owned(),
        target_dsids: vec![0],
        effect_binding: None,
        remote_spend_intent_commitments: Vec::new(),
    };
    (batch, binding)
}

#[test]
fn verified_fee_sponsor_proof_fixtures_keep_policy_da_and_expiry_separate() {
    let fixtures = VerifiedFeeSponsorProofFixtures::new();
    let (batch, binding) = verified_fee_sponsor_proof_cache_test_key();
    let mut wrong_policy = binding.clone();
    wrong_policy.policy_commitment = "64".repeat(32);
    let mut with_da = batch.clone();
    let mut da = vec![1];
    da.extend_from_slice(&[0x22; 32]);
    with_da.metadata.insert(
        fastpq_prover::AXT_FASTPQ_DA_COMMITMENT_METADATA_KEY.to_owned(),
        da,
    );
    let mut later_expiry = batch.clone();
    later_expiry.metadata.insert(
        fastpq_prover::AXT_FASTPQ_EXPIRY_SLOT_METADATA_KEY.to_owned(),
        21_u64.to_le_bytes().to_vec(),
    );
    for (index, (batch, binding)) in [
        (&batch, &binding),
        (&batch, &wrong_policy),
        (&with_da, &binding),
        (&later_expiry, &binding),
    ]
    .into_iter()
    .enumerate()
    {
        let bytes = vec![u8::try_from(index).expect("four fixture contexts")];
        assert_eq!(
            fixtures.get_or_produce(batch, binding, || bytes.clone()),
            bytes
        );
        assert_eq!(
            fixtures.get_or_produce(batch, binding, || panic!("same complete request")),
            bytes
        );
    }
}

#[test]
fn verified_fee_sponsor_proof_fixtures_use_complete_batch_and_binding_values() {
    let fixtures = VerifiedFeeSponsorProofFixtures::new();
    let (batch, binding) = verified_fee_sponsor_proof_cache_test_key();
    assert_eq!(
        fixtures.get_or_produce(&batch, &binding, || vec![0]),
        vec![0]
    );
    let mut requests = Vec::new();
    let mut different = batch.clone();
    different.parameter.push_str("-different");
    requests.push((different, binding.clone()));
    let mut different = batch.clone();
    different.public_inputs.old_root[0] ^= 1;
    requests.push((different, binding.clone()));
    let mut different = batch.clone();
    different.transitions[0].pre_value.push(1);
    requests.push((different, binding.clone()));
    let mut different = batch.clone();
    different
        .metadata
        .insert("private-witness".to_owned(), vec![1]);
    requests.push((different, binding.clone()));
    let mut different = batch.clone();
    different.metadata.insert(
        fastpq_prover::AXT_FASTPQ_MANIFEST_ROOT_METADATA_KEY.to_owned(),
        vec![0x64; 32],
    );
    requests.push((different, binding.clone()));
    let mut different = binding.clone();
    different.source_dsid += 1;
    requests.push((batch.clone(), different));
    let mut different = binding.clone();
    different.claim_digest = "55".repeat(32);
    requests.push((batch.clone(), different));
    let mut different = binding.clone();
    different.remote_spend_intent_commitments.push([1; 32]);
    requests.push((batch.clone(), different));
    for (index, (different_batch, different_binding)) in requests.iter().enumerate() {
        let bytes = vec![u8::try_from(index + 1).expect("bounded key cases")];
        assert_eq!(
            fixtures.get_or_produce(different_batch, different_binding, || bytes.clone()),
            bytes
        );
    }
    assert_eq!(
        fixtures.get_or_produce(&batch, &binding, || panic!("original complete request")),
        vec![0]
    );
}

#[test]
fn verified_fee_sponsor_proof_fixtures_return_independent_owned_bytes() {
    let fixtures = VerifiedFeeSponsorProofFixtures::new();
    let (batch, binding) = verified_fee_sponsor_proof_cache_test_key();
    let mut mutated = fixtures.get_or_produce(&batch, &binding, || vec![1, 2, 3]);
    mutated[0] ^= 0xFF;
    mutated.push(4);
    assert_eq!(
        fixtures.get_or_produce(&batch, &binding, || panic!("shared value already produced")),
        vec![1, 2, 3]
    );
    assert_ne!(mutated, vec![1, 2, 3]);
}

#[test]
fn verified_fee_sponsor_proof_fixtures_produce_once_for_concurrent_equal_requests() {
    let fixtures = VerifiedFeeSponsorProofFixtures::new();
    let (batch, binding) = verified_fee_sponsor_proof_cache_test_key();
    let start = std::sync::Barrier::new(8);
    let attempts = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..8 {
            threads.push(scope.spawn(|| {
                start.wait();
                fixtures.get_or_produce(&batch, &binding, || {
                    assert_eq!(
                        attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        0
                    );
                    vec![1, 2, 3]
                })
            }));
        }
        for thread in threads {
            assert_eq!(
                thread.join().expect("cache caller completed"),
                vec![1, 2, 3]
            );
        }
    });
    assert_eq!(attempts.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn verified_fee_sponsor_proof_fixtures_do_not_cache_panics_or_poison_other_keys() {
    let fixtures = VerifiedFeeSponsorProofFixtures::new();
    let (batch, binding) = verified_fee_sponsor_proof_cache_test_key();
    let failed = std::panic::catch_unwind(|| {
        fixtures.get_or_produce(&batch, &binding, || panic!("synthetic producer refusal"))
    });
    assert!(
        failed.is_err(),
        "producer failure must reach its original caller"
    );
    let mut unrelated = binding.clone();
    unrelated.source_dsid += 1;
    assert_eq!(
        fixtures.get_or_produce(&batch, &unrelated, || vec![2]),
        vec![2]
    );
    assert_eq!(
        fixtures.get_or_produce(&batch, &binding, || vec![1]),
        vec![1]
    );
    assert_eq!(
        fixtures.get_or_produce(&batch, &binding, || panic!("successful retry is cached")),
        vec![1]
    );
}

fn verified_fee_sponsor_registration_fixture(
    frozen_manifest_root: Option<[u8; 32]>,
    proof_manifest_root: [u8; 32],
    policy_commitment_manifest_root: [u8; 32],
    da_commitment: Option<[u8; 32]>,
    proof_expiry: u64,
) -> (
    State,
    iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation,
) {
    use iroha_data_model::nexus::{
        AxtEffectBinding, AxtFastpqBinding, AxtPolicyEntry, FeeSponsorProgram, FeeSponsorProgramId,
        FeeSponsorProgramLifecycle, FeeSponsorProgramRevisionKey, FeeSponsorVault,
        FeeSponsorVaultAllocationClaim, FeeSponsorVaultKey,
        fee_sponsor_vault_allocation_claim_digest, fee_sponsor_vault_policy_commitment,
        fee_sponsor_vault_source_state_root,
    };

    let source_dataspace_id = DataSpaceId::new(7);
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "proof_policy".parse().expect("program name"),
    );
    let verified_allocation = Quantity::from(10_u32);
    let source_height = 1;
    let expires_at_height = 20;
    let source_state_root = fee_sponsor_vault_source_state_root(
        &program_id,
        1,
        &asset_definition_id,
        &verified_allocation,
        source_dataspace_id,
        source_height,
    );
    let lease_id = Hash::new(b"verified-fee-sponsor-policy-lease");
    let claim = FeeSponsorVaultAllocationClaim {
        program_id: program_id.clone(),
        program_revision: 1,
        asset_definition_id: asset_definition_id.clone(),
        verified_allocation: verified_allocation.clone(),
        source_dataspace_id,
        source_height,
        source_state_root,
        expires_at_height,
        lease_id,
    };
    let source_tx_commitment = Hash::new(b"verified-fee-sponsor-policy-source-tx");
    let claim_digest = fee_sponsor_vault_allocation_claim_digest(&claim);
    let custody = iroha_config::parameters::actual::Nexus::default()
        .fees
        .sponsor_vault_custody_account_id
        .clone();
    let binding = AxtFastpqBinding {
        parameter: fastpq_prover::AXT_DEFAULT_PARAMETER.to_owned(),
        source_dsid: source_dataspace_id.as_u64(),
        source_dataspace: "dataspace-7".to_owned(),
        source_receipt_id: "verified-fee-sponsor-policy-receipt".to_owned(),
        source_tx_commitment: hex::encode(source_tx_commitment.as_ref()),
        claim_type: "tx_predicate".to_owned(),
        claim_digest: hex::encode(claim_digest.as_ref()),
        witness_commitment: hex::encode(Hash::new(b"verified-fee-sponsor-policy-witness").as_ref()),
        policy_commitment: hex::encode(
            fee_sponsor_vault_policy_commitment(&policy_commitment_manifest_root).as_ref(),
        ),
        verified_effect_type: "fee_sponsor_vault_allocation".to_owned(),
        corridor: "fee-sponsor-program:proof-policy".to_owned(),
        verifier_id: "fastpq".to_owned(),
        verifier_version: "v1".to_owned(),
        target_dsids: vec![DataSpaceId::UNIVERSAL.as_u64()],
        effect_binding: Some(AxtEffectBinding {
            destination_domain: None,
            destination_account_id: Some(custody.to_string()),
            vault_account_id: Some(custody.to_string()),
            issuance_account_id: None,
            source_asset_definition_id: Some(asset_definition_id.to_string()),
            destination_asset_definition_id: None,
            source_amount_i64: Some(10),
            destination_amount_i64: None,
        }),
        remote_spend_intent_commitments: Vec::new(),
    };
    let mut dsid_bytes = [0_u8; 16];
    dsid_bytes[..8].copy_from_slice(&source_dataspace_id.as_u64().to_le_bytes());
    let mut batch = fastpq_prover::TransitionBatch::new(
        fastpq_prover::AXT_DEFAULT_PARAMETER,
        fastpq_prover::PublicInputs {
            dsid: dsid_bytes,
            slot: source_height,
            old_root: *source_state_root.as_ref(),
            new_root: *source_state_root.as_ref(),
            perm_root: Hash::new(b"verified-fee-sponsor-policy-permissions").into(),
            tx_set_hash: claim_digest.into(),
        },
    );
    // Prove the real sponsor-to-custody funding transfer. The allocation claim
    // remains separately bound to the authoritative vault snapshot, policy and
    // lease; no opaque authorization label can replace a witnessed transfer.
    let delta = iroha_data_model::fastpq::TransferDeltaTranscript {
        from_account: ALICE_ID.clone(),
        to_account: custody,
        asset_definition: asset_definition_id.clone(),
        amount: verified_allocation.clone(),
        from_balance_before: verified_allocation.clone(),
        from_balance_after: Quantity::zero(),
        to_balance_before: Quantity::zero(),
        to_balance_after: verified_allocation.clone(),
        from_smt_witness: Default::default(),
        to_smt_witness: Default::default(),
    };
    let digest =
        fastpq_prover::gadgets::transfer::compute_poseidon_digest(&delta, &source_tx_commitment);
    let mut transcripts = vec![iroha_data_model::fastpq::TransferTranscript {
        batch_hash: source_tx_commitment,
        deltas: vec![delta],
        authority_digest: Hash::new(
            &norito::encode_canonical(&*ALICE_ID).expect("canonical funding authority"),
        ),
        poseidon_preimage_digest: Some(digest),
    }];
    use fastpq_prover::gadgets::public_transfer_statement::{
        PublicTransferLimits, TransferSmtBuildLimits, materialize_quantity_public_transfers,
        public_claims_from_transcripts,
    };
    let limits = PublicTransferLimits::default();
    let public = public_claims_from_transcripts(&transcripts, limits).expect("exact funding claim");
    let materialized = {
        // This test fixture owns its finite tree pool; production supplies its original owner.
        let tree_claims = &public;
        let tree_limits =
            TransferSmtBuildLimits::for_update_limit(2).expect("two exact account updates");
        let tree_updates = tree_claims
            .iter()
            .try_fold(0_usize, |count, claim| {
                count.checked_add(claim.deltas.len())
            })
            .expect("fixture effect count fits")
            .checked_mul(2)
            .expect("fixture row count fits");
        let tree_bytes = tree_limits
            .allocation_bytes(tree_updates, tree_updates)
            .expect("fixture tree allocation demand fits");
        let tree_budget = iroha_allocation::AllocationBudget::new(tree_bytes);
        let mut tree_reservation = tree_budget
            .try_reserve_bytes(tree_bytes)
            .expect("fixture owns complete tree credit");
        materialize_quantity_public_transfers(
            tree_claims,
            batch.public_inputs,
            fastpq_prover::ProofSemantics::AxtTransferClaim,
            limits,
            tree_limits,
            &tree_budget,
            &mut tree_reservation,
        )
    }
    .expect("canonical funding SMT roots and quantity rows");
    let (rows, inputs, _, private) = materialized.into_parts();
    let witnesses = private.pairs();
    transcripts[0].deltas[0].from_smt_witness = witnesses[0][0].clone();
    transcripts[0].deltas[0].to_smt_witness = witnesses[0][1].clone();
    batch.transitions = rows;
    batch.public_inputs = inputs;
    batch.metadata.insert(
        iroha_data_model::fastpq::TRANSFER_TRANSCRIPTS_METADATA_KEY.into(),
        norito::encode_canonical(&transcripts).expect("canonical funding transfer transcripts"),
    );
    batch.metadata.insert(
        "entry_hash".to_owned(),
        source_tx_commitment.as_ref().to_vec(),
    );
    batch.sort();
    fastpq_prover::bind_axt_batch_with_proof_metadata(
        &mut batch,
        &binding,
        proof_manifest_root,
        da_commitment,
        Some(10),
        Some(proof_expiry),
    )
    .expect("bind verified fee sponsor proof metadata");
    static PROOFS: VerifiedFeeSponsorProofFixtures = VerifiedFeeSponsorProofFixtures::new();
    let proof = PROOFS.get_or_produce(&batch, &binding, || {
        crate::unit_test_support::prove_axt_bound_batch_when_available(&batch, &binding)
    });
    let proof_blob = fastpq_prover::axt_proof_blob_from_bound_batch(
        &batch,
        proof,
        proof_manifest_root,
        da_commitment,
        Some(proof_expiry),
    )
    .expect("package verified fee sponsor proof");

    let instruction = iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation {
        program_id: program_id.clone(),
        program_revision: 1,
        asset_definition_id: asset_definition_id.clone(),
        verified_allocation: verified_allocation.clone(),
        source_dataspace_id,
        source_height,
        source_state_root,
        expires_at_height,
        lease_id,
        manifest_root: proof_manifest_root,
        proof_blob,
    };

    let mut world = World::default();
    if let Some(manifest_root) = frozen_manifest_root {
        world.axt_policies.insert(
            source_dataspace_id,
            AxtPolicyEntry {
                manifest_root,
                target_lane: LaneId::SINGLE,
                active_handle_era: 1,
                next_handle_counter: 1,
                current_slot: 1,
            },
        );
    }
    world.asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::numeric(
            asset_definition_id.clone(),
            "global fee asset".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID),
    );
    world.fee_sponsor_program_revisions.insert(
        FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
        fee_sponsor_revision_fixture(program_id.clone(), asset_definition_id.clone(), 1),
    );
    let mut program = FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone());
    program.lifecycle = FeeSponsorProgramLifecycle::Active;
    program.active_revision = Some(1);
    world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let vault_key = FeeSponsorVaultKey {
        program_id,
        asset_definition_id,
    };
    world.fee_sponsor_vaults.insert(
        vault_key.clone(),
        FeeSponsorVault {
            key: vault_key,
            balance: verified_allocation,
        },
    );
    (
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ),
        instruction,
    )
}
fn execute_verified_fee_sponsor_registration(
    state: &State,
    instruction: iroha_data_model::isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation,
) -> Result<(), Error> {
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();

    instruction.execute(&ALICE_ID, &mut transaction)
}
#[test]
fn verified_fee_sponsor_registration_accepts_exact_proof_policy_context() {
    let manifest_root = [0x63; 32];
    let (state, instruction) = verified_fee_sponsor_registration_fixture(
        Some(manifest_root),
        manifest_root,
        manifest_root,
        None,
        20,
    );
    let mut wrong_effect = instruction.clone();
    let mut envelope: iroha_data_model::nexus::AxtProofEnvelope =
        norito::decode_canonical(&wrong_effect.proof_blob.payload)
            .expect("canonical funding proof");
    envelope
        .fastpq_binding
        .as_mut()
        .expect("exact funding binding")
        .verified_effect_type = "unrelated_effect".to_owned();
    wrong_effect.proof_blob.payload = norito::encode_canonical(&envelope).unwrap();
    let error = execute_verified_fee_sponsor_registration(&state, wrong_effect)
        .expect_err("a genuine transfer proof cannot authorize a different allocation effect");
    assert!(format!("{error:?}").contains("wrong source or effect type"));
    let mut wrong_amount = instruction.clone();
    wrong_amount.verified_allocation = Quantity::from(9_u32);
    let error = execute_verified_fee_sponsor_registration(&state, wrong_amount)
        .expect_err("the exact proved allocation digest cannot authorize a different amount");
    assert!(format!("{error:?}").contains("committed amount mismatch"));
    let mut wrong_lease = instruction.clone();
    wrong_lease.lease_id = Hash::new(b"different-allocation-lease");
    let error = execute_verified_fee_sponsor_registration(&state, wrong_lease)
        .expect_err("the proved allocation digest cannot authorize a replacement lease");
    assert!(format!("{error:?}").contains("claim digest mismatch"));
    execute_verified_fee_sponsor_registration(&state, instruction)
        .expect("exact frozen policy and proof metadata must register");
}
#[test]
fn verified_fee_sponsor_registration_rejects_oversized_proof_before_decode() {
    let manifest_root = [0x63; 32];
    let (state, mut instruction) = verified_fee_sponsor_registration_fixture(
        Some(manifest_root),
        manifest_root,
        manifest_root,
        None,
        20,
    );
    instruction.proof_blob.payload =
        vec![0xA5; iroha_data_model::nexus::MAX_AXT_PROOF_BLOB_PAYLOAD_BYTES + 1];

    let error = execute_verified_fee_sponsor_registration(&state, instruction)
        .expect_err("oversized proof payload must fail before canonical decode");
    assert!(
        format!("{error:?}").contains("decode limit"),
        "unexpected oversized proof rejection: {error:?}"
    );
}
#[test]
fn verified_fee_sponsor_registration_rejects_missing_or_rotated_frozen_policy() {
    let proof_manifest_root = [0x63; 32];
    let (state, instruction) = verified_fee_sponsor_registration_fixture(
        None,
        proof_manifest_root,
        proof_manifest_root,
        None,
        20,
    );
    let error = execute_verified_fee_sponsor_registration(&state, instruction)
        .expect_err("missing frozen source policy must fail");
    assert!(format!("{error:?}").contains("no frozen AXT policy"));

    let (state, instruction) = verified_fee_sponsor_registration_fixture(
        Some([0x64; 32]),
        proof_manifest_root,
        proof_manifest_root,
        None,
        20,
    );
    let error = execute_verified_fee_sponsor_registration(&state, instruction)
        .expect_err("proof under a rotated manifest must fail");
    assert!(format!("{error:?}").contains("frozen AXT policy"));
}
#[test]
fn verified_fee_sponsor_registration_rejects_wrong_policy_da_and_expiry() {
    let manifest_root = [0x63; 32];
    let (state, instruction) = verified_fee_sponsor_registration_fixture(
        Some(manifest_root),
        manifest_root,
        [0x64; 32],
        None,
        20,
    );
    let error = execute_verified_fee_sponsor_registration(&state, instruction)
        .expect_err("owner-selected policy commitment must fail");
    assert!(format!("{error:?}").contains("policy commitment mismatch"));

    let (state, instruction) = verified_fee_sponsor_registration_fixture(
        Some(manifest_root),
        manifest_root,
        manifest_root,
        Some([0x22; 32]),
        20,
    );
    let error = execute_verified_fee_sponsor_registration(&state, instruction)
        .expect_err("fee sponsor proof with DA must fail");
    assert!(format!("{error:?}").contains("must not carry a DA commitment"));

    let (state, instruction) = verified_fee_sponsor_registration_fixture(
        Some(manifest_root),
        manifest_root,
        manifest_root,
        None,
        21,
    );
    let error = execute_verified_fee_sponsor_registration(&state, instruction)
        .expect_err("proof expiry must equal the lease deadline");
    assert!(format!("{error:?}").contains("must equal the allocation lease expiry"));
}
#[test]
fn initial_genesis_authority_can_bootstrap_fee_sponsor_lifecycle() {
    use iroha_data_model::{
        isi::nexus::{
            ActivateFeeSponsorProgramRevision, CreateFeeSponsorProgram,
            EnrollFeeSponsorBeneficiary, FundFeeSponsorProgram, StageFeeSponsorProgramRevision,
        },
        nexus::{
            FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramLifecycle, FeeSponsorVaultKey,
        },
    };
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let custody = stx.nexus.fees.sponsor_vault_custody_account_id.clone();
    for account in [ALICE_ID.clone(), BOB_ID.clone(), custody.clone()] {
        if stx.world.account(&account).is_err() {
            Register::account(Account::new(account))
                .execute(&ALICE_ID, &mut stx)
                .expect("register genesis fee sponsor fixture account");
        }
    }
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    stx.world.asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::numeric(
            asset_definition_id.clone(),
            "global genesis fee asset".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID),
    );
    let sponsor_asset = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    Mint::asset_quantity(Quantity::from(10_u32), sponsor_asset.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("prefund genesis sponsor");
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "genesis_bootstrap".parse().expect("program name"),
    );

    // Retain the prefunded World, then execute the lifecycle under the original
    // signed genesis authority instead of a header-shaped component transaction.
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("retain prefunded component World only");
    let mut config = original_world_config(state);
    config.genesis_key = iroha_test_samples::BOB_KEYPAIR.clone();
    config.genesis_instructions = vec![
        CreateFeeSponsorProgram {
            program: FeeSponsorProgram::new(program_id.clone(), ALICE_ID.clone()),
        }
        .into(),
        StageFeeSponsorProgramRevision {
            revision: fee_sponsor_revision_fixture(
                program_id.clone(),
                asset_definition_id.clone(),
                1,
            ),
        }
        .into(),
        EnrollFeeSponsorBeneficiary {
            program_id: program_id.clone(),
            beneficiary: ALICE_ID.clone(),
        }
        .into(),
        FundFeeSponsorProgram {
            program_id: program_id.clone(),
            asset_definition_id: asset_definition_id.clone(),
            amount: Quantity::from(10_u32),
        }
        .into(),
        ActivateFeeSponsorProgramRevision {
            program_id: program_id.clone(),
            revision: 1,
            activate_at_height: 1,
        }
        .into(),
    ];
    let prepared = crate::sumeragi::test_chain::CertifiedTestChain::prepare(config)
        .expect("all five fee sponsor actions form an authenticated signed BOB genesis");
    let topology = crate::sumeragi::network_topology::Topology::new(
        prepared
            .validator_keys
            .iter()
            .map(|key| crate::PeerId::new(key.public_key().clone())),
    );
    let (valid, mut original) = {
        let selected_genesis = prepared.genesis.block().clone();
        let selected_scope = crate::sumeragi::epoch::authenticated_genesis(&selected_genesis)
            .expect("signed fixture root scope")
            .into_parts()
            .1;
        crate::block::ValidBlock::validate_signed_genesis(
            selected_genesis,
            &topology,
            &BOB_ID,
            &iroha_primitives::time::TimeSource::new_system(),
            &prepared.state,
            iroha_data_model::parameter::system::ConsensusMode::Permissioned,
            selected_scope,
        )
    }
    .unpack(|_| {})
    .unwrap_or_else(|(_, error)| panic!("original sponsor genesis executes: {error}"));
    assert!(valid.as_ref().output_results().all(|result| result.is_ok()));
    // Signed-genesis validation already captured the execution witness and
    // drained its staging map. Inspect that retained source-owned evidence.
    let captured = original
        .take_exec_witness()
        .expect("authenticated genesis retains its captured funding witness");
    let witness = captured.wire();
    let original_transfer_count = witness
        .fastpq_transcripts
        .iter()
        .map(|bundle| bundle.transcripts.len())
        .sum::<usize>();
    assert!(original.drain_transfer_transcripts().is_empty());
    assert_eq!(witness.fastpq_transcripts.len(), 1);
    let bundle = &witness.fastpq_transcripts[0];
    assert!(
        valid
            .as_ref()
            .external_transactions()
            .any(|transaction| { Hash::from(transaction.hash()) == bundle.entry_hash })
    );
    assert_eq!(bundle.transcripts.len(), 1);
    let transcript = &bundle.transcripts[0];
    assert_eq!(transcript.batch_hash, bundle.entry_hash);
    // The original authority is the signed BOB genesis signer, with the
    // domain-separated AccountId commitment specified by the transfer gadget.
    let mut authority_preimage = b"iroha:fastpq:v1:authority|".to_vec();
    authority_preimage.extend_from_slice(&norito::codec::Encode::encode(&*BOB_ID));
    assert_eq!(transcript.authority_digest, Hash::new(authority_preimage));
    assert_ne!(
        transcript.authority_digest,
        crate::fastpq::authority_digest(&ALICE_ID)
    );
    assert_eq!(transcript.deltas.len(), 1);
    let delta = &transcript.deltas[0];
    assert_eq!(delta.from_account, *ALICE_ID);
    assert_eq!(delta.to_account, custody);
    assert_eq!(delta.asset_definition, asset_definition_id);
    assert_eq!(delta.amount, Quantity::from(10_u32));
    assert_eq!(delta.from_balance_before, Quantity::from(10_u32));
    assert_eq!(delta.from_balance_after, Quantity::zero());
    assert_eq!(delta.to_balance_before, Quantity::zero());
    assert_eq!(delta.to_balance_after, Quantity::from(10_u32));
    let stx = original.transaction();
    let program = stx
        .world
        .fee_sponsor_programs
        .get(&program_id)
        .expect("bootstrapped sponsor program");
    assert_eq!(program.lifecycle, FeeSponsorProgramLifecycle::Active);
    assert_eq!(program.active_revision, Some(1));
    let vault_key = FeeSponsorVaultKey {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
    };
    assert_eq!(
        stx.world
            .fee_sponsor_vaults
            .get(&vault_key)
            .expect("genesis funding creates the isolated sponsor vault")
            .balance,
        Quantity::from(10_u32),
    );
    assert_eq!(
        original_transfer_count, 1,
        "genesis sponsor funding must retain one auditable transfer transcript",
    );
    assert!(
        stx.world.assets.get(&sponsor_asset).is_none(),
        "fully funded sponsor source is removed at zero balance",
    );
    let custody_asset = AssetId::new(asset_definition_id, custody);
    assert_eq!(
        stx.world
            .assets
            .get(&custody_asset)
            .expect("genesis sponsor funding reaches custody")
            .as_ref(),
        &Quantity::from(10_u32),
    );
}

#[test]
fn prospective_fee_sponsor_enrollment_funds_only_exact_self_bootstrap() {
    use iroha_data_model::{
        isi::{
            instruction_wire_id,
            nexus::{ActivateFeeSponsorProgramRevision, EnrollFeeSponsorBeneficiary},
            smart_contract_code::UploadSmartContractCodeChunk,
        },
        nexus::{
            FeeRejectionCode, FeeSponsorEnrollmentKey, FeeSponsorNativeInstructionSelector,
            FeeSponsorProgramRevisionKey, FeeSponsorRuleSelector,
        },
        transaction::{FeePaymentIntent, TransactionDomain, signed::TransactionPayload},
    };
    let fresh = |seed| {
        AccountId::new(
            iroha_crypto::KeyPair::try_from_seed(vec![seed; 32], iroha_crypto::Algorithm::Ed25519)
                .expect("derive prospective beneficiary")
                .public_key()
                .clone(),
        )
    };
    let beneficiary = fresh(0x71);
    let other = fresh(0x72);
    let bootstrap = |authority: &AccountId| -> Vec<InstructionBox> {
        let permission: Permission =
            iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode
                .into();
        vec![
            Register::account(Account::new(authority.clone())).into(),
            Grant::account_permission(permission, authority.clone()).into(),
            UploadSmartContractCodeChunk {
                artifact_id: iroha_data_model::smart_contract::ContractArtifactId::new(
                    iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                    Hash::new(b"prospective publisher code"),
                ),
                total_size: 4,
                chunk_index: 0,
                chunk_count: 1,
                chunk: vec![1, 2, 3, 4],
            }
            .into(),
        ]
    };
    let (state, program_id, vault_key) = staged_fee_sponsor_activation_fixture();
    let header =
        iroha_data_model::block::BlockHeader::new(NonZeroU64::new(146).unwrap(), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    assert!(!crate::executor::is_initial_genesis_context(&stx));
    assert!(stx.world.account(&beneficiary).is_err());
    assert!(stx.world.account(&other).is_err());
    stx.world
        .fee_sponsor_enrollments
        .remove(FeeSponsorEnrollmentKey {
            program_id: program_id.clone(),
            beneficiary: ALICE_ID.clone(),
        });
    EnrollFeeSponsorBeneficiary {
        program_id: program_id.clone(),
        beneficiary: beneficiary.clone(),
    }
    .execute(&ALICE_ID, &mut stx)
    .expect("owner may authorize an exact prospective beneficiary");
    assert!(
        stx.world.account(&beneficiary).is_err(),
        "enrollment does not create the account"
    );
    let revision_key = FeeSponsorProgramRevisionKey::new(program_id.clone(), 1);
    let mut revision = stx
        .world
        .fee_sponsor_program_revisions
        .get(&revision_key)
        .unwrap()
        .clone();
    revision.rules[0].selectors = bootstrap(&beneficiary)
        .iter()
        .map(|instruction| {
            FeeSponsorRuleSelector::NativeInstruction(FeeSponsorNativeInstructionSelector {
                wire_id: instruction_wire_id(instruction).unwrap().to_owned(),
                asset_definition_id: None,
            })
        })
        .collect();
    revision.asset_budgets[0].per_transaction = Quantity::from(2_u32);
    revision
        .validate()
        .expect("bounded native bootstrap revision");
    stx.world
        .fee_sponsor_program_revisions
        .insert(revision_key, revision);
    ActivateFeeSponsorProgramRevision {
        program_id: program_id.clone(),
        revision: 1,
        activate_at_height: 146,
    }
    .execute(&ALICE_ID, &mut stx)
    .expect("funded program activates with exact prospective eligibility");
    let mut nexus = stx.nexus.clone();
    nexus.dataspace_fee_sponsor_program_ids.clear();
    nexus.fees.fee_asset_id = vault_key.asset_definition_id.to_string();
    assert_eq!(
        crate::block::resolve_network_xor_asset_definition(&stx.world, &nexus.fees.fee_asset_id, 0)
            .expect("completed pin read"),
        Some(vault_key.asset_definition_id.clone()),
        "sponsor funding must use the network's exact XOR asset"
    );
    assert!(
        stx.world
            .asset_definition(&vault_key.asset_definition_id)
            .is_ok()
    );
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = "0.001".parse().unwrap();
    nexus.fees.per_gas_unit_fee = "0.00005".parse().unwrap();
    nexus.fees.settlement_mode = iroha_config::parameters::actual::NexusFeeSettlementMode::Direct;
    let pipeline = iroha_config::parameters::actual::Pipeline::default();
    for (authority, eligible) in [(&beneficiary, true), (&other, false)] {
        let mut payload = TransactionPayload {
            domain: TransactionDomain::Network(
                "hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                    .parse()
                    .unwrap(),
            ),
            authority: authority.clone(),
            creation_time_ms: 0,
            instructions: bootstrap(authority).into(),
            time_to_live_ms: NonZeroU64::new(60_000),
            nonce: None,
            fee_payment: FeePaymentIntent::sponsor(program_id.clone(), 1, Vec::new(), None),

            metadata: Metadata::default(),
            attachments: None,
        };
        let result = crate::executor::quote_nexus_fee_admission_draft(
            &stx.world,
            &nexus,
            &pipeline,
            &crate::gas::DEFAULT_ZK_GAS,
            &payload,
            0,
            crate::smartcontracts::isi::sccp::hold::committed_time_ms(&stx)
                .expect("original committed fixture time"),
            146,
            None,
        );
        if eligible {
            let quoted = result.expect("exact absent beneficiary can fund its first bootstrap");
            assert!(
                !quoted.quote.charges.is_empty(),
                "bootstrap remains fee-paying"
            );
            payload.fee_payment = quoted.recommended_intent;
            crate::executor::quote_nexus_fee_admission_payload(
                &stx.world,
                &nexus,
                &pipeline,
                &crate::gas::DEFAULT_ZK_GAS,
                &payload,
                0,
                crate::smartcontracts::isi::sccp::hold::committed_time_ms(&stx)
                    .expect("original committed fixture time"),
                146,
                None,
            )
            .expect("exact signature-bound quote also passes strict admission");
        } else {
            assert_eq!(
                crate::execution_attempt::expect_completed_rejection(
                    result.expect_err("other absent identity is not enrolled")
                )
                .code(),
                FeeRejectionCode::BeneficiaryNotEligible
            );
        }
    }
    assert!(stx.world.account(&beneficiary).is_err());
    assert!(stx.world.account(&other).is_err());
}

#[test]
fn prospective_fee_sponsor_enrollment_preserves_authority_and_closed_guards() {
    use iroha_data_model::{
        isi::nexus::EnrollFeeSponsorBeneficiary,
        nexus::{FeeSponsorEnrollmentKey, FeeSponsorProgramId, FeeSponsorProgramLifecycle},
        permission::Permissions,
    };
    use iroha_executor_data_model::permission::nexus::CanEnrollFeeSponsorProgram;
    let beneficiary = AccountId::new(
        iroha_crypto::KeyPair::try_from_seed(vec![0x73; 32], iroha_crypto::Algorithm::Ed25519)
            .expect("derive prospective beneficiary")
            .public_key()
            .clone(),
    );
    for case in ["unauthorized", "wrong_program", "exact_delegate", "closed"] {
        let (state, program_id, _) = staged_fee_sponsor_activation_fixture();
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(146).unwrap(),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction();
        assert!(!crate::executor::is_initial_genesis_context(&stx));
        if matches!(case, "wrong_program" | "exact_delegate") {
            let delegated_id = if case == "exact_delegate" {
                program_id.clone()
            } else {
                FeeSponsorProgramId::new(ALICE_ID.clone(), "different".parse().unwrap())
            };
            stx.world.account_permissions.insert(
                BOB_ID.clone(),
                Permissions::from([CanEnrollFeeSponsorProgram {
                    program_id: delegated_id,
                }
                .into()]),
            );
        }
        if case == "closed" {
            let mut program = stx
                .world
                .fee_sponsor_programs
                .get(&program_id)
                .unwrap()
                .clone();
            program.lifecycle = FeeSponsorProgramLifecycle::Closed;
            stx.world
                .fee_sponsor_programs
                .insert(program_id.clone(), program);
        }
        let key = FeeSponsorEnrollmentKey {
            program_id: program_id.clone(),
            beneficiary: beneficiary.clone(),
        };
        let authority = if case == "closed" {
            &*ALICE_ID
        } else {
            &*BOB_ID
        };
        let result = EnrollFeeSponsorBeneficiary {
            program_id,
            beneficiary: beneficiary.clone(),
        }
        .execute(authority, &mut stx);
        if case == "exact_delegate" {
            result.expect("existing exact program enrollment delegation remains supported");
            assert_eq!(
                stx.world.fee_sponsor_enrollments.get(&key).unwrap().key,
                key
            );
        } else {
            let error = result.expect_err("unauthorized or closed program cannot enroll");
            let expected = if case == "closed" {
                "closed fee sponsor program"
            } else {
                "cannot manage enrollments"
            };
            assert!(format!("{error:?}").contains(expected), "{case}: {error:?}");
            assert!(stx.world.fee_sponsor_enrollments.get(&key).is_none());
        }
        assert!(stx.world.account(&beneficiary).is_err());
    }
}

fn staged_fee_sponsor_activation_fixture() -> (
    State,
    iroha_data_model::nexus::FeeSponsorProgramId,
    iroha_data_model::nexus::FeeSponsorVaultKey,
) {
    use iroha_data_model::nexus::{
        FeeSponsorEnrollment, FeeSponsorEnrollmentKey, FeeSponsorProgram, FeeSponsorProgramId,
        FeeSponsorProgramRevisionKey, FeeSponsorVault, FeeSponsorVaultKey,
    };
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "activation_lower_bound".parse().expect("program name"),
    );
    // Fee admission pins XOR to the signed network identity, or the canonical
    // default when this fixture has no NPoS parameter. Fund that exact asset.
    let asset_definition_id: AssetDefinitionId =
        iroha_config::parameters::defaults::nexus::fees::fee_asset_id()
            .parse()
            .expect("canonical network XOR asset");
    let revision = fee_sponsor_revision_fixture(program_id.clone(), asset_definition_id.clone(), 1);
    revision.validate().expect("valid staged revision");
    let mut world = World::default();
    for account in [ALICE_ID.clone(), BOB_ID.clone()] {
        world.accounts.insert(
            account,
            iroha_data_model::account::AccountValue::new(
                iroha_data_model::account::AccountDetails::default(),
            ),
        );
    }
    world.asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::numeric(
            asset_definition_id.clone(),
            "activation fee asset".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID),
    );
    world.fee_sponsor_program_revisions.insert(
        FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
        revision,
    );
    let mut program = FeeSponsorProgram::new(program_id.clone(), ALICE_ID.clone());
    program.staged_revision = Some(1);
    world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let enrollment_key = FeeSponsorEnrollmentKey {
        program_id: program_id.clone(),
        beneficiary: ALICE_ID.clone(),
    };
    world.fee_sponsor_enrollments.insert(
        enrollment_key.clone(),
        FeeSponsorEnrollment {
            key: enrollment_key,
            enrolled_at_height: 142,
        },
    );
    let vault_key = FeeSponsorVaultKey {
        program_id: program_id.clone(),
        asset_definition_id,
    };
    world.fee_sponsor_vaults.insert(
        vault_key.clone(),
        FeeSponsorVault {
            key: vault_key.clone(),
            balance: Quantity::from(10_u32),
        },
    );
    // This admission component fixture requires explicit Global root metadata.
    // It does not execute signed genesis or authenticate a native history.
    let mut parameters = world.parameters.block();
    parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ))
        .expect("valid fixture parameters");
    parameters.commit();
    (
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ),
        program_id,
        vault_key,
    )
}

#[test]
fn fee_sponsor_activation_instruction_uses_requested_height_as_lower_bound() {
    use iroha_data_model::{
        isi::nexus::ActivateFeeSponsorProgramRevision,
        nexus::{FeeSponsorProgramActivation, FeeSponsorProgramLifecycle},
    };
    for requested in [0, 144, 146, 147] {
        let (state, program_id, _) = staged_fee_sponsor_activation_fixture();
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(146).expect("nonzero executing height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction();
        assert!(!crate::executor::is_initial_genesis_context(&stx));
        ActivateFeeSponsorProgramRevision {
            program_id: program_id.clone(),
            revision: 1,
            activate_at_height: requested,
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("the lower bound must survive ordinary inclusion delay");
        let program = stx.world.fee_sponsor_programs.get(&program_id).unwrap();
        if requested <= 146 {
            assert_eq!(program.lifecycle, FeeSponsorProgramLifecycle::Active);
            assert_eq!(program.active_revision, Some(1));
            assert_eq!(program.staged_revision, None);
            assert_eq!(program.scheduled_activation, None);
        } else {
            assert_eq!(program.lifecycle, FeeSponsorProgramLifecycle::Staged);
            assert_eq!(program.active_revision, None);
            assert_eq!(program.staged_revision, Some(1));
            assert_eq!(
                program.scheduled_activation,
                Some(FeeSponsorProgramActivation {
                    revision: 1,
                    activate_at_height: requested,
                })
            );
        }
    }
}

#[test]
fn fee_sponsor_elapsed_activation_preserves_readiness_and_authority_guards() {
    use iroha_data_model::{
        isi::nexus::ActivateFeeSponsorProgramRevision,
        nexus::{FeeSponsorEnrollmentKey, FeeSponsorProgramLifecycle, FeeSponsorVault},
    };
    for (case, expected) in [
        ("owner", "cannot manage fee sponsor program"),
        ("revision", "requested fee sponsor revision is not staged"),
        (
            "closing",
            "closing or closed fee sponsor program cannot activate",
        ),
        ("vault", "before activation; available 0"),
        ("enrollment", "no eligible beneficiary"),
    ] {
        let (state, program_id, vault_key) = staged_fee_sponsor_activation_fixture();
        let header = iroha_data_model::block::BlockHeader::new(
            NonZeroU64::new(146).expect("nonzero executing height"),
            None,
            None,
            0,
            0,
        );
        let mut block = state.block(header);
        let mut stx = block.transaction();
        match case {
            "closing" => {
                let mut program = stx
                    .world
                    .fee_sponsor_programs
                    .get(&program_id)
                    .unwrap()
                    .clone();
                program.lifecycle = FeeSponsorProgramLifecycle::Closing;
                stx.world
                    .fee_sponsor_programs
                    .insert(program_id.clone(), program);
            }
            "vault" => {
                stx.world.fee_sponsor_vaults.insert(
                    vault_key.clone(),
                    FeeSponsorVault {
                        key: vault_key,
                        balance: Quantity::zero(),
                    },
                );
            }
            "enrollment" => {
                stx.world
                    .fee_sponsor_enrollments
                    .remove(FeeSponsorEnrollmentKey {
                        program_id: program_id.clone(),
                        beneficiary: ALICE_ID.clone(),
                    });
            }
            _ => {}
        }
        let before = stx
            .world
            .fee_sponsor_programs
            .get(&program_id)
            .unwrap()
            .clone();
        let authority = if case == "owner" {
            &*BOB_ID
        } else {
            &*ALICE_ID
        };
        let error = ActivateFeeSponsorProgramRevision {
            program_id: program_id.clone(),
            revision: if case == "revision" { 2 } else { 1 },
            activate_at_height: 144,
        }
        .execute(authority, &mut stx)
        .expect_err("elapsed activation cannot bypass readiness or authority");
        assert!(format!("{error:?}").contains(expected), "{case}: {error:?}");
        assert_eq!(
            stx.world.fee_sponsor_programs.get(&program_id),
            Some(&before)
        );
    }
}
#[test]
fn post_genesis_authority_cannot_bootstrap_another_sponsors_program() {
    use iroha_data_model::{
        isi::nexus::CreateFeeSponsorProgram,
        nexus::{FeeSponsorProgram, FeeSponsorProgramId},
    };
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "post_genesis_denied".parse().expect("program name"),
    );
    let error = CreateFeeSponsorProgram {
        program: FeeSponsorProgram::new(program_id, ALICE_ID.clone()),
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("height-two authority must not manage another sponsor's program");
    assert!(format!("{error:?}").contains("cannot manage fee sponsor program"));
}
#[test]
fn replayed_genesis_header_cannot_regain_fee_sponsor_bootstrap_authority() {
    use iroha_data_model::{
        isi::nexus::CreateFeeSponsorProgram,
        nexus::{FeeSponsorProgram, FeeSponsorProgramId},
    };
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    seed_committed_world_test_block(&state);
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    assert!(stx._curr_block.is_genesis());
    assert!(!crate::executor::is_initial_genesis_context(&stx));
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "replayed_genesis_denied".parse().expect("program name"),
    );
    let error = CreateFeeSponsorProgram {
        program: FeeSponsorProgram::new(program_id.clone(), ALICE_ID.clone()),
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("committed history must disable the height-one owner exception");
    assert!(format!("{error:?}").contains("cannot manage fee sponsor program"));
    assert!(stx.world.fee_sponsor_programs.get(&program_id).is_none());
}
#[test]
fn post_genesis_fund_mismatch_preserves_balances_vault_and_transcripts() {
    use iroha_data_model::{
        isi::nexus::FundFeeSponsorProgram,
        nexus::{FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorVaultKey},
    };
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let custody = stx.nexus.fees.sponsor_vault_custody_account_id.clone();
    for account in [ALICE_ID.clone(), BOB_ID.clone(), custody.clone()] {
        if stx.world.account(&account).is_err() {
            Register::account(Account::new(account))
                .execute(&ALICE_ID, &mut stx)
                .expect("register post-genesis sponsor fixture account");
        }
    }
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    stx.world.asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::numeric(
            asset_definition_id.clone(),
            "post-genesis fee asset".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID),
    );
    let sponsor_asset = AssetId::new(asset_definition_id.clone(), ALICE_ID.clone());
    Mint::asset_quantity(Quantity::from(10_u32), sponsor_asset.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("prefund post-genesis sponsor");
    let custody_asset = AssetId::new(asset_definition_id.clone(), custody);
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "fund_mismatch".parse().expect("program name"),
    );
    stx.world.fee_sponsor_programs.insert(
        program_id.clone(),
        FeeSponsorProgram::new(program_id.clone(), ALICE_ID.clone()),
    );
    let vault_key = FeeSponsorVaultKey {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
    };
    let sponsor_before = stx
        .world
        .assets
        .get(&sponsor_asset)
        .expect("prefunded sponsor asset")
        .as_ref()
        .clone();
    let custody_before = stx.world.assets.get(&custody_asset).cloned();

    let error = FundFeeSponsorProgram {
        program_id,
        asset_definition_id,
        amount: Quantity::from(3_u32),
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("height-two non-owner funding must fail before moving assets");

    assert!(format!("{error:?}").contains("cannot manage fee sponsor program"));
    assert_eq!(
        stx.world
            .assets
            .get(&sponsor_asset)
            .expect("rejected funding preserves sponsor asset")
            .as_ref(),
        &sponsor_before,
    );
    assert_eq!(
        stx.world.assets.get(&custody_asset).cloned(),
        custody_before
    );
    assert!(stx.world.fee_sponsor_vaults.get(&vault_key).is_none());
    assert_eq!(stx.pending_transfer_transcript_count_for_testing(), 0);
}
#[test]
fn fee_sponsor_program_rejects_unregistered_payout_account() {
    use iroha_data_model::{
        isi::nexus::CreateFeeSponsorProgram,
        nexus::{FeeSponsorProgram, FeeSponsorProgramId},
    };
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();
    Register::account(Account::new(ALICE_ID.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register sponsor");
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "closed_payout".parse().expect("program name"),
    );
    let create = CreateFeeSponsorProgram {
        program: FeeSponsorProgram::new(program_id.clone(), BOB_ID.clone()),
    };
    let error = create
        .clone()
        .execute(&ALICE_ID, &mut stx)
        .expect_err("an unregistered payout account must fail closed");
    assert!(format!("{error:?}").contains("unknown fee sponsor payout account"));
    assert!(stx.world.fee_sponsor_programs.get(&program_id).is_none());
    Register::account(Account::new(BOB_ID.clone()))
        .execute(&ALICE_ID, &mut stx)
        .expect("register payout account");
    create
        .execute(&ALICE_ID, &mut stx)
        .expect("registered immutable payout account must be accepted");
    assert_eq!(
        stx.world
            .fee_sponsor_programs
            .get(&program_id)
            .expect("created sponsor program")
            .payout_account,
        *BOB_ID
    );
    let error = Unregister::account(BOB_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect_err("a live program's immutable payout account must remain registered");
    assert!(format!("{error:?}").contains("immutable payout account"));
}
#[test]
fn fee_sponsor_withdrawal_is_owner_only_and_pays_registered_account() {
    use iroha_data_model::{
        isi::nexus::WithdrawFeeSponsorProgram,
        nexus::{
            FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramLifecycle, FeeSponsorVault,
            FeeSponsorVaultKey,
        },
        permission::Permissions,
    };
    use iroha_executor_data_model::permission::nexus::CanManageFeeSponsorProgram;
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction_for_fastpq_protocol_testing();
    let custody = stx.nexus.fees.sponsor_vault_custody_account_id.clone();
    for account in [ALICE_ID.clone(), BOB_ID.clone(), custody.clone()] {
        if stx.world.account(&account).is_err() {
            Register::account(Account::new(account))
                .execute(&ALICE_ID, &mut stx)
                .expect("register sponsor withdrawal fixture account");
        }
    }
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    stx.world.asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::numeric(
            asset_definition_id.clone(),
            "global fee asset".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID),
    );
    let custody_asset = AssetId::new(asset_definition_id.clone(), custody);
    Mint::asset_quantity(Quantity::from(10_u32), custody_asset.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("fund sponsor custody");
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "owner_payout".parse().expect("program name"),
    );
    let mut program = FeeSponsorProgram::new(program_id.clone(), BOB_ID.clone());
    program.lifecycle = FeeSponsorProgramLifecycle::Paused;
    stx.world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let vault_key = FeeSponsorVaultKey {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
    };
    stx.world.fee_sponsor_vaults.insert(
        vault_key.clone(),
        FeeSponsorVault {
            key: vault_key.clone(),
            balance: Quantity::from(10_u32),
        },
    );
    stx.world.account_permissions.insert(
        BOB_ID.clone(),
        Permissions::from([CanManageFeeSponsorProgram {
            sponsor: ALICE_ID.clone(),
        }
        .into()]),
    );
    let withdrawal = WithdrawFeeSponsorProgram {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
        amount: Quantity::from(3_u32),
    };
    let error = withdrawal
        .clone()
        .execute(&BOB_ID, &mut stx)
        .expect_err("a delegated manager must not withdraw sponsor funds");
    assert!(format!("{error:?}").contains("only sponsor"));
    assert_eq!(
        stx.world
            .fee_sponsor_vaults
            .get(&vault_key)
            .expect("rejected withdrawal preserves vault")
            .balance,
        Quantity::from(10_u32)
    );
    withdrawal
        .execute(&ALICE_ID, &mut stx)
        .expect("exact sponsor may withdraw to the registered payout account");
    let payout_asset = AssetId::new(asset_definition_id, BOB_ID.clone());
    assert_eq!(
        stx.world
            .assets
            .get(&payout_asset)
            .expect("registered payout receives withdrawal")
            .as_ref(),
        &Quantity::from(3_u32)
    );
    assert_eq!(
        stx.world
            .assets
            .get(&custody_asset)
            .expect("custody retains remaining balance")
            .as_ref(),
        &Quantity::from(7_u32)
    );
    assert_eq!(
        stx.world
            .fee_sponsor_vaults
            .get(&vault_key)
            .expect("nonempty vault remains")
            .balance,
        Quantity::from(7_u32)
    );
}
#[test]
fn fee_sponsor_vault_allocation_requires_program_management_authority() {
    use iroha_data_model::{
        isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation,
        nexus::{
            FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramLifecycle,
            FeeSponsorProgramRevisionKey, ProofBlob,
        },
        permission::Permissions,
    };
    use iroha_executor_data_model::permission::nexus::CanManageFeeSponsorProgram;
    use iroha_model_base::topology::DataSpaceId;
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(2).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "allocation_auth".parse().expect("program name"),
    );
    stx.world.fee_sponsor_program_revisions.insert(
        FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
        fee_sponsor_revision_fixture(program_id.clone(), asset_definition_id.clone(), 1),
    );
    let mut program = FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone());
    program.lifecycle = FeeSponsorProgramLifecycle::Active;
    program.active_revision = Some(1);
    stx.world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let error = RegisterVerifiedFeeSponsorVaultAllocation {
        program_id: program_id.clone(),
        program_revision: 1,
        asset_definition_id: asset_definition_id.clone(),
        verified_allocation: Quantity::from(1_u32),
        source_dataspace_id: DataSpaceId::UNIVERSAL,
        source_height: 1,
        source_state_root: Hash::new(b"allocation-auth-source"),
        expires_at_height: 2,
        lease_id: Hash::new(b"allocation-auth-lease"),
        manifest_root: [1; 32],
        proof_blob: ProofBlob {
            payload: vec![1],
            expiry_slot: None,
        },
    }
    .execute(&BOB_ID, &mut stx)
    .expect_err("ordinary accounts must not reserve a sponsor vault");
    assert!(format!("{error:?}").contains("cannot manage fee sponsor program"));
    let mut permissions = Permissions::new();
    permissions.insert(
        CanManageFeeSponsorProgram {
            sponsor: ALICE_ID.clone(),
        }
        .into(),
    );
    stx.world
        .account_permissions
        .insert(BOB_ID.clone(), permissions);
    ensure_fee_sponsor_program_owner(&BOB_ID, &program_id, &stx)
        .expect("delegated manager must be authorized to register allocations");
}
#[test]
fn fee_sponsor_vault_allocation_rejects_future_source_height() {
    use iroha_data_model::{
        isi::nexus::RegisterVerifiedFeeSponsorVaultAllocation,
        nexus::{
            FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramLifecycle,
            FeeSponsorProgramRevisionKey, FeeSponsorVault, FeeSponsorVaultKey, ProofBlob,
        },
    };
    use iroha_model_base::topology::DataSpaceId;
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    stx.world.asset_definitions.insert(
        asset_definition_id.clone(),
        AssetDefinition::numeric(
            asset_definition_id.clone(),
            "global fee asset".to_owned(),
            AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID),
    );
    let program_id = FeeSponsorProgramId::new(
        ALICE_ID.clone(),
        "future_source".parse().expect("program name"),
    );
    stx.world.fee_sponsor_program_revisions.insert(
        FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
        fee_sponsor_revision_fixture(program_id.clone(), asset_definition_id.clone(), 1),
    );
    let mut program = FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone());
    program.lifecycle = FeeSponsorProgramLifecycle::Active;
    program.active_revision = Some(1);
    stx.world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let vault_key = FeeSponsorVaultKey {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
    };
    stx.world.fee_sponsor_vaults.insert(
        vault_key.clone(),
        FeeSponsorVault {
            key: vault_key,
            balance: Quantity::from(10_u32),
        },
    );
    let error = RegisterVerifiedFeeSponsorVaultAllocation {
        program_id,
        program_revision: 1,
        asset_definition_id,
        verified_allocation: Quantity::from(10_u32),
        source_dataspace_id: DataSpaceId::UNIVERSAL,
        source_height: 2,
        source_state_root: Hash::new(b"future-source-state"),
        expires_at_height: u64::MAX,
        lease_id: Hash::new(b"future-source-lease"),
        manifest_root: [1; 32],
        proof_blob: ProofBlob {
            payload: vec![1],
            expiry_slot: None,
        },
    }
    .execute(&ALICE_ID, &mut stx)
    .expect_err("a source snapshot cannot come from a future height");
    match error {
        InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) => assert!(
            message.contains("invalid source height"),
            "unexpected error: {message}"
        ),
        other => panic!("unexpected error: {other:?}"),
    }
}
#[test]
fn fee_sponsor_rejects_restricted_assets_at_every_write_boundary() {
    use iroha_data_model::{
        isi::nexus::{
            FundFeeSponsorProgram, RegisterVerifiedFeeSponsorVaultAllocation,
            StageFeeSponsorProgramRevision,
        },
        nexus::{
            FeeSponsorProgram, FeeSponsorProgramId, FeeSponsorProgramLifecycle,
            FeeSponsorProgramRevisionKey, ProofBlob,
        },
    };
    use iroha_model_base::topology::DataSpaceId;
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let header = iroha_data_model::block::BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(header);
    let mut stx = block.transaction();

    let authority = ALICE_ID.clone();
    let asset_definition_id: AssetDefinitionId = "66owaQmAQMuHxPzxUN3bqZ6FJfDa"
        .parse()
        .expect("canonical asset definition id");
    let owning_domain = DomainId::try_new("fees", "restricted").expect("fee asset owning domain");
    let definition = AssetDefinition::numeric(
        asset_definition_id.clone(),
        "restricted fee asset".to_owned(),
        AssetBalancePolicy::DataspaceRestricted,
        Some(owning_domain),
    )
    .build(&authority);
    stx.world
        .asset_definitions
        .insert(asset_definition_id.clone(), definition);
    let program_id = FeeSponsorProgramId::new(
        authority.clone(),
        "restricted_asset".parse().expect("program name"),
    );
    let revision_one =
        fee_sponsor_revision_fixture(program_id.clone(), asset_definition_id.clone(), 1);
    stx.world.fee_sponsor_program_revisions.insert(
        FeeSponsorProgramRevisionKey::new(program_id.clone(), 1),
        revision_one,
    );
    let mut program = FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone());
    program.lifecycle = FeeSponsorProgramLifecycle::Active;
    program.active_revision = Some(1);
    stx.world
        .fee_sponsor_programs
        .insert(program_id.clone(), program);
    let stage_error = StageFeeSponsorProgramRevision {
        revision: fee_sponsor_revision_fixture(program_id.clone(), asset_definition_id.clone(), 2),
    }
    .execute(&authority, &mut stx)
    .expect_err("restricted fee asset revision must fail");
    let is_restricted_asset_error = |error: &Error| {
        matches!(
            error,
            Error::InvalidParameter(InvalidParameterError::SmartContract(message))
                if message.contains("requires global-balance")
        )
    };
    assert!(is_restricted_asset_error(&stage_error));
    assert!(
        stx.world
            .fee_sponsor_program_revisions
            .get(&FeeSponsorProgramRevisionKey::new(program_id.clone(), 2))
            .is_none()
    );
    let fund_error = FundFeeSponsorProgram {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
        amount: Quantity::from(1_u32),
    }
    .execute(&authority, &mut stx)
    .expect_err("restricted fee asset funding must fail");
    assert!(is_restricted_asset_error(&fund_error));
    let allocation_error = RegisterVerifiedFeeSponsorVaultAllocation {
        program_id,
        program_revision: 1,
        asset_definition_id,
        verified_allocation: Quantity::from(1_u32),
        source_dataspace_id: DataSpaceId::new(1),
        source_height: 1,
        source_state_root: Hash::new(b"source-state-root"),
        expires_at_height: 10,
        lease_id: Hash::new(b"restricted-fee-asset-lease"),
        manifest_root: [1; 32],
        proof_blob: ProofBlob {
            payload: vec![1],
            expiry_slot: None,
        },
    }
    .execute(&authority, &mut stx)
    .expect_err("restricted fee asset allocation must fail");
    assert!(is_restricted_asset_error(&allocation_error));
}

#[derive(Clone)]
struct RetainedValidationFeeUnregisterFixture {
    policy_treasury: AccountId,
    payout_binding: iroha_data_model::validation_fee::ValidationFeeTreasuryPayoutBindingV1,
    custody_policy_proposal_id: [u8; 32],
    policy_proposal_id: [u8; 32],
    lifecycle_proposal_id: [u8; 32],
    unrelated_account: AccountId,
}

fn validation_fee_unregister_account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
            .expect("validation-fee unregister fixture key")
            .public_key()
            .clone(),
    )
}

fn install_retained_validation_fee_unregister_fixture(
    state_transaction: &mut StateTransaction<'_, '_>,
    policy_ds_asset_id: AssetDefinitionId,
    payout_ds_asset_id: AssetDefinitionId,
    payout_xor_asset_id: AssetDefinitionId,
) -> RetainedValidationFeeUnregisterFixture {
    use iroha_data_model::{
        governance::types::{
            ProposalKind, ValidationFeePayoutLifecycleProposal, ValidationFeePolicyProposal,
        },
        validation_fee::{
            VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS, ValidationFeeChargingMode,
            ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1,
            initial_validation_fee_amount,
        },
    };

    let network_id = *state_transaction.network_id();
    let contract_address =
        ContractAddress::derive(&network_id, &ALICE_ID, 369, DataSpaceId::UNIVERSAL)
            .expect("validation-fee unregister fixture contract address");
    let pool_contract_address =
        ContractAddress::derive(&network_id, &ALICE_ID, 370, DataSpaceId::UNIVERSAL)
            .expect("pool address");
    let payout_binding = ValidationFeeTreasuryPayoutBindingV1 {
        treasury_account_id: contract_address.subject_id(),
        contract_address,
        code_hash: [0xD1; 32],
        entrypoint: "autonomous_validation_fee_tick"
            .parse()
            .expect("validation-fee payout entrypoint"),
        ds_asset_id: payout_ds_asset_id,
        xor_asset_id: payout_xor_asset_id,
        pool_vault_account_id: pool_contract_address.subject_id(),
        pool_contract_address,
        pool_code_hash: [0xD2; 32],
        reward_pool_account_id: validation_fee_unregister_account(0xD3),
        reference_feed_id: "xor_per_sbd".parse().expect("feed"),
        reference_feed_config_version: 1,
        reference_provider_accounts: (0xE0..0xE5)
            .map(validation_fee_unregister_account)
            .collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100000,
        min_interval_ms: 60000,
        max_source_age_ms: 300000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    };
    assert_eq!(
        payout_binding.invariant_error(),
        None,
        "unregister fixture must carry the exact V1 payout binding"
    );

    let policy_contract =
        ContractAddress::derive(&network_id, &ALICE_ID, 371, DataSpaceId::UNIVERSAL).unwrap();
    let policy_treasury = policy_contract.subject_id();
    let mut policy_binding = payout_binding.clone();
    policy_binding.contract_address = policy_contract;
    policy_binding.treasury_account_id = policy_treasury.clone();
    policy_binding.ds_asset_id = policy_ds_asset_id.clone();
    let lifecycle_kind =
        ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
            proposal_operator: ALICE_ID.clone(),
            payout_binding: payout_binding.clone(),
        });
    let lifecycle_proposal_id = lifecycle_kind.fingerprint();
    let policy_kind = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: ALICE_ID.clone(),
        policy: ValidationFeePolicyV1 {
            retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
            effective_from_ms: 1793451600000,
            notice_published_at_ms: 1790859600000,
            schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
            network_id: network_id.clone(),
            policy_version: 1,
            previous_policy_hash: None,
            ds_asset_id: policy_ds_asset_id,
            ds_scale: VALIDATION_FEE_DS_SCALE,
            fee: initial_validation_fee_amount(),
            treasury_account_id: policy_treasury.clone(),
            charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

            exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.into()],
            reward_custody: policy_binding.custody(),
        },
    });
    let policy_proposal_id = policy_kind.fingerprint();
    state_transaction
        .world
        .put_governance_proposal(
            policy_proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: ALICE_ID.clone(),
                kind: policy_kind,
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Enacted,
            },
        )
        .expect("retain enacted validation-fee policy fixture");

    state_transaction
        .world
        .put_governance_proposal(
            lifecycle_proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: ALICE_ID.clone(),
                kind: lifecycle_kind,
                created_height: 2,
                status: crate::state::GovernanceProposalStatus::Enacted,
            },
        )
        .expect("retain enacted validation-fee payout lifecycle fixture");

    let custody_policy = ValidationFeePolicyV1 {
        retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
        effective_from_ms: 1793451600000,
        notice_published_at_ms: 1790859600000,
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id,
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: payout_binding.ds_asset_id.clone(),
        ds_scale: VALIDATION_FEE_DS_SCALE,
        fee: initial_validation_fee_amount(),
        treasury_account_id: payout_binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.to_owned()],
        reward_custody: payout_binding.custody(),
    };
    assert_eq!(
        custody_policy.policy_invariant_error(),
        None,
        "the immutable reward custody policy fixture must satisfy every first-release invariant",
    );
    let custody_policy_kind = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: ALICE_ID.clone(),
        policy: custody_policy,
    });
    let custody_policy_proposal_id = custody_policy_kind.fingerprint();
    state_transaction
        .world
        .put_governance_proposal(
            custody_policy_proposal_id,
            crate::state::GovernanceProposalRecord {
                proposer: ALICE_ID.clone(),
                kind: custody_policy_kind,
                created_height: 3,
                status: crate::state::GovernanceProposalStatus::Proposed,
            },
        )
        .expect("retain validation-fee policy with immutable reward custody fixture");

    RetainedValidationFeeUnregisterFixture {
        policy_treasury,
        payout_binding,
        custody_policy_proposal_id,
        policy_proposal_id,
        lifecycle_proposal_id,
        unrelated_account: validation_fee_unregister_account(0xDF),
    }
}

fn register_validation_fee_fixture_asset(
    state_transaction: &mut StateTransaction<'_, '_>,
    asset_definition_id: AssetDefinitionId,
    domain_id: Option<DomainId>,
) -> AssetId {
    Register::asset_definition(AssetDefinition::numeric(
        asset_definition_id.clone(),
        "validation fee unregister fixture asset".to_owned(),
        AssetBalancePolicy::Global,
        domain_id,
    ))
    .execute(&ALICE_ID, state_transaction)
    .expect("register validation-fee unregister fixture asset definition");
    let asset_id = AssetId::new(asset_definition_id, ALICE_ID.clone());
    Mint::asset_quantity(Quantity::from(7_u32), asset_id.clone())
        .execute(&ALICE_ID, state_transaction)
        .expect("mint validation-fee unregister fixture balance");
    asset_id
}

#[test]
fn enacted_policy_reward_custody_references_are_pinned_without_conversion_lifecycle() {
    blank_test_state_transaction!(state, block, stx);
    bootstrap_alice_account(&mut stx);
    let fixture_domain = DomainId::try_new("vfcustody", "universal").expect("fixture domain");
    let policy_ds = AssetDefinitionId::derive_from_components(
        fixture_domain.clone(),
        "policy_ds".parse().expect("policy DS name"),
    );
    let payout_ds = AssetDefinitionId::derive_from_components(
        fixture_domain.clone(),
        "payout_ds".parse().expect("payout DS name"),
    );
    let payout_xor = AssetDefinitionId::derive_from_components(
        fixture_domain,
        "payout_xor".parse().expect("payout XOR name"),
    );
    let fixture = install_retained_validation_fee_unregister_fixture(
        &mut stx,
        policy_ds,
        payout_ds.clone(),
        payout_xor.clone(),
    );
    {
        let mut proposals = stx.world.governance_proposals_mut();
        for proposal_id in [fixture.policy_proposal_id, fixture.lifecycle_proposal_id] {
            proposals
                .get_mut(&proposal_id)
                .expect("other retained proposal")
                .status = crate::state::GovernanceProposalStatus::Proposed;
        }
        proposals
            .get_mut(&fixture.custody_policy_proposal_id)
            .expect("retained reward custody policy proposal")
            .status = crate::state::GovernanceProposalStatus::Enacted;
    }

    let protected_accounts = [
        (
            "policy treasury",
            fixture.payout_binding.treasury_account_id.clone(),
        ),
        (
            "validator reward custody",
            fixture.payout_binding.reward_pool_account_id.clone(),
        ),
    ];
    let conversion_accounts: Vec<_> = std::iter::once((
        "payout pool vault",
        fixture.payout_binding.pool_vault_account_id.clone(),
    ))
    .chain(
        fixture
            .payout_binding
            .reference_provider_accounts
            .iter()
            .cloned()
            .map(|account| ("reference provider", account)),
    )
    .collect();
    for (_, account_id) in protected_accounts.iter().chain(&conversion_accounts) {
        Register::account(Account::new(account_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register retained-reference fixture account");
    }
    let protected_assets = [
        ("policy DS asset definition", payout_ds),
        ("payout XOR asset definition", payout_xor),
    ];
    let asset_ids: Vec<_> = protected_assets
        .iter()
        .map(|(_, definition_id)| {
            register_validation_fee_fixture_asset(&mut stx, definition_id.clone(), None)
        })
        .collect();
    let accounts_before: BTreeSet<_> = stx
        .world
        .accounts
        .iter()
        .map(|(id, _)| id.clone())
        .collect();
    let custody_proposal = hex::encode(fixture.custody_policy_proposal_id);
    for (reference_kind, account_id) in &protected_accounts {
        let error = Unregister::account(account_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("the enacted pricing policy independently pins immutable custody");
        assert!(error.to_string().contains(reference_kind), "{error}");
        assert!(error.to_string().contains(&custody_proposal), "{error}");
        assert_eq!(
            stx.world
                .accounts
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<BTreeSet<_>>(),
            accounts_before,
            "rejected custody deletion must preserve every account",
        );
    }
    for ((reference_kind, definition_id), asset_id) in protected_assets.iter().zip(&asset_ids) {
        let balance_before = stx.world.asset(asset_id).unwrap().as_ref().clone();
        let error = Unregister::asset_definition(definition_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("the enacted pricing policy independently pins each custody asset");
        assert!(error.to_string().contains(reference_kind), "{error}");
        assert!(error.to_string().contains(&custody_proposal), "{error}");
        assert!(stx.world.asset_definition(definition_id).is_ok());
        assert_eq!(stx.world.asset(asset_id).unwrap().as_ref(), &balance_before);
    }

    // Pricing retains immutable reward custody, not the separately governed
    // pool and oracle configuration. A proposed lifecycle has no pinning power.
    for (_, account_id) in &conversion_accounts {
        Unregister::account(account_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("conversion-only references require an enacted lifecycle");
        assert!(stx.world.account(account_id).is_err());
        Register::account(Account::new(account_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("restore conversion account for enacted-lifecycle control");
    }
    stx.world
        .governance_proposals_mut()
        .get_mut(&fixture.lifecycle_proposal_id)
        .expect("retained lifecycle proposal")
        .status = crate::state::GovernanceProposalStatus::Enacted;
    let lifecycle_proposal = hex::encode(fixture.lifecycle_proposal_id);
    for (reference_kind, account_id) in &conversion_accounts {
        let error = Unregister::account(account_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("the enacted lifecycle pins every conversion-only account");
        assert!(error.to_string().contains(reference_kind), "{error}");
        assert!(error.to_string().contains(&lifecycle_proposal), "{error}");
        assert_eq!(
            stx.world
                .accounts
                .iter()
                .map(|(id, _)| id.clone())
                .collect::<BTreeSet<_>>(),
            accounts_before,
            "rejected lifecycle deletion must preserve every account",
        );
    }
}

#[test]
fn non_enacted_validation_fee_proposal_statuses_do_not_pin_payout_references() {
    for status in [
        crate::state::GovernanceProposalStatus::Proposed,
        crate::state::GovernanceProposalStatus::Rejected,
        crate::state::GovernanceProposalStatus::Superseded,
        crate::state::GovernanceProposalStatus::ExecutionFailed,
    ] {
        blank_test_state_transaction!(state, block, stx);
        bootstrap_alice_account(&mut stx);
        let fixture_domain = DomainId::try_new("vfunpinned", "universal").expect("fixture domain");
        let policy_ds = AssetDefinitionId::derive_from_components(
            fixture_domain.clone(),
            "policy_ds".parse().expect("policy DS name"),
        );
        let payout_ds = AssetDefinitionId::derive_from_components(
            fixture_domain.clone(),
            "payout_ds".parse().expect("payout DS name"),
        );
        let payout_xor = AssetDefinitionId::derive_from_components(
            fixture_domain,
            "payout_xor".parse().expect("payout XOR name"),
        );
        let fixture = install_retained_validation_fee_unregister_fixture(
            &mut stx,
            policy_ds,
            payout_ds,
            payout_xor.clone(),
        );
        {
            let mut proposals = stx.world.governance_proposals_mut();
            proposals
                .get_mut(&fixture.policy_proposal_id)
                .expect("retained custody-only pricing proposal")
                .status = status;
            proposals
                .get_mut(&fixture.lifecycle_proposal_id)
                .expect("retained lifecycle proposal")
                .status = status;
            proposals
                .get_mut(&fixture.custody_policy_proposal_id)
                .expect("retained reward custody policy proposal")
                .status = status;
        }

        let pool_vault = fixture.payout_binding.pool_vault_account_id.clone();
        Register::account(Account::new(pool_vault.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register non-enacted payout pool vault");
        let payout_asset =
            register_validation_fee_fixture_asset(&mut stx, payout_xor.clone(), None);
        Unregister::account(pool_vault.clone())
            .execute(&ALICE_ID, &mut stx)
            .unwrap_or_else(|error| panic!("status {status:?} pinned an account: {error}"));
        Unregister::asset_definition(payout_xor.clone())
            .execute(&ALICE_ID, &mut stx)
            .unwrap_or_else(|error| {
                panic!("status {status:?} pinned an asset definition: {error}")
            });
        assert!(stx.world.account(&pool_vault).is_err());
        assert!(stx.world.asset_definition(&payout_xor).is_err());
        assert!(stx.world.asset(&payout_asset).is_err());
    }
}

#[test]
fn enacted_validation_fee_account_references_reject_unregister_atomically() {
    blank_test_state_transaction!(state, block, stx);
    bootstrap_alice_account(&mut stx);
    let fixture_domain = DomainId::try_new("vfaccount", "universal").expect("fixture domain");
    let fixture = install_retained_validation_fee_unregister_fixture(
        &mut stx,
        AssetDefinitionId::derive_from_components(
            fixture_domain.clone(),
            "policy_ds".parse().expect("policy DS name"),
        ),
        AssetDefinitionId::derive_from_components(
            fixture_domain.clone(),
            "payout_ds".parse().expect("payout DS name"),
        ),
        AssetDefinitionId::derive_from_components(
            fixture_domain,
            "payout_xor".parse().expect("payout XOR name"),
        ),
    );
    let mut references = vec![
        ("policy treasury", fixture.policy_treasury.clone()),
        (
            "payout treasury",
            fixture.payout_binding.treasury_account_id.clone(),
        ),
        (
            "payout pool vault",
            fixture.payout_binding.pool_vault_account_id.clone(),
        ),
    ];
    references.push((
        "validator reward custody",
        fixture.payout_binding.reward_pool_account_id.clone(),
    ));
    references.extend(
        fixture
            .payout_binding
            .reference_provider_accounts
            .iter()
            .map(|account| ("reference provider", account.clone())),
    );
    for (_, account_id) in references.iter().chain(std::iter::once(&(
        "unrelated",
        fixture.unrelated_account.clone(),
    ))) {
        Register::account(Account::new(account_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register validation-fee account reference fixture");
    }

    let account_ids_before: BTreeSet<_> = stx
        .world
        .accounts
        .iter()
        .map(|(account_id, _)| account_id.clone())
        .collect();
    for (reference_kind, account_id) in &references {
        let error = Unregister::account(account_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("retained enacted validation-fee account reference must reject");
        assert!(
            format!("{error:?}").contains(reference_kind),
            "unexpected {reference_kind} rejection: {error}"
        );
        assert_eq!(
            stx.world
                .accounts
                .iter()
                .map(|(account_id, _)| account_id.clone())
                .collect::<BTreeSet<_>>(),
            account_ids_before,
            "rejected {reference_kind} unregister must not mutate accounts"
        );
    }

    Unregister::account(fixture.unrelated_account.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("an unrelated account remains unregisterable");
    assert!(
        stx.world.account(&fixture.unrelated_account).is_err(),
        "unrelated account must actually be removed"
    );
}

#[test]
fn enacted_validation_fee_asset_references_reject_unregister_atomically() {
    blank_test_state_transaction!(state, block, stx);
    bootstrap_alice_account(&mut stx);
    let fixture_domain = DomainId::try_new("vfasset", "universal").expect("fixture domain");
    let policy_ds = AssetDefinitionId::derive_from_components(
        fixture_domain.clone(),
        "policy_ds".parse().expect("policy DS name"),
    );
    let payout_ds = AssetDefinitionId::derive_from_components(
        fixture_domain.clone(),
        "payout_ds".parse().expect("payout DS name"),
    );
    let payout_xor = AssetDefinitionId::derive_from_components(
        fixture_domain.clone(),
        "payout_xor".parse().expect("payout XOR name"),
    );
    let unrelated = AssetDefinitionId::derive_from_components(
        fixture_domain,
        "unrelated".parse().expect("unrelated asset name"),
    );
    let fixture = install_retained_validation_fee_unregister_fixture(
        &mut stx,
        policy_ds.clone(),
        payout_ds.clone(),
        payout_xor.clone(),
    );
    let _ = fixture;
    let references = [
        ("policy DS asset definition", policy_ds),
        ("payout DS asset definition", payout_ds),
        ("payout XOR asset definition", payout_xor),
    ];
    let mut reference_assets = Vec::new();
    for (_, asset_definition_id) in &references {
        reference_assets.push(register_validation_fee_fixture_asset(
            &mut stx,
            asset_definition_id.clone(),
            None,
        ));
    }
    let unrelated_asset = register_validation_fee_fixture_asset(&mut stx, unrelated.clone(), None);

    for ((reference_kind, asset_definition_id), asset_id) in
        references.iter().zip(&reference_assets)
    {
        let balance_before = stx
            .world
            .asset(asset_id)
            .expect("referenced asset exists")
            .as_ref()
            .clone();
        let error = Unregister::asset_definition(asset_definition_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("retained enacted validation-fee asset reference must reject");
        assert!(
            format!("{error:?}").contains(reference_kind),
            "unexpected {reference_kind} rejection: {error}"
        );
        assert!(
            stx.world.asset_definition(asset_definition_id).is_ok(),
            "rejected {reference_kind} unregister must retain the definition"
        );
        assert_eq!(
            stx.world
                .asset(asset_id)
                .expect("rejected unregister retains balance")
                .as_ref(),
            &balance_before,
            "rejected {reference_kind} unregister must retain balances"
        );
    }

    Unregister::asset_definition(unrelated.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("an unrelated asset definition remains unregisterable");
    assert!(stx.world.asset_definition(&unrelated).is_err());
    assert!(stx.world.asset(&unrelated_asset).is_err());
}

#[test]
fn enacted_validation_fee_asset_references_reject_containing_domain_unregister_atomically() {
    blank_test_state_transaction!(state, block, stx);
    bootstrap_alice_account(&mut stx);
    let policy_domain = DomainId::try_new("vfpolicy", "universal").expect("policy domain");
    let payout_ds_domain = DomainId::try_new("vfpayoutds", "universal").expect("payout DS domain");
    let payout_xor_domain =
        DomainId::try_new("vfpayoutxor", "universal").expect("payout XOR domain");
    let unrelated_domain = DomainId::try_new("vfunrelated", "universal").expect("unrelated domain");
    for domain_id in [
        &policy_domain,
        &payout_ds_domain,
        &payout_xor_domain,
        &unrelated_domain,
    ] {
        seed_domain_name_lease_tx(&mut stx.world, &ALICE_ID, domain_id);
        Register::domain(Domain::new(domain_id.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register validation-fee unregister fixture domain");
    }
    let policy_ds = AssetDefinitionId::derive_from_components(
        policy_domain.clone(),
        "policy_ds".parse().expect("policy DS name"),
    );
    let payout_ds = AssetDefinitionId::derive_from_components(
        payout_ds_domain.clone(),
        "payout_ds".parse().expect("payout DS name"),
    );
    let payout_xor = AssetDefinitionId::derive_from_components(
        payout_xor_domain.clone(),
        "payout_xor".parse().expect("payout XOR name"),
    );
    let unrelated = AssetDefinitionId::derive_from_components(
        unrelated_domain.clone(),
        "unrelated".parse().expect("unrelated asset name"),
    );
    let fixture = install_retained_validation_fee_unregister_fixture(
        &mut stx,
        policy_ds.clone(),
        payout_ds.clone(),
        payout_xor.clone(),
    );
    let _ = fixture;
    let references = [
        ("policy DS asset definition", policy_domain, policy_ds),
        ("payout DS asset definition", payout_ds_domain, payout_ds),
        ("payout XOR asset definition", payout_xor_domain, payout_xor),
    ];
    let mut reference_assets = Vec::new();
    for (_, domain_id, asset_definition_id) in &references {
        reference_assets.push(register_validation_fee_fixture_asset(
            &mut stx,
            asset_definition_id.clone(),
            Some(domain_id.clone()),
        ));
    }
    let unrelated_asset = register_validation_fee_fixture_asset(
        &mut stx,
        unrelated.clone(),
        Some(unrelated_domain.clone()),
    );

    for ((reference_kind, domain_id, asset_definition_id), asset_id) in
        references.iter().zip(&reference_assets)
    {
        let balance_before = stx
            .world
            .asset(asset_id)
            .expect("referenced domain asset exists")
            .as_ref()
            .clone();
        let error = Unregister::domain(domain_id.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect_err("domain containing retained validation-fee asset must reject");
        assert!(
            format!("{error:?}").contains(reference_kind),
            "unexpected {reference_kind} domain rejection: {error}"
        );
        assert!(stx.world.domain(domain_id).is_ok());
        assert!(stx.world.asset_definition(asset_definition_id).is_ok());
        assert_eq!(
            stx.world
                .asset(asset_id)
                .expect("rejected domain unregister retains balance")
                .as_ref(),
            &balance_before,
            "rejected {reference_kind} domain unregister must be atomic"
        );
    }

    Unregister::domain(unrelated_domain.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("an unrelated containing domain remains unregisterable");
    assert!(stx.world.domain(&unrelated_domain).is_err());
    assert!(stx.world.asset_definition(&unrelated).is_err());
    assert!(stx.world.asset(&unrelated_asset).is_err());
}

#[test]
fn signed_payout_scope_refusal_cannot_publish_a_parliament_terminal_outcome() {
    use crate::execution_attempt::ExecutionAttemptError;
    use crate::state::StateBlockStartError;
    use iroha_data_model::governance::types::ValidationFeePayoutLifecycleProposal;
    let (mut chain, binding) =
        crate::validation_fee::tests::signed_payout_lifecycle_registry_fixture();
    // Every predecessor is a real signed/certified nonempty block. The due-certificate reducer
    // fixture supplies the original retained governance state, not a height-only root identity.
    while chain.state().view().height() < 59 {
        let height = u64::try_from(chain.state().view().height()).unwrap() + 1;
        chain.commit_at(height * 1_000, Vec::new());
    }
    let mut fixture = None;
    chain.setup_world_at(60_000, |transaction| {
        crate::validation_fee::tests::register_bound_payout_time_trigger(
            transaction,
            &binding,
            *transaction
                .world
                .contract_instances
                .get(&binding.contract_address)
                .unwrap(),
            "original_registry_payout_tick",
        );
        let subject_id = [0xE4; 32];
        let expected = super::parliament_validation_fee_payout_observed_head_v1(
            subject_id,
            &binding,
            transaction,
        )
        .expect("the original active runtime is a vacant lifecycle head");
        assert!(matches!(expected, GovernanceExpectedHeadV1::Absent(_)));
        super::validate_validation_fee_payout_lifecycle_runtime_before_effect_install(
            &binding,
            transaction,
        )
        .expect("the original exact runtime is ready before the due effect");
        // Measure the real currency-read prefix, then permit exactly that much
        // decoding. The contract read, rather than an earlier NPoS read, must
        // produce the refusal observed by the due-effect runtime validator.
        let prefix = || {
            crate::state::validate_network_xor_asset(
                &transaction.world,
                &binding.xor_asset_id,
            )
            .expect("the complete committed NPoS currency read succeeds");
        };
        const CEILING: usize = 1 << 20;
        let prefix_bytes = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, 32),
            || {
                prefix();
                let norito::Error::TotalAllocationExceeded { attempted, limit } =
                    norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
                else {
                    panic!("original currency-read allocation observation changed");
                };
                assert_eq!(limit, CEILING as u64);
                usize::try_from(attempted).unwrap() - CEILING - 1
            },
        );
        assert!(prefix_bytes > 0);
        let limits = norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            prefix_bytes,
            32,
        );
        norito::with_decode_limits_scope(limits, || prefix());
        let producer_refusal = norito::with_decode_limits_scope(limits, || {
            prefix();
            crate::smartcontracts::code::fetch_bound_contract_record(
                transaction,
                &binding.contract_address,
            )
        });
        assert!(
            matches!(producer_refusal, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
            "the bound-contract read must retain the original local refusal after the currency prefix"
        );
        let refused = norito::with_decode_limits_scope(
            limits,
            || {
                super::validate_validation_fee_payout_lifecycle_runtime_before_effect_install(
                    &binding,
                    transaction,
                )
            },
        );
        assert!(
            matches!(refused, Err(ExecutionAttemptError::Deferred(ref reason))
            if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
        );
        assert_eq!(
            super::parliament_validation_fee_payout_observed_head_v1(
                subject_id,
                &binding,
                transaction
            )
            .unwrap(),
            expected
        );
        fixture = Some(seed_due_parliament_certificate(
            transaction,
            ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
                proposal_operator: ALICE_ID.clone(),
                payout_binding: binding.clone(),
            }),
        ));
    });
    let fixture = fixture.unwrap();
    let state = std::sync::Arc::clone(chain.state());
    let header = BlockHeader::new(
        60_u64.try_into().unwrap(),
        state.view().latest_block_hash(),
        None,
        60_000,
        0,
    );
    let refused = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(96, usize::MAX, usize::MAX, 0, 32),
        || state.try_block(header),
    );
    assert!(
        matches!(refused, Err(StateBlockStartError::ExecutionDeferred(ref reason))
        if reason.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity)
    );
    {
        let view = state.view();
        assert_eq!(view.height(), 59);
        assert_eq!(chain.kura().blocks_count(), 59);
        assert_eq!(
            view.world
                .governance_proposals
                .get(&fixture.proposal_id)
                .unwrap()
                .status,
            crate::state::GovernanceProposalStatus::Proposed
        );
        assert_eq!(
            view.world
                .parliament_attempts
                .get(&fixture.governance_attempt_id)
                .unwrap()
                .attempt()
                .status,
            GovernanceAttemptStatusV1::Certified
        );
    }
    // A fresh attempt over the same original State enacts and publishes once funding returns.
    chain.commit_at(60_000, Vec::new());
    let view = state.view();
    assert_eq!(view.height(), 60);
    assert_eq!(chain.kura().blocks_count(), 60);
    assert_eq!(
        view.world
            .governance_proposals
            .get(&fixture.proposal_id)
            .unwrap()
            .status,
        crate::state::GovernanceProposalStatus::Enacted
    );
    assert_eq!(
        view.world
            .parliament_attempts
            .get(&fixture.governance_attempt_id)
            .unwrap()
            .attempt()
            .status,
        GovernanceAttemptStatusV1::Enacted
    );
}
