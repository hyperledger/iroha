//! Nonshipping fixture: genuine native monthly-fee quote and signed multisig transfer.
//! Test setup owns the bound runtime and the proposal-bound Parliament reducer records.
//! The value movement and its certified cut use the ordinary native execution path.
use super::{CertifiedTestChain, TestChainConfig};
use crate::{
    smartcontracts::Execute,
    state::{StateTransaction, World, WorldReadOnly},
    validation_fee::VALIDATION_FEE_POOL_SWAP_ENTRYPOINT,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    asset::AssetBalancePolicy,
    events::time::{ExecutionTime, Schedule, TimeEventFilter},
    governance::types::{
        GovernanceCertificateId, ProposalKind, ValidationFeePayoutLifecycleProposal,
        ValidationFeePolicyProposal,
    },
    prelude::*,
    transaction::{Executable, SignedTransaction, executable::ContractInvocation},
    trigger::{
        Trigger,
        action::{Action, Repeats},
    },
    validation_fee::*,
};
use iroha_executor_data_model::isi::multisig::{
    DEFAULT_MULTISIG_TTL_MS, MultisigApprove, MultisigPropose, MultisigRegister, MultisigSpec,
};
use iroha_model_base::{domain::DomainId, state_path::StatePath};
use iroha_primitives::numeric::{NumericSpec, Quantity};
use mv::storage::StorageReadOnly;
use std::{
    collections::BTreeMap,
    num::{NonZeroU16, NonZeroU64},
};
// Fixed September 2026 Honiara month boundary, before the fixture runner clock.
const START: u64 = 1_788_181_200_000;
fn key(seed: u8) -> KeyPair {
    KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
}
fn account(seed: u8) -> AccountId {
    AccountId::new(key(seed).public_key().clone())
}

/// Exact original signed approval and its executed native transfer.
pub struct NativeRetailMultisigTransferFixture {
    /// Original real execution and finality fixture.
    pub chain: CertifiedTestChain,
    /// Registered multisig payment authority.
    pub source: AccountId,
    /// Distinct registered intake account.
    pub destination: AccountId,
    /// Exact native Global payment holding.
    pub source_holding: AssetId,
    /// Original Transfer and native monthly assessment marker.
    pub instructions: Vec<InstructionBox>,
    /// Native hash of the exact reviewed instruction vector.
    pub instructions_hash: HashOf<Vec<InstructionBox>>,
    /// Original locally signed proposal transaction.
    pub proposal_transaction: SignedTransaction,
    /// Original locally signed quorum-reaching approval transaction.
    pub approval_transaction: SignedTransaction,
    /// Assessment returned by the actual governed native fee quote.
    pub assessment: RetailFeeAssessmentV1,
    /// Committed height that executed the transfer.
    pub approval_height: u64,
    /// Ledger timestamp that executed the transfer.
    pub approval_time_ms: u64,
    /// Exact native approval outcome and terminal execution StatePaths.
    pub keys: [StatePath; 2],
}
impl NativeRetailMultisigTransferFixture {
    /// Capture the funded original snapshot and two exact stored records at this fixture's tip.
    /// The returned data conveys no finality authority; the consumer verifies its independent cut.
    pub fn execution_records(
        &self,
    ) -> (
        iroha_data_model::sumeragi_finality::WorldStateSnapshotV1,
        Vec<u8>,
        Vec<u8>,
    ) {
        let tip = self.chain.committed(self.chain.height());
        let budget = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
        let records = self
            .chain
            .state()
            .with_native_execution_records_snapshot_v1(
                &tip,
                &self.keys,
                &budget,
                |snapshot, outcome, terminal| {
                    Ok((snapshot.clone(), outcome.clone(), terminal.clone()))
                },
            )
            .unwrap();
        assert_eq!(budget.reserved_bytes(), 0);
        records
    }
}

/// Descriptor for a zero-argument function returning exactly one initialized Unit word.
fn unit_callable(entry_pc: u64) -> ivm::call::EmbeddedCallableV1 {
    ivm::call::EmbeddedCallableV1 {
        entry_pc,
        frame_bytes: 0,
        arguments: ivm::call::CallSchemaV1::empty(),
        results: ivm::call::CallSchemaV1::unit(),
    }
}

/// A complete Unit return through the caller-owned result table and protected return address.
fn unit_return() -> [u8; 16] {
    use ivm::{
        encoding::wide,
        instruction::wide::{arithmetic, control, memory},
    };
    let instructions = [
        wide::encode_store(memory::STORE64, 12, 0, 0),
        wide::encode_ri(arithmetic::ADDI, 10, 12, 0),
        wide::encode_ri(arithmetic::ADDI, 11, 0, 1),
        wide::encode_rr(control::JALR, 0, 1, 0),
    ];
    let mut code = [0; 16];
    for (slot, instruction) in code.chunks_exact_mut(4).zip(instructions) {
        slot.copy_from_slice(&instruction.to_le_bytes());
    }
    code
}
fn treasury_payout_binding(
    network_id: &NetworkId,
    contract_address: iroha_data_model::smart_contract::ContractAddress,
    code: &[u8],
) -> ValidationFeeTreasuryPayoutBindingV1 {
    let treasury = contract_address.subject_id();
    let pool_contract_address = iroha_data_model::smart_contract::ContractAddress::derive(
        network_id,
        &account(2),
        43,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .expect("pool address");
    ValidationFeeTreasuryPayoutBindingV1 {
        contract_address,
        code_hash: <[u8; 32]>::from(ivm::contract_code_hash(code)),
        entrypoint: "autonomous_validation_fee_tick"
            .parse()
            .expect("payout entrypoint"),
        treasury_account_id: treasury,
        ds_asset_id: "7ZepsJTHCVLKsrFFNZGSRGZgvBhv".parse().unwrap(),
        xor_asset_id: AssetDefinitionId::derive_from_components(
            DomainId::try_new("fees", "paynet").unwrap(),
            "xor".parse().unwrap(),
        ),
        pool_vault_account_id: pool_contract_address.subject_id(),
        pool_contract_address,
        pool_code_hash: [2; 32],
        reward_pool_account_id: account(8),
        reference_feed_id: "xor_per_sbd".parse().expect("feed"),
        reference_feed_config_version: 1,
        reference_provider_accounts: (10..15).map(account).collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100000,
        min_interval_ms: 60000,
        max_source_age_ms: 300000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    }
}

fn minimal_bound_contract_artifact() -> (
    Vec<u8>,
    iroha_data_model::smart_contract::manifest::ContractManifest,
) {
    let metadata = ivm::ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 4,
        abi_version: 1,
    };
    let wrapper_entrypoint = iroha_data_model::smart_contract::manifest::EntrypointDescriptor {
        name: "autonomous_validation_fee_tick".to_owned(),
        kind: iroha_data_model::smart_contract::manifest::EntryPointKind::Kotoage,
        params: Vec::new(),
        argument_schema: None,
        return_type: Some("()".to_owned()),
        return_schema: Some(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit,
                ],
            },
        ),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "Payout".parse().unwrap(),
            ),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
    };
    let pool_entrypoint = iroha_data_model::smart_contract::manifest::EntrypointDescriptor {
        name: VALIDATION_FEE_POOL_SWAP_ENTRYPOINT.to_owned(),
        authorization:
            iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Permission(
                "SwapQuotePublic".parse().unwrap(),
            ),
        ..wrapper_entrypoint.clone()
    };
    let entrypoints = [wrapper_entrypoint, pool_entrypoint];
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: ["Payout", "SwapQuotePublic"].into_iter().map(|name| iroha_data_model::smart_contract::manifest::ContractPermissionDescriptorV1 { name: name.parse().unwrap(), scope: iroha_data_model::smart_contract::manifest::ContractPermissionScopeV1::Instance }).collect(),
        callables: (0..entrypoints.len())
            .map(|index| unit_callable(index as u64 * 16))
            .collect(),
        seiyaku_name: "ValidationFeePayout".to_owned(),
        compiler_fingerprint: "validation-fee-bound-contract-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: entrypoints
            .iter()
            .enumerate()
            .map(|(index, entrypoint)| ivm::EmbeddedEntrypointDescriptor {
                name: entrypoint.name.clone(),
                kind: entrypoint.kind,
                params: entrypoint.params.clone(),
                argument_schema: entrypoint.argument_schema.clone(),
                return_type: entrypoint.return_type.clone(),
                return_schema: entrypoint.return_schema.clone(),
                authorization: entrypoint.authorization.clone(),
                read_keys: entrypoint.read_keys.clone(),
                write_keys: entrypoint.write_keys.clone(),
                access_hints_complete: entrypoint.access_hints_complete,
                access_hints_skipped: entrypoint.access_hints_skipped.clone(),
                triggers: entrypoint.triggers.clone(),
                entry_pc: u64::try_from(index).expect("fixture entrypoint index fits u64") * 16,
            })
            .collect(),
        error_types: Vec::new(),
        error_messages: Vec::new(),
        states: Vec::new(),
    };
    let mut instructions = Vec::new();
    for _ in &entrypoints {
        instructions.extend_from_slice(&unit_return());
    }
    let mut artifact = metadata.encode();
    artifact.extend_from_slice(&interface.encode_section());
    artifact.extend_from_slice(&instructions);
    let verified = ivm::verify_contract_artifact(&artifact).expect("valid bound contract artifact");
    (artifact, verified.manifest)
}

fn register_bound_payout_time_trigger(
    state_tx: &mut StateTransaction<'_, '_>,
    binding: &ValidationFeeTreasuryPayoutBindingV1,
    expected_code_hash: Hash,
    trigger_id: &str,
) -> iroha_data_model::trigger::TriggerId {
    let trigger_id: iroha_data_model::trigger::TriggerId =
        trigger_id.parse().expect("payout trigger id");
    let block_cadence = std::time::Duration::from_millis(
        state_tx
            .world
            .parameters
            .sumeragi()
            .block_cadence_ms()
            .get(),
    );
    let action = Action::new(
        Executable::ContractCall(ContractInvocation {
            contract_address: binding.contract_address.clone(),
            expected_code_hash,
            entrypoint: binding.entrypoint.to_string(),
            arguments: None,
        }),
        Repeats::Indefinitely,
        binding.treasury_account_id.clone(),
        TimeEventFilter::new(ExecutionTime::Schedule(
            Schedule::starting_at(std::time::Duration::from_millis(1)).with_period(block_cadence),
        )),
    )
    .expect("bound payout trigger action");
    let trigger = Trigger::new(trigger_id.clone(), action);
    crate::smartcontracts::isi::triggers::isi::register_trigger_internal(
        &binding.treasury_account_id,
        state_tx,
        trigger,
        None,
    )
    .expect("register exact bound payout trigger");
    trigger_id
}

fn activate_bound_payout_runtime(
    state_tx: &mut StateTransaction<'_, '_>,
    deployer: &AccountId,
    code: &[u8],
    code_hash: Hash,
    nonce: u64,
    ds_asset_id: AssetDefinitionId,
    trigger_id: &str,
) -> ValidationFeeTreasuryPayoutBindingV1 {
    use iroha_data_model::smart_contract::ContractAddress;
    use iroha_model_base::topology::DataSpaceId;
    let contract_address = ContractAddress::derive(
        &state_tx.network_id,
        deployer,
        nonce,
        DataSpaceId::UNIVERSAL,
    )
    .expect("derive payout contract address");
    state_tx
        .world
        .bind_inactive_contract_subject_for_testing(contract_address.clone(), deployer.clone());
    crate::smartcontracts::code::activate_instance(
        deployer,
        contract_address.clone(),
        1,
        code_hash,
        state_tx,
    )
    .expect("activate payout contract instance");
    let mut binding = treasury_payout_binding(&state_tx.network_id, contract_address.clone(), code);
    binding.ds_asset_id = ds_asset_id;
    let trigger_id = register_bound_payout_time_trigger(state_tx, &binding, code_hash, trigger_id);
    let _ = trigger_id;
    let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
    feed.feed_id = binding.reference_feed_id.clone();
    feed.feed_config_version =
        iroha_data_model::oracle::FeedConfigVersion(binding.reference_feed_config_version);
    feed.providers = binding.reference_provider_accounts.clone();
    feed.min_signers = 3;
    feed.committee_size = 5;
    state_tx
        .world
        .oracle_feeds
        .insert(feed.feed_id.clone(), feed);
    binding
}

fn install_enacted(
    transaction: &mut StateTransaction<'_, '_>,
    kind: ProposalKind,
) -> ValidationFeeParliamentAuthorizationV1 {
    let attempt = crate::governance::parliament::enacted_parliament_attempt_for_testing(
        &kind,
        (220..=243).map(account).collect(),
        &transaction.network_id,
        20,
    );
    let certificate = attempt.certificate().cloned().unwrap();
    let authorization = ValidationFeeParliamentAuthorizationV1 {
        proposal_operator: account(250),
        proposal_fingerprint: kind.fingerprint(),
        governance_certificate_id: GovernanceCertificateId::derive_v1(&certificate),
        governance_certificate: certificate,
        enacted_at_height: 20,
    };
    assert_eq!(authorization.invariant_error(), None);
    transaction
        .world
        .put_governance_proposal(
            kind.fingerprint(),
            crate::state::GovernanceProposalRecord {
                proposer: account(250),
                kind,
                created_height: 1,
                status: crate::state::GovernanceProposalStatus::Enacted,
            },
        )
        .unwrap();
    transaction
        .world
        .put_parliament_attempt_for_testing(attempt.attempt().id, attempt)
        .unwrap();
    authorization
}
fn install_monthly_policy(
    transaction: &mut StateTransaction<'_, '_>,
    deployer_key: &KeyPair,
    source: &AccountId,
) {
    use iroha_model_base::topology::DataSpaceId;

    let deployer = AccountId::new(deployer_key.public_key().clone());
    let permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(permission, deployer.clone())
        .execute(&deployer, transaction)
        .unwrap();
    let (code, manifest) = minimal_bound_contract_artifact();
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let code_hash = crate::smartcontracts::code::register_code_bytes(
        &deployer,
        DataSpaceId::UNIVERSAL,
        code.clone(),
        transaction,
    )
    .unwrap();
    crate::smartcontracts::code::register_manifest(
        &deployer,
        DataSpaceId::UNIVERSAL,
        manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                deployer_key,
            )
            .expect("sign bounded fixture manifest"),
        transaction,
    )
    .unwrap();
    let asset: AssetDefinitionId = "7ZepsJTHCVLKsrFFNZGSRGZgvBhv".parse().unwrap();
    let mut binding = activate_bound_payout_runtime(
        transaction,
        &deployer,
        &code,
        code_hash,
        91,
        asset.clone(),
        "retail_ms_conversion",
    );
    let pool = activate_bound_payout_runtime(
        transaction,
        &deployer,
        &code,
        code_hash,
        92,
        asset.clone(),
        "retail_ms_pool",
    );
    binding.pool_vault_account_id = pool.treasury_account_id;
    binding.pool_contract_address = pool.contract_address;
    binding.pool_code_hash = pool.code_hash;
    let policy = ValidationFeePolicyV1 {
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: transaction.network_id,
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: asset,
        ds_scale: 2,
        fee: "0.10".parse().unwrap(),
        treasury_account_id: binding.treasury_account_id.clone(),
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,
        retail_schedule: RetailFeeScheduleV1::default(),
        effective_from_ms: START,
        notice_published_at_ms: START - RETAIL_FEE_NOTICE_MS,
        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.into()],
        reward_custody: binding.custody(),
    };
    let payout_kind =
        ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
            proposal_operator: account(250),
            payout_binding: binding.clone(),
        });
    let payout = ValidationFeePayoutPolicyEntryV1 {
        revision: 1,
        proposal_id: payout_kind.fingerprint(),
        lifecycle_seal: binding.lifecycle_seal().unwrap(),
        payout_binding: binding,
        parliament_authorization: install_enacted(transaction, payout_kind),
    };
    let kind = ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: account(250),
        policy: policy.clone(),
    });
    let authorization = install_enacted(transaction, kind);
    let registry = ValidationFeePolicyRegistryV1 {
        registered_policies: vec![
            ValidationFeePolicyRegistryEntryV1::from_enactment(policy, authorization).unwrap(),
        ],
        payout_policies: ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![payout],
        },
    };
    registry.validate().unwrap();
    transaction
        .world
        .parameters
        .get_mut()
        .set_parameter(Parameter::Custom(registry.into_custom_parameter()));
    let record = RetailFeeAccountStateV1::enroll(source.clone(), START, 1000).unwrap();
    crate::retail_fee::write_account(&mut transaction.world, &record).unwrap();
}

/// Build a real executed two-instruction retail transfer and retain all native proof selectors.
/// Governance/custody setup is explicit test-only state, never a production qualification claim.
pub fn native_retail_multisig_transfer_fixture() -> NativeRetailMultisigTransferFixture {
    let first = key(0x81);
    let second = key(0x82);
    let destination = account(0x84);
    let domain = DomainId::try_new("fees", "paynet").unwrap();
    let asset: AssetDefinitionId = "7ZepsJTHCVLKsrFFNZGSRGZgvBhv".parse().unwrap();
    let xor = AssetDefinitionId::derive_from_components(domain.clone(), "xor".parse().unwrap());
    let mut config = TestChainConfig::new(World::new(), START);
    let genesis_key = config.genesis_key.clone();
    config.genesis_instructions = vec![
        Register::domain(Domain::new(domain.clone())).into(),
        Register::domain(Domain::new(
            DomainId::try_new("contracts", "universal").unwrap(),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::new(
            asset.clone(),
            "SBD".to_owned(),
            NumericSpec::fractional(2),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
        Register::asset_definition(AssetDefinition::new(
            xor,
            "XOR".to_owned(),
            NumericSpec::fractional(2),
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ];
    for seed in [0x81, 0x82, 0x84, 2, 8, 9, 10, 11, 12, 13, 14, 250]
        .into_iter()
        .chain(220..=243)
    {
        config
            .genesis_instructions
            .push(Register::account(Account::new(account(seed))).into());
    }
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let spec = MultisigSpec::new(
        BTreeMap::from([(account(0x81), 1), (account(0x82), 1)]),
        NonZeroU16::new(2).unwrap(),
        NonZeroU64::new(DEFAULT_MULTISIG_TTL_MS).unwrap(),
    );
    let register = chain.sign(
        &genesis_key,
        [MultisigRegister::with_account(account(0x83), domain, spec).into()],
        START + 1_000,
    );
    assert_eq!(chain.commit_at(START + 1_000, vec![register]), [true]);
    let source = chain
        .state()
        .view()
        .world()
        .accounts_iter()
        .find(|a| a.id().multisig_policy().is_some())
        .unwrap()
        .id()
        .clone();
    let source_holding = AssetId::new(asset.clone(), source.clone());
    let mint = chain.sign(
        &genesis_key,
        [Mint::asset_quantity(10_u32, source_holding.clone()).into()],
        START + 2_000,
    );
    assert_eq!(chain.commit_at(START + 2_000, vec![mint]), [true]);
    while chain.height() < 25 {
        chain.commit_at(START + 2_000 + chain.height(), Vec::new());
    }
    let now = START + 3_000;
    chain.setup_world_at(now, |transaction| {
        install_monthly_policy(transaction, &genesis_key, &source)
    });
    chain.commit_at(now, Vec::new());
    let request = RetailFeeQuoteRequestV1 {
        account_id: source.clone(),
        asset_definition_id: asset,
        transfers: vec![RetailFeePaymentLegV1 {
            destination_account_id: destination.clone(),
            amount_minor_units: 125,
        }],
    };
    let assessment = {
        let view = chain.state().view();
        crate::retail_fee::quote(view.world(), chain.height(), now, &request).unwrap()
    };
    assert_eq!(assessment.fee_minor, 0);
    assert!(assessment.retail_enrolled);
    assert_ne!(assessment.state_commitment, [0; 32]);
    let marker = format!(
        "{}{}",
        crate::retail_fee::ASSESSMENT_MARKER_PREFIX,
        hex::encode(norito::encode_canonical(&assessment).unwrap())
    );
    let instructions = vec![
        Transfer::asset_quantity(
            source_holding.clone(),
            "1.25".parse::<Quantity>().unwrap(),
            destination.clone(),
        )
        .into(),
        Log::new(Level::TRACE, marker).into(),
    ];
    let instructions_hash = HashOf::new(&instructions);
    let proposal_transaction = chain.sign(
        &first,
        [MultisigPropose::new(source.clone(), instructions.clone(), None).into()],
        now + 1,
    );
    assert_eq!(
        chain.commit_at(now + 1, vec![proposal_transaction.clone()]),
        [true]
    );
    let approval_created_ms = now + 2;
    let approval_transaction = chain.sign(
        &second,
        [MultisigApprove::new(source.clone(), instructions_hash).into()],
        approval_created_ms,
    );
    let entrypoint_hash = *approval_transaction.hash_as_entrypoint().as_ref();
    assert_eq!(
        chain.commit_at(approval_created_ms, vec![approval_transaction.clone()]),
        [true]
    );
    let approval_height = chain.height();
    // Execution records bind the block's assembled clock, which is strictly after
    // transaction creation, rather than the caller-requested commit time.
    let approval_time_ms = u64::try_from(
        chain
            .committed(approval_height)
            .block()
            .header()
            .creation_time()
            .as_millis(),
    )
    .expect("native approval block time fits u64");
    let keys = [
        crate::smartcontracts::isi::multisig::multisig_approval_outcome_state_key(
            entrypoint_hash,
            &source,
            &instructions_hash,
        ),
        crate::smartcontracts::isi::multisig::multisig_proposal_terminal_execution_state_key(
            entrypoint_hash,
            &source,
            &instructions_hash,
        ),
    ];
    {
        let view = chain.state().view();
        assert_eq!(
            view.world().assets().get(&source_holding).unwrap().as_ref(),
            &"8.75".parse::<Quantity>().unwrap()
        );
        assert_eq!(
            view.world()
                .assets()
                .get(&AssetId::new(
                    request.asset_definition_id,
                    destination.clone()
                ))
                .unwrap()
                .as_ref(),
            &"1.25".parse::<Quantity>().unwrap()
        );
    }
    chain.commit_at(now + 3, Vec::new());
    NativeRetailMultisigTransferFixture {
        chain,
        source,
        destination,
        source_holding,
        instructions,
        instructions_hash,
        proposal_transaction,
        approval_transaction,
        assessment,
        approval_height,
        approval_time_ms,
        keys,
    }
}
