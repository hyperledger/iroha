//! Integration coverage for validator admission of Parliament-enacted validation-fee policy.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
use iroha_config::parameters::actual::ParliamentTimedOvn;
use iroha_core::{
    governance::parliament::{
        ParliamentAttemptStateV1, ParliamentDecisionModeV1, RequiredParliamentBodyV1,
    },
    smartcontracts::Execute,
    smartcontracts::ivm::cache::IvmCache,
    state::{State, StateTransaction, World, WorldReadOnly},
    tx::AcceptedTransaction,
};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{Asset, AssetDefinition, AssetDefinitionId, AssetId},
    block::BlockHeader,
    events::{
        EventFilterBox,
        time::{ExecutionTime, TimeEventFilter},
    },
    governance::types::{
        BallotAttemptId, BeaconPulseId, BeaconSessionId, BodyElectionAttemptId,
        DeliberationPhaseV1, GovernanceAttemptId, GovernanceAttemptStatusV1, GovernanceAttemptV1,
        GovernanceCertificateId, GovernanceExpectedHeadAbsentV1, GovernanceExpectedHeadV1,
        GovernanceStageV1, ParliamentAggregateOutcomeV1, ParliamentAggregateTallyV1,
        ParliamentBody, ProposalContentId, ProposalKind, RiskTierV1, SortitionRequestV1,
        TleKeySessionId, TleSessionId, ValidationFeePayoutLifecycleProposal,
        ValidationFeePolicyProposal, parliament_candidate_root_v1,
    },
    isi::{SetParameter, Transfer, governance::ParliamentSortitionRequestRegistrationV1},
    parameter::Parameter,
    prelude::*,
    smart_contract::{
        ContractAddress,
        manifest::{TriggerCallback, TriggerDescriptor},
    },
    transaction::SignedTransaction,
    trigger::action::Repeats,
    validation_fee::{
        VALIDATION_FEE_DS_SCALE, VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS, ValidationFeeChargingMode,
        ValidationFeeParliamentAuthorizationV1, ValidationFeePolicyRegistryEntryV1,
        ValidationFeePolicyRegistryV1, ValidationFeePolicyV1, ValidationFeeTreasuryPayoutBindingV1,
    },
};
use iroha_model_base::{domain::DomainId, metadata::Metadata, topology::DataSpaceId};
use iroha_primitives::{json::Json, numeric::NumericSpec};
use mv::storage::StorageReadOnly;
use sha2::{Digest as _, Sha256};
use std::{num::NonZeroU64, sync::Arc};
const TEST_VALIDATION_FEE_ASSET_SCALE: u8 = VALIDATION_FEE_DS_SCALE;
const TEST_POLICY_ENACTMENT_HEIGHT: u64 = 7_202;
const TEST_POLICY_EFFECTIVE_HEIGHT: u64 = TEST_POLICY_ENACTMENT_HEIGHT + 1;
const TEST_PARLIAMENT_POLICY_VERSION: u64 = 1;
fn quantity(value: &str) -> Quantity {
    value
        .parse()
        .expect("canonical validation-fee fixture quantity")
}
fn block_header(state: &State, height: u64, timestamp_ms: u64) -> BlockHeader {
    BlockHeader::new(
        NonZeroU64::new(height).expect("height"),
        state.view().latest_block_hash(),
        None,
        timestamp_ms,
        0,
    )
}
fn key_pair(seed: u8) -> KeyPair {
    KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519).expect("key pair")
}
fn account(seed: u8) -> (AccountId, KeyPair) {
    let key_pair = key_pair(seed);
    (AccountId::new(key_pair.public_key().clone()), key_pair)
}
fn fee_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").expect("domain id"),
        "fee_token".parse().expect("asset name"),
    )
}
fn xor_asset_definition_id() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", "paynet").expect("domain id"),
        "xor".parse().expect("asset name"),
    )
}
fn payout_contract_address(network: &iroha_data_model::NetworkId) -> ContractAddress {
    ContractAddress::derive(network, &account(1).0, 42, DataSpaceId::UNIVERSAL)
        .expect("payout contract address")
}
fn pool_contract_address(network: &iroha_data_model::NetworkId) -> ContractAddress {
    ContractAddress::derive(network, &account(2).0, 43, DataSpaceId::UNIVERSAL)
        .expect("pool contract address")
}
fn payout_contract_artifact() -> (
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
    let entrypoint = iroha_data_model::smart_contract::manifest::EntrypointDescriptor {
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
        permission: Some("CanInvokeContractEntrypoint".to_owned()),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: vec![TriggerDescriptor {
            id: "validation_fee_payout_tick"
                .parse()
                .expect("payout trigger id"),
            repeats: Repeats::Indefinitely,
            filter: EventFilterBox::Time(TimeEventFilter(ExecutionTime::PreCommit)),
            authority: None,
            metadata: Metadata::default(),
            callback: TriggerCallback {
                namespace: None,
                entrypoint: "autonomous_validation_fee_tick".to_owned(),
            },
        }],
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![ivm::call::EmbeddedCallableV1 {
            entry_pc: 0,
            frame_bytes: 0,
            arguments: ivm::call::CallSchemaV1::empty(),
            results: ivm::call::CallSchemaV1::unit(),
        }],
        seiyaku_name: "ValidationFeePayout".to_owned(),
        compiler_fingerprint: "validation-fee-admission-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: entrypoint.name.clone(),
            kind: entrypoint.kind,
            params: entrypoint.params.clone(),
            argument_schema: entrypoint.argument_schema.clone(),
            return_type: entrypoint.return_type.clone(),
            return_schema: entrypoint.return_schema.clone(),
            permission: entrypoint.permission.clone(),
            read_keys: entrypoint.read_keys.clone(),
            write_keys: entrypoint.write_keys.clone(),
            access_hints_complete: entrypoint.access_hints_complete,
            access_hints_skipped: entrypoint.access_hints_skipped.clone(),
            triggers: entrypoint.triggers.clone(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut artifact = metadata.encode();
    artifact.extend_from_slice(&interface.encode_section());
    for instruction in [
        ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
    ] {
        artifact.extend_from_slice(&instruction.to_le_bytes());
    }
    let verified =
        ivm::verify_contract_artifact(&artifact).expect("valid payout contract artifact");
    (artifact, verified.manifest)
}
fn pool_contract_artifact() -> (
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
    let entrypoint = iroha_data_model::smart_contract::manifest::EntrypointDescriptor {
        name: "swap_exact_in_quote_public".to_owned(),
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
        permission: Some("CanInvokeContractEntrypoint".to_owned()),
        read_keys: Vec::new(),
        write_keys: Vec::new(),
        access_hints_complete: None,
        access_hints_skipped: Vec::new(),
        triggers: Vec::new(),
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        callables: vec![ivm::call::EmbeddedCallableV1 {
            entry_pc: 0,
            frame_bytes: 0,
            arguments: ivm::call::CallSchemaV1::empty(),
            results: ivm::call::CallSchemaV1::unit(),
        }],
        seiyaku_name: "ValidationFeePool".to_owned(),
        compiler_fingerprint: "validation-fee-pool-admission-test".to_owned(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: 0,
        access_set_hints: None,
        kotoba: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: entrypoint.name.clone(),
            kind: entrypoint.kind,
            params: entrypoint.params.clone(),
            argument_schema: entrypoint.argument_schema.clone(),
            return_type: entrypoint.return_type.clone(),
            return_schema: entrypoint.return_schema.clone(),
            permission: entrypoint.permission.clone(),
            read_keys: entrypoint.read_keys.clone(),
            write_keys: entrypoint.write_keys.clone(),
            access_hints_complete: entrypoint.access_hints_complete,
            access_hints_skipped: entrypoint.access_hints_skipped.clone(),
            triggers: entrypoint.triggers.clone(),
            entry_pc: 0,
        }],
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
    };
    let mut artifact = metadata.encode();
    artifact.extend_from_slice(&interface.encode_section());
    for instruction in [
        ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
        ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
        ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
    ] {
        artifact.extend_from_slice(&instruction.to_le_bytes());
    }
    let verified = ivm::verify_contract_artifact(&artifact).expect("valid pool contract artifact");
    (artifact, verified.manifest)
}
fn payout_binding(
    network: &iroha_data_model::NetworkId,
    fee_asset: &AssetDefinitionId,
) -> ValidationFeeTreasuryPayoutBindingV1 {
    let contract_address = payout_contract_address(network);
    let (contract_artifact, _) = payout_contract_artifact();
    ValidationFeeTreasuryPayoutBindingV1 {
        treasury_account_id: contract_address.subject_id(),
        contract_address,
        code_hash: <[u8; 32]>::from(Sha256::digest(contract_artifact)),
        entrypoint: "autonomous_validation_fee_tick"
            .parse()
            .expect("payout entrypoint"),
        ds_asset_id: fee_asset.clone(),
        xor_asset_id: xor_asset_definition_id(),
        pool_vault_account_id: pool_contract_address(network).subject_id(),
        pool_contract_address: pool_contract_address(network),
        pool_code_hash: <[u8; 32]>::from(Sha256::digest(pool_contract_artifact().0)),
        reward_pool_account_id: account(7).0,
        reference_feed_id: "xor_per_sbd".parse().unwrap(),
        reference_feed_config_version: 1,
        reference_provider_accounts: (10..15).map(|seed| account(seed).0).collect(),
        max_sbd_per_attempt_minor: 1000,
        max_sbd_per_day_minor: 100000,
        min_interval_ms: 60000,
        max_source_age_ms: 300000,
        max_slippage_bps: 100,
        validator_lane_id: iroha_model_base::topology::LaneId::new(0),
        min_reward_claim_xor_minor: 1,
    }
}
fn test_state() -> (
    State,
    AccountId,
    KeyPair,
    AccountId,
    AccountId,
    AssetDefinitionId,
) {
    let (user, user_key_pair) = account(1);
    let (recipient, _) = account(8);
    let domain_id = DomainId::try_new("fees", "paynet").expect("domain id");
    let domain = Domain::new(domain_id).build(&user);
    let fee_asset = fee_asset_definition_id();
    let asset_definition = AssetDefinition::new(
        fee_asset.clone(),
        "fee_token".to_owned(),
        NumericSpec::fractional(u32::from(TEST_VALIDATION_FEE_ASSET_SCALE)),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&user);
    let xor_asset_definition = AssetDefinition::new(
        xor_asset_definition_id(),
        "xor".to_owned(),
        NumericSpec::fractional(9),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&user);
    let user_asset = Asset::new(
        AssetId::new(fee_asset.clone(), user.clone()),
        Quantity::from(100_u64),
    );
    let mut accounts = vec![
        Account::new(user.clone()).build(&user),
        Account::new(recipient.clone()).build(&user),
    ];
    accounts.extend(
        (2..=15)
            .filter(|seed| *seed != 8)
            .map(|seed| Account::new(account(seed).0).build(&user)),
    );
    use iroha_core::sumeragi::{
        startup,
        test_chain::{CertifiedTestChain, TestChainConfig},
    };
    let mut config = TestChainConfig::new(
        World::with_assets(
            [domain],
            accounts,
            [asset_definition, xor_asset_definition],
            [user_asset],
            [],
        ),
        1_700_000_000_000,
    );
    // The native payout fixture requires the network currency in the actual signed genesis.
    // The fee token keeps its independent scale; this component prestate qualifies no election.
    let npos = iroha_data_model::parameter::system::SumeragiNposParameters {
        xor_asset_definition_id: xor_asset_definition_id(),
        ..Default::default()
    };
    npos.validate().expect("native currency fixture policy");
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = npos.xor_asset_definition_id.canonical_address();
    nexus.staking.stake_asset_id = npos.xor_asset_definition_id.canonical_address();
    // Preserve the original component State fixture's zero generic fees.
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    config.consensus_mode = iroha_data_model::parameter::system::SumeragiConsensusMode::Npos;
    config.genesis_parameters.extend([
        Parameter::Sumeragi(
            iroha_data_model::parameter::system::SumeragiParameter::EpochLengthBlocks(
                npos.epoch_length_blocks,
            ),
        ),
        Parameter::Custom(npos.into_custom_parameter()),
    ]);
    let genesis_authority = AccountId::new(config.genesis_key.public_key().clone());
    let mode = config.consensus_mode;
    let prepared =
        CertifiedTestChain::prepare(config).expect("original signed fee admission genesis");
    let state = Arc::try_unwrap(prepared.state)
        .unwrap_or_else(|_| panic!("unpublished fee admission State is unique"));
    startup::apply_genesis(
        &state,
        prepared.genesis.block().clone(),
        &genesis_authority,
        mode.into(),
        None,
    )
    .expect("apply actual signed fee admission genesis");
    let treasury = payout_contract_address(state.network_id_ref()).subject_id();
    assert_eq!(
        state.network_id_ref().into_genesis_hash(),
        state.view().latest_block_hash().unwrap()
    );
    (state, user, user_key_pair, recipient, treasury, fee_asset)
}

#[test]
fn admission_fixture_authenticates_network_xor_identity_and_precision_in_signed_genesis() {
    let (state, _, _, _, _, fee_asset) = test_state();
    let view = state.view();
    let world = view.world();
    let npos = world
        .sumeragi_npos_parameters()
        .expect("original committed parameter decoder completes")
        .expect("actual signed genesis commits native currency identity");
    assert_eq!(npos.xor_asset_definition_id, xor_asset_definition_id());
    let nexus = state.nexus_snapshot();
    assert_eq!(
        nexus.fees.fee_asset_id,
        npos.xor_asset_definition_id.canonical_address()
    );
    assert_eq!(
        nexus.staking.stake_asset_id,
        npos.xor_asset_definition_id.canonical_address()
    );
    assert_eq!(
        AssetDefinitionId::parse_address_literal(&nexus.fees.fee_asset_id)
            .expect("the fee selector is the canonical authenticated currency address"),
        npos.xor_asset_definition_id
    );
    assert_eq!(nexus.fees.base_fee, Quantity::zero());
    assert_eq!(nexus.fees.per_byte_fee, Quantity::zero());
    assert_eq!(nexus.fees.per_instruction_fee, Quantity::zero());
    assert_eq!(nexus.fees.per_gas_unit_fee, Quantity::zero());
    // Inspect the committed native-currency definition through its public model
    // contract; internal resolver and admission guards retain their own unit tests.
    assert_eq!(
        world
            .asset_definition(&npos.xor_asset_definition_id)
            .unwrap()
            .balance_scope_policy(),
        iroha_data_model::asset::AssetBalancePolicy::Global
    );
    assert_eq!(
        world
            .asset_definition(&npos.xor_asset_definition_id)
            .unwrap()
            .spec(),
        NumericSpec::fractional(9)
    );
    assert_eq!(
        world.asset_definition(&fee_asset).unwrap().spec(),
        NumericSpec::fractional(u32::from(TEST_VALIDATION_FEE_ASSET_SCALE))
    );
    assert_eq!(view.height(), 1);
    assert_eq!(
        state.network_id_ref().into_genesis_hash(),
        view.latest_block_hash().unwrap()
    );
}
fn accept_transaction(state: &State, tx: SignedTransaction) -> AcceptedTransaction<'static> {
    let max_clock_drift = state
        .view()
        .world()
        .parameters()
        .sumeragi()
        .max_clock_drift();
    let tx_params = state.view().world().parameters().transaction();
    let crypto = state.crypto.read().clone();
    AcceptedTransaction::accept(
        tx,
        state.network_id_ref(),
        max_clock_drift,
        tx_params,
        crypto.as_ref(),
    )
    .expect("transaction admission should pass stateless checks")
}
fn validation_fee_policy(
    state: &State,
    fee_asset: AssetDefinitionId,
    treasury: AccountId,
) -> ValidationFeePolicyV1 {
    let payout_binding = payout_binding(state.network_id_ref(), &fee_asset);
    assert_eq!(treasury, payout_binding.treasury_account_id);
    ValidationFeePolicyV1 {
        retail_schedule: iroha_data_model::validation_fee::RetailFeeScheduleV1::default(),
        effective_from_ms: 1793451600000,
        notice_published_at_ms: 1790859600000,
        schema_version: VALIDATION_FEE_POLICY_SCHEMA_VERSION,
        network_id: *state.network_id_ref(),
        policy_version: 1,
        previous_policy_hash: None,
        ds_asset_id: fee_asset,
        ds_scale: TEST_VALIDATION_FEE_ASSET_SCALE,
        fee: iroha_data_model::validation_fee::initial_validation_fee_amount(),
        treasury_account_id: treasury,
        charging_mode: ValidationFeeChargingMode::RetailMonthlyAllowance,

        exemption_classes: vec![VALIDATION_FEE_TREASURY_PAYOUT_EXEMPTION_CLASS.to_owned()],
        reward_custody: payout_binding.custody(),
    }
}
fn parliament_test_root(tag: u8) -> [u8; 32] {
    [tag.max(1); 32]
}
fn parliament_test_candidates() -> Vec<AccountId> {
    let mut candidates = (1_u8..=24).map(|seed| account(seed).0).collect::<Vec<_>>();
    candidates.sort_unstable();
    candidates
}
fn validation_fee_parliament_requirements() -> Vec<RequiredParliamentBodyV1> {
    [
        ParliamentBody::RulesCommittee,
        ParliamentBody::AgendaCouncil,
        ParliamentBody::InterestPanel,
        ParliamentBody::ReviewPanel,
        ParliamentBody::CoordinationCouncil,
        ParliamentBody::MpcCommittee,
        ParliamentBody::FmaCommittee,
        ParliamentBody::OversightCommittee,
        ParliamentBody::PolicyJury,
    ]
    .into_iter()
    .map(|body| RequiredParliamentBodyV1 {
        body,
        decision_mode: if body == ParliamentBody::PolicyJury {
            ParliamentDecisionModeV1::HiddenBindingBallot
        } else {
            ParliamentDecisionModeV1::PublicFinding
        },
    })
    .collect()
}
fn parliament_test_governance(
    requirements: &[RequiredParliamentBodyV1],
) -> iroha_config::parameters::actual::Governance {
    let mut governance = iroha_config::parameters::actual::Governance {
        parliament_alternate_size: 0,
        ..iroha_config::parameters::actual::Governance::default()
    };
    for requirement in requirements {
        match requirement.body {
            ParliamentBody::RulesCommittee => governance.rules_committee_size = 3,
            ParliamentBody::AgendaCouncil => governance.agenda_council_size = 3,
            ParliamentBody::InterestPanel => governance.interest_panel_size = 3,
            ParliamentBody::ReviewPanel => governance.review_panel_size = 3,
            ParliamentBody::CoordinationCouncil => governance.coordination_council_size = 3,
            ParliamentBody::MpcCommittee => governance.mpc_committee_size = 3,
            ParliamentBody::FmaCommittee => governance.fma_committee_size = 3,
            ParliamentBody::OversightCommittee => governance.oversight_committee_size = 3,
            ParliamentBody::PolicyJury => governance.policy_jury_size = 3,
            ParliamentBody::ConfirmationJury => governance.confirmation_jury_size = 3,
        }
    }
    governance
}
fn complete_parliament_body_for_authorization(
    attempt: &mut ParliamentAttemptStateV1,
    requirement: RequiredParliamentBodyV1,
    election_attempt_id: BodyElectionAttemptId,
    result_tag: u8,
) -> u64 {
    let governance_attempt_id = attempt.attempt().id;
    attempt
        .begin_invitation_acceptance(governance_attempt_id, election_attempt_id, 20, 1)
        .expect("open deterministic Parliament invitation window");
    let members = attempt
        .election(&election_attempt_id)
        .expect("drawn Parliament election")
        .primary_assignments()
        .iter()
        .map(|assignment| assignment.member.clone())
        .collect::<Vec<_>>();
    for member in &members {
        attempt
            .record_invitation_response(
                governance_attempt_id,
                election_attempt_id,
                member,
                true,
                20,
            )
            .expect("accept deterministic Parliament invitation");
    }
    let body_instance_id = attempt
        .seal_body_roster(governance_attempt_id, election_attempt_id, 21)
        .expect("seal deterministic Parliament roster");
    let mut phases = vec![
        DeliberationPhaseV1::Orientation,
        DeliberationPhaseV1::Evidence,
        DeliberationPhaseV1::Questions,
        DeliberationPhaseV1::Responses,
        DeliberationPhaseV1::Deliberation,
        DeliberationPhaseV1::Reflection,
    ];
    if requirement.decision_mode == ParliamentDecisionModeV1::HiddenBindingBallot {
        phases.push(DeliberationPhaseV1::Vote);
    }
    for phase in phases {
        attempt
            .advance_body_phase(governance_attempt_id, body_instance_id, phase, 22, 1)
            .expect("advance deterministic Parliament deliberation");
    }
    match requirement.decision_mode {
        ParliamentDecisionModeV1::PublicFinding => {
            let result_root = parliament_test_root(result_tag);
            let mut finalized = false;
            for member in &members {
                finalized = attempt
                    .endorse_public_finding(
                        governance_attempt_id,
                        body_instance_id,
                        result_root,
                        member,
                        22,
                    )
                    .expect("endorse deterministic public finding");
                if finalized {
                    break;
                }
            }
            assert!(
                finalized,
                "three seats must reach the two-thirds finding quorum"
            );
        }
        ParliamentDecisionModeV1::HiddenBindingBallot => {
            let ballot_attempt_id = BallotAttemptId::derive_v1(body_instance_id, 0);
            let release_beacon_session_id = BeaconSessionId::new(parliament_test_root(0xD0));
            let tle_key_session_id = TleKeySessionId::new(parliament_test_root(0xD1));
            let release_height = 42;
            let tle_session_id = TleSessionId::derive_v1(
                ballot_attempt_id,
                tle_key_session_id,
                release_beacon_session_id,
                release_height,
            );
            attempt
                .register_ballot_attempt(
                    governance_attempt_id,
                    body_instance_id,
                    ballot_attempt_id,
                    0,
                    tle_session_id,
                    tle_key_session_id,
                    release_beacon_session_id,
                    30,
                    ParliamentTimedOvn {
                        registration_phase_blocks: 4,
                        survivor_freeze_phase_blocks: 3,
                        commitment_phase_blocks: 1,
                        release_delay_blocks: 4,
                        opening_phase_blocks: 2,
                        max_ballot_retries: 2,
                        max_corpus_entries: 3,
                    },
                    release_height,
                )
                .expect("register deterministic binding ballot");
            let registration_root = parliament_test_root(0xD2);
            let dropout_root = parliament_test_root(0xD3);
            let survivor_root = parliament_test_root(0xD4);
            let no_recovery_root = parliament_test_root(0xD5);
            let corpus_root = parliament_test_root(0xD6);
            let timed_commitment_root = parliament_test_root(0xD7);
            attempt
                .close_ballot_registration(
                    governance_attempt_id,
                    ballot_attempt_id,
                    registration_root,
                    3,
                    34,
                )
                .expect("close deterministic ballot registration");
            attempt
                .freeze_ballot_survivors(
                    governance_attempt_id,
                    ballot_attempt_id,
                    dropout_root,
                    survivor_root,
                    3,
                    no_recovery_root,
                    37,
                )
                .expect("freeze deterministic ballot survivors");
            attempt
                .freeze_timed_ovn_corpus(
                    governance_attempt_id,
                    ballot_attempt_id,
                    corpus_root,
                    survivor_root,
                    3,
                    timed_commitment_root,
                    38,
                )
                .expect("freeze deterministic timed-OVN corpus");
            attempt
                .begin_ballot_opening_batch(
                    governance_attempt_id,
                    vec![ballot_attempt_id],
                    release_beacon_session_id,
                    release_height,
                    release_height,
                    BeaconPulseId::new(parliament_test_root(0xD8)),
                )
                .expect("open deterministic timed ballot");
            let outcome = attempt
                .finalize_opened_ballot(
                    governance_attempt_id,
                    ballot_attempt_id,
                    corpus_root,
                    no_recovery_root,
                    tle_session_id,
                    parliament_test_root(0xD9),
                    3,
                    ParliamentAggregateTallyV1 {
                        original_seats: 3,
                        accepted_ballots: 3,
                        aye: 2,
                        nay: 1,
                        abstain: 0,
                    },
                    2,
                    43,
                )
                .expect("finalize deterministic aggregate ballot");
            assert_eq!(outcome, ParliamentAggregateOutcomeV1::Approved);
        }
    }
    attempt
        .body(&body_instance_id)
        .and_then(|body| body.result_height())
        .expect("completed authorization body result height")
}
fn test_parliament_authorization(
    state: &State,
    proposal_kind: &ProposalKind,
    enacted_at_height: u64,
) -> (
    ValidationFeeParliamentAuthorizationV1,
    ParliamentAttemptStateV1,
) {
    let proposal_operator = match proposal_kind {
        ProposalKind::ValidationFeePolicy(proposal) => proposal.proposal_operator.clone(),
        ProposalKind::ValidationFeePayoutLifecycle(proposal) => proposal.proposal_operator.clone(),
        _ => panic!("validation-fee fixture requires a validation-fee proposal"),
    };
    let proposal_fingerprint = proposal_kind.fingerprint();
    let proposal_content_id = ProposalContentId::new(proposal_fingerprint);
    let governance_attempt_id = GovernanceAttemptId::derive_v1(proposal_content_id, 0);
    let requirements = validation_fee_parliament_requirements();
    let expected_head = GovernanceExpectedHeadV1::Absent(GovernanceExpectedHeadAbsentV1 {
        subject_id: proposal_kind
            .governed_subject_id_v1()
            .expect("derive exact validation-fee governed subject"),
    });
    let mut attempt = ParliamentAttemptStateV1::try_new(
        GovernanceAttemptV1 {
            id: governance_attempt_id,
            proposal_content_id,
            sequence: 0,
            risk_tier: RiskTierV1::Constitutional,
            stage: GovernanceStageV1::Qualification,
            status: GovernanceAttemptStatusV1::Active,
        },
        TEST_PARLIAMENT_POLICY_VERSION,
        10,
        proposal_kind.effect_preimage_hash_v1(),
        expected_head,
        requirements.clone(),
    )
    .expect("create exact validation-fee Parliament attempt");
    attempt
        .complete_qualification(governance_attempt_id)
        .expect("complete deterministic qualification");
    let candidates = parliament_test_candidates();
    let candidate_count = u32::try_from(candidates.len()).expect("candidate count fits u32");
    let sortition_session = BeaconSessionId::new(parliament_test_root(0xB0));
    let mut request_ids = Vec::with_capacity(requirements.len());
    let mut registrations = Vec::with_capacity(requirements.len());
    for requirement in &requirements {
        let election_attempt_id =
            BodyElectionAttemptId::derive_v1(governance_attempt_id, requirement.body, 0);
        let request = SortitionRequestV1::try_new_canonical(
            governance_attempt_id,
            election_attempt_id,
            requirement.body,
            parliament_candidate_root_v1(governance_attempt_id, requirement.body, &candidates),
            candidate_count,
            3,
            10,
            20,
            sortition_session,
            None,
        )
        .expect("construct deterministic sortition request");
        request_ids.push(request.id);
        registrations.push(ParliamentSortitionRequestRegistrationV1 {
            sequence: 0,
            request,
        });
    }
    attempt
        .register_sortition_request_batch(governance_attempt_id, registrations, candidates.clone())
        .expect("register deterministic sortition request batch");
    request_ids.sort_unstable();
    let sortition_pulse_id = BeaconPulseId::new(parliament_test_root(0xB1));
    attempt
        .consume_sortition_pulse_batch(
            governance_attempt_id,
            request_ids,
            sortition_session,
            20,
            sortition_pulse_id,
            *sortition_pulse_id.as_bytes(),
            state.network_id_ref(),
            &parliament_test_governance(&requirements),
        )
        .expect("consume deterministic simultaneous Parliament draw");
    let mut certified_at_height = 0;
    for (index, requirement) in requirements.iter().copied().enumerate() {
        let result_height = complete_parliament_body_for_authorization(
            &mut attempt,
            requirement,
            BodyElectionAttemptId::derive_v1(governance_attempt_id, requirement.body, 0),
            0xC0_u8
                .checked_add(u8::try_from(index).expect("body index fits u8"))
                .expect("result tag does not overflow"),
        );
        certified_at_height = certified_at_height.max(result_height);
    }
    assert_eq!(attempt.attempt().stage, GovernanceStageV1::Certification);
    let governance_certificate = attempt
        .construct_certificate(
            governance_attempt_id,
            certified_at_height,
            enacted_at_height,
        )
        .expect("construct complete validation-fee Parliament certificate");
    governance_certificate
        .validate()
        .expect("validation-fee Parliament certificate validates");
    attempt
        .mark_enacted(governance_attempt_id, enacted_at_height)
        .expect("mark exact-due validation-fee attempt enacted");
    attempt
        .validate()
        .expect("enacted validation-fee Parliament attempt validates");
    let authorization = ValidationFeeParliamentAuthorizationV1 {
        proposal_operator,
        proposal_fingerprint,
        governance_certificate_id: GovernanceCertificateId::derive_v1(&governance_certificate),
        governance_certificate,
        enacted_at_height,
    };
    assert_eq!(authorization.invariant_error(), None);
    (authorization, attempt)
}
fn payout_lifecycle_proposal(state: &State, policy: &ValidationFeePolicyV1) -> ProposalKind {
    ProposalKind::ValidationFeePayoutLifecycle(ValidationFeePayoutLifecycleProposal {
        proposal_operator: account(1).0,
        payout_binding: payout_binding(state.network_id_ref(), &policy.ds_asset_id),
    })
}
fn policy_proposal(policy: &ValidationFeePolicyV1) -> ProposalKind {
    ProposalKind::ValidationFeePolicy(ValidationFeePolicyProposal {
        proposal_operator: account(1).0,
        policy: policy.clone(),
    })
}
fn canonical_policy_registry_state(
    state: &State,
    policy: &ValidationFeePolicyV1,
) -> (
    ValidationFeePolicyRegistryV1,
    Vec<(ProposalKind, ParliamentAttemptStateV1)>,
) {
    let enacted_at_height = TEST_POLICY_EFFECTIVE_HEIGHT - 1;
    let lifecycle_proposal = payout_lifecycle_proposal(state, policy);
    let binding = payout_binding(state.network_id_ref(), &policy.ds_asset_id);
    let lifecycle_seal = binding
        .lifecycle_seal()
        .expect("canonical lifecycle binding");
    let policy_proposal = policy_proposal(policy);
    let (lifecycle_authorization, lifecycle_attempt) =
        test_parliament_authorization(state, &lifecycle_proposal, enacted_at_height);
    let (policy_authorization, policy_attempt) =
        test_parliament_authorization(state, &policy_proposal, enacted_at_height);
    let entry =
        ValidationFeePolicyRegistryEntryV1::from_enactment(policy.clone(), policy_authorization)
            .expect("registry entry");
    let registry = ValidationFeePolicyRegistryV1 {
        registered_policies: vec![entry],
        payout_policies: iroha_data_model::validation_fee::ValidationFeePayoutPolicyRegistryV1 {
            entries: vec![
                iroha_data_model::validation_fee::ValidationFeePayoutPolicyEntryV1 {
                    revision: 1,
                    proposal_id: lifecycle_proposal.fingerprint(),
                    lifecycle_seal,
                    payout_binding: binding,
                    parliament_authorization: lifecycle_authorization,
                },
            ],
        },
    };
    registry
        .validate()
        .expect("canonical validation-fee registry validates");
    (
        registry,
        vec![
            (lifecycle_proposal, lifecycle_attempt),
            (policy_proposal, policy_attempt),
        ],
    )
}
fn policy_registry(state: &State, policy: &ValidationFeePolicyV1) -> ValidationFeePolicyRegistryV1 {
    canonical_policy_registry_state(state, policy).0
}
fn seed_canonical_enacted_proposal(
    kind: ProposalKind,
    proposer: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> [u8; 32] {
    let proposal_id = kind.fingerprint();
    assert!(
        matches!(
            &kind,
            ProposalKind::ValidationFeePolicy(_) | ProposalKind::ValidationFeePayoutLifecycle(_)
        ),
        "validation-fee admission fixture requires a validation-fee proposal"
    );
    let selection_epoch = 1;
    state_transaction.world.governance_proposals_mut().insert(
        proposal_id,
        iroha_core::state::GovernanceProposalRecord {
            proposer: proposer.clone(),
            kind,
            created_height: selection_epoch,
            status: iroha_core::state::GovernanceProposalStatus::Enacted,
        },
    );
    proposal_id
}
fn install_canonical_post_enactment_validation_fee_state(
    state: &State,
    authority: &AccountId,
    authority_key_pair: &KeyPair,
    policy: ValidationFeePolicyV1,
) {
    let manifest_signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (registry, enacted_attempts) = canonical_policy_registry_state(state, &policy);
    assert_eq!(
        registry.registered_policies[0]
            .parliament_authorization
            .enacted_at_height,
        TEST_POLICY_ENACTMENT_HEIGHT
    );
    let mut block = state.block(block_header(
        &state,
        TEST_POLICY_ENACTMENT_HEIGHT,
        1_700_000_006_000,
    ));
    let mut state_transaction = block
        .transaction_for_fastpq_testing(Hash::new(b"validation_fee_admission_original_callback"));

    let register_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanManageSmartContractCode.into();
    Grant::account_permission(register_permission, authority.clone())
        .execute(authority, &mut state_transaction)
        .expect("grant payout-contract registration authority");
    let payout_dataspace = payout_contract_address(state.network_id_ref())
        .dataspace_id()
        .expect("payout contract has an exact native dataspace");
    let (contract_artifact, contract_manifest) = payout_contract_artifact();
    let registered_code_hash = iroha_core::smartcontracts::code::register_code_bytes(
        authority,
        payout_dataspace,
        contract_artifact,
        &mut state_transaction,
    )
    .expect("register payout-contract bytes");
    iroha_core::smartcontracts::code::register_manifest(
        authority,
        payout_dataspace,
        contract_manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                authority_key_pair,
            )
            .expect("sign bounded fixture manifest"),
        &mut state_transaction,
    )
    .expect("register signed payout-contract manifest");
    let payout_contract_address_for_activation = payout_contract_address(state.network_id_ref());
    state_transaction
        .world
        .bind_inactive_contract_subject_for_testing(
            payout_contract_address_for_activation.clone(),
            authority.clone(),
        );
    iroha_core::smartcontracts::code::activate_instance(
        authority,
        payout_contract_address_for_activation,
        1,
        registered_code_hash,
        &mut state_transaction,
    )
    .expect("activate immutable payout-contract subject");

    let pool_dataspace = pool_contract_address(state.network_id_ref())
        .dataspace_id()
        .expect("pool contract has an exact native dataspace");
    let (pool_artifact, pool_manifest) = pool_contract_artifact();
    let pool_code_hash = iroha_core::smartcontracts::code::register_code_bytes(
        authority,
        pool_dataspace,
        pool_artifact,
        &mut state_transaction,
    )
    .expect("register pool-contract bytes");
    iroha_core::smartcontracts::code::register_manifest(
        authority,
        pool_dataspace,
        pool_manifest
            .try_signed(
                manifest_signing.context(),
                manifest_signing.max_frame_bytes(),
                authority_key_pair,
            )
            .expect("sign bounded fixture manifest"),
        &mut state_transaction,
    )
    .expect("register signed pool-contract manifest");
    let pool_contract_address_for_activation = pool_contract_address(state.network_id_ref());
    state_transaction
        .world
        .bind_inactive_contract_subject_for_testing(
            pool_contract_address_for_activation.clone(),
            authority.clone(),
        );
    iroha_core::smartcontracts::code::activate_instance(
        authority,
        pool_contract_address_for_activation,
        1,
        pool_code_hash,
        &mut state_transaction,
    )
    .expect("activate pool contract");

    let payout_binding = payout_binding(state.network_id_ref(), &policy.ds_asset_id);
    let wrapper_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
            contract: payout_contract_address(state.network_id_ref()),
            entrypoint: "autonomous_validation_fee_tick".to_owned(),
        }
        .into();
    let pool_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
            contract: pool_contract_address(state.network_id_ref()),
            entrypoint: "swap_exact_in_quote_public".to_owned(),
        }
        .into();
    let wrapper_ds_transfer_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::asset::CanTransferAsset {
            asset: AssetId::new(
                policy.ds_asset_id.clone(),
                policy.treasury_account_id.clone(),
            ),
        }
        .into();
    for (permission, holder) in [
        (
            wrapper_permission,
            payout_binding.treasury_account_id.clone(),
        ),
        (pool_permission, payout_binding.treasury_account_id.clone()),
        (
            wrapper_ds_transfer_permission,
            payout_binding.pool_vault_account_id.clone(),
        ),
    ] {
        Grant::account_permission(permission, holder)
            .execute(authority, &mut state_transaction)
            .expect("grant exact enacted payout-lifecycle effect permission");
    }

    for (proposal_kind, attempt) in enacted_attempts {
        let proposal_id = proposal_kind.fingerprint();
        assert_eq!(
            attempt.proposal_content_id(),
            ProposalContentId::new(proposal_id)
        );
        assert_eq!(
            seed_canonical_enacted_proposal(proposal_kind, authority, &mut state_transaction),
            proposal_id
        );
        let governance_attempt_id = attempt.attempt().id;
        state_transaction
            .world
            .put_parliament_attempt_for_testing(governance_attempt_id, attempt)
            .expect("persist validated enacted Parliament attempt");
    }
    state_transaction
        .world
        .parameters_mut_for_testing()
        .get_mut()
        .set_parameter(Parameter::Custom(registry.into_custom_parameter()));
    state_transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit canonical post-enactment validation-fee state");
}

fn assessment_metadata(
    state: &State,
    user: &AccountId,
    recipient: &AccountId,
    fee_asset: &AssetDefinitionId,
    amount_minor: u64,
) -> Metadata {
    let request = iroha_data_model::validation_fee::RetailFeeQuoteRequestV1 {
        account_id: user.clone(),
        asset_definition_id: fee_asset.clone(),
        transfers: vec![iroha_data_model::validation_fee::RetailFeePaymentLegV1 {
            destination_account_id: recipient.clone(),
            amount_minor_units: amount_minor,
        }],
    };
    let assessment = iroha_core::retail_fee::quote(
        state.view().world(),
        TEST_POLICY_EFFECTIVE_HEIGHT,
        1_793_451_601_000,
        &request,
    )
    .unwrap();
    let mut metadata = Metadata::default();
    metadata.insert(
        iroha_data_model::validation_fee::RETAIL_FEE_ASSESSMENT_METADATA_KEY
            .parse()
            .unwrap(),
        Json::new(assessment),
    );
    metadata
}
fn signed_payment(
    state: &State,
    user: &AccountId,
    key: &KeyPair,
    recipient: &AccountId,
    asset: &AssetDefinitionId,
    amount: Quantity,
    metadata: Metadata,
) -> SignedTransaction {
    TransactionBuilder::new(
        *state.network_id_ref(),
        user.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_instructions([Transfer::asset_quantity(
        AssetId::new(asset.clone(), user.clone()),
        amount,
        recipient.clone(),
    )])
    .with_metadata(metadata)
    .sign(key.private_key())
}
fn signed_transfer(
    state: &State,
    user: &AccountId,
    key: &KeyPair,
    recipient: &AccountId,
    asset: &AssetDefinitionId,
    _policy: &ValidationFeePolicyV1,
    reviewed: bool,
) -> SignedTransaction {
    let metadata = if reviewed {
        assessment_metadata(state, user, recipient, asset, 100)
    } else {
        Metadata::default()
    };
    signed_payment(
        state,
        user,
        key,
        recipient,
        asset,
        Quantity::from(1_u32),
        metadata,
    )
}
fn validate_in_block(state: &State, height: u64, tx: SignedTransaction) -> String {
    let accepted = accept_transaction(state, tx);
    let mut block = state.block(block_header(
        state,
        height,
        1_793_451_601_000 + height.saturating_sub(TEST_POLICY_EFFECTIVE_HEIGHT),
    ));
    let mut ivm_cache = IvmCache::new();
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accepted,
        &mut ivm_cache,
        None,
    );
    match result {
        Ok(_) => "ok".to_string(),
        Err(error) => format!("{error:?}"),
    }
}
fn asset_balance(world: &impl WorldReadOnly, asset_id: &AssetId) -> Quantity {
    world
        .assets()
        .get(asset_id)
        .map_or_else(Quantity::zero, |value| value.clone().into_inner())
}
#[test]
fn validation_fee_registry_cannot_be_installed_through_generic_parameter_path() {
    let (state, user, _, _, treasury, fee_asset) = test_state();
    let policy = validation_fee_policy(&state, fee_asset, treasury);
    let custom = policy_registry(&state, &policy).into_custom_parameter();
    let mut block = state.block(block_header(
        &state,
        TEST_POLICY_ENACTMENT_HEIGHT,
        1_700_000_001_000,
    ));
    let mut state_transaction = block.transaction();
    let error = SetParameter::new(Parameter::Custom(custom))
        .execute(&user, &mut state_transaction)
        .expect_err("generic parameter writes must not bypass Parliament");
    let error_debug = format!("{error:?}");
    assert!(
        error_debug.contains("can only be changed by an enacted SORA Parliament proposal"),
        "unexpected protected-registry rejection: {error_debug}"
    );
}
#[test]
fn active_registry_rejects_missing_enacted_parliament_attempt() {
    let (state, user, user_key_pair, recipient, treasury, fee_asset) = test_state();
    let policy = validation_fee_policy(&state, fee_asset.clone(), treasury);
    install_canonical_post_enactment_validation_fee_state(
        &state,
        &user,
        &user_key_pair,
        policy.clone(),
    );
    let proposal_id = policy_proposal(&policy).fingerprint();
    {
        let mut block = state.block(block_header(
            &state,
            TEST_POLICY_ENACTMENT_HEIGHT + 1,
            1_700_000_007_000,
        ));
        let mut stx = block.transaction();
        let attempt_id = GovernanceAttemptId::derive_v1(ProposalContentId::new(proposal_id), 0);
        assert!(
            stx.world
                .remove_parliament_attempt_for_testing(&attempt_id)
                .is_some(),
            "canonical fixture must retain the enacted Parliament attempt"
        );
        stx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit adversarial missing-attempt state");
    }
    let error = validate_in_block(
        &state,
        TEST_POLICY_EFFECTIVE_HEIGHT,
        signed_transfer(
            &state,
            &user,
            &user_key_pair,
            &recipient,
            &fee_asset,
            &policy,
            true,
        ),
    );
    assert!(
        error.contains("authorized Parliament attempt is missing"),
        "missing enacted Parliament attempt must fail closed: {error}"
    );
}
#[test]
fn enacted_lifecycle_pins_exact_wrapper_pool_and_asset_effect_permissions() {
    let (state, user, user_key_pair, recipient, treasury, fee_asset) = test_state();
    let policy = validation_fee_policy(&state, fee_asset, treasury.clone());
    install_canonical_post_enactment_validation_fee_state(&state, &user, &user_key_pair, policy);
    let wrapper_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
            contract: payout_contract_address(state.network_id_ref()),
            entrypoint: "autonomous_validation_fee_tick".to_owned(),
        }
        .into();
    let pool_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::smart_contract::CanInvokeContractEntrypoint {
            contract: pool_contract_address(state.network_id_ref()),
            entrypoint: "swap_exact_in_quote_public".to_owned(),
        }
        .into();
    let wrapper_ds_transfer_permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::asset::CanTransferAsset {
            asset: AssetId::new(fee_asset_definition_id(), treasury.clone()),
        }
        .into();
    let mut block = state.block(block_header(
        &state,
        TEST_POLICY_ENACTMENT_HEIGHT + 1,
        1_700_000_007_000,
    ));
    let mut stx = block.transaction();
    for (permission, required_owner) in [
        (wrapper_permission, treasury.clone()),
        (pool_permission, treasury.clone()),
        (
            wrapper_ds_transfer_permission,
            pool_contract_address(state.network_id_ref()).subject_id(),
        ),
    ] {
        let grant_error = Grant::account_permission(permission.clone(), recipient.clone())
            .execute(&user, &mut stx)
            .expect_err(
                "payout runtime permission must not be delegated after lifecycle enactment",
            );
        assert!(
            grant_error
                .to_string()
                .contains("forbids delegating its exact runtime permissions"),
            "unexpected payout runtime delegation error: {grant_error}"
        );
        let revoke_error = Revoke::account_permission(permission, required_owner)
            .execute(&user, &mut stx)
            .expect_err("required payout runtime permission must remain pinned");
        assert!(
            revoke_error
                .to_string()
                .contains("pins its exact runtime permissions"),
            "unexpected payout runtime revocation error: {revoke_error}"
        );
    }
}

#[test]
fn direct_submission_requires_signed_assessment_and_native_charging_is_atomic() {
    let (state, user, key, recipient, treasury, asset) = test_state();
    let policy = validation_fee_policy(&state, asset.clone(), treasury.clone());
    install_canonical_post_enactment_validation_fee_state(&state, &user, &key, policy.clone());
    let missing = signed_transfer(&state, &user, &key, &recipient, &asset, &policy, false);
    assert!(
        validate_in_block(&state, TEST_POLICY_EFFECTIVE_HEIGHT, missing)
            .contains("validation_fee_assessment")
    );
    // Principal fits but its overage does not: neither leg nor receipt may commit.
    let underfunded = signed_payment(
        &state,
        &user,
        &key,
        &recipient,
        &asset,
        quantity("99.95"),
        assessment_metadata(&state, &user, &recipient, &asset, 9995),
    );
    assert!(
        validate_in_block(&state, TEST_POLICY_EFFECTIVE_HEIGHT, underfunded)
            .contains("insufficient")
    );
    assert_eq!(
        asset_balance(
            state.view().world(),
            &AssetId::new(asset.clone(), recipient.clone())
        ),
        Quantity::zero()
    );
    assert!(
        iroha_core::retail_fee::receipts(state.view().world(), &user, None, 10)
            .unwrap()
            .is_empty()
    );
    let tx = signed_transfer(&state, &user, &key, &recipient, &asset, &policy, true);
    let accepted = accept_transaction(&state, tx);
    let mut block = state.block(block_header(
        &state,
        TEST_POLICY_EFFECTIVE_HEIGHT,
        1_793_451_601_000,
    ));
    let result = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accepted,
        &mut IvmCache::new(),
        None,
    );
    assert!(result.is_ok(), "{result:?}");
    block.commit_world_overlay_for_testing().unwrap();
    assert_eq!(
        asset_balance(
            state.view().world(),
            &AssetId::new(asset.clone(), user.clone())
        ),
        quantity("98.90")
    );
    assert_eq!(
        asset_balance(
            state.view().world(),
            &AssetId::new(asset.clone(), recipient)
        ),
        quantity("1")
    );
    assert_eq!(
        asset_balance(state.view().world(), &AssetId::new(asset, treasury)),
        quantity("0.10")
    );
    let receipts = iroha_core::retail_fee::receipts(state.view().world(), &user, None, 10).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].collected_minor, 10);
}
#[test]
fn signed_assessment_cannot_be_repurposed_for_another_amount_or_charge() {
    let (state, user, key, recipient, treasury, asset) = test_state();
    let policy = validation_fee_policy(&state, asset.clone(), treasury);
    install_canonical_post_enactment_validation_fee_state(&state, &user, &key, policy);
    let metadata = assessment_metadata(&state, &user, &recipient, &asset, 100);
    let wrong_amount = signed_payment(
        &state,
        &user,
        &key,
        &recipient,
        &asset,
        quantity("2"),
        metadata.clone(),
    );
    assert!(
        validate_in_block(&state, TEST_POLICY_EFFECTIVE_HEIGHT, wrong_amount).contains("differs")
    );
    let mut assessment = metadata
        .get(iroha_data_model::validation_fee::RETAIL_FEE_ASSESSMENT_METADATA_KEY)
        .unwrap()
        .try_into_any_norito::<iroha_data_model::validation_fee::RetailFeeAssessmentV1>()
        .unwrap();
    assessment.fee_minor = 0;
    let mut altered = Metadata::default();
    altered.insert(
        iroha_data_model::validation_fee::RETAIL_FEE_ASSESSMENT_METADATA_KEY
            .parse()
            .unwrap(),
        Json::new(assessment),
    );
    let tx = signed_payment(
        &state,
        &user,
        &key,
        &recipient,
        &asset,
        quantity("1"),
        altered,
    );
    assert!(validate_in_block(&state, TEST_POLICY_EFFECTIVE_HEIGHT, tx).contains("differs"));
}

#[test]
fn concurrent_reviewed_retail_payments_and_replay_do_not_double_spend_inclusion() {
    let (mut state, user, key, recipient, treasury, asset) = test_state();
    let policy = validation_fee_policy(&state, asset.clone(), treasury.clone());
    install_canonical_post_enactment_validation_fee_state(&state, &user, &key, policy);
    {
        let mut record = iroha_data_model::validation_fee::RetailFeeAccountStateV1::enroll(
            user.clone(),
            1_793_451_600_000,
            10_000,
        )
        .unwrap();
        record.payments_used = 49;
        let storage_key = format!(
            "retail_fee_v1/{}",
            hex::encode(iroha_crypto::Hash::new(user.to_string().as_bytes()).as_ref())
        )
        .parse()
        .unwrap();
        let mut store = state.world.smart_contract_state_mut_for_testing().block();
        store.insert(storage_key, norito::to_bytes(&record).unwrap());
        store.commit();
    }
    let metadata = assessment_metadata(&state, &user, &recipient, &asset, 100);
    let transactions = (1..=2)
        .map(|nonce| {
            let mut builder = TransactionBuilder::new(
                *state.network_id_ref(),
                user.clone(),
                iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
            )
            .with_instructions([Transfer::asset_quantity(
                AssetId::new(asset.clone(), user.clone()),
                Quantity::from(1_u32),
                recipient.clone(),
            )])
            .with_metadata(metadata.clone());
            builder.set_nonce(std::num::NonZeroU32::new(nonce).unwrap());
            builder.sign(key.private_key())
        })
        .collect::<Vec<_>>();
    let mut block = state.block(block_header(
        &state,
        TEST_POLICY_EFFECTIVE_HEIGHT,
        1_793_451_601_000,
    ));
    let mut cache = IvmCache::new();
    let first = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accept_transaction(&state, transactions[0].clone()),
        &mut cache,
        None,
    );
    assert!(first.is_ok(), "{first:?}");
    let stale = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accept_transaction(&state, transactions[1].clone()),
        &mut cache,
        None,
    );
    assert!(
        stale.is_err(),
        "concurrent free assessment cannot acquire an overage charge"
    );
    let replay = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accept_transaction(&state, transactions[0].clone()),
        &mut cache,
        None,
    );
    assert!(
        replay.is_err(),
        "same signed payment cannot consume another included payment"
    );
    block.commit_world_overlay_for_testing().unwrap();
    let view = state.view();
    assert_eq!(
        iroha_core::retail_fee::account_state(view.world(), &user)
            .unwrap()
            .unwrap()
            .payments_used,
        50
    );
    assert_eq!(
        asset_balance(view.world(), &AssetId::new(asset.clone(), user.clone())),
        quantity("99")
    );
    assert_eq!(
        asset_balance(view.world(), &AssetId::new(asset, treasury)),
        Quantity::zero()
    );
    assert_eq!(
        iroha_core::retail_fee::receipts(view.world(), &user, None, 10)
            .unwrap()
            .len(),
        1
    );
}
