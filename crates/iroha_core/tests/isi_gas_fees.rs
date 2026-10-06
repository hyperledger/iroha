//! Integration-style test: non-VM (native ISI) transaction gas metering and fee transfer.
#![allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::restriction)]
#![allow(clippy::similar_names)]
use iroha_config::parameters::actual::{GasLiquidity, GasVolatility};
use iroha_core::{
    executor::Executor,
    gas as isi_gas,
    governance::manifest::LaneManifestRegistry,
    kura::Kura,
    query,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
    tx::{AcceptedTransaction, TransactionRejectionReason},
};
use iroha_data_model::prelude::*;
use iroha_data_model::transaction::signed::TransactionSignatureError;
use iroha_model_base::chain::ChainId;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::numeric::Numeric;
use iroha_test_samples::gen_account_in;
use ivm::{ProgramMetadata, encoding, instruction, syscalls as ivm_sys};
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
use std::{borrow::Cow, num::NonZeroU64, sync::Arc};
fn test_network_id(label: &[u8]) -> NetworkId {
    NetworkId::from_genesis_hash(
        iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
            iroha_crypto::Hash::new(label),
        ),
    )
}
fn new_state(
    world: World,
    kura: Arc<Kura>,
    query_handle: query::store::LiveQueryStoreHandle,
    chain_id: ChainId,
) -> State {
    // Direct executor fixtures declare their immutable scope explicitly. Real
    // genesis/finality cases below still use the signed CertifiedTestChain.
    {
        let mut parameters = world.parameters.block();
        parameters.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            iroha_data_model::block::consensus::SumeragiRootScope::Global,
        ));
        parameters.commit();
    }
    let state = State::new_with_chain_for_testing(world, kura, query_handle, chain_id);

    let nexus = state.nexus_snapshot();
    let lane_manifests =
        Arc::new(LaneManifestRegistry::empty().rebind(&nexus.lane_catalog, &nexus.governance));
    state.install_lane_manifests_for_testing(&lane_manifests);
    state
}
fn new_account_in_domain(account_id: &AccountId, _domain: &str) -> Account {
    Account::new(account_id.clone()).build(account_id)
}
fn default_fee_sponsor_program_id(sponsor: &AccountId) -> FeeSponsorProgramId {
    FeeSponsorProgramId::new(
        sponsor.clone(),
        "default".parse().expect("default fee sponsor program"),
    )
}
fn fee_sponsor_setup_hash(program_id: &FeeSponsorProgramId) -> iroha_crypto::Hash {
    iroha_crypto::Hash::new(format!("iroha:test:fee-sponsor-program-setup:{program_id}").as_bytes())
}
fn provision_fee_sponsor_program(
    state_block: &mut iroha_core::state::StateBlock<'_>,
    sponsor: &AccountId,
    beneficiary: &AccountId,
    program_id: &FeeSponsorProgramId,
    asset_definition_id: &AssetDefinitionId,
    instruction: &InstructionBox,
    allocation: u128,
    activate_at_height: u64,
) {
    let setup_call_hash = fee_sponsor_setup_hash(program_id);
    let mut state_transaction = state_block.transaction_for_fastpq_testing(setup_call_hash);
    let selector = FeeSponsorRuleSelector::NativeInstruction(
        iroha_data_model::nexus::FeeSponsorNativeInstructionSelector {
            wire_id: iroha_data_model::isi::instruction_wire_id(instruction)
                .expect("native instruction must have a registered wire id")
                .to_owned(),
            asset_definition_id: None,
        },
    );
    let revision = FeeSponsorProgramRevision {
        program_id: program_id.clone(),
        revision: 1,
        eligibility: FeeSponsorEligibility::EnrolledOnly,
        rules: vec![FeeSponsorRule {
            id: "allow_set_account_metadata"
                .parse()
                .expect("valid sponsor rule id"),
            effect: FeeSponsorRuleEffect::Allow,
            selectors: vec![selector],
        }],
        asset_budgets: vec![FeeSponsorAssetBudget {
            asset_definition_id: asset_definition_id.clone(),
            per_transaction: Quantity::from(allocation),
            per_block: Quantity::from(allocation),
            per_program_epoch: Quantity::from(allocation),
            per_beneficiary_epoch: Quantity::from(allocation),
            reserve_floor: Quantity::zero(),
            epoch_length_blocks: nonzero!(1_u64),
        }],
    };
    iroha_data_model::isi::nexus::CreateFeeSponsorProgram {
        program: FeeSponsorProgram::new(program_id.clone(), program_id.sponsor.clone()),
    }
    .execute(sponsor, &mut state_transaction)
    .expect("create fee sponsor program");
    iroha_data_model::isi::nexus::StageFeeSponsorProgramRevision { revision }
        .execute(sponsor, &mut state_transaction)
        .expect("stage fee sponsor program revision");
    iroha_data_model::isi::nexus::EnrollFeeSponsorBeneficiary {
        program_id: program_id.clone(),
        beneficiary: beneficiary.clone(),
    }
    .execute(sponsor, &mut state_transaction)
    .expect("enroll fee sponsor beneficiary");
    iroha_data_model::isi::nexus::FundFeeSponsorProgram {
        program_id: program_id.clone(),
        asset_definition_id: asset_definition_id.clone(),
        amount: Quantity::from(allocation),
    }
    .execute(sponsor, &mut state_transaction)
    .expect("fund fee sponsor program");
    iroha_data_model::isi::nexus::ActivateFeeSponsorProgramRevision {
        program_id: program_id.clone(),
        revision: 1,
        activate_at_height,
    }
    .execute(sponsor, &mut state_transaction)
    .expect("activate fee sponsor program revision");
    state_transaction.apply();
}
#[test]
fn non_vm_instructions_charge_fees() {
    // 1) Minimal world: domains, accounts, asset definition, payer balance, tech account
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let init = 100_000u128;
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(init));
    let world = World::with_assets([dom_w, dom_i], [alice, tech], [ad], [payer_balance], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    // 2) Configure pipeline gas policy
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    let rate: u64 = 10; // minimal units per one gas
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: rate,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let native_chain = crate::block::tests::component_chain(state);
    let state = native_chain.state();
    // 3) Build a simple native ISI transaction (SetKeyValue<Account>)
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction.clone()));
    let used = isi_gas::meter_instructions(
        match &exec {
            Executable::Instructions(v) => v.as_ref(),
            _ => unreachable!(),
        },
        &iroha_core::gas::DEFAULT_ZK_GAS,
    );
    assert!(used > 0);
    let fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(init),
        )],
        NonZeroU64::new(1_000_000),
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(exec)
    .sign(alice_kp.private_key());
    // 4) Execute after genesis so the production fee exemption does not apply.
    let executor = Executor::default();
    let block_header = BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    );
    let mut block = state.block(block_header);
    let mut state_tx =
        block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
    // Direct component execution supplies the same explicit route to both State owners.
    state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    executor
        .execute_transaction(&mut state_tx, &alice_id, tx, &mut ivm_cache)
        .expect("execution");
    // Used gas is recorded for block-level accounting
    assert!(state_tx.last_tx_gas_used >= used);
    // Fee = used * rate (units_per_gas)
    let fee = u128::from(state_tx.last_tx_gas_used) * u128::from(rate);
    // Read balances and assert transfer took place
    let payer_balance_after = state_tx
        .world
        .assets()
        .get(&payer_asset)
        .expect("payer asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let payee_balance_after = state_tx
        .world
        .assets()
        .get(&AssetId::of(asset_def_id.clone(), gas_id.clone()))
        .expect("tech account asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    assert_eq!(payer_balance_after, init - fee);
    assert_eq!(payee_balance_after, fee);
}
#[test]
fn non_vm_instructions_charge_restricted_gas_asset_on_current_route() {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let route = DataSpaceId::new(10);
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "routegas".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "routegas".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
        Some(DomainId::try_new("wonderland", "universal").unwrap()),
    )
    .build(&alice_id);
    let payer_asset = AssetId::with_scope(
        asset_def_id.clone(),
        alice_id.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(route),
    );
    let init = 100_000u128;
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(init));
    let world = World::with_assets([dom_w, dom_i], [alice, tech], [ad], [payer_balance], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    let rate: u64 = 10;
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: rate,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let native_chain = crate::block::tests::component_chain(state);
    let state = native_chain.state();
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction.clone()));
    let used = isi_gas::meter_instructions(
        match &exec {
            Executable::Instructions(v) => v.as_ref(),
            _ => unreachable!(),
        },
        &iroha_core::gas::DEFAULT_ZK_GAS,
    );
    assert!(used > 0);
    let fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(init),
        )],
        NonZeroU64::new(1_000_000),
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(exec)
    .sign(alice_kp.private_key());
    let executor = Executor::default();
    let block_header = BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    );
    let mut block = state.block(block_header);
    let mut state_tx =
        block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
    state_tx.current_dataspace_id = Some(route);
    state_tx.world.current_dataspace_id = Some(route);
    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    executor
        .execute_transaction(&mut state_tx, &alice_id, tx, &mut ivm_cache)
        .expect("execution");
    assert_eq!(state_tx.current_dataspace_id, Some(route));
    let fee = u128::from(state_tx.last_tx_gas_used) * u128::from(rate);
    let payee_asset = AssetId::with_scope(
        asset_def_id.clone(),
        gas_id.clone(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(route),
    );
    let payer_balance_after = state_tx
        .world
        .assets()
        .get(&payer_asset)
        .expect("payer route-scoped asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let payee_balance_after = state_tx
        .world
        .assets()
        .get(&payee_asset)
        .expect("tech account route-scoped asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    assert_eq!(payer_balance_after, init - fee);
    assert_eq!(payee_balance_after, fee);
}
#[test]
fn non_vm_instructions_can_charge_gas_to_fee_sponsor() {
    // 1) Minimal world: domains, accounts, asset definition, sponsor balance, custody, and tech account
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (sponsor_id, _sponsor_kp) = gen_account_in("wonderland");
    let (custody_id, _custody_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let sponsor = new_account_in_domain(&sponsor_id, "wonderland");
    let custody = new_account_in_domain(&custody_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let sponsor_asset = AssetId::of(asset_def_id.clone(), sponsor_id.clone());
    let custody_asset = AssetId::of(asset_def_id.clone(), custody_id.clone());
    let init = 100_000u128;
    let sponsor_balance = Asset::new(sponsor_asset.clone(), Quantity::from(init));
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(0_u64));
    let world = World::with_assets(
        [dom_w, dom_i],
        [alice, sponsor, custody, tech],
        [ad],
        [sponsor_balance, payer_balance],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    state.nexus.get_mut().fees.sponsor_vault_custody_account_id = custody_id.clone();
    // 2) Configure pipeline gas policy.
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    let rate: u64 = 10; // minimal units per one gas
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: rate,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let native_chain = crate::block::tests::component_chain(state);
    let state = native_chain.state();

    // 3) Build a simple native ISI transaction (SetKeyValue<Account>)
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction.clone()));
    let used = isi_gas::meter_instructions(
        match &exec {
            Executable::Instructions(v) => v.as_ref(),
            _ => unreachable!(),
        },
        &iroha_core::gas::DEFAULT_ZK_GAS,
    );
    assert!(used > 0);
    let program_id = default_fee_sponsor_program_id(&sponsor_id);
    let fee_payment = FeePaymentIntent::sponsor(
        program_id.clone(),
        1,
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(init),
        )],
        None,
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(exec)
    .sign(alice_kp.private_key());
    // 4) Execute after genesis and verify sponsored fee transfer.
    let executor = Executor::default();
    let block_header = BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    );
    let mut block = state.block(block_header);
    provision_fee_sponsor_program(
        &mut block,
        &sponsor_id,
        &alice_id,
        &program_id,
        &asset_def_id,
        &instruction,
        init,
        2,
    );
    let mut state_tx =
        block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
    // Direct component execution supplies the same explicit route to both State owners.
    state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);

    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    executor
        .execute_transaction(&mut state_tx, &alice_id, tx, &mut ivm_cache)
        .expect("execution");
    // Used gas is recorded for block-level accounting
    assert!(state_tx.last_tx_gas_used >= used);
    // Fee = used * rate (units_per_gas)
    let fee = u128::from(state_tx.last_tx_gas_used) * u128::from(rate);
    // Funding moved the allocation into protocol custody; charging moves only the fee to tech.
    let payer_balance_after = state_tx
        .world
        .assets()
        .get(&payer_asset)
        .expect("payer asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let sponsor_balance_after = state_tx
        .world
        .assets()
        .get(&sponsor_asset)
        .map(|asset| asset.0.as_numeric().try_mantissa_u128().unwrap())
        .unwrap_or(0);
    let custody_balance_after = state_tx
        .world
        .assets()
        .get(&custody_asset)
        .expect("custody asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let payee_balance_after = state_tx
        .world
        .assets()
        .get(&AssetId::of(asset_def_id.clone(), gas_id.clone()))
        .expect("tech account asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    assert_eq!(payer_balance_after, 0);
    assert_eq!(sponsor_balance_after, 0);
    assert_eq!(custody_balance_after, init - fee);
    assert_eq!(payee_balance_after, fee);
}
#[test]
fn non_vm_instructions_can_charge_gas_to_fee_sponsor_via_overlay_pipeline() {
    use iroha_core::block::BlockBuilder;
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (sponsor_id, _sponsor_kp) = gen_account_in("wonderland");
    let (custody_id, _custody_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let sponsor = new_account_in_domain(&sponsor_id, "wonderland");
    let custody = new_account_in_domain(&custody_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let sponsor_asset = AssetId::of(asset_def_id.clone(), sponsor_id.clone());
    let custody_asset = AssetId::of(asset_def_id.clone(), custody_id.clone());
    let tech_asset = AssetId::of(asset_def_id.clone(), gas_id.clone());
    let init = 100_000u128;
    let sponsor_balance = Asset::new(sponsor_asset.clone(), Quantity::from(init));
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(0_u64));
    let world = World::with_assets(
        [dom_w, dom_i],
        [alice, sponsor, custody, tech],
        [ad],
        [sponsor_balance, payer_balance],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "00000000-0000-0000-0000-000000000000".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    {
        let nexus = state.nexus.get_mut();
        nexus.fees.sponsor_vault_custody_account_id = custody_id.clone();
    }
    let program_id = default_fee_sponsor_program_id(&sponsor_id);
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let setup_block = BlockBuilder::new(Vec::new())
        .chain(0, None)
        .sign(alice_kp.private_key())
        .unpack(|_| {});
    // Provision the sponsor in an explicit world fixture before validating the
    // first block, so setup transfers cannot become unowned finalized sources.
    let mut setup_state_block = state.block(setup_block.header());
    {
        provision_fee_sponsor_program(
            &mut setup_state_block,
            &sponsor_id,
            &alice_id,
            &program_id,
            &asset_def_id,
            &instruction,
            init,
            1,
        );
    }
    let policy_entries = vec![iroha_data_model::nexus::AxtPolicyBinding {
        dsid: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
        policy: iroha_data_model::nexus::AxtPolicyEntry {
            manifest_root: iroha_crypto::Hash::new(b"sponsor-overlay-lane-manifest").into(),
            target_lane: iroha_model_base::topology::LaneId::SINGLE,
            active_handle_era: 0,
            next_handle_counter: 0,
            current_slot: 0,
        },
    }];
    setup_state_block
        .install_axt_policy_snapshot(&iroha_data_model::nexus::AxtPolicySnapshot {
            version: iroha_data_model::nexus::AxtPolicySnapshot::compute_version(&policy_entries),
            entries: policy_entries,
        })
        .expect("bind sponsored settlement to the current lane manifest");
    setup_state_block
        .commit_world_overlay_for_testing()
        .expect("commit sponsor world fixture");
    {
        let check_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
        let mut check_block = state.block(check_header);
        let check_tx = check_block.transaction();
        let program = check_tx
            .world
            .fee_sponsor_programs()
            .get(&program_id)
            .expect("setup block must create the exact fee sponsor program");
        assert_eq!(program.lifecycle, FeeSponsorProgramLifecycle::Active);
        assert_eq!(program.active_revision, Some(1));
        assert!(
            check_tx
                .world
                .fee_sponsor_enrollments()
                .get(&iroha_data_model::nexus::FeeSponsorEnrollmentKey {
                    program_id: program_id.clone(),
                    beneficiary: alice_id.clone(),
                })
                .is_some(),
            "setup block must enroll the authority in the exact sponsor program"
        );
    }
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: 10,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);

    let mut native_chain = crate::block::tests::component_chain(state);
    let state = Arc::clone(native_chain.state());
    let fee_payment = FeePaymentIntent::sponsor(
        program_id,
        1,
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(init),
        )],
        None,
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(Executable::from(core::iter::once(instruction)))
    .sign(alice_kp.private_key());
    native_chain.commit(vec![tx]);
    let committed = native_chain.committed(native_chain.height());
    let validation_events = native_chain.take_events().unwrap();
    assert!(
        committed.block().output_error(0).is_none(),
        "{:?}",
        committed.block().output_error(0)
    );
    let inspect_header = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    let mut inspect_block = state.block(inspect_header);
    let inspect_tx = inspect_block.transaction();
    let payer_balance_after = inspect_tx
        .world
        .assets()
        .get(&payer_asset)
        .expect("payer asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let sponsor_balance_after = inspect_tx
        .world
        .assets()
        .get(&sponsor_asset)
        .map(|asset| asset.0.as_numeric().try_mantissa_u128().unwrap())
        .unwrap_or(0);
    let custody_balance_after = inspect_tx
        .world
        .assets()
        .get(&custody_asset)
        .expect("custody asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let account_after = inspect_tx
        .world
        .accounts()
        .get(&alice_id)
        .expect("authority account exists");
    assert!(
        account_after
            .metadata()
            .get(&"k".parse::<Name>().expect("metadata key"))
            .is_some(),
        "overlay transaction must apply instruction effects; validation_events={validation_events:?}"
    );
    assert_eq!(payer_balance_after, 0);
    assert_eq!(sponsor_balance_after, 0);
    assert!(custody_balance_after < init);
    let payee_balance_after = inspect_tx
        .world
        .assets()
        .get(&tech_asset)
        .map(|asset| asset.0.as_numeric().try_mantissa_u128().unwrap())
        .unwrap_or(0);
    assert!(
        payee_balance_after > 0,
        "gas fee recipient must receive sponsored fee units"
    );
}
#[test]
fn genesis_overlay_pipeline_transactions_remain_fee_free() {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let tech_asset = AssetId::of(asset_def_id.clone(), gas_id.clone());
    let init = 100_000u128;
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(init));
    let tech_balance = Asset::new(tech_asset.clone(), Quantity::from(0_u64));
    let mut world = World::with_assets(
        [dom_w, dom_i],
        [alice, tech],
        [ad],
        [payer_balance, tech_balance],
        [],
    );
    crate::sns::seed_default_namespace_policies_for_payment_asset(
        &mut world,
        &asset_def_id.canonical_address(),
    );
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "00000000-0000-0000-0000-000000000000".parse().unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.base_fee = Quantity::from(1_u32);
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::from(1_u32);
    nexus.fees.fee_asset_id = asset_def_id.canonical_address();
    nexus.fees.fee_sink_account_id = gas_id.to_string();
    let (mut state, _) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        world,
        nexus.clone(),
        query_handle,
        chain,
        test_network_id(b"fee-free-configured-genesis"),
    );
    state
        .set_nexus_from_config(nexus)
        .expect("original configured fee asset");
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: 10,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let nexus = state.nexus_snapshot();
    let pipeline = state.installed_pipeline().clone();
    let mut config = iroha_core::sumeragi::test_chain::TestChainConfig::new(state.world, 0);
    config.genesis_key = alice_kp;
    config.genesis_instructions = vec![instruction];
    config.pipeline = pipeline;
    config.nexus = Some(nexus);
    let native_chain = iroha_core::sumeragi::test_chain::CertifiedTestChain::start(config)
        .expect("real signed four-validator genesis retains fee-free execution");
    let state = native_chain.state();
    let inspect_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut inspect_block = state.block(inspect_header);
    let inspect_tx = inspect_block.transaction();
    let account_after = inspect_tx
        .world
        .accounts()
        .get(&alice_id)
        .expect("authority account exists");
    assert!(
        account_after
            .metadata()
            .get(&"k".parse::<Name>().expect("metadata key"))
            .is_some(),
        "overlay transaction must apply instruction effects"
    );
    let payer_balance_after = inspect_tx
        .world
        .assets()
        .get(&payer_asset)
        .expect("payer asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let payee_balance_after = inspect_tx
        .world
        .assets()
        .get(&tech_asset)
        .expect("tech account asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    assert_eq!(payer_balance_after, init);
    assert_eq!(payee_balance_after, 0);
}
#[test]
fn non_vm_gas_limit_too_low_rejects() {
    // Minimal world: one domain/account/asset; no fee mapping needed for this negative test.
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let dom: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let world = World::with([dom], [alice], [ad]);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let state = new_state(world, kura, query_handle, chain.clone());
    // Single SetKeyValue<Account> instruction
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction));
    let used = isi_gas::meter_instructions(
        match &exec {
            Executable::Instructions(v) => v.as_ref(),
            _ => unreachable!(),
        },
        &iroha_core::gas::DEFAULT_ZK_GAS,
    );
    assert!(used > 0);
    let gas_limit = NonZeroU64::new(used.saturating_sub(1))
        .expect("metered instruction usage must exceed one gas unit");
    let fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(1_000_000_u64),
        )],
        Some(gas_limit),
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(exec)
    .sign(alice_kp.private_key());
    let executor = Executor::default();
    let block_header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx =
        block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
    // Direct component execution supplies the same explicit route to both State owners.
    state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    let res = executor.execute_transaction(&mut state_tx, &alice_id, tx, &mut ivm_cache);
    assert!(
        matches!(
            &res,
            Err(
                iroha_core::execution_attempt::ExecutionAttemptError::Rejected(
                    ValidationFail::NotPermitted(message)
                )
            ) if message == &format!("out of gas: used {used} > limit {gas_limit}")
        ),
        "expected exact gas-limit rejection, got {res:?}"
    );
}
#[test]
fn ivm_syscall_charges_fees() {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let rate: u64 = 10;
    let gas_bound = 1_000_000_u64;
    let fee_capacity = u128::from(gas_bound) * u128::from(rate);
    let init = fee_capacity + 100;
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(init));
    let world = World::with_assets([dom_w, dom_i], [alice, tech], [ad], [payer_balance], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: rate,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let native_chain = crate::block::tests::component_chain(state);
    let state = native_chain.state();
    let scall = encoding::wide::encode_sys(
        instruction::wide::system::SCALL,
        u8::try_from(ivm_sys::SYSCALL_DEBUG_PRINT).expect("syscall id fits in u8"),
    );
    let mut program = ProgramMetadata {
        max_cycles: 1_000,
        ..ProgramMetadata::default()
    }
    .encode();
    program.extend_from_slice(&scall.to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let exec = Executable::Ivm(IvmBytecode::from_compiled(program));
    let fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(fee_capacity),
        )],
        NonZeroU64::new(gas_bound),
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(exec)
    .sign(alice_kp.private_key());
    let executor = Executor::default();
    let block_header = BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    );
    let mut block = state.block(block_header);
    let mut state_tx =
        block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
    let contract_route = iroha_model_base::topology::DataSpaceId::new(10);
    state_tx.current_dataspace_id = Some(contract_route);
    state_tx.world.current_dataspace_id = Some(contract_route);
    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    executor
        .execute_transaction(&mut state_tx, &alice_id, tx, &mut ivm_cache)
        .expect("execution");
    assert_eq!(state_tx.current_dataspace_id, Some(contract_route));
    let scall_cost = ivm::gas::cost_of(scall).expect("SCALL must have gas cost");
    // DEBUG_PRINT charges deterministic host work gas on top of the SCALL opcode.
    let debug_print_host_gas = 16;
    let expected_debug_print_gas = scall_cost + debug_print_host_gas;
    assert_eq!(state_tx.last_tx_gas_used, expected_debug_print_gas);
    let fee = u128::from(state_tx.last_tx_gas_used) * u128::from(rate);
    let payer_balance_after = state_tx
        .world
        .assets()
        .get(&payer_asset)
        .expect("payer asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    let payee_balance_after = state_tx
        .world
        .assets()
        .get(&AssetId::of(asset_def_id.clone(), gas_id.clone()))
        .expect("tech account asset exists")
        .0
        .as_numeric()
        .try_mantissa_u128()
        .unwrap();
    assert_eq!(payer_balance_after, init - fee);
    assert_eq!(payee_balance_after, fee);
}
#[test]
fn legacy_gas_limit_metadata_string_is_rejected() {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction));
    let mut md = Metadata::default();
    md.insert(
        "gas_limit".parse().unwrap(),
        iroha_primitives::json::Json::new("not-a-number"),
    );
    let network_id = test_network_id(b"isi-gas-fees-legacy-metadata-string");
    let error = iroha_data_model::transaction::TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(exec)
    .with_metadata(md)
    .try_sign(alice_kp.private_key())
    .expect_err("legacy gas_limit metadata must fail before signing");
    assert_eq!(
        error,
        TransactionSignatureError::InvalidFeePaymentIntent(
            "legacy transaction metadata key `gas_limit` is not supported".to_owned(),
        )
    );
}
#[test]
fn legacy_gas_limit_metadata_zero_is_rejected() {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction));
    let mut md = Metadata::default();
    md.insert(
        "gas_limit".parse().unwrap(),
        iroha_primitives::json::Json::new(0_u64),
    );
    let network_id = test_network_id(b"isi-gas-fees-legacy-metadata-zero");
    let error = iroha_data_model::transaction::TransactionBuilder::new(
        network_id,
        alice_id.clone(),
        iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
    )
    .with_executable(exec)
    .with_metadata(md)
    .try_sign(alice_kp.private_key())
    .expect_err("legacy gas_limit metadata must fail before signing");
    assert_eq!(
        error,
        TransactionSignatureError::InvalidFeePaymentIntent(
            "legacy transaction metadata key `gas_limit` is not supported".to_owned(),
        )
    );
}
#[test]
fn ivm_gas_fees_transfer_exact_signed_asset_quantity() {
    // 1) Minimal world: domains, accounts, asset definition, payer balance, tech account
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let rate: u64 = 7;
    let gas_bound = 1_000_000_u64;
    let fee_capacity = u128::from(gas_bound) * u128::from(rate);
    let init = fee_capacity + 100;
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(init));
    let world = World::with_assets([dom_w, dom_i], [alice, tech], [ad], [payer_balance], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    // 2) Configure pipeline gas policy
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: rate,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let native_chain = crate::block::tests::component_chain(state);
    let state = native_chain.state();
    // 3) Build a minimal IVM program that consumes gas
    let mut code = Vec::new();
    code.extend_from_slice(
        &encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 1, 0, 0).to_le_bytes(),
    );
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let meta = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 1_000_000,
        abi_version: 1,
    };
    let mut program = meta.encode();
    program.extend_from_slice(&code);
    let fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(fee_capacity),
        )],
        NonZeroU64::new(gas_bound),
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(Executable::Ivm(IvmBytecode::from_compiled(program)))
    .sign(alice_kp.private_key());
    // 4) Execute after genesis and verify exact actual asset effects.
    let executor = Executor::default();
    let block_header = BlockHeader::new(
        nonzero!(2_u64),
        state.view().latest_block_hash(),
        None,
        0,
        0,
    );
    let mut block = state.block(block_header);
    let mut state_tx =
        block.transaction_for_fastpq_testing(iroha_crypto::Hash::from(tx.hash_as_entrypoint()));
    // Direct component execution supplies the same explicit route to both State owners.
    state_tx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    state_tx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    executor
        .execute_transaction(&mut state_tx, &alice_id, tx, &mut ivm_cache)
        .expect("execution");
    assert!(state_tx.last_tx_gas_used > 0);
    let fee = u128::from(state_tx.last_tx_gas_used) * u128::from(rate);
    assert_eq!(
        state_tx.world.assets().get(&payer_asset).unwrap().as_ref(),
        &Quantity::from(init - fee),
    );
    assert_eq!(
        state_tx
            .world
            .assets()
            .get(&AssetId::new(asset_def_id, gas_id))
            .unwrap()
            .as_ref(),
        &Quantity::from(fee),
    );
}
#[test]
fn block_gas_rejection_rolls_back_actual_fee_and_business_effects() {
    let (alice_id, alice_kp) = gen_account_in("wonderland");
    let (gas_id, _gas_kp) = gen_account_in("ivm");
    let dom_w: Domain =
        Domain::new(DomainId::try_new("wonderland", "universal").unwrap()).build(&alice_id);
    let dom_i: Domain = Domain::new(DomainId::try_new("ivm", "universal").unwrap()).build(&gas_id);
    let alice = new_account_in_domain(&alice_id, "wonderland");
    let tech = new_account_in_domain(&gas_id, "ivm");
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "xor".parse().unwrap(),
        );
    let ad: AssetDefinition = AssetDefinition::numeric(
        asset_def_id.clone(),
        "xor".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&alice_id);
    let instruction: InstructionBox = iroha_data_model::isi::SetKeyValue::account(
        alice_id.clone(),
        "k".parse().unwrap(),
        iroha_primitives::json::Json::new("v"),
    )
    .into();
    let exec = Executable::from(core::iter::once(instruction));
    let used = isi_gas::meter_instructions(
        match &exec {
            Executable::Instructions(v) => v.as_ref(),
            _ => unreachable!(),
        },
        &iroha_core::gas::DEFAULT_ZK_GAS,
    );
    assert!(used > 0);
    let rate: u64 = 10;
    let fee = u128::from(used) * u128::from(rate);
    let init = fee.saturating_add(100);
    let payer_asset = AssetId::of(asset_def_id.clone(), alice_id.clone());
    let payer_balance = Asset::new(payer_asset.clone(), Quantity::from(init));
    let world = World::with_assets([dom_w, dom_i], [alice, tech], [ad], [payer_balance], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let chain: ChainId = "test-chain".parse().unwrap();
    let mut state = new_state(world, kura, query_handle, chain.clone());
    let mut pipeline = state.installed_pipeline().clone();
    pipeline.gas.tech_account_id = gas_id.to_string();
    pipeline.gas.accepted_assets = vec![asset_def_id.to_string()];
    pipeline.gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: asset_def_id.to_string(),
        units_per_gas: rate,
        twap_local_per_xor: Numeric::one(),
        liquidity: GasLiquidity::Tier2,
        volatility: GasVolatility::Stable,
    }];
    state.set_pipeline(pipeline);
    let fee_payment = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::PipelineGas,
            asset_def_id.clone(),
            Quantity::from(init),
        )],
        NonZeroU64::new(1_000_000),
    );
    let tx = iroha_data_model::transaction::TransactionBuilder::new(
        *state.network_id_ref(),
        alice_id.clone(),
        fee_payment,
    )
    .with_executable(exec)
    .sign(alice_kp.private_key());
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    block.gas_limit_per_block = used.saturating_sub(1);
    let mut ivm_cache = iroha_core::smartcontracts::ivm::cache::IvmCache::new();
    let accepted = AcceptedTransaction::new_unchecked(Cow::Owned(tx));
    let res = iroha_core::tx::execute_component_transaction_for_testing(
        &mut block,
        accepted,
        &mut ivm_cache,
        None,
    );
    assert!(matches!(
        res,
        Err(TransactionRejectionReason::Validation(
            ValidationFail::NotPermitted(_)
        ))
    ));
    assert_eq!(
        block.world.assets().get(&payer_asset).unwrap().as_ref(),
        &Quantity::from(init),
        "the rejected transaction overlay must not debit its fee payer",
    );
    assert!(
        block
            .world
            .assets()
            .get(&AssetId::new(asset_def_id, gas_id))
            .is_none(),
        "the rejected transaction overlay must not credit a fee recipient",
    );
    assert!(
        block
            .world
            .map_account(&alice_id, |account| {
                account
                    .value()
                    .metadata()
                    .get(&"k".parse::<Name>().unwrap())
                    .is_none()
            })
            .unwrap(),
        "the rejected transaction overlay must not retain business writes"
    );
}
