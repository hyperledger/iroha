//! Original signed private-root H2 approval for downstream HTTP worker-boundary tests.
//!
//! Uses the existing native AMX private configuration, signed genesis, owner grant,
//! paid native execution and CertifiedTestChain's real four-validator certificates.
//! It signs certificates locally rather than running consensus and adds no proof authority.

use super::{CertifiedTestChain, TestChainConfig};
use crate::state::{World, WorldReadOnly as _};
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId},
    block::consensus::SumeragiRootScope,
    isi::{Grant, Mint, Register, sumeragi_amx::RegisterAmxParticipantV1},
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    role::Role,
    sumeragi_amx::AmxDebitApprovalV1,
};
use iroha_executor_data_model::permission::query::CanReadAllLedgerData;
use iroha_model_base::{chain::ChainId, domain::DomainId, topology::DataSpaceId};
use iroha_primitives::numeric::{Numeric, Quantity};
use mv::storage::StorageReadOnly as _;

const DATASPACE: DataSpaceId = DataSpaceId::new((1_u64 << 40) + 117);
fn payer() -> KeyPair {
    KeyPair::from_seed(vec![0x51; 32], Algorithm::Ed25519)
}

fn receiver() -> KeyPair {
    KeyPair::from_seed(vec![0x52; 32], Algorithm::Ed25519)
}

fn account(key: &KeyPair) -> AccountId {
    AccountId::new(key.public_key().clone())
}

fn principal() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("amx", "private-amx").unwrap(),
        "principal".parse().unwrap(),
    )
}

fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}

fn private_config(global: &CertifiedTestChain, id: DataSpaceId) -> TestChainConfig {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.chain_id = ChainId::from("native-amx-private-root");
    config.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: global.network_id(),
        dataspace_id: id,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.lane_catalog = LaneCatalog::new(
        1_u32.try_into().unwrap(),
        vec![LaneConfig {
            dataspace_id: id,
            alias: "private-amx".into(),
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id,
        alias: "private-amx".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = id;
    nexus.fees.fee_asset_id = fee_asset().canonical_address();
    nexus.fees.fee_sink_account_id = account(&config.genesis_key).to_string();
    nexus.fees.base_fee = Quantity::zero();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config.nexus = Some(nexus);
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            iroha_data_model::block::consensus::PrivateRootFeePolicy {
                asset_definition_id: fee_asset(),
                base_fee: 1_u32.into(),
                per_byte_fee: Quantity::zero(),
                per_instruction_fee: 1_u32.into(),
                per_gas_unit_fee: 1_u32.into(),
            }
            .into_custom_parameter()
            .unwrap(),
        ));
    let mut gas = iroha_config::parameters::actual::Gas::default();
    gas.tech_account_id = account(&config.genesis_key).to_string();
    gas.accepted_assets = vec![fee_asset().canonical_address()];
    gas.units_per_gas = vec![iroha_config::parameters::actual::GasRate {
        asset: fee_asset().canonical_address(),
        units_per_gas: 1,
        twap_local_per_xor: Numeric::one(),
        liquidity: iroha_config::parameters::actual::GasLiquidity::Tier2,
        volatility: iroha_config::parameters::actual::GasVolatility::Stable,
    }];
    config
        .genesis_parameters
        .extend(crate::pipeline_gas_policy::parameters_for_testing(gas));
    let domain = DomainId::try_new("amx", "private-amx").unwrap();
    config.genesis_instructions = vec![
        Register::account(Account::new(account(&payer()))).into(),
        Register::account(Account::new(account(&receiver()))).into(),
        Register::domain(iroha_data_model::domain::Domain::new(domain.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "AMX fee",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain.clone()),
        ))
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            principal(),
            "AMX principal",
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain),
        ))
        .into(),
        Mint::asset_quantity(
            1_000_000_u32,
            AssetId::with_scope(
                fee_asset(),
                account(&payer()),
                AssetBalanceScope::Dataspace(id),
            ),
        )
        .into(),
        Mint::asset_quantity(
            1_000_000_u32,
            AssetId::with_scope(
                fee_asset(),
                account(&receiver()),
                AssetBalanceScope::Dataspace(id),
            ),
        )
        .into(),
        Mint::asset_quantity(
            1_000_u32,
            AssetId::with_scope(
                principal(),
                account(&payer()),
                AssetBalanceScope::Dataspace(id),
            ),
        )
        .into(),
        RegisterAmxParticipantV1 {
            dataspace: id,
            global_chain_id: global.state().chain_id_ref().clone(),
            global_genesis: global.committed(1).block().encode_wire().unwrap(),
            global_successor: global.committed(2).block().encode_wire().unwrap(),
        }
        .into(),
    ];
    // Every ordinary private fixture transaction, including clock work and negative controls,
    // pays the real signed private fee policy from its own restricted balance partition.
    for key in [
        config.genesis_key.clone(),
        KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519),
    ] {
        config.genesis_instructions.push(
            Mint::asset_quantity(
                1_000_000_u32,
                AssetId::with_scope(fee_asset(), account(&key), AssetBalanceScope::Dataspace(id)),
            )
            .into(),
        );
    }
    config
}

/// Create a signed, fee-charged H2 that grants one exact debit approval to the reader.
///
/// The reader has only a role-derived full-ledger capability and a separate direct
/// owner-issued debit grant. Principal remains unchanged, while the private fee balance
/// pays the exact committed native charge, including instruction gas. This is
/// certificate/HTTP component test support.
/// # Panics
/// If signed genesis, current native fee authorization, execution or monetary checks fail.
#[must_use]
pub fn native_amx_approval_route_fixture() -> (CertifiedTestChain, AmxDebitApprovalV1, KeyPair) {
    // This parent lineage is authenticated by the native private-genesis owner.
    // Its H2 is real explicit configuration work; the tested paid input is bank H2 below.
    let config = TestChainConfig::new(World::new(), 1_000);
    let global_key = config.genesis_key.clone();
    let mut global = CertifiedTestChain::start(config).unwrap();
    let signed = global.sign(
        &global_key,
        [iroha_data_model::isi::Log::new(
            iroha_logger::Level::INFO,
            "authenticate AMX approval fixture parent".into(),
        )
        .into()],
        1_499,
    );
    assert_eq!(global.commit_at(1_500, vec![signed]), vec![true]);
    let mut config = private_config(&global, DATASPACE);
    config.genesis_instructions.push(
        Register::role(
            Role::new("amx_route_read".parse().unwrap(), account(&receiver()))
                .add_permission(CanReadAllLedgerData),
        )
        .into(),
    );
    let mut bank = CertifiedTestChain::start(config).unwrap();
    let approval = AmxDebitApprovalV1 {
        global_network: global.network_id(),
        participant_network: bank.network_id(),
        participant_instance: bank.instance().0,
        dataspace: DATASPACE,
        // An exact opaque business-intent identity; this read requires no Begin or escrow.
        transaction_id: [0xA7; 32],
        debited_asset: AssetId::with_scope(
            principal(),
            account(&payer()),
            AssetBalanceScope::Dataspace(DATASPACE),
        ),
    };
    let signed = bank.sign(
        &payer(),
        [Grant::account_permission(approval.permission().unwrap(), account(&receiver())).into()],
        1_999,
    );
    let original_id = signed.hash_as_entrypoint();
    assert_eq!(bank.commit_at(2_000, vec![signed]), vec![true]);
    assert_eq!(bank.height(), 2);
    let committed = bank.committed(2);
    let input = committed.block().network_entrypoint_at(0).unwrap();
    assert_eq!(input.hash(), original_id);
    let (_, output) = committed.block().network_output_at(0).unwrap();
    assert!(output.result.is_ok());
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("actual paid H2 grant receipt");
    receipt.validate_for_network_input(input, 2).unwrap();
    assert_eq!(receipt.dataspace_id, DATASPACE);
    assert_eq!(receipt.lane_id, iroha_model_base::topology::LaneId::new(0));
    assert_eq!(receipt.fee_asset_id, fee_asset());
    assert_eq!(
        receipt.debit_source,
        iroha_data_model::nexus::FeeDebitSource::Account(account(&payer()))
    );
    assert_eq!(
        receipt.settlement,
        iroha_data_model::block::consensus::NexusFeeSettlementV1::Burn
    );
    // Independently recompute from the policy authored in signed bank genesis:
    // one base unit + one instruction unit + one unit per actual native gas.
    // Neither a balance delta nor the receipt's claimed amount chooses this expectation.
    assert_eq!(receipt.schedule.base_fee, Quantity::from(1_u32));
    assert_eq!(receipt.schedule.per_byte_fee, Quantity::zero());
    assert_eq!(receipt.schedule.per_instruction_fee, Quantity::from(1_u32));
    assert_eq!(receipt.schedule.per_gas_unit_fee, Quantity::from(1_u32));
    assert_eq!(receipt.schedule.instruction_count, 1);
    assert!(receipt.schedule.gas_used > 0);
    let expected_fee = Quantity::from(2_u64.checked_add(receipt.schedule.gas_used).unwrap());
    assert_eq!(receipt.fee_amount, expected_fee);
    let view = bank.state().view();
    let fee = AssetId::with_scope(
        fee_asset(),
        account(&payer()),
        AssetBalanceScope::Dataspace(DATASPACE),
    );
    assert_eq!(
        view.world().assets().get(&fee).unwrap().as_ref(),
        &Quantity::from(1_000_000_u32)
            .checked_sub(&expected_fee)
            .unwrap()
    );
    assert_eq!(
        view.world()
            .asset_definition(&fee_asset())
            .unwrap()
            .total_quantity(),
        &Quantity::from(4_000_000_u32)
            .checked_sub(&expected_fee)
            .unwrap(),
        "the exact paid charge burns both payer balance and supply",
    );
    assert_eq!(
        view.world()
            .assets()
            .get(&approval.debited_asset)
            .unwrap()
            .as_ref(),
        &Quantity::from(1_000_u32)
    );
    let direct = view
        .world()
        .account_permissions_iter(&account(&receiver()))
        .unwrap()
        .collect::<Vec<_>>();
    assert!(direct.contains(&&approval.permission().unwrap()));
    assert!(!direct.contains(&&CanReadAllLedgerData.into()));
    assert_eq!(
        view.world()
            .account_roles_iter(&account(&receiver()))
            .count(),
        1
    );
    drop(view);
    (bank, approval, receiver())
}
