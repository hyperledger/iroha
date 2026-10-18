//! Real paid H2 private-context source for downstream authorization-race controls.
//!
//! Reuses the canonical empty-pool bootstrap planner and CertifiedTestChain's actual native
//! execution/publication. The fixture signs genuine four-seat certificates itself; it does
//! not run a consensus network or grant a production proof-authority constructor.

use super::{CertifiedTestChain, TestChainConfig};
use crate::{
    private_settlement::{
        global_state::plan_private_settlement_pool_bootstrap_v1,
        state::PrivateSettlementPoolStateExtV1 as _,
    },
    state::{World, WorldReadOnly as _},
};
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{
    account::AccountId,
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId},
    isi::{Grant, InstructionBox, Mint, Register, Transfer},
    nexus::{
        PrivateSettlementPoolGovernanceLifecycleV1, PrivateSettlementPoolGovernanceProjectionV1,
        PrivateSettlementPoolKeyV1, PrivateSettlementRouteV1,
    },
    privacy::PrivacyPoolIdV1,
    transaction::{
        FeeChargeKind, FeeChargeLimit, FeePaymentIntent, SignedTransaction, TransactionBuilder,
    },
};
use iroha_executor_data_model::permission::query::CanReadAllLedgerData;
use iroha_model_base::{
    domain::DomainId,
    topology::{DataSpaceId, LaneId},
};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly as _;
use std::time::Duration;

const GLOBAL_FEE: u32 = 2;
const GLOBAL_INITIAL: u32 = 1_000_000;
fn account(key: &KeyPair) -> AccountId {
    AccountId::new(key.public_key().clone())
}
fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .unwrap()
}
fn paid_global_config() -> TestChainConfig {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let domain = DomainId::try_new(
        "fees",
        iroha_config::parameters::defaults::nexus::DEFAULT_DATASPACE_ALIAS,
    )
    .unwrap();
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = fee_asset().clone();
    nexus.fees.fee_sink_account_id = account(&config.genesis_key).clone();
    nexus.fees.base_fee = GLOBAL_FEE.into();
    nexus.fees.per_byte_fee = Quantity::zero();
    nexus.fees.per_instruction_fee = Quantity::zero();
    nexus.fees.per_gas_unit_fee = Quantity::zero();
    config
        .genesis_parameters
        .push(iroha_data_model::parameter::Parameter::Custom(
            nexus
                .fees
                .clone()
                .into_custom_parameter()
                .expect("original signed Global fee policy"),
        ));
    config.nexus = Some(nexus);
    config.genesis_instructions.extend([
        Register::domain(iroha_data_model::domain::Domain::new(domain.clone())).into(),
        Register::asset_definition(AssetDefinition::numeric(
            fee_asset(),
            "AMX global fee",
            AssetBalancePolicy::Global,
            Some(domain),
        ))
        .into(),
        Mint::asset_quantity(
            GLOBAL_INITIAL,
            AssetId::with_scope(
                fee_asset(),
                account(&config.genesis_key),
                AssetBalanceScope::Global,
            ),
        )
        .into(),
        Mint::asset_quantity(
            GLOBAL_INITIAL,
            AssetId::with_scope(
                fee_asset(),
                account(&KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519)),
                AssetBalanceScope::Global,
            ),
        )
        .into(),
    ]);
    config
}

fn paid_global_sign(
    chain: &CertifiedTestChain,
    key: &KeyPair,
    instructions: impl IntoIterator<Item = InstructionBox>,
    created_ms: u64,
) -> SignedTransaction {
    let intent = FeePaymentIntent::authority(
        vec![FeeChargeLimit::new(
            FeeChargeKind::Nexus,
            fee_asset(),
            GLOBAL_FEE.into(),
        )],
        None,
    );
    let mut builder = TransactionBuilder::new(chain.network_id(), account(key), intent);
    builder.set_creation_time(Duration::from_millis(created_ms));
    builder
        .with_instructions(instructions)
        .sign(key.private_key())
}

/// Build an actual fee-charged H2 and its selected native pool plus the authorized reader signer.
///
/// The signer holds `CanReadAllLedgerData` from signed genesis. The fixture's Global payer and
/// recipient balances assert the nonzero fee and transfer before any context route runs.
/// # Panics
/// If canonical bootstrap, signed genesis, native execution, or exact balance assertions fail.
pub fn native_private_context_route_fixture()
-> (CertifiedTestChain, PrivateSettlementPoolKeyV1, KeyPair) {
    let mut config = paid_global_config();
    let signer = config.genesis_key.clone();
    config
        .genesis_instructions
        .push(Grant::account_permission(CanReadAllLedgerData, account(&signer)).into());
    let key = PrivateSettlementPoolKeyV1 {
        route: PrivateSettlementRouteV1 {
            dataspace_id: DataSpaceId::new(7),
            lane_id: LaneId::new(17),
            lane_incarnation: Hash::new(b"private public-cut lane incarnation"),
        },
        pool_id: PrivacyPoolIdV1::new([0xD4; 32]),
    };
    {
        use iroha_data_model::{
            consensus::{ConsensusKeyId, ConsensusKeyRecord, ConsensusKeyRole, ConsensusKeyStatus},
            sumeragi_lanes::{SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord},
        };
        use iroha_model_base::peer::PeerId;
        let mut keys = (0..4)
            .map(|i| KeyPair::from_seed(vec![0xB0 + i; 32], Algorithm::BlsNormal))
            .collect::<Vec<_>>();
        keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
        let members = keys
            .iter()
            .enumerate()
            .map(|(i, pair)| {
                let id = ConsensusKeyId::new(
                    ConsensusKeyRole::Committee,
                    format!("pool-context-member-{i}"),
                );
                let pop = iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap();
                config
                    .world
                    .consensus_keys_by_pk
                    .insert(pair.public_key().to_string(), vec![id.clone()]);
                config.world.consensus_keys.insert(
                    id.clone(),
                    ConsensusKeyRecord {
                        id,
                        public_key: pair.public_key().clone(),
                        pop: Some(pop.clone()),
                        activation_height: 1,
                        expiry_height: None,
                        replaces: None,
                        status: ConsensusKeyStatus::Pending,
                    },
                );
                SumeragiLaneMember {
                    peer: PeerId::new(pair.public_key().clone()),
                    pop,
                }
            })
            .collect();
        let mut lanes = config.world.sumeragi_lanes.view().get().clone();
        lanes.upsert(SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: key.route.lane_id,
            dataspace: key.route.dataspace_id,
            incarnation: *key.route.lane_incarnation.as_ref(),
            params: Default::default(),
            committee: members,
            created_at: 0,
            active_from: 1,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 1,
            rescued: 0,
        });
        config.world.sumeragi_lanes = mv::cell::Cell::new(lanes);
    }
    let governance = PrivateSettlementPoolGovernanceProjectionV1 {
        version: 1,
        route: key.route,
        pool_id: key.pool_id,
        asset_binding_commitment: Hash::new(b"public-cut opaque asset commitment"),
        audit_policy_digest: Hash::new(b"public-cut opaque audit commitment"),
        audit_key_epoch: 1,
        lifecycle: PrivateSettlementPoolGovernanceLifecycleV1 {
            governance_revision: 1,
            activation_height: 1,
            retirement_height: None,
        },
        governance_digest: Hash::new(b"public-cut opaque governance commitment"),
        prior_revisions: Vec::new(),
    };
    let plan = plan_private_settlement_pool_bootstrap_v1(
        &config.world.private_settlement_governance.view(),
        &config.world.private_settlement_pools.view(),
        &config.world.private_settlement_roots.view(),
        governance,
        &[],
        1,
    )
    .unwrap()
    .unwrap();
    plan.pool.validate().unwrap();
    config
        .world
        .private_settlement_governance
        .insert(plan.key, plan.governance);
    config
        .world
        .private_settlement_pools
        .insert(plan.key, plan.pool);
    config
        .world
        .private_settlement_roots
        .insert(plan.root_key, plan.root_provenance);
    let mut chain = CertifiedTestChain::start(config).unwrap();
    let owner = account(&signer);
    let recipient = account(&KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519));
    let source = AssetId::with_scope(fee_asset(), owner.clone(), AssetBalanceScope::Global);
    let signed = paid_global_sign(
        &chain,
        &signer,
        [Transfer::asset_quantity(source.clone(), 1_u32, recipient.clone()).into()],
        1_999,
    );
    let original_input = signed.hash_as_entrypoint();
    assert_eq!(chain.commit_at(2_000, vec![signed]), vec![true]);
    let committed = chain.committed(2);
    let input = committed.block().network_entrypoint_at(0).unwrap();
    assert_eq!(input.hash(), original_input);
    let (_, output) = committed.block().network_output_at(0).unwrap();
    assert!(output.result.is_ok());
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("actual paid Global H2 context source receipt");
    receipt.validate_for_network_input(input, 2).unwrap();
    assert_eq!(receipt.dataspace_id, DataSpaceId::UNIVERSAL);
    assert_eq!(receipt.lane_id, LaneId::new(0));
    assert_eq!(receipt.fee_asset_id, fee_asset());
    assert_eq!(
        receipt.debit_source,
        iroha_data_model::nexus::FeeDebitSource::Account(owner.clone()),
    );
    assert_eq!(
        receipt.settlement,
        iroha_data_model::block::consensus::NexusFeeSettlementV1::Burn,
    );
    // Pin the original H1-authored Global schedule and fee independently of balance deltas.
    let authored = chain
        .state()
        .view()
        .world()
        .state_parameters()
        .root_fees()
        .cloned()
        .expect("committed Global root fee policy");
    assert_eq!(authored.base_fee, Quantity::from(GLOBAL_FEE));
    assert_eq!(authored.fee_asset_id, fee_asset());
    assert_eq!(receipt.schedule.base_fee, Quantity::from(GLOBAL_FEE));
    assert_eq!(receipt.schedule.per_byte_fee, Quantity::zero());
    assert_eq!(receipt.schedule.per_instruction_fee, Quantity::zero());
    assert_eq!(receipt.schedule.per_gas_unit_fee, Quantity::zero());
    assert_eq!(receipt.schedule.instruction_count, 1);
    assert_eq!(receipt.fee_amount, Quantity::from(GLOBAL_FEE));
    let view = chain.state().view();
    let destination = AssetId::with_scope(fee_asset(), recipient, AssetBalanceScope::Global);
    assert_eq!(
        view.world().assets().get(&source).unwrap().as_ref(),
        &Quantity::from(GLOBAL_INITIAL - GLOBAL_FEE - 1)
    );
    assert_eq!(
        view.world().assets().get(&destination).unwrap().as_ref(),
        &Quantity::from(GLOBAL_INITIAL + 1)
    );
    assert_eq!(
        view.world()
            .asset_definition(&fee_asset())
            .unwrap()
            .total_quantity(),
        &Quantity::from(2 * GLOBAL_INITIAL - GLOBAL_FEE)
    );
    drop(view);
    (chain, key, signer)
}
