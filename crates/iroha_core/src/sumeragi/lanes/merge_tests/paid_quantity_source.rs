//! Original certified lane inputs retain their invocation route through global fee Burn.

use super::*;
use crate::sumeragi::test_chain::Signers;
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId, AssetId},
    block::consensus::NexusFeeSettlementV1,
    fastpq::{
        FastpqExecutionEffectContextV1, FastpqExecutionEffectKindV1, FastpqSourceEffectCoverageV1,
        FastpqSourceExecutionEntryV1, FastpqSourceExecutionKindV1, FastpqSourceLaneV1,
        FastpqSourceRouteV1, FastpqSourceStatementContextV1,
    },
    isi::{Mint, Register},
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig},
    transaction::{FeeChargeKind, FeeChargeLimit, FeePaymentIntent, TransactionBuilder},
};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;

const INITIAL_BALANCE: u32 = 10_000;
const FEE: u32 = 2;

fn fee_asset() -> AssetDefinitionId {
    AssetDefinitionId::parse_address_literal(
        &iroha_config::parameters::defaults::nexus::fees::fee_asset_id(),
    )
    .expect("canonical network XOR")
}

fn paid_fixture(dataspace: DataSpaceId) -> Fixture {
    let mut lane_policy = policy();
    lane_policy.fixed[0].dataspace = dataspace;
    Fixture::start_with_policy_and_configure(lane_policy, |config| {
        let mut nexus = iroha_config::parameters::actual::Nexus::default();
        let mut dataspaces = vec![DataSpaceMetadata::default()];
        if dataspace != DataSpaceId::UNIVERSAL {
            dataspaces.push(DataSpaceMetadata {
                id: dataspace,
                alias: "paid-source-lane".into(),
                description: None,
                fault_tolerance: 1,
            });
        }
        nexus.dataspace_catalog = DataSpaceCatalog::new(dataspaces).unwrap();
        nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
        if dataspace != DataSpaceId::UNIVERSAL {
            // Physical policy lanes and certified native ordering lanes have
            // distinct identities. Route this payer through physical lane 1,
            // while retaining native lane 2 in its original execution source.
            let physical_lane = LaneId::new(1);
            nexus.lane_catalog = LaneCatalog::new(
                std::num::NonZeroU32::new(2).unwrap(),
                vec![
                    LaneConfig::default(),
                    LaneConfig {
                        id: physical_lane,
                        dataspace_id: dataspace,
                        alias: "paid-source-physical-lane".into(),
                        ..LaneConfig::default()
                    },
                ],
            )
            .unwrap();
            nexus.configured_lane_catalog = nexus.lane_catalog.clone();
            nexus.lane_config =
                iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
            nexus
                .routing_policy
                .rules
                .push(iroha_config::parameters::actual::LaneRoutingRule {
                    lane: physical_lane,
                    dataspace: Some(dataspace),
                    matcher: iroha_config::parameters::actual::LaneRoutingMatcher {
                        account: Some(AccountId::new(lane_user().public_key().clone()).to_string()),
                        ..Default::default()
                    },
                });
        }
        nexus.fees.fee_asset_id = fee_asset().clone();
        nexus.fees.fee_sink_account_id =
            AccountId::new(config.genesis_key.public_key().clone()).clone();
        nexus.fees.base_fee = Quantity::from(FEE);
        nexus.fees.per_byte_fee = Quantity::zero();
        nexus.fees.per_instruction_fee = Quantity::zero();
        nexus.fees.per_gas_unit_fee = Quantity::zero();
        config.nexus = Some(nexus);
        config.genesis_instructions.push(
            Register::asset_definition(AssetDefinition::numeric(
                fee_asset(),
                "Paid source XOR",
                AssetBalancePolicy::Global,
                None,
            ))
            .into(),
        );
        for key in [lane_user(), other_user()] {
            config.genesis_instructions.push(
                Mint::asset_quantity(
                    INITIAL_BALANCE,
                    AssetId::of(fee_asset(), AccountId::new(key.public_key().clone())),
                )
                .into(),
            );
        }
    })
}

fn paid_log(fixture: &Fixture, key: &KeyPair, text: &str, created_ms: u64) -> SignedTransaction {
    let mut builder = TransactionBuilder::new(
        fixture.chain.network_id(),
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(
            vec![FeeChargeLimit::new(
                FeeChargeKind::Nexus,
                fee_asset(),
                Quantity::from(FEE),
            )],
            None,
        ),
    );
    builder.set_creation_time(Duration::from_millis(created_ms));
    builder
        .with_instructions([InstructionBox::from(Log::new(Level::INFO, text.to_owned()))])
        .sign(key.private_key())
}

fn assert_paid_lane_source(dataspace: DataSpaceId) {
    let _fee_guard = crate::status::nexus_fee_test_lock().lock().unwrap();
    let mut fixture = paid_fixture(dataspace);
    for (height, created_ms) in [(2, GENESIS_MS), (3, GENESIS_MS + 1)] {
        let work = paid_log(&fixture, &other_user(), "activate paid lane", created_ms);
        assert_eq!(fixture.chain.commit(vec![work]), vec![true]);
        assert_eq!(fixture.chain.height(), height);
    }
    let record = fixture.record();
    assert_eq!(record.dataspace, dataspace);
    assert_eq!(record.active_from, 3);

    // This body has no quantity instruction or transfer transcript. The only
    // original quantity effect is its ordinary, positively paid global XOR Burn.
    let transaction = paid_log(
        &fixture,
        &lane_user(),
        "original lane output",
        GENESIS_MS + 2,
    );
    fixture.certify(1, 3, vec![transaction.clone()]);
    let direct = paid_log(
        &fixture,
        &other_user(),
        "original global output",
        GENESIS_MS + 2,
    );
    let proposal = fixture.chain.proposal(None, vec![direct]);
    assert_eq!(proposal.header().height().get(), 4);
    let call = iroha_crypto::Hash::from(transaction.hash_as_entrypoint());
    let pool = fixture.chain.state().ivm_execution_budget();
    let network_id = fixture.chain.network_id();
    let mut execution = fixture
        .chain
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .unwrap_or_else(|error| panic!("original paid lane output must execute: {error}"));
    let committed = execution.publish(Signers::Quorum).unwrap();
    let block = committed.block();
    assert_eq!(block.merged_entrypoint_count(), 1);
    let index = block
        .external_entrypoints_slice()
        .iter()
        .position(|input| input.hash() == transaction.hash_as_entrypoint())
        .expect("the original certified lane input is retained once");
    let (_, output) = block
        .network_output_at(u32::try_from(index).unwrap())
        .unwrap();
    let input = block.network_entrypoint_at(index).unwrap();
    assert!(output.result.is_ok(), "{:?}", output.result);
    assert_eq!(input.hash(), transaction.hash_as_entrypoint());
    let receipt = output
        .result
        .nexus_fee_receipt()
        .expect("original paid Burn");
    receipt.validate_for_network_input(input, 4).unwrap();
    assert_eq!(receipt.dataspace_id, dataspace);
    assert_eq!(receipt.lane_id, LANE);
    assert_eq!(receipt.fee_asset_id, fee_asset());
    assert_eq!(receipt.fee_amount, Quantity::from(FEE));
    assert_eq!(receipt.settlement, NexusFeeSettlementV1::Burn);
    assert!(!block.fastpq_transcripts().contains_key(&call));

    // Consume the actual published Worker witness, rather than rebuilding a
    // context or re-decoding a caller-supplied statement as execution authority.
    let original = execution.take_finalized_fastpq_source().unwrap();
    original.verify_current().unwrap();
    assert!(original.pool().same_pool(&pool));
    assert_eq!(
        original.manifest().coverage,
        FastpqSourceEffectCoverageV1::Complete
    );
    let expected = FastpqExecutionEffectContextV1 {
        source: FastpqSourceStatementContextV1 {
            network_id,
            height: 4,
        },
        entry: FastpqSourceExecutionEntryV1 {
            entry_hash: call,
            execution_kind: FastpqSourceExecutionKindV1::ExecutionCall,
            route: FastpqSourceRouteV1::Lane(FastpqSourceLaneV1 {
                lane_id: LANE,
                lane_incarnation: iroha_crypto::Hash::from_marked_bytes(record.incarnation)
                    .expect("authenticated original lane incarnation"),
            }),
            dataspace_id: dataspace,
        },
    };
    assert!(original.entries().contains(&expected.entry));
    let statement = original
        .leaves()
        .iter()
        .position(|leaf| leaf.entry_hash == call)
        .unwrap();
    let retained = original.entry(statement).unwrap();
    assert!(retained.pool().same_pool(&pool));
    assert_eq!(retained.effects().context, expected);
    let [effect] = retained.effects().effects.as_slice() else {
        panic!("the paid Log must own exactly one quantity effect");
    };
    let FastpqExecutionEffectKindV1::Burn(burn) = &effect.kind else {
        panic!("the original fee must be a Burn");
    };
    assert_eq!(burn.balance.scope, AssetBalanceScope::Global);
    assert_eq!(burn.balance.asset.definition, fee_asset());
    assert_eq!(
        burn.balance.account,
        AccountId::new(lane_user().public_key().clone())
    );
    assert_eq!(burn.amount, Quantity::from(FEE));
    assert_eq!(burn.balance_before, Quantity::from(INITIAL_BALANCE));
    assert_eq!(burn.balance_after, Quantity::from(INITIAL_BALANCE - FEE));
    assert_eq!(
        burn.supply_before
            .checked_sub(&Quantity::from(FEE))
            .unwrap(),
        burn.supply_after
    );
    drop(original);
    drop(execution);

    let view = fixture.chain.state().view();
    let payer = AssetId::of(
        fee_asset(),
        AccountId::new(lane_user().public_key().clone()),
    );
    let sink = AssetId::of(fee_asset(), fixture.chain.genesis_account().clone());
    assert_eq!(
        view.world().assets().get(&payer).unwrap().as_ref(),
        &Quantity::from(INITIAL_BALANCE - FEE)
    );
    assert!(view.world().assets().get(&sink).is_none());
    assert_eq!(
        view.world()
            .asset_definitions()
            .get(&fee_asset())
            .unwrap()
            .total_quantity(),
        &Quantity::from(2 * INITIAL_BALANCE - 4 * FEE)
    );
    assert_eq!(fixture.chain.height(), 4);
}

#[test]
fn paid_universal_lane_burn_preserves_complete_source_control() {
    assert_paid_lane_source(DataSpaceId::UNIVERSAL);
}

#[test]
fn paid_merged_lane_burn_keeps_original_nonuniversal_source() {
    assert_paid_lane_source(DataSpaceId::new(7));
}
