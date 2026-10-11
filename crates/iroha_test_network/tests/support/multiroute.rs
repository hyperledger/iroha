//! Shared four-validator, three-public-lane fixture using production NPoS and DA policies.
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    account::{Account, AccountId},
    asset::{AssetDefinition, AssetDefinitionId, AssetId},
    domain::Domain,
    isi::{
        InstructionBox, Mint, Register, SetParameter,
        staking::{ActivatePublicLaneValidator, RegisterPublicLaneValidator},
    },
    parameter::{
        Parameter,
        system::{SumeragiNposParameters, SumeragiParameters},
    },
    prelude::Quantity,
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy, SumeragiLaneRoute,
    },
};
use iroha_genesis::GenesisTopologyEntry;
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::peer::PeerId;
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_test_network::{
    NetworkBuilder, genesis_participant_committee_key_instructions,
    unexecuted_genesis_factory_with_post_topology,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use std::time::Duration;
use toml::{Table, Value as TomlValue};

const SMOKE_PIPELINE_TIME: Duration = Duration::from_secs(2);
const ROUTE_VALIDATOR_STAKE: u32 = 2_000;
pub(super) const ROUTE_VALIDATOR_FEE_SEED_AMOUNT: u32 = 1_000_000;
const ROUTE_XOR_ASSET_NAME: &str = "XOR";

fn route_lane_validator_account(index: usize) -> AccountId {
    let key_pair = checked_localnet_smoke_keypair(
        format!("integration_tests::sumeragi_localnet_smoke::route-validator::{index}")
            .into_bytes(),
        Algorithm::Ed25519,
    );
    AccountId::new(key_pair.public_key().clone())
}
fn route_bootstrap_gas_account_id() -> AccountId {
    let key_pair = universal_route_key_pair();
    AccountId::new(key_pair.public_key().clone())
}
// This funded genesis account has no account-route override and uses lane 0.
pub(super) fn universal_route_key_pair() -> KeyPair {
    checked_localnet_smoke_keypair(
        b"integration_tests::sumeragi_localnet_smoke::route-bootstrap-gas".to_vec(),
        Algorithm::Ed25519,
    )
}
fn checked_localnet_smoke_keypair(seed: Vec<u8>, algorithm: Algorithm) -> KeyPair {
    KeyPair::try_from_seed(seed, algorithm).expect("derive localnet smoke fixture key")
}
fn route_stake_asset_definition_id() -> AssetDefinitionId {
    route_fee_asset_definition_id()
}
pub(super) fn route_fee_asset_definition_id() -> AssetDefinitionId {
    iroha_data_model::parameter::system::SumeragiNposParameters::default().xor_asset_definition_id
}
fn route_multilane_genesis_post_topology_transactions(
    topology: &[PeerId],
    topology_entries: &[GenesisTopologyEntry],
) -> Vec<Vec<InstructionBox>> {
    let stake_asset_id = route_stake_asset_definition_id();
    let fee_asset_id = route_fee_asset_definition_id();
    let gas_account_id = route_bootstrap_gas_account_id();
    let lane_ids = [LaneId::new(0), LaneId::new(1), LaneId::new(2)];
    let mint_amount = ROUTE_VALIDATOR_STAKE
        .saturating_mul(u32::try_from(lane_ids.len()).expect("lane count fits into u32"));
    let mut bootstrap_tx = vec![
        Register::domain(Domain::new(
            DomainId::try_new("nexus", "universal").expect("nexus domain"),
        ))
        .into(),
        Register::domain(Domain::new(
            DomainId::try_new("universal", "universal").expect("universal domain"),
        ))
        .into(),
        Register::account(Account::new(gas_account_id.clone())).into(),
        Register::asset_definition(
            AssetDefinition::new(
                stake_asset_id.clone(),
                ROUTE_XOR_ASSET_NAME.to_owned(),
                iroha_primitives::numeric::NumericSpec::fractional(9),
                iroha_data_model::asset::AssetBalancePolicy::Global,
                None,
            )
            .with_metadata(Metadata::default()),
        )
        .into(),
        Mint::asset_quantity(
            ROUTE_VALIDATOR_FEE_SEED_AMOUNT,
            AssetId::new(fee_asset_id.clone(), ALICE_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            ROUTE_VALIDATOR_FEE_SEED_AMOUNT,
            AssetId::new(fee_asset_id.clone(), BOB_ID.clone()),
        )
        .into(),
        Mint::asset_quantity(
            ROUTE_VALIDATOR_FEE_SEED_AMOUNT,
            AssetId::new(fee_asset_id.clone(), gas_account_id.clone()),
        )
        .into(),
    ];
    let mut validator_tx = Vec::with_capacity(topology.len() * 2);
    bootstrap_tx.extend(genesis_participant_committee_key_instructions(
        topology_entries,
        topology,
    ));
    // Physical policy lanes do not create native ordering instances. Sign their
    // exact committees and account routes in the original genesis as well.
    let mut native_policy = SumeragiLanePolicy::for_chain(
        SumeragiParameters {
            block_cadence_ms: std::num::NonZeroU64::new(
                u64::try_from(SMOKE_PIPELINE_TIME.as_millis()).unwrap(),
            )
            .unwrap(),
            ..SumeragiParameters::default()
        },
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    let mut committee = topology_entries
        .iter()
        .map(|entry| SumeragiLaneMember {
            peer: entry.peer.clone(),
            pop: entry
                .pop_bytes()
                .expect("valid fixture PoP")
                .expect("fixture PoP"),
        })
        .collect::<Vec<_>>();
    committee.sort_by(|left, right| left.peer.cmp(&right.peer));
    for (id, account) in [(1_u32, &*ALICE_ID), (2_u32, &*BOB_ID)] {
        native_policy.fixed.push(SumeragiFixedLane {
            lane: LaneId::new(id),
            dataspace: DataSpaceId::new(u64::from(id)),
            committee: committee.clone(),
        });
        native_policy.routes.push(SumeragiLaneRoute {
            lane: LaneId::new(id),
            account: Some(account.to_string()),
            instruction: None,
        });
    }
    native_policy
        .validate()
        .expect("canonical native fixture lanes");
    bootstrap_tx
        .push(SetParameter::new(Parameter::Custom(native_policy.into_custom_parameter())).into());
    for (index, peer_id) in topology.iter().enumerate() {
        let validator_id = route_lane_validator_account(index);
        bootstrap_tx.push(Register::account(Account::new(validator_id.clone())).into());
        bootstrap_tx.push(
            Mint::asset_quantity(
                mint_amount,
                AssetId::new(stake_asset_id.clone(), validator_id.clone()),
            )
            .into(),
        );
        bootstrap_tx.push(
            Mint::asset_quantity(
                ROUTE_VALIDATOR_FEE_SEED_AMOUNT,
                AssetId::new(fee_asset_id.clone(), validator_id.clone()),
            )
            .into(),
        );
        for lane_id in lane_ids {
            validator_tx.push(
                RegisterPublicLaneValidator::new(
                    lane_id,
                    validator_id.clone(),
                    peer_id.clone(),
                    validator_id.clone(),
                    Quantity::from(ROUTE_VALIDATOR_STAKE),
                    Metadata::default(),
                    iroha_data_model::nexus::PublicLaneMonetaryPlanV1::genesis_registration(
                        AssetId::new(stake_asset_id.clone(), validator_id.clone()),
                        AssetId::new(stake_asset_id.clone(), gas_account_id.clone()),
                        Quantity::from(ROUTE_VALIDATOR_STAKE),
                    ),
                )
                .into(),
            );
            validator_tx
                .push(ActivatePublicLaneValidator::new(lane_id, validator_id.clone()).into());
        }
    }
    vec![bootstrap_tx, validator_tx]
}
pub(super) fn network_builder() -> NetworkBuilder {
    network_builder_with_genesis_transactions(Vec::new())
}

/// Include fixture instructions in the custom genesis that every peer executes.
pub(super) fn network_builder_with_genesis_transactions(
    extra_transactions: Vec<Vec<InstructionBox>>,
) -> NetworkBuilder {
    let mut lane_universal = Table::new();
    lane_universal.insert("index".into(), TomlValue::Integer(0));
    lane_universal.insert(
        "alias".into(),
        TomlValue::String("lane-universal".to_owned()),
    );
    lane_universal.insert(
        "dataspace".into(),
        TomlValue::String("universal".to_owned()),
    );
    lane_universal.insert("visibility".into(), TomlValue::String("public".to_owned()));
    lane_universal.insert("metadata".into(), TomlValue::Table(Table::new()));
    let mut lane_alice = Table::new();
    lane_alice.insert("index".into(), TomlValue::Integer(1));
    lane_alice.insert("alias".into(), TomlValue::String("lane-alice".to_owned()));
    lane_alice.insert("dataspace".into(), TomlValue::String("ds1".to_owned()));
    lane_alice.insert("visibility".into(), TomlValue::String("public".to_owned()));
    lane_alice.insert("metadata".into(), TomlValue::Table(Table::new()));
    let mut lane_bob = Table::new();
    lane_bob.insert("index".into(), TomlValue::Integer(2));
    lane_bob.insert("alias".into(), TomlValue::String("lane-bob".to_owned()));
    lane_bob.insert("dataspace".into(), TomlValue::String("ds2".to_owned()));
    lane_bob.insert("visibility".into(), TomlValue::String("public".to_owned()));
    lane_bob.insert("metadata".into(), TomlValue::Table(Table::new()));
    let mut ds_universal = Table::new();
    ds_universal.insert("alias".into(), TomlValue::String("universal".to_owned()));
    ds_universal.insert("id".into(), TomlValue::Integer(0));
    ds_universal.insert(
        "description".into(),
        TomlValue::String("default dataspace".to_owned()),
    );
    ds_universal.insert("fault_tolerance".into(), TomlValue::Integer(1));
    let mut ds1 = Table::new();
    ds1.insert("alias".into(), TomlValue::String("ds1".to_owned()));
    ds1.insert("id".into(), TomlValue::Integer(1));
    ds1.insert(
        "manifest_hash".into(),
        TomlValue::String(
            "0100000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
    );
    ds1.insert(
        "description".into(),
        TomlValue::String("alice route dataspace".to_owned()),
    );
    ds1.insert("fault_tolerance".into(), TomlValue::Integer(1));
    let mut ds2 = Table::new();
    ds2.insert("alias".into(), TomlValue::String("ds2".to_owned()));
    ds2.insert("id".into(), TomlValue::Integer(2));
    ds2.insert(
        "manifest_hash".into(),
        TomlValue::String(
            "0200000000000000000000000000000000000000000000000000000000000000".to_owned(),
        ),
    );
    ds2.insert(
        "description".into(),
        TomlValue::String("bob route dataspace".to_owned()),
    );
    ds2.insert("fault_tolerance".into(), TomlValue::Integer(1));
    let mut matcher_alice = Table::new();
    matcher_alice.insert("account".into(), TomlValue::String(ALICE_ID.to_string()));
    let mut rule_alice = Table::new();
    rule_alice.insert("lane".into(), TomlValue::Integer(1));
    rule_alice.insert("dataspace".into(), TomlValue::String("ds1".to_owned()));
    rule_alice.insert("matcher".into(), TomlValue::Table(matcher_alice));
    let mut matcher_bob = Table::new();
    matcher_bob.insert("account".into(), TomlValue::String(BOB_ID.to_string()));
    let mut rule_bob = Table::new();
    rule_bob.insert("lane".into(), TomlValue::Integer(2));
    rule_bob.insert("dataspace".into(), TomlValue::String("ds2".to_owned()));
    rule_bob.insert("matcher".into(), TomlValue::Table(matcher_bob));
    let mut policy = Table::new();
    policy.insert("default_lane".into(), TomlValue::Integer(0));
    policy.insert(
        "default_dataspace".into(),
        TomlValue::String("universal".to_owned()),
    );
    policy.insert(
        "rules".into(),
        TomlValue::Array(vec![
            TomlValue::Table(rule_alice),
            TomlValue::Table(rule_bob),
        ]),
    );
    let gas_account_str = route_bootstrap_gas_account_id()
        .canonical_i105()
        .expect("canonical I105 bootstrap gas account literal");
    let stake_asset_id_literal = route_stake_asset_definition_id().to_string();
    let fee_asset_id_literal = route_fee_asset_definition_id().to_string();
    let mut npos = SumeragiNposParameters::default();
    npos.max_validators = 4;
    npos.epoch_length_blocks = std::num::NonZeroU64::new(3_600).unwrap();
    NetworkBuilder::new()
        .with_peers(4)
        .with_auto_populated_trusted_peers()
        .without_npos_genesis_bootstrap()
        .with_genesis_block(move |topology, topology_entries| {
            let post_topology = route_multilane_genesis_post_topology_transactions(
                topology.as_ref(),
                &topology_entries,
            );
            // The builder authenticates this source, then binds DA policies from
            // the complete lane config before signing the final genesis.
            unexecuted_genesis_factory_with_post_topology(
                extra_transactions.clone(),
                post_topology,
                topology,
                topology_entries,
            )
        })
        .with_block_cadence(SMOKE_PIPELINE_TIME)
        .with_npos_consensus()
        .with_genesis_instruction(SetParameter::new(Parameter::Custom(
            npos.into_custom_parameter(),
        )))
        .with_config_layer(move |layer| {
            layer
                .write(["nexus", "lane_count"], 3_i64)
                .write(
                    ["nexus", "lane_catalog"],
                    TomlValue::Array(vec![
                        TomlValue::Table(lane_universal.clone()),
                        TomlValue::Table(lane_alice.clone()),
                        TomlValue::Table(lane_bob.clone()),
                    ]),
                )
                .write(
                    ["nexus", "dataspace_catalog"],
                    TomlValue::Array(vec![
                        TomlValue::Table(ds_universal.clone()),
                        TomlValue::Table(ds1.clone()),
                        TomlValue::Table(ds2.clone()),
                    ]),
                )
                .write(
                    ["nexus", "routing_policy"],
                    TomlValue::Table(policy.clone()),
                )
                .write(
                    ["nexus", "fees", "fee_asset_id"],
                    fee_asset_id_literal.clone(),
                )
                .write(
                    ["nexus", "staking", "stake_asset_id"],
                    stake_asset_id_literal.clone(),
                )
                .write(
                    ["nexus", "staking", "stake_escrow_account_id"],
                    gas_account_str.clone(),
                )
                .write(
                    ["nexus", "staking", "slash_sink_account_id"],
                    gas_account_str.clone(),
                )
                .write(
                    ["nexus", "staking", "restricted_validator_mode"],
                    "stake_elected",
                )
                .write(
                    ["nexus", "staking", "public_validator_mode"],
                    "stake_elected",
                )
                .write(["nexus", "staking", "max_validators"], 4_i64);
        })
}

#[test]
fn multiroute_genesis_authenticates_all_configured_lane_policies() {
    iroha_test_network::init_instruction_registry();
    let network = network_builder().build();
    let genesis = network.genesis();
    let authority = AccountId::new(
        iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR
            .public_key()
            .clone(),
    );
    iroha_core::block::check_genesis_block(&genesis.0, &authority)
        .expect("complete multilane genesis signature and results authenticate");
    let policies = genesis
        .0
        .da_proof_policies()
        .expect("config-derived DA policies");
    assert_eq!(policies.policies().len(), 3);
    assert_eq!(
        genesis.0.header().da_proof_policies_hash(),
        Some(iroha_crypto::HashOf::new(policies))
    );
    let mut native_policies = Vec::new();
    for input in genesis.0.network_entrypoints() {
        let iroha_data_model::transaction::TransactionEntrypoint::External(tx) = input else {
            panic!("genesis must contain signed transactions");
        };
        let iroha_data_model::transaction::Executable::Instructions(instructions) =
            tx.instructions()
        else {
            continue;
        };
        for instruction in instructions.iter() {
            let Some(parameter) = instruction.as_any().downcast_ref::<SetParameter>() else {
                continue;
            };
            let Parameter::Custom(custom) = parameter.inner() else {
                continue;
            };
            if let Some(policy) = SumeragiLanePolicy::from_custom_parameter(custom) {
                native_policies.push(policy.expect("canonical signed native policy"));
            }
        }
    }
    assert_eq!(
        native_policies.len(),
        1,
        "exactly one signed native lane policy"
    );
    let policy = &native_policies[0];
    iroha_core::sumeragi::lanes::step::validate_policy(policy).unwrap();
    let epoch = iroha_data_model::sumeragi_finality::authenticated_genesis(&genesis.0)
        .map(|genesis| genesis.into_parts().0)
        .unwrap();
    assert_eq!(policy.da_layout, epoch.da_layout);
    assert_eq!(policy.fixed.len(), 2);
    assert_eq!(policy.routes.len(), 2);
    for (index, account) in [&*ALICE_ID, &*BOB_ID].into_iter().enumerate() {
        let lane = &policy.fixed[index];
        assert_eq!(lane.lane, LaneId::new(u32::try_from(index + 1).unwrap()));
        assert_eq!(
            lane.dataspace,
            DataSpaceId::new(u64::try_from(index + 1).unwrap())
        );
        assert_eq!(lane.committee.len(), 4);
        for (member, original) in lane.committee.iter().zip(&epoch.committee) {
            assert_eq!(member.peer, original.validator);
            assert_eq!(
                member.pop.as_slice(),
                original.proof_of_possession.as_slice()
            );
        }
        assert_eq!(
            policy.routes[index],
            SumeragiLaneRoute {
                lane: lane.lane,
                account: Some(account.to_string()),
                instruction: None,
            }
        );
    }
}
