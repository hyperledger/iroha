// Exact private-root home admission, original route custody and confined balance controls.

use super::*;
use crate::{
    query::store::LiveQueryStore,
    state::{State, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    account::{Account, AccountAddress},
    asset::{AssetBalanceScope, AssetDefinition, AssetId},
    block::{
        BlockHeader,
        consensus::{PrivateRootFeePolicy, SumeragiRootScope},
    },
    domain::Domain,
    isi::{Mint, Register, RegisterDataspaceAssetDefinition},
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
    parameter::Parameter,
    sns::{NameControllerV1, NameRecordV1},
};
use iroha_model_base::{metadata::Metadata, topology::LaneId};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use std::num::NonZeroU32;

const ALIAS: &str = "private-home";

fn home() -> DataSpaceId {
    crate::sns::dataspace_id_for_sns_alias(ALIAS).unwrap()
}

fn scope(home: DataSpaceId) -> SumeragiRootScope {
    SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"independent private-home parent",
        ))),
        dataspace_id: home,
    }
}

fn geometry(home: DataSpaceId) -> iroha_config::parameters::actual::Nexus {
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: home,
        alias: ALIAS.into(),
        ..DataSpaceMetadata::default()
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.lane_catalog = LaneCatalog::new(
        NonZeroU32::MIN,
        vec![LaneConfig {
            dataspace_id: home,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.routing_policy.default_dataspace = home;
    nexus
}

fn definition() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", ALIAS).unwrap(),
        "unit".parse().unwrap(),
    )
}

fn domain_definition() -> AssetDefinitionId {
    AssetDefinitionId::derive_from_components(
        DomainId::try_new("fees", ALIAS).unwrap(),
        "domainunit".parse().unwrap(),
    )
}

fn seed_owner(world: &mut World) {
    let selector = crate::sns::selector_for_dataspace_alias(ALIAS).unwrap();
    let address = AccountAddress::from_account_id(&ALICE_ID).unwrap();
    let record = NameRecordV1::new(
        selector.clone(),
        ALICE_ID.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        Metadata::default(),
    );
    world.smart_contract_state_mut_for_testing().insert(
        crate::sns::record_storage_key(&selector),
        norito::codec::Encode::encode(&record),
    );
}

fn original_private_chain() -> CertifiedTestChain {
    let home = home();
    let id = definition();
    let owning_domain = DomainId::try_new("fees", ALIAS).unwrap();
    let mut world = World::with(
        [Domain::new(owning_domain.clone()).build(&ALICE_ID)],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        [],
    );
    seed_owner(&mut world);
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_key = ALICE_KEYPAIR.clone();
    config.root_scope = scope(home);
    let mut nexus = geometry(home);
    nexus.fees.fee_asset_id = domain_definition().canonical_address();
    config.nexus = Some(nexus);
    config.genesis_parameters.push(Parameter::Custom(
        PrivateRootFeePolicy {
            asset_definition_id: domain_definition(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    config.genesis_instructions = vec![
        RegisterDataspaceAssetDefinition::new(
            home,
            AssetDefinition::numeric(
                id.clone(),
                "Private unit",
                AssetBalancePolicy::DataspaceRestricted,
                None,
            ),
        )
        .unwrap()
        .into(),
        Mint::asset_quantity(
            10_u32,
            AssetId::with_scope(id, ALICE_ID.clone(), AssetBalanceScope::Dataspace(home)),
        )
        .into(),
        Register::asset_definition(AssetDefinition::numeric(
            domain_definition(),
            "Private domain unit",
            AssetBalancePolicy::DataspaceRestricted,
            Some(owning_domain),
        ))
        .into(),
        Mint::asset_quantity(
            20_u32,
            AssetId::with_scope(
                domain_definition(),
                ALICE_ID.clone(),
                AssetBalanceScope::Dataspace(home),
            ),
        )
        .into(),
    ];
    CertifiedTestChain::start(config).expect("original restricted private genesis executes")
}

fn header(chain: &CertifiedTestChain) -> BlockHeader {
    BlockHeader::new(
        2_u64.try_into().unwrap(),
        Some(chain.genesis().hash()),
        None,
        1_001,
        0,
    )
}

fn bind(tx: &mut StateTransaction<'_, '_>) {
    tx.current_dataspace_id = Some(home());
    tx.world.current_dataspace_id = Some(home());
}

#[test]
fn original_private_root_registers_confined_home_and_never_creates_global_bucket() {
    let chain = original_private_chain();
    let view = chain.state().view();
    let id = definition();
    let global = AssetId::new(id.clone(), ALICE_ID.clone());
    let confined = AssetId::with_scope(
        id.clone(),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(home()),
    );
    assert_eq!(
        view.world().asset_definition_dataspace(&id).unwrap(),
        Some(home())
    );
    assert_eq!(
        view.world().assets().get(&confined).unwrap().as_ref(),
        &iroha_primitives::numeric::Quantity::from(10_u32)
    );
    assert!(
        view.world().assets().get(&global).is_none(),
        "private registration must not create a Global balance bucket"
    );
    let domain_bucket = AssetId::with_scope(
        domain_definition(),
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(home()),
    );
    assert_eq!(
        view.world().assets().get(&domain_bucket).unwrap().as_ref(),
        &iroha_primitives::numeric::Quantity::from(20_u32)
    );
    assert!(
        view.world()
            .assets()
            .get(&AssetId::new(domain_definition(), ALICE_ID.clone()))
            .is_none(),
        "private domain registration must not create a Global balance bucket"
    );
    drop(view);
    let mut block = chain.state().block(header(&chain));
    let mut tx = block.transaction_for_callback_testing();
    bind(&mut tx);
    assert_eq!(
        tx.world
            .resolve_asset_id_for_scope_hint(&global, None)
            .unwrap(),
        confined
    );
    let foreign = AssetId::with_scope(
        id,
        ALICE_ID.clone(),
        AssetBalanceScope::Dataspace(DataSpaceId::new(17)),
    );
    assert!(
        tx.world
            .resolve_asset_id_for_scope_hint(&foreign, None)
            .is_err()
    );
    assert!(tx.world.assets().get(&global).is_none());
}

#[test]
fn restricted_home_requires_original_private_root_not_global_missing_or_foreign_scope() {
    for root in [
        Some(SumeragiRootScope::Global),
        None,
        Some(scope(DataSpaceId::new(17))),
    ] {
        // Adversarial component metadata is deliberately insufficient private-root authority.
        // All route/physical guards are valid so omission of only the source guard is causal.
        let world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
        if let Some(root) = root {
            let mut parameters = world.parameters.block();
            parameters.set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
                root,
            ));
            parameters.commit();
        }
        let state = State::new_with_nexus_for_testing(
            world,
            geometry(home()),
            LiveQueryStore::start_test(),
        );
        let mut block = state.block(BlockHeader::new(
            2_u64.try_into().unwrap(),
            None,
            None,
            1_000,
            0,
        ));
        let mut tx = block.transaction_for_callback_testing();
        bind(&mut tx);
        let result = ensure_home_admissible(
            &mut tx,
            &definition(),
            AssetBalancePolicy::DataspaceRestricted,
            home(),
        );
        assert!(
            result.is_err(),
            "restricted home requires the original authenticated private root: {root:?}"
        );
        assert!(tx.execution_deferral().is_none());
        assert!(tx.world.asset_definitions().get(&definition()).is_none());
    }
    let state = State::new_with_nexus_for_testing(
        crate::sumeragi::lanes::routing::test_support::world(scope(home())),
        geometry(home()),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(BlockHeader::new(
        1_u64.try_into().unwrap(),
        None,
        None,
        1_000,
        0,
    ));
    let mut tx = block.transaction_for_callback_testing();
    bind(&mut tx);
    assert!(
        ensure_home_admissible(
            &mut tx,
            &definition(),
            AssetBalancePolicy::DataspaceRestricted,
            home()
        )
        .is_err(),
        "restricted home requires the original authenticated private root even at a genesis-shaped header"
    );
}

#[test]
fn original_private_home_requires_both_exact_captured_routes() {
    let chain = original_private_chain();
    let foreign = Some(DataSpaceId::new(17));
    for (state_route, world_route) in [
        (None, None),
        (foreign, foreign),
        (Some(home()), foreign),
        (foreign, Some(home())),
        (None, Some(home())),
        (Some(home()), None),
    ] {
        let mut block = chain.state().block(header(&chain));
        let mut tx = block.transaction_for_callback_testing();
        tx.current_dataspace_id = state_route;
        tx.world.current_dataspace_id = world_route;
        assert!(
            ensure_home_admissible(
                &mut tx,
                &definition(),
                AssetBalancePolicy::DataspaceRestricted,
                home()
            )
            .is_err(),
            "private home admission must retain both original route coordinates: {state_route:?}/{world_route:?}"
        );
        assert!(tx.execution_deferral().is_none());
        assert!(
            tx.world
                .assets()
                .get(&AssetId::new(definition(), ALICE_ID.clone()))
                .is_none()
        );
    }
}

#[test]
fn original_private_home_requires_canonical_single_root_geometry() {
    let chain = original_private_chain();
    for variant in 0..8 {
        let mut block = chain.state().block(header(&chain));
        let mut tx = block.transaction_for_callback_testing();
        bind(&mut tx);
        match variant {
            0 => tx.nexus.configured_lane_catalog = LaneCatalog::default(),
            1 => tx.nexus.configured_dataspace_catalog = DataSpaceCatalog::default(),
            2 => tx.nexus.lane_config = iroha_config::parameters::actual::LaneConfig::default(),
            3 => tx.nexus.routing_policy.default_dataspace = DataSpaceId::new(17),
            4 => tx.nexus.routing_policy.default_lane = LaneId::new(1),
            5 => tx.nexus.autoscale.enabled = true,
            6 => tx.nexus.autoscale.last_transition_height = 1,
            7 => tx.world.dataspace_catalog = DataSpaceCatalog::default(),
            _ => unreachable!(),
        }
        assert!(
            ensure_home_admissible(
                &mut tx,
                &definition(),
                AssetBalancePolicy::DataspaceRestricted,
                home()
            )
            .is_err(),
            "private home admission must validate the exact original physical geometry: variant {variant}"
        );
        assert!(tx.execution_deferral().is_none());
    }
}

#[test]
fn original_private_home_root_decode_refusal_remains_local_and_global_policy_stays_refused() {
    let chain = original_private_chain();
    let budget = chain.state().ivm_execution_budget();
    let original_charge = budget.reserved_bytes();
    let context = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        0,
        64,
    ));
    let mut block = chain.state().block(header(&chain));
    {
        let mut tx = block.transaction_for_callback_testing();
        bind(&mut tx);
        for _ in 0..2 {
            assert!(
                context
                    .with(|| ensure_home_admissible(
                        &mut tx,
                        &definition(),
                        AssetBalancePolicy::DataspaceRestricted,
                        home()
                    ))
                    .is_err()
            );
            assert_eq!(
                tx.execution_deferral().unwrap().reason(),
                ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
                "private home admission must retain the original local root decoder refusal"
            );
            assert_eq!(
                tx.require_storage_admission(),
                Err(crate::state::StateStorageAdmissionError::RootScopeDecode(
                    crate::state::RootScopeDecodeRefusal::Budget
                ))
            );

            assert!(
                tx.world
                    .assets()
                    .get(&AssetId::new(definition(), ALICE_ID.clone()))
                    .is_none()
            );
        }
    }
    assert_eq!(
        block.require_storage_admission(),
        Err(crate::state::StateStorageAdmissionError::RootScopeDecode(
            crate::state::RootScopeDecodeRefusal::Budget
        ))
    );
    drop(block);
    // The failed overlay cannot publish or clear the refusal. A separate pristine attempt
    // reads the same committed source with its normal inherited allowance.
    let mut block = chain.state().block(header(&chain));
    let mut retry = block.transaction_for_callback_testing();
    bind(&mut retry);
    ensure_home_admissible(
        &mut retry,
        &definition(),
        AssetBalancePolicy::DataspaceRestricted,
        home(),
    )
    .unwrap();
    assert!(retry.execution_deferral().is_none());
    let global_error = context
        .with(|| {
            ensure_home_admissible(
                &mut retry,
                &definition(),
                AssetBalancePolicy::Global,
                home(),
            )
        })
        .unwrap_err();
    assert!(
        global_error
            .to_string()
            .contains("cannot be registered in restricted dataspace")
    );
    assert!(
        retry.execution_deferral().is_none(),
        "global policy rejection precedes root decoding"
    );
    drop(retry);
    drop(block);
    assert_eq!(budget.reserved_bytes(), original_charge);
}
