//! Genuine native successor authority allocations must retain the source's original pool.
//!
//! These tests use the unchanged production constructor before and after repair. The
//! signed genesis and two actual certified successor blocks are produced by the real
//! execution/schedule/QC fixture; no decoded DTO or World roster grants authority.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn chain(root_scope: SumeragiRootScope) -> CertifiedTestChain {
    let mut config = match root_scope {
        SumeragiRootScope::Global => TestChainConfig::new(World::new(), 1_000),
        SumeragiRootScope::Dataspace { dataspace_id, .. } => private_config(dataspace_id),
    };
    config.root_scope = root_scope;
    let mut chain = CertifiedTestChain::start(config).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}

fn private_config(dataspace_id: iroha_model_base::topology::DataSpaceId) -> TestChainConfig {
    use iroha_data_model::{
        Registrable,
        account::{Account, AccountId},
        asset::{
            Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId,
            AssetId,
        },
        block::consensus::RootFeePolicy,
        domain::Domain,
        nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
        parameter::Parameter,
    };

    let clock = iroha_crypto::KeyPair::from_seed(vec![0xCC; 32], iroha_crypto::Algorithm::Ed25519);
    let owner = AccountId::new(clock.public_key().clone());
    let domain =
        iroha_model_base::domain::DomainId::parse_fully_qualified("app.parent-service-test")
            .unwrap();
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "gas".parse().unwrap());
    let mut definition = AssetDefinition::numeric(
        asset.clone(),
        "Private gas",
        AssetBalancePolicy::DataspaceRestricted,
        Some(domain.clone()),
    )
    .build(&owner);
    definition.total_quantity = 1_000_000_u32.into();
    let world = World::with_assets(
        [Domain::new(domain).build(&owner)],
        [Account::new(owner.clone()).build(&owner)],
        [definition],
        [Asset::new(
            AssetId::with_scope(
                asset.clone(),
                owner,
                AssetBalanceScope::Dataspace(dataspace_id),
            ),
            1_000_000_u32,
        )],
        [],
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_parameters.push(Parameter::Custom(
        RootFeePolicy {
            fee_asset_id: asset.clone(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
            ..iroha_config::parameters::defaults::nexus::fees::genesis_policy()
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    nexus.fees.fee_asset_id = asset.clone();
    nexus.lane_catalog = LaneCatalog::new(
        std::num::NonZeroU32::MIN,
        vec![LaneConfig {
            dataspace_id,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: dataspace_id,
        alias: "parent-service-test".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = dataspace_id;
    config.nexus = Some(nexus);
    config
}

#[test]
fn original_parent_service_context_retains_signed_dataspace_scope() {
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"parent-service parent network",
        ))),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(7),
    };
    let chain = chain(scope);
    let view = chain.state().view();
    let mut preparation = ParentServicePreparation::default();
    preparation.prepare(&view, 3).unwrap();
    let (predecessor, parent, _, _, context) = preparation.inputs();
    assert_eq!(context.instance, chain.instance());
    assert_eq!(context.root_scope, scope);
    assert_eq!((predecessor.height(), parent.height()), (2, 3));
    let input_parent = parent.block().clone();
    preparation
        .prepare_producer_copy(&view, &input_parent)
        .unwrap();
    let reader = CertifiedChain::new_for_parent_service(&view).unwrap();
    assert_eq!(
        preparation.proposal_original(&view, &input_parent).unwrap(),
        reader
            .parent_service_proposal_original(&input_parent)
            .unwrap()
    );
}

#[test]
fn original_native_successor_authority_retains_its_actual_source_pool() {
    // Pin before fixture publication so its retired State generations cannot be
    // refunded by another test while this original pool is measured or exhausted.
    let epoch = crossbeam_epoch::pin();
    let chain = chain(SumeragiRootScope::Global);
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let original = (
        parent.id(),
        current.id(),
        parent.block().clone(),
        current.block().clone(),
    );
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let authority = reader
        .executed_successor_authority(&parent, &current)
        .unwrap();
    let retained = budget.reserved_bytes();
    eprintln!("original authority backing: before={baseline}, live={retained}");
    assert!(
        retained > baseline,
        "native successor authority owns its heap graph in the original source pool"
    );
    assert_eq!((parent.id(), current.id()), (original.0, original.1));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        parent.block(),
        &original.2
    ));
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        current.block(),
        &original.3
    ));
    drop(authority);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "the final authority reader releases exactly its retired graph"
    );
    let certified = reader
        .verify_executed_successor(&parent, current.clone())
        .unwrap();
    assert_eq!(certified.id(), current.id());
    assert_eq!(certified.verification(), QcVerification::Verified);
    assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
        certified.block(),
        current.block()
    ));
    assert_eq!(budget.reserved_bytes(), baseline);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _authority = reader
            .executed_successor_authority(&parent, &current)
            .unwrap();
        assert!(budget.reserved_bytes() > baseline);
        panic!("cancel original native authority reader");
    }));
    assert!(unwind.is_err());
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(epoch);
}

#[test]
fn original_native_authority_capacity_refusal_waits_for_its_own_release_then_retries() {
    use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
    use std::{
        future::Future as _,
        pin::Pin,
        task::{Context, Waker},
    };

    // Pin before fixture publication so its retired State generations cannot be
    // refunded by another test while this original pool is measured or exhausted.
    let epoch = crossbeam_epoch::pin();
    let chain = chain(SumeragiRootScope::Global);
    let parent = chain.committed(2);
    let current = chain.committed(3);
    let original = (parent.id(), current.id());
    let view = chain.state().view();
    let reader = CertifiedChain::new(&view).unwrap();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let waiter_bytes = ReleaseRegistration::allocation_layout().size();
    let mut reservation = budget.try_reserve_bytes(waiter_bytes).unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut reservation).unwrap();
    drop(reservation);
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let refused = reader.executed_successor_authority(&parent, &current);
    let Err(VerificationReadError::Deferred(local)) = refused else {
        panic!(
            "native authority must refuse the original full pool before allocating its owned graph"
        )
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = local.allocation_refusal() else {
        panic!("native authority capacity retains the original allocation release owner")
    };
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut task = Context::from_waker(Waker::noop());
    assert!(
        Pin::new(&mut wait).poll(&mut task).is_pending(),
        "refusal has no candidate allocation to refund and wake itself"
    );
    let unrelated = AllocationBudget::new(19);
    drop(unrelated.try_reserve_bytes(19).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut task).is_pending());
    // Original source rejection keeps its precedence over the local pool limit.
    assert!(matches!(
        reader.executed_successor_authority(&current, &current),
        Err(VerificationReadError::Source(
            ChainReadError::Discontinuous { height: 3 }
        ))
    ));
    drop(blocker);
    assert!(Pin::new(&mut wait).poll(&mut task).is_ready());
    drop(wait);
    let authority = reader
        .executed_successor_authority(&parent, &current)
        .unwrap();
    assert!(budget.reserved_bytes() > baseline + waiter_bytes);
    assert_eq!((parent.id(), current.id()), original);
    drop(authority);
    let certified = reader
        .verify_executed_successor(&parent, current.clone())
        .unwrap();
    assert_eq!(certified.id(), current.id());
    assert_eq!(certified.verification(), QcVerification::Verified);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(epoch);
}
