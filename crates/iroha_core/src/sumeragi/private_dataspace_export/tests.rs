//! Compact exports from genuinely executed signed private genesis and native BLS certificates.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, Signers, TestChainConfig},
};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    NetworkId,
    nexus::{DataSpaceCatalog, DataSpaceMetadata, LaneCatalog, LaneConfig, LaneVisibility},
    private_dataspace::{PrivateDataspaceAnchorOutcome, PrivateDataspaceAnchorState},
};
use iroha_model_base::topology::DataSpaceId;
use std::num::NonZeroU32;

fn private_chain() -> CertifiedTestChain {
    let ds = DataSpaceId::new(u64::MAX - 15);
    use iroha_data_model::{
        Registrable,
        account::{Account, AccountId},
        asset::{
            Asset, AssetBalancePolicy, AssetBalanceScope, AssetDefinition, AssetDefinitionId,
            AssetId,
        },
        block::consensus::PrivateRootFeePolicy,
        domain::Domain,
        parameter::Parameter,
    };
    let clock = iroha_crypto::KeyPair::from_seed(vec![0xCC; 32], iroha_crypto::Algorithm::Ed25519);
    let owner = AccountId::new(clock.public_key().clone());
    let domain =
        iroha_model_base::domain::DomainId::parse_fully_qualified("app.private-export-test")
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
            AssetId::with_scope(asset.clone(), owner, AssetBalanceScope::Dataspace(ds)),
            1_000_000_u32,
        )],
        [],
    );
    let mut config = TestChainConfig::new(world, 1_000);
    config.genesis_parameters.push(Parameter::Custom(
        PrivateRootFeePolicy {
            asset_definition_id: asset.clone(),
            base_fee: 1_u32.into(),
            per_byte_fee: 0_u32.into(),
            per_instruction_fee: 1_u32.into(),
            per_gas_unit_fee: 1_u32.into(),
        }
        .into_custom_parameter()
        .unwrap(),
    ));
    config.root_scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(
            b"independent public parent",
        ))),
        dataspace_id: ds,
    };
    let mut nexus = iroha_config::parameters::actual::Nexus::default();
    // The signed private genesis policy also seeds SNS pricing in this same fee asset.
    nexus.fees.fee_asset_id = asset.to_string();
    nexus.lane_catalog = LaneCatalog::new(
        NonZeroU32::new(1).unwrap(),
        vec![LaneConfig {
            dataspace_id: ds,
            visibility: LaneVisibility::Restricted,
            ..LaneConfig::default()
        }],
    )
    .unwrap();
    nexus.configured_lane_catalog = nexus.lane_catalog.clone();
    nexus.lane_config =
        iroha_config::parameters::actual::LaneConfig::from_catalog(&nexus.lane_catalog);
    nexus.dataspace_catalog = DataSpaceCatalog::new(vec![DataSpaceMetadata {
        id: ds,
        alias: "private-export-test".into(),
        description: None,
        fault_tolerance: 1,
    }])
    .unwrap();
    nexus.configured_dataspace_catalog = nexus.dataspace_catalog.clone();
    nexus.routing_policy.default_dataspace = ds;
    config.nexus = Some(nexus);
    CertifiedTestChain::start(config).expect("original signed private root executes")
}

#[test]
fn terminal_result_scope_comes_from_the_signed_private_root() {
    let mut chain = private_chain();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    let view = chain.state().view();
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        &view.execution_budget(),
    )
    .unwrap();
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let terminal = context.with(|| reader.certified_terminal_amx(3)).unwrap();
    let scope = iroha_data_model::sumeragi_finality::CertifiedResultScope::from_root_scope(
        SumeragiRootScope::Dataspace {
            parent_network_id: NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
                Hash::new(b"independent public parent"),
            )),
            dataspace_id: DataSpaceId::new(u64::MAX - 15),
        },
    );
    assert_eq!(terminal.committed().result_scope(), scope);
    assert_eq!(terminal.committed().result(), chain.committed(3).result());
}

#[test]
fn compact_export_authenticates_original_genesis_and_successor_without_private_bodies() {
    let mut chain = private_chain();
    let registered = registration(&chain.state().view()).unwrap();
    assert_eq!(
        registered.genesis_cursor.result,
        chain.committed(1).result().0
    );
    assert_eq!(registered.child_network_id, chain.network_id());
    assert_eq!(registered.instance, chain.instance().0);
    assert_eq!(
        registered.scope.dataspace_id(),
        DataSpaceId::new(u64::MAX - 15)
    );
    assert!(anchor(&chain.state().view(), 0).is_err());
    assert!(anchor(&chain.state().view(), 1).is_err());
    assert!(anchor(&chain.state().view(), 2).is_err());
    chain.commit_at(1_100, vec![]);
    let exported = anchor(&chain.state().view(), 2).unwrap();
    let mut parent = PrivateDataspaceAnchorState::from_authorized_registration(registered).unwrap();
    assert_eq!(
        parent.apply(&exported).unwrap(),
        PrivateDataspaceAnchorOutcome::Advanced
    );
    assert_eq!(parent.cursor().result, chain.committed(2).result().0);
    assert_eq!(
        parent.apply(&exported).unwrap(),
        PrivateDataspaceAnchorOutcome::AlreadyAnchored
    );
    let json = norito::json::to_value(&exported).unwrap();
    let fields = json.as_object().unwrap();
    assert_eq!(fields.len(), 4);
    assert!(fields.contains_key("certificate"));
    assert!(!fields.contains_key("block_wire"));
}

#[test]
fn compact_export_rejects_global_roots_and_oversized_native_quorums() {
    let global = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    assert!(registration(&global.state().view()).is_err());
    assert!(anchor(&global.state().view(), 2).is_err());
    let mut private = private_chain();
    let proposal = private.proposal(Some(1_100), vec![]);
    let refusal = private
        .begin_proposal(proposal, Default::default())
        .unwrap()
        .publish(Signers::All)
        .unwrap_err();
    assert!(refusal.contains("TooManySigners"), "{refusal}");
    assert_eq!(
        private.height(),
        1,
        "invalid certificate never publishes native custody"
    );
    assert!(matches!(
        anchor(&private.state().view(), 2),
        Err(ExportError::Custody(_))
    ));
}

#[test]
fn original_private_export_refusal_preserves_read_owner_and_exact_custody_retry() {
    let mut chain = private_chain();
    chain.commit_at(1_100, vec![]);
    let view = chain.state().view();
    let registered = registration(&view).unwrap();
    let anchored = anchor(&view, 2).unwrap();
    let genesis_wire = chain.committed(1).block().encode_wire().unwrap();
    let successor_wire = chain.committed(2).block().encode_wire().unwrap();
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || {
            let original = CertifiedChain::new(&view).err().unwrap();
            let ExecutionAttemptError::Deferred(original) = original else {
                panic!("the original certified source read must refuse locally");
            };
            for error in [
                registration(&view).unwrap_err(),
                anchor(&view, 2).unwrap_err(),
            ] {
                let ExportError::Deferred(reason) = error else {
                    panic!("an unfinished export read cannot reject custody: {error:?}");
                };
                assert_eq!(reason, original);
                assert!(
                    reason.allocation_refusal().is_none(),
                    "the decode counter has no release owner"
                );
            }
            assert_eq!(view.height(), 2);
        },
    );
    assert_eq!(registration(&view).unwrap(), registered);
    assert_eq!(anchor(&view, 2).unwrap(), anchored);
    assert_eq!(
        chain.committed(1).block().encode_wire().unwrap(),
        genesis_wire
    );
    assert_eq!(
        chain.committed(2).block().encode_wire().unwrap(),
        successor_wire
    );
    assert!(matches!(
        anchor(&view, 3),
        Err(ExportError::Custody(ChainReadError::NotCommitted {
            height: 3
        }))
    ));
}

#[test]
fn private_execution_tip_keeps_its_signed_role_through_successor_and_history_read() {
    let mut chain = private_chain();
    let original = chain.state().view().native_execution_tip().unwrap();
    assert!(matches!(
        original.root_scope(),
        SumeragiRootScope::Dataspace { .. }
    ));
    assert_eq!(
        original.result_scope(),
        iroha_data_model::sumeragi_finality::CertifiedResultScope::NonGlobal
    );
    chain.commit_at(1_100, vec![]);
    let view = chain.state().view();
    let current = view.native_execution_tip().unwrap();
    assert_eq!(current.root_scope(), original.root_scope());
    let reader = CertifiedChain::new(&view).unwrap();
    assert_eq!(reader.root_scope(), original.root_scope());
    let receipt = reader.committed(2).unwrap();
    assert_eq!(receipt.result_scope(), original.result_scope());
    let decoded = iroha_data_model::sumeragi_finality::CertifiedResultV1::decode(
        receipt
            .block()
            .commit_certificate()
            .unwrap()
            .result_preimage(),
        original.result_scope(),
    )
    .unwrap();
    assert!(!decoded.header().is_active());
    assert_eq!(current.result(), receipt.result());
    assert_eq!(
        anchor(&view, 2).unwrap().certificate.result_preimage,
        receipt
            .block()
            .commit_certificate()
            .unwrap()
            .result_preimage()
    );
}

#[test]
fn private_profile_export_preserves_local_resource_category_after_decode_scope_retires() {
    for (resource, expected) in [
        (
            norito::core::DecodeResourceError::AllocationFailed { bytes: 1 },
            ivm::error::ExecutionDeferral::AllocationUnavailable,
        ),
        (
            norito::core::DecodeResourceError::TotalAllocationExceeded {
                attempted: 2,
                limit: 1,
            },
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity,
        ),
    ] {
        let ExportError::Deferred(retained) =
            ExportError::from(PrivateDataspaceAnchorError::Resource(resource))
        else {
            panic!("captured local resource cannot become a profile rejection");
        };
        assert_eq!(retained.reason(), expected);
        assert!(retained.allocation_refusal().is_none());
    }
    assert!(matches!(
        ExportError::from(PrivateDataspaceAnchorError::Invalid("malformed".into())),
        ExportError::Profile(_)
    ));
}
