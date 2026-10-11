//! Complete cold publication, original allocation ownership and certified-cut refusal.

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_data_model::{
    Identifiable, Registrable, asset::AssetBalancePolicy, domain::Domain, isi::Register,
    nexus::AxtAssetIncarnationV1,
};
use iroha_model_base::domain::DomainId;
use std::cell::Cell;

/// Borrow one exact asset definition and its incarnation at the original certified cut.
///
/// Both targets must be present in the reconstructed complete snapshot before the consumer runs.
fn with_asset_snapshot<T>(
    state: &State,
    tip: &CommittedBlock,
    asset_id: &AssetDefinitionId,
    budget: &AllocationBudget,
    consume: impl FnOnce(
        &WorldStateSnapshotV1,
        &AssetDefinition,
        &AxtAssetIncarnationV1,
    ) -> Result<T, String>,
) -> Result<T, WorldStateSnapshotError> {
    state.with_native_world_state_snapshot_cut_v1(tip, None, budget, |snapshot, world| {
        let definition = world
            .asset_definitions
            .get(asset_id)
            .ok_or("World snapshot exact asset definition is absent")?;
        let incarnation = world
            .axt_asset_incarnations
            .get(asset_id)
            .ok_or("World snapshot exact asset incarnation is absent")?;
        for (field, value) in [
            ("world.asset_definitions", hash_value(definition)?),
            ("world.axt_asset_incarnations", hash_value(incarnation)?),
        ] {
            require_target(
                snapshot,
                field,
                WorldStateElementKindV1::Table,
                Some(hash_value(asset_id)?),
                value,
            )?;
        }
        consume(snapshot, definition, incarnation)
    })
}

#[test]
fn snapshot_reader_refusal_preserves_original_source_and_does_not_call_consumer() {
    let (chain, asset) = asset_chain();
    let state = chain.state();
    let tip = chain.committed(chain.height());
    let budget = state.ivm_execution_budget();
    let initial_bytes = budget.reserved_bytes();
    let original = state.latest_block_header.write();
    let expected = state.latest_block_header.try_read_or_wait().err().unwrap();
    let called = Cell::new(false);
    let result = with_asset_snapshot(state, &tip, &asset, &budget, |_, _, _| {
        called.set(true);
        Ok(())
    });
    let Err(WorldStateSnapshotError::View(StateViewError::Busy(actual))) = result else {
        panic!("snapshot must retain the original physical reader refusal");
    };
    assert_eq!(actual, expected);
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), initial_bytes);
    drop(original);
    with_asset_snapshot(state, &tip, &asset, &budget, |_, _, _| {
        called.set(true);
        Ok(())
    })
    .unwrap();
    assert!(called.get());
    assert_eq!(budget.reserved_bytes(), initial_bytes);
}

#[test]
fn provider_snapshot_publishes_original_current_heads_and_refuses_an_obsolete_cut() {
    use crate::smartcontracts::isi::sorafs_provider_admission::test_fixture::{
        NOW, ProviderAdmissionTestFixtureV1,
    };
    use iroha_data_model::{
        sorafs::provider_admission::{
            discovery::{ProviderDiscoveryProofRefV1, ProviderDiscoveryProofV1},
            history::AdmissionHistoryRecordV1,
        },
        sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier},
    };
    let mut fixture = ProviderAdmissionTestFixtureV1::new();
    fixture.admit();
    let chain = fixture.chain();
    let tip = chain.committed(chain.height());
    let validators = chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    let mut verifier = SumeragiFinalityVerifier::new(
        chain.genesis(),
        &chain.state().chain_id_ref().to_string(),
        validators,
    )
    .unwrap();
    let genesis_proof = crate::sumeragi::finality::build_proof(&chain.state().view(), 1).unwrap();
    verifier.verify(&genesis_proof).unwrap();
    let proof =
        crate::sumeragi::finality::build_proof(&chain.state().view(), chain.height()).unwrap();
    let verified = verifier.verify(&proof).unwrap();
    let mut advert: sorafs_manifest::ProviderAdvertV1 =
        norito::decode_from_bytes(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/sorafs_manifest/provider_admission/advert_v1.to"
        )))
        .unwrap();
    let key = iroha_crypto::KeyPair::from_private_key(
        iroha_crypto::PrivateKey::from_bytes(iroha_crypto::Algorithm::Ed25519, &[0x21; 32])
            .unwrap(),
    )
    .unwrap();
    advert.network_id = *chain.network_id().as_bytes();
    advert.body = fixture.envelope().advert_body.clone();
    advert.issued_at = NOW;
    advert.expires_at = NOW + 60;
    advert.signature.signature = iroha_crypto::Signature::new(
        key.private_key(),
        &advert.signature_payload_bytes().unwrap(),
    )
    .payload()
    .to_vec();
    let advert = norito::encode_canonical(&advert).unwrap();
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let selected = chain
        .state()
        .with_native_provider_admission_snapshot_v1(
            &tip,
            fixture.provider(),
            &budget,
            |originals| {
                assert_eq!(
                    originals.world.root().unwrap(),
                    tip.commitment().execution.world_state_root
                );
                assert_eq!(
                    originals.world.schema_hash,
                    State::native_world_schema_hash_v1().unwrap()
                );
                let head = AdmissionHistoryRecordV1::decode_frame(originals.provider_head).unwrap();
                assert_eq!(head.owner.as_ref(), Some(originals.owner));
                assert!(!head.revoked);
                assert!(originals.provider_predecessor.is_none());
                assert!(originals.council_predecessor.is_none());
                let response = ProviderDiscoveryProofRefV1::new(
                    originals.world,
                    (originals.council_head, originals.council_predecessor),
                    (originals.provider_head, originals.provider_predecessor),
                    originals.owner,
                    &advert,
                    originals.stream_token,
                );
                norito::encode_canonical(&response).map_err(|e| e.to_string())
            },
        )
        .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    let selected = ProviderDiscoveryProofV1::decode_frame(&selected).unwrap();
    selected
        .verify(
            chain.network_id(),
            fixture.provider(),
            State::native_world_schema_hash_v1().unwrap(),
            &verified,
            NOW + 1,
        )
        .unwrap();
    fixture.revoke();
    let called = Cell::new(false);
    assert!(
        fixture
            .state()
            .with_native_provider_admission_snapshot_v1(&tip, fixture.provider(), &budget, |_| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.get());
}

#[test]
fn provider_snapshot_missing_authority_and_insufficient_budget_never_call_consumer() {
    use crate::smartcontracts::isi::sorafs_provider_admission::test_fixture::ProviderAdmissionTestFixtureV1;
    let mut fixture = ProviderAdmissionTestFixtureV1::new();
    fixture.admit();
    let tip = fixture.chain().committed(fixture.chain().height());
    let called = Cell::new(false);
    for (provider, bytes) in [
        (fixture.provider(), 0),
        // Snapshot storage can fit while native authority decoder scratch cannot.
        (fixture.provider(), 17 * 1024 * 1024),
        (
            iroha_data_model::sorafs::capacity::ProviderId::new([0xFA; 32]),
            32 * 1024 * 1024,
        ),
    ] {
        assert!(
            fixture
                .state()
                .with_native_provider_admission_snapshot_v1(
                    &tip,
                    provider,
                    &AllocationBudget::new(bytes),
                    |_| {
                        called.set(true);
                        Ok(())
                    }
                )
                .is_err()
        );
    }
    assert!(!called.get());
}

#[test]
fn complete_cold_snapshot_matches_original_accumulator_and_registry() {
    let world = World::new();
    let overlay = world.block();
    let original = WorldStateAccumulator::capture(&overlay).unwrap();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let captured = capture(&overlay, &original, &budget).unwrap();
    assert_eq!(captured.snapshot.root().unwrap(), original.root().unwrap());
    assert_eq!(
        captured.snapshot.schema_hash,
        field_index().as_ref().unwrap().schema
    );
    assert_eq!(
        captured.snapshot.schema_hash,
        State::native_world_schema_hash_v1().unwrap()
    );
    assert_eq!(captured.snapshot.entries.len() as u64, original.entries());
    assert!(captured.snapshot.entries.iter().all(|entry| {
        field_index()
            .as_ref()
            .unwrap()
            .ids
            .contains(&entry.field_id.as_str())
            && (entry.kind == WorldStateElementKindV1::Table) == entry.key_hash.is_some()
    }));
    // Untouched canonical cells retain their exact original preimage even when
    // every table is empty; parameters is a live canonical Cell<Parameters>.
    let original_parameters_hash = hash_value(overlay.parameters.get()).unwrap();
    assert!(
        captured
            .snapshot
            .entries
            .iter()
            .any(|entry| entry.field_id == "world.parameters"
                && entry.kind == WorldStateElementKindV1::Cell
                && entry.key_hash.is_none()
                && entry.value_hash == original_parameters_hash)
    );
    assert!(
        budget.reserved_bytes() > 0,
        "snapshot retains its original charges"
    );
    drop(captured);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "all snapshot storage is physically gone"
    );
}

#[test]
fn complete_cold_snapshot_preserves_actual_trigger_child_registry_identity() {
    use crate::smartcontracts::isi::triggers::specialized::{
        SpecializedAction, SpecializedTrigger,
    };
    use iroha_data_model::{events::execute_trigger::ExecuteTriggerEventFilter, prelude::*};
    let world = World::new();
    let mut overlay = world.block();
    {
        let mut transaction = overlay.triggers.transaction();
        let action = SpecializedAction::new(
            Executable::Instructions(
                vec![InstructionBox::from(Log::new(
                    Level::INFO,
                    "complete native trigger cut".into(),
                ))]
                .into(),
            ),
            Repeats::Exactly(3),
            iroha_test_samples::ALICE_ID.clone(),
            ExecuteTriggerEventFilter::new(),
        )
        .unwrap();
        assert!(
            transaction
                .add_by_call_trigger(SpecializedTrigger::new(
                    "snapshot_cut".parse().unwrap(),
                    action,
                ))
                .unwrap()
        );
        transaction.apply();
    }
    let original = WorldStateAccumulator::capture(&overlay).unwrap();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let captured = capture(&overlay, &original, &budget).unwrap();
    let row = captured
        .snapshot
        .entries
        .iter()
        .find(|entry| entry.field_id == "triggers.by_call")
        .unwrap();
    assert_eq!(row.kind, WorldStateElementKindV1::Table);
    assert!(row.key_hash.is_some());
    assert!(
        !captured
            .snapshot
            .entries
            .iter()
            .any(|entry| entry.field_id == "triggers.ids"
                || entry.field_id.starts_with("triggers.active_"))
    );
    assert_eq!(captured.snapshot.root().unwrap(), original.root().unwrap());
    drop(captured);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn complete_cold_snapshot_refuses_changed_accumulator_and_refunds_original_pool() {
    let world = World::new();
    let overlay = world.block();
    let mut original = WorldStateAccumulator::capture(&overlay).unwrap();
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    original.lanes[0] = original.lanes[0].wrapping_add(1);
    assert!(capture(&overlay, &original, &budget).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    original.entries += 1;
    assert!(capture(&overlay, &original, &budget).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn complete_cold_snapshot_has_no_replacement_budget_on_refusal() {
    let world = World::new();
    let overlay = world.block();
    let original = WorldStateAccumulator::capture(&overlay).unwrap();
    let budget = AllocationBudget::new(0);
    assert!(capture(&overlay, &original, &budget).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(SnapshotCollector::new(&budget, MAX_WORLD_STATE_SNAPSHOT_ENTRIES_V1 + 1, 1).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn snapshot_collector_rejects_omission_duplicate_and_excess_elements() {
    let budget = AllocationBudget::new(1024 * 1024);
    let schema = Hash::new(b"schema");
    let mut duplicate = SnapshotCollector::new(&budget, 2, 1).unwrap();
    for _ in 0..2 {
        duplicate
            .push(
                "world.test",
                WorldStateElementKindV1::Cell,
                None,
                Hash::new(b"v"),
            )
            .unwrap();
    }
    assert!(duplicate.finish(schema).is_err());
    assert_eq!(budget.reserved_bytes(), 0);
    let mut excess = SnapshotCollector::new(&budget, 1, 1).unwrap();
    excess
        .push(
            "world.test",
            WorldStateElementKindV1::Cell,
            None,
            Hash::new(b"v"),
        )
        .unwrap();
    assert!(
        excess
            .push(
                "world.test",
                WorldStateElementKindV1::Cell,
                None,
                Hash::new(b"v")
            )
            .is_err()
    );
    drop(excess);
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        SnapshotCollector::new(&budget, 1, 1)
            .unwrap()
            .finish(schema)
            .is_err()
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

fn asset_chain() -> (CertifiedTestChain, AssetDefinitionId) {
    let mut config = TestChainConfig::new(World::new(), 1_000);
    let domain = DomainId::try_new("snapshot", "universal").unwrap();
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
    config.genesis_instructions = vec![
        Register::domain(Domain::new(domain)).into(),
        Register::asset_definition(AssetDefinition::numeric(
            asset.clone(),
            "Snapshot coin",
            AssetBalancePolicy::Global,
            None,
        ))
        .into(),
    ];
    let mut chain = CertifiedTestChain::start(config).unwrap();
    chain.commit_at(2_000, Vec::new());
    (chain, asset)
}

#[test]
fn certified_world_cut_survives_equivalent_and_refused_manifest_refresh() {
    use crate::governance::manifest::LaneManifestRegistry;
    use iroha_config::parameters::actual::LaneRegistry;
    use std::sync::Arc;

    let (mut chain, asset) = asset_chain();
    let tip = chain.committed(chain.height());
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    {
        let state = chain.state();
        let nexus = state.nexus_snapshot();
        let original = state.lane_manifests.read().clone();
        let privacy = state.lane_privacy_registry.read().clone();
        let generation = state.state_view_generation();
        let assert_proof = || {
            with_asset_snapshot(state, &tip, &asset, &budget, |snapshot, _, _| {
                assert_eq!(
                    snapshot.root().unwrap(),
                    tip.commitment().execution.world_state_root
                );
                Ok(())
            })
            .expect("manifest refresh must preserve the original certified World proof");
            assert_eq!(budget.reserved_bytes(), 0);
        };
        assert_proof();
        // A new materialization of the exact source is what each watcher tick supplies.
        let equivalent = Arc::new(original.rebind(&nexus.lane_catalog, &nexus.governance));
        assert!(!Arc::ptr_eq(&original, &equivalent));
        assert!(state.install_lane_manifests_if_consensus_compatible(&equivalent));
        assert_proof();
        assert_eq!(state.state_view_generation(), generation);
        assert!(Arc::ptr_eq(&state.lane_manifests.read(), &original));
        assert!(Arc::ptr_eq(&state.lane_privacy_registry.read(), &privacy));

        let directory = tempfile::tempdir().unwrap();
        let alias = &nexus.lane_catalog.lanes()[0].alias;
        std::fs::write(
            directory.path().join(format!("{alias}.manifest.json")),
            norito::json::to_vec(&norito::json!({ "lane": alias })).unwrap(),
        )
        .unwrap();
        let changed = Arc::new(LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &LaneRegistry {
                manifest_directory: Some(directory.path().to_path_buf()),
                ..LaneRegistry::default()
            },
        ));
        assert_ne!(
            changed
                .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
                .unwrap(),
            original
                .canonical_materialized_authority_preimage(&nexus.lane_catalog, &nexus.governance)
                .unwrap(),
        );
        for rejected in [changed, Arc::new(LaneManifestRegistry::default())] {
            assert!(!state.install_lane_manifests_if_consensus_compatible(&rejected));
            assert_proof();
            assert_eq!(state.state_view_generation(), generation);
            assert!(Arc::ptr_eq(&state.lane_manifests.read(), &original));
            assert!(Arc::ptr_eq(&state.lane_privacy_registry.read(), &privacy));
        }
    }
    // A real native successor still retires the former cut. No generation check is relaxed.
    chain.commit_at(3_000, Vec::new());
    let called = Cell::new(false);
    assert!(
        with_asset_snapshot(chain.state(), &tip, &asset, &budget, |_, _, _| {
            called.set(true);
            Ok(())
        })
        .is_err()
    );
    assert!(!called.get());
    let successor = chain.committed(chain.height());
    with_asset_snapshot(
        chain.state(),
        &successor,
        &asset,
        &budget,
        |snapshot, _, _| {
            assert_eq!(
                snapshot.root().unwrap(),
                successor.commitment().execution.world_state_root
            );
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn replayed_world_cut_survives_exact_startup_queue_handoff_without_another_block() {
    use crate::queue::Queue;
    use iroha_primitives::time::TimeSource;
    use std::sync::Arc;

    let config = || {
        let nexus = iroha_config::parameters::actual::Nexus::default();
        let baseline = crate::governance::manifest::LaneManifestRegistry::from_config(
            &nexus.lane_catalog,
            &nexus.governance,
            &nexus.registry,
        );
        let mut config = TestChainConfig::new(World::new(), 1_000);
        // Startup installs the retained baseline before native genesis/replay begins.
        config.lane_manifests = Some(Arc::new(
            baseline
                .with_runtime_additions(
                    &[],
                    &nexus.lane_catalog,
                    &nexus.dataspace_catalog,
                    &nexus.governance,
                )
                .unwrap(),
        ));
        config
    };
    let mut source = CertifiedTestChain::start(config()).unwrap();
    source.commit_at(2_000, Vec::new());
    let mut replay = CertifiedTestChain::start(config()).unwrap();
    replay.replay_from(&source).unwrap();
    assert_eq!(replay.height(), 2);
    let tip = replay.committed(2);
    assert_eq!(
        tip.block().encode_wire().unwrap(),
        source.committed(2).block().encode_wire().unwrap()
    );
    let state = replay.state();
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let assert_proof = || {
        state
            .with_native_world_state_snapshot_cut_v1(&tip, None, &budget, |snapshot, _| {
                assert_eq!(
                    snapshot.root().unwrap(),
                    tip.commitment().execution.world_state_root
                );
                Ok(())
            })
            .expect(
                "post-replay Queue handoff must preserve the native replay's certified World cut",
            );
        assert_eq!(budget.reserved_bytes(), 0);
    };
    assert_proof();
    let nexus = state.nexus_snapshot();
    let original = state.lane_manifests.read().clone();
    let privacy = state.lane_privacy_registry.read().clone();
    let generation = state.state_view_generation();
    // This is the daemon's original post-replay rebind and public Queue handoff recipe.
    let handoff = state
        .lane_manifests_with_committed_catalog(&original, &nexus)
        .unwrap();
    assert!(!Arc::ptr_eq(&handoff, &original));
    let queue = Queue::test(Default::default(), &TimeSource::new_system());
    queue
        .install_materialized_lane_manifests_with_state(
            &handoff,
            state,
            &nexus.lane_catalog,
            &nexus.governance,
        )
        .unwrap();
    assert_proof();
    assert_eq!(state.state_view_generation(), generation);
    assert!(Arc::ptr_eq(&state.lane_manifests.read(), &original));
    assert!(Arc::ptr_eq(&state.lane_privacy_registry.read(), &privacy));
    assert_eq!(
        replay.height(),
        2,
        "no new block repairs an invalidated proof in this regression"
    );

    // An invalid later handoff does not damage the original publication either.
    let unbound = Arc::new(crate::governance::manifest::LaneManifestRegistry::default());
    assert!(
        queue
            .install_materialized_lane_manifests_with_state(
                &unbound,
                state,
                &nexus.lane_catalog,
                &nexus.governance,
            )
            .is_err()
    );
    assert_proof();
    assert_eq!(state.state_view_generation(), generation);
}

#[test]
fn sns_lease_snapshot_authenticates_native_record_and_refuses_changed_or_unfunded_cut() {
    use iroha_data_model::{
        sns::lease::{SnsLeaseProofRefV1, SnsLeaseProofV1},
        sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier},
    };
    let (mut chain, _) = asset_chain();
    let selector =
        crate::sns::selector_for_domain(&DomainId::try_new("snapshot", "universal").unwrap())
            .unwrap();
    let record = crate::sns::record_by_selector(chain.state().view().world(), &selector)
        .unwrap()
        .unwrap();
    let validators = chain
        .validators()
        .iter()
        .map(|(peer, pop)| FinalityValidator {
            public_key: peer.public_key().clone(),
            proof_of_possession: pop.clone(),
        })
        .collect();
    let mut verifier = SumeragiFinalityVerifier::new(
        chain.genesis(),
        &chain.state().chain_id_ref().to_string(),
        validators,
    )
    .unwrap();
    verifier
        .verify(&crate::sumeragi::finality::build_proof(&chain.state().view(), 1).unwrap())
        .unwrap();
    let verified = verifier
        .verify(&crate::sumeragi::finality::build_proof(&chain.state().view(), 2).unwrap())
        .unwrap();
    let tip = chain.committed(2);
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let bytes = chain
        .state()
        .with_native_sns_lease_snapshot_v1(&tip, &selector, &budget, |world, bytes| {
            assert_eq!(
                world.root().unwrap(),
                tip.commitment().execution.world_state_root
            );
            norito::encode_canonical(&SnsLeaseProofRefV1::new(world, bytes))
                .map_err(|e| e.to_string())
        })
        .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    let proof = SnsLeaseProofV1::decode_frame(&bytes).unwrap();
    assert_eq!(
        proof
            .verify(
                chain.network_id(),
                &selector,
                &record.owner,
                State::native_world_schema_hash_v1().unwrap(),
                &verified,
                2_000
            )
            .unwrap()
            .record(),
        &record
    );
    let called = Cell::new(false);
    assert!(
        chain
            .state()
            .with_native_sns_lease_snapshot_v1(
                &tip,
                &selector,
                &AllocationBudget::new(0),
                |_, _| {
                    called.set(true);
                    Ok(())
                }
            )
            .is_err()
    );
    let missing = iroha_data_model::sns::NameSelectorV1::new(
        iroha_data_model::sns::DATASPACE_ALIAS_SUFFIX_ID,
        "missing",
    )
    .unwrap();
    assert!(
        chain
            .state()
            .with_native_sns_lease_snapshot_v1(&tip, &missing, &budget, |_, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    chain.commit_at(3_000, vec![]);
    assert!(
        chain
            .state()
            .with_native_sns_lease_snapshot_v1(&tip, &selector, &budget, |_, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn publisher_authenticates_original_native_cut_and_borrows_exact_targets() {
    let (mut chain, asset) = asset_chain();
    let original_tip = chain.committed(2);
    let budget = AllocationBudget::new(16 * 1024 * 1024);
    let state = chain.state();
    let generation = state.state_view_generation();
    let (
        original_definition,
        original_incarnation_pointer,
        original_incarnation,
        original_parameters_hash,
    ) = {
        let view = state.view();
        let world = view.world();
        let definition = world.asset_definitions().get(&asset).unwrap();
        let incarnation = world.axt_asset_incarnations().get(&asset).unwrap();
        (
            std::ptr::from_ref(definition),
            std::ptr::from_ref(incarnation),
            *incarnation,
            hash_value(world.parameters()).unwrap(),
        )
    };
    with_asset_snapshot(
        state,
        &original_tip,
        &asset,
        &budget,
        |snapshot, definition, incarnation| {
            assert_eq!(
                snapshot.schema_hash,
                State::native_world_schema_hash_v1().unwrap()
            );
            assert_eq!(
                snapshot.root().unwrap(),
                original_tip.commitment().execution.world_state_root
            );
            assert_eq!(definition.id(), &asset);
            assert!(std::ptr::eq(definition, original_definition));
            assert!(std::ptr::eq(incarnation, original_incarnation_pointer));
            assert_eq!(*incarnation, original_incarnation);
            for (field, kind, key, value) in [
                (
                    "world.asset_definitions",
                    WorldStateElementKindV1::Table,
                    Some(hash_value(&asset).unwrap()),
                    hash_value(definition).unwrap(),
                ),
                (
                    "world.axt_asset_incarnations",
                    WorldStateElementKindV1::Table,
                    Some(hash_value(&asset).unwrap()),
                    hash_value(incarnation).unwrap(),
                ),
                (
                    "world.parameters",
                    WorldStateElementKindV1::Cell,
                    None,
                    original_parameters_hash,
                ),
            ] {
                assert!(
                    snapshot.entries.iter().any(|entry| entry.field_id == field
                        && entry.kind == kind
                        && entry.key_hash == key
                        && entry.value_hash == value),
                    "{field}"
                );
            }
            assert!(budget.reserved_bytes() > 0);
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        state.state_view_generation(),
        generation,
        "read-only overlay publishes nothing"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    let called = Cell::new(false);
    let absent = AssetDefinitionId::derive_from_components(
        DomainId::try_new("snapshot", "universal").unwrap(),
        "absent".parse().unwrap(),
    );
    assert!(
        with_asset_snapshot(state, &original_tip, &absent, &budget, |_, _, _| {
            called.set(true);
            Ok(())
        })
        .is_err()
    );
    assert!(!called.get());
    assert!(
        with_asset_snapshot(
            state,
            &original_tip,
            &asset,
            &AllocationBudget::new(0),
            |_, _, _| {
                called.set(true);
                Ok(())
            }
        )
        .is_err()
    );
    assert!(!called.get());
    // Exercise callback invalidation while the original cut still owns this generation.
    let callback_entered = Cell::new(false);
    let error = with_asset_snapshot(state, &original_tip, &asset, &budget, |_, _, _| {
        callback_entered.set(true);
        let mut publication = state.state_view_publication();
        let _writer = publication.begin();
        Ok(())
    })
    .unwrap_err();
    assert!(callback_entered.get());
    assert!(error.to_string().contains("generation changed"), "{error}");
    assert_eq!(budget.reserved_bytes(), 0);
    // Advancing publication cannot grant the old journal authority over a new generation.
    let error = with_asset_snapshot(state, &original_tip, &asset, &budget, |_, _, _| {
        called.set(true);
        Ok(())
    })
    .unwrap_err();
    assert!(
        error.to_string().contains("another certified generation"),
        "{error}"
    );
    assert!(!called.get());
    {
        let mut publication = state.state_view_publication();
        let _writer = publication.begin();
        assert!(
            with_asset_snapshot(state, &original_tip, &asset, &budget, |_, _, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(!called.get());
    }
    assert_eq!(budget.reserved_bytes(), 0);
    chain.commit_at(3_000, Vec::new());
    assert!(
        with_asset_snapshot(chain.state(), &original_tip, &asset, &budget, |_, _, _| {
            called.set(true);
            Ok(())
        })
        .is_err()
    );
    assert!(
        !called.get(),
        "retired native tip must refuse before invoking the callback"
    );
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cold_reconstruction_removes_tail_insertions_and_restores_deletions_and_updates() {
    use super::super::world_state_cut::JournalCapture;
    use iroha_model_base::state_path::StatePath;
    let (chain, _) = asset_chain();
    let native = chain.state().view().native_execution_tip().unwrap();
    let world = World::new();
    let path = |value: &str| value.parse::<StatePath>().unwrap();
    {
        let mut seed = world.block();
        seed.smart_contract_state
            .insert(path("app/deleted"), vec![1]);
        seed.smart_contract_state
            .insert(path("app/updated"), vec![2]);
        let accumulator = WorldStateAccumulator::capture(&seed).unwrap();
        *seed.state_accumulator.get_mut() = accumulator;
        seed.commit();
    }
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let mut block = world.block();
    block
        .smart_contract_state
        .insert(path("app/updated"), vec![3]);
    let cut = JournalCapture::capture(&block, false, &budget).unwrap();
    let at_result = WorldStateAccumulator::capture(&block).unwrap();
    block.smart_contract_state.remove(path("app/deleted"));
    block
        .smart_contract_state
        .insert(path("app/updated"), vec![4]);
    block
        .smart_contract_state
        .insert(path("app/tail-only"), vec![5]);
    block.advance_state_accumulator(false).unwrap();
    block.begin_freeze();
    block.finish_freeze();
    let capsule = cut.prepare(&block, native, 2, &budget).unwrap();
    let applied = capture(&block, block.state_accumulator.get(), &budget).unwrap();
    let certified = reconstruct(&applied, &capsule, &budget).unwrap();
    assert_eq!(
        certified.snapshot.root().unwrap(),
        at_result.root().unwrap()
    );
    let target = hash_value(&path("app/updated")).unwrap();
    require_target(
        &certified.snapshot,
        "world.smart_contract_state",
        WorldStateElementKindV1::Table,
        Some(target),
        hash_value(&vec![3_u8]).unwrap(),
    )
    .unwrap();
    assert!(
        require_target(
            &certified.snapshot,
            "world.smart_contract_state",
            WorldStateElementKindV1::Table,
            Some(target),
            hash_value(&vec![4_u8]).unwrap()
        )
        .is_err()
    );
    let deleted = hash_value(&path("app/deleted")).unwrap();
    require_target(
        &certified.snapshot,
        "world.smart_contract_state",
        WorldStateElementKindV1::Table,
        Some(deleted),
        hash_value(&vec![1_u8]).unwrap(),
    )
    .unwrap();
    let inserted = hash_value(&path("app/tail-only")).unwrap();
    assert!(
        !certified
            .snapshot
            .entries
            .iter()
            .any(|row| row.field_id == "world.smart_contract_state"
                && row.key_hash == Some(inserted))
    );
    drop(certified);
    drop(applied);
    drop(capsule);
    drop(cut);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn cold_reconstruction_rejects_missing_changed_or_foreign_complete_applied_rows() {
    use super::super::world_state_cut::JournalCapture;
    use iroha_model_base::state_path::StatePath;
    let (chain, _) = asset_chain();
    let native = chain.state().view().native_execution_tip().unwrap();
    let world = World::new();
    {
        let mut seed = world.block();
        let accumulator = WorldStateAccumulator::capture(&seed).unwrap();
        *seed.state_accumulator.get_mut() = accumulator;
        seed.commit();
    }
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let mut block = world.block();
    let cut = JournalCapture::capture(&block, false, &budget).unwrap();
    let key = "app/tail".parse::<StatePath>().unwrap();
    block.smart_contract_state.insert(key.clone(), vec![9]);
    block.advance_state_accumulator(false).unwrap();
    block.begin_freeze();
    block.finish_freeze();
    let capsule = cut.prepare(&block, native, 2, &budget).unwrap();
    let mut applied = capture(&block, block.state_accumulator.get(), &budget).unwrap();
    let original = applied.snapshot.entries.clone(); // Explicit test-only mutation specimen.
    let position = applied
        .snapshot
        .entries
        .iter()
        .position(|row| {
            row.field_id == "world.smart_contract_state"
                && row.key_hash == Some(hash_value(&key).unwrap())
        })
        .unwrap();
    applied.snapshot.entries[position].value_hash = Hash::new(b"substituted post-tail preimage");
    assert!(reconstruct(&applied, &capsule, &budget).is_err());
    applied.snapshot.entries = original;
    applied.snapshot.entries.remove(position);
    assert!(reconstruct(&applied, &capsule, &budget).is_err());
    assert!(reconstruct(&applied, &capsule, &AllocationBudget::new(0)).is_err());
}

#[test]
fn publisher_requires_original_capture_after_snapshot_restore_or_raw_commit() {
    let (chain, asset) = asset_chain();
    let tip = chain.committed(2);
    let state = chain.state();
    // Dropping the private original models the truthful decoded-restoration
    // boundary; a matching bare stored World root is never replacement authority.
    *state.native_world_cut.lock() = None;
    let called = Cell::new(false);
    let error = with_asset_snapshot(
        state,
        &tip,
        &asset,
        &AllocationBudget::new(16 * 1024 * 1024),
        |_, _, _| {
            called.set(true);
            Ok(())
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("requires native replay"));
    assert!(!called.get());
}

fn names_chain() -> (CertifiedTestChain, AccountId, AssetDefinitionId) {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{IntoKeyValue, account::Account};
    use std::collections::BTreeSet;
    let mut world = World::new();
    let key = KeyPair::from_seed(vec![0x35; 32], Algorithm::Ed25519);
    let reader = AccountId::new(key.public_key().clone());
    let (id, value) = Account::new(reader.clone()).build(&reader).into_key_value();
    world.accounts.insert(id, value);
    world.account_permissions.insert(
        reader.clone(),
        BTreeSet::from([iroha_executor_data_model::permission::query::CanReadAllLedgerData.into()]),
    );
    let domain = DomainId::try_new("snapshot", "universal").unwrap();
    let asset = AssetDefinitionId::derive_from_components(domain.clone(), "coin".parse().unwrap());
    // Startup rebuilds alias indexes before genesis instructions execute. The
    // initial binding must therefore reference actual initial native entities.
    world
        .domains
        .insert(domain.clone(), Domain::new(domain).build(&reader));
    world.asset_definitions.insert(
        asset.clone(),
        AssetDefinition::numeric(
            asset.clone(),
            "Names original fixture",
            AssetBalancePolicy::Global,
            None,
        )
        .build(&reader),
    );
    world.asset_definition_alias_bindings.insert(
        asset.clone(),
        AssetDefinitionAliasBindingRecord {
            alias: "coin#snapshot.universal".parse().unwrap(),
            lease_expiry_ms: None,
            grace_until_ms: None,
            bound_at_ms: 1_000,
        },
    );
    world
        .smart_contract_state
        .insert("sns/records/4099/is2".parse().unwrap(), vec![1, 2, 3]);
    world
        .smart_contract_state
        .insert("customer/private-key-name".parse().unwrap(), vec![99, 98]);
    let config = TestChainConfig::new(world, 1_000);
    let mut chain = CertifiedTestChain::start(config).unwrap();
    chain.commit_at(2_000, Vec::new());
    (chain, reader, asset)
}

#[test]
fn names_publisher_requires_actual_native_root_and_complete_exact_cut_originals() {
    let (chain, reader, asset) = names_chain();
    let state = chain.state();
    let tip = chain.committed(2);
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let generation = state.state_view_generation();
    // Native startup seeds the reserved universal lease before the certified
    // genesis. Its durable key uses the native selector hash, not the label.
    let universal_selector =
        crate::sns::selector_for_dataspace_alias(crate::sns::RESERVED_UNIVERSAL_DATASPACE_ALIAS)
            .unwrap();
    let universal_key = crate::sns::record_storage_key(&universal_selector);
    let universal_owner = chain.genesis_account().clone();
    let universal_controller =
        iroha_data_model::account::AccountAddress::from_account_id(&universal_owner).unwrap();
    let mut universal_metadata = iroha_model_base::metadata::Metadata::default();
    universal_metadata.insert(
        crate::sns::SNS_DATASPACE_ID_METADATA_KEY.parse().unwrap(),
        iroha_primitives::json::Json::new(
            iroha_model_base::topology::DataSpaceId::UNIVERSAL.as_u64(),
        ),
    );
    let expected_universal_record = iroha_data_model::sns::NameRecordV1::new(
        universal_selector,
        universal_owner,
        vec![iroha_data_model::sns::NameControllerV1::account(
            &universal_controller,
        )],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        universal_metadata,
    );
    state
        .with_native_resource_names_snapshot_v1(
            &tip,
            &reader,
            &budget,
            |snapshot, aliases, keys, names| {
                assert_eq!(
                    snapshot.schema_hash,
                    State::native_world_schema_hash_v1().unwrap()
                );
                assert_eq!(
                    snapshot.root().unwrap(),
                    tip.commitment().execution.world_state_root
                );
                assert_eq!(tip.block_time_ms(), 2_000);
                assert_eq!(aliases.len(), 1);
                assert_eq!(aliases[0].0, &asset);
                assert_eq!(aliases[0].1.alias.to_string(), "coin#snapshot.universal");
                require_complete_table_count(
                    snapshot,
                    "world.asset_definition_alias_bindings",
                    aliases.len(),
                )
                .unwrap();
                require_complete_table_count(snapshot, "world.smart_contract_state", keys.len())
                    .unwrap();
                assert!(
                    keys.iter()
                        .any(|key| key.as_ref() == "customer/private-key-name")
                );
                assert_eq!(names.len(), 2, "duplicate disclosed rows are refused");
                assert_eq!(
                    names
                        .iter()
                        .map(|(key, _)| key.as_ref())
                        .collect::<std::collections::BTreeSet<_>>(),
                    std::collections::BTreeSet::from([
                        "sns/records/4099/is2",
                        universal_key.as_ref(),
                    ]),
                    "only the exact synthetic SNS row and native universal lease are disclosed"
                );
                let synthetic = names
                    .iter()
                    .find(|entry| entry.0.as_ref() == "sns/records/4099/is2")
                    .unwrap();
                assert_eq!(synthetic.1, &vec![1, 2, 3]);
                let universal = names
                    .iter()
                    .find(|entry| entry.0 == &universal_key)
                    .unwrap();
                use norito::codec::{Decode as _, Encode as _};
                let mut universal_wire = universal.1.as_slice();
                let universal_record =
                    iroha_data_model::sns::NameRecordV1::decode(&mut universal_wire).unwrap();
                assert!(universal_wire.is_empty());
                assert_eq!(universal_record, expected_universal_record);
                assert_eq!(universal_record.encode(), *universal.1);
                assert!(
                    !names
                        .iter()
                        .any(|entry| { entry.0.as_ref() == "customer/private-key-name" }),
                    "unrelated values must be withheld even from the full reader"
                );
                assert!(
                    require_complete_table_count(
                        snapshot,
                        "world.smart_contract_state",
                        keys.len() - 1
                    )
                    .is_err()
                );
                assert!(budget.reserved_bytes() > 0);
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    assert_eq!(
        generation,
        state.state_view_generation(),
        "read-only capture publishes no effects"
    );
    let called = Cell::new(false);
    let error = state
        .with_native_resource_names_snapshot_v1(
            &tip,
            chain.genesis_account(),
            &budget,
            |_, _, _, _| {
                called.set(true);
                Ok(())
            },
        )
        .unwrap_err();
    assert!(
        error.to_string().contains("CanReadAllLedgerData"),
        "{error}"
    );
    assert!(
        !called.get(),
        "registered genesis identity does not imply a read root"
    );
    assert_eq!(budget.reserved_bytes(), 0);
    assert!(
        state
            .with_native_resource_names_snapshot_v1(
                &tip,
                &reader,
                &AllocationBudget::new(0),
                |_, _, _, _| {
                    called.set(true);
                    Ok(())
                }
            )
            .is_err()
    );
    assert!(!called.get());
}

#[test]
fn names_publisher_refuses_retired_cut_and_callback_generation_change() {
    let (mut chain, reader, _) = names_chain();
    let tip = chain.committed(2);
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let state = chain.state();
    let called = Cell::new(false);
    let error = state
        .with_native_resource_names_snapshot_v1(&tip, &reader, &budget, |_, _, _, _| {
            called.set(true);
            let mut publication = state.state_view_publication();
            let _writer = publication.begin();
            Ok(())
        })
        .unwrap_err();
    assert!(called.get());
    assert!(error.to_string().contains("generation changed"), "{error}");
    assert_eq!(budget.reserved_bytes(), 0);
    chain.commit_at(3_000, Vec::new());
    called.set(false);
    assert!(
        chain
            .state()
            .with_native_resource_names_snapshot_v1(&tip, &reader, &budget, |_, _, _, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.get());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn names_read_root_checks_direct_role_and_revocation_without_inferred_grants() {
    use crate::role::RoleIdWithOwner;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{IntoKeyValue, Registrable, account::Account, role::Role};
    use std::collections::BTreeSet;
    let mut world = World::new();
    let reader = AccountId::new(
        KeyPair::from_seed(vec![0x41; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let (id, value) = Account::new(reader.clone()).build(&reader).into_key_value();
    world.accounts.insert(id, value);
    assert!(require_names_read_authority(&world.block(), &reader).is_err());
    let permission: iroha_data_model::permission::Permission =
        iroha_executor_data_model::permission::query::CanReadAllLedgerData.into();
    world
        .account_permissions
        .insert(reader.clone(), BTreeSet::from([permission.clone()]));
    assert!(require_names_read_authority(&world.block(), &reader).is_ok());
    {
        let mut permissions = world.account_permissions.block();
        permissions.remove(reader.clone());
        permissions.commit();
    }
    assert!(require_names_read_authority(&world.block(), &reader).is_err());
    let role_id: iroha_data_model::role::RoleId = "names_reader".parse().unwrap();
    let role = Role::new(role_id.clone(), reader.clone())
        .add_permission(permission)
        .build(&reader);
    world.roles.insert(role_id.clone(), role);
    // An existing role alone is not assignment to the authenticated reader.
    assert!(require_names_read_authority(&world.block(), &reader).is_err());
    let assignment = RoleIdWithOwner::new(reader.clone(), role_id);
    world.account_roles.insert(assignment.clone(), ());
    assert!(require_names_read_authority(&world.block(), &reader).is_ok());
    {
        let mut roles = world.account_roles.block();
        roles.remove(assignment);
        roles.commit();
    }
    assert!(require_names_read_authority(&world.block(), &reader).is_err());
}
