//! Actual prepared World, deferred DA cache and undo controls.
//! These component fixtures do not authorize a consensus carrier or a lifecycle plan.

use super::*;
use crate::{query::store::LiveQueryStore, state::world_projection::WorldStateAccumulator};
use iroha_data_model::{
    account::{AccountDetails, AccountValue},
    da::pin_intent::DaPinIntent,
};

fn fixture() -> (State, iroha_crypto::KeyPair) {
    let key =
        iroha_crypto::KeyPair::try_from_seed(vec![0x93; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let mut world = World::new();
    world.accounts.insert(
        AccountId::new(key.public_key().clone()),
        AccountValue::new(AccountDetails::default()),
    );
    (
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ),
        key,
    )
}

fn intent(
    state: &State,
    key: &iroha_crypto::KeyPair,
    sequence: u64,
    alias: Option<&str>,
) -> DaPinIntent {
    crate::da::signed_test_pin_intent(
        crate::da::signed_test_ingest_authorization(
            *state.network_id_ref(),
            key,
            LaneId::SINGLE,
            1,
            sequence,
            1,
        ),
        key,
        StorageTicketId::new([sequence as u8 + 1; 32]),
        ManifestDigest::new([sequence as u8 + 65; 32]),
        alias.map(str::to_owned),
    )
}

fn pending(intents: Vec<DaPinIntent>) -> PendingDaPinIntentBundle {
    PendingDaPinIntentBundle {
        block_height: 1,
        intents,
        quota_writes: BTreeMap::from([("da/prepared-quota".parse().unwrap(), vec![7])]),
    }
}

fn retail_policy_pair() -> ((StatePath, Vec<u8>), (StatePath, Vec<u8>)) {
    use iroha_data_model::asset::RetailDailyLimitPolicyV1;
    use iroha_model_base::domain::DomainId;

    let issuer =
        iroha_crypto::KeyPair::try_from_seed(vec![0x71; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let reserve =
        iroha_crypto::KeyPair::try_from_seed(vec![0x72; 32], iroha_crypto::Algorithm::Ed25519)
            .unwrap();
    let policy = RetailDailyLimitPolicyV1 {
        asset_definition_id: AssetDefinitionId::derive_from_components(
            DomainId::try_new("kina", "bpng").unwrap(),
            "pgk".parse().unwrap(),
        ),
        physical_dataspace: DataSpaceId::new(7),
        revision: 1,
        daily_cap: Quantity::from(5_u32),
        identity_issuer: AccountId::new(issuer.public_key().clone()),
        identity_issuer_public_key: issuer.public_key().clone(),
        monetary_issuer_account: AccountId::new(issuer.public_key().clone()),
        reserve_account: AccountId::new(reserve.public_key().clone()),
        institutional_exceptions: BTreeSet::new(),
    };
    let activation = retail_daily_limit_state::activation_for_policy(&policy, 1_000).unwrap();
    (
        (
            retail_daily_limit_state::policy_key(
                &policy.asset_definition_id,
                policy.physical_dataspace,
            ),
            norito::encode_canonical(&policy).unwrap(),
        ),
        (
            retail_daily_limit_state::activation_key(&policy.asset_definition_id),
            norito::encode_canonical(&activation).unwrap(),
        ),
    )
}

#[test]
fn retail_policy_commit_refuses_replacement_and_removal_before_publication() {
    let ((policy_path, policy), (activation_path, activation)) = retail_policy_pair();
    let mut replacement: iroha_data_model::asset::RetailDailyLimitPolicyV1 =
        norito::decode_canonical(&policy).unwrap();
    replacement.daily_cap = Quantity::from(6_u32);
    let replacement_activation =
        retail_daily_limit_state::activation_for_policy(&replacement, 1_000).unwrap();
    for (policy_after, activation_after) in [
        (None, Some(activation.clone())),
        (Some(policy.clone()), None),
        (None, None),
        (Some(vec![0]), Some(activation.clone())),
        (Some(policy.clone()), Some(vec![0])),
        (
            Some(norito::encode_canonical(&replacement).unwrap()),
            Some(norito::encode_canonical(&replacement_activation).unwrap()),
        ),
    ] {
        let (mut state, _) = fixture();
        state
            .world
            .smart_contract_state
            .insert(policy_path.clone(), policy.clone());
        state
            .world
            .smart_contract_state
            .insert(activation_path.clone(), activation.clone());
        let nexus = state.nexus_snapshot();
        let activations = state.lane_incarnation_activation_heights_snapshot();
        let mut world = state.world.block();
        for (path, after) in [
            (&policy_path, policy_after),
            (&activation_path, activation_after),
        ] {
            match after {
                Some(bytes) => {
                    world.smart_contract_state.insert(path.clone(), bytes);
                }
                None => {
                    world.smart_contract_state.remove(path.clone());
                }
            }
        }
        let error =
            PreparedWorldCommit::prepare(&state, world, 2, &nexus, &activations, None, None)
                .err()
                .expect("changed established policy pair must not prepare");
        assert!(
            matches!(error, crate::execution_attempt::ExecutionAttemptError::Rejected(ref message)
            if message.contains("cannot be replaced or removed"))
        );
        let current = state.world.smart_contract_state.view();
        assert_eq!(current.get(&policy_path), Some(&policy));
        assert_eq!(current.get(&activation_path), Some(&activation));
    }
}

#[test]
fn retail_policy_commit_accepts_fresh_pair_and_preserves_identical_bytes() {
    let ((policy_path, policy), (activation_path, activation)) = retail_policy_pair();
    let (state, _) = fixture();
    let nexus = state.nexus_snapshot();
    let activations = state.lane_incarnation_activation_heights_snapshot();
    for height in [1, 2] {
        let mut world = state.world.block();
        world
            .smart_contract_state
            .insert(policy_path.clone(), policy.clone());
        world
            .smart_contract_state
            .insert(activation_path.clone(), activation.clone());
        world
            .smart_contract_state
            .insert("unrelated/state".parse().unwrap(), vec![height as u8]);
        // This fixture tests the publication invariant only. It does not
        // authenticate native activation, its owner, or a finalized block.
        PreparedWorldCommit::prepare(&state, world, height, &nexus, &activations, None, None)
            .expect("fresh exact pair or exact retained bytes")
            .commit();
    }
    let current = state.world.smart_contract_state.view();
    assert_eq!(current.get(&policy_path), Some(&policy));
    assert_eq!(current.get(&activation_path), Some(&activation));
}

#[test]
fn retail_policy_commit_refuses_orphan_malformed_and_repaired_predecessor_pairs() {
    let ((policy_path, policy), (activation_path, activation)) = retail_policy_pair();
    for case in 0..4 {
        let (mut state, _) = fixture();
        if case == 3 {
            state
                .world
                .smart_contract_state
                .insert(activation_path.clone(), activation.clone());
        }
        let nexus = state.nexus_snapshot();
        let activations = state.lane_incarnation_activation_heights_snapshot();
        let mut world = state.world.block();
        if case != 1 {
            world.smart_contract_state.insert(
                if case == 2 {
                    "retail_day_policy_v1/wrong".parse().unwrap()
                } else {
                    policy_path.clone()
                },
                policy.clone(),
            );
        }
        if case != 0 {
            world
                .smart_contract_state
                .insert(activation_path.clone(), activation.clone());
        }
        assert!(
            PreparedWorldCommit::prepare(&state, world, 2, &nexus, &activations, None, None,)
                .is_err(),
            "invalid activation pair case {case}"
        );
        assert!(
            state
                .world
                .smart_contract_state
                .view()
                .get(&policy_path)
                .is_none()
        );
    }
}

#[test]
fn authoritative_world_is_identical_with_empty_or_ahead_pin_cache() {
    let mut roots = Vec::new();
    for ahead in [false, true] {
        let (state, key) = fixture();
        let pin = intent(&state, &key, 0, Some("owner/alias"));
        if ahead {
            assert!(state.da_pin_intents.write().insert(
                pin.clone(),
                DaCommitmentLocation {
                    block_height: 99,
                    index_in_bundle: 7
                }
            ));
        }
        let nexus = state.nexus_snapshot();
        let world = state.world.block();
        let parent = WorldStateAccumulator::capture(&world).unwrap();
        let prepared = PreparedWorldCommit::prepare(
            &state,
            world,
            1,
            &nexus,
            &state.lane_incarnation_activation_heights_snapshot(),
            Some(&pending(vec![pin.clone()])),
            None,
        )
        .unwrap();
        assert_eq!(
            prepared.effects.da_pins.len(),
            1,
            "cache content cannot veto an authoritative write"
        );
        // Capacity admission receives the actual nonempty deferred allocation,
        // before either World or cache publication, including its nested alias.
        let retained = prepared.effects.admission_pins();
        assert!(std::ptr::eq(retained, &raw const prepared.effects.da_pins));
        assert_eq!(retained.capacity(), prepared.effects.da_pins.capacity());
        assert_eq!(retained[0].intent, pin);
        assert_eq!(
            state.da_pin_intents.read().len(),
            usize::from(ahead),
            "preparation never publishes cache effects"
        );
        assert!(state.world.da_pin_intents_by_ticket.view().is_empty());
        let next = parent.apply_block(prepared.world()).unwrap();
        assert_eq!(
            next.root(),
            WorldStateAccumulator::capture(prepared.world())
                .unwrap()
                .root()
        );
        let diff = prepared.world().tiered_snapshot_diff();
        assert!(diff.entries().iter().any(|key| matches!(key, TieredKeyHandle::SmartContractState(path) if path.as_ref() == "da/prepared-quota")));
        let payload = prepared.world().tiered_snapshot_payload();
        assert!(TieredSnapshotDiff::from(&payload).entries().iter().any(|key| matches!(key, TieredKeyHandle::SmartContractState(path) if path.as_ref() == "da/prepared-quota")));
        roots.push(next.root());
        prepared.commit();
        assert_eq!(
            next.root(),
            WorldStateAccumulator::capture(&state.world.block())
                .unwrap()
                .root()
        );
        let cache = state.da_pin_intents.read();
        let record = cache.get_by_ticket(&pin.storage_ticket).unwrap();
        assert_eq!(
            record.location,
            DaCommitmentLocation {
                block_height: 1,
                index_in_bundle: 0
            }
        );
        assert_eq!(record.intent, pin);
        assert_eq!(
            cache.get_by_alias("owner/alias").unwrap().0,
            &pin.storage_ticket
        );
    }
    assert_eq!(roots[0], roots[1]);
}

#[test]
fn dropped_and_wrong_height_preparations_leave_world_and_cache_unpublished() {
    let (state, key) = fixture();
    let pin = intent(&state, &key, 0, None);
    let before = WorldStateAccumulator::capture(&state.world.block())
        .unwrap()
        .root();
    let nexus = state.nexus_snapshot();
    let pending = pending(vec![pin]);
    {
        let prepared = PreparedWorldCommit::prepare(
            &state,
            state.world.block(),
            1,
            &nexus,
            &state.lane_incarnation_activation_heights_snapshot(),
            Some(&pending),
            None,
        )
        .unwrap();
        assert!(!prepared.world().da_pin_intents_by_ticket.is_empty());
    }
    assert_eq!(
        before,
        WorldStateAccumulator::capture(&state.world.block())
            .unwrap()
            .root()
    );
    assert_eq!(state.da_pin_intents.read().len(), 0);
    assert!(
        PreparedWorldCommit::prepare(
            &state,
            state.world.block(),
            2,
            &nexus,
            &state.lane_incarnation_activation_heights_snapshot(),
            Some(&pending),
            None,
        )
        .is_err()
    );
    assert_eq!(
        before,
        WorldStateAccumulator::capture(&state.world.block())
            .unwrap()
            .root()
    );
    assert_eq!(state.da_pin_intents.read().len(), 0);
}

#[test]
fn world_identity_indexes_reject_duplicates_even_with_an_empty_cache() {
    let (state, key) = fixture();
    let first = intent(&state, &key, 0, None);
    let next = intent(&state, &key, 1, Some("next"));
    let nexus = state.nexus_snapshot();
    PreparedWorldCommit::prepare(
        &state,
        state.world.block(),
        1,
        &nexus,
        &state.lane_incarnation_activation_heights_snapshot(),
        Some(&pending(vec![first.clone()])),
        None,
    )
    .unwrap()
    .commit();
    *state.da_pin_intents.write() = DaPinStore::default();
    let mut next_pending = pending(vec![first.clone(), next.clone()]);
    next_pending.block_height = 2;
    let prepared = PreparedWorldCommit::prepare(
        &state,
        state.world.block(),
        2,
        &nexus,
        &state.lane_incarnation_activation_heights_snapshot(),
        Some(&next_pending),
        None,
    )
    .unwrap();
    assert_eq!(prepared.effects.da_pins.len(), 1);
    assert_eq!(
        prepared.effects.da_pins[0].intent.storage_ticket,
        next.storage_ticket
    );
    assert_eq!(
        prepared
            .world()
            .da_pin_intents_by_ticket
            .get(&first.storage_ticket)
            .unwrap()
            .location
            .block_height,
        1
    );
    assert_eq!(
        prepared.effects.da_pins[0].location.index_in_bundle, 1,
        "filtered duplicate keeps canonical source positions"
    );
}

fn cleanup_fixture(state: &State, reset: LaneId) -> PendingAutoscaleLaneLifecycle {
    let nexus = state.nexus_snapshot();
    PendingAutoscaleLaneLifecycle {
        catalog_update: LaneLifecycleCatalogUpdate {
            previous_catalog: nexus.lane_catalog.clone(),
            updated_catalog: nexus.lane_catalog.clone(),
            previous_dataspace_catalog: nexus.dataspace_catalog.clone(),
            updated_dataspace_catalog: nexus.dataspace_catalog.clone(),
            previous_routing_policy: nexus.routing_policy.clone(),
            previous_autoscale: nexus.autoscale,
            previous_lane_config: nexus.lane_config.clone(),
            updated_lane_config: nexus.lane_config,
            previous_lane_incarnations: BTreeMap::new(),
            updated_lane_incarnations: BTreeMap::new(),
            previous_lane_incarnation_lineage: BTreeMap::new(),
            updated_lane_incarnation_lineage: BTreeMap::new(),
            previous_lane_incarnation_activation_heights: BTreeMap::new(),
            updated_lane_incarnation_activation_heights: BTreeMap::new(),
            lanes_to_reset: BTreeSet::from([reset]),
            replaced_lane_ids: BTreeSet::new(),
        },
        updated_lane_manifests: state.lane_manifests.read().clone(),
        plan: iroha_data_model::nexus::LaneLifecyclePlan::default(),
        transition: PendingAutoscaleTransition::Manual,
        transition_height: 1,
        expected_incarnation_root: Hash::new(b"component cleanup fixture"),
        runtime_catalog: None,
    }
}

#[test]
fn lifecycle_cleanup_is_in_the_single_overlay_and_its_replacement_undo() {
    let (state, key) = fixture();
    let retired = LaneId::SINGLE;
    let retained = LaneId::new(8);
    let retired_intent = intent(&state, &key, 0, Some("retired-pin"));
    let retained_intent = crate::da::signed_test_pin_intent(
        crate::da::signed_test_ingest_authorization(
            *state.network_id_ref(),
            &key,
            retained,
            1,
            1,
            1,
        ),
        &key,
        StorageTicketId::new([2; 32]),
        ManifestDigest::new([66; 32]),
        Some("retained-pin".into()),
    );
    {
        let mut setup = state.world.block();
        for intent in [&retired_intent, &retained_intent] {
            let ticket = intent.storage_ticket;
            setup.da_pin_intents_by_ticket.insert(
                ticket,
                DaPinIntentWithLocation {
                    intent: intent.clone(),
                    location: iroha_data_model::da::commitment::DaCommitmentLocation {
                        block_height: 1,
                        index_in_bundle: u32::try_from(intent.sequence).unwrap(),
                    },
                },
            );
            setup
                .da_pin_intents_by_manifest
                .insert(intent.manifest_hash, ticket);
            setup
                .da_pin_intents_by_alias
                .insert(intent.alias.clone().unwrap(), ticket);
            setup
                .da_pin_intents_by_lane_epoch
                .insert((intent.lane_id, intent.epoch, intent.sequence), ticket);
        }
        setup.commit();
    }
    let world = state.world.block();
    let parent = WorldStateAccumulator::capture(&world).unwrap();
    let pending = cleanup_fixture(&state, retired);
    let prepared = PreparedWorldCommit::prepare(
        &state,
        world,
        1,
        &state.nexus_snapshot(),
        &state.lane_incarnation_activation_heights_snapshot(),
        None,
        Some(&pending),
    )
    .unwrap();
    let world = prepared.world();
    assert!(
        world
            .da_pin_intents_by_ticket
            .get(&retired_intent.storage_ticket)
            .is_none()
    );
    assert!(
        world
            .da_pin_intents_by_manifest
            .get(&retired_intent.manifest_hash)
            .is_none()
    );
    assert!(world.da_pin_intents_by_alias.get("retired-pin").is_none());
    assert!(
        world
            .da_pin_intents_by_lane_epoch
            .get(&(retired, 1, 0))
            .is_none()
    );
    assert!(
        world
            .da_pin_intents_by_ticket
            .get(&retained_intent.storage_ticket)
            .is_some()
    );
    assert!(
        world
            .da_pin_intents_by_manifest
            .get(&retained_intent.manifest_hash)
            .is_some()
    );
    assert!(world.da_pin_intents_by_alias.get("retained-pin").is_some());
    assert!(
        world
            .da_pin_intents_by_lane_epoch
            .get(&(retained, 1, 1))
            .is_some()
    );
    let next = parent.apply_block(prepared.world()).unwrap();
    prepared.commit();
    assert_eq!(
        next.root(),
        WorldStateAccumulator::capture(&state.world.block())
            .unwrap()
            .root()
    );
    let reverted = state.world.block_and_revert();
    assert_eq!(
        parent.root(),
        WorldStateAccumulator::capture(&reverted).unwrap().root()
    );
}

#[test]
fn canonical_lane_reset_filters_pins_before_world_or_cache_publication() {
    let (state, key) = fixture();
    let pin = intent(&state, &key, 0, None);
    let lifecycle = cleanup_fixture(&state, LaneId::SINGLE);
    let prepared = PreparedWorldCommit::prepare(
        &state,
        state.world.block(),
        1,
        &state.nexus_snapshot(),
        &state.lane_incarnation_activation_heights_snapshot(),
        Some(&pending(vec![pin])),
        Some(&lifecycle),
    )
    .unwrap();
    assert!(prepared.effects.da_pins.is_empty());
    assert!(prepared.world().da_pin_intents_by_ticket.is_empty());
    prepared.commit();
    assert_eq!(state.da_pin_intents.read().len(), 0);
}

#[test]
fn actual_state_commit_publishes_prepared_da_despite_ahead_cache() {
    use std::{
        future::Future,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
    };
    struct ReaderProbe {
        state: Arc<State>,
        calls: AtomicUsize,
        blocked: AtomicUsize,
    }
    impl Wake for ReaderProbe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.state.state_commit_lock.try_lock().is_none()
                || self.state.state_write_lock.try_lock().is_none()
                || self.state.da_pin_intents.try_write().is_none()
            {
                self.blocked.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    let (state, key) = fixture();
    let state = Arc::new(state);
    let mut registrations = [
        crate::unit_test_support::release_registration(&state.ivm_execution_budget()),
        crate::unit_test_support::release_registration(&state.ivm_execution_budget()),
    ];
    let pin = intent(&state, &key, 0, None);
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1,
        0,
    ));
    // State block acquisition hydrates the derived cache from World. Install
    // this contradictory cache only afterward, so the actual publisher must
    // take its collision reconstruction path instead of seeing an empty cache.
    assert!(state.da_pin_intents.write().insert(
        pin.clone(),
        DaCommitmentLocation {
            block_height: 77,
            index_in_bundle: 9,
        },
    ));
    block
        .stage_da_pin_intent_bundle(1, vec![pin.clone()])
        .unwrap();
    let probe = Arc::new(ReaderProbe {
        state: Arc::clone(&state),
        calls: AtomicUsize::new(0),
        blocked: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    let mut context = Context::from_waker(&waker);
    let mut pending: Vec<_> = [
        state
            .world
            .da_pin_intents_by_ticket
            .observe_reader_release(),
        state.world.da_pin_intents_by_alias.observe_reader_release(),
    ]
    .into_iter()
    .zip(registrations.iter_mut())
    .map(|(wait, registration)| Box::pin(wait.wait_for_release(registration)))
    .collect();
    for wait in &mut pending {
        assert!(wait.as_mut().poll(&mut context).is_pending());
    }
    block.commit_empty_block_for_testing().unwrap();
    assert_eq!(probe.calls.load(Ordering::SeqCst), pending.len());
    assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
    for wait in &mut pending {
        assert!(wait.as_mut().poll(&mut context).is_ready());
    }
    let world = state.world.da_pin_intents_by_ticket.view();
    let record = world.get(&pin.storage_ticket).unwrap();
    assert_eq!(record.location.block_height, 1);
    assert_eq!(
        state
            .da_pin_intents
            .read()
            .get_by_ticket(&pin.storage_ticket),
        Some(record)
    );
}

#[test]
fn corrupt_da_quota_refuses_preparation_without_replacing_the_pending_bundle() {
    let (state, key) = fixture();
    let pin = intent(&state, &key, 0, None);
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1,
        0,
    ));
    block
        .stage_da_pin_intent_bundle(1, vec![pin.clone()])
        .unwrap();
    let pending = block.pending_da_pin_intents.as_ref().unwrap();
    let before_intents = pending.intents.clone();
    let before_quota = pending.quota_writes.clone();
    let quota_key = before_quota.keys().next().unwrap().clone();
    block
        .world
        .smart_contract_state
        .insert(quota_key.clone(), vec![0xFF; 129]);
    let error = block.stage_da_pin_intent_bundle(1, vec![pin]).unwrap_err();
    assert!(error.to_string().contains("DA ingest quota preparation"));
    let pending = block.pending_da_pin_intents.as_ref().unwrap();
    assert_eq!(pending.intents, before_intents);
    assert_eq!(pending.quota_writes, before_quota);
    assert_eq!(
        block.world.smart_contract_state.get(&quota_key),
        Some(&vec![0xFF; 129])
    );
    drop(block);
    assert!(
        state
            .world
            .smart_contract_state
            .view()
            .get(&quota_key)
            .is_none()
    );
    assert_eq!(state.committed_height(), 0);
}

#[test]
fn borrowed_world_tail_matches_move_only_preparation_and_retains_publication_records() {
    let (state, key) = fixture();
    let pin = intent(&state, &key, 0, Some("prepared/owner"));
    let pins = pending(vec![pin]);
    let nexus = state.nexus_snapshot();
    let activations = state.lane_incarnation_activation_heights_snapshot();
    let before = WorldStateAccumulator::capture(&state.world.block())
        .unwrap()
        .root();
    let (expected_root, expected_records) = {
        let prepared = PreparedWorldCommit::prepare(
            &state,
            state.world.block(),
            1,
            &nexus,
            &activations,
            Some(&pins),
            None,
        )
        .unwrap();
        (
            WorldStateAccumulator::capture(prepared.world())
                .unwrap()
                .root(),
            prepared.effects.da_pins.clone(),
        )
    };
    assert_eq!(
        WorldStateAccumulator::capture(&state.world.block())
            .unwrap()
            .root(),
        before
    );
    {
        let mut world = state.world.block();
        let effects = PreparedWorldCommit::prepare_overlay(
            &mut world,
            &iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
            1,
            &nexus,
            &activations,
            Some(&pins),
            None,
        )
        .map_err(crate::execution_attempt::expect_completed_rejection)
        .unwrap();
        assert_eq!(effects.da_pins, expected_records);
        assert_eq!(effects.da_pins.len(), 1);
        assert_eq!(
            WorldStateAccumulator::capture(&world).unwrap().root(),
            expected_root
        );
        assert_eq!(state.da_pin_intents.read().len(), 0);
    }
    assert_eq!(
        WorldStateAccumulator::capture(&state.world.block())
            .unwrap()
            .root(),
        before
    );
    assert_eq!(state.da_pin_intents.read().len(), 0);
}

#[test]
fn staged_snapshot_projects_pin_indexes_and_matches_actual_commit() {
    let (state, key) = fixture();
    let pin = intent(&state, &key, 0, Some("snapshot/alias"));
    let mut block = state.block(BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        1,
        0,
    ));
    block
        .stage_da_pin_intent_bundle(1, vec![pin.clone()])
        .unwrap();
    // Compare the same complete metadata cut: commit must not add this fixture's
    // carrier hash and membership only after the expected snapshot is captured.
    block.finalize_axt_asset_incarnations().unwrap();
    block
        .stage_canonical_carrier_membership(Vec::new(), NonZeroUsize::MIN)
        .unwrap();
    let block_hash = block._curr_block.hash();
    block.block_hashes.push(block_hash);
    let expected = crate::snapshot::canonical_staged_state_snapshot_hash(&block);
    let bytes = crate::snapshot::canonical_staged_state_snapshot_bytes(&block);
    assert!(
        String::from_utf8(bytes)
            .unwrap()
            .contains("da_pin_intents_by_ticket")
    );
    assert!(state.world.da_pin_intents_by_ticket.view().is_empty());
    block.commit().unwrap();
    assert_eq!(
        expected,
        crate::snapshot::canonical_state_snapshot_hash(&state)
            .expect("stable valid fixture snapshot")
    );
    assert!(
        state
            .world
            .da_pin_intents_by_ticket
            .view()
            .get(&pin.storage_ticket)
            .is_some()
    );
}

#[test]
fn cold_pin_cache_restores_world_records_without_resurrecting_unbound_aliases() {
    let (state, key) = fixture();
    let pin = intent(&state, &key, 0, Some("formerly/bound"));
    PreparedWorldCommit::prepare(
        &state,
        state.world.block(),
        1,
        &state.nexus_snapshot(),
        &state.lane_incarnation_activation_heights_snapshot(),
        Some(&pending(vec![pin.clone()])),
        None,
    )
    .unwrap()
    .commit();
    {
        let mut world = state.world.block();
        world
            .da_pin_intents_by_alias
            .remove("formerly/bound".to_owned());
        world.commit();
    }
    *state.da_pin_intents.write() = DaPinStore::default();
    *state.da_indexes_hydrated.write() = None;
    state.ensure_da_indexes_hydrated().unwrap();
    let cache = state.da_pin_intents.read();
    assert_eq!(
        cache.get_by_ticket(&pin.storage_ticket).unwrap().intent,
        pin
    );
    assert!(cache.get_by_alias("formerly/bound").is_none());
}

#[test]
fn local_cursor_reset_watermark_cannot_veto_captured_world_admission() {
    let mut roots = Vec::new();
    for local_reset in [0, 99] {
        let (state, key) = fixture();
        let pin = intent(&state, &key, 0, None);
        if local_reset != 0 {
            state
                .da_shard_cursors
                .write()
                .mark_lanes_canonically_reset(&BTreeSet::from([LaneId::SINGLE]), local_reset);
        }
        let captured = state.lane_incarnation_activation_heights_snapshot();
        let prepared = PreparedWorldCommit::prepare(
            &state,
            state.world.block(),
            1,
            &state.nexus_snapshot(),
            &captured,
            Some(&pending(vec![pin.clone()])),
            None,
        )
        .unwrap();
        assert_eq!(
            prepared.effects.da_pins.len(),
            1,
            "operational watermark cannot change admission"
        );
        assert_eq!(
            prepared
                .world()
                .da_pin_intents_by_ticket
                .get(&pin.storage_ticket)
                .unwrap()
                .intent,
            pin
        );
        roots.push(
            WorldStateAccumulator::capture(prepared.world())
                .unwrap()
                .root(),
        );
        drop(prepared);
        let reset_cut = BTreeMap::from([(LaneId::SINGLE, 1)]);
        let rejected = PreparedWorldCommit::prepare(
            &state,
            state.world.block(),
            1,
            &state.nexus_snapshot(),
            &reset_cut,
            Some(&pending(vec![pin])),
            None,
        )
        .unwrap();
        assert!(
            rejected.effects.da_pins.is_empty(),
            "captured canonical activation does retire old pins"
        );
    }
    assert_eq!(roots[0], roots[1]);
}

#[path = "staged_snapshot_tests.rs"]
mod staged_snapshot;
