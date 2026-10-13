//! Native/physical separation and original pre-effect source-custody controls.

use super::*;
use crate::{governance::manifest::LaneManifestRegistry, query::store::LiveQueryStore};
use iroha_data_model::{
    Registrable,
    account::Account,
    block::{BlockExecutionContextBundle, ExternalExecutionContext, builder::BlockBuilder},
    isi::Log,
    parameter::Parameter,
    sumeragi_lanes::{
        SumeragiFixedLane, SumeragiLaneFrontier, SumeragiLaneMergeSection, SumeragiLanePolicy,
        SumeragiLaneRecord, SumeragiLaneRoute, SumeragiLaneState,
    },
    transaction::{FeePaymentIntent, TransactionBuilder, signed::SealedTransactionReveal},
};
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
use std::sync::Arc;

fn state() -> State {
    let mut world = World::with([], [Account::new(ALICE_ID.clone()).build(&ALICE_ID)], []);
    let mut committee = crate::sumeragi::test_chain::fixture_validators()
        .into_iter()
        .map(|(peer, pop)| iroha_data_model::sumeragi_lanes::SumeragiLaneMember { peer, pop })
        .collect::<Vec<_>>();
    committee.sort();
    let policy = SumeragiLanePolicy {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        anchor_freshness: 16,
        max_merge_blocks: 32,
        stall_window: 256,
        lane_params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        fixed: vec![SumeragiFixedLane {
            lane: LaneId::new(1),
            dataspace: DataSpaceId::UNIVERSAL,
            committee: committee.clone(),
        }],
        routes: vec![SumeragiLaneRoute {
            lane: LaneId::new(1),
            account: Some(ALICE_ID.to_string()),
            instruction: None,
        }],
        autoscale: None,
    };
    policy.validate().expect("valid native policy fixture");
    // Component setup supplies committed native policy/state, not a certificate substitute.
    let mut parameters = world.parameters.view().get().clone();
    parameters
        .set_parameter(Parameter::Custom(policy.into_custom_parameter()))
        .expect("valid fixture parameters");
    parameters
        .set_parameter(crate::sumeragi::lanes::routing::test_support::metadata(
            SumeragiRootScope::Global,
        ))
        .expect("valid fixture parameters");
    world.parameters = mv::cell::Cell::new(parameters);
    let mut lanes = SumeragiLaneState::default();
    lanes.upsert(SumeragiLaneRecord {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        lane: LaneId::new(1),
        dataspace: DataSpaceId::UNIVERSAL,
        incarnation: Hash::new(b"native ordering identity").into(),
        params: iroha_data_model::parameter::system::SumeragiParameters::default(),
        committee,
        created_at: 1,
        active_from: 3,
        closing: None,
        anchor_freshness: 16,
        merged: SumeragiLaneFrontier::default(),
        merged_at: 3,
        rescued: 0,
    });
    world.sumeragi_lanes = mv::cell::Cell::new(lanes);
    let state = State::new_for_testing(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let nexus = state.nexus_snapshot();
    let registry =
        LaneManifestRegistry::from_config(&nexus.lane_catalog, &nexus.governance, &nexus.registry);
    registry
        .validate_materialized_authority_for_catalog(&nexus.lane_catalog, &nexus.governance)
        .unwrap();
    state.install_lane_manifests_for_testing(&Arc::new(registry));
    state
}

fn input(state: &State, label: &str) -> TransactionEntrypoint {
    TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([Log::new(iroha_data_model::Level::INFO, label.to_owned())])
    .sign(ALICE_KEYPAIR.private_key())
    .into()
}

fn source(
    inputs: Vec<TransactionEntrypoint>,
    height: u64,
    contexts: Option<Vec<ExternalExecutionContext>>,
) -> SignedBlock {
    let mut builder = BlockBuilder::new(BlockHeader::new(
        height.try_into().unwrap(),
        None,
        None,
        1000,
        0,
    ));
    for input in inputs {
        match input {
            TransactionEntrypoint::External(signed) => {
                builder.push_transaction(signed);
            }
            TransactionEntrypoint::SealedReveal(reveal) => {
                builder.push_sealed_transaction_reveal(reveal);
            }
            TransactionEntrypoint::SealedCommitment(commitment) => {
                builder.push_sealed_transaction_commitment(commitment);
            }
        }
    }
    builder.set_execution_context(contexts.map(BlockExecutionContextBundle::new));
    builder.build_with_signature(0, ALICE_KEYPAIR.private_key())
}

fn carrier(inputs: Vec<TransactionEntrypoint>) -> SignedBlock {
    let contexts = inputs
        .iter()
        .map(|input| {
            ExternalExecutionContext::new(input.hash(), LaneId::new(1), DataSpaceId::UNIVERSAL)
        })
        .collect();
    source(inputs, 4, Some(contexts))
}

fn before_effects(
    state: &State,
    source: &SignedBlock,
    replacement: bool,
    check: impl FnOnce(&mut StateBlock<'_>),
) {
    let stage_update = |block: &mut StateBlock<'_>| {
        assert!(!block.start_of_block_effects_applied);
        check(block);
        Err::<(), _>("examined pristine owner")
    };
    let result = if replacement {
        state
            .block_and_revert_with_pristine_carrier_stage(source, stage_update)
            .map(|_| ())
    } else {
        state
            .block_with_owned_start_stages_with_carrier(
                source.header(),
                Some(source),
                stage_update,
                |_, ()| Ok(()),
            )
            .map(|_| ())
    };
    assert!(matches!(
        result,
        Err(StateBlockStartError::Stage("examined pristine owner"))
    ));
}

#[test]
fn native_ordering_lane_uses_independently_resolved_physical_policy() {
    let state = state();
    let source = carrier(vec![input(&state, "independent namespaces")]);
    before_effects(&state, &source, false, |block| {
        let (native, token) = block
            .network_policy_routes
            .as_ref()
            .unwrap()
            .get(&source, 0)
            .unwrap();
        assert_eq!(
            native,
            RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL)
        );
        assert_eq!(
            token.physical().unwrap().decision(),
            RoutingDecision::default()
        );
        let TransactionEntrypoint::External(signed) = source.network_entrypoint_at(0).unwrap()
        else {
            unreachable!()
        };
        let mut tx = block.transaction();
        StateBlock::validate_stateful_admission(signed, &mut tx, native, token, None).unwrap();
        assert_eq!(tx.current_lane_id, Some(LaneId::new(1)));
        assert_eq!(tx.current_dataspace_id, Some(DataSpaceId::UNIVERSAL));
    });
}

#[test]
fn normal_and_replacement_routes_are_frozen_before_every_prefix_hook() {
    for replacement in [false, true] {
        let state = state();
        let source = carrier(vec![input(&state, "first"), input(&state, "second")]);
        before_effects(&state, &source, replacement, |block| {
            let first = block
                .network_policy_routes
                .as_ref()
                .unwrap()
                .get(&source, 1)
                .unwrap();
            block.nexus.routing_policy.default_lane = LaneId::new(99);
            block
                .world
                .sumeragi_lanes
                .get_mut()
                .lane_mut(LaneId::new(1))
                .unwrap()
                .closing = Some(3);
            let second = block
                .network_policy_routes
                .as_ref()
                .unwrap()
                .get(&source, 1)
                .unwrap();
            assert_eq!(first.0, second.0);
            assert_eq!(first.1.physical(), second.1.physical());
            assert_eq!(
                second.1.physical().unwrap().decision().lane_id,
                LaneId::SINGLE
            );
            let accepted = AcceptedTransaction::new_unchecked_entrypoint(Cow::Borrowed(
                source.network_entrypoint_at(1).unwrap(),
            ));
            assert!(
                PhysicalExecutionPolicyRoute::resolve(&block.nexus, &block.world, &accepted, 3, 0)
                    .is_err()
            );
        });
    }
}

#[test]
fn source_owner_rejects_missing_context_and_every_noncanonical_native_field() {
    let state = state();
    let entry = input(&state, "context");
    let valid = ExternalExecutionContext::new(entry.hash(), LaneId::new(1), DataSpaceId::UNIVERSAL);
    for mutation in 0..7 {
        let mut changed = valid.clone();
        match mutation {
            0 => {}
            1 => changed.entrypoint_hash = HashOf::from_untyped_unchecked(Hash::new(b"foreign")),
            2 => changed.lane_id = LaneId::new(7),
            3 => changed.dataspace_id = DataSpaceId::new(9),
            4 => changed.routing_plan_digest = Hash::new(b"foreign plan"),
            5 => changed.routing_plan_legs.clear(),
            6 => changed.routing_plan_legs[0].role = ExternalExecutionRouteRole::Participant,
            _ => unreachable!(),
        }
        let source = source(
            vec![entry.clone()],
            4,
            if mutation == 0 {
                None
            } else {
                Some(vec![changed])
            },
        );
        before_effects(&state, &source, false, |block| {
            assert!(
                block
                    .network_policy_routes
                    .as_ref()
                    .unwrap()
                    .get(&source, 0)
                    .is_err()
            );
        });
    }
    let source = source(vec![entry], 4, Some(vec![valid]));
    before_effects(&state, &source, false, |block| {
        assert!(
            block
                .network_policy_routes
                .as_ref()
                .unwrap()
                .get(&source, 0)
                .is_ok()
        )
    });
}

#[test]
fn native_activation_and_closure_are_checked_at_the_exact_predecessor_height() {
    for (height, closing, valid) in [
        (3, None, false),
        (4, None, true),
        (4, Some(3), false),
        (4, Some(4), true),
    ] {
        let state = state();
        let mut lanes = state.world.sumeragi_lanes.block();
        lanes.get_mut().lane_mut(LaneId::new(1)).unwrap().closing = closing;
        lanes.commit();
        let entry = input(&state, "native activation");
        let source = source(
            vec![entry.clone()],
            height,
            Some(vec![ExternalExecutionContext::new(
                entry.hash(),
                LaneId::new(1),
                DataSpaceId::UNIVERSAL,
            )]),
        );
        before_effects(&state, &source, false, |block| {
            assert_eq!(
                block
                    .network_policy_routes
                    .as_ref()
                    .unwrap()
                    .get(&source, 0)
                    .is_ok(),
                valid
            )
        });
    }
}

#[test]
fn physical_dataspace_mismatch_is_a_transaction_refusal_not_a_carrier_failure() {
    let state = state();
    let mut lanes = state.world.sumeragi_lanes.block();
    lanes.get_mut().lane_mut(LaneId::new(1)).unwrap().dataspace = DataSpaceId::new(7);
    lanes.commit();
    let entry = input(&state, "dataspace mismatch");
    let source = source(
        vec![entry.clone()],
        4,
        Some(vec![ExternalExecutionContext::new(
            entry.hash(),
            LaneId::new(1),
            DataSpaceId::new(7),
        )]),
    );
    before_effects(&state, &source, false, |block| {
        let (native, token) = block
            .network_policy_routes
            .as_ref()
            .unwrap()
            .get(&source, 0)
            .unwrap();
        assert!(matches!(
            token.projection,
            PolicyProjection::Signed(Err(PhysicalPolicyRouteRejection::DataspaceMismatch))
        ));
        let TransactionEntrypoint::External(signed) = &entry else {
            unreachable!()
        };
        let tx = block.transaction();
        assert!(matches!(
            token.for_signed(signed, &tx, native),
            Err(ExecutionAttemptError::Rejected(
                TransactionRejectionReason::Validation(_)
            ))
        ));
    });
}

#[test]
fn missing_physical_route_is_retained_as_bounded_ordinary_rejection() {
    let state = state();
    // Seed the malformed route in its canonical owner; the process-local Nexus cache
    // is not the authority from which block acquisition projects routing policy.
    let mut runtime = state.canonical_runtime.view().get().clone();
    runtime.owner_policy.routing_default_lane = LaneId::new(99);
    state
        .canonical_runtime
        .replace_current_preserving_predecessor(runtime);
    let source = carrier(vec![input(&state, "missing physical lane")]);
    before_effects(&state, &source, false, |block| {
        let (_, token) = block
            .network_policy_routes
            .as_ref()
            .unwrap()
            .get(&source, 0)
            .unwrap();
        assert!(matches!(token.projection, PolicyProjection::Signed(Err(_))));
        assert!(!std::mem::needs_drop::<SourceRow>());
    });
}

#[test]
fn original_source_hash_order_and_carrier_are_required() {
    let state = state();
    let a = input(&state, "a");
    let b = input(&state, "b");
    let source = carrier(vec![a.clone(), b.clone()]);
    let foreign = carrier(vec![b, a]);
    before_effects(&state, &source, false, |block| {
        let owner = block.network_policy_routes.as_ref().unwrap();
        assert!(owner.get(&source, 0).is_ok());
        assert!(owner.get(&source, 1).is_ok());
        assert!(owner.get(&source, 2).is_err());
        assert!(owner.get(&foreign, 0).is_err());
        assert!(owner.get(&foreign, 1).is_err());
        // Original owner capture is write-once even with the same valid source.
        let mut owner = block.network_policy_routes.take().unwrap();
        let retained_rows = owner.rows.as_slice().len();
        owner
            .fill_from_preblock(block, &source)
            .expect("completed capture attempt");
        assert_eq!(
            owner.validate_carrier(&source),
            Err("physical policy capture is not repeatable")
        );
        assert!(owner.get(&source, 0).is_err());
        owner
            .fill_from_preblock(block, &foreign)
            .expect("completed capture attempt");
        owner
            .fill_from_preblock(block, &source)
            .expect("completed capture attempt");
        assert_eq!(
            owner.validate_carrier(&source),
            Err("physical policy capture is not repeatable")
        );
        assert_eq!(owner.rows.as_slice().len(), retained_rows);
    });
}

#[test]
fn actual_merged_suffix_receives_original_ordinal_and_policy_rows() {
    let state = state();
    let a = input(&state, "ordinary");
    let b = input(&state, "merged");
    let mut builder = BlockBuilder::new(BlockHeader::new(
        4_u64.try_into().unwrap(),
        None,
        None,
        1000,
        0,
    ));
    let TransactionEntrypoint::External(signed) = a.clone() else {
        unreachable!()
    };
    builder.push_transaction(signed);
    let mut context = BlockExecutionContextBundle::new(vec![ExternalExecutionContext::new(
        a.hash(),
        LaneId::new(1),
        DataSpaceId::UNIVERSAL,
    )]);
    context.lane_merge = Some(SumeragiLaneMergeSection {
        merges: vec![],
        time_floor_ms: 0,
        merged_count: 0,
    });
    builder.set_execution_context(Some(context));
    let source = builder
        .build_with_signature(0, ALICE_KEYPAIR.private_key())
        .with_merged_entrypoints(
            vec![b.clone()],
            vec![ExternalExecutionContext::new(
                b.hash(),
                LaneId::new(1),
                DataSpaceId::UNIVERSAL,
            )],
        )
        .unwrap();
    assert_eq!(source.merged_entrypoint_count(), 1);
    before_effects(&state, &source, false, |block| {
        let owner = block.network_policy_routes.as_ref().unwrap();
        assert_eq!(owner.rows.as_slice().len(), 2);
        assert_eq!(owner.rows.as_slice()[0].entrypoint, a.hash());
        assert_eq!(owner.rows.as_slice()[1].entrypoint, b.hash());
        assert_eq!(
            owner
                .get(&source, 1)
                .unwrap()
                .1
                .physical()
                .unwrap()
                .decision(),
            RoutingDecision::default()
        );
    });
}

#[test]
fn sealed_reveal_policy_uses_inner_fields_but_retains_outer_source_binding() {
    let state = state();
    let TransactionEntrypoint::External(signed) = input(&state, "sealed inner") else {
        unreachable!()
    };
    let reveal = TransactionEntrypoint::SealedReveal(SealedTransactionReveal::new(
        Hash::new(b"commitment"),
        signed.clone(),
        [7; 32],
    ));
    let source = carrier(vec![reveal.clone()]);
    before_effects(&state, &source, false, |block| {
        let owner = block.network_policy_routes.as_ref().unwrap();
        assert_eq!(owner.rows.as_slice()[0].entrypoint, reveal.hash());
        let (native, token) = owner.get(&source, 0).unwrap();
        assert_eq!(token.signed_hash, Some(signed.hash()));
        block.nexus.routing_policy.default_lane = LaneId::new(99);
        let tx = block.transaction();
        assert_eq!(
            token.for_signed(&signed, &tx, native).unwrap().decision(),
            RoutingDecision::default()
        );
        let TransactionEntrypoint::External(foreign) = input(&state, "foreign") else {
            unreachable!()
        };
        assert!(token.for_signed(&foreign, &tx, native).is_err());
        assert!(
            token
                .for_signed(&signed, &tx, RoutingDecision::default())
                .is_err()
        );
    });
}

#[test]
fn policy_rows_remain_charged_until_the_original_block_owner_drops() {
    let state = state();
    let source = carrier(vec![input(&state, "charge a"), input(&state, "charge b")]);
    let bytes = std::alloc::Layout::array::<SourceRow>(2).unwrap().size();
    let budget = AllocationBudget::new(bytes);
    let owner = CapturedNetworkPolicyRoutes::reserve(&source, &budget).unwrap();
    assert_eq!(budget.reserved_bytes(), bytes);
    assert!(owner.validate_carrier(&source).is_err());
    assert!(CapturedNetworkPolicyRoutes::reserve(&source, &budget).is_err());
    drop(owner);
    assert_eq!(budget.reserved_bytes(), 0);
    let refused = CapturedNetworkPolicyRoutes::reserve(&source, &AllocationBudget::new(bytes - 1));
    assert!(refused.is_err());
}

#[test]
fn only_genesis_carries_explicit_bootstrap_policy_and_normal_scope_has_no_fallback() {
    let state = state();
    let entry = input(&state, "bootstrap");
    let genesis = crate::sumeragi::test_chain::signed_genesis_fixture(
        &state.chain_id,
        &ALICE_KEYPAIR,
        &crate::sumeragi::test_chain::fixture_validators(),
        vec![Log::new(iroha_data_model::Level::INFO, "bootstrap".to_owned()).into()],
        1_000,
        iroha_data_model::parameter::system::ConsensusMode::Permissioned,
        None,
    )
    .unwrap();
    before_effects(&state, &genesis, false, |block| {
        let (native, token) = block
            .network_policy_routes
            .as_ref()
            .unwrap()
            .get(&genesis, 0)
            .unwrap();
        assert_eq!(native, RoutingDecision::default());
        assert!(matches!(
            token.projection,
            PolicyProjection::Genesis(SumeragiRootScope::Global)
        ));
    });
    let absent = state.block(carrier(vec![entry]).header());
    assert!(absent.network_policy_routes.is_none());
}

#[test]
fn missing_governed_and_private_physical_manifests_cannot_use_native_number_collision() {
    use crate::governance::manifest::LaneManifestStatus;
    use iroha_data_model::nexus::{LaneStorageProfile, LaneVisibility};
    for (governance, storage) in [
        (None, LaneStorageProfile::FullReplica),
        (Some("required".to_owned()), LaneStorageProfile::FullReplica),
        (None, LaneStorageProfile::CommitmentOnly),
    ] {
        let state = state();
        let source = carrier(vec![input(&state, "physical manifest denial")]);
        before_effects(&state, &source, false, |block| {
            let (native, token) = block
                .network_policy_routes
                .as_ref()
                .unwrap()
                .get(&source, 0)
                .unwrap();
            let native_status = LaneManifestStatus {
                lane: LaneId::new(1),
                alias: "unrelated native number".into(),
                dataspace: DataSpaceId::UNIVERSAL,
                visibility: LaneVisibility::Public,
                storage: LaneStorageProfile::FullReplica,
                governance: None,
                manifest_path: None,
                governance_rules: None,
                privacy_commitments: vec![],
            };
            let mut statuses = BTreeMap::from([(LaneId::new(1), native_status.clone())]);
            if governance.is_some() || storage != LaneStorageProfile::FullReplica {
                statuses.insert(
                    LaneId::SINGLE,
                    LaneManifestStatus {
                        lane: LaneId::SINGLE,
                        alias: "actual physical policy".into(),
                        governance,
                        storage,
                        ..native_status
                    },
                );
            }
            block.lane_manifests = Arc::new(LaneManifestRegistry::from_statuses(statuses));
            assert!(
                block
                    .lane_manifests
                    .ensure_lane_ready(native.lane_id)
                    .is_ok()
            );
            assert!(
                block
                    .lane_manifests
                    .ensure_lane_ready(LaneId::SINGLE)
                    .is_err()
            );
            let TransactionEntrypoint::External(signed) = source.network_entrypoint_at(0).unwrap()
            else {
                unreachable!()
            };
            let mut tx = block.transaction();
            assert!(matches!(
                StateBlock::validate_stateful_admission(signed, &mut tx, native, token, None),
                Err(TransactionRejectionReason::Validation(_))
            ));
            assert_eq!(tx.current_lane_id, Some(native.lane_id));
        });
    }
}

#[test]
fn allocation_refusal_precedes_normal_and_replacement_pristine_callbacks() {
    for replacement in [false, true] {
        let state = state();
        let source = carrier(vec![input(&state, "prepaid refusal")]);
        let budget = state.ivm_execution_budget();
        let before = budget.reserved_bytes();
        budget.set_limit_bytes(before);
        let stage_update = |_: &mut StateBlock<'_>| -> Result<(), &'static str> {
            panic!("allocation refusal cannot enter a pristine callback")
        };
        let result = if replacement {
            state
                .block_and_revert_with_pristine_carrier_stage(&source, stage_update)
                .map(|_| ())
        } else {
            state
                .block_with_owned_start_stages_with_carrier(
                    source.header(),
                    Some(&source),
                    stage_update,
                    |_, ()| Ok(()),
                )
                .map(|_| ())
        };
        assert!(matches!(
            result,
            Err(StateBlockStartError::ExecutionDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), before);
        assert_eq!(state.committed_height(), 0);
    }
}

#[test]
fn height_one_ordinary_carrier_cannot_acquire_genesis_bootstrap_authority() {
    let state = state();
    let forged = source(
        vec![input(&state, "ordinary domain is not genesis")],
        1,
        None,
    );
    before_effects(&state, &forged, false, |block| {
        assert_eq!(
            block
                .network_policy_routes
                .as_ref()
                .unwrap()
                .validate_carrier(&forged),
            Err("Network genesis has no authenticated original authority"),
        );
    });
}

#[test]
fn genesis_scope_comes_from_original_signed_body_and_private_bootstrap_stays_scoped() {
    let state = state(); // Its synthetic committed metadata deliberately says Global.
    let own = DataSpaceId::new((1_u64 << 40) + 9);
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: state.network_id,
        dataspace_id: own,
    };
    let genesis = crate::sumeragi::lanes::routing::test_support::signed_genesis(scope);
    before_effects(&state, &genesis, false, |block| {
        let (native, token) = block
            .network_policy_routes
            .as_ref()
            .unwrap()
            .get(&genesis, 0)
            .unwrap();
        assert_eq!(native, RoutingDecision::new(LaneId::SINGLE, own));
        assert!(matches!(token.projection, PolicyProjection::Genesis(actual) if actual == scope));
        let TransactionEntrypoint::External(signed) = genesis.network_entrypoint_at(0).unwrap()
        else {
            unreachable!()
        };
        let tx = block.transaction();
        assert!(
            token.for_signed(signed, &tx, native).is_err(),
            "private genesis cannot use the universal physical default"
        );
    });
}

#[test]
fn ordinary_capture_requires_immutable_metadata_even_with_valid_lane_policy() {
    let state = state();
    let source = carrier(vec![input(&state, "no scope fallback")]);
    before_effects(&state, &source, false, |block| {
        let mut parameters = block.world.parameters.get().clone();
        parameters
            .set_parameter(Parameter::Custom(
                iroha_data_model::parameter::custom::CustomParameter::new(
                    iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id(),
                    iroha_primitives::json::Json::from_norito_value_ref(
                        &norito::json::Value::Bool(false),
                    )
                    .unwrap(),
                ),
            ))
            .expect("valid fixture parameters");
        *block.world.parameters.get_mut() = parameters;
        let budget = AllocationBudget::new(1024 * 1024);
        let mut owner = CapturedNetworkPolicyRoutes::reserve(&source, &budget).unwrap();
        owner
            .fill_from_preblock(block, &source)
            .expect("completed capture attempt");
        assert_eq!(
            owner.validate_carrier(&source),
            Err("Network source has no immutable root scope")
        );
    });
}

#[test]
fn genesis_instruction_capability_requires_both_signed_route_and_exact_authenticated_input() {
    let state = state();
    let genesis =
        crate::sumeragi::lanes::routing::test_support::signed_genesis(SumeragiRootScope::Global);
    let authenticated =
        crate::block::authenticate_genesis_block_intents(&genesis, &ALICE_ID).unwrap();
    let original = authenticated.transaction_for(&genesis, 0).unwrap();
    before_effects(&state, &genesis, false, |block| {
        let (_, route) = block
            .network_policy_routes
            .as_ref()
            .unwrap()
            .get(&genesis, 0)
            .unwrap();
        let TransactionEntrypoint::External(signed) = genesis.network_entrypoint_at(0).unwrap()
        else {
            unreachable!()
        };
        let mut tx = block.transaction();
        tx.current_network_entrypoint_hash = Some(signed.hash_as_entrypoint());
        tx.current_entrypoint_index = Some(0);
        assert!(route.genesis_execution_scope(signed, &tx, None).is_err());
        let capability = route
            .genesis_execution_scope(signed, &tx, Some(&original))
            .unwrap()
            .unwrap();
        assert_eq!(
            capability.for_transaction(&tx),
            Some(SumeragiRootScope::Global)
        );
        tx.genesis_execution_scope = Some(capability);
        assert_eq!(
            crate::executor::root_scope::execution_root_scope(&mut tx).unwrap(),
            SumeragiRootScope::Global
        );
        let log: iroha_data_model::isi::InstructionBox = Log::new(
            iroha_data_model::Level::INFO,
            "authenticated bootstrap".into(),
        )
        .into();
        crate::executor::Executor::Initial
            .execute_instruction(&mut tx, &ALICE_ID, log)
            .unwrap();
        tx.current_entrypoint_index = Some(1);
        assert!(crate::executor::root_scope::execution_root_scope(&mut tx).is_err());
        assert!(
            route
                .genesis_execution_scope(signed, &tx, Some(&original))
                .is_err()
        );
        tx.current_entrypoint_index = Some(0);
        tx.current_network_entrypoint_hash = Some(HashOf::from_untyped_unchecked(Hash::new(
            b"substituted genesis input",
        )));
        assert!(crate::executor::root_scope::execution_root_scope(&mut tx).is_err());
    });
}

/// Observe the original root decoder's cumulative allocation without adding a production preflight.
fn original_routing_root_allocation(state: &StateBlock<'_>) -> usize {
    const CEILING: usize = 1 << 20;
    norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, CEILING, 32),
        || {
            assert_eq!(
                crate::sumeragi::lanes::routing::read_committed_root_scope(&state.world).unwrap(),
                Some(SumeragiRootScope::Global)
            );
            let norito::Error::TotalAllocationExceeded { attempted, limit } =
                norito::core::reserve_decode_allocation(CEILING + 1).unwrap_err()
            else {
                panic!("original root allocation observation changed");
            };
            assert_eq!(limit, CEILING as u64);
            usize::try_from(attempted).unwrap() - CEILING - 1
        },
    )
}

fn original_routing_capture_refusal(allocation: Option<usize>) {
    let state = state();
    let source = carrier(vec![input(&state, "retry exact native routing carrier")]);
    before_effects(&state, &source, false, |block| {
        let root_id = iroha_data_model::parameter::system::consensus_metadata::handshake_meta_id();
        let policy_id = SumeragiLanePolicy::parameter_id();
        let root_bytes = block
            .world
            .parameters()
            .custom()
            .get(&root_id)
            .unwrap()
            .payload()
            .get()
            .to_owned();
        let policy_bytes = block
            .world
            .parameters()
            .custom()
            .get(&policy_id)
            .unwrap()
            .payload()
            .get()
            .to_owned();
        let limit = allocation.unwrap_or_else(|| original_routing_root_allocation(block));
        let budget = AllocationBudget::new(1 << 20);
        let mut owner = CapturedNetworkPolicyRoutes::reserve(&source, &budget).unwrap();
        let result = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 32),
            || owner.fill_from_preblock(block, &source),
        );
        let reason = result
            .expect_err("unfinished original routing read cannot produce a completed physical row");
        assert_eq!(
            reason.reason(),
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity
        );
        assert!(owner.rows.as_slice().is_empty());
        assert!(
            owner.invalid_context.is_none(),
            "local pressure cannot become invalid source context"
        );
        assert_eq!(
            block
                .world
                .parameters()
                .custom()
                .get(&root_id)
                .unwrap()
                .payload()
                .get(),
            &root_bytes
        );
        assert_eq!(
            block
                .world
                .parameters()
                .custom()
                .get(&policy_id)
                .unwrap()
                .payload()
                .get(),
            &policy_bytes
        );
        let snapshot_refusal = norito::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, limit, 32),
            || crate::sumeragi::lanes::routing::RoutingSnapshot::of(block).unwrap_err(),
        );
        assert_eq!(snapshot_refusal, reason);
        drop(owner);
        let snapshot = crate::sumeragi::lanes::routing::RoutingSnapshot::of(block).unwrap();
        assert_eq!(snapshot.policy().unwrap().fixed[0].lane, LaneId::new(1));
        let mut retry = CapturedNetworkPolicyRoutes::reserve(&source, &budget).unwrap();
        retry.fill_from_preblock(block, &source).unwrap();
        assert!(retry.validate_carrier(&source).is_ok());
        let (native, route) = retry.get(&source, 0).unwrap();
        assert_eq!(
            native,
            RoutingDecision::new(LaneId::new(1), DataSpaceId::UNIVERSAL)
        );
        assert_eq!(route.physical().unwrap().decision().lane_id, LaneId::new(0));
    });
}

#[test]
fn original_root_scope_read_refusal_does_not_publish_invalid_native_context() {
    original_routing_capture_refusal(Some(0));
}

#[test]
fn original_lane_policy_read_refusal_after_root_keeps_exact_capture_retryable() {
    original_routing_capture_refusal(None);
}
