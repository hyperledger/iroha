//! Real paid native transfer and original funded World publication of public pool facts.
//!
//! The fixture seeds a valid empty pool through the native bootstrap planner, then certifies
//! an ordinary paid transfer. It does not synthesize a spent note or a proof of settlement.

use super::*;
use crate::private_settlement::{
    global_state::plan_private_settlement_pool_bootstrap_v1,
    state::PrivateSettlementPoolStateExtV1 as _,
};
use crate::state::{State, WorldStateSnapshotError};
use iroha_allocation::AllocationRefusal;
use iroha_crypto::Hash;
use iroha_data_model::{
    nexus::{
        PrivateSettlementPoolCutProofV1, PrivateSettlementPoolGovernanceLifecycleV1,
        PrivateSettlementPoolGovernanceProjectionV1, PrivateSettlementPoolKeyV1,
        PrivateSettlementRouteV1,
    },
    privacy::{PrivacyCommitmentV1, PrivacyNullifierV1, PrivacyPoolIdV1},
    sumeragi_finality::{FinalityValidator, SumeragiFinalityVerifier, VerifiedSumeragiBlock},
};
use iroha_model_base::topology::LaneId;
use mv::storage::AdmittedStorageError;
use std::{
    cell::Cell,
    task::{Context, Waker},
};

fn fixture() -> (CertifiedTestChain, PrivateSettlementPoolKeyV1) {
    fixture_with_assignment(false)
}
fn fixture_with_assignment(assignment: bool) -> (CertifiedTestChain, PrivateSettlementPoolKeyV1) {
    let mut config = paid_global_config();
    let key = PrivateSettlementPoolKeyV1 {
        route: PrivateSettlementRouteV1 {
            dataspace_id: FIRST,
            lane_id: LaneId::new(17),
            lane_incarnation: Hash::new(b"private public-cut lane incarnation"),
        },
        pool_id: PrivacyPoolIdV1::new([0xD4; 32]),
    };
    if assignment {
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
    let owner = account(&global_config().genesis_key);
    let recipient = account(&KeyPair::from_seed(vec![0xCC; 32], Algorithm::Ed25519));
    let source = AssetId::with_scope(fee_asset(), owner.clone(), AssetBalanceScope::Global);
    let signed = paid_global_sign(
        &chain,
        [Transfer::asset_quantity(source.clone(), 1_u32, recipient.clone()).into()],
        1_999,
    );
    assert_eq!(chain.commit_at(2_000, vec![signed]), vec![true]);
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
    (chain, key)
}

fn verified_tip(chain: &CertifiedTestChain) -> VerifiedSumeragiBlock {
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
        chain.state().chain_id_ref().as_str(),
        validators,
    )
    .unwrap();
    let view = chain.state().view();
    let mut last = None;
    for height in 1..=chain.height() {
        last = Some(
            verifier
                .verify(&crate::sumeragi::finality::build_proof(&view, height).unwrap())
                .unwrap(),
        );
    }
    last.unwrap()
}

#[test]
fn private_pool_cut_borrows_real_paid_native_world_and_authenticates_selected_rows() {
    let (chain, key) = fixture();
    let _epoch = crossbeam_epoch::pin();
    let state = chain.state();
    let tip = chain.committed(chain.height());
    let execution = state.ivm_execution_budget();
    let initial = execution.reserved_bytes();
    let request = AllocationBudget::new(32 * 1024 * 1024);
    assert!(!execution.same_pool(&request));
    let (bytes, charge) = state
        .with_native_private_settlement_pool_snapshot_v1(&tip, key, &request, |borrowed| {
            assert!(
                execution.reserved_bytes() > initial,
                "original World acquisition retains its own funded owner"
            );
            assert!(
                request.reserved_bytes() > 0,
                "snapshot entries retain the request owner"
            );
            let size = norito::canonical_frame_len(&borrowed).map_err(|error| error.to_string())?;
            let charge = request
                .try_reserve_bytes(size)
                .map_err(|error| error.to_string())?;
            assert!(charge.belongs_to(&request));
            Ok((
                norito::encode_canonical(&borrowed).map_err(|error| error.to_string())?,
                charge,
            ))
        })
        .unwrap();
    assert_eq!(execution.reserved_bytes(), initial);
    assert_eq!(request.reserved_bytes(), bytes.len());
    let proof = PrivateSettlementPoolCutProofV1::decode_frame(&bytes).unwrap();
    assert_eq!(
        proof.world.root().unwrap(),
        tip.commitment().execution.world_state_root
    );
    drop(bytes);
    drop(charge);
    assert_eq!(request.reserved_bytes(), 0);
    let block = verified_tip(&chain);
    let cut = proof
        .verify(
            chain.network_id(),
            crate::state::State::native_world_schema_hash_v1().unwrap(),
            key,
            &block,
        )
        .unwrap();
    assert_eq!(cut.height(), 2);
    assert_eq!(cut.key(), key);
    cut.pool().validate().unwrap();
    assert_eq!(cut.pool().tree_size, 0);
    assert_eq!(
        cut.governance().governance_digest,
        cut.pool().restricted_pool_policy_digest()
    );
    cut.verify_nullifier_absent(PrivacyNullifierV1::new([0xD5; 32]))
        .unwrap();
    cut.verify_output_absent(PrivacyCommitmentV1::new([0xD6; 32]))
        .unwrap();
    // No native private spend was fabricated: this fixture proves only public rows and absence.
    assert!(
        state
            .view()
            .world()
            .private_settlement_nullifiers
            .iter()
            .next()
            .is_none()
    );
    assert!(
        state
            .view()
            .world()
            .private_settlement_outputs
            .iter()
            .next()
            .is_none()
    );
}

#[test]
fn private_pool_cut_preserves_original_pool_refusal_and_refunds_exact_retry() {
    let (chain, key) = fixture();
    let _epoch = crossbeam_epoch::pin();
    let state = chain.state();
    let tip = chain.committed(chain.height());
    let execution = state.ivm_execution_budget();
    let request = AllocationBudget::new(32 * 1024 * 1024);
    let called = Cell::new(false);
    let mut registration = crate::unit_test_support::release_registration(&execution);
    let mut context = Context::from_waker(Waker::noop());
    let occupied = execution
        .try_reserve_bytes(execution.limit_bytes() - execution.reserved_bytes())
        .unwrap();
    let error = state
        .with_native_private_settlement_pool_snapshot_v1(&tip, key, &request, |_| {
            called.set(true);
            Ok(())
        })
        .unwrap_err();
    let WorldStateSnapshotError::Acquisition(AdmittedStorageError::Allocation(refusal)) = error
    else {
        panic!("private cut must retain the original State acquisition refusal: {error}");
    };
    let AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    } = &refusal
    else {
        panic!("original occupied State pool must preserve its capacity observation: {refusal}");
    };
    assert!(!called.get());
    assert_eq!(request.reserved_bytes(), 0);
    assert_eq!(
        refusal,
        execution.try_reserve_bytes(*requested_bytes).unwrap_err()
    );
    assert!(registration.poll_wait(release, &mut context).is_pending());
    drop(request.try_reserve_bytes(1).unwrap());
    assert!(registration.poll_wait(release, &mut context).is_pending());
    drop(occupied);
    assert!(registration.poll_wait(release, &mut context).is_ready());
    registration.cancel();
    state
        .with_native_private_settlement_pool_snapshot_v1(&tip, key, &request, |_| {
            called.set(true);
            Ok(())
        })
        .unwrap();
    assert!(called.get());
    assert_eq!(request.reserved_bytes(), 0);
    let empty = AllocationBudget::new(0);
    called.set(false);
    assert!(
        state
            .with_native_private_settlement_pool_snapshot_v1(&tip, key, &empty, |_| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(!called.get());
    assert_eq!(empty.reserved_bytes(), 0);
}

#[test]
fn private_context_borrows_same_paid_world_assignment_and_refuses_local_capacity() {
    use iroha_data_model::nexus::{
        PrivateSettlementContextRequestV1, PrivateSettlementContextsProofV1,
    };
    let (chain, key) = fixture_with_assignment(true);
    let selectors = PrivateSettlementContextRequestV1 { pools: vec![key] };
    let _epoch = crossbeam_epoch::pin();
    let state = chain.state();
    let tip = chain.committed(chain.height());
    let execution = state.ivm_execution_budget();
    let initial = execution.reserved_bytes();
    let tiny = AllocationBudget::new(1);
    let called = Cell::new(false);
    assert!(
        state
            .with_native_private_settlement_context_v1(&tip, &selectors, &tiny, |_| {
                called.set(true);
                Ok(())
            })
            .is_err()
    );
    assert!(
        !called.get(),
        "local request capacity refusal cannot publish an unfunded context"
    );
    assert_eq!(tiny.reserved_bytes(), 0);
    assert_eq!(execution.reserved_bytes(), initial);
    let request = AllocationBudget::new(32 * 1024 * 1024);
    let (bytes, charge) = state
        .with_native_private_settlement_context_v1(&tip, &selectors, &request, |original| {
            assert!(
                execution.reserved_bytes() > initial,
                "actual original World acquisition remains funded"
            );
            let length = norito::canonical_frame_len(&original).map_err(|e| e.to_string())?;
            let charge = request
                .try_reserve_bytes(length)
                .map_err(|e| e.to_string())?;
            Ok((
                norito::encode_canonical(&original).map_err(|e| e.to_string())?,
                charge,
            ))
        })
        .unwrap();
    assert!(charge.belongs_to(&request));
    assert_eq!(execution.reserved_bytes(), initial);
    assert_eq!(request.reserved_bytes(), bytes.len());
    let batch = PrivateSettlementContextsProofV1::decode_frame(&bytes).unwrap();
    batch
        .verify(
            chain.network_id(),
            State::native_world_schema_hash_v1().unwrap(),
            &selectors,
            &verified_tip(&chain),
        )
        .unwrap();
    let proof = &batch.contexts[0];
    assert_eq!(
        proof.pool.world.root().unwrap(),
        tip.commitment().execution.world_state_root
    );
    let block = verified_tip(&chain);
    let context = proof
        .verify(
            chain.network_id(),
            State::native_world_schema_hash_v1().unwrap(),
            key,
            &block,
        )
        .unwrap();
    assert_eq!(context.pool_cut().height(), 2);
    assert_eq!(context.authority().route, key.route);
    assert_eq!(context.authority().validators.len(), 4);
    context
        .pool_cut()
        .verify_nullifier_absent(PrivacyNullifierV1::new([0xD7; 32]))
        .unwrap();
    context
        .pool_cut()
        .verify_output_absent(PrivacyCommitmentV1::new([0xD8; 32]))
        .unwrap();
    // Same original complete World root authenticates the fee/native-execution cut and all
    // public authority rows; the empty private pool does not claim an executed private spend.
    drop(bytes);
    drop(charge);
    assert_eq!(request.reserved_bytes(), 0);
}

#[test]
fn private_context_full_world_hashes_reveal_unselected_native_paid_balance() {
    use iroha_data_model::{
        asset::AssetValue,
        nexus::{PrivateSettlementContextRequestV1, PrivateSettlementContextsProofV1},
        sumeragi_finality::world_state_value_hash_v1,
    };
    let (chain, key) = fixture_with_assignment(true);
    let _epoch = crossbeam_epoch::pin();
    let tip = chain.committed(chain.height());
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let selectors = PrivateSettlementContextRequestV1 { pools: vec![key] };
    let (wire, charge) = chain
        .state()
        .with_native_private_settlement_context_v1(&tip, &selectors, &budget, |proof| {
            let size = norito::canonical_frame_len(&proof).map_err(|error| error.to_string())?;
            let charge = budget
                .try_reserve_bytes(size)
                .map_err(|error| error.to_string())?;
            Ok((
                norito::encode_canonical(&proof).map_err(|error| error.to_string())?,
                charge,
            ))
        })
        .unwrap();
    let proof = PrivateSettlementContextsProofV1::decode_frame(&wire).unwrap();
    proof
        .verify(
            chain.network_id(),
            State::native_world_schema_hash_v1().unwrap(),
            &selectors,
            &verified_tip(&chain),
        )
        .unwrap();
    let unrelated = AssetId::with_scope(
        fee_asset(),
        account(&global_config().genesis_key),
        AssetBalanceScope::Global,
    );
    let key_hash = world_state_value_hash_v1(&unrelated).unwrap();
    let row = proof.contexts[0]
        .pool
        .world
        .entries
        .iter()
        .find(|row| row.field_id == "world.assets" && row.key_hash == Some(key_hash))
        .expect("actual selected private context still carries unrelated asset hashes");
    let possible_balances = [
        GLOBAL_INITIAL - GLOBAL_FEE - 1,
        GLOBAL_INITIAL - GLOBAL_FEE,
        GLOBAL_INITIAL - 1,
        GLOBAL_INITIAL,
    ];
    let recovered = possible_balances
        .into_iter()
        .filter(|quantity| {
            world_state_value_hash_v1(&AssetValue::new(Quantity::from(*quantity))).unwrap()
                == row.value_hash
        })
        .collect::<Vec<_>>();
    assert_eq!(
        recovered,
        vec![GLOBAL_INITIAL - GLOBAL_FEE - 1],
        "the actual independently certified native publisher discloses exact unrelated post-payment balances to a small dictionary"
    );
    drop(wire);
    drop(charge);
    assert_eq!(budget.reserved_bytes(), 0);
}
