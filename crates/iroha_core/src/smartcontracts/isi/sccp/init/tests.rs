//! Signed-genesis SCCP initialization, policy and local-refusal regressions.

use super::*;
use crate::{
    query::store::LiveQueryStore,
    smartcontracts::isi::sccp::committee_owner::CommitteeOwnerError,
    state::{State, World, WorldReadOnly},
};
use iroha_config::parameters::actual::Nexus;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    NetworkId,
    block::{BlockHeader, SignedBlock},
    bridge::SccpNetworkV1,
    nexus::{PublicLaneValidatorRecord, PublicLaneValidatorStatus},
    parameter::system::SumeragiConsensusMode,
    sccp::{
        committee::SccpGenerationCauseV1, params::SccpParametersV1,
        registry::SCCP_ROUTE_NETWORKS_V1,
    },
};
use iroha_model_base::{chain::ChainId, metadata::Metadata, topology::LaneId};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use std::{num::NonZeroU64, time::Duration};

fn authority() -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![91; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}
fn instruction() -> InitializeSccpV1 {
    InitializeSccpV1 {
        parameters: SccpParametersV1::taira_default(),
        reset_nonce: [0x5a; 32],
    }
}
fn fixture(mode: SumeragiConsensusMode, delay_ms: u64, slash_bps: u16) -> (State, SignedBlock) {
    fixture_at_epoch(mode, delay_ms, slash_bps, 3600)
}
fn fixture_at_epoch(
    mode: SumeragiConsensusMode,
    delay_ms: u64,
    slash_bps: u16,
    epoch: u64,
) -> (State, SignedBlock) {
    let signed = crate::sumeragi::epoch::tests::genesis_fixture(mode, epoch, false);
    let mut nexus = Nexus::default();
    nexus.staking.unbonding_delay = Duration::from_millis(delay_ms);
    nexus.staking.max_slash_bps = slash_bps;
    let (state, _) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        World::default(),
        nexus,
        LiveQueryStore::start_test(),
        ChainId::from("sccp-genesis-test"),
        NetworkId::from_genesis_hash(signed.hash()),
    );
    (state, signed)
}
fn valid_fixture() -> (State, SignedBlock) {
    let p = instruction().parameters;
    fixture(
        SumeragiConsensusMode::Npos,
        p.committee_validity_ms + p.forgery_evidence_grace_ms,
        1,
    )
}
fn seed_original_members(stx: &mut StateTransaction<'_, '_>) {
    let epoch = stx.sccp_genesis_source.unwrap().epoch().clone();
    let mut chain = stx.world.parameters.get().sumeragi().clone();
    chain.epoch_length_blocks = NonZeroU64::new(3600).unwrap();
    chain.block_cadence_ms = NonZeroU64::new(1000).unwrap();
    stx.world.parameters.get_mut().set_sumeragi(chain);
    for (index, seat) in epoch.committee.iter().enumerate() {
        let account = AccountId::new(
            KeyPair::from_seed(
                vec![u8::try_from(index).unwrap() + 10; 32],
                Algorithm::Ed25519,
            )
            .public_key()
            .clone(),
        );
        let row = PublicLaneValidatorRecord {
            lane_id: LaneId::SINGLE,
            validator: account.clone(),
            peer_id: seat.validator.clone(),
            stake_account: account.clone(),
            total_stake: Quantity::from(10_u32),
            self_stake: Quantity::from(10_u32),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
        };
        stx.world
            .public_lane_validators
            .insert((LaneId::SINGLE, account), row);
    }
}
fn refusal(result: Result<(), Error>) -> String {
    result.expect_err("refused").to_string()
}

#[test]
fn signed_genesis_initializes_original_generation_nonce_escrows_and_empty_routes() {
    let (state, signed) = valid_fixture();
    let mut block = state.block(signed.header());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    let mut stx = block.transaction();
    seed_original_members(&mut stx);
    let original = stx.sccp_genesis_source.unwrap().epoch().clone();
    stx.world.peers.clear();
    let instruction = instruction();
    execute_initialize(instruction.clone(), &authority(), &mut stx).unwrap();
    assert_eq!(
        store::parameters::get(&*stx.world).as_ref(),
        Some(&instruction.parameters)
    );
    assert_eq!(
        *store::reset_nonce::get(&*stx.world),
        Some(instruction.reset_nonce)
    );
    assert_eq!(stx.world.sccp_committee_current(), 1);
    assert_eq!(
        stx.world.sccp_liability_clock(),
        signed.header().creation_time_ms
    );
    assert_eq!(stx.world.sccp_degraded_run(), 0);
    let generation = stx.world.sccp_committee_generations().get(&1).unwrap();
    assert_eq!(generation.cause, SccpGenerationCauseV1::Genesis);
    assert_eq!(generation.start_height, 1);
    assert_eq!(
        generation.start_timestamp_ms,
        signed.header().creation_time_ms
    );
    assert_eq!(generation.keys.len(), 4);
    assert!(generation.members.iter().all(Option::is_some));
    assert_eq!(
        generation.committee_root,
        iroha_data_model::sumeragi_finality::certified_result::context_committee_root(&original)
            .unwrap()
    );
    assert_eq!(
        generation.deadline_ms,
        generation.start_timestamp_ms + instruction.parameters.committee_validity_ms
    );
    for network in SCCP_ROUTE_NETWORKS_V1 {
        let route = store::routes::get(&*stx.world, &network).unwrap();
        assert!(route.revisions.is_empty());
        assert!(stx.world.accounts.get(&route.escrow).is_some());
    }
    assert!(store::routes::get(&*stx.world, &SccpNetworkV1::SoraTaira).is_none());
    assert!(
        refusal(execute_initialize(instruction, &authority(), &mut stx))
            .contains("already initialized")
    );
}

#[test]
fn absent_capture_non_genesis_permissioned_and_unbound_seats_refuse() {
    for case in 0..4 {
        let (state, signed) = if case == 2 {
            fixture(SumeragiConsensusMode::Permissioned, 1_814_400_000, 1)
        } else {
            valid_fixture()
        };
        let header = if case == 1 {
            BlockHeader::new(NonZeroU64::new(2).unwrap(), None, None, 10, 0)
        } else {
            signed.header()
        };
        let mut block = state.block(header);
        if case >= 2 {
            block
                .request_sumeragi_schedule(1, &signed, None, None)
                .unwrap();
        }
        let mut stx = block.transaction();
        if case >= 2 {
            seed_original_members(&mut stx);
        }
        if case == 3 {
            let first = stx
                .world
                .public_lane_validators
                .iter()
                .next()
                .unwrap()
                .0
                .clone();
            stx.world.public_lane_validators.remove(first);
        }
        assert!(execute_initialize(instruction(), &authority(), &mut stx).is_err());
        assert!(store::parameters::get(&*stx.world).is_none());
        assert_eq!(stx.world.sccp_committee_current(), 0);
        assert!(
            stx.require_storage_admission().is_ok(),
            "deterministic initialization refusal"
        );
    }
}

#[test]
fn genesis_rejects_nonce_parameter_epoch_and_pinned_staking_violations_before_writes() {
    for case in 0..5 {
        let (state, signed) = match case {
            3 => fixture(SumeragiConsensusMode::Npos, 1_814_399_999, 1),
            4 => fixture(SumeragiConsensusMode::Npos, 1_814_400_000, 0),
            _ => valid_fixture(),
        };
        let mut block = state.block(signed.header());
        block
            .request_sumeragi_schedule(1, &signed, None, None)
            .unwrap();
        let mut stx = block.transaction();
        seed_original_members(&mut stx);
        let mut instruction = instruction();
        let expected = match case {
            0 => {
                instruction.reset_nonce = [0; 32];
                "reset_nonce"
            }
            1 => {
                instruction.parameters.committee_heartbeat_ms = 1;
                "committee_heartbeat_ms"
            }
            2 => {
                let mut chain = stx.world.parameters.get().sumeragi().clone();
                chain.epoch_length_blocks = NonZeroU64::new(3599).unwrap();
                stx.world.parameters.get_mut().set_sumeragi(chain);
                "epoch_length_blocks"
            }
            3 => "unbonding_delay_ms",
            _ => "max_slash_bps",
        };
        let error = refusal(execute_initialize(instruction, &authority(), &mut stx));
        assert!(error.contains(expected), "{case}: {error}");
        assert!(store::parameters::get(&*stx.world).is_none());
        assert_eq!(stx.world.sccp_committee_current(), 0);
    }
}

#[test]
fn local_owner_refusal_preserves_original_capacity_and_prevents_publication() {
    let (state, signed) = valid_fixture();
    let pool = iroha_allocation::AllocationBudget::new(8);
    let occupied = pool.try_reserve_bytes(8).unwrap();
    let original = pool.try_reserve_bytes(1).unwrap_err();
    let mut block = state.block(signed.header());
    let mut stx = block.transaction();
    generation_error(
        GenerationWriteError::Owner(CommitteeOwnerError::Admission(original.clone())),
        &mut stx,
    );
    let expected =
        StateStorageAdmissionError::SccpGeneration(SccpGenerationLocalError::Admission(original));
    assert_eq!(stx.require_storage_admission(), Err(expected.clone()));
    drop(stx);
    assert_eq!(block.require_storage_admission(), Err(expected));
    drop(occupied);
    assert!(
        state
            .world_view()
            .sccp_committee_generations()
            .iter()
            .next()
            .is_none()
    );
}

#[test]
fn dropped_initialization_rolls_back_generation_and_all_escrow_effects() {
    let (state, signed) = valid_fixture();
    let mut block = state.block(signed.header());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    {
        let mut stx = block.transaction();
        seed_original_members(&mut stx);
        execute_initialize(instruction(), &authority(), &mut stx).unwrap();
        assert_eq!(stx.world.sccp_committee_current(), 1);
    }
    let stx = block.transaction();
    assert_eq!(stx.world.sccp_committee_current(), 0);
    assert!(store::parameters::get(&*stx.world).is_none());
    assert!(store::reset_nonce::get(&*stx.world).is_none());
    for network in SCCP_ROUTE_NETWORKS_V1 {
        assert!(store::routes::get(&*stx.world, &network).is_none());
    }
}

#[test]
fn retained_generation_lifetime_survives_current_parameter_tightening() {
    let (state, signed) = valid_fixture();
    let mut block = state.block(signed.header());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    let mut stx = block.transaction();
    seed_original_members(&mut stx);
    execute_initialize(instruction(), &authority(), &mut stx).unwrap();
    let mut next = instruction().parameters;
    next.enabled = false;
    next.forgery_evidence_grace_ms = 86_400_000;
    let mut staking = stx.nexus().staking.clone();
    staking.unbonding_delay =
        Duration::from_millis(next.committee_validity_ms + next.forgery_evidence_grace_ms);
    let error = params::validate_staking_policy(&*stx.world, &next, &staking).unwrap_err();
    assert!(matches!(
        error,
        params::SccpPolicyError::RetainedLiability { generation: 1, .. }
    ));
    staking.unbonding_delay = Duration::from_millis(1_814_400_000);
    params::validate_staking_policy(&*stx.world, &next, &staking).unwrap();
}

#[test]
fn staged_long_epoch_cannot_replace_short_original_signed_epoch() {
    let (state, signed) = fixture_at_epoch(SumeragiConsensusMode::Npos, 1_814_400_000, 1, 10);
    let mut block = state.block(signed.header());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    let mut stx = block.transaction();
    seed_original_members(&mut stx);
    let error = refusal(execute_initialize(instruction(), &authority(), &mut stx));
    assert!(error.contains("epoch_length_blocks 10"), "{error}");
    assert!(store::parameters::get(&*stx.world).is_none());
    assert_eq!(stx.world.sccp_committee_current(), 0);
}

#[test]
fn local_allocator_decoder_and_source_cut_failures_remain_typed() {
    for case in 0..3 {
        let (state, signed) = valid_fixture();
        let mut block = state.block(signed.header());
        let mut stx = block.transaction();
        let (failure, expected) = match case {
            0 => (
                GenerationWriteError::Owner(CommitteeOwnerError::Allocator {
                    requested_bytes: 123,
                }),
                SccpGenerationLocalError::Allocator {
                    requested_bytes: 123,
                },
            ),
            1 => {
                let original = norito::core::DecodeResourceError::TotalAllocationExceeded {
                    attempted: 99,
                    limit: 8,
                };
                (
                    GenerationWriteError::Owner(CommitteeOwnerError::DecodeResource(
                        original.clone().into(),
                    )),
                    SccpGenerationLocalError::DecodeResource(original),
                )
            }
            _ => (
                GenerationWriteError::SourceCut,
                SccpGenerationLocalError::Invariant("genesis generation source cut changed"),
            ),
        };
        generation_error(failure, &mut stx);
        assert_eq!(
            stx.require_storage_admission(),
            Err(StateStorageAdmissionError::SccpGeneration(expected))
        );
    }
}

#[test]
fn governance_parameter_enactment_cannot_extend_liability_beyond_pinned_delay() {
    use iroha_data_model::sccp::governance::{
        SccpGovernanceActionV1, SccpGovernanceProposalV1, SccpGovernanceSubjectV1,
        SccpSetParametersActionV1,
    };
    let (state, signed) = valid_fixture();
    let mut block = state.block(signed.header());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    let mut stx = block.transaction();
    seed_original_members(&mut stx);
    execute_initialize(instruction(), &authority(), &mut stx).unwrap();
    let original = instruction().parameters;
    let mut next = original;
    next.forgery_evidence_grace_ms += 1;
    let mut proposal = SccpGovernanceProposalV1 {
        network_id: *stx.network_id(),
        base_revisions: vec![(SccpGovernanceSubjectV1::Parameters, 0).into()],
        actions: vec![SccpGovernanceActionV1::SetParameters(
            SccpSetParametersActionV1 { next },
        )],
    };
    let error = refusal(crate::smartcontracts::isi::sccp::governance::enact(
        &mut stx, &proposal, [7; 32],
    ));
    assert!(error.contains("unbonding_delay_ms"), "{error}");
    assert_eq!(store::parameters::get(&*stx.world), &Some(original));
    assert_eq!(
        store::governance_revision(&*stx.world, &SccpGovernanceSubjectV1::Parameters),
        0
    );
    next = original;
    next.forgery_evidence_grace_ms -= 1;
    proposal.actions = vec![SccpGovernanceActionV1::SetParameters(
        SccpSetParametersActionV1 { next },
    )];
    crate::smartcontracts::isi::sccp::governance::enact(&mut stx, &proposal, [8; 32]).unwrap();
    assert_eq!(store::parameters::get(&*stx.world), &Some(next));
    assert_eq!(
        stx.world
            .sccp_committee_generations()
            .get(&1)
            .unwrap()
            .grace_ms,
        original.forgery_evidence_grace_ms
    );
}

#[test]
fn signed_dataspace_genesis_cannot_initialize_global_sccp() {
    use iroha_data_model::block::consensus::SumeragiRootScope;
    use iroha_model_base::topology::DataSpaceId;
    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
                b"parent genesis",
            )),
        ),
        dataspace_id: DataSpaceId::new(7),
    };
    // A private root has a permissioned native committee. NPoS on that root is
    // rejected earlier by epoch control, before an initialization source exists.
    let signed = crate::sumeragi::epoch::tests::genesis_fixture_with_scope(
        SumeragiConsensusMode::Permissioned,
        3600,
        false,
        scope,
    );
    let mut nexus = Nexus::default();
    nexus.staking.unbonding_delay = Duration::from_millis(
        instruction().parameters.committee_validity_ms
            + instruction().parameters.forgery_evidence_grace_ms,
    );
    nexus.staking.max_slash_bps = 1;
    let (state, _) = State::new_with_chain_and_network_id_and_pre_genesis_nexus_for_testing(
        World::default(),
        nexus,
        LiveQueryStore::start_test(),
        ChainId::from("sccp-genesis-test"),
        NetworkId::from_genesis_hash(signed.hash()),
    );
    let mut block = state.block(signed.header());
    block
        .request_sumeragi_schedule(1, &signed, None, None)
        .unwrap();
    let mut stx = block.transaction();
    seed_original_members(&mut stx);
    assert_eq!(stx.sccp_genesis_source.unwrap().root_scope(), scope);
    assert!(
        refusal(execute_initialize(instruction(), &authority(), &mut stx))
            .contains("Global root scope")
    );
    assert!(store::parameters::get(&*stx.world).is_none());
    assert_eq!(stx.world.sccp_committee_current(), 0);
    assert!(
        stx.world
            .sccp_committee_generations()
            .iter()
            .next()
            .is_none()
    );
}
