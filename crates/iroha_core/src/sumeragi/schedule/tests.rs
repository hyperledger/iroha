//! Canonical native schedule geometry, signed bootstrap and boundary barrier regressions.

use super::*;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::{
    Level,
    account::AccountId,
    block::SignedBlock,
    isi::{InstructionBox, Log, RegisterBox, RegisterPeerWithPop},
    parameter::system::SumeragiParameter,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_sumeragi::{api::ConfigError, pacemaker::FRAME_OVERHEAD, types::ChainParams};
use std::num::{NonZeroU32, NonZeroU64};

fn bls() -> KeyPair {
    KeyPair::random_with_algorithm(Algorithm::BlsNormal)
}

fn peer(pair: &KeyPair) -> PeerId {
    PeerId::new(pair.public_key().clone())
}

fn params() -> ChainParamsRecord {
    ChainParamsRecord::from_core(&ChainParams::default())
}

#[test]
fn chain_params_record_round_trips_the_core_and_on_chain_forms() {
    let core = ChainParams::default();
    let record = ChainParamsRecord::from_core(&core);
    assert_eq!(record.to_core(), core);
    assert_eq!(
        ChainParamsRecord::from_parameters(&SumeragiParameters::default()),
        record
    );
    record.validate().expect("defaults are valid");
    let bytes = norito::encode_canonical(&record).expect("encode");
    assert_eq!(
        norito::decode_canonical::<ChainParamsRecord>(&bytes).expect("decode"),
        record
    );
    let json = norito::json::to_json(&record).expect("json");
    assert_eq!(
        norito::json::from_str::<ChainParamsRecord>(&json).expect("parse"),
        record
    );
}

#[test]
fn chain_params_validation_uses_the_chain_transport_limit() {
    let mut record = params();
    record.max_block_bytes =
        u32::try_from(CHAIN_TRANSPORT_FRAME_LIMIT - u64::from(FRAME_OVERHEAD)).expect("fits");
    record.validate().expect("exactly at the limit");
    record.max_block_bytes += 1;
    assert_eq!(
        record.validate(),
        Err(ConfigError::MaxBlockBytesAboveTransport)
    );
    let mut record = params();
    record.block_time_ms = record.payload_retry_interval_ms + 1;
    assert_eq!(
        record.validate(),
        Err(ConfigError::BlockTimeAbovePayloadRetry)
    );
    assert_eq!(
        CHAIN_TRANSPORT_FRAME_LIMIT,
        crate::sumeragi::driver::DriverConfig::default().frame_limit
    );
}

#[test]
fn consensus_key_maps_bls_peers_both_ways_and_rejects_others() {
    let pair = bls();
    let key = consensus_key(&peer(&pair)).expect("bls");
    assert_eq!(key.as_bytes().len(), 48);
    assert_eq!(peer_of(&key).expect("inverse"), peer(&pair));
    let ed = KeyPair::random();
    assert!(matches!(
        consensus_key(&peer(&ed)),
        Err(ScheduleError::NotBlsNormal(_))
    ));
    assert!(peer_of(&PublicKey::new(vec![7; 48]).expect("len")).is_err());
}

#[test]
fn canonical_committee_sorts_by_core_key_and_dedups() {
    let pairs = [bls(), bls(), bls()];
    let peers: Vec<_> = pairs.iter().map(peer).collect();
    let committee =
        canonical_committee(peers.iter().rev().cloned().chain([peers[0].clone()])).expect("bls");
    assert_eq!(committee.len(), 3);
    let keys: Vec<_> = committee
        .iter()
        .map(|p| consensus_key(p).unwrap())
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn parameter_changes_validate_after_genesis_only() {
    let current = SumeragiParameters::default();
    let window = SumeragiParameter::DemotionWindow(NonZeroU64::new(64).unwrap());
    validate_parameter_change(&current, &window, true).expect("genesis");
    assert_eq!(
        validate_parameter_change(&current, &window, false),
        Err(ScheduleError::GenesisOnly)
    );
    let too_fast_retry = SumeragiParameter::PayloadRetryIntervalMs(NonZeroU64::new(999).unwrap());
    assert_eq!(
        validate_parameter_change(&current, &too_fast_retry, false),
        Err(ScheduleError::Params(
            ConfigError::BlockTimeAbovePayloadRetry
        ))
    );
    // In genesis the combination is checked when the schedule is installed.
    validate_parameter_change(&current, &too_fast_retry, true).expect("genesis defers");
    let huge = SumeragiParameter::MaxBlockBytes(NonZeroU32::new(u32::MAX).unwrap());
    assert!(matches!(
        validate_parameter_change(&current, &huge, false),
        Err(ScheduleError::Params(
            ConfigError::MaxBlockBytesAboveTransport
        ))
    ));
    for ok in [
        SumeragiParameter::MaxClockDriftMs(5),
        SumeragiParameter::PayloadRetryIntervalMs(NonZeroU64::new(6_000).unwrap()),
        SumeragiParameter::ExecBudgetMs(NonZeroU64::new(3_000).unwrap()),
        SumeragiParameter::ApplyBudgetMs(NonZeroU64::new(500).unwrap()),
        SumeragiParameter::MaxBlockBytes(NonZeroU32::new(1 << 20).unwrap()),
        SumeragiParameter::EpochLengthBlocks(NonZeroU64::new(7_200).unwrap()),
    ] {
        validate_parameter_change(&current, &ok, false).expect("valid change");
    }
}

fn genesis_with(instructions: Vec<InstructionBox>) -> GenesisBlock {
    let genesis_key = KeyPair::random();
    let account = AccountId::new(genesis_key.public_key().clone());
    let transaction =
        TransactionBuilder::new_genesis(account, FeePaymentIntent::authority(Vec::new(), None))
            .with_instructions(instructions)
            .sign(genesis_key.private_key());
    GenesisBlock(SignedBlock::genesis(
        vec![transaction],
        genesis_key.private_key(),
        None,
        None,
    ))
}

fn register_instruction(pair: &KeyPair) -> InstructionBox {
    let pop = iroha_crypto::bls_normal_pop_prove(pair.private_key()).expect("pop");
    InstructionBox::from(RegisterBox::Peer(RegisterPeerWithPop::new(peer(pair), pop)))
}

#[test]
fn genesis_committee_reads_the_signed_validator_registrations() {
    let pairs = [bls(), bls(), bls(), bls()];
    let mut instructions: Vec<_> = pairs.iter().map(register_instruction).collect();
    instructions.push(InstructionBox::from(Log::new(Level::INFO, "x".to_owned())));
    let genesis = genesis_with(instructions);
    let validators = genesis_validators(&genesis).expect("validators");
    assert_eq!(validators.len(), 4);
    let committee = genesis_committee(&genesis).expect("committee");
    assert_eq!(committee.n(), 4);
    for pair in &pairs {
        assert!(committee.contains(&consensus_key(&peer(pair)).unwrap()));
    }
}

#[test]
fn signed_genesis_requires_exact_global_geometry_without_observer_padding() {
    let pairs = (0..8).map(|_| bls()).collect::<Vec<_>>();
    for count in 0..=pairs.len() {
        let instructions = pairs[..count].iter().map(register_instruction).collect();
        let genesis = genesis_with(instructions);
        if count == 4 || count == 7 {
            assert_eq!(genesis_committee(&genesis).unwrap().n(), count);
        } else {
            assert_eq!(
                genesis_committee(&genesis),
                Err(GenesisCommitteeError::Committee(
                    ScheduleError::InvalidCommitteeSize { validators: count }
                ))
            );
        }
    }
    let mut instructions = pairs[..3]
        .iter()
        .map(register_instruction)
        .collect::<Vec<_>>();
    instructions.push(
        iroha_data_model::isi::register::RegisterCommitteePeerWithPop::new(
            peer(&pairs[3]),
            iroha_crypto::bls_normal_pop_prove(pairs[3].private_key()).unwrap(),
        )
        .into(),
    );
    assert_eq!(
        genesis_committee(&genesis_with(instructions)),
        Err(GenesisCommitteeError::Committee(
            ScheduleError::InvalidCommitteeSize { validators: 3 }
        ))
    );
}

#[test]
fn genesis_committee_rejects_bad_registrations() {
    let pair = bls();
    let duplicate = genesis_with(vec![
        register_instruction(&pair),
        register_instruction(&pair),
    ]);
    assert!(matches!(
        genesis_validators(&duplicate),
        Err(GenesisCommitteeError::DuplicateValidator(_))
    ));
    let other = bls();
    let bad_pop = iroha_crypto::bls_normal_pop_prove(other.private_key()).expect("pop");
    let forged = genesis_with(vec![InstructionBox::from(RegisterBox::Peer(
        RegisterPeerWithPop::new(peer(&pair), bad_pop),
    ))]);
    assert!(matches!(
        genesis_validators(&forged),
        Err(GenesisCommitteeError::InvalidProofOfPossession(_))
    ));
    // The unverified registrations still carry the forged proof; admission refuses it.
    let registered = genesis_registrations(&forged.0).expect("registrations");
    assert_eq!(registered.len(), 1);
    assert!(
        crate::sumeragi::crypto::BlsCrypto::new()
            .admit(pair.public_key(), &registered[&peer(&pair)])
            .is_err()
    );
    assert!(matches!(
        genesis_registrations(&duplicate.0),
        Err(GenesisCommitteeError::DuplicateValidator(_))
    ));
    let empty = genesis_with(vec![InstructionBox::from(Log::new(
        Level::INFO,
        "x".to_owned(),
    ))]);
    assert_eq!(
        genesis_committee(&empty),
        Err(GenesisCommitteeError::Committee(
            ScheduleError::InvalidCommitteeSize { validators: 0 }
        ))
    );
}

fn epoch(length: u64) -> iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1 {
    let genesis = crate::sumeragi::epoch::tests::genesis_fixture(
        iroha_data_model::parameter::system::SumeragiConsensusMode::Npos,
        length,
        false,
    );
    crate::sumeragi::epoch::authenticated_genesis(&genesis)
        .map(|genesis| genesis.into_parts().0)
        .unwrap()
}
fn ordinary(schedule: &ConsensusSchedule, height: u64) -> ScheduleOutcome {
    let current = schedule.ready(height).unwrap().epoch.clone();
    let next = schedule.get(height + 1).unwrap().clone();
    let after_next = if height + 2 <= current.authorization.last_height {
        ScheduledSlot::Ready(ScheduledConfig {
            height: height + 2,
            epoch: current.clone(),
            params: params(),
        })
    } else {
        ScheduledSlot::PendingBoundary {
            height: height + 2,
            boundary_height: current.authorization.last_height,
            predecessor_context_id: current.context_id().unwrap(),
            params: params(),
        }
    };
    ScheduleOutcome {
        height,
        current,
        boundary: None,
        next,
        after_next,
    }
}
fn retained_boundary(
    current: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
) -> ScheduleOutcome {
    use iroha_data_model::sumeragi::epoch::ValidatorEpochBoundaryV1;
    use iroha_data_model::sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorEpochDecisionV1,
    };
    let height = current.authorization.last_height;
    let mut next = current.clone();
    next.authorization.epoch += 1;
    next.authorization.first_height = height + 1;
    next.authorization.last_height = height + 3;
    next.authorization.previous_authorization_id =
        current.authorization.authorization_id().unwrap();
    next.authorization.decision = ValidatorEpochDecisionV1::Retain;
    next.authorization.beacon = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
        session_id: [0x41; 32],
        transcript_hash: [0x42; 32],
    });
    next.leader_seed = [0x43; 32];
    let boundary = ValidatorEpochBoundaryV1 {
        version: 1,
        height,
        predecessor_context_id: current.context_id().unwrap(),
        selection_anchor: iroha_crypto::HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(
            b"graph-only externally authenticated predecessor fixture",
        )),
        next: next.clone(),
        preparation: None,
    };
    ScheduleOutcome {
        height,
        current: current.clone(),
        boundary: Some(boundary),
        next: ScheduledSlot::Ready(ScheduledConfig {
            height: height + 1,
            epoch: next.clone(),
            params: params(),
        }),
        after_next: ScheduledSlot::Ready(ScheduledConfig {
            height: height + 2,
            epoch: next,
            params: params(),
        }),
    }
}

#[test]
fn global_committees_have_exact_bounded_geometry_and_equal_vote_quorums() {
    let pairs = (0..35).map(|_| bls()).collect::<Vec<_>>();
    for count in 0..=pairs.len() {
        let keys = pairs[..count]
            .iter()
            .map(|pair| consensus_key(&peer(pair)).unwrap())
            .collect();
        if (4..=31).contains(&count) && (count - 1) % 3 == 0 {
            let committee = global_committee(keys).unwrap();
            assert_eq!(
                (committee.n(), committee.f(), committee.q()),
                (count, (count - 1) / 3, 2 * ((count - 1) / 3) + 1)
            );
        } else {
            assert_eq!(
                global_committee(keys),
                Err(ScheduleError::InvalidCommitteeSize { validators: count })
            );
        }
    }
}

#[test]
fn native_epoch_binds_core_authority_and_rejects_missing_reordered_or_changed_original_proofs() {
    let config = ScheduledConfig {
        height: 2,
        epoch: epoch(3),
        params: params(),
    };
    let core = config.height_config().unwrap();
    assert_eq!(
        core.epoch.id.context,
        iroha_sumeragi::types::Hash32(config.epoch.context_id().unwrap())
    );
    assert_eq!(
        core.epoch.authority_generation,
        iroha_sumeragi::types::Hash32(config.epoch.generation().generation_id().unwrap())
    );
    assert_eq!((core.committee.n(), core.committee.q()), (4, 3));
    for mutation in 0..4 {
        let mut bad = config.clone();
        match mutation {
            0 => {
                bad.epoch.committee.pop();
            }
            1 => bad.epoch.committee.swap(0, 1),
            2 => bad.epoch.committee[0].proof_of_possession.clear(),
            _ => bad.epoch.committee[0].proof_of_possession[0] ^= 1,
        }
        assert!(bad.height_config().is_err());
    }
    let mut bad = config;
    bad.params.payload_retry_interval_ms = 0;
    assert!(matches!(bad.height_config(), Err(ScheduleError::Params(_))));
}

#[test]
fn boundary_application_is_the_only_cut_that_replaces_pending_authority() {
    let current = epoch(3);
    let genesis = ConsensusSchedule::from_genesis(current.clone(), params()).unwrap();
    let h2 = ordinary(&genesis, 2);
    let pending = genesis.advanced(&h2).unwrap();
    assert!(pending.ready(4).is_err());
    assert!(matches!(
        pending.init_configs(1).unwrap().last().unwrap().1,
        iroha_sumeragi::types::ConfigSlot::PendingBoundary {
            boundary_height: 3,
            ..
        }
    ));
    let boundary = retained_boundary(&current);
    let next = pending.advanced(&boundary).unwrap();
    assert_eq!(next.ready(4).unwrap().epoch.authorization.epoch, 1);
    assert_eq!(
        next.ready(4).unwrap().epoch.generation(),
        current.generation()
    );
    assert_eq!(next.ready(4).unwrap().epoch.committee, current.committee);
    assert!(matches!(
        boundary.applied_config().unwrap(),
        iroha_sumeragi::types::AppliedConfig::Boundary { .. }
    ));
    for mutation in 0..4 {
        let mut bad = boundary.clone();
        match mutation {
            0 => bad.boundary = None,
            1 => {
                bad.next = ScheduledSlot::Ready(ScheduledConfig {
                    height: 4,
                    epoch: current.clone(),
                    params: params(),
                })
            }
            2 => {
                if let ScheduledSlot::Ready(config) = &mut bad.next {
                    config.params.payload_retry_interval_ms += 1;
                }
            }
            _ => bad.after_next = h2.after_next.clone(),
        }
        assert!(pending.advanced(&bad).is_err(), "mutation {mutation}");
    }
    assert!(
        genesis.advanced(&boundary).is_err(),
        "cannot jump over the certified prefix"
    );
}

#[test]
fn scheduled_slot_json_requires_its_canonical_variant_tag() {
    let slot = ScheduledSlot::PendingBoundary {
        height: 4,
        boundary_height: 3,
        predecessor_context_id: [7; 32],
        params: params(),
    };
    let json = norito::json::to_json(&slot).unwrap();
    assert!(json.contains("\"kind\":\"pending_boundary\""));
    assert_eq!(
        norito::json::from_str::<ScheduledSlot>(&json).unwrap(),
        slot
    );
    let unknown = json.replace("pending_boundary", "unknown_boundary");
    assert!(norito::json::from_str::<ScheduledSlot>(&unknown).is_err());
    let missing = json.replace("\"kind\":\"pending_boundary\",", "");
    assert_ne!(missing, json);
    assert!(norito::json::from_str::<ScheduledSlot>(&missing).is_err());
}

#[test]
fn restored_schedule_keeps_original_generation_and_full_epoch_graph() {
    let initial = ConsensusSchedule::from_genesis(epoch(3), params()).unwrap();
    let h2 = ordinary(&initial, 2);
    let pending = initial.advanced(&h2).unwrap();
    let h3 = retained_boundary(&h2.current);
    let active = pending.advanced(&h3).unwrap();
    for schedule in [&initial, &pending, &active] {
        let restored: ConsensusSchedule =
            norito::decode_canonical(&norito::encode_canonical(schedule).unwrap()).unwrap();
        assert_eq!(&restored, schedule);
        assert_eq!(
            restored.init_configs(1).unwrap(),
            schedule.init_configs(1).unwrap()
        );
        let json = norito::json::to_json(schedule).unwrap();
        assert_eq!(
            norito::json::from_str::<ConsensusSchedule>(&json).unwrap(),
            *schedule
        );
    }
    let mut substituted = h3.clone();
    if let ScheduledSlot::Ready(config) = &mut substituted.next {
        config.epoch.committee[0].proof_of_possession[0] ^= 1;
    }
    assert!(pending.advanced(&substituted).is_err());
    let mut ordinary_change = h2;
    if let ScheduledSlot::Ready(config) = &mut ordinary_change.next {
        config.epoch.leader_seed[0] ^= 1;
    }
    assert!(initial.advanced(&ordinary_change).is_err());
}

#[test]
fn genesis_outcome_cannot_supply_an_arbitrary_epoch_or_boundary() {
    let context = epoch(10);
    let original = ConsensusSchedule::from_genesis(context.clone(), params()).unwrap();
    let outcome = ScheduleOutcome {
        height: 1,
        current: context,
        boundary: None,
        next: original.get(2).unwrap().clone(),
        after_next: original.get(3).unwrap().clone(),
    };
    assert_eq!(
        ConsensusSchedule::from_genesis_outcome(&outcome).unwrap(),
        original
    );
    let mut bad = outcome.clone();
    if let ScheduledSlot::Ready(config) = &mut bad.after_next {
        config.params.payload_retry_interval_ms += 1;
    }
    assert!(ConsensusSchedule::from_genesis_outcome(&bad).is_err());
    assert!(ConsensusSchedule::from_genesis_outcome(&retained_boundary(&outcome.current)).is_err());
}
