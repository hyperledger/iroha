//! Real BLS-generation and adaptive threshold-share tests for frozen committee preparation.

#[path = "tests/generation.rs"]
mod generation;
#[path = "tests/incumbent.rs"]
mod incumbent;
#[path = "tests/liability.rs"]
mod liability;
#[path = "tests/restore.rs"]
mod restore;

use super::*;
use crate::{
    beacon::{
        RetainedFinalizedGlobalThresholdBeaconSessionV1,
        prepared_session_and_signers_fixture_for_keys_v1, prepared_session_and_signers_fixture_v1,
        prove_global_threshold_beacon_seat_readiness_v1,
    },
    state::World,
};
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, SignatureOf};
use iroha_data_model::{
    block::consensus::ValidatorPower,
    consensus::GlobalThresholdBeaconDkgSessionV1,
    nexus::{
        PublicLaneStakeShare, PublicLaneUnbonding, PublicLaneValidatorRecord,
        PublicLaneValidatorStatus, ValidatorCommitteeCredentialsV1,
        ValidatorCommitteePreparationV1, ValidatorCommitteeSeatReadinessV1,
    },
    parameter::{
        Parameter,
        system::{ConsensusMode, SumeragiNposParameters},
    },
    sumeragi::epoch::InstalledBeaconEpochBindingV1,
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochBoundaryV1, ValidatorEpochContextV1,
    },
};
use iroha_model_base::metadata::Metadata;
use iroha_primitives::numeric::Quantity;

pub(crate) struct Fixture {
    pub(crate) world: World,
    pub(crate) incumbent: ValidatorGenerationV1,
    pub(crate) authorization: ValidatorEpochAuthorizationV1,
    pub(crate) transition: ValidatorCommitteeTransitionV1,
}

pub(crate) fn fixture(size: usize) -> Fixture {
    fixture_with_selection_anchor(
        size,
        HashOf::from_untyped_unchecked(Hash::new(b"height-nine")),
    )
}

pub(crate) fn fixture_with_selection_anchor(
    size: usize,
    selection_anchor: HashOf<iroha_data_model::block::BlockHeader>,
) -> Fixture {
    let network = iroha_data_model::NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(
        Hash::new(b"prepared-committee-proof-tests"),
    ));
    fixture_with_native_selection(size, network, selection_anchor, [0x31; 32])
}

/// Keep native proof fixtures bound to their actual signed genesis and fresh certified pulse.
pub(crate) fn fixture_with_native_selection(
    size: usize,
    network: iroha_data_model::NetworkId,
    selection_anchor: HashOf<iroha_data_model::block::BlockHeader>,
    election_seed: [u8; 32],
) -> Fixture {
    // Pure World component fixture: one explicit original pool for both generations.
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let mut keys = (1..=size)
        .map(|index| KeyPair::from_seed(vec![index as u8; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| a.public_key().cmp(b.public_key()));
    let roster = keys
        .iter()
        .map(|key| ValidatorPower {
            validator: PeerId::new(key.public_key().clone()),
            power: 1,
        })
        .collect::<Vec<_>>();
    // The incumbent is the four seats whose keys the beacon fixture signs with (seeds 1..=4 in
    // canonical order); with more seats they are not the first four of the sorted roster.
    let incumbent_keys = (1..=4_u8)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    let incumbent_roster = roster
        .iter()
        .filter(|seat| {
            incumbent_keys
                .iter()
                .any(|key| key.public_key() == seat.validator.public_key())
        })
        .cloned()
        .collect::<Vec<_>>();
    let incumbent = ValidatorGenerationV1 {
        network_id: network,
        generation: 0,
        validators: incumbent_roster
            .iter()
            .map(|seat| seat.validator.clone())
            .collect(),
    };
    incumbent.validate().unwrap();
    let peers = incumbent.validators.clone();
    let dkg = |session_id, attempt_id, roster: &[PeerId], start_height| {
        GlobalThresholdBeaconDkgSessionV1 {
            version: 1,
            network_id: network,
            session_id,
            attempt_id,
            authority_generation: u64::from(start_height > 1),
            roster_hash: crate::beacon::global_threshold_beacon_roster_hash_v1(roster),
            committee_size: roster.len() as u16,
            threshold: ((roster.len() - 1) / 3 + 1) as u16,
            start_height,
            commitments_end_height: start_height + 1,
            deliveries_end_height: start_height + 2,
            acceptances_end_height: start_height + 3,
        }
    };
    let (old, _) =
        prepared_session_and_signers_fixture_v1(dkg([0x71; 32], [0x71; 32], &peers, 1), &budget);
    let mut old_record = RetainedFinalizedGlobalThresholdBeaconSessionV1 {
        session: old.clone(),
        activated_at_height: None,
        retired_at_height: None,
    };
    old_record.activate(5).unwrap();
    let genesis = ValidatorEpochAuthorizationV1::genesis(&incumbent, 10).unwrap();
    let authorization = successor_authorization(
        &genesis,
        &incumbent,
        20,
        BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
            session_id: old.record().session_id,
            transcript_hash: old.record().transcript_hash,
        }),
        ValidatorEpochDecisionV1::Retain,
        [0; 32],
    );
    let preparation = ValidatorCommitteePreparationV1 {
        version: 1,
        network_id: network,
        selection_epoch: 0,
        selection_height: 10,
        selection_anchor,
        target_epoch: 2,
        first_height: 21,
        last_height: 30,
        authority_generation: 1,
        preparing_authorization_id: authorization.authorization_id().unwrap(),
        election_seed,
        eligibility: iroha_data_model::nexus::ValidatorElectionPolicyV1 {
            epoch_length_blocks: 10,
            ..iroha_data_model::nexus::ValidatorElectionPolicyV1::from_npos_parameters(
                &iroha_data_model::parameter::system::SumeragiNposParameters::default(),
            )
            .unwrap()
        },
        committee: keys
            .iter()
            .map(
                |key| iroha_data_model::sumeragi::epoch::ValidatorCommitteeMemberV1 {
                    validator: PeerId::new(key.public_key().clone()),
                    proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key())
                        .unwrap(),
                },
            )
            .collect(),
    };
    let target_peers = roster
        .iter()
        .map(|seat| seat.validator.clone())
        .collect::<Vec<_>>();
    // The target ceremony is the preparation's own attempt.
    let (target, signers) = prepared_session_and_signers_fixture_for_keys_v1(
        dkg(
            preparation.beacon_session_id().unwrap(),
            preparation.transition_id().unwrap(),
            &target_peers,
            11,
        ),
        &keys,
        &budget,
    );
    let mut world = World::new();
    world
        .global_beacon_key_sessions
        .insert(old_record.session.session_id, old_record);
    world.global_beacon_active_session.insert(
        GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY,
        old.record().session_id,
    );
    world.global_beacon_key_sessions.insert(
        target.record().session_id,
        RetainedFinalizedGlobalThresholdBeaconSessionV1 {
            session: target.clone(),
            activated_at_height: None,
            retired_at_height: None,
        },
    );
    let mut transition = ValidatorCommitteeTransitionV1 {
        preparation,
        credentials: Some(ValidatorCommitteeCredentialsV1 {
            beacon: InstalledBeaconEpochBindingV1 {
                session_id: target.record().session_id,
                transcript_hash: target.record().transcript_hash,
            },
        }),
        readiness: Vec::new(),
        outcome: None,
    };
    for (index, signer) in signers.iter().enumerate() {
        let context = transition.readiness_context(index as u32).unwrap();
        let generation = transition.preparation.generation();
        transition
            .readiness
            .push(ValidatorCommitteeSeatReadinessV1 {
                validator_index: index as u32,
                beacon: prove_global_threshold_beacon_seat_readiness_v1(
                    signer,
                    &target,
                    &generation,
                    &context,
                )
                .unwrap(),
            });
    }
    world
        .validator_committee_transitions
        .insert(2, transition.clone());
    Fixture {
        world,
        incumbent,
        authorization,
        transition,
    }
}

fn successor_authorization(
    previous: &ValidatorEpochAuthorizationV1,
    generation: &ValidatorGenerationV1,
    last_height: u64,
    beacon: BeaconEpochBindingV1,
    decision: ValidatorEpochDecisionV1,
    transition_id: [u8; 32],
) -> ValidatorEpochAuthorizationV1 {
    let authorization = ValidatorEpochAuthorizationV1 {
        epoch: previous.epoch.checked_add(1).unwrap(),
        first_height: previous.last_height.checked_add(1).unwrap(),
        last_height,
        authority_generation: generation.generation,
        authority_id: generation.generation_id().unwrap(),
        beacon,
        previous_authorization_id: previous.authorization_id().unwrap(),
        transition_id,
        decision,
        ..*previous
    };
    authorization
        .validate_against_generation(generation)
        .unwrap();
    authorization.validate_successor(previous).unwrap();
    authorization
}

fn outcome(fixture: &Fixture, activate: bool) -> ValidatorEpochAuthorizationV1 {
    let credentials = fixture.transition.credentials.as_ref().unwrap();
    ValidatorEpochAuthorizationV1 {
        epoch: 2,
        first_height: 21,
        last_height: 30,
        previous_authorization_id: fixture.authorization.authorization_id().unwrap(),
        transition_id: fixture.transition.preparation.transition_id().unwrap(),
        decision: if activate {
            ValidatorEpochDecisionV1::Activate
        } else {
            ValidatorEpochDecisionV1::RetainAndCancel
        },
        authority_generation: if activate { 1 } else { 0 },
        authority_id: if activate {
            fixture
                .transition
                .preparation
                .generation()
                .generation_id()
                .unwrap()
        } else {
            fixture.incumbent.generation_id().unwrap()
        },
        beacon: if activate {
            BeaconEpochBindingV1::Installed(credentials.beacon)
        } else {
            fixture.authorization.beacon
        },
        ..fixture.authorization
    }
}

#[test]
fn committee_progress_authenticates_every_seat_and_rejects_cross_attempt_proofs() {
    let mut fixture = fixture(7);
    verify_progress(&fixture.world.view(), &fixture.transition).unwrap();
    fixture.transition.outcome = Some(outcome(&fixture, true));
    verify_progress(&fixture.world.view(), &fixture.transition).unwrap();
    let saved = fixture.transition.readiness.pop().unwrap();
    assert!(
        verify_progress(&fixture.world.view(), &fixture.transition).is_err(),
        "a target quorum cannot replace all target seats"
    );
    fixture.transition.outcome = Some(outcome(&fixture, false));
    verify_progress(&fixture.world.view(), &fixture.transition).unwrap();
    fixture.transition.readiness.push(saved);
    fixture.transition.readiness[0].beacon.proof.z_s[0] ^= 1;
    assert!(verify_progress(&fixture.world.view(), &fixture.transition).is_err());
    fixture.transition.credentials = None;
    fixture.transition.readiness.clear();
    verify_progress(&fixture.world.view(), &fixture.transition).unwrap();
}

#[test]
fn committee_bls_consent_and_beacon_readiness_reject_network_generation_replay() {
    use crate::beacon::seat_readiness::verify_global_threshold_beacon_seat_readiness_v1;
    use iroha_data_model::isi::{PublicLaneCandidateAuthorization, RegisterPublicLaneValidator};
    use iroha_data_model::nexus::PublicLaneMonetaryPlanV1;

    let fixture = fixture(4);
    let key = KeyPair::from_seed(vec![1; 32], Algorithm::BlsNormal);
    let owner = iroha_test_samples::ALICE_ID.clone();
    let asset: iroha_data_model::asset::AssetDefinitionId =
        iroha_config::parameters::actual::NexusStaking::default()
            .stake_asset_id
            .parse()
            .unwrap();
    let source = iroha_data_model::asset::AssetId::new(asset.clone(), owner.clone());
    let escrow = iroha_data_model::asset::AssetId::new(asset, iroha_test_samples::BOB_ID.clone());
    let registration = RegisterPublicLaneValidator::new(
        LaneId::SINGLE,
        owner.clone(),
        PeerId::new(key.public_key().clone()),
        owner,
        Quantity::from(100u64),
        Metadata::default(),
        PublicLaneMonetaryPlanV1::genesis_registration(source, escrow, Quantity::from(100u64)),
    );
    let consent =
        PublicLaneCandidateAuthorization::new(fixture.incumbent.network_id, registration, 1);
    let signature = SignatureOf::new(key.private_key(), &consent);
    assert!(consent.registration.monetary_plan.has_canonical_shape());
    signature.verify(key.public_key(), &consent).unwrap();
    let mut foreign = consent.clone();
    foreign.network_id = iroha_data_model::NetworkId::from_genesis_hash(
        HashOf::from_untyped_unchecked(Hash::new(b"foreign")),
    );
    assert!(signature.verify(key.public_key(), &foreign).is_err());
    let mut later_tenure = consent;
    later_tenure.activation_height += 10;
    assert!(signature.verify(key.public_key(), &later_tenure).is_err());
    fixture.transition.preparation.validate().unwrap();
    let mut corrupt_pop = fixture.transition.preparation.clone();
    corrupt_pop.committee[0].proof_of_possession[0] ^= 1;
    assert!(corrupt_pop.validate().is_err());

    let generation = fixture.transition.preparation.generation();
    let context = fixture.transition.readiness_context(0).unwrap();
    let proof = &fixture.transition.readiness[0].beacon;
    let view = fixture.world.view();
    let session = &view
        .global_beacon_key_sessions()
        .get(&context.beacon.session_id)
        .unwrap()
        .session;
    verify_global_threshold_beacon_seat_readiness_v1(session, &generation, &context, proof)
        .unwrap();
    for coordinate in 0..3 {
        let mut changed = context;
        match coordinate {
            0 => changed.network_id = foreign.network_id,
            1 => changed.authority_generation += 1,
            _ => changed.transition_id[0] ^= 1,
        }
        assert!(
            verify_global_threshold_beacon_seat_readiness_v1(session, &generation, &changed, proof)
                .is_err()
        );
    }
    let mut corrupt_proof = *proof;
    corrupt_proof.proof.z_s[0] ^= 1;
    assert!(
        verify_global_threshold_beacon_seat_readiness_v1(
            session,
            &generation,
            &context,
            &corrupt_proof
        )
        .is_err()
    );
}

#[test]
fn committee_pending_transcript_cannot_activate_or_escape_its_attempt_cutoff() {
    let fixture = fixture(7);
    let peers = fixture
        .incumbent
        .validators
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let view = fixture.world.view();
    let record = view
        .global_beacon_key_sessions()
        .get(
            &fixture
                .transition
                .credentials
                .as_ref()
                .unwrap()
                .beacon
                .session_id,
        )
        .unwrap();
    assert_eq!(
        validate_beacon_preparation(
            &view,
            15,
            &fixture.incumbent,
            &fixture.authorization,
            record,
            &peers
        ),
        Ok(false)
    );
    assert!(
        validate_beacon_preparation(
            &view,
            20,
            &fixture.incumbent,
            &fixture.authorization,
            record,
            &peers
        )
        .is_err()
    );
    assert!(
        validate_beacon_preparation(
            &view,
            13,
            &fixture.incumbent,
            &fixture.authorization,
            record,
            &peers
        )
        .is_err()
    );
    let mut wrong = fixture.authorization;
    wrong.epoch += 1;
    assert!(
        validate_beacon_preparation(&view, 15, &fixture.incumbent, &wrong, record, &peers).is_err()
    );
    assert_eq!(
        view.active_global_beacon_key_session(),
        match fixture.authorization.beacon {
            BeaconEpochBindingV1::Installed(binding) => Some(binding.session_id),
            _ => None,
        }
    );
}

#[test]
fn committee_bootstrap_beacon_requires_the_exact_genesis_authority() {
    let fixture = fixture(4);
    let peers = fixture
        .incumbent
        .validators
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let BeaconEpochBindingV1::Installed(binding) = fixture.authorization.beacon else {
        panic!("installed fixture")
    };
    let mut record = fixture
        .world
        .view()
        .global_beacon_key_sessions()
        .get(&binding.session_id)
        .unwrap()
        .clone();
    record.activated_at_height = None;
    let world = World::new();
    let genesis = ValidatorEpochAuthorizationV1::genesis(&fixture.incumbent, 10).unwrap();
    assert_eq!(
        validate_beacon_preparation(
            &world.view(),
            4,
            &fixture.incumbent,
            &genesis,
            &record,
            &peers
        ),
        Ok(true)
    );
    assert!(
        validate_beacon_preparation(
            &world.view(),
            3,
            &fixture.incumbent,
            &genesis,
            &record,
            &peers
        )
        .is_err()
    );
    assert!(
        validate_beacon_preparation(
            &world.view(),
            15,
            &fixture.incumbent,
            &fixture.authorization,
            &record,
            &peers
        )
        .is_err()
    );
    let mut wrong_roster = peers;
    wrong_roster.swap(0, 1);
    assert!(
        validate_beacon_preparation(
            &world.view(),
            4,
            &fixture.incumbent,
            &genesis,
            &record,
            &wrong_roster
        )
        .is_err()
    );
}

#[test]
fn committee_retention_extends_exit_and_pending_unbond_liability() {
    let mut fixture = fixture(4);
    let owner = iroha_test_samples::ALICE_ID.clone();
    let peer = fixture.incumbent.validators[0].clone();
    let key = (LaneId::SINGLE, owner.clone());
    fixture.world.public_lane_validators.insert(
        key.clone(),
        PublicLaneValidatorRecord {
            lane_id: key.0,
            validator: owner.clone(),
            peer_id: peer,
            stake_account: owner.clone(),
            total_stake: Quantity::zero(),
            self_stake: Quantity::zero(),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Exiting(0),
            activation_height: 1,
            election_exit_height: Some(21),
            deactivation_height: None,
        },
    );
    let request = Hash::new(b"retained-unbond");
    fixture.world.public_lane_stake_shares.insert(
        (key.0, owner.clone(), owner.clone()),
        PublicLaneStakeShare {
            lane_id: key.0,
            validator: owner.clone(),
            staker: owner,
            bonded: Quantity::zero(),
            metadata: Metadata::default(),
            pending_unbonds: std::collections::BTreeMap::from([(
                request,
                PublicLaneUnbonding {
                    request_id: request,
                    amount: Quantity::from(100u64),
                    release_at_ms: 0,
                    slashable_through_height: 20,
                    liability_release_height: 23,
                },
            )]),
        },
    );
    let mut parameters = fixture.world.parameters.block();
    parameters.set_parameter(Parameter::Custom(
        SumeragiNposParameters {
            evidence_horizon_blocks: 2,
            slashing_delay_blocks: 1,
            ..SumeragiNposParameters::default()
        }
        .into_custom_parameter(),
    ));
    parameters.commit();
    // This component fixture exercises the native boundary reducer with the exact original
    // credentials. It does not claim a certified chain or executed transition.
    let current = ValidatorEpochContextV1 {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        version: 1,
        network_id: fixture.authorization.network_id,
        mode: ConsensusMode::Npos,
        authorization: fixture.authorization,
        committee: fixture.transition.preparation.committee.clone(),
        leader_seed: [2; 32],
    };
    current.validate().unwrap();
    let mut boundary = ValidatorEpochBoundaryV1 {
        version: 1,
        height: current.authorization.last_height,
        predecessor_context_id: current.context_id().unwrap(),
        selection_anchor: fixture.transition.preparation.selection_anchor,
        next: ValidatorEpochContextV1 {
            authorization: outcome(&fixture, false),
            leader_seed: [3; 32],
            ..current.clone()
        },
        preparation: None,
    };
    boundary.validate_against(&current).unwrap();
    let retained = prepare_staking_obligations(&fixture.world.view(), &boundary).unwrap();
    assert!(
        retained.validators.is_empty(),
        "retention must not close the tenure"
    );
    let pending = &retained.shares[0].1.pending_unbonds[&request];
    assert_eq!(
        (
            pending.slashable_through_height,
            pending.liability_release_height
        ),
        (30, 33)
    );
    let replacement = KeyPair::from_seed(vec![99; 32], Algorithm::BlsNormal);
    boundary.next.committee[0] = ValidatorCommitteeMemberV1 {
        validator: PeerId::new(replacement.public_key().clone()),
        proof_of_possession: iroha_crypto::bls_normal_pop_prove(replacement.private_key()).unwrap(),
    };
    boundary
        .next
        .committee
        .sort_by(|a, b| a.validator.cmp(&b.validator));
    boundary.next.authorization.authority_generation = 1;
    boundary.next.authorization.authority_id = boundary.next.generation().generation_id().unwrap();
    boundary.next.authorization.decision = ValidatorEpochDecisionV1::Activate;
    boundary.validate_against(&current).unwrap();
    let released = prepare_staking_obligations(&fixture.world.view(), &boundary).unwrap();
    assert_eq!(released.validators[0].1.deactivation_height, Some(21));
}

#[path = "tests/refusal.rs"]
mod refusal;
