//! Real BLS epoch codec, identity, generation and successor controls.

use super::*;
use iroha_crypto::{Hash, KeyPair};

pub fn fixture(count: usize) -> ValidatorEpochContextV1 {
    let mut pairs = (1..=count)
        .map(|seed| {
            KeyPair::try_from_seed(vec![u8::try_from(seed).unwrap(); 32], Algorithm::BlsNormal)
                .unwrap()
        })
        .collect::<Vec<_>>();
    pairs.sort_by_key(|pair| PeerId::new(pair.public_key().clone()));
    let committee = pairs
        .iter()
        .map(|pair| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(pair.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
        })
        .collect::<Vec<_>>();
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"native epoch fixture"),
    ));
    let generation = ValidatorGenerationV1::from_committee(network_id, 0, &committee);
    let authorization = ValidatorEpochAuthorizationV1::genesis(&generation, 10).unwrap();
    let context = ValidatorEpochContextV1 {
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
        version: 1,
        network_id,
        mode: ConsensusMode::Npos,
        authorization,
        committee,
        leader_seed: [0x31; 32],
    };
    context.validate().unwrap();
    context
}

pub fn retained(previous: &ValidatorEpochContextV1) -> ValidatorEpochContextV1 {
    let mut next = previous.clone();
    let authorization = &mut next.authorization;
    authorization.epoch += 1;
    authorization.first_height = previous.authorization.last_height + 1;
    authorization.last_height = authorization.first_height + 9;
    authorization.previous_authorization_id = previous.authorization.authorization_id().unwrap();
    authorization.decision = ValidatorEpochDecisionV1::Retain;
    authorization.beacon = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
        session_id: [0x41; 32],
        transcript_hash: [0x51; 32],
    });
    next.leader_seed = [0x32; 32];
    next
}

#[test]
fn complete_epoch_round_trips_real_credentials_and_binds_every_field() {
    for count in [4, 7, 10] {
        let context = fixture(count);
        let id = context.context_id().unwrap();
        let bytes = norito::encode_canonical(&context).unwrap();
        let decoded: ValidatorEpochContextV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, context);
        assert_eq!(decoded.context_id().unwrap(), id);
        let json = norito::json::to_json(&context).unwrap();
        assert_eq!(
            norito::json::from_str::<ValidatorEpochContextV1>(&json).unwrap(),
            context
        );
        let mut changed = context.clone();
        changed.leader_seed[0] ^= 1;
        assert_ne!(changed.context_id().unwrap(), id);
        let mut changed = context.clone();
        changed.mode = ConsensusMode::Permissioned;
        assert_ne!(changed.context_id().unwrap(), id);
        let mut changed = context.clone();
        changed.authorization.last_height += 1;
        assert_ne!(changed.context_id().unwrap(), id);
        let mut changed = context.clone();
        changed.version = 2;
        assert!(changed.validate().is_err());
        let mut changed = context.clone();
        changed.network_id = NetworkId::from_genesis_hash(
            HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"other network")),
        );
        assert!(changed.validate().is_err());
    }
}

#[test]
fn malformed_roster_order_proof_and_generation_vectors_are_refused() {
    let context = fixture(4);
    for mutation in 0..7 {
        let mut bad = context.clone();
        match mutation {
            0 => {
                bad.committee.pop();
            }
            1 => bad.committee.swap(0, 1),
            2 => bad.committee[0].proof_of_possession.clear(),
            3 => bad.committee[0].proof_of_possession[0] ^= 1,
            4 => bad.committee[1] = bad.committee[0].clone(),
            5 => bad.authorization.authority_generation = 1,
            _ => bad.authorization.authority_id[0] ^= 1,
        }
        if mutation < 5 {
            // Rebind the authorization so only the roster defect remains.
            if let Ok(id) = bad.generation().generation_id() {
                bad.authorization.authority_id = id;
            }
        }
        assert!(bad.validate().is_err(), "mutation {mutation}");
        assert!(bad.context_id().is_err());
    }
    for length in [1, 2] {
        let mut short = context.clone();
        short.authorization.last_height = length;
        assert!(short.validate().is_err());
    }
}

#[test]
fn epoch_retention_keeps_generation_and_original_proofs_but_changes_context() {
    let initial = fixture(4);
    let next = retained(&initial);
    next.validate_successor(&initial).unwrap();
    assert_eq!(next.generation(), initial.generation());
    assert_eq!(next.committee, initial.committee);
    assert_ne!(next.context_id().unwrap(), initial.context_id().unwrap());
    let mut skipped = next.clone();
    skipped.authorization.first_height += 1;
    assert!(skipped.validate_successor(&initial).is_err());
    let mut relabeled = next.clone();
    relabeled.authorization.authority_generation += 1;
    relabeled.authorization.authority_id = relabeled.generation().generation_id().unwrap();
    relabeled.validate().unwrap();
    assert!(relabeled.validate_successor(&initial).is_err());
    let mut changed = next.clone();
    changed.committee = fixture(7).committee;
    changed.authorization.authority_id = changed.generation().generation_id().unwrap();
    changed.validate().unwrap();
    assert!(changed.validate_successor(&initial).is_err());
}

#[test]
fn boundary_binds_exact_incumbent_cut_and_contiguous_successor() {
    let current = fixture(4);
    let boundary = ValidatorEpochBoundaryV1 {
        version: 1,
        height: 10,
        predecessor_context_id: current.context_id().unwrap(),
        selection_anchor: HashOf::from_untyped_unchecked(Hash::new(
            b"actual prestate cut supplied externally",
        )),
        next: retained(&current),
        preparation: None,
    };
    boundary.validate_against(&current).unwrap();
    let bytes = norito::encode_canonical(&boundary).unwrap();
    let decoded: ValidatorEpochBoundaryV1 = norito::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded, boundary);
    decoded.validate_against(&current).unwrap();
    for mutation in 0..3 {
        let mut bad = boundary.clone();
        match mutation {
            0 => bad.height -= 1,
            1 => bad.predecessor_context_id[0] ^= 1,
            _ => bad.next.authorization.first_height += 1,
        }
        assert!(bad.validate_against(&current).is_err());
    }
}

#[test]
fn uniform_rank_binds_network_epochs_seed_and_peer_without_stake_weight() {
    let context = fixture(4);
    let peer = &context.committee[0].validator;
    let rank = validator_seat_rank(context.network_id, 0, 2, [7; 32], peer).unwrap();
    let bytes = norito::encode_canonical(peer).unwrap();
    let independent = Hash::new_from_chunks(&[
        b"iroha:validator-seat:v1",
        &[0],
        context.network_id.as_bytes(),
        &0_u64.to_le_bytes(),
        &2_u64.to_le_bytes(),
        &[7; 32],
        &bytes,
    ]);
    assert_eq!(rank, <[u8; 32]>::from(independent));
    assert_ne!(
        rank,
        validator_seat_rank(context.network_id, 1, 3, [7; 32], peer).unwrap()
    );
    assert_ne!(
        rank,
        validator_seat_rank(context.network_id, 0, 2, [8; 32], peer).unwrap()
    );
    assert_ne!(
        rank,
        validator_seat_rank(
            context.network_id,
            0,
            2,
            [7; 32],
            &context.committee[1].validator
        )
        .unwrap()
    );
    assert!(validator_seat_rank(context.network_id, 0, 1, [7; 32], peer).is_err());
    assert!(validator_seat_rank(context.network_id, 0, 2, [0; 32], peer).is_err());
}

#[test]
fn signed_availability_layout_binds_epoch_and_cannot_change_at_retention() {
    let original = fixture(4);
    let mut changed = original.clone();
    changed.da_layout.chunk_size_bytes /= 2;
    changed.validate().unwrap();
    assert_ne!(
        original.context_id().unwrap(),
        changed.context_id().unwrap()
    );
    let mut next = retained(&original);
    next.validate_successor(&original).unwrap();
    next.da_layout = changed.da_layout;
    assert!(next.validate_successor(&original).is_err());
    changed.da_layout.parity_shards = 0;
    assert!(changed.validate().is_err());
    assert!(crate::sumeragi_finality::core_epoch(&changed).is_err());
}

// This is a public-call counterexample. The signed fixture and independent
// generation/wire oracles are complete before physical observation starts.
#[test]
fn epoch_validation_retains_original_signed_roster_without_generation_allocation() {
    use crate::{
        amx_prepare_streaming_allocations::PhysicalObservation,
        block::SharedSignedBlock,
        sumeragi_finality::{authenticated_genesis, test_fixtures::NativeFinalityFixture},
    };
    use iroha_allocation::AllocationBudget;
    use norito::core::DecodeBudgetContext;

    let fixture = NativeFinalityFixture::start_with_mode(
        "borrowed-generation-allocation",
        crate::parameter::system::SumeragiConsensusMode::Npos,
    );
    let budget = AllocationBudget::new(32 * 1024 * 1024);
    let genesis = SharedSignedBlock::try_new(fixture.genesis().clone(), &budget).unwrap();
    let decoder = DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(1_000_000, 48 * 1024 * 1024, 1_000_000, 48 * 1024 * 1024, 64),
        &budget,
    )
    .unwrap();
    let (context, scope) = decoder
        .with(|| authenticated_genesis(&genesis))
        .unwrap()
        .into_parts();
    let original_scope = crate::block::consensus::SumeragiRootScope::Global;
    let wire = norito::encode_canonical(&context).unwrap();
    let generation = context.generation();
    let generation_id = generation.generation_id().unwrap();
    let original_keys = context
        .committee
        .iter()
        .map(|member| {
            let (_, key) = member.validator.public_key().try_to_bytes().unwrap();
            (
                key.as_ptr(),
                key.len(),
                member.proof_of_possession.as_ptr(),
                member.proof_of_possession.len(),
            )
        })
        .collect::<Vec<_>>();
    let blocker = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let original_charge = budget.reserved_bytes();
    let original_debit = decoder.consumed_allocated_bytes();
    let physical = PhysicalObservation::start();
    let validated = decoder.with(|| context.validate());
    let requests = physical.snapshot().requests();
    drop(physical);
    let current_keys = context
        .committee
        .iter()
        .map(|member| {
            let (_, key) = member.validator.public_key().try_to_bytes().unwrap();
            (
                key.as_ptr(),
                key.len(),
                member.proof_of_possession.as_ptr(),
                member.proof_of_possession.len(),
            )
        })
        .collect::<Vec<_>>();
    let current_wire = norito::encode_canonical(&context).unwrap();
    let current_charge = budget.reserved_bytes();
    let current_debit = decoder.consumed_allocated_bytes();
    let source_is_original =
        genesis.belongs_to(&budget) && genesis.hash() == fixture.genesis().hash();
    drop(blocker);
    drop(generation);
    drop(context);
    drop(genesis);
    drop(decoder);
    let retired = budget.reserved_bytes();

    validated.unwrap();
    assert_eq!(scope, original_scope);
    assert!(source_is_original);
    assert_eq!(current_keys, original_keys);
    assert_eq!(current_wire, wire);
    assert_eq!(current_charge, original_charge);
    assert_eq!(current_debit, original_debit);
    assert_eq!(generation_id, generation_id_from_wire_oracle(&wire));
    assert_eq!(retired, 0);
    assert_eq!(
        requests,
        [0, 0, 0],
        "validating the original signed epoch must not allocate a temporary generation roster: {requests:?}"
    );
}

fn generation_id_from_wire_oracle(wire: &[u8]) -> [u8; 32] {
    // The separately materialized oracle is outside physical observation and
    // grants no source authentication to the measured public call.
    let context: ValidatorEpochContextV1 = norito::decode_canonical(wire).unwrap();
    context.generation().generation_id().unwrap()
}

#[test]
fn borrowed_generation_preserves_exact_identity_and_original_refusal_order() {
    let original = fixture(4);
    let generation = original.generation();
    let expected = generation.generation_id().unwrap();
    let physical = crate::amx_prepare_streaming_allocations::PhysicalObservation::start();
    let borrowed = generation::generation_id_from_roster(
        original.network_id,
        generation.generation,
        original.committee.iter().map(|member| &member.validator),
    );
    let requests = physical.snapshot().requests();
    drop(physical);
    assert_eq!(borrowed.unwrap(), expected);
    assert_eq!(requests, [0, 0, 0]);
    assert_eq!(
        ValidatorEpochAuthorizationV1::genesis_from_committee(
            original.network_id,
            &original.committee,
            original.authorization.last_height,
        )
        .unwrap(),
        original.authorization,
    );
    let generation_error = ValidatorEpochAuthorizationErrorV1::InvalidField {
        field: "validator_generation",
    };
    let relation_error = ValidatorEpochAuthorizationErrorV1::InvalidField {
        field: "epoch_authorization.generation",
    };
    for mutation in 0..4 {
        let mut committee = original.committee.clone();
        match mutation {
            0 => {
                committee.pop();
            }
            1 => committee.swap(0, 1),
            2 => committee[1] = committee[0].clone(),
            _ => {
                committee[0].validator = PeerId::new(
                    KeyPair::from_seed(vec![9; 32], Algorithm::Ed25519)
                        .public_key()
                        .clone(),
                );
            }
        }
        let owned = ValidatorGenerationV1::from_committee(original.network_id, 0, &committee);
        assert_eq!(owned.generation_id(), Err(generation_error));
        assert_eq!(
            generation::generation_id_from_roster(
                original.network_id,
                0,
                committee.iter().map(|member| &member.validator),
            ),
            Err(generation_error),
        );
        // Malformed roster is checked before the competing empty genesis interval.
        assert_eq!(
            ValidatorEpochAuthorizationV1::genesis_from_committee(
                original.network_id,
                &committee,
                0,
            ),
            ValidatorEpochAuthorizationV1::genesis(&owned, 0),
        );
        assert_eq!(
            ValidatorEpochAuthorizationV1::genesis_from_committee(
                original.network_id,
                &committee,
                0,
            ),
            Err(generation_error),
        );
        // Authorization refusal precedes any later malformed roster relation.
        let mut unsupported = original.authorization;
        unsupported.version = 2;
        assert_eq!(
            unsupported.validate_against_committee(original.network_id, 0, &committee),
            Err(ValidatorEpochAuthorizationErrorV1::UnsupportedVersion { actual: 2 }),
        );
        let foreign = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::new(b"borrowed-roster-foreign-network"),
        ));
        assert_eq!(
            original
                .authorization
                .validate_against_committee(foreign, 0, &committee),
            Err(relation_error),
        );
        assert_eq!(
            original
                .authorization
                .validate_against_committee(original.network_id, 1, &committee),
            Err(relation_error),
        );
        assert_eq!(
            original
                .authorization
                .validate_against_committee(original.network_id, 0, &committee),
            Err(generation_error),
        );
    }
    assert_eq!(
        ValidatorEpochAuthorizationV1::genesis_from_committee(
            original.network_id,
            &original.committee,
            0,
        ),
        Err(ValidatorEpochAuthorizationErrorV1::InvalidField {
            field: "epoch_authorization"
        }),
    );
}

#[test]
fn borrowed_epoch_relation_keeps_original_committee_and_authorization_error_order() {
    let original = fixture(4);
    let mut bad = original.clone();
    bad.da_layout.chunk_size_bytes = 0;
    bad.version = 2;
    bad.leader_seed = [0; 32];
    bad.committee[0].proof_of_possession.clear();
    bad.authorization.version = 2;
    let layout_error = bad.da_layout.validate().unwrap_err().to_string();
    assert_eq!(bad.validate(), Err(layout_error));
    bad.da_layout = original.da_layout;
    assert_eq!(
        bad.validate(),
        Err("invalid native epoch version or leader seed".into())
    );
    bad.version = original.version;
    bad.leader_seed = original.leader_seed;
    assert_eq!(
        bad.validate(),
        Err("native committee key order or proof shape is invalid".into())
    );
    bad.committee = original.committee.clone();
    assert_eq!(
        bad.validate(),
        Err(ValidatorEpochAuthorizationErrorV1::UnsupportedVersion { actual: 2 }.to_string()),
    );
    bad.authorization = original.authorization;
    bad.authorization.last_height = 2;
    assert_eq!(
        bad.validate(),
        Err("native NPoS epoch must leave a real preboundary pulse and parent".into()),
    );
    bad.authorization.authority_id[0] ^= 1;
    assert_eq!(
        bad.validate(),
        Err(ValidatorEpochAuthorizationErrorV1::InvalidField {
            field: "epoch_authorization.generation",
        }
        .to_string()),
    );
    assert_eq!(original.validate(), Ok(()));
}
