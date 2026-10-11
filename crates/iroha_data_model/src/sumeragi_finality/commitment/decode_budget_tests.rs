//! Complete ten-seat result codecs, inherited caller allocation-limit controls, and the
//! measurement of the largest supported result body against its byte bound.
//!
//! These are valid native context graphs, not certified execution or finality owners.

use super::*;
use crate::{
    asset::AssetBalanceScope,
    consensus::{
        GLOBAL_THRESHOLD_BEACON_VERSION_V1, GlobalThresholdBeaconChainAnchorV1,
        GlobalThresholdBeaconPulseContextV1,
    },
    nexus::{ValidatorCommitteePreparationV1, ValidatorElectionPolicyV1},
    parameter::system::SumeragiNposParameters,
    sumeragi::epoch::{
        MAX_VALIDATORS, ValidatorCommitteeMemberV1, ValidatorEpochBoundaryV1,
        ValidatorEpochContextV1, ValidatorEpochDecisionV1,
        tests::{fixture, retained},
        validate_committee,
    },
    sumeragi_finality::{
        CertifiedResultScope, CertifiedResultV1, MAX_RESULT_BODY_BYTES, SccpFinalityHeaderFieldsV1,
        SccpFinalityHeaderV1, ScheduledConfig, ScheduledSlot,
        certified_result::{FLAG_ACTIVE, FLAG_ROTATION, MAX_VALIDITY_MS, X_LEN},
        context_committee_root, global_threshold_beacon_pulse_id_v1,
    },
};
use iroha_crypto::{Algorithm, HashOf, KeyPair};
use iroha_model_base::peer::PeerId;
use iroha_primitives::{
    bigint::BigInt,
    numeric::{MAX_MANTISSA_BYTES, Numeric, Quantity, XOR_QUANTITY_SCALE},
};
use iroha_sumeragi::types::ChainParams;
use std::num::NonZeroU64;

pub(super) fn boundary_result(seats: usize) -> ExecutionResultCommitment {
    let current = fixture(seats);
    let next = retained(&current);
    let height = current.authorization.last_height;
    let params = ChainParamsRecord::from_core(&ChainParams::default());
    let slot = |height| {
        ScheduledSlot::Ready(ScheduledConfig {
            height,
            epoch: next.clone(),
            params,
        })
    };
    let (native_lanes, root) = NativeLaneStateProof::empty_for_testing(current.network_id, height);
    ExecutionResultCommitment::new(
        height,
        ExecutionCommitment {
            parent_state_root: Hash::new(b"ten-seat result prestate"),
            post_state_root: root,
            ordinary_writes_root: root,
            parent_world_state_root: Hash::new(b"fixture parent world"),
            world_state_root: Hash::new(b"fixture world"),
            event_commitment: None,
            executed_block_wire_len: 1,
            executed_block_wire_hash: Hash::new(b"synthetic codec result, not executed World"),
            transaction_input_commitment: None,
            transaction_output_commitment: None,
        },
        ScheduleOutcome {
            height,
            boundary: Some(ValidatorEpochBoundaryV1 {
                version: 1,
                height,
                predecessor_context_id: current.context_id().unwrap(),
                selection_anchor: HashOf::from_untyped_unchecked(Hash::new(
                    b"synthetic codec boundary parent",
                )),
                next: next.clone(),
                preparation: None,
            }),
            current,
            next: slot(height + 1),
            after_next: slot(height + 2),
        },
        None,
        native_lanes,
    )
    .unwrap()
}

fn ten_seat_boundary() -> ExecutionResultCommitment {
    boundary_result(10)
}

fn protocol_limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        96,
        MAX_RESULT_PREIMAGE_BYTES,
        norito::canonical_decode_limits(MAX_RESULT_PREIMAGE_BYTES).max_total_elements(),
        allocation,
        32,
    )
}

fn assert_ten_seats(epoch: &ValidatorEpochContextV1) {
    assert_eq!(epoch.committee.len(), 10);
    epoch.validate().unwrap();
}

#[test]
fn ten_seat_boundary_result_roundtrips_complete_repeated_epoch_graph() {
    let value = ten_seat_boundary();
    let bytes = value.preimage().unwrap();
    assert!(bytes.len() <= MAX_RESULT_PREIMAGE_BYTES);
    assert_ten_seats(&value.schedule.current);
    assert_ten_seats(&value.schedule.boundary.as_ref().unwrap().next);
    for slot in [&value.schedule.next, &value.schedule.after_next] {
        let ScheduledSlot::Ready(config) = slot else {
            panic!("boundary must install each successor");
        };
        assert_ten_seats(&config.epoch);
    }
    let decoded = ExecutionResultCommitment::decode(&bytes).unwrap();
    assert_eq!(decoded, value);
    assert_eq!(decoded.preimage().unwrap(), bytes);
    assert_eq!(decoded.result().unwrap(), value.result().unwrap());
    let mut invalid = value;
    invalid.schedule.boundary = None;
    assert!(matches!(
        norito::encode_canonical(&invalid),
        Err(norito::Error::NonCanonicalEncoding)
    ));
}

#[test]
fn strict_outer_allocation_limit_refuses_same_result_and_scope_exit_allows_retry() {
    let value = ten_seat_boundary();
    let bytes = value.preimage().unwrap();
    let original = bytes.clone();
    let inner =
        protocol_limits(norito::canonical_decode_limits(bytes.len()).max_total_allocated_bytes());
    let error = norito::with_decode_limits(protocol_limits(0), || {
        norito::decode_canonical_with_limits::<ExecutionResultCommitment>(&bytes, inner)
    })
    .unwrap_err();
    assert!(error.is_decode_resource_limit());
    assert!(matches!(
        error,
        norito::Error::TotalAllocationExceeded { attempted, limit: 0 } if attempted > 0
    ));
    let wrapped = norito::with_decode_limits_scope(protocol_limits(0), || {
        ExecutionResultCommitment::decode(&bytes)
    });
    // Preserve the exact local category through the production result wrapper.
    assert_eq!(
        wrapped,
        Err(CommitmentError::Resource(
            error.decode_resource_error().unwrap()
        ))
    );
    assert_eq!(bytes, original);
    assert_eq!(ExecutionResultCommitment::decode(&bytes).unwrap(), value);
}

#[test]
fn original_caller_decode_counter_is_not_replaced_after_nested_refusal() {
    let value = ten_seat_boundary();
    let bytes = value.preimage().unwrap();
    let cap = norito::canonical_decode_limits(bytes.len()).max_total_allocated_bytes();
    norito::with_decode_limits_scope(protocol_limits(cap), || {
        // Occupy the existing caller's counter before entering the result decoder. This is
        // counter-policy evidence only; it is not an original memory-pool reservation.
        norito::core::reserve_decode_allocation(cap).unwrap();
        let inner = protocol_limits(cap);
        let error =
            norito::decode_canonical_with_limits::<ExecutionResultCommitment>(&bytes, inner)
                .unwrap_err();
        assert!(matches!(
            error,
            norito::Error::TotalAllocationExceeded { attempted, limit }
                if attempted > limit && limit == cap as u64
        ));
        assert_eq!(
            ExecutionResultCommitment::decode(&bytes),
            Err(CommitmentError::Resource(
                error.decode_resource_error().unwrap()
            ))
        );
        // Failed nested scopes must neither reset nor refund the caller's consumed counter.
        assert!(matches!(
            norito::core::reserve_decode_allocation(1),
            Err(norito::Error::TotalAllocationExceeded { attempted, limit })
                if attempted == cap as u64 + 1 && limit == cap as u64
        ));
    });
    assert_eq!(ExecutionResultCommitment::decode(&bytes).unwrap(), value);
}

#[test]
fn strict_outer_element_limit_refuses_without_replacing_original_counter() {
    let value = ten_seat_boundary();
    let bytes = value.preimage().unwrap();
    let canonical = norito::canonical_decode_limits(bytes.len());
    let outer = norito::DecodeLimits::new(
        96,
        MAX_RESULT_PREIMAGE_BYTES,
        0,
        canonical.max_total_allocated_bytes(),
        32,
    );
    let refusal =
        norito::with_decode_limits_scope(outer, || ExecutionResultCommitment::decode(&bytes));
    assert!(matches!(
        refusal,
        Err(CommitmentError::Resource(
            norito::core::DecodeResourceError::TotalElementsExceeded { .. }
        ))
    ));
    assert_eq!(ExecutionResultCommitment::decode(&bytes).unwrap(), value);
}

/// `count` canonically ordered BLS-normal members with their real proofs of possession, from
/// the seeds `first_seed..first_seed + count`: disjoint seed ranges give disjoint rosters.
fn roster(first_seed: u8, count: usize) -> Vec<ValidatorCommitteeMemberV1> {
    let mut pairs = (0..count)
        .map(|index| {
            let seed = first_seed + u8::try_from(index).unwrap();
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap()
        })
        .collect::<Vec<_>>();
    pairs.sort_by_key(|pair| PeerId::new(pair.public_key().clone()));
    pairs
        .iter()
        .map(|pair| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(pair.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
        })
        .collect()
}

/// The widest bond an election policy admits: the largest mantissa of the signed 512-bit
/// domain, at the XOR scale.
fn widest_bond() -> Quantity {
    // 2^511 - 1 in little-endian two's complement. It is odd, so no trailing zero is trimmed.
    let mut mantissa = [0xFF; MAX_MANTISSA_BYTES];
    mantissa[MAX_MANTISSA_BYTES - 1] = 0x7F;
    let mantissa = BigInt::from_twos_bytes(&mantissa).unwrap();
    Quantity::try_from_numeric(Numeric::try_new(mantissa, XOR_QUANTITY_SCALE).unwrap()).unwrap()
}

fn merkle_commitment<T>(label: &[u8], leaves: u64) -> Option<MerkleTreeCommitment<T>> {
    Some(MerkleTreeCommitment::new(
        HashOf::from_untyped_unchecked(Hash::new(label)),
        NonZeroU64::new(leaves).unwrap(),
    ))
}

/// The largest result body the validation rules admit for `seats` validators.
///
/// It is an epoch boundary under a non-genesis context (the installed beacon binding is the
/// wider one). The boundary activates a second complete committee and freezes a third as the
/// E+2 preparation, whose election policy carries the widest bonds. The finalized pulse and
/// every optional execution commitment are present. Every other field has a fixed width, and
/// a boundary admits only `Ready` successor slots, so only `seats` changes the length.
fn maximal_boundary_result(seats: usize) -> ExecutionResultCommitment {
    // Epoch length of the epoch fixtures: the genesis epoch is heights 1..=10.
    const EPOCH_LENGTH: u64 = 10;
    let current = retained(&fixture(seats));
    let mut next = retained(&current);
    next.committee = roster(32, seats);
    next.authorization.authority_generation += 1;
    next.authorization.transition_id = [0x61; 32];
    next.authorization.decision = ValidatorEpochDecisionV1::Activate;
    next.authorization.authority_id = next.generation().generation_id().unwrap();
    next.validate_successor(&current).unwrap();

    let height = current.authorization.last_height;
    let current_id = current.context_id().unwrap();
    let anchor = HashOf::from_untyped_unchecked(Hash::new(b"maximal boundary parent"));
    let preparation = ValidatorCommitteePreparationV1 {
        version: 1,
        network_id: current.network_id,
        selection_epoch: current.authorization.epoch,
        selection_height: height,
        selection_anchor: anchor,
        target_epoch: current.authorization.epoch + 2,
        first_height: next.authorization.last_height + 1,
        last_height: next.authorization.last_height + EPOCH_LENGTH,
        authority_generation: next.authorization.authority_generation + 1,
        preparing_authorization_id: next.authorization.authorization_id().unwrap(),
        election_seed: [0x43; 32],
        eligibility: ValidatorElectionPolicyV1 {
            xor_asset_definition_id: SumeragiNposParameters::default()
                .xor_asset_definition_id()
                .clone(),
            asset_scope: AssetBalanceScope::Global,
            asset_scale: XOR_QUANTITY_SCALE,
            min_self_bond: widest_bond(),
            min_nomination_bond: widest_bond(),
            max_validators: 31,
            epoch_length_blocks: EPOCH_LENGTH,
        },
        committee: roster(63, seats),
    };

    let BeaconEpochBindingV1::Installed(session) = current.authorization.beacon else {
        panic!("a retained epoch carries an installed beacon binding");
    };
    // Shape validation needs one canonical nonzero G1 point, not a threshold signature.
    let (_, point) = current.committee[0]
        .validator
        .public_key()
        .try_to_bytes()
        .unwrap();
    let mut pulse = FinalizedGlobalThresholdBeaconPulseV1 {
        version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        network_id: current.network_id,
        session_id: session.session_id,
        roster_hash: [0x71; 32],
        transcript_hash: session.transcript_hash,
        context: GlobalThresholdBeaconPulseContextV1 {
            instance: [0x72; 32],
            epoch: current.authorization.epoch,
            epoch_context_id: current_id,
            parent_consensus_hash: [0x73; 32],
            parent_result: [0x74; 32],
        },
        height,
        round: 0,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
            height: height - 1,
            block_hash: anchor,
        },
        signature: point.try_into().unwrap(),
        seed: [0x75; 32],
        pulse_id: [0; 32],
    };
    pulse.pulse_id = global_threshold_beacon_pulse_id_v1(&pulse, pulse.seed);

    let params = ChainParamsRecord::from_core(&ChainParams::default());
    let slot = |height| {
        ScheduledSlot::Ready(ScheduledConfig {
            height,
            epoch: next.clone(),
            params,
        })
    };
    let (native_lanes, root) = NativeLaneStateProof::empty_for_testing(current.network_id, height);
    ExecutionResultCommitment::new(
        height,
        ExecutionCommitment {
            parent_state_root: Hash::new(b"maximal result prestate"),
            post_state_root: root,
            ordinary_writes_root: root,
            parent_world_state_root: Hash::new(b"fixture parent world"),
            world_state_root: Hash::new(b"fixture world"),
            event_commitment: merkle_commitment(b"events", u64::MAX),
            executed_block_wire_len: MAX_EXECUTED_BLOCK_WIRE_BYTES,
            executed_block_wire_hash: Hash::new(b"synthetic codec result, not executed World"),
            transaction_input_commitment: merkle_commitment(b"inputs", u64::MAX),
            transaction_output_commitment: merkle_commitment(b"outputs", u64::MAX),
        },
        ScheduleOutcome {
            height,
            boundary: Some(ValidatorEpochBoundaryV1 {
                version: 1,
                height,
                predecessor_context_id: current_id,
                selection_anchor: anchor,
                next: next.clone(),
                preparation: Some(preparation),
            }),
            next: slot(height + 1),
            after_next: slot(height + 2),
            current,
        },
        Some(pulse),
        native_lanes,
    )
    .unwrap()
}

/// Canonical payload bytes of one component, without the length prefix its parent adds.
fn payload_len(value: &dyn norito::SerializePayload) -> usize {
    let _canonical = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::encoded_payload_len(value).unwrap()
}

/// Measured canonical length of the largest supported result body. It is pinned, so a layout
/// change that moves it also has to update `specs/sccp.md` §13 item 5.
const MAXIMAL_31_SEAT_BOUNDARY_BODY_BYTES: usize = 30_763;

/// `specs/sccp.md` §3.6 and §13 item 5; `specs/sumeragi.md` §4.1.1.
#[test]
fn maximal_31_seat_boundary_with_frozen_preparation_fits_the_result_body_bound() {
    let value = maximal_boundary_result(MAX_VALIDATORS);
    let bytes = norito::encode_canonical(&value).unwrap();
    assert_eq!(bytes.len(), norito::canonical_frame_len(&value).unwrap());
    let boundary = value.schedule.boundary.as_ref().unwrap();
    let preparation = boundary.preparation.as_ref().unwrap();
    let pulse = value.beacon.as_ref().unwrap();

    // Nothing larger is admitted. Seats: three complete rosters of the largest committee.
    assert_eq!(MAX_VALIDATORS, 31);
    for committee in [
        &value.schedule.current.committee,
        &boundary.next.committee,
        &preparation.committee,
    ] {
        assert_eq!(committee.len(), MAX_VALIDATORS);
    }
    assert!(validate_committee(&roster(1, MAX_VALIDATORS + 3)).is_err());
    // Credentials: a member is one 48-byte key and one 96-byte proof, never more.
    let mut longer = value.clone();
    longer.schedule.current.committee[0]
        .proof_of_possession
        .push(0);
    assert!(longer.validate().is_err());
    // Bonds: the mantissa fills the signed 512-bit domain, and the next value is no quantity.
    for bond in [
        &preparation.eligibility.min_self_bond,
        &preparation.eligibility.min_nomination_bond,
    ] {
        assert_eq!(bond.mantissa().twos_byte_len(), MAX_MANTISSA_BYTES);
        assert_eq!(bond.scale(), XOR_QUANTITY_SCALE);
    }
    let mut above = [0; MAX_MANTISSA_BYTES + 1];
    above[MAX_MANTISSA_BYTES - 1] = 0x80;
    assert!(
        Numeric::try_new(BigInt::from_twos_bytes(&above).unwrap(), XOR_QUANTITY_SCALE).is_err()
    );
    // Optional parts: all are present, and dropping any one of them shrinks the frame.
    let optional_parts: [fn(&mut ExecutionResultCommitment); 5] = [
        |body| body.beacon = None,
        |body| body.schedule.boundary.as_mut().unwrap().preparation = None,
        |body| body.execution.event_commitment = None,
        |body| body.execution.transaction_input_commitment = None,
        |body| body.execution.transaction_output_commitment = None,
    ];
    for drop_part in optional_parts {
        let mut smaller = value.clone();
        drop_part(&mut smaller);
        assert!(norito::canonical_frame_len(&smaller).unwrap() < bytes.len());
    }
    // Seats: the smallest supported committee gives a smaller body of the same shape.
    let four_seats = norito::canonical_frame_len(&maximal_boundary_result(4)).unwrap();
    assert!(four_seats < bytes.len());

    // The stored preimage `X ‖ body` of the same body, under an active rotating header, passes
    // the reader with its production decode limits.
    let header = SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: *value.schedule.current.network_id.as_bytes(),
        height: value.height,
        timestamp_ms: 1_790_000_000_000,
        flags: FLAG_ACTIVE | FLAG_ROTATION,
        generation: 1,
        committee_root: context_committee_root(&value.schedule.current).unwrap(),
        validity_ms: MAX_VALIDITY_MS,
        next_committee_root: context_committee_root(&boundary.next).unwrap(),
        ..SccpFinalityHeaderFieldsV1::default()
    })
    .unwrap();
    let certified =
        CertifiedResultV1::new(header, value.clone(), CertifiedResultScope::TairaGlobal).unwrap();
    let preimage = certified.preimage().unwrap();
    assert_eq!(preimage.len(), X_LEN + bytes.len());
    assert_eq!(preimage[X_LEN..], bytes[..]);
    assert!(preimage.len() <= MAX_RESULT_PREIMAGE_BYTES);
    assert_eq!(
        CertifiedResultV1::decode(&preimage, CertifiedResultScope::TairaGlobal),
        Ok(certified)
    );

    // Per-component payload bytes; the last row is what the listed parts do not cover.
    let successor = payload_len(&boundary.next);
    let frozen = payload_len(preparation);
    let parts = [
        ("frame header", bytes.len() - payload_len(&value)),
        ("height", payload_len(&value.height)),
        ("execution commitment", payload_len(&value.execution)),
        (
            "current context, 31 seats",
            payload_len(&value.schedule.current),
        ),
        ("boundary: successor context, 31 seats", successor),
        ("boundary: frozen preparation, 31 seats", frozen),
        (
            "boundary: own fields and framing",
            payload_len(boundary) - successor - frozen,
        ),
        ("beacon pulse", payload_len(pulse)),
        ("native lane state proof", payload_len(&value.native_lanes)),
    ];
    let listed: usize = parts.iter().map(|(_, len)| len).sum();
    let permille = bytes.len() * 1000 / MAX_RESULT_BODY_BYTES;
    println!(
        "31-seat boundary result body: {} of {MAX_RESULT_BODY_BYTES} bytes ({}.{} %); \
         X ‖ body: {} of {MAX_RESULT_PREIMAGE_BYTES} bytes",
        bytes.len(),
        permille / 10,
        permille % 10,
        preimage.len(),
    );
    for (name, len) in parts {
        println!("  {name:<44}{len:>6}");
    }
    println!(
        "  {:<44}{:>6}",
        "field framing and two Ready successor slots",
        bytes.len() - listed
    );
    println!(
        "one committee member: {} bytes; the same shape at 4 seats: {four_seats} bytes",
        payload_len(&value.schedule.current.committee[0]),
    );

    assert!(bytes.len() <= MAX_RESULT_BODY_BYTES);
    assert_eq!(bytes.len(), MAXIMAL_31_SEAT_BOUNDARY_BODY_BYTES);
}
