//! Canonical archive decode and exact ordinary-write allocation custody regressions.

use super::*;
use iroha_data_model::{
    parliament_casting::{
        MAX_PARLIAMENT_CONCURRENT_CASTING_CONTEXTS_V1,
        ParliamentTimedOvnCastingContextBindingV1 as Binding,
        ParliamentTimedOvnCastingPhaseV1 as Phase,
        ParliamentTimedOvnRegistrationCorpusCommitmentV1 as Corpus,
        ParliamentTimedOvnReleaseBindingV1 as Release,
    },
    parliament_types::{
        BallotAttemptId, BodyInstanceId, GovernanceAttemptId, ProposalContentId, TleKeySessionId,
    },
};
use norito::codec::Encode;

fn casting_binding(phase: Phase) -> Binding {
    let mut binding = Binding {
        version: 1,
        evaluated_height: 12,
        phase,
        network_id: [1; 32],
        proposal_content_id: ProposalContentId::new([2; 32]),
        governance_attempt_id: GovernanceAttemptId::new([3; 32]),
        body_instance_id: BodyInstanceId::new([4; 32]),
        ballot_attempt_id: BallotAttemptId::new([9; 32]),
        parameter_hash: [5; 32],
        tle_key_session_id: TleKeySessionId::new([6; 32]),
        tle_key_transcript_hash: [7; 32],
        tle_master_public_key: [8; 96],
        registration_opened_at_finalized_height: 10,
        registration_close_height: 20,
        survivor_freeze_height: 30,
        commitment_close_height: 40,
        target_finalized_height: 50,
        registration_corpus: Corpus::from_records(&[]).unwrap(),
        survivor_count: None,
        dropout_root: None,
        release_identity: None,
    };
    match phase {
        Phase::Registered => {}
        Phase::RegistrationClosed => binding.evaluated_height = 25,
        Phase::SurvivorsFrozen => {
            binding.evaluated_height = 35;
            binding.survivor_count = Some(0);
            binding.dropout_root = Some([11; 32]);
            binding.release_identity = Some(Release {
                tle_key_session_id: binding.tle_key_session_id,
                governance_attempt_id: binding.governance_attempt_id,
                body_instance_id: binding.body_instance_id,
                ballot_attempt_id: binding.ballot_attempt_id,
                survivor_corpus_root: [12; 32],
                no_recovery_root: [13; 32],
                target_finalized_height: binding.target_finalized_height,
                parameter_hash: binding.parameter_hash,
            });
        }
    }
    binding
}
fn replace_field<const N: usize>(
    encoded: &[u8],
    index: usize,
    replacement: &[u8],
    flags: u8,
) -> Vec<u8> {
    let original = fields::<N>(encoded, flags).unwrap();
    let mut output = Vec::new();
    for (i, value) in original.into_iter().enumerate() {
        let value = if index == i { replacement } else { value };
        ncore::write_len_with_flags(&mut output, value.len() as u64, flags).unwrap();
        output.extend_from_slice(value);
    }
    output
}
fn casting_sequence(binding: &[u8], flags: u8) -> Vec<u8> {
    let mut sequence = 1_u64.to_le_bytes().to_vec();
    ncore::write_len_with_flags(&mut sequence, binding.len() as u64, flags).unwrap();
    sequence.extend_from_slice(binding);
    sequence
}

fn projection() -> NativeExecutionProjectionV1 {
    NativeExecutionProjectionV1 {
        carrier_height: 2,
        carrier_hash: HashOf::from_untyped_unchecked(iroha_crypto::Hash::new(b"original carrier")),
        lanes: SumeragiLaneState::default(),
        casting_bindings: vec![],
        sccp_delta: vec![],
        ordinary_writes: vec![
            ExecKv {
                key: vec![1],
                value: vec![2, 3],
            },
            ExecKv {
                key: vec![1],
                value: vec![4, 5, 6],
            },
            ExecKv {
                key: vec![],
                value: vec![],
            },
        ],
    }
}
fn input(bytes: &[u8], budget: &AllocationBudget) -> ChargedBuffer<u8> {
    let mut output = ChargedBuffer::new(bytes.len(), budget).unwrap();
    output.append(bytes).unwrap();
    output
}
fn demand(bytes: &[u8]) -> usize {
    let view = ncore::from_bytes_view(bytes).unwrap();
    let [_, _, _, writes, _, _] = fields::<6>(view.as_bytes(), view.flags()).unwrap();
    RawWrites::new(writes, view.flags())
        .unwrap()
        .demand()
        .unwrap()
        .bytes
}

#[test]
fn original_write_allocations_retain_exact_pool_custody_after_input_drop() {
    let original = projection();
    let bytes = norito::encode_canonical(&original).unwrap();
    let expected = demand(&bytes);
    let budget = AllocationBudget::new(bytes.len() + expected);
    let encoded = input(&bytes, &budget);
    let decoded = decode_projection(&encoded, &budget).unwrap();
    assert_eq!(decoded.carrier_height, original.carrier_height);
    assert_eq!(decoded.carrier_hash, original.carrier_hash);
    assert_eq!(decoded.lane_payload, original.lanes.encode());
    assert_eq!(
        decoded.casting_bindings.as_slice(),
        original.casting_bindings
    );
    assert_eq!(decoded.witness.get().writes, original.ordinary_writes);
    assert!(decoded.witness.belongs_to(&budget));
    assert_eq!(budget.reserved_bytes(), bytes.len() + expected);
    assert_eq!(budget.peak_reserved_bytes(), bytes.len() + expected);
    let DecodedProjection {
        witness,
        casting_bindings,
        ..
    } = decoded;
    drop(encoded);
    assert_eq!(budget.reserved_bytes(), expected);
    assert_eq!(witness.get().writes[1].value, [4, 5, 6]);
    drop(witness);
    drop(casting_bindings);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn capacity_refusal_retains_original_input_and_retry_observation() {
    let bytes = norito::encode_canonical(&projection()).unwrap();
    let expected = demand(&bytes);
    let budget = AllocationBudget::new(bytes.len() + expected);
    let encoded = input(&bytes, &budget);
    let occupied = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    assert!(matches!(decode_projection(&encoded, &budget),
        Err(WriteDecodeError::Admission(AllocationRefusal::Capacity { requested_bytes, .. }))
            if requested_bytes == expected));
    assert_eq!(budget.reserved_bytes(), bytes.len() + 1);
    assert_eq!(budget.peak_reserved_bytes(), bytes.len() + 1);
    assert_eq!(encoded.as_slice(), bytes);
    drop(occupied);
    let decoded = decode_projection(&encoded, &budget).unwrap();
    drop(decoded);
    assert_eq!(budget.reserved_bytes(), bytes.len());
}

#[test]
fn equal_sized_foreign_pool_cannot_fund_source_or_receive_its_refund() {
    let bytes = norito::encode_canonical(&projection()).unwrap();
    let maximum = bytes.len() + demand(&bytes);
    let source = AllocationBudget::new(maximum);
    let foreign = AllocationBudget::new(maximum);
    let encoded = input(&bytes, &source);
    assert!(matches!(
        decode_projection(&encoded, &foreign),
        Err(WriteDecodeError::ForeignPool)
    ));
    assert_eq!(source.reserved_bytes(), bytes.len());
    assert_eq!(foreign.peak_reserved_bytes(), 0);
    let cloned = source.clone();
    let owner = decode_projection(&encoded, &cloned).unwrap();
    assert!(owner.witness.belongs_to(&source));
    drop(owner);
    drop(encoded);
    assert_eq!(source.reserved_bytes(), 0);
}

#[test]
fn malformed_write_count_and_suffix_fail_before_materialization() {
    let flags = ncore::default_encode_flags();
    assert!(RawWrites::new(&u64::MAX.to_le_bytes(), flags).is_err());
    assert!(RawWrites::new(&1_u64.to_le_bytes(), flags).is_err());
    let extra = [0_u8; 9];
    assert!(RawWrites::new(&extra, flags).unwrap().demand().is_err());
    assert!(raw_bytes(&[0; 9]).is_err());
    assert!(array::<ExecKv>(usize::MAX).is_err());
}

#[test]
fn canonical_framing_and_post_admission_errors_never_leak_normal_drop_credit() {
    let original = projection();
    let bytes = norito::encode_canonical(&original).unwrap();
    let budget = AllocationBudget::new(1 << 20);
    let mut variants = vec![bytes[..bytes.len() - 1].to_vec()];
    let mut suffix = bytes.clone();
    suffix.push(0);
    variants.push(suffix);
    let mut wrong_schema = bytes.clone();
    wrong_schema[8] ^= 1;
    variants.push(wrong_schema);
    for malformed in variants {
        let encoded = input(&malformed, &budget);
        let before = budget.reserved_bytes();
        assert!(decode_projection(&encoded, &budget).is_err());
        assert_eq!(budget.reserved_bytes(), before);
        drop(encoded);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    // A valid raw write graph followed by a bad fixed carrier hash exercises cleanup after
    // complete write allocation, while retaining the original schema/header/checksum.
    let view = ncore::from_bytes_view(&bytes).unwrap();
    let root = fields::<6>(view.as_bytes(), view.flags()).unwrap();
    let mut payload = Vec::new();
    for (index, field) in root.into_iter().enumerate() {
        let value = if index == 1 { &[][..] } else { field };
        ncore::write_len_with_flags(&mut payload, value.len() as u64, view.flags()).unwrap();
        payload.extend_from_slice(value);
    }
    let invalid =
        ncore::frame_bare_with_header_flags::<NativeExecutionProjectionV1>(&payload, view.flags())
            .unwrap();
    let encoded = input(&invalid, &budget);
    let before = budget.reserved_bytes();
    assert!(decode_projection(&encoded, &budget).is_err());
    assert!(
        budget.peak_reserved_bytes() > before,
        "write allocations preceded the bad carrier hash"
    );
    assert_eq!(budget.reserved_bytes(), before);
    drop(encoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn unwind_keeps_ledger_until_complete_payload_reclamation_can_be_proven() {
    let bytes = norito::encode_canonical(&projection()).unwrap();
    let view = ncore::from_bytes_view(&bytes).unwrap();
    let [_, _, _, writes, _, _] = fields::<6>(view.as_bytes(), view.flags()).unwrap();
    let raw = RawWrites::new(writes, view.flags()).unwrap();
    let expected = raw.demand().unwrap().bytes;
    let budget = AllocationBudget::new(expected);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut construction = Construction::new(raw.demand().unwrap(), &budget).unwrap();
        let _writes = construction.writes(raw).unwrap();
        panic!("injected construction unwind before immutable custody transfer");
    }));
    assert!(outcome.is_err());
    // Conservatively leaked only in this injected unwind. No uncertain partial destructor
    // returns credits that a subsequent proof could spend again.
    assert_eq!(budget.reserved_bytes(), expected);
}

#[test]
fn canonical_casting_phases_retain_original_exact_array_and_write_custody() {
    let mut original = projection();
    original.casting_bindings = [
        Phase::Registered,
        Phase::RegistrationClosed,
        Phase::SurvivorsFrozen,
    ]
    .into_iter()
    .map(casting_binding)
    .collect();
    let bytes = norito::encode_canonical(&original).unwrap();
    let casting_bytes = array::<Binding>(original.casting_bindings.len())
        .unwrap()
        .size();
    let expected = demand(&bytes) + casting_bytes;
    let budget = AllocationBudget::new(bytes.len() + expected);
    let encoded = input(&bytes, &budget);
    let decoded = decode_projection(&encoded, &budget).unwrap();
    assert_eq!(
        decoded.casting_bindings.as_slice(),
        original.casting_bindings
    );
    assert!(decoded.casting_bindings.belongs_to(&budget));
    assert!(
        !decoded
            .casting_bindings
            .belongs_to(&AllocationBudget::new(budget.reserved_bytes()))
    );
    assert_eq!(budget.reserved_bytes(), bytes.len() + expected);
    assert_eq!(budget.peak_reserved_bytes(), bytes.len() + expected);
    let DecodedProjection {
        witness,
        casting_bindings,
        ..
    } = decoded;
    drop(encoded);
    assert_eq!(budget.reserved_bytes(), expected);
    drop(witness);
    assert_eq!(budget.reserved_bytes(), casting_bytes);
    assert_eq!(
        casting_bindings.as_slice()[2].release_identity,
        original.casting_bindings[2].release_identity
    );
    drop(casting_bindings);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn casting_and_writes_require_one_complete_reservation_before_materialization() {
    let mut original = projection();
    original
        .casting_bindings
        .push(casting_binding(Phase::SurvivorsFrozen));
    let bytes = norito::encode_canonical(&original).unwrap();
    let expected = demand(&bytes) + array::<Binding>(1).unwrap().size();
    let budget = AllocationBudget::new(bytes.len() + expected);
    let encoded = input(&bytes, &budget);
    let occupied = ChargedBuffer::<u8>::new(1, &budget).unwrap();
    assert!(matches!(decode_projection(&encoded, &budget),
        Err(WriteDecodeError::Admission(AllocationRefusal::Capacity { requested_bytes, .. }))
        if requested_bytes == expected));
    assert_eq!(budget.peak_reserved_bytes(), bytes.len() + 1);
    drop(occupied);
    let decoded = decode_projection(&encoded, &budget).unwrap();
    assert_eq!(
        decoded.casting_bindings.as_slice(),
        original.casting_bindings
    );
    drop(decoded);
    drop(encoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn casting_materializer_rejects_malformed_native_fields_before_any_allocation() {
    let flags = ncore::default_encode_flags();
    let original = casting_binding(Phase::SurvivorsFrozen).encode();
    let root = fields::<21>(&original, flags).unwrap();
    let bad_id_version = replace_field::<3>(root[4], 0, &2_u16.to_le_bytes(), flags);
    let bad_id_length = replace_field::<3>(root[4], 1, &31_u16.to_le_bytes(), flags);
    let bad_id_generic = replace_field::<3>(root[4], 2, &[2_u8; 32].encode(), flags);
    let bad_digest = replace_field::<3>(root[17], 2, &[0; 32], flags);
    let mut option_suffix = root[20].to_vec();
    option_suffix.push(0);
    let mutations = [
        replace_field::<21>(&original, 2, &3_u32.to_le_bytes(), flags),
        replace_field::<21>(&original, 3, &[1_u8; 32].encode(), flags),
        replace_field::<21>(&original, 8, &[5_u8; 32].encode(), flags),
        replace_field::<21>(&original, 11, &[8_u8; 96].encode(), flags),
        replace_field::<21>(&original, 4, &bad_id_version, flags),
        replace_field::<21>(&original, 4, &bad_id_length, flags),
        replace_field::<21>(&original, 4, &bad_id_generic, flags),
        replace_field::<21>(&original, 11, &root[11][..root[11].len() - 1], flags),
        replace_field::<21>(&original, 17, &bad_digest, flags),
        replace_field::<21>(&original, 18, &[0, 0], flags),
        replace_field::<21>(&original, 19, &[2], flags),
        replace_field::<21>(&original, 20, &option_suffix, flags),
    ];
    let mut projection = projection();
    projection
        .casting_bindings
        .push(casting_binding(Phase::SurvivorsFrozen));
    let encoded = norito::encode_canonical(&projection).unwrap();
    let view = ncore::from_bytes_view(&encoded).unwrap();
    for malformed in mutations {
        let sequence = casting_sequence(&malformed, flags);
        assert!(RawCasting::new(&sequence, flags).is_err());
        let payload = replace_field::<6>(view.as_bytes(), 4, &sequence, view.flags());
        let frame = ncore::frame_bare_with_header_flags::<NativeExecutionProjectionV1>(
            &payload,
            view.flags(),
        )
        .unwrap();
        let budget = AllocationBudget::new(frame.len() + (1 << 20));
        let input = input(&frame, &budget);
        assert!(decode_projection(&input, &budget).is_err());
        assert_eq!(budget.peak_reserved_bytes(), frame.len());
        drop(input);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    assert!(RawCasting::new(&u64::MAX.to_le_bytes(), flags).is_err());
    assert!(RawCasting::new(&[0; 9], flags).is_err());
    let too_many = vec![
        casting_binding(Phase::Registered);
        MAX_PARLIAMENT_CONCURRENT_CASTING_CONTEXTS_V1 as usize + 1
    ]
    .encode();
    assert!(RawCasting::new(&too_many, flags).is_err());
}

#[test]
fn compact_casting_backing_cannot_be_rebound_to_an_equal_sized_pool() {
    let values = vec![casting_binding(Phase::SurvivorsFrozen)].encode();
    let raw = RawCasting::new(&values, ncore::default_encode_flags()).unwrap();
    let bytes = array::<Binding>(1).unwrap().size();
    let original = AllocationBudget::new(bytes);
    let foreign = AllocationBudget::new(bytes);
    let mut reservation = original.try_reserve_bytes(bytes).unwrap();
    let buffer = raw.materialize(&mut reservation).unwrap();
    assert_eq!(reservation.remaining_bytes(), 0);
    let (values, charge) = casting::split(buffer);
    assert!(matches!(
        casting::retain(values, charge, &foreign),
        Err(WriteDecodeError::ForeignPool)
    ));
    assert_eq!(original.reserved_bytes(), 0);
    assert_eq!(foreign.peak_reserved_bytes(), 0);
}

#[test]
fn nonempty_lane_graph_is_borrowed_from_the_original_charged_frame() {
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::sumeragi_lanes::{
        SumeragiLaneFrontier, SumeragiLaneMember, SumeragiLaneRecord, SumeragiLaneSample,
    };
    use iroha_model_base::{
        peer::PeerId,
        topology::{DataSpaceId, LaneId},
    };
    let mut original = projection();
    let mut committee = (1..=4)
        .map(|seed| {
            let keys = KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal);
            SumeragiLaneMember {
                peer: PeerId::new(keys.public_key().clone()),
                pop: iroha_crypto::bls_normal_pop_prove(keys.private_key()).unwrap(),
            }
        })
        .collect::<Vec<_>>();
    committee.sort();
    original.lanes = SumeragiLaneState {
        custody: Vec::new(),
        lanes: vec![SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(1),
            dataspace: DataSpaceId::new(1),
            incarnation: [1; 32],
            params: Default::default(),
            committee,
            created_at: 1,
            active_from: 3,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 3,
            rescued: 0,
        }],
        samples: vec![SumeragiLaneSample {
            height: 1,
            time_ms: 1_000,
            transactions: 4,
            lanes: 2,
        }]
        .try_into()
        .unwrap(),
        last_transition: 1,
        incarnations: 1,
    };
    let bytes = norito::encode_canonical(&original).unwrap();
    let expected = demand(&bytes);
    let budget = AllocationBudget::new(bytes.len() + expected);
    let input = input(&bytes, &budget);
    let decoded = decode_projection(&input, &budget).unwrap();
    let view = ncore::from_bytes_view(input.as_slice()).unwrap();
    let lane = fields::<6>(view.as_bytes(), view.flags()).unwrap()[2];
    assert!(std::ptr::eq(decoded.lane_payload.as_ptr(), lane.as_ptr()));
    assert_eq!(decoded.lane_payload, original.lanes.encode());
    assert_eq!(
        budget.peak_reserved_bytes(),
        bytes.len() + expected,
        "no committee, key, PoP, algorithm or sample DTO allocation may consume credits"
    );
    drop(decoded);
    drop(input);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn alternate_archive_flags_and_noncanonical_outer_lengths_are_rejected() {
    let original = projection();
    let (payload, flags) = norito::codec::encode_with_header_flags(&original);
    assert_eq!(flags, ncore::default_encode_flags());
    // Valid checksum and schema with unsupported/noncanonical layout flags still cannot enter.
    let frame =
        ncore::frame_bare_with_header_flags::<NativeExecutionProjectionV1>(&payload, 0).unwrap();
    let budget = AllocationBudget::new(frame.len() + (1 << 20));
    let encoded = input(&frame, &budget);
    assert!(decode_projection(&encoded, &budget).is_err());
    assert_eq!(budget.peak_reserved_bytes(), frame.len());
    drop(encoded);
    let fields = fields::<6>(&payload, flags).unwrap();
    let mut changed = Vec::new();
    // Encode the first short length with an overlong compact prefix, preserving all field bytes.
    changed.extend_from_slice(&[(fields[0].len() as u8) | 0x80, 0]);
    changed.extend_from_slice(fields[0]);
    for field in &fields[1..] {
        ncore::write_len_with_flags(&mut changed, field.len() as u64, flags).unwrap();
        changed.extend_from_slice(field);
    }
    let frame = ncore::frame_bare_with_header_flags::<NativeExecutionProjectionV1>(&changed, flags)
        .unwrap();
    let encoded = input(&frame, &budget);
    assert!(decode_projection(&encoded, &budget).is_err());
    drop(encoded);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn mandatory_delta_field_has_no_five_field_fallback() {
    let projection = projection();
    let encoded = norito::encode_canonical(&projection).unwrap();
    let view = ncore::from_bytes_view(&encoded).unwrap();
    let items = fields::<6>(view.as_bytes(), view.flags()).unwrap();
    let mut old_payload = Vec::new();
    for item in &items[..5] {
        ncore::write_len_with_flags(
            &mut old_payload,
            u64::try_from(item.len()).unwrap(),
            view.flags(),
        )
        .unwrap();
        old_payload.extend_from_slice(item);
    }
    let frame = ncore::frame_bare_with_header_flags::<NativeExecutionProjectionV1>(
        &old_payload,
        view.flags(),
    )
    .unwrap();
    let budget = AllocationBudget::new(frame.len() + (1 << 20));
    let source = input(&frame, &budget);
    assert!(decode_projection(&source, &budget).is_err());
    drop(source);
    assert_eq!(budget.reserved_bytes(), 0);
}
