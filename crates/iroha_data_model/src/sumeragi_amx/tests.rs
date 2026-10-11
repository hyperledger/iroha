//! AMX records, proofs, the foreign-committee tracker and the global two-phase-commit state,
//! over genuine BLS certificates of synthetic foreign blocks.

use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair, bls_normal_aggregate_signatures};
use iroha_model_base::peer::PeerId;
use iroha_sumeragi::{
    message::{BlockHeader as CoreHeader, Qc, VoteKind},
    types::{AggregateSignature, Bitmap, ChainParams, ControlWitness, Hash32},
};

use super::*;
use crate::{
    block::consensus::{ExecKv, ExecWitness},
    sumeragi::epoch::{
        BeaconEpochBindingV1, InstalledBeaconEpochBindingV1, ValidatorCommitteeMemberV1,
        ValidatorEpochBoundaryV1, ValidatorEpochContextV1, ValidatorEpochDecisionV1,
        tests::{fixture, retained},
    },
    sumeragi_finality::{
        ChainParamsRecord, ExecutionCommitment, ExecutionResultCommitment, FinalityValidator,
        NativeLaneStateProof, ProofCrypto, SUMERAGI_LANE_STATE_WITNESS_KEY, ScheduleOutcome,
        ScheduledConfig, ScheduledSlot, SumeragiLaneStateCommitment, core_epoch,
    },
    sumeragi_lanes::SumeragiLaneState,
};

const DS1: DataSpaceId = DataSpaceId::new(11);
const DS2: DataSpaceId = DataSpaceId::new(12);
const DS3: DataSpaceId = DataSpaceId::new(13);

fn instance(dataspace: DataSpaceId) -> [u8; 32] {
    Hash::new(dataspace.as_u64().to_be_bytes()).into()
}

/// The BLS key pairs of seeds `seeds`, as `fixture` derives them.
fn key_pairs(seeds: impl IntoIterator<Item = u8>) -> Vec<KeyPair> {
    seeds
        .into_iter()
        .map(|seed| KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal).unwrap())
        .collect()
}

/// A successor of `previous` activating a new generation with the keys of `seeds`.
fn rotated(previous: &ValidatorEpochContextV1, seeds: [u8; 4]) -> ValidatorEpochContextV1 {
    let mut pairs = key_pairs(seeds);
    pairs.sort_by_key(|pair| PeerId::new(pair.public_key().clone()));
    let mut next = retained(previous);
    next.committee = pairs
        .iter()
        .map(|pair| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(pair.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(pair.private_key()).unwrap(),
        })
        .collect();
    next.authorization.authority_generation += 1;
    next.authorization.authority_id = next.generation().generation_id().unwrap();
    next.authorization.decision = ValidatorEpochDecisionV1::Activate;
    next.authorization.transition_id = [0x61; 32];
    next.authorization.beacon = BeaconEpochBindingV1::Installed(InstalledBeaconEpochBindingV1 {
        session_id: [0x42; 32],
        transcript_hash: [0x52; 32],
    });
    next.leader_seed = [0x33; 32];
    next.validate_successor(previous).unwrap();
    next
}

fn slot(height: u64, context: &ValidatorEpochContextV1) -> ScheduledSlot {
    ScheduledSlot::Ready(ScheduledConfig {
        height,
        epoch: context.clone(),
        params: ChainParamsRecord::from_core(&ChainParams::default()),
    })
}

/// A genesis-anchored epoch context whose first epoch spans heights `1..=100`, for tests that
/// need more heights than [`fixture`]'s ten.
fn long_fixture() -> ValidatorEpochContextV1 {
    let mut context = fixture(4);
    context.authorization.last_height = 100;
    context.validate().unwrap();
    context
}

/// The retained successor of `previous`: same generation, committee and installed beacon, next
/// interval.
fn kept(previous: &ValidatorEpochContextV1) -> ValidatorEpochContextV1 {
    let mut next = retained(previous);
    next.authorization.transition_id = [0; 32];
    if previous.authorization.beacon != BeaconEpochBindingV1::Bootstrap {
        next.authorization.beacon = previous.authorization.beacon;
    }
    next.validate_successor(previous).unwrap();
    next
}

/// The complete write set of a synthetic block of `context` at `height`: the mandatory
/// lane-state write, then `writes`. A record proof's path is built over all of it.
fn block_writes(
    context: &ValidatorEpochContextV1,
    height: u64,
    writes: &[(Vec<u8>, Vec<u8>)],
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let lanes = SumeragiLaneStateCommitment::from_state(
        context.network_id,
        height,
        &SumeragiLaneState::default(),
    )
    .unwrap();
    let mut all = vec![(
        SUMERAGI_LANE_STATE_WITNESS_KEY.to_vec(),
        norito::encode_canonical(&lanes).unwrap(),
    )];
    all.extend(writes.iter().cloned());
    all
}

/// The certified result of a synthetic block of `context` at `height` whose execution wrote
/// `writes` (plus the mandatory lane-state write); at the last height of the epoch it carries
/// the boundary into `next`.
fn result_commitment(
    context: &ValidatorEpochContextV1,
    height: u64,
    writes: &[(Vec<u8>, Vec<u8>)],
    next: Option<&ValidatorEpochContextV1>,
) -> ExecutionResultCommitment {
    let mut witness = ExecWitness::default();
    for (key, value) in block_writes(context, height, writes) {
        witness.writes.push(ExecKv { key, value });
    }
    let scratch = NativeLaneStateProof::scratch_bytes(witness.writes.len()).unwrap();
    let native_lanes = NativeLaneStateProof::from_witness(
        &witness,
        &iroha_allocation::AllocationBudget::new(scratch),
    )
    .unwrap();
    let root = native_lanes.computed_root().unwrap();
    // Two independent implementations of the write-set tree agree.
    assert_eq!(
        write_set_root(
            witness
                .writes
                .iter()
                .map(|write| (write.key.as_slice(), write.value.as_slice()))
        )
        .unwrap(),
        root
    );
    let boundary = next.map(|next| ValidatorEpochBoundaryV1 {
        version: 1,
        height,
        predecessor_context_id: context.context_id().unwrap(),
        selection_anchor: HashOf::from_untyped_unchecked(Hash::new(b"boundary parent")),
        next: next.clone(),
        preparation: None,
    });
    let successor = next.unwrap_or(context);
    let schedule = ScheduleOutcome {
        height,
        current: context.clone(),
        boundary,
        next: slot(height + 1, successor),
        after_next: slot(height + 2, successor),
    };
    ExecutionResultCommitment::new(
        height,
        ExecutionCommitment {
            parent_state_root: Hash::new(b"parent"),
            post_state_root: root,
            ordinary_writes_root: root,
            parent_world_state_root: Hash::new(b"fixture parent world"),
            world_state_root: Hash::new(b"fixture world"),
            event_commitment: None,
            executed_block_wire_len: 64,
            executed_block_wire_hash: Hash::new(height.to_be_bytes()),
            transaction_input_commitment: None,
            transaction_output_commitment: None,
        },
        schedule,
        None,
        native_lanes,
    )
    .unwrap()
}

/// A core header of `instance` at `height` in `context` and its `CommitQC` for `result`, signed
/// by the first `signers` members of the committee (canonical key order).
fn sign(
    instance: [u8; 32],
    context: &ValidatorEpochContextV1,
    height: u64,
    result: Hash32,
    signers: usize,
) -> (CoreHeader, Qc) {
    let validators: Vec<FinalityValidator> = context
        .committee
        .iter()
        .map(|member| FinalityValidator {
            public_key: member.validator.public_key().clone(),
            proof_of_possession: member.proof_of_possession.clone(),
        })
        .collect();
    let (crypto, _) = ProofCrypto::new(&validators).unwrap();
    let epoch = core_epoch(context).unwrap();
    let header = CoreHeader {
        instance: Hash32(instance),
        epoch: epoch.id,
        height,
        origin_view: 0,
        parent_hash: Hash32([7; 32]),
        parent_result: Hash32([8; 32]),
        payload_hash: Hash32([9; 32]),
        availability_digest: Hash32([10; 32]),
        payload_len: 100,
        proposer: 0,
        skipped_leaders: vec![],
        control_witness: ControlWitness::empty(),
    };
    let mut qc = Qc {
        kind: VoteKind::Commit,
        instance: header.instance,
        epoch: header.epoch,
        height,
        view: 0,
        block_hash: header.hash(&crypto),
        result,
        signers: Bitmap::from_indices(4, 0..u32::try_from(signers).unwrap()).unwrap(),
        agg_sig: AggregateSignature([0; 96]),
    };
    let everyone = key_pairs(1..=16);
    let shares: Vec<_> = context
        .committee
        .iter()
        .take(signers)
        .map(|member| {
            let pair = everyone
                .iter()
                .find(|pair| pair.public_key() == member.validator.public_key())
                .expect("a fixture key");
            iroha_crypto::Signature::try_new(pair.private_key(), &qc.preimage()).unwrap()
        })
        .collect();
    let payloads: Vec<_> = shares
        .iter()
        .map(iroha_crypto::Signature::payload)
        .collect();
    qc.agg_sig = AggregateSignature(
        bls_normal_aggregate_signatures(&payloads)
            .unwrap()
            .try_into()
            .unwrap(),
    );
    (header, qc)
}

/// Certify a synthetic block of `instance` at `height` in `context` whose execution wrote
/// `writes` (plus the mandatory lane-state write), signed by `signers` members; at the last
/// height of the epoch the result carries the boundary into `next`.
fn certify(
    instance: [u8; 32],
    context: &ValidatorEpochContextV1,
    height: u64,
    writes: &[(Vec<u8>, Vec<u8>)],
    next: Option<&ValidatorEpochContextV1>,
    signers: usize,
) -> AmxCertifiedBlockV1 {
    let commitment = result_commitment(context, height, writes, next);
    let (header, qc) = sign(
        instance,
        context,
        height,
        commitment.result().unwrap(),
        signers,
    );
    AmxCertifiedBlockV1 {
        consensus_header: norito::encode_canonical(&header).unwrap(),
        commit_qc: norito::encode_canonical(&qc).unwrap(),
        result_preimage: commitment.preimage().unwrap(),
    }
}

fn write_of(record: &AmxRecordV1) -> (Vec<u8>, Vec<u8>) {
    (
        record.witness_key().to_vec(),
        record.witness_value().unwrap(),
    )
}

/// A proof that `instance` recorded `record` at `height` of `context`, next to `others`.
fn record_proof(
    instance: [u8; 32],
    context: &ValidatorEpochContextV1,
    height: u64,
    record: &AmxRecordV1,
    others: &[(Vec<u8>, Vec<u8>)],
) -> AmxRecordProofV1 {
    let mut writes = others.to_vec();
    writes.push(write_of(record));
    let block = certify(instance, context, height, &writes, None, 3);
    AmxRecordProofV1::from_writes(
        block,
        block_writes(context, height, &writes)
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        record.clone(),
    )
    .unwrap()
}

fn transaction(participants: &[DataSpaceId], deadline: u64, nonce: u8) -> AmxTransactionV1 {
    AmxTransactionV1 {
        legs: participants
            .iter()
            .map(|dataspace| AmxLegV1 {
                dataspace: *dataspace,
                payload: vec![nonce; 3],
            })
            .collect(),
        deadline,
        nonce: [nonce; 32],
    }
}

fn prepared(tx: [u8; 32], participant: DataSpaceId, vote: AmxVoteV1) -> AmxRecordV1 {
    AmxRecordV1::Prepared(AmxPreparedV1 {
        tx,
        participant,
        vote,
    })
}

fn state_with(dataspaces: &[DataSpaceId]) -> SumeragiAmxState {
    let mut state = SumeragiAmxState::default();
    for dataspace in dataspaces {
        state
            .register_dataspace(
                *dataspace,
                AmxForeignInstanceV1::new(instance(*dataspace), fixture(4)).unwrap(),
            )
            .unwrap();
    }
    state
}

#[test]
fn sumeragi_amx_transaction_id_binds_every_field_and_validates_shape() {
    let base = transaction(&[DS1, DS2], 50, 1);
    let id = base.id().unwrap();
    assert_eq!(id, base.id().unwrap());
    let mut changed = base.clone();
    changed.deadline += 1;
    assert_ne!(changed.id().unwrap(), id);
    let mut changed = base.clone();
    changed.nonce[0] ^= 1;
    assert_ne!(changed.id().unwrap(), id);
    let mut changed = base.clone();
    changed.legs[1].payload.push(0);
    assert_ne!(changed.id().unwrap(), id);
    let begin = base.begin().unwrap();
    assert_eq!(begin.participants, vec![DS1, DS2]);
    assert!(begin.matches(&base) && !begin.matches(&changed));
    assert_eq!(base.leg(DS2).unwrap().dataspace, DS2);
    assert!(base.leg(DS3).is_none());

    for bad in [
        transaction(&[DS1], 50, 1),
        transaction(&[DS2, DS1], 50, 1),
        transaction(&[DS1, DS1], 50, 1),
        transaction(&[DS1, DS2], 0, 1),
    ] {
        assert!(bad.id().is_err(), "{bad:?}");
    }
    let mut oversized = base.clone();
    oversized.legs[0].payload = vec![0; MAX_AMX_LEG_BYTES + 1];
    assert!(oversized.validate().is_err());
    let many: Vec<DataSpaceId> = (0..=MAX_AMX_PARTICIPANTS as u64)
        .map(DataSpaceId::new)
        .collect();
    assert!(transaction(&many, 50, 1).validate().is_err());
    assert!(
        transaction(&many[..MAX_AMX_PARTICIPANTS], 50, 1)
            .validate()
            .is_ok()
    );
}

#[test]
fn sumeragi_amx_begin_match_borrows_exact_fields_and_rejects_each_substitution() {
    let original = transaction(&[DS1, DS2], 50, 1);
    let begin = original.begin().unwrap();
    let expected_frame = norito::encode_canonical(&original).unwrap();
    let expected_id: [u8; 32] =
        Hash::new_from_chunks(&[AMX_TRANSACTION_DOMAIN, &expected_frame]).into();
    assert_eq!(original.id().unwrap(), expected_id);
    let legs = original.legs.as_ptr();
    let participants = begin.participants.as_ptr();
    assert!(begin.matches(&original));
    for altered in [
        AmxBeginV1 {
            tx: [0; 32],
            ..begin.clone()
        },
        AmxBeginV1 {
            deadline: 51,
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DS1, DS3],
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DS2, DS1],
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DS1],
            ..begin.clone()
        },
        AmxBeginV1 {
            participants: vec![DS1, DS2, DS3],
            ..begin.clone()
        },
    ] {
        assert!(!altered.matches(&original));
    }
    for malformed in [
        transaction(&[DS1], 50, 1),
        transaction(&[DS1, DS1], 50, 1),
        transaction(&[DS2, DS1], 50, 1),
        transaction(&[DS1, DS2], 0, 1),
    ] {
        let mut altered = begin.clone();
        altered.deadline = malformed.deadline;
        altered.participants = malformed.legs.iter().map(|leg| leg.dataspace).collect();
        assert!(!altered.matches(&malformed));
        assert!(matches!(malformed.id(), Err(AmxError::Transaction(_))));
    }
    assert_eq!(original.legs.as_ptr(), legs);
    assert_eq!(begin.participants.as_ptr(), participants);
    assert_eq!(norito::encode_canonical(&original).unwrap(), expected_frame);
}

#[test]
fn sumeragi_amx_records_round_trip_norito_and_json() {
    let tx = transaction(&[DS1, DS2], 50, 1);
    let x = tx.id().unwrap();
    let records = [
        AmxRecordV1::Begin(tx.begin().unwrap()),
        prepared(x, DS1, AmxVoteV1::Yes([5; 32])),
        prepared(x, DS2, AmxVoteV1::No),
        AmxRecordV1::Decision(AmxDecisionV1 {
            tx: x,
            outcome: AmxOutcomeV1::Commit,
        }),
        AmxRecordV1::Decision(AmxDecisionV1 {
            tx: x,
            outcome: AmxOutcomeV1::Abort,
        }),
    ];
    for record in &records {
        let bytes = norito::encode_canonical(record).unwrap();
        assert_eq!(
            &norito::decode_canonical::<AmxRecordV1>(&bytes).unwrap(),
            record
        );
        let json = norito::json::to_json(record).unwrap();
        assert_eq!(
            &norito::json::from_str::<AmxRecordV1>(&json).unwrap(),
            record
        );
        let (key, value) = write_of(record);
        assert_eq!(key[0], 0xD9);
        assert_eq!(key[1], record.kind() as u8);
        assert_eq!(&key[2..], x.as_slice());
        assert_eq!(&AmxRecordV1::from_witness(&key, &value).unwrap(), record);
    }
    // A value under another record's key, or a malformed value, is not a record.
    let (begin_key, _) = write_of(&records[0]);
    let (_, decision_value) = write_of(&records[3]);
    assert!(AmxRecordV1::from_witness(&begin_key, &decision_value).is_err());
    assert!(AmxRecordV1::from_witness(&begin_key, &[1, 2, 3]).is_err());
    let json = norito::json::to_json(&tx).unwrap();
    assert_eq!(
        norito::json::from_str::<AmxTransactionV1>(&json).unwrap(),
        tx
    );
    let bytes = norito::encode_canonical(&tx).unwrap();
    assert_eq!(
        norito::decode_canonical::<AmxTransactionV1>(&bytes).unwrap(),
        tx
    );
}

#[test]
fn sumeragi_amx_write_proof_matches_the_certified_write_root() {
    let writes: Vec<(Vec<u8>, Vec<u8>)> = (0u8..40)
        .map(|index| (vec![index, 1, 2], vec![index; usize::from(index) + 1]))
        .collect();
    let pairs = || {
        writes
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
    };
    let root = write_set_root(pairs()).unwrap();
    for (key, value) in &writes {
        let (proof, found) = AmxWriteProofV1::from_writes(pairs(), key).unwrap();
        assert_eq!(&found, value);
        assert_eq!(proof.root(key, value).unwrap(), root);
        assert!(proof.siblings.len() < 20, "compact path");
        assert_ne!(proof.root(key, b"other").unwrap(), root);
        let bytes = norito::encode_canonical(&proof).unwrap();
        assert_eq!(
            norito::decode_canonical::<AmxWriteProofV1>(&bytes).unwrap(),
            proof
        );
        let mut tampered = proof.clone();
        tampered.present[0] ^= 1;
        assert!(!tampered.root(key, value).is_ok_and(|other| other == root));
        let mut unmarked = proof.clone();
        if let Some(first) = unmarked.siblings.first_mut() {
            first[31] &= 0xFE;
            assert!(unmarked.root(key, value).is_err());
        }
    }
    assert!(AmxWriteProofV1::from_writes(pairs(), b"absent").is_err());
    // The last write of a key wins, as in the executor's recorder.
    let mut repeated = writes.clone();
    repeated.push((writes[3].0.clone(), b"latest".to_vec()));
    let (proof, found) = AmxWriteProofV1::from_writes(
        repeated
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        &writes[3].0,
    )
    .unwrap();
    assert_eq!(found, b"latest");
    assert_eq!(
        proof.root(&writes[3].0, b"latest").unwrap(),
        write_set_root(
            repeated
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice()))
        )
        .unwrap()
    );
    assert_eq!(write_set_root(std::iter::empty()).unwrap(), Hash::new([]));
}

#[test]
fn sumeragi_amx_record_proof_construction_requires_the_complete_certified_write_set() {
    let context = fixture(4);
    let tx = transaction(&[DS1, DS2], 50, 1).id().unwrap();
    let record = prepared(tx, DS1, AmxVoteV1::Yes([5; 32]));
    let writes = vec![
        (b"unrelated".to_vec(), b"write".to_vec()),
        write_of(&record),
    ];
    let block = certify(instance(DS1), &context, 3, &writes, None, 3);
    let all = block_writes(&context, 3, &writes);
    let build = |block, writes: &[(Vec<u8>, Vec<u8>)]| {
        AmxRecordProofV1::from_writes(
            block,
            writes
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            record.clone(),
        )
    };

    let proof = build(block.clone(), &all).unwrap();
    let tracker = AmxForeignInstanceV1::new(instance(DS1), context.clone()).unwrap();
    tracker.verify_record(&proof).unwrap();
    let encoded = norito::encode_canonical(&proof).unwrap();
    let restored: AmxRecordProofV1 = norito::decode_canonical(&encoded).unwrap();
    assert_eq!(restored, proof);
    tracker.verify_record(&restored).unwrap();

    // Keeping the AMX record while losing either mandatory or ordinary writes must fail
    // before a relayer retains an unusable proof.
    assert!(build(block.clone(), &writes).is_err());
    assert!(build(block.clone(), &[all[0].clone(), all[2].clone()]).is_err());
    let mut changed = all.clone();
    changed[1].1 = b"changed".to_vec();
    assert!(build(block.clone(), &changed).is_err());
    let mut extra = all.clone();
    extra.push((b"unexpected".to_vec(), b"write".to_vec()));
    assert!(build(block.clone(), &extra).is_err());
    let foreign = certify(instance(DS1), &context, 4, &writes, None, 3);
    assert!(build(foreign, &all).is_err());

    // Repeated writes are valid when their final values are exactly those certified.
    let mut repeated = vec![(b"unrelated".to_vec(), b"superseded".to_vec())];
    repeated.extend(all);
    assert_eq!(build(block.clone(), &repeated).unwrap(), proof);
    repeated.push((b"unrelated".to_vec(), b"uncertified".to_vec()));
    assert!(build(block, &repeated).is_err());
}

#[test]
fn sumeragi_amx_record_proof_construction_rejects_invalid_result_preimages() {
    let context = fixture(4);
    let tx = transaction(&[DS1, DS2], 50, 1).id().unwrap();
    let record = prepared(tx, DS1, AmxVoteV1::Yes([5; 32]));
    let writes = vec![write_of(&record)];
    let block = certify(instance(DS1), &context, 3, &writes, None, 3);
    let all = block_writes(&context, 3, &writes);
    let preimages = [
        Vec::new(),
        vec![0; crate::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES + 1],
        block.result_preimage[..block.result_preimage.len() - 1].to_vec(),
        certify(instance(DS1), &context, 3, &[], None, 3).result_preimage,
    ];
    for result_preimage in preimages {
        let mut invalid = block.clone();
        invalid.result_preimage = result_preimage;
        assert!(
            AmxRecordProofV1::from_writes(
                invalid,
                all.iter()
                    .map(|(key, value)| (key.as_slice(), value.as_slice())),
                record.clone(),
            )
            .is_err()
        );
    }
}

#[test]
fn sumeragi_amx_tracker_verifies_records_under_the_tracked_committee_only() {
    let context = fixture(4);
    let tracker = AmxForeignInstanceV1::new(instance(DS1), context.clone()).unwrap();
    let x = transaction(&[DS1, DS2], 50, 1).id().unwrap();
    let record = prepared(x, DS1, AmxVoteV1::Yes([5; 32]));
    let others = vec![(b"unrelated".to_vec(), b"write".to_vec())];
    let proof = record_proof(instance(DS1), &context, 3, &record, &others);
    let verified = tracker.verify_record(&proof).unwrap();
    assert_eq!((verified.height, verified.epoch), (3, 0));
    let bytes = norito::encode_canonical(&proof).unwrap();
    assert_eq!(
        norito::decode_canonical::<AmxRecordProofV1>(&bytes).unwrap(),
        proof
    );
    let json = norito::json::to_json(&proof).unwrap();
    assert_eq!(
        norito::json::from_str::<AmxRecordProofV1>(&json).unwrap(),
        proof
    );

    // Another record under the same path, or the same record in another instance's block.
    let mut forged = proof.clone();
    forged.record = prepared(x, DS1, AmxVoteV1::No);
    assert!(tracker.verify_record(&forged).is_err());
    let foreign = record_proof(instance(DS2), &context, 3, &record, &others);
    assert!(tracker.verify_record(&foreign).is_err());
    // A block that does not hold the record.
    let mut elsewhere = proof.clone();
    elsewhere.block = certify(instance(DS1), &context, 3, &others, None, 3);
    assert!(tracker.verify_record(&elsewhere).is_err());
    // Fewer than a quorum of signers.
    let mut short = proof.clone();
    short.block = certify(
        instance(DS1),
        &context,
        3,
        &[others[0].clone(), write_of(&record)],
        None,
        2,
    );
    assert!(tracker.verify_record(&short).is_err());
    // A committee the tracker does not hold (same epoch number, other keys).
    let other = rotated(&context, [9, 10, 11, 12]);
    let stranger = record_proof(instance(DS1), &other, 13, &record, &others);
    assert!(matches!(
        tracker.verify_record(&stranger),
        Err(AmxError::EpochNotTracked { epoch: 1, .. })
    ));
    // A result preimage that is not the certified one.
    let mut swapped = proof.clone();
    swapped.block.result_preimage =
        certify(instance(DS1), &context, 3, &others, None, 3).result_preimage;
    assert!(tracker.verify_record(&swapped).is_err());
    // A header of another height under the same certificate.
    let mut moved = proof.clone();
    moved.block.consensus_header =
        certify(instance(DS1), &context, 4, &others, None, 3).consensus_header;
    assert!(tracker.verify_record(&moved).is_err());
    // Oversized parts are rejected before decoding.
    let mut oversized = proof;
    oversized.block.commit_qc = vec![0; MAX_AMX_QC_BYTES + 1];
    assert!(tracker.verify_record(&oversized).is_err());
}

#[test]
fn sumeragi_amx_tracker_hands_off_epoch_by_epoch() {
    let first = fixture(4);
    let second = rotated(&first, [5, 6, 7, 8]);
    let third = kept(&second);
    let mut tracker = AmxForeignInstanceV1::new(instance(DS1), first.clone()).unwrap();
    let x = [3; 32];
    let record = prepared(x, DS1, AmxVoteV1::No);
    let in_second = record_proof(instance(DS1), &second, 12, &record, &[]);
    let in_third = record_proof(instance(DS1), &third, 22, &record, &[]);
    assert!(matches!(
        tracker.verify_record(&in_second),
        Err(AmxError::EpochNotTracked {
            epoch: 1,
            tracked: 0
        })
    ));

    // A handoff must be the last block of the tracked epoch and carry the boundary decision.
    let early = AmxHandoffProofV1 {
        block: certify(instance(DS1), &first, 5, &[], None, 3),
    };
    assert!(tracker.apply_handoff(&early).is_err());
    // A boundary signed by the successor committee is not verifiable yet.
    let skipped = AmxHandoffProofV1 {
        block: certify(instance(DS1), &second, 20, &[], Some(&third), 3),
    };
    assert!(matches!(
        tracker.apply_handoff(&skipped),
        Err(AmxError::EpochNotTracked { .. })
    ));
    let handoff = AmxHandoffProofV1 {
        block: certify(instance(DS1), &first, 10, &[], Some(&second), 3),
    };
    let json = norito::json::to_json(&handoff).unwrap();
    assert_eq!(
        norito::json::from_str::<AmxHandoffProofV1>(&json).unwrap(),
        handoff
    );
    assert_eq!(
        tracker.apply_handoff(&handoff).unwrap(),
        AmxHandoffOutcome::Advanced { epoch: 1 }
    );
    assert_eq!(tracker.epoch(), 1);
    tracker.validate().unwrap();
    // Epochs e − 1 and e verify; the replayed handoff is stale.
    tracker.verify_record(&in_second).unwrap();
    tracker
        .verify_record(&record_proof(instance(DS1), &first, 4, &record, &[]))
        .unwrap();
    assert_eq!(
        tracker.apply_handoff(&handoff).unwrap(),
        AmxHandoffOutcome::Stale
    );
    assert!(tracker.verify_record(&in_third).is_err());
    assert_eq!(
        tracker.apply_handoff(&AmxHandoffProofV1 {
            block: certify(instance(DS1), &second, 20, &[], Some(&third), 3),
        }),
        Ok(AmxHandoffOutcome::Advanced { epoch: 2 })
    );
    tracker.verify_record(&in_third).unwrap();
    // Epoch 0 has left the window.
    assert!(matches!(
        tracker.verify_record(&record_proof(instance(DS1), &first, 4, &record, &[])),
        Err(AmxError::EpochNotTracked { epoch: 0, .. })
    ));
    let bytes = norito::encode_canonical(&tracker).unwrap();
    assert_eq!(
        norito::decode_canonical::<AmxForeignInstanceV1>(&bytes).unwrap(),
        tracker
    );
}

#[test]
fn sumeragi_amx_begin_rejects_duplicates_unregistered_participants_and_bad_deadlines() {
    let mut state = state_with(&[DS1, DS2]);
    let tx = transaction(&[DS1, DS2], 50, 1);
    let record = state.begin(10, &tx).unwrap();
    assert_eq!(record, AmxRecordV1::Begin(tx.begin().unwrap()));
    assert_eq!(state.transaction(&tx.id().unwrap()).unwrap().begun_at, 10);
    assert!(matches!(state.begin(11, &tx), Err(AmxError::State(_))));
    assert!(state.begin(10, &transaction(&[DS1, DS3], 50, 2)).is_err());
    assert!(state.begin(50, &transaction(&[DS1, DS2], 50, 3)).is_err());
    assert!(
        state
            .begin(
                10,
                &transaction(&[DS1, DS2], 11 + MAX_AMX_DEADLINE_WINDOW, 4)
            )
            .is_err()
    );
    state
        .begin(
            10,
            &transaction(&[DS1, DS2], 10 + MAX_AMX_DEADLINE_WINDOW, 5),
        )
        .unwrap();
    assert!(
        state
            .register_dataspace(DS1, state.dataspaces[0].tracker.clone())
            .is_err()
    );
    state.validate().unwrap();
    let bytes = norito::encode_canonical(&state).unwrap();
    assert_eq!(
        norito::decode_canonical::<SumeragiAmxState>(&bytes).unwrap(),
        state
    );
    let json = norito::json::to_json(&state).unwrap();
    assert_eq!(
        norito::json::from_str::<SumeragiAmxState>(&json).unwrap(),
        state
    );
}

#[test]
fn sumeragi_amx_commit_needs_every_yes_by_the_deadline() {
    let mut state = state_with(&[DS1, DS2, DS3]);
    let tx = transaction(&[DS1, DS2, DS3], 40, 1);
    let x = tx.id().unwrap();
    state.begin(10, &tx).unwrap();
    let yes = |dataspace| {
        record_proof(
            instance(dataspace),
            &fixture(4),
            5,
            &prepared(
                x,
                dataspace,
                AmxVoteV1::Yes([u8::try_from(dataspace.as_u64()).unwrap(); 32]),
            ),
            &[],
        )
    };
    assert_eq!(
        state.relay_prepared(12, &yes(DS1)).unwrap(),
        AmxRelayOutcome::Voted
    );
    // A repeated vote is ignored.
    assert_eq!(
        state.relay_prepared(13, &yes(DS1)).unwrap(),
        AmxRelayOutcome::Ignored
    );
    // A proof from one dataspace cannot vote for another.
    let mut impostor = yes(DS2);
    impostor.record = prepared(x, DS3, AmxVoteV1::Yes([13; 32]));
    assert!(state.relay_prepared(13, &impostor).is_err());
    assert_eq!(
        state.relay_prepared(14, &yes(DS2)).unwrap(),
        AmxRelayOutcome::Voted
    );
    assert_eq!(
        state.relay_prepared(40, &yes(DS3)).unwrap(),
        AmxRelayOutcome::Decided(AmxDecisionV1 {
            tx: x,
            outcome: AmxOutcomeV1::Commit
        })
    );
    let entry = state.transaction(&x).unwrap();
    assert_eq!(entry.yes.len(), 3);
    assert_eq!(
        entry.decided,
        Some(AmxDecidedV1 {
            outcome: AmxOutcomeV1::Commit,
            height: 40
        })
    );
    state.validate().unwrap();
    // One immutable decision: a later No is ignored, and the deadline step keeps the Commit.
    let no = record_proof(
        instance(DS1),
        &fixture(4),
        6,
        &prepared(x, DS1, AmxVoteV1::No),
        &[],
    );
    assert_eq!(
        state.relay_prepared(40, &no).unwrap(),
        AmxRelayOutcome::Ignored
    );
    assert!(expire_records(&mut state, 40).is_empty());
    assert!(expire_records(&mut state, 41).is_empty());
    assert!(state.transaction(&x).is_none());
    // The dropped id can never be begun again: its deadline passed.
    assert!(state.begin(41, &tx).is_err());
    // A proof for an unknown transaction is ignored.
    assert_eq!(
        state.relay_prepared(42, &yes(DS1)).unwrap(),
        AmxRelayOutcome::Ignored
    );
}

/// Collect records only in the test oracle; production expiration streams them.
fn expire_records(state: &mut SumeragiAmxState, height: u64) -> Vec<AmxDecisionV1> {
    let mut records = Vec::new();
    let count = state
        .expire(height, |record| {
            records.push(record);
            Ok::<(), std::convert::Infallible>(())
        })
        .unwrap();
    assert_eq!(count, records.len());
    records
}

#[test]
fn sumeragi_amx_first_no_or_the_deadline_aborts() {
    let mut state = state_with(&[DS1, DS2]);
    let aborted_by_no = transaction(&[DS1, DS2], 40, 1);
    let late_yes = transaction(&[DS1, DS2], 30, 2);
    let silent = transaction(&[DS1, DS2], 30, 3);
    for tx in [&aborted_by_no, &late_yes, &silent] {
        state.begin(10, tx).unwrap();
    }
    let vote = |tx: &AmxTransactionV1, dataspace, vote| {
        record_proof(
            instance(dataspace),
            &fixture(4),
            5,
            &prepared(tx.id().unwrap(), dataspace, vote),
            &[],
        )
    };
    assert_eq!(
        state
            .relay_prepared(12, &vote(&aborted_by_no, DS2, AmxVoteV1::No))
            .unwrap(),
        AmxRelayOutcome::Decided(AmxDecisionV1 {
            tx: aborted_by_no.id().unwrap(),
            outcome: AmxOutcomeV1::Abort
        })
    );
    assert_eq!(
        state
            .relay_prepared(13, &vote(&aborted_by_no, DS1, AmxVoteV1::Yes([1; 32])))
            .unwrap(),
        AmxRelayOutcome::Ignored
    );
    state
        .relay_prepared(20, &vote(&late_yes, DS1, AmxVoteV1::Yes([1; 32])))
        .unwrap();
    // The completing Yes arrives in the first block after the deadline: no Commit.
    assert_eq!(
        state
            .relay_prepared(31, &vote(&late_yes, DS2, AmxVoteV1::Yes([2; 32])))
            .unwrap(),
        AmxRelayOutcome::Voted
    );
    assert!(expire_records(&mut state, 30).is_empty());
    let mut aborted = expire_records(&mut state, 31);
    aborted.sort();
    let mut expected = vec![
        AmxDecisionV1 {
            tx: late_yes.id().unwrap(),
            outcome: AmxOutcomeV1::Abort,
        },
        AmxDecisionV1 {
            tx: silent.id().unwrap(),
            outcome: AmxOutcomeV1::Abort,
        },
    ];
    expected.sort();
    assert_eq!(aborted, expected);
    assert!(state.transaction(&late_yes.id().unwrap()).is_none());
    assert!(state.transaction(&aborted_by_no.id().unwrap()).is_some());
    assert!(expire_records(&mut state, 41).is_empty());
    assert!(state.transactions.is_empty());
}

#[test]
fn sumeragi_amx_state_validation_rejects_broken_invariants() {
    let mut state = state_with(&[DS1, DS2]);
    let tx = transaction(&[DS1, DS2], 40, 1);
    state.begin(10, &tx).unwrap();
    state.validate().unwrap();
    let mut unordered = state.clone();
    unordered.dataspaces.reverse();
    assert!(unordered.validate().is_err());
    let mut committed_without_votes = state.clone();
    committed_without_votes.transactions[0].decided = Some(AmxDecidedV1 {
        outcome: AmxOutcomeV1::Commit,
        height: 12,
    });
    assert!(committed_without_votes.validate().is_err());
    let mut stranger_vote = state.clone();
    stranger_vote.transactions[0].yes.push(AmxYesV1 {
        participant: DS3,
        effects_hash: [0; 32],
    });
    assert!(stranger_vote.validate().is_err());
    let mut unregistered = state;
    unregistered.dataspaces.pop();
    assert!(unregistered.validate().is_err());
}

#[test]
fn sumeragi_amx_state_relays_handoffs_to_the_registered_tracker() {
    let first = fixture(4);
    let second = rotated(&first, [5, 6, 7, 8]);
    let mut state = state_with(&[DS1]);
    let handoff = AmxHandoffProofV1 {
        block: certify(instance(DS1), &first, 10, &[], Some(&second), 3),
    };
    assert!(state.relay_handoff(DS2, &handoff).is_err());
    assert_eq!(
        state.relay_handoff(DS1, &handoff).unwrap(),
        AmxHandoffOutcome::Advanced { epoch: 1 }
    );
    assert_eq!(state.dataspace(DS1).unwrap().tracker.epoch(), 1);
    state.validate().unwrap();
}

const GLOBAL: [u8; 32] = [0x47; 32];

/// An in-memory dataspace ledger: a leg `[from, to, amount_be64]` moves `amount` from `from` to
/// `to`; escrow debits `from` into the transaction's escrow.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Ledger {
    balances: std::collections::BTreeMap<u8, u64>,
    escrows: std::collections::BTreeMap<[u8; 32], (u8, u8, u64)>,
    applied: Vec<[u8; 32]>,
    released: Vec<[u8; 32]>,
}

impl Ledger {
    fn with(balances: &[(u8, u64)]) -> Self {
        Self {
            balances: balances.iter().copied().collect(),
            ..Self::default()
        }
    }

    fn total(&self) -> u64 {
        self.balances.values().sum::<u64>()
            + self
                .escrows
                .values()
                .map(|(_, _, amount)| amount)
                .sum::<u64>()
    }
}

impl AmxEscrow for Ledger {
    type Error = core::convert::Infallible;

    fn escrow(&mut self, tx: &[u8; 32], leg: &AmxLegV1) -> Result<Option<[u8; 32]>, Self::Error> {
        let [from, to, amount @ ..] = leg.payload.as_slice() else {
            return Ok(None);
        };
        let Ok(amount) = amount.try_into() else {
            return Ok(None);
        };
        let amount = u64::from_be_bytes(amount);
        let balance = self.balances.get(from).copied().unwrap_or_default();
        if balance < amount {
            return Ok(None);
        }
        self.balances.insert(*from, balance - amount);
        self.escrows.insert(*tx, (*from, *to, amount));
        Ok(Some(Hash::new(&leg.payload).into()))
    }

    fn apply(&mut self, tx: &[u8; 32]) -> Result<(), Self::Error> {
        let (_, to, amount) = self.escrows.remove(tx).expect("an escrow to apply");
        *self.balances.entry(to).or_default() += amount;
        self.applied.push(*tx);
        Ok(())
    }

    fn release(&mut self, tx: &[u8; 32]) -> Result<(), Self::Error> {
        let (from, _, amount) = self.escrows.remove(tx).expect("an escrow to release");
        *self.balances.entry(from).or_default() += amount;
        self.released.push(*tx);
        Ok(())
    }
}

fn leg_payload(from: u8, to: u8, amount: u64) -> Vec<u8> {
    let mut payload = vec![from, to];
    payload.extend_from_slice(&amount.to_be_bytes());
    payload
}

fn transfer(deadline: u64, nonce: u8, amounts: [u64; 2]) -> AmxTransactionV1 {
    AmxTransactionV1 {
        legs: vec![
            AmxLegV1 {
                dataspace: DS1,
                payload: leg_payload(1, 2, amounts[0]),
            },
            AmxLegV1 {
                dataspace: DS2,
                payload: leg_payload(3, 4, amounts[1]),
            },
        ],
        deadline,
        nonce: [nonce; 32],
    }
}

fn global_proof(height: u64, record: &AmxRecordV1) -> AmxRecordProofV1 {
    record_proof(GLOBAL, &long_fixture(), height, record, &[])
}

fn decision(tx: &AmxTransactionV1, outcome: AmxOutcomeV1) -> AmxRecordV1 {
    AmxRecordV1::Decision(AmxDecisionV1 {
        tx: tx.id().unwrap(),
        outcome,
    })
}

fn participant() -> AmxParticipantStateV1 {
    AmxParticipantStateV1::new(
        DS1,
        AmxForeignInstanceV1::new(GLOBAL, long_fixture()).unwrap(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscrowCall {
    Prepare,
    Apply,
    Release,
}

struct RefusingEscrow {
    ledger: Ledger,
    refused: Option<EscrowCall>,
    calls: Vec<EscrowCall>,
}

impl RefusingEscrow {
    fn called(&mut self, call: EscrowCall) -> Result<(), EscrowCall> {
        self.calls.push(call);
        if self.refused == Some(call) {
            Err(call)
        } else {
            Ok(())
        }
    }
}

impl AmxEscrow for RefusingEscrow {
    type Error = EscrowCall;

    fn escrow(&mut self, tx: &[u8; 32], leg: &AmxLegV1) -> Result<Option<[u8; 32]>, Self::Error> {
        self.called(EscrowCall::Prepare)?;
        Ok(self.ledger.escrow(tx, leg).unwrap())
    }

    fn apply(&mut self, tx: &[u8; 32]) -> Result<(), Self::Error> {
        self.called(EscrowCall::Apply)?;
        self.ledger.apply(tx).unwrap();
        Ok(())
    }

    fn release(&mut self, tx: &[u8; 32]) -> Result<(), Self::Error> {
        self.called(EscrowCall::Release)?;
        self.ledger.release(tx).unwrap();
        Ok(())
    }
}

fn corrupted_signature(proof: &AmxRecordProofV1) -> AmxRecordProofV1 {
    let mut changed = proof.clone();
    let mut certificate: Qc = norito::decode_canonical(&changed.block.commit_qc).unwrap();
    certificate.agg_sig.0[17] ^= 1;
    changed.block.commit_qc = norito::encode_canonical(&certificate).unwrap();
    changed
}

#[test]
fn sumeragi_amx_participant_resource_refusal_never_votes_no_or_closes_escrow() {
    for (outcome, operation, settled) in [
        (
            AmxOutcomeV1::Commit,
            EscrowCall::Apply,
            AmxSettleOutcome::Applied,
        ),
        (
            AmxOutcomeV1::Abort,
            EscrowCall::Release,
            AmxSettleOutcome::Released,
        ),
    ] {
        let tx = transfer(10, 31, [7, 8]);
        let begin = global_proof(2, &AmxRecordV1::Begin(tx.begin().unwrap()));
        let decision_height = if outcome == AmxOutcomeV1::Abort {
            11
        } else {
            9
        };
        let decision = global_proof(decision_height, &decision(&tx, outcome));
        let mut state = participant();
        let original = state.clone();
        let mut escrow = RefusingEscrow {
            ledger: Ledger::with(&[(1, 20)]),
            refused: Some(EscrowCall::Prepare),
            calls: Vec::new(),
        };
        let original_ledger = escrow.ledger.clone();
        assert_eq!(
            state.prepare(&mut escrow, &tx, &begin),
            Err(AmxParticipantError::Escrow(EscrowCall::Prepare))
        );
        assert_eq!(
            state, original,
            "refusal cannot install No or advance global height"
        );
        assert_eq!(escrow.ledger, original_ledger);

        escrow.refused = None;
        let AmxRecordV1::Prepared(prepared) = state.prepare(&mut escrow, &tx, &begin).unwrap()
        else {
            panic!("original request must prepare on retry");
        };
        assert!(matches!(prepared.vote, AmxVoteV1::Yes(_)));
        let prepared_state = state.clone();
        let locked_ledger = escrow.ledger.clone();
        escrow.refused = Some(operation);
        let calls = escrow.calls.clone();
        assert!(matches!(
            state.settle(&mut escrow, &corrupted_signature(&decision)),
            Err(AmxParticipantError::Protocol(AmxError::Proof(_)))
        ));
        assert_eq!(
            escrow.calls, calls,
            "invalid signature cannot invoke escrow"
        );
        assert_eq!(state, prepared_state);
        for _ in 0..2 {
            assert_eq!(
                state.settle(&mut escrow, &decision),
                Err(AmxParticipantError::Escrow(operation))
            );
            assert_eq!(
                state, prepared_state,
                "failed settlement cannot close or prune the Yes"
            );
            assert_eq!(escrow.ledger, locked_ledger);
        }
        escrow.refused = None;
        assert_eq!(state.settle(&mut escrow, &decision).unwrap(), settled);
        assert_eq!(escrow.ledger.total(), original_ledger.total());
        assert!(escrow.ledger.escrows.is_empty());
        assert_eq!(
            escrow.ledger.applied.len() + escrow.ledger.released.len(),
            1
        );
        let calls = escrow.calls.clone();
        // A late duplicate can be held after deadline pruning, but never invokes escrow twice.
        let _ = state.settle(&mut escrow, &decision);
        assert_eq!(escrow.calls, calls);
        state.validate().unwrap();
    }
}

#[test]
fn sumeragi_amx_participant_held_or_invalid_proof_never_calls_refusing_escrow() {
    let tx = transfer(10, 32, [7, 8]);
    let begin = global_proof(2, &AmxRecordV1::Begin(tx.begin().unwrap()));
    let abort = global_proof(3, &decision(&tx, AmxOutcomeV1::Abort));
    let mut state = participant();
    let mut escrow = RefusingEscrow {
        ledger: Ledger::with(&[(1, 20)]),
        refused: Some(EscrowCall::Prepare),
        calls: Vec::new(),
    };
    let original_ledger = escrow.ledger.clone();
    let original_state = state.clone();
    assert!(matches!(
        state.prepare(&mut escrow, &tx, &corrupted_signature(&begin)),
        Err(AmxParticipantError::Protocol(AmxError::Proof(_)))
    ));
    assert!(matches!(
        state.prepare(&mut escrow, &tx, &abort),
        Err(AmxParticipantError::Protocol(_))
    ));
    assert!(matches!(
        state.settle(&mut escrow, &begin),
        Err(AmxParticipantError::Protocol(_))
    ));
    assert_eq!(state, original_state);
    assert_eq!(
        state.settle(&mut escrow, &abort).unwrap(),
        AmxSettleOutcome::Held
    );
    let AmxRecordV1::Prepared(prepared) = state.prepare(&mut escrow, &tx, &begin).unwrap() else {
        panic!("held decision must produce Prepared No");
    };
    assert_eq!(prepared.vote, AmxVoteV1::No);
    assert!(escrow.calls.is_empty());
    assert_eq!(escrow.ledger, original_ledger);
    state.validate().unwrap();
}

#[test]
fn sumeragi_amx_participant_escrows_once_and_applies_on_commit() {
    let mut state = participant();
    let mut ledger = Ledger::with(&[(1, 100)]);
    let tx = transfer(40, 1, [60, 5]);
    let begin = global_proof(5, &AmxRecordV1::Begin(tx.begin().unwrap()));
    let record = state.prepare(&mut ledger, &tx, &begin).unwrap();
    let AmxRecordV1::Prepared(prepared) = record else {
        panic!("a Prepared record");
    };
    assert_eq!(prepared.participant, DS1);
    assert!(matches!(prepared.vote, AmxVoteV1::Yes(_)));
    assert_eq!(ledger.balances[&1], 40);
    // A second inclusion of x is rejected and escrows nothing more.
    assert!(state.prepare(&mut ledger, &tx, &begin).is_err());
    assert_eq!(ledger.balances[&1], 40);
    let commit = global_proof(20, &decision(&tx, AmxOutcomeV1::Commit));
    assert_eq!(
        state.settle(&mut ledger, &commit).unwrap(),
        AmxSettleOutcome::Applied
    );
    assert_eq!((ledger.balances[&1], ledger.balances[&2]), (40, 60));
    assert!(state.settle(&mut ledger, &commit).is_err());
    assert_eq!(ledger.applied.len(), 1);
    assert_eq!(ledger.total(), 100);
    state.validate().unwrap();
    let bytes = norito::encode_canonical(&state).unwrap();
    assert_eq!(
        norito::decode_canonical::<AmxParticipantStateV1>(&bytes).unwrap(),
        state
    );
    let json = norito::json::to_json(&state).unwrap();
    assert_eq!(
        norito::json::from_str::<AmxParticipantStateV1>(&json).unwrap(),
        state
    );
}

#[test]
fn sumeragi_amx_participant_releases_a_yes_escrow_only_with_the_abort_proof() {
    let mut state = participant();
    let mut ledger = Ledger::with(&[(1, 100)]);
    let tx = transfer(40, 2, [70, 5]);
    let begin = global_proof(5, &AmxRecordV1::Begin(tx.begin().unwrap()));
    state.prepare(&mut ledger, &tx, &begin).unwrap();
    assert_eq!(ledger.balances[&1], 30);
    // A decision of another transaction, a non-decision record or a forged global block
    // releases nothing.
    let other = transfer(40, 3, [1, 1]);
    assert_eq!(
        state
            .settle(
                &mut ledger,
                &global_proof(20, &decision(&other, AmxOutcomeV1::Abort))
            )
            .unwrap(),
        AmxSettleOutcome::Held
    );
    assert!(state.settle(&mut ledger, &begin).is_err());
    let forged = record_proof(
        instance(DS2),
        &long_fixture(),
        20,
        &decision(&tx, AmxOutcomeV1::Abort),
        &[],
    );
    assert!(state.settle(&mut ledger, &forged).is_err());
    assert!(ledger.released.is_empty());
    assert_eq!(ledger.balances[&1], 30);
    assert_eq!(
        state
            .settle(
                &mut ledger,
                &global_proof(21, &decision(&tx, AmxOutcomeV1::Abort))
            )
            .unwrap(),
        AmxSettleOutcome::Released
    );
    assert_eq!(ledger.balances[&1], 100);
    assert_eq!(ledger.total(), 100);
}

#[test]
fn sumeragi_amx_participant_votes_no_without_escrow() {
    let mut state = participant();
    let mut ledger = Ledger::with(&[(1, 10)]);
    let tx = transfer(40, 4, [60, 5]);
    let begin = global_proof(5, &AmxRecordV1::Begin(tx.begin().unwrap()));
    assert_eq!(
        state.prepare(&mut ledger, &tx, &begin).unwrap(),
        AmxRecordV1::Prepared(AmxPreparedV1 {
            tx: tx.id().unwrap(),
            participant: DS1,
            vote: AmxVoteV1::No
        })
    );
    assert!(ledger.escrows.is_empty());
    assert_eq!(
        state
            .settle(
                &mut ledger,
                &global_proof(20, &decision(&tx, AmxOutcomeV1::Abort))
            )
            .unwrap(),
        AmxSettleOutcome::Closed
    );
    assert_eq!(ledger.balances[&1], 10);
}

#[test]
fn sumeragi_amx_participant_holding_the_decision_votes_no() {
    let mut state = participant();
    let mut ledger = Ledger::with(&[(1, 100)]);
    let tx = transfer(40, 5, [60, 5]);
    // The global chain aborted x (another participant's No) before this dataspace prepared it.
    assert_eq!(
        state
            .settle(
                &mut ledger,
                &global_proof(12, &decision(&tx, AmxOutcomeV1::Abort))
            )
            .unwrap(),
        AmxSettleOutcome::Held
    );
    let begin = global_proof(5, &AmxRecordV1::Begin(tx.begin().unwrap()));
    let AmxRecordV1::Prepared(prepared) = state.prepare(&mut ledger, &tx, &begin).unwrap() else {
        panic!("a Prepared record");
    };
    assert_eq!(prepared.vote, AmxVoteV1::No);
    assert!(ledger.escrows.is_empty());
    assert_eq!(
        state.entry(&tx.id().unwrap()).unwrap().settled,
        Some(AmxOutcomeV1::Abort)
    );
    assert!(state.held.is_empty());
    state.validate().unwrap();
}

#[test]
fn sumeragi_amx_participant_rejects_foreign_or_late_prepares_and_prunes() {
    let mut state = participant();
    let mut ledger = Ledger::with(&[(1, 100)]);
    let tx = transfer(30, 6, [10, 5]);
    let begin = global_proof(5, &AmxRecordV1::Begin(tx.begin().unwrap()));
    // The Begin of another transaction, a Begin certified by a non-global instance, a
    // transaction without this participant and a non-Begin record are rejected.
    let other = transfer(30, 7, [10, 5]);
    assert!(state.prepare(&mut ledger, &other, &begin).is_err());
    let foreign = record_proof(
        instance(DS2),
        &long_fixture(),
        5,
        &AmxRecordV1::Begin(tx.begin().unwrap()),
        &[],
    );
    assert!(state.prepare(&mut ledger, &tx, &foreign).is_err());
    let elsewhere = transaction(&[DS2, DS3], 30, 8);
    let begin_elsewhere = global_proof(5, &AmxRecordV1::Begin(elsewhere.begin().unwrap()));
    assert!(
        state
            .prepare(&mut ledger, &elsewhere, &begin_elsewhere)
            .is_err()
    );
    let not_begin = global_proof(5, &decision(&tx, AmxOutcomeV1::Abort));
    assert!(state.prepare(&mut ledger, &tx, &not_begin).is_err());
    assert!(ledger.escrows.is_empty());

    state.prepare(&mut ledger, &tx, &begin).unwrap();
    state
        .settle(
            &mut ledger,
            &global_proof(20, &decision(&tx, AmxOutcomeV1::Commit)),
        )
        .unwrap();
    assert!(state.entry(&tx.id().unwrap()).is_some());
    // An unsettled No (nothing escrowed) and an unsettled Yes escrow of the same deadline.
    let refused = transfer(30, 10, [1_000, 5]);
    let escrowed = transfer(30, 11, [5, 5]);
    for pending in [&refused, &escrowed] {
        let pending_begin = global_proof(6, &AmxRecordV1::Begin(pending.begin().unwrap()));
        state.prepare(&mut ledger, pending, &pending_begin).unwrap();
    }
    assert_eq!(
        state.entry(&refused.id().unwrap()).unwrap().vote,
        AmxVoteV1::No
    );
    // Once a verified global block is beyond the deadline, no Prepare of x can follow: the
    // settled entry is dropped and a late Prepare is rejected, not escrowed again.
    let late = transfer(35, 9, [10, 5]);
    let late_begin = global_proof(31, &AmxRecordV1::Begin(late.begin().unwrap()));
    state.prepare(&mut ledger, &late, &late_begin).unwrap();
    assert!(state.entry(&tx.id().unwrap()).is_none());
    assert!(
        state.entry(&refused.id().unwrap()).is_none(),
        "an unsettled No past its deadline is dropped"
    );
    assert!(
        state.entry(&escrowed.id().unwrap()).is_some(),
        "an unsettled Yes escrow stays until its decision proof"
    );
    assert_eq!(state.global_height, 31);
    assert!(state.prepare(&mut ledger, &tx, &begin).is_err());
    // The dropped No's decision is only held; the escrow's decision releases it.
    assert_eq!(
        state
            .settle(
                &mut ledger,
                &global_proof(31, &decision(&refused, AmxOutcomeV1::Abort))
            )
            .unwrap(),
        AmxSettleOutcome::Held
    );
    assert_eq!(
        state
            .settle(
                &mut ledger,
                &global_proof(31, &decision(&escrowed, AmxOutcomeV1::Abort))
            )
            .unwrap(),
        AmxSettleOutcome::Released
    );
    assert_eq!(ledger.total(), 100);
    assert_eq!(ledger.applied, vec![tx.id().unwrap()]);
}

#[test]
fn sumeragi_amx_participant_follows_global_handoffs() {
    let first = fixture(4);
    let second = rotated(&first, [5, 6, 7, 8]);
    let mut state = AmxParticipantStateV1::new(
        DS1,
        AmxForeignInstanceV1::new(GLOBAL, first.clone()).unwrap(),
    );
    let handoff = AmxHandoffProofV1 {
        block: certify(GLOBAL, &first, 10, &[], Some(&second), 3),
    };
    assert_eq!(
        state.handoff(&handoff).unwrap(),
        AmxHandoffOutcome::Advanced { epoch: 1 }
    );
    assert_eq!(state.global_height, 10);
    let mut ledger = Ledger::with(&[(1, 100)]);
    let tx = transfer(40, 10, [10, 5]);
    let begin = record_proof(
        GLOBAL,
        &second,
        12,
        &AmxRecordV1::Begin(tx.begin().unwrap()),
        &[],
    );
    state.prepare(&mut ledger, &tx, &begin).unwrap();
}

fn refused_amx_decode_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        96,
        crate::sumeragi_finality::MAX_RESULT_PREIMAGE_BYTES,
        usize::MAX,
        0,
        32,
    )
}

#[test]
fn amx_record_decode_refusal_is_not_a_deterministic_record_error() {
    let record = prepared([0x71; 32], DS1, AmxVoteV1::Yes([0x72; 32]));
    let key = record.witness_key();
    let bytes = record.witness_value().unwrap();
    let original = bytes.clone();
    let error = norito::with_decode_limits_scope(refused_amx_decode_limits(), || {
        AmxRecordV1::from_witness(&key, &bytes)
    })
    .unwrap_err();
    assert!(
        !matches!(error, AmxError::Encoding(_)),
        "local decoder refusal became a deterministic record error: {error:?}"
    );
    assert_eq!(bytes, original);
    assert_eq!(AmxRecordV1::from_witness(&key, &bytes).unwrap(), record);
}

#[test]
fn amx_foreign_certificate_decode_refusal_is_not_a_proof_verdict() {
    let context = fixture(4);
    let tracker = AmxForeignInstanceV1::new(instance(DS1), context.clone()).unwrap();
    let block = certify(instance(DS1), &context, 2, &[], None, 3);
    let original = block.clone();
    let expected = tracker.verify_block(&block).unwrap();
    let error = norito::with_decode_limits_scope(refused_amx_decode_limits(), || {
        tracker.verify_block(&block)
    })
    .unwrap_err();
    assert!(
        !matches!(error, AmxError::Proof(_)),
        "local decoder refusal became a deterministic proof verdict: {error:?}"
    );
    assert_eq!(block, original);
    assert_eq!(tracker.verify_block(&block).unwrap(), expected);
}

#[test]
fn amx_record_proof_decode_refusal_is_not_a_proof_verdict() {
    let context = fixture(4);
    let record = prepared([0x73; 32], DS1, AmxVoteV1::Yes([0x74; 32]));
    let writes = vec![write_of(&record)];
    let block = certify(instance(DS1), &context, 2, &writes, None, 3);
    let original = block.clone();
    let complete = block_writes(&context, 2, &writes);
    let denied_record = record.clone();
    let error = norito::with_decode_limits_scope(refused_amx_decode_limits(), || {
        AmxRecordProofV1::from_writes(
            block,
            complete
                .iter()
                .map(|(key, value)| (key.as_slice(), value.as_slice())),
            denied_record,
        )
    })
    .unwrap_err();
    assert!(
        !matches!(error, AmxError::Proof(_)),
        "local result decode refusal became a deterministic proof verdict: {error:?}"
    );
    let retry = AmxRecordProofV1::from_writes(
        original.clone(),
        complete
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        record.clone(),
    )
    .unwrap();
    assert_eq!(retry.block, original);
    assert_eq!(retry.record, record);
}

#[test]
fn amx_participant_decode_refusal_preserves_original_escrow_and_cursor() {
    for outcome in [AmxOutcomeV1::Commit, AmxOutcomeV1::Abort] {
        let tx = transfer(10, 41, [7, 8]);
        let begin = global_proof(2, &AmxRecordV1::Begin(tx.begin().unwrap()));
        let decision = global_proof(9, &decision(&tx, outcome));
        let mut state = participant();
        let original = state.clone();
        let mut escrow = RefusingEscrow {
            ledger: Ledger::with(&[(1, 20)]),
            refused: None,
            calls: Vec::new(),
        };
        let original_ledger = escrow.ledger.clone();
        let error = norito::with_decode_limits_scope(refused_amx_decode_limits(), || {
            state.prepare(&mut escrow, &tx, &begin)
        })
        .unwrap_err();
        assert!(matches!(error, AmxParticipantError::Resource(_)));
        assert_eq!(state, original);
        assert_eq!(escrow.ledger, original_ledger);
        assert!(escrow.calls.is_empty());
        state.prepare(&mut escrow, &tx, &begin).unwrap();
        let prepared = state.clone();
        let held = escrow.ledger.clone();
        let calls = escrow.calls.clone();
        let error = norito::with_decode_limits_scope(refused_amx_decode_limits(), || {
            state.settle(&mut escrow, &decision)
        })
        .unwrap_err();
        assert!(matches!(error, AmxParticipantError::Resource(_)));
        assert_eq!(state, prepared);
        assert_eq!(escrow.ledger, held);
        assert_eq!(escrow.calls, calls);
        assert_eq!(
            state.settle(&mut escrow, &decision).unwrap(),
            match outcome {
                AmxOutcomeV1::Commit => AmxSettleOutcome::Applied,
                AmxOutcomeV1::Abort => AmxSettleOutcome::Released,
            }
        );
    }
}

#[test]
fn amx_codec_classification_preserves_resource_category_and_malformed_input() {
    let error = norito::Error::AllocationFailed { bytes: 57 };
    let expected =
        AmxError::Resource(norito::core::DecodeResourceError::AllocationFailed { bytes: 57 });
    assert_eq!(
        super::proof_codec_error(&error, "core header", false),
        expected
    );
    assert_eq!(
        super::commitment_error(&crate::sumeragi_finality::CommitmentError::Resource(
            error.decode_resource_error().unwrap()
        )),
        expected
    );
    assert!(matches!(
        super::proof_codec_error(&norito::Error::InvalidMagic, "core header", true),
        AmxError::Proof(_)
    ));
    let protocol: AmxParticipantError<core::convert::Infallible> =
        AmxError::State("malformed").into();
    assert!(matches!(
        protocol,
        AmxParticipantError::Protocol(AmxError::State("malformed"))
    ));
}

#[test]
fn amx_intrinsic_codec_limit_without_caller_scope_remains_a_proof_error() {
    let error = norito::Error::SequenceLengthExceeded {
        length: 97,
        limit: 96,
    };
    assert!(matches!(
        super::proof_codec_error(&error, "core header", false),
        AmxError::Proof(_)
    ));
    assert_eq!(
        super::proof_codec_error(&error, "core header", true),
        AmxError::Resource(error.decode_resource_error().unwrap())
    );
}

/// Construct the actual allocation owner from the existing exact-quorum BLS AMX fixture.
/// The producer grants no authority; native source authentication and paid execution remain
/// independently exercised by Core. All fixture input allocation predates its finite pool.
pub fn allocated_amx_instruction_fixture() -> (
    AmxTransactionV1,
    AllocatedAmxRecordProofV1,
    iroha_allocation::AllocationBudget,
) {
    use crate::block::CommitCertificate;
    let transaction = transaction(&[DS1, DS2], 9, 0x71);
    let record = AmxRecordV1::Begin(transaction.begin().unwrap());
    let context = fixture(4);
    let writes = vec![
        write_of(&record),
        (b"unrelated original field".to_vec(), vec![0x31; 5]),
    ];
    let block = certify(GLOBAL, &context, 2, &writes, None, 3);
    let complete = block_writes(&context, 2, &writes);
    let ordinary_root = write_set_root(
        complete
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
    )
    .unwrap();
    let expected = AmxRecordProofV1::from_writes(
        block.clone(),
        complete
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice())),
        record,
    )
    .unwrap();
    assert_eq!(
        AmxForeignInstanceV1::new(GLOBAL, context)
            .unwrap()
            .verify_record(&expected)
            .unwrap()
            .height,
        2
    );
    // This input remains explicitly offchain/unadmitted. Its BLS fixture check above does
    // not make the allocation owner a production publication or monetary credential.
    let certificate = CommitCertificate::from_untrusted_parts(
        block.consensus_header,
        block.commit_qc,
        block.result_preimage,
        Vec::new(),
    );
    let witness = ExecWitness {
        writes: complete
            .into_iter()
            .map(|(key, value)| ExecKv { key, value })
            .collect(),
        ..ExecWitness::default()
    };
    let pool = iroha_allocation::AllocationBudget::new(1 << 20);
    let original = AllocatedAmxRecordProofV1::from_original_witness(
        &certificate,
        &witness,
        AmxRecordKind::Begin,
        transaction.id().unwrap(),
        ordinary_root,
        &pool,
    )
    .unwrap()
    .unwrap();
    assert_eq!(original.canonical(), &expected);
    (transaction, original, pool)
}

#[test]
fn sumeragi_amx_expiry_refusal_and_unwind_preserve_original_pending_graph() {
    let mut state = state_with(&[DS1, DS2]);
    for (deadline, nonce) in [(20, 11), (20, 12), (30, 13)] {
        state
            .begin(10, &transaction(&[DS1, DS2], deadline, nonce))
            .unwrap();
    }
    let before = state.clone();
    let original_pointer = state.transactions.as_ptr();
    let original_capacity = state.transactions.capacity();
    let participants = state
        .transactions
        .iter()
        .map(|entry| {
            (
                entry.begin.participants.as_ptr(),
                entry.begin.participants.capacity(),
                entry.yes.as_ptr(),
                entry.yes.capacity(),
            )
        })
        .collect::<Vec<_>>();
    let expected = before
        .transactions
        .iter()
        .filter(|entry| entry.begin.deadline < 21)
        .map(|entry| AmxDecisionV1 {
            tx: entry.begin.tx,
            outcome: AmxOutcomeV1::Abort,
        })
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 2);
    let refusal = [0x19_u8, 0x96];
    for fail_at in 0..2 {
        let mut observed = Vec::new();
        let error = state
            .expire(21, |record| {
                if observed.len() == fail_at {
                    return Err(&refusal);
                }
                observed.push(record);
                Ok(())
            })
            .expect_err("record refusal must preserve all original pending entries");
        assert!(std::ptr::eq(error, &raw const refusal));
        assert_eq!(observed, expected[..fail_at]);
        assert_eq!(state, before);
        assert_eq!(state.transactions.as_ptr(), original_pointer);
        assert_eq!(state.transactions.capacity(), original_capacity);
        for (entry, (pointer, capacity, yes_pointer, yes_capacity)) in
            state.transactions.iter().zip(&participants)
        {
            assert_eq!(entry.begin.participants.as_ptr(), *pointer);
            assert_eq!(entry.begin.participants.capacity(), *capacity);
            assert_eq!(entry.yes.as_ptr(), *yes_pointer);
            assert_eq!(entry.yes.capacity(), *yes_capacity);
        }
    }
    let mut observed = 0;
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = state.expire(21, |_| {
            observed += 1;
            assert!(observed != 2, "record writer unwind");
            Ok::<(), std::convert::Infallible>(())
        });
    }));
    assert!(unwind.is_err());
    assert_eq!(state, before);
    assert_eq!(state.transactions.as_ptr(), original_pointer);
    assert_eq!(expire_records(&mut state, 21), expected);
    assert_eq!(state.transactions.len(), 1);
    assert_eq!(state.transactions[0].begin.deadline, 30);
    assert!(expire_records(&mut state, 21).is_empty());
}

#[test]
fn sumeragi_amx_encoding_keeps_exact_physical_allocator_refusal() {
    let error = norito::Error::AllocationFailed { bytes: 57 };
    assert_eq!(
        super::encoding(&error),
        AmxError::Resource(norito::core::DecodeResourceError::AllocationFailed { bytes: 57 })
    );
    assert!(matches!(
        super::encoding(norito::Error::LengthMismatch),
        AmxError::Encoding(_)
    ));
}
