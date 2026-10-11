//! Real BLS checkpoint authority and bounded canonical-record regressions.

use super::*;
use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;

fn root(fixture: &NativeFinalityFixture) -> SumeragiFinalityVerifier {
    SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap()
}

fn certificate(
    fixture: &NativeFinalityFixture,
    proof: &SumeragiFinalityProof,
) -> SumeragiCommitCertificateV1 {
    SumeragiCommitCertificateV1::from_verified(
        &fixture.verifier().verify_retained_decision(proof).unwrap(),
    )
    .unwrap()
}

fn authenticated_boundary(
    seats: usize,
) -> (
    NativeFinalityFixture,
    Vec<SumeragiFinalityProof>,
    SumeragiCommitVerifierV1,
) {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(seats);
    let mut reader = SumeragiCommitVerifierV1::new(&root(&fixture)).unwrap();
    reader.verify(&certificate(&fixture, &chain[2])).unwrap();
    (fixture, chain, reader)
}

#[test]
fn initial_checkpoint_ignores_authenticated_later_decisions() {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let populated = fixture.verifier();
    assert!(!populated.decisions.is_empty());
    let generic = SumeragiCommitVerifierV1::new(&populated).unwrap();
    assert_eq!(generic.epochs.len(), 2);
    let later = generic.export_epoch_checkpoint(1).unwrap();
    assert_eq!(
        later.selected_epoch().authorization.epoch,
        1,
        "the generic constructor must retain its authenticated-history semantics"
    );

    let checkpoint = SumeragiCommitCheckpointV1::from_authenticated_genesis(&populated).unwrap();
    let fresh = SumeragiCommitCheckpointV1::from_authenticated_genesis(&root(&fixture)).unwrap();
    assert_eq!(checkpoint, fresh);
    assert_eq!(checkpoint.initial, checkpoint.selected);
    assert_eq!(checkpoint.selected_epoch().authorization.epoch, 0);
    assert_eq!(
        checkpoint.encode_canonical().unwrap(),
        fresh.encode_canonical().unwrap()
    );
    let mut bounded =
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, &populated).unwrap();
    assert_eq!(bounded.epochs.len(), 1);
    assert!(bounded.export_epoch_checkpoint(1).is_err());
    assert!(bounded.verify(&certificate(&fixture, &chain[3])).is_err());
    assert_eq!(
        bounded
            .verify(&certificate(&fixture, &chain[1]))
            .unwrap()
            .height(),
        2
    );
    assert_eq!(bounded.epochs.len(), 1);

    let private = NativeFinalityFixture::start_with_scope(
        "initial-checkpoint-private",
        crate::block::consensus::SumeragiRootScope::Dataspace {
            parent_network_id: fixture.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(9),
        },
    );
    assert!(SumeragiCommitCheckpointV1::from_authenticated_genesis(&root(&private)).is_err());
}

#[test]
fn authenticated_boundary_checkpoint_restores_without_prior_blocks() {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let selected = root(&fixture);
    assert!(selected.decisions.is_empty());
    let mut reader = SumeragiCommitVerifierV1::new(&selected).unwrap();
    let initial = reader.export_epoch_checkpoint(0).unwrap();
    assert!(reader.export_epoch_checkpoint(1).is_err());
    assert!(reader.export_epoch_checkpoint(u64::MAX).is_err());

    let boundary = certificate(&fixture, &chain[2]);
    let mut forged = boundary.clone();
    let mut qc: Qc = norito::decode_canonical(&forged.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert!(reader.verify(&forged).is_err());
    assert!(reader.export_epoch_checkpoint(1).is_err());

    // H2 is never replayed to authenticate the actual H3 boundary certificate.
    assert_eq!(reader.verify(&boundary).unwrap().height(), 3);
    let checkpoint = reader.export_epoch_checkpoint(1).unwrap();
    let bytes = checkpoint.encode_canonical().unwrap();
    let decoded = SumeragiCommitCheckpointV1::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded, checkpoint);
    assert_eq!(decoded.encode_canonical().unwrap(), bytes);
    assert_eq!(decoded.network(), fixture.network_id());
    assert_eq!(decoded.chain_id(), fixture.chain_id());
    assert_eq!(decoded.selected_epoch().authorization.epoch, 1);

    // Simulate exact trusted local selection of the bytes exported above. This call
    // does not authenticate peer-supplied DTOs and does not replay H1/H2/H3.
    let mut resumed =
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&decoded, &selected).unwrap();
    assert_eq!(resumed.epochs.len(), 2);
    let successor = certificate(&fixture, &chain[3]);
    let actual = resumed.verify(&successor).unwrap();
    let expected = reader.verify(&successor).unwrap();
    assert_eq!(actual.height(), 4);
    assert_eq!(actual.core_hash(), expected.core_hash());
    assert_eq!(actual.commitment(), expected.commitment());

    // A separately retained older record remains usable for a delayed receipt.
    let mut delayed =
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&initial, &selected).unwrap();
    assert_eq!(delayed.epochs.len(), 1);
    assert!(delayed.verify(&successor).is_err());
    assert_eq!(
        delayed
            .verify(&certificate(&fixture, &chain[1]))
            .unwrap()
            .height(),
        2
    );
    assert_eq!(reader.epochs.len(), 2, "export must not evict authority");
}

#[test]
fn restore_requires_exact_independently_selected_global_root() {
    let (fixture, _, reader) = authenticated_boundary(4);
    let selected = root(&fixture);
    let checkpoint = reader.export_epoch_checkpoint(1).unwrap();
    let foreign = NativeFinalityFixture::start("checkpoint-foreign-genesis");
    assert!(
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, &root(&foreign))
            .is_err()
    );
    let other_chain = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        "checkpoint-other-chain",
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    assert!(
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, &other_chain).is_err()
    );
    let private = NativeFinalityFixture::start_with_scope(
        fixture.chain_id(),
        crate::block::consensus::SumeragiRootScope::Dataspace {
            parent_network_id: fixture.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(9),
        },
    );
    assert!(
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, &root(&private))
            .is_err()
    );
    let foreign_root = root(&foreign);
    let mut changed = checkpoint.clone();
    changed.genesis_hash = foreign_root.genesis.hash();
    assert!(SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&changed, &selected).is_err());
    changed = checkpoint.clone();
    changed.network = foreign.network_id();
    assert!(SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&changed, &selected).is_err());
    changed = checkpoint.clone();
    changed.chain = "substituted-chain".into();
    assert!(SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&changed, &selected).is_err());
    changed = checkpoint.clone();
    changed.instance.0[0] ^= 1;
    assert!(SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&changed, &selected).is_err());

    // Matching the network does not permit replacing the complete signed initial context.
    let mut changed = reader.export_epoch_checkpoint(0).unwrap();
    changed.initial.leader_seed[0] ^= 1;
    changed.selected = changed.initial.clone();
    changed.encode_canonical().unwrap();
    assert!(SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&changed, &selected).is_err());
}

#[test]
fn checkpoint_codec_rejects_noncanonical_malformed_and_oversized_data() {
    let (_, _, reader) = authenticated_boundary(4);
    let checkpoint = reader.export_epoch_checkpoint(1).unwrap();
    let bytes = checkpoint.encode_canonical().unwrap();
    for malformed in [
        Vec::new(),
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        [bytes.as_slice(), bytes.as_slice()].concat(),
        vec![0; MAX_COMMIT_CHECKPOINT_BYTES + 1],
    ] {
        assert!(SumeragiCommitCheckpointV1::decode_canonical(&malformed).is_err());
    }
    for mutate in [
        |value: &mut SumeragiCommitCheckpointV1| value.chain.clear(),
        |value: &mut SumeragiCommitCheckpointV1| value.chain = "x".repeat(1025),
        |value: &mut SumeragiCommitCheckpointV1| value.selected.version = 2,
        |value: &mut SumeragiCommitCheckpointV1| value.selected.committee.reverse(),
        |value: &mut SumeragiCommitCheckpointV1| {
            value.selected.committee[0].proof_of_possession.clear();
        },
        |value: &mut SumeragiCommitCheckpointV1| {
            value.selected.authorization.previous_authorization_id[0] ^= 1;
        },
        |value: &mut SumeragiCommitCheckpointV1| {
            value.selected.authorization.first_height = value.initial.authorization.last_height;
        },
    ] {
        let mut changed = checkpoint.clone();
        mutate(&mut changed);
        assert!(changed.encode_canonical().is_err());
        let untrusted_bytes = norito::encode_canonical(&changed).unwrap();
        assert!(SumeragiCommitCheckpointV1::decode_canonical(&untrusted_bytes).is_err());
    }
    let mut oversized = checkpoint;
    oversized.selected.committee[0]
        .proof_of_possession
        .resize(MAX_COMMIT_CHECKPOINT_BYTES + 1, 0);
    assert!(oversized.encode_canonical().is_err());
}

#[test]
fn largest_valid_rosters_and_chain_label_fit_checkpoint_bound() {
    let (_, _, reader) = authenticated_boundary(crate::sumeragi::epoch::MAX_VALIDATORS);
    let mut checkpoint = reader.export_epoch_checkpoint(1).unwrap();
    // Only exercise DTO encoding geometry here; changing a label confers no authority.
    checkpoint.chain = "x".repeat(1024);
    assert_eq!(checkpoint.initial.committee.len(), 31);
    assert_eq!(checkpoint.selected.committee.len(), 31);
    let bytes = checkpoint.encode_canonical().unwrap();
    assert!(bytes.len() <= MAX_COMMIT_CHECKPOINT_BYTES);
    assert_eq!(
        SumeragiCommitCheckpointV1::decode_canonical(&bytes).unwrap(),
        checkpoint
    );
}

fn resign(qc: &mut Qc) {
    let mut keys: Vec<_> = (1..=4)
        .map(|seed| {
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal)
        })
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1, 2]).unwrap();
    let shares: Vec<_> = keys[..3]
        .iter()
        .map(|key| iroha_crypto::Signature::try_new(key.private_key(), &qc.preimage()).unwrap())
        .collect();
    let refs: Vec<_> = shares
        .iter()
        .map(iroha_crypto::Signature::payload)
        .collect();
    qc.agg_sig = AggregateSignature(
        iroha_crypto::bls_normal_aggregate_signatures(&refs)
            .unwrap()
            .try_into()
            .unwrap(),
    );
}

/// Produce synthetic execution DATA signed by the genuine four-validator fixture keys.
/// This exercises native schedule/QC admission, not beacon-ceremony or VM execution evidence.
fn next_boundary(
    fixture: &NativeFinalityFixture,
    template: &SumeragiCommitCertificateV1,
    current: &ValidatorEpochContextV1,
) -> SumeragiCommitCertificateV1 {
    let height = current.authorization.last_height;
    let mut next = current.clone();
    next.authorization.epoch += 1;
    next.authorization.first_height = height + 1;
    next.authorization.last_height = height + 3;
    next.authorization.previous_authorization_id =
        current.authorization.authorization_id().unwrap();
    next.leader_seed = [u8::try_from(next.authorization.epoch).unwrap(); 32];
    next.validate_successor(current).unwrap();
    let mut result = ExecutionResultCommitment::decode(&template.result_preimage).unwrap();
    result.height = height;
    result.schedule.height = height;
    result.schedule.current = current.clone();
    let boundary = result.schedule.boundary.as_mut().unwrap();
    boundary.height = height;
    boundary.predecessor_context_id = current.context_id().unwrap();
    boundary.next = next.clone();
    let params = *result.schedule.next.params();
    result.schedule.next = ScheduledSlot::Ready(ScheduledConfig {
        height: height + 1,
        epoch: next.clone(),
        params,
    });
    result.schedule.after_next = ScheduledSlot::Ready(ScheduledConfig {
        height: height + 2,
        epoch: next,
        params,
    });
    let (lanes, writes_root) =
        NativeLaneStateProof::empty_for_testing(fixture.network_id(), height);
    result.native_lanes = lanes;
    result.execution.ordinary_writes_root = writes_root;
    result.validate().unwrap();

    let mut header: CoreHeader = norito::decode_canonical(&template.consensus_header).unwrap();
    header.height = height;
    header.epoch = core_epoch(current).unwrap().id;
    let (crypto, _) = ProofCrypto::new(&fixture.genesis_proof().committee).unwrap();
    let mut qc: Qc = norito::decode_canonical(&template.commit_qc).unwrap();
    qc.height = height;
    qc.epoch = header.epoch;
    qc.block_hash = header.hash(&crypto);
    let result_preimage = result.preimage().unwrap();
    qc.result = result_of_preimage(&result_preimage);
    resign(&mut qc);
    SumeragiCommitCertificateV1 {
        consensus_header: norito::encode_canonical(&header).unwrap(),
        commit_qc: norito::encode_canonical(&qc).unwrap(),
        result_preimage,
    }
}

#[test]
fn repeated_authenticated_boundaries_keep_two_checkpoint_contexts() {
    let (fixture, chain, mut reader) = authenticated_boundary(4);
    let selected = root(&fixture);
    let template = certificate(&fixture, &chain[2]);
    let mut encoded_lengths = Vec::new();
    for epoch in 1..=70 {
        let checkpoint = reader.export_epoch_checkpoint(epoch).unwrap();
        let bytes = checkpoint.encode_canonical().unwrap();
        encoded_lengths.push(bytes.len());
        let mut restored =
            SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&checkpoint, &selected)
                .unwrap();
        assert_eq!(restored.epochs.len(), 2);
        assert_eq!(
            restored.epochs.keys().copied().collect::<Vec<_>>(),
            [0, epoch]
        );
        let proof = next_boundary(&fixture, &template, checkpoint.selected_epoch());
        let expected = reader.verify(&proof).unwrap();
        let promoted = restored.verify_epoch_boundary(&proof).unwrap();
        assert_eq!(promoted, reader.export_epoch_checkpoint(epoch + 1).unwrap());
        let actual = restored.verify(&proof).unwrap();
        assert_eq!(actual.commitment(), expected.commitment());
        assert_eq!(
            restored.export_epoch_checkpoint(epoch + 1).unwrap(),
            reader.export_epoch_checkpoint(epoch + 1).unwrap()
        );
        // Generic readers still retain all authenticated epochs for historical receipts.
        assert_eq!(reader.epochs.len(), usize::try_from(epoch + 2).unwrap());
    }
    assert!(
        encoded_lengths
            .iter()
            .all(|length| *length <= MAX_COMMIT_CHECKPOINT_BYTES)
    );
    assert!(
        encoded_lengths
            .iter()
            .all(|length| *length == encoded_lengths[0])
    );
}
