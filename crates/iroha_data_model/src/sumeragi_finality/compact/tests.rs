//! Direct native BLS and sparse epoch-authorization regression tests.

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

fn resign(qc: &mut Qc, signers: &[usize]) {
    let mut keys: Vec<_> = (1..=4)
        .map(|seed| {
            iroha_crypto::KeyPair::from_seed(vec![seed; 32], iroha_crypto::Algorithm::BlsNormal)
        })
        .collect();
    keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
    qc.signers = iroha_sumeragi::types::Bitmap::from_indices(
        4,
        signers.iter().map(|i| u32::try_from(*i).unwrap()),
    )
    .unwrap();
    let shares: Vec<_> = signers
        .iter()
        .map(|i| iroha_crypto::Signature::try_new(keys[*i].private_key(), &qc.preimage()).unwrap())
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

#[test]
fn ordinary_certificate_needs_no_intermediate_block_history() {
    let mut fixture = NativeFinalityFixture::start("compact-same-epoch");
    let selected = root(&fixture);
    for _ in 0..3 {
        let block = fixture.block_with_submitted_work(fixture.next_header());
        fixture.certify(block);
    }
    let proof = certificate(&fixture, fixture.latest());
    let mut reader = SumeragiCommitVerifierV1::new(&selected).unwrap();
    assert_eq!(reader.network(), fixture.network_id());
    assert_eq!(reader.chain_id(), fixture.chain_id());
    let certified = reader.verify(&proof).unwrap();
    let original = fixture
        .verifier()
        .verify_retained_decision(fixture.latest())
        .unwrap();
    assert_eq!(certified.height(), 4);
    assert_eq!(certified.core_hash(), original.core_hash());
    assert_eq!(certified.execution(), original.execution());
    assert_eq!(certified.commitment(), original.commitment());
    certified
        .verify_global_scope(fixture.network_id(), fixture.chain_id())
        .unwrap();
    assert!(
        certified
            .verify_global_scope(fixture.network_id(), "foreign-chain")
            .is_err()
    );
    let genesis = fixture
        .verifier()
        .verify_retained_decision(fixture.genesis_proof())
        .unwrap();
    assert!(SumeragiCommitCertificateV1::from_verified(&genesis).is_err());
}

#[test]
fn original_certificate_codec_and_selectors_grant_no_authority() {
    let fixture = NativeFinalityFixture::new();
    let proof = certificate(&fixture, fixture.latest());
    let bytes = proof.to_canonical_bytes().unwrap();
    assert_eq!(
        SumeragiCommitCertificateV1::decode_canonical(&bytes).unwrap(),
        proof
    );
    assert_eq!(proof.height().unwrap(), fixture.latest().height());
    assert_eq!(proof.epoch_id().unwrap(), 0);
    assert!(bytes.len() <= MAX_COMMIT_CERTIFICATE_BYTES_V1);
    for malformed in [
        Vec::new(),
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        [bytes.as_slice(), bytes.as_slice()].concat(),
        vec![0; MAX_COMMIT_CERTIFICATE_BYTES_V1 + 1],
    ] {
        assert!(SumeragiCommitCertificateV1::decode_canonical(&malformed).is_err());
    }
    for mutate in [
        |value: &mut SumeragiCommitCertificateV1| value.consensus_header.push(0),
        |value: &mut SumeragiCommitCertificateV1| value.commit_qc.push(0),
        |value: &mut SumeragiCommitCertificateV1| value.result_preimage.push(0),
    ] {
        let mut changed = proof.clone();
        mutate(&mut changed);
        assert!(changed.to_canonical_bytes().is_err());
        assert!(
            SumeragiCommitCertificateV1::decode_canonical(
                &norito::encode_canonical(&changed).unwrap()
            )
            .is_err()
        );
    }
    let mut changed = proof.clone();
    changed.consensus_header.clear();
    assert!(changed.height().is_err());
    assert!(changed.epoch_id().is_err());
    let mut forged = proof;
    let mut qc: Qc = norito::decode_canonical(&forged.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.commit_qc = norito::encode_canonical(&qc).unwrap();
    let data = SumeragiCommitCertificateV1::decode_canonical(&forged.to_canonical_bytes().unwrap())
        .unwrap();
    assert!(
        SumeragiCommitVerifierV1::new(&root(&fixture))
            .unwrap()
            .verify(&data)
            .is_err()
    );
}

#[test]
fn boundary_sync_requires_a_verified_boundary_and_is_atomic() {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let selected = root(&fixture);
    let mut reader = SumeragiCommitVerifierV1::new(&selected).unwrap();
    let initial = reader.export_epoch_checkpoint(0).unwrap();
    assert!(
        reader
            .verify_epoch_boundary(&certificate(&fixture, &chain[1]))
            .is_err()
    );
    assert_eq!(reader.epochs.len(), 1);
    assert_eq!(reader.export_epoch_checkpoint(0).unwrap(), initial);
    let boundary = certificate(&fixture, &chain[2]);
    let mut forged = boundary.clone();
    forged.commit_qc[0] ^= 1;
    assert!(reader.verify_epoch_boundary(&forged).is_err());
    assert!(reader.export_epoch_checkpoint(1).is_err());
    let next = reader.verify_epoch_boundary(&boundary).unwrap();
    assert_eq!(next.selected_epoch().authorization.epoch, 1);
    assert_eq!(reader.verify_epoch_boundary(&boundary).unwrap(), next);
    let decoded =
        SumeragiCommitCheckpointV1::decode_canonical(&next.encode_canonical().unwrap()).unwrap();
    let mut restarted =
        SumeragiCommitVerifierV1::from_trusted_epoch_checkpoint(&decoded, &selected).unwrap();
    assert_eq!(
        restarted
            .verify(&certificate(&fixture, &chain[3]))
            .unwrap()
            .height(),
        4
    );
}

#[test]
fn only_incumbent_boundary_certificate_installs_successor() {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let selected = root(&fixture);
    let boundary = certificate(&fixture, &chain[2]);
    let successor = certificate(&fixture, &chain[3]);
    let mut reader = SumeragiCommitVerifierV1::new(&selected).unwrap();
    assert!(reader.verify(&successor).is_err());

    let mut forged = boundary.clone();
    let mut qc: Qc = norito::decode_canonical(&forged.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert!(reader.verify(&forged).is_err());
    assert!(reader.verify(&successor).is_err());

    // The B-1 block is deliberately absent. Its execution was validated by the
    // honest incumbent quorum before it signed this exact B boundary result.
    assert_eq!(reader.verify(&boundary).unwrap().height(), 3);
    assert_eq!(reader.verify(&successor).unwrap().height(), 4);

    let mut changed = successor.clone();
    let mut result = ExecutionResultCommitment::decode(&changed.result_preimage).unwrap();
    result.schedule.current.leader_seed[0] ^= 1;
    if let ScheduledSlot::Ready(slot) = &mut result.schedule.next {
        slot.epoch = result.schedule.current.clone();
    }
    if let ScheduledSlot::Ready(slot) = &mut result.schedule.after_next {
        slot.epoch = result.schedule.current.clone();
    }
    changed.result_preimage = result.preimage().unwrap();
    assert!(reader.verify(&changed).is_err());

    // Existing fully verified native checkpoints already convey successor authority.
    let mut checkpoint_reader = SumeragiCommitVerifierV1::new(&fixture.verifier()).unwrap();
    assert_eq!(checkpoint_reader.verify(&successor).unwrap().height(), 4);
}

#[test]
fn certificate_rejects_forged_bindings_and_non_exact_quorum() {
    let fixture = NativeFinalityFixture::new();
    let proof = certificate(&fixture, fixture.latest());
    let selected = root(&fixture);
    let check = |proof: &SumeragiCommitCertificateV1| {
        SumeragiCommitVerifierV1::new(&selected)
            .unwrap()
            .verify(proof)
    };
    check(&proof).unwrap();
    for mutate in [
        |qc: &mut Qc| qc.height += 1,
        |qc: &mut Qc| qc.result.0[0] ^= 1,
        |qc: &mut Qc| qc.instance.0[0] ^= 1,
        |qc: &mut Qc| qc.block_hash.0[0] ^= 1,
        |qc: &mut Qc| qc.agg_sig.0[0] ^= 1,
        |qc: &mut Qc| qc.kind = VoteKind::Prepare,
        |qc: &mut Qc| qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1]).unwrap(),
        |qc: &mut Qc| {
            qc.signers = iroha_sumeragi::types::Bitmap::from_indices(4, [0, 1, 2, 3]).unwrap()
        },
    ] {
        let mut changed = proof.clone();
        let mut qc: Qc = norito::decode_canonical(&changed.commit_qc).unwrap();
        mutate(&mut qc);
        changed.commit_qc = norito::encode_canonical(&qc).unwrap();
        assert!(check(&changed).is_err());
    }
    for signers in [vec![0, 1], vec![0, 1, 2, 3]] {
        let mut changed = proof.clone();
        let mut qc: Qc = norito::decode_canonical(&changed.commit_qc).unwrap();
        resign(&mut qc, &signers);
        changed.commit_qc = norito::encode_canonical(&qc).unwrap();
        assert!(
            check(&changed).is_err(),
            "valid BLS still requires exactly n-f votes"
        );
    }
    let mut changed = proof.clone();
    changed.result_preimage.push(0);
    assert!(check(&changed).is_err());
    changed = proof.clone();
    changed.consensus_header.clear();
    assert!(changed.validate_shape().is_err());
    changed = proof.clone();
    changed.commit_qc.resize(MAX_COMMIT_QC_BYTES + 1, 0);
    assert!(changed.validate_shape().is_err());
    let foreign = NativeFinalityFixture::start("foreign-genesis");
    assert!(
        SumeragiCommitVerifierV1::new(&root(&foreign))
            .unwrap()
            .verify(&proof)
            .is_err()
    );
    let foreign_network = NativeFinalityFixture::start_with_mode(
        fixture.chain_id(),
        crate::parameter::system::SumeragiConsensusMode::Npos,
    );
    assert!(
        SumeragiCommitVerifierV1::new(&root(&foreign_network))
            .unwrap()
            .verify(&proof)
            .is_err()
    );
    let private = NativeFinalityFixture::start_with_scope(
        fixture.chain_id(),
        crate::block::consensus::SumeragiRootScope::Dataspace {
            parent_network_id: fixture.network_id(),
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(9),
        },
    );
    assert!(SumeragiCommitVerifierV1::new(&root(&private)).is_err());
}

#[test]
fn certificate_codec_roundtrips_data_before_native_authentication() {
    let fixture = NativeFinalityFixture::new();
    let proof = certificate(&fixture, fixture.latest());
    let bytes = proof.to_canonical_bytes().unwrap();
    let decoded = SumeragiCommitCertificateV1::decode_canonical(&bytes).unwrap();
    assert_eq!(decoded, proof);
    assert_eq!(decoded.to_canonical_bytes().unwrap(), bytes);
    assert_eq!(decoded.height().unwrap(), fixture.latest().height());
    assert_eq!(decoded.epoch_id().unwrap(), 0);
    let mut reader = SumeragiCommitVerifierV1::new(&root(&fixture)).unwrap();
    reader.verify(&decoded).unwrap();

    let mut forged = decoded;
    let mut qc: Qc = norito::decode_canonical(&forged.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.commit_qc = norito::encode_canonical(&qc).unwrap();
    let data = SumeragiCommitCertificateV1::decode_canonical(&forged.to_canonical_bytes().unwrap())
        .unwrap();
    assert!(
        reader.verify(&data).is_err(),
        "canonical DATA is not authority"
    );
    for malformed in [
        Vec::new(),
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        [bytes.as_slice(), bytes.as_slice()].concat(),
        vec![0; MAX_COMMIT_CERTIFICATE_BYTES_V1 + 1],
    ] {
        assert!(SumeragiCommitCertificateV1::decode_canonical(&malformed).is_err());
    }
}

#[test]
fn certificate_codec_preserves_each_component_cap_and_inner_canonicality() {
    let fixture = NativeFinalityFixture::new();
    let proof = certificate(&fixture, fixture.latest());
    for component in 0..3 {
        for invalidity in 0..3 {
            let mut invalid = proof.clone();
            let (field, cap) = match component {
                0 => (&mut invalid.consensus_header, MAX_COMMIT_HEADER_BYTES),
                1 => (&mut invalid.commit_qc, MAX_COMMIT_QC_BYTES),
                _ => (&mut invalid.result_preimage, MAX_RESULT_PREIMAGE_BYTES),
            };
            match invalidity {
                0 => field.clear(),
                1 => field.resize(cap + 1, 0),
                _ => field.push(0),
            }
            assert!(invalid.to_canonical_bytes().is_err());
            let raw = norito::encode_canonical(&invalid).unwrap();
            assert!(SumeragiCommitCertificateV1::decode_canonical(&raw).is_err());
            if component == 0 {
                assert!(invalid.height().is_err());
                assert!(invalid.epoch_id().is_err());
            }
        }
    }

    // Check the maximum shape/framing allowance without mistaking zero DATA for originals.
    let maximum_shape = SumeragiCommitCertificateV1 {
        consensus_header: vec![0; MAX_COMMIT_HEADER_BYTES],
        commit_qc: vec![0; MAX_COMMIT_QC_BYTES],
        result_preimage: vec![0; MAX_RESULT_PREIMAGE_BYTES],
    };
    maximum_shape.validate_shape().unwrap();
    let bytes = norito::encode_canonical(&maximum_shape).unwrap();
    assert!(bytes.len() <= MAX_COMMIT_CERTIFICATE_BYTES_V1);
    assert!(maximum_shape.to_canonical_bytes().is_err());
    assert!(SumeragiCommitCertificateV1::decode_canonical(&bytes).is_err());
}

#[test]
fn epoch_boundary_helper_never_advances_on_ordinary_or_forged_data() {
    let (fixture, chain) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let mut reader = SumeragiCommitVerifierV1::new(&root(&fixture)).unwrap();
    let before = reader.epochs.clone();
    assert!(
        reader
            .verify_epoch_boundary(&certificate(&fixture, &chain[1]))
            .is_err()
    );
    assert_eq!(reader.epochs, before);
    let boundary = certificate(&fixture, &chain[2]);
    let mut forged = boundary.clone();
    let mut qc: Qc = norito::decode_canonical(&forged.commit_qc).unwrap();
    qc.agg_sig.0[0] ^= 1;
    forged.commit_qc = norito::encode_canonical(&qc).unwrap();
    assert!(reader.verify_epoch_boundary(&forged).is_err());
    assert_eq!(reader.epochs, before);

    let checkpoint = reader.verify_epoch_boundary(&boundary).unwrap();
    assert_eq!(checkpoint.selected_epoch().authorization.epoch, 1);
    assert_eq!(checkpoint, reader.export_epoch_checkpoint(1).unwrap());
    assert_eq!(
        reader
            .verify(&certificate(&fixture, &chain[3]))
            .unwrap()
            .height(),
        4
    );
    let after = reader.epochs.clone();
    assert!(
        reader
            .verify_epoch_boundary(&certificate(&fixture, &chain[3]))
            .is_err()
    );
    assert_eq!(reader.epochs, after);
}
