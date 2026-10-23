//! Native portable readers bind the sole X/body result format to the original block and root.

use super::certified_result::{FLAG_ACTIVE, X_LEN};
use super::test_fixtures::NativeFinalityFixture;
use super::*;
use crate::block::{CommitCertificate, consensus::SumeragiRootScope};

fn replace_preimage(
    proof: &SumeragiFinalityProof,
    preimage: Vec<u8>,
    resign: bool,
) -> SumeragiFinalityProof {
    let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let original = block.commit_certificate().unwrap();
    let header = original.consensus_header().to_vec();
    let availability = original.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical(original.commit_qc()).unwrap();
    if resign {
        qc.result = result_of_preimage(&preimage).unwrap();
        let mut keys: Vec<_> = (1..=4)
            .map(|seed| iroha_crypto::KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
            .collect();
        keys.sort_by_key(|key| key.public_key().try_to_bytes().unwrap().1.to_vec());
        super::tests::sign_qc(&mut qc, &keys, &[0, 1, 2]);
    }
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&qc).unwrap(),
        preimage,
        availability,
    )));
    SumeragiFinalityProof {
        block_header: block.header(),
        block_wire: block.encode_wire().unwrap(),
        committee: proof.committee.clone(),
    }
}

#[test]
fn portable_readers_reject_body_only_and_mismatched_header_before_granting_authority() {
    let fixture = NativeFinalityFixture::new();
    let proof = fixture.latest();
    let block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let preimage = block.commit_certificate().unwrap().result_preimage();
    assert!(
        proof
            .decode_checked(CertifiedResultScope::TairaGlobal)
            .is_ok()
    );
    let bare = replace_preimage(proof, preimage[X_LEN..].to_vec(), false);
    assert!(
        bare.decode_checked(CertifiedResultScope::TairaGlobal)
            .is_err()
    );
    let mut compact = SumeragiCommitCertificateV1::from_verified(
        &fixture.verifier().verify_retained_decision(proof).unwrap(),
    )
    .unwrap();
    compact.result_preimage = preimage[X_LEN..].to_vec();
    assert!(
        SumeragiCommitVerifierV1::new(&fixture.verifier())
            .unwrap()
            .verify(&compact)
            .is_err()
    );

    let header = SccpFinalityHeaderV1::parse(&preimage[..X_LEN]).unwrap();
    for mutation in 0..4 {
        let mut fields = header.fields();
        match mutation {
            0 => fields.height += 1,
            1 => fields.timestamp_ms += 1,
            2 => fields.network_id[0] ^= 1,
            3 => fields.flags = 0x80,
            _ => unreachable!(),
        }
        let mut changed = fields.to_bytes().to_vec();
        changed.extend_from_slice(&preimage[X_LEN..]);
        let changed = replace_preimage(proof, changed, false);
        let error = changed
            .decode_checked(CertifiedResultScope::TairaGlobal)
            .map_err(invalid_read_error)
            .unwrap_err()
            .0;
        assert!(error.contains("finality header"), "{mutation}: {error}");
        assert!(
            fixture
                .verifier()
                .verify_retained_decision(&changed)
                .is_err()
        );
    }
}

fn active_proof(fixture: &NativeFinalityFixture) -> SumeragiFinalityProof {
    let proof = fixture.latest();
    let block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let preimage = block.commit_certificate().unwrap().result_preimage();
    let result = CertifiedResultV1::decode(preimage, CertifiedResultScope::TairaGlobal).unwrap();
    let mut fields = result.header().fields();
    fields.flags = FLAG_ACTIVE;
    fields.generation = 1;
    fields.committee_root = context_committee_root(&result.commitment().schedule.current).unwrap();
    let mut preimage = SccpFinalityHeaderV1::from_fields(&fields)
        .unwrap()
        .as_bytes()
        .to_vec();
    preimage.extend_from_slice(&result.commitment().preimage().unwrap());
    replace_preimage(proof, preimage, true)
}

#[test]
fn original_signed_root_scope_controls_active_finality_admission() {
    let global = NativeFinalityFixture::new();
    let active_global = active_proof(&global);
    // Synthetic SCCP data is certified by the real fixture quorum; this is reader evidence,
    // not execution evidence for the SCCP State producer.
    active_global
        .decode_checked(CertifiedResultScope::TairaGlobal)
        .unwrap();
    let mut verifier = SumeragiFinalityVerifier::new(
        global.genesis(),
        global.chain_id(),
        global.genesis_proof().committee.clone(),
    )
    .unwrap();
    verifier.verify(global.genesis_proof()).unwrap();
    let accepted = verifier.verify(&active_global).unwrap();
    let compact = SumeragiCommitCertificateV1::from_verified(&accepted).unwrap();
    SumeragiCommitVerifierV1::new(&verifier)
        .unwrap()
        .verify(&compact)
        .unwrap();

    let scope = SumeragiRootScope::Dataspace {
        parent_network_id: global.network_id(),
        dataspace_id: iroha_model_base::topology::DataSpaceId::new(73),
    };
    let mut private = NativeFinalityFixture::start_with_scope("certified-result-private", scope);
    let block = private.block_with_submitted_work(private.next_header());
    private.certify(block);
    let active_private = active_proof(&private);
    active_private
        .decode_checked(CertifiedResultScope::TairaGlobal)
        .unwrap();
    assert!(
        active_private
            .decode_checked(CertifiedResultScope::NonGlobal)
            .is_err()
    );
    let mut verifier = SumeragiFinalityVerifier::new(
        private.genesis(),
        private.chain_id(),
        private.genesis_proof().committee.clone(),
    )
    .unwrap();
    verifier.verify(private.genesis_proof()).unwrap();
    assert_eq!(
        verifier
            .verify(&active_private)
            .map_err(invalid_read_error)
            .unwrap_err()
            .0,
        "a non-global root carries an active finality header"
    );
    verifier.verify(private.latest()).unwrap();
    assert!(SumeragiCommitVerifierV1::new(&verifier).is_err());
}

fn assert_original_reader_refusal(operation: impl FnOnce() -> Result<(), FinalityReadError>) {
    let limits = norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        0,
        64,
    );
    let failure = norito::with_decode_limits_scope(limits, operation).unwrap_err();
    let FinalityReadError::DecodeResource(original) = failure else {
        panic!("binary reader must retain the original unfinished attempt: {failure:?}");
    };
    assert_eq!(
        original.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    let raw = original.into_error();
    assert!(matches!(
        raw.decode_resource_error(),
        Some(norito::core::DecodeResourceError::TotalAllocationExceeded { limit: 0, .. })
    ));
    norito::with_decode_limits_scope(limits, || {
        assert!(
            !norito::core::decode_error_matches_active_limits(&raw),
            "equal numeric limits do not transfer ownership of the retired attempt"
        );
    });
}

#[test]
fn compact_and_full_original_readers_preserve_local_refusal_after_scope_retirement() {
    let fixture = NativeFinalityFixture::new();
    let native = fixture.verifier();
    let proof = fixture.latest();
    let verified = native.verify_retained_decision(proof).unwrap();
    let compact = SumeragiCommitCertificateV1::from_verified(&verified).unwrap();
    let compact_bytes = compact.to_canonical_bytes().unwrap();
    let mut reader = SumeragiCommitVerifierV1::new(&native).unwrap();
    let selected = reader
        .export_epoch_checkpoint(compact.epoch_id().unwrap())
        .unwrap();
    let selected_bytes = selected.encode_canonical().unwrap();
    let full_checkpoint = native.export_checkpoint(proof).unwrap();
    let full_checkpoint_bytes = full_checkpoint.encode_canonical().unwrap();
    assert_original_reader_refusal(|| compact.to_canonical_bytes().map(|_| ()));
    assert_original_reader_refusal(|| {
        SumeragiCommitCertificateV1::decode_canonical(&compact_bytes).map(|_| ())
    });
    assert_original_reader_refusal(|| reader.verify(&compact).map(|_| ()));
    assert_original_reader_refusal(|| reader.verify_epoch_boundary(&compact).map(|_| ()));
    assert_original_reader_refusal(|| {
        SumeragiCommitCheckpointV1::decode_canonical(&selected_bytes).map(|_| ())
    });
    assert_original_reader_refusal(|| {
        proof
            .decode_checked(CertifiedResultScope::TairaGlobal)
            .map(|_| ())
    });
    assert_original_reader_refusal(|| native.verify_retained_decision(proof).map(|_| ()));
    assert_original_reader_refusal(|| native.export_checkpoint(proof).map(|_| ()));
    assert_original_reader_refusal(|| {
        SumeragiFinalityCheckpoint::decode_canonical(&full_checkpoint_bytes).map(|_| ())
    });
    assert_eq!(
        reader
            .export_epoch_checkpoint(selected.selected_epoch().authorization.epoch)
            .unwrap(),
        selected,
        "local refusal must not publish a new authority selection"
    );
    assert_eq!(
        reader.verify(&compact).unwrap().core_hash(),
        verified.core_hash()
    );
    native.verify_retained_decision(proof).unwrap();
    SumeragiFinalityCheckpoint::decode_canonical(&full_checkpoint_bytes).unwrap();
}

#[test]
fn compact_header_readers_need_no_decode_heap_and_preserve_original_field_refusals() {
    let fixture = NativeFinalityFixture::new();
    let verified = fixture
        .verifier()
        .verify_retained_decision(fixture.latest())
        .unwrap();
    let compact = SumeragiCommitCertificateV1::from_verified(&verified).unwrap();
    let no_allocation =
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX);
    let no_field = norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, usize::MAX);
    for reader in [
        SumeragiCommitCertificateV1::height,
        SumeragiCommitCertificateV1::epoch_id,
    ] {
        let expected = reader(&compact).unwrap();
        assert_eq!(
            norito::with_decode_limits_scope(no_allocation, || reader(&compact)).unwrap(),
            expected
        );
        let failure = norito::with_decode_limits_scope(no_field, || reader(&compact)).unwrap_err();
        let FinalityReadError::DecodeResource(original) = failure else {
            panic!("header reader must retain its actual scoped field refusal: {failure:?}");
        };
        assert_eq!(
            original.kind(),
            norito::core::DecodeAttemptErrorKind::EnclosingLimit
        );
        let raw = original.into_error();
        assert!(
            matches!(raw.decode_resource_error(), Some(norito::core::DecodeResourceError::FieldLengthExceeded { length, limit: 0 }) if length > 0)
        );
        norito::with_decode_limits_scope(no_field, || {
            assert!(!norito::core::decode_error_matches_active_limits(&raw));
        });
        assert_eq!(reader(&compact).unwrap(), expected);
    }
}
