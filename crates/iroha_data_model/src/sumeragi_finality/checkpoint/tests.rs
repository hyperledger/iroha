//! Current four-validator checkpoint and publication authentication regressions.
use super::super::tests::{Fixture, certify_successor, result, sign_qc};
use super::*;
use crate::{
    account::AccountId,
    block::{CommitCertificate, builder::BlockBuilder, output_test_support},
    isi::{Log, sorafs::AssertSorafsPublicationV1},
    level::Level,
    sorafs::{
        pin_registry::{ManifestDigest, ReplicationOrderId},
        publication::{SorafsPublicationProofV1, verify_sorafs_publication_v1},
    },
    transaction::{
        FeePaymentIntent, SignedTransaction, TransactionBuilder, error::TransactionRejectionReason,
    },
};
use iroha_crypto::KeyPair;
use std::num::NonZeroU64;

const CHAIN: &str = "portable-finality-test";

fn extend(
    fixture: &Fixture,
    parent: &SumeragiFinalityProof,
    tx: SignedTransaction,
    succeeds: bool,
) -> SumeragiFinalityProof {
    let parent = parent.decode_checked().unwrap();
    let height = parent.block.header().height().get() + 1;
    let mut builder = BlockBuilder::new(BlockHeader::new(
        NonZeroU64::new(height).unwrap(),
        Some(parent.block.hash()),
        None,
        parent.block.header().creation_time_ms + 1,
        0,
    ));
    builder.push_transaction(tx);
    let mut block = builder.build(crate::block::BlockSignatures::default());
    let output = if succeeds {
        Ok(Vec::default())
    } else {
        Err(TransactionRejectionReason::Validation(
            crate::ValidationFail::NotPermitted("publication assertion rejected".into()),
        ))
    };
    output_test_support::install_network(&mut block, vec![output]).unwrap();
    let result = result(&block, &parent.commitment.schedule.current);
    certify_successor(
        &fixture.keys,
        &fixture.validators,
        fixture.verifier().instance(),
        &parent,
        block,
        &result,
    )
}

fn transaction(fixture: &Fixture, text: &str) -> SignedTransaction {
    let key = KeyPair::from_seed(vec![42; 32], Algorithm::Ed25519);
    TransactionBuilder::new(
        fixture.network,
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([Log::new(Level::INFO, text.into())])
    .sign(key.private_key())
}

fn checkpoint(fixture: &Fixture) -> SumeragiFinalityCheckpoint {
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(&fixture.second).unwrap();
    verifier.export_checkpoint(&fixture.second).unwrap()
}

fn assertion(
    fixture: &Fixture,
    checkpoint: &SumeragiFinalityCheckpoint,
    complete: bool,
    challenge: u8,
) -> SignedTransaction {
    let key = KeyPair::from_seed(vec![43; 32], Algorithm::Ed25519);
    TransactionBuilder::new(
        fixture.network,
        AccountId::new(key.public_key().clone()),
        FeePaymentIntent::authority(vec![], None),
    )
    .with_instructions([AssertSorafsPublicationV1 {
        manifest_digest: ManifestDigest([0x31; 32]),
        order_id: ReplicationOrderId([0x32; 32]),
        assignment_revision: 1,
        canonical_order_digest: [0x33; 32],
        require_complete: complete,
        challenge: [challenge; 32],
        minimum_height: checkpoint.height(),
        minimum_block_hash: *checkpoint.block_hash().as_ref(),
    }])
    .sign(key.private_key())
}

#[test]
fn checkpoint_roundtrip_retains_only_three_authenticated_decisions_and_extends() {
    let fixture = Fixture::new();
    let mut verifier = fixture.verifier();
    let mut tip = fixture.first.clone();
    verifier.verify(&tip).unwrap();
    for height in 1..=5 {
        if height > 1 {
            tip = extend(
                &fixture,
                &tip,
                transaction(&fixture, &format!("height {height}")),
                true,
            );
            verifier.verify(&tip).unwrap();
        }
        let checkpoint = verifier.export_checkpoint(&tip).unwrap();
        assert_eq!(checkpoint.decisions.len(), height.min(3));
        assert_eq!(checkpoint.height(), height as u64);
        assert_eq!(checkpoint.block_hash(), tip.block_header.hash());
        assert_eq!(checkpoint.network_id(), fixture.network);
        assert_eq!(checkpoint.chain_id(), CHAIN);
        let bytes = checkpoint.encode_canonical().unwrap();
        let decoded = SumeragiFinalityCheckpoint::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, checkpoint);
        let mut resumed =
            SumeragiFinalityVerifier::from_trusted_checkpoint(&decoded, &fixture.network, CHAIN)
                .unwrap();
        assert_eq!(resumed.decisions.len(), height.min(3));
        let next = extend(&fixture, &tip, transaction(&fixture, "after restart"), true);
        resumed.verify(&next).unwrap();
        assert_eq!(
            resumed.export_checkpoint(&next).unwrap().height(),
            height as u64 + 1
        );
    }
    // The general verifier's existing prefix retention contract stays unchanged.
    assert_eq!(verifier.decisions.len(), 5);
}

#[test]
fn checkpoint_rejects_substituted_roots_schedule_tip_and_noncanonical_material() {
    let fixture = Fixture::new();
    let good = checkpoint(&fixture);
    let foreign =
        NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")));
    assert!(SumeragiFinalityVerifier::from_trusted_checkpoint(&good, &foreign, CHAIN).is_err());
    assert!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(&good, &fixture.network, "wrong chain")
            .is_err()
    );
    for mutation in 0..10 {
        let mut bad = good.clone();
        match mutation {
            0 => bad.genesis_wire = fixture.second.block_wire.clone(),
            1 => bad.genesis_committee[0].proof_of_possession[0] ^= 1,
            2 => bad.tip.committee[0].proof_of_possession[0] ^= 1,
            3 => {
                bad.decisions[0].block_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"other genesis"))
            }
            4 => bad.decisions[0].result[0] ^= 1,
            5 => bad.decisions[1].committee_digest[0] ^= 1,
            6 => bad.decisions[1].executed_len += 1,
            7 => bad.decisions[1].height += 1,
            8 => {
                bad.tip = extend(
                    &fixture,
                    &fixture.first,
                    transaction(&fixture, "fork"),
                    true,
                )
            }
            _ => {
                bad.decisions.pop();
            }
        }
        assert!(
            SumeragiFinalityVerifier::from_trusted_checkpoint(&bad, &fixture.network, CHAIN)
                .is_err(),
            "mutation {mutation}"
        );
        assert!(
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
                &bad,
                &fixture.network,
                CHAIN,
            )
            .is_err(),
            "tip handoff mutation {mutation}"
        );
    }
    let mut trailing = good.encode_canonical().unwrap();
    trailing.push(0);
    assert!(SumeragiFinalityCheckpoint::decode_canonical(&trailing).is_err());
    assert!(SumeragiFinalityCheckpoint::decode_canonical(&[]).is_err());
    let mut oversized = good;
    oversized.chain_id = "x".repeat(1025);
    assert!(oversized.encode_canonical().is_err());
}

#[test]
fn checkpoint_exports_only_verified_tip_and_accepts_alternate_certificate() {
    let fixture = Fixture::new();
    let mut verifier = fixture.verifier();
    assert!(verifier.export_checkpoint(&fixture.first).is_err());
    verifier.verify(&fixture.first).unwrap();
    assert!(verifier.export_checkpoint(&fixture.second).is_err());
    verifier.verify(&fixture.second).unwrap();
    assert!(verifier.export_checkpoint(&fixture.first).is_err());
    let checkpoint = verifier.export_checkpoint(&fixture.alternate()).unwrap();
    let resumed =
        SumeragiFinalityVerifier::from_trusted_checkpoint(&checkpoint, &fixture.network, CHAIN)
            .unwrap();
    resumed
        .verify_same_decision(checkpoint.tip(), &fixture.second)
        .unwrap();
}

#[test]
fn checkpoint_lag_two_binding_and_height_exhaustion_refuse() {
    let fixture = Fixture::new();
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(&fixture.second).unwrap();
    let third = extend(
        &fixture,
        &fixture.second,
        transaction(&fixture, "third"),
        true,
    );
    verifier.verify(&third).unwrap();
    let mut checkpoint = verifier.export_checkpoint(&third).unwrap();
    checkpoint.decisions[0].schedule.current.leader_seed[0] ^= 1;
    assert!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(&checkpoint, &fixture.network, CHAIN)
            .is_err()
    );
    let decision = verifier.decisions.get(&3).unwrap().clone();
    verifier.decisions.insert(u64::MAX, decision);
    assert!(
        verifier
            .verify(&third)
            .unwrap_err()
            .0
            .contains("height exhausted")
    );
    checkpoint.tip.block_header.height = NonZeroU64::new(u64::MAX).unwrap();
    assert!(checkpoint.encode_canonical().is_err());
}

#[test]
fn publication_proof_authenticates_both_phases_and_canonical_current_wire() {
    let fixture = Fixture::new();
    let checkpoint = checkpoint(&fixture);
    for complete in [false, true] {
        let tx = assertion(&fixture, &checkpoint, complete, 1);
        let tip = extend(&fixture, &fixture.second, tx.clone(), true);
        let proof = SorafsPublicationProofV1 {
            lineage: vec![fixture.alternate(), tip.clone()],
        };
        let bytes = norito::encode_canonical(&proof).unwrap();
        let decoded: SorafsPublicationProofV1 = norito::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, proof);
        let verified =
            verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &decoded).unwrap();
        assert_eq!(verified.completed(), complete);
        assert_eq!(verified.finality().tip(), &tip);
        assert_eq!(tip.committee.len(), 4);
        let block = tip.decode_checked().unwrap();
        let qc: Qc =
            norito::decode_canonical(block.block.commit_certificate().unwrap().commit_qc())
                .unwrap();
        assert_eq!(qc.signers.count_ones(), 3);
        assert!(
            SumeragiFinalityVerifier::from_trusted_checkpoint(
                verified.finality(),
                &fixture.network,
                CHAIN
            )
            .is_ok()
        );
    }
}

#[test]
fn publication_proof_rejects_signed_failure_replay_phase_and_output_substitution() {
    let fixture = Fixture::new();
    let checkpoint = checkpoint(&fixture);
    let tx = assertion(&fixture, &checkpoint, false, 1);
    let tip = extend(&fixture, &fixture.second, tx.clone(), true);
    let valid = SorafsPublicationProofV1 {
        lineage: vec![fixture.second.clone(), tip],
    };
    for expected in [
        assertion(&fixture, &checkpoint, false, 2),
        assertion(&fixture, &checkpoint, true, 1),
        assertion(&fixture, &checkpoint, false, 0),
        transaction(&fixture, "not an assertion"),
    ] {
        assert!(
            verify_sorafs_publication_v1(&fixture.network, &checkpoint, &expected, &valid).is_err()
        );
    }
    let failed_tip = extend(&fixture, &fixture.second, tx.clone(), false);
    failed_tip.decode_checked().unwrap();
    let failed = SorafsPublicationProofV1 {
        lineage: vec![fixture.second.clone(), failed_tip.clone()],
    };
    assert!(verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &failed).is_err());
    let mut substituted = valid.clone();
    let mut failed_block = failed_tip.decode_checked().unwrap().block;
    let valid_certificate = valid.lineage[1]
        .decode_checked()
        .unwrap()
        .block
        .commit_certificate()
        .unwrap()
        .clone();
    failed_block.set_commit_certificate(Some(valid_certificate));
    substituted.lineage[1].block_wire = failed_block.encode_wire().unwrap();
    assert!(
        verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &substituted).is_err()
    );
    let mut corrupt = valid.clone();
    let mut block = corrupt.lineage[1].decode_checked().unwrap().block;
    let certificate = block.commit_certificate().unwrap();
    let consensus_header = certificate.consensus_header().to_vec();
    let result_preimage = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    qc.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        consensus_header,
        norito::encode_canonical(&qc).unwrap(),
        result_preimage,
        availability,
    )));
    corrupt.lineage[1].block_wire = block.encode_wire().unwrap();
    assert!(verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &corrupt).is_err());
    let mut truncated = valid.clone();
    truncated.lineage.remove(0);
    assert!(verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &truncated).is_err());
    let replayed =
        verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &valid).unwrap();
    assert!(
        verify_sorafs_publication_v1(&fixture.network, replayed.finality(), &tx, &valid).is_err()
    );
}

#[test]
fn publication_proof_rejects_independently_valid_fork_gap_and_unbound_floor() {
    let fixture = Fixture::new();
    let checkpoint = checkpoint(&fixture);
    let tx = assertion(&fixture, &checkpoint, true, 3);
    let fork = extend(
        &fixture,
        &fixture.first,
        transaction(&fixture, "independently valid fork"),
        true,
    );
    let mut foreign = fixture.verifier();
    foreign.verify(&fixture.first).unwrap();
    foreign.verify(&fork).unwrap();
    let foreign_checkpoint = foreign.export_checkpoint(&fork).unwrap();
    let proof = SorafsPublicationProofV1 {
        lineage: vec![
            fixture.second.clone(),
            extend(&fixture, &fixture.second, tx.clone(), true),
        ],
    };
    assert!(
        verify_sorafs_publication_v1(&fixture.network, &foreign_checkpoint, &tx, &proof).is_err()
    );
    let wrong_floor = assertion(&fixture, &foreign_checkpoint, true, 3);
    let wrong_floor_proof = SorafsPublicationProofV1 {
        lineage: vec![
            fixture.second.clone(),
            extend(&fixture, &fixture.second, wrong_floor.clone(), true),
        ],
    };
    assert!(
        verify_sorafs_publication_v1(
            &fixture.network,
            &checkpoint,
            &wrong_floor,
            &wrong_floor_proof
        )
        .is_err()
    );
    let fourth = extend(&fixture, &proof.lineage[1], tx.clone(), true);
    let gap = SorafsPublicationProofV1 {
        lineage: vec![fixture.second.clone(), fourth],
    };
    assert!(verify_sorafs_publication_v1(&fixture.network, &checkpoint, &tx, &gap).is_err());
}

#[test]
fn retained_decision_verifier_uses_selected_checkpoint_commitments() {
    let fixture = Fixture::new();
    let checkpoint = checkpoint(&fixture);
    let verifier =
        SumeragiFinalityVerifier::from_trusted_checkpoint(&checkpoint, &fixture.network, CHAIN)
            .unwrap();
    verifier.verify_retained_decision(&fixture.first).unwrap();
    verifier.verify_retained_decision(&fixture.second).unwrap();
    let empty = fixture.verifier();
    assert!(empty.verify_retained_decision(&fixture.first).is_err());
    let mut forged = fixture.second.clone();
    let mut block = decode_framed_signed_block(&forged.block_wire).unwrap();
    let cert = block.commit_certificate().unwrap();
    let header = cert.consensus_header().to_vec();
    let availability = cert.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical(cert.commit_qc()).unwrap();
    let mut result = ExecutionResultCommitment::decode(cert.result_preimage()).unwrap();
    result.execution.parent_state_root = Hash::new(b"different retained execution");
    qc.result = result.result().unwrap();
    sign_qc(&mut qc, &fixture.keys, &[0, 1, 2]);
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&qc).unwrap(),
        result.preimage().unwrap(),
        availability,
    )));
    forged.block_wire = block.encode_wire().unwrap();
    assert!(forged.decode_checked().is_ok());
    assert!(verifier.verify_retained_decision(&forged).is_err());
}

#[test]
fn original_checkpoint_binary_refusal_preserves_exact_fields_and_retries() {
    let fixture = Fixture::new();
    let selected = checkpoint(&fixture);
    let original = selected.encode_canonical().unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let producer = norito::with_decode_limits_scope(limits, || {
        norito::with_decode_limits_scope(
            norito::canonical_decode_limits(selected.genesis_wire.len()),
            || decode_framed_signed_block(&selected.genesis_wire),
        )
    })
    .unwrap_err();
    assert_eq!(
        producer.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    let expected = producer
        .into_error()
        .decode_resource_error()
        .expect("original resource fields");
    assert!(
        matches!(expected, norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 } if attempted > 0)
    );
    let error = norito::with_decode_limits_scope(limits, || {
        SumeragiFinalityVerifier::from_trusted_checkpoint(&selected, &fixture.network, CHAIN)
    })
    .unwrap_err();
    let super::super::FinalityReadError::DecodeResource(actual) = error else {
        panic!("{error:?}");
    };
    assert_eq!(
        actual.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    assert_eq!(actual.into_error().decode_resource_error(), Some(expected));
    assert_eq!(selected.encode_canonical().unwrap(), original);
    let retried =
        SumeragiFinalityVerifier::from_trusted_checkpoint(&selected, &fixture.network, CHAIN)
            .unwrap();
    assert_eq!(retried.export_checkpoint(selected.tip()).unwrap(), selected);
    let mut malformed = selected.clone();
    malformed.genesis_wire[0] = u8::MAX;
    let error =
        SumeragiFinalityVerifier::from_trusted_checkpoint(&malformed, &fixture.network, CHAIN)
            .unwrap_err();
    assert!(
        matches!(error, super::super::FinalityReadError::Invalid(_)),
        "{error:?}"
    );
    assert_eq!(selected.encode_canonical().unwrap(), original);
}

#[test]
fn native_decision_data_retains_exact_selected_genesis_and_all_three_parents() {
    use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let mut fixture = NativeFinalityFixture::start("native-decision-data-fixture");
    let original = fixture
        .verifier()
        .export_checkpoint(fixture.latest())
        .unwrap();
    let mut proofs = vec![fixture.latest().clone()];
    for _ in 0..4 {
        let block = fixture.block_with_submitted_work(fixture.next_header());
        proofs.push(
            fixture.certify_with_world_root(block, Hash::new(b"known public synthetic World")),
        );
    }
    let bounded = &proofs[2..];
    let checkpoint = original
        .with_independently_authenticated_decision_data(bounded)
        .unwrap();
    let actual = fixture
        .verifier()
        .export_checkpoint(fixture.latest())
        .unwrap();
    assert_eq!(
        checkpoint.encode_canonical().unwrap(),
        actual.encode_canonical().unwrap()
    );
    assert_eq!(checkpoint.network_id(), original.network_id());
    assert_eq!(checkpoint.chain_id(), original.chain_id());
    let admitted = SumeragiFinalityVerifier::from_trusted_checkpoint(
        &checkpoint,
        &fixture.network_id(),
        "native-decision-data-fixture",
    )
    .unwrap();
    admitted.verify_retained_decision(fixture.latest()).unwrap();
    assert!(
        original
            .with_independently_authenticated_decision_data(&bounded[1..])
            .is_err()
    );
    assert!(
        original
            .with_independently_authenticated_decision_data(&[
                bounded[1].clone(),
                bounded[0].clone(),
                bounded[2].clone()
            ])
            .is_err()
    );
    assert!(
        original
            .with_independently_authenticated_decision_data(&proofs)
            .is_err()
    );
    assert!(
        original
            .with_independently_authenticated_decision_data(&[])
            .is_err()
    );
}

#[test]
fn decoded_decision_equality_never_labels_different_execution_as_native() {
    use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let fixture = NativeFinalityFixture::new();
    let genuine = fixture
        .verifier()
        .verify_retained_decision(fixture.latest())
        .unwrap();
    let decoded = fixture.latest().decode_checked().unwrap();
    assert!(decoded.matches_native_execution_decision(
        &fixture.latest().block_header.hash(),
        genuine.core_hash().0,
        genuine.result().0,
        genuine.commitment()
    ));
    let mut altered = genuine.commitment().clone();
    altered.execution.world_state_root = Hash::new(b"different synthetic World");
    assert!(!decoded.matches_native_execution_decision(
        &fixture.latest().block_header.hash(),
        genuine.core_hash().0,
        genuine.result().0,
        &altered
    ));
    assert!(!decoded.matches_native_execution_decision(
        &fixture.latest().block_header.hash(),
        [1; 32],
        genuine.result().0,
        genuine.commitment()
    ));
    assert!(!decoded.matches_native_execution_decision(
        &fixture.latest().block_header.hash(),
        genuine.core_hash().0,
        [1; 32],
        genuine.commitment()
    ));
}

#[test]
fn checkpoint_single_witness_rechecks_certificate_and_preserves_distinct_witness_refusal() {
    let fixture = Fixture::new();
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(&fixture.second).unwrap();
    let good = verifier.export_checkpoint(&fixture.second).unwrap();

    // Preserve the authenticated height, executed result and block header while corrupting
    // only the current quorum signature. A retained decision cannot authenticate these bytes.
    let mut bad = fixture.second.clone();
    let mut block = decode_framed_signed_block(&bad.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let consensus_header = certificate.consensus_header().to_vec();
    let result_preimage = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    qc.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        consensus_header.clone(),
        norito::encode_canonical(&qc).unwrap(),
        result_preimage.clone(),
        availability.clone(),
    )));
    let changed = block.commit_certificate().unwrap();
    assert_eq!(changed.consensus_header(), consensus_header);
    assert_eq!(changed.result_preimage(), result_preimage);
    assert_eq!(changed.availability(), availability);
    assert_eq!(
        norito::decode_canonical::<Qc>(changed.commit_qc()).unwrap(),
        qc
    );
    bad.block_wire = block.encode_wire().unwrap();
    assert_eq!(bad.block_header, fixture.second.block_header);
    assert_ne!(bad.block_wire, fixture.second.block_wire);
    assert!(verifier.export_checkpoint(&bad).is_err());
    let mut substituted = good.clone();
    substituted.tip = bad.clone();
    assert!(matches!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(&substituted, &fixture.network, CHAIN),
        Err(FinalityReadError::Invalid(_))
    ));
    assert!(matches!(
        SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &substituted,
            &fixture.network,
            CHAIN,
        ),
        Err(FinalityReadError::Invalid(_))
    ));
    assert_eq!(verifier.export_checkpoint(&fixture.second).unwrap(), good);

    let calls = std::cell::Cell::new(0_u32);
    let bad_bytes = substituted.encode_canonical().unwrap();
    let refusal = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
        &substituted,
        &fixture.network,
        CHAIN,
        |_, _, _| calls.set(calls.get() + 1),
    )
    .unwrap_err();
    assert!(matches!(refusal, FinalityReadError::Invalid(_)));
    assert_eq!(calls.get(), 0);
    assert_eq!(substituted.encode_canonical().unwrap(), bad_bytes);
    let retried = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
        &good,
        &fixture.network,
        CHAIN,
        |source, imported, tip| {
            calls.set(calls.get() + 1);
            assert!(std::ptr::eq(source, &raw const good));
            assert_eq!(imported.export_checkpoint(&source.tip).unwrap(), good);
            assert_eq!(tip.block().encode_wire().unwrap(), good.tip.block_wire);
            tip.context_id()
        },
    )
    .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        retried,
        verifier
            .verify_retained_decision(&fixture.second)
            .unwrap()
            .context_id()
    );

    let resumed =
        SumeragiFinalityVerifier::from_trusted_checkpoint(&good, &fixture.network, CHAIN).unwrap();
    // Two distinct offered witnesses still both undergo the original verification API.
    assert!(resumed.verify_same_decision(&good.tip, &bad).is_err());
    assert!(resumed.verify_same_decision(&bad, &good.tip).is_err());
    let alternate = fixture.alternate();
    assert_ne!(alternate.block_wire, good.tip.block_wire);
    assert!(resumed.verify_same_decision(&good.tip, &alternate).is_ok());
    let alternate_checkpoint = resumed.export_checkpoint(&alternate).unwrap();
    assert!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(
            &alternate_checkpoint,
            &fixture.network,
            CHAIN,
        )
        .is_ok()
    );
    assert_eq!(resumed.export_checkpoint(&good.tip).unwrap(), good);
}

#[test]
fn checkpoint_import_handoff_preserves_exact_witness_scope_and_resource_errors() {
    let fixture = Fixture::new();
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(&fixture.second).unwrap();
    let alternate = fixture.alternate();
    assert_ne!(alternate.block_wire, fixture.second.block_wire);
    for proof in [&fixture.second, &alternate] {
        let selected = verifier.export_checkpoint(proof).unwrap();
        let original = selected.encode_canonical().unwrap();
        let (imported, tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &selected,
            &fixture.network,
            CHAIN,
        )
        .unwrap();
        let ordinary =
            SumeragiFinalityVerifier::from_trusted_checkpoint(&selected, &fixture.network, CHAIN)
                .unwrap();
        assert_eq!(tip.block().encode_wire().unwrap(), proof.block_wire);
        assert_eq!(tip.height(), selected.height());
        assert_eq!(tip.header().hash(), selected.block_hash());
        assert_eq!(imported.export_checkpoint(proof).unwrap(), selected);
        assert_eq!(ordinary.export_checkpoint(proof).unwrap(), selected);

        let calls = std::cell::Cell::new(0_u32);
        let owned_source = selected.clone();
        let owned_wire = owned_source.tip.block_wire.as_ptr();
        let projected = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
            owned_source,
            &fixture.network,
            CHAIN,
            |source, imported, tip| {
                calls.set(calls.get() + 1);
                assert_eq!(source.tip.block_wire.as_ptr(), owned_wire);
                assert_eq!(source, selected);
                assert_eq!(imported.export_checkpoint(proof).unwrap(), selected);
                assert_eq!(tip.block().encode_wire().unwrap(), proof.block_wire);
                (tip.height(), tip.context_id())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(projected, (tip.height(), tip.context_id()));

        let foreign =
            NetworkId::from_genesis_hash(HashOf::from_untyped_unchecked(Hash::new(b"foreign")));
        for (network, chain) in [(foreign, CHAIN), (fixture.network, "wrong chain")] {
            let handoff = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
                &selected, &network, chain,
            )
            .unwrap_err();
            let ordinary =
                SumeragiFinalityVerifier::from_trusted_checkpoint(&selected, &network, chain)
                    .unwrap_err();
            assert_eq!(format!("{handoff:?}"), format!("{ordinary:?}"));
            let refused = std::cell::Cell::new(false);
            let consumer = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                &selected,
                &network,
                chain,
                |_, _, _| refused.set(true),
            )
            .unwrap_err();
            assert_eq!(format!("{consumer:?}"), format!("{ordinary:?}"));
            assert!(!refused.get());
        }
        let no_allocation = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
        let handoff = norito::with_decode_limits_scope(no_allocation, || {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
                &selected,
                &fixture.network,
                CHAIN,
            )
        })
        .unwrap_err();
        let ordinary = norito::with_decode_limits_scope(no_allocation, || {
            SumeragiFinalityVerifier::from_trusted_checkpoint(&selected, &fixture.network, CHAIN)
        })
        .unwrap_err();
        assert!(matches!(handoff, FinalityReadError::DecodeResource(_)));
        assert_eq!(format!("{handoff:?}"), format!("{ordinary:?}"));
        let refused = std::cell::Cell::new(0_u32);
        let consumer = norito::with_decode_limits_scope(no_allocation, || {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                &selected,
                &fixture.network,
                CHAIN,
                |_, _, _| refused.set(refused.get() + 1),
            )
        })
        .unwrap_err();
        assert!(matches!(consumer, FinalityReadError::DecodeResource(_)));
        assert_eq!(format!("{consumer:?}"), format!("{ordinary:?}"));
        let owned_source = selected.clone();
        let owned_refusal = norito::with_decode_limits_scope(no_allocation, || {
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
                owned_source,
                &fixture.network,
                CHAIN,
                |_, _, _| refused.set(refused.get() + 1),
            )
        })
        .unwrap_err();
        assert!(matches!(
            owned_refusal,
            FinalityReadError::DecodeResource(_)
        ));
        assert_eq!(format!("{owned_refusal:?}"), format!("{ordinary:?}"));
        assert_eq!(refused.get(), 0);
        assert_eq!(selected.encode_canonical().unwrap(), original);
        let retried = SumeragiFinalityVerifier::from_trusted_checkpoint_with_consumer(
            &selected,
            &fixture.network,
            CHAIN,
            |source, imported, tip| {
                refused.set(refused.get() + 1);
                assert!(std::ptr::eq(source, &raw const selected));
                assert_eq!(imported.export_checkpoint(proof).unwrap(), selected);
                assert_eq!(tip.block().encode_wire().unwrap(), proof.block_wire);
                tip.height()
            },
        )
        .unwrap();
        assert_eq!(refused.get(), 1);
        assert_eq!(retried, selected.height());
        assert_eq!(selected.encode_canonical().unwrap(), original);
        assert!(
            SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
                &selected,
                &fixture.network,
                CHAIN,
            )
            .is_ok()
        );
    }
}
