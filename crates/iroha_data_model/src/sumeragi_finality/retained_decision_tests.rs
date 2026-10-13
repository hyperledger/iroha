//! Retained decision equality borrows checked proofs while preserving complete witness checks.

use super::{tests::Fixture, *};
use crate::consensus::{
    FinalizedGlobalThresholdBeaconPulseV1, GLOBAL_THRESHOLD_BEACON_VERSION_V1,
    GlobalThresholdBeaconChainAnchorV1, GlobalThresholdBeaconPulseContextV1,
};

#[test]
fn decision_window_preserves_lagging_witness_across_pruning() {
    let mut fixture = test_fixtures::NativeFinalityFixture::start("retained-window");
    let mut verifier = fixture.verifier();
    let mut proofs = vec![fixture.genesis_proof().clone()];
    while fixture.latest().height() < 8 {
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let proof = fixture.certify(block);
        verifier.verify(&proof).unwrap();
        if proof.height().is_multiple_of(4) {
            verifier.retain_recent_decisions(5);
            assert!(verifier.decisions.len() <= 5);
        }
        proofs.push(proof);
    }

    // A five-decision window at H8 must retain H4, the parent of the H5 witness.
    verifier.verify_retained_decision(&proofs[4]).unwrap();
    assert_eq!(
        verifier.decisions.keys().copied().collect::<Vec<_>>(),
        vec![4, 5, 6, 7, 8]
    );
    assert_eq!(
        verifier.verify_retained_decision(&proofs[3]).unwrap_err(),
        FinalityError("authenticated parent is missing".into())
    );
    assert_eq!(
        verifier.verify_retained_decision(&proofs[2]).unwrap_err(),
        FinalityError("decision is outside authenticated prefix".into())
    );

    let checkpoint = verifier.export_checkpoint(fixture.latest()).unwrap();
    assert_eq!(
        checkpoint.encode_canonical().unwrap(),
        fixture.checkpoint().encode_canonical().unwrap()
    );
    // The canonical restart context is still three decisions, not the runtime window.
    let compact = SumeragiFinalityVerifier::from_trusted_checkpoint(
        &checkpoint,
        &fixture.network_id(),
        fixture.chain_id(),
    )
    .unwrap();
    assert_eq!(compact.decisions.len(), 3);
    assert_eq!(
        compact.verify_retained_decision(&proofs[4]).unwrap_err(),
        FinalityError("decision is outside authenticated prefix".into())
    );

    // Increasing the requested window cannot recover a discarded parent or decision.
    verifier.retain_recent_decisions(usize::MAX);
    assert_eq!(verifier.decisions.len(), 5);
    assert!(verifier.verify_retained_decision(&proofs[3]).is_err());
    assert!(verifier.verify_retained_decision(&proofs[2]).is_err());
    assert!(verifier.verify(fixture.latest()).is_err());
    let block = fixture.block_with_submitted_work(fixture.next_header());
    let next = fixture.certify(block);
    verifier.verify(&next).unwrap();
    assert_eq!(
        verifier.decisions.len(),
        6,
        "pruning is explicitly requested"
    );
    verifier.retain_recent_decisions(5);
    assert_eq!(verifier.decisions.len(), 5);
    verifier.verify_retained_decision(&proofs[5]).unwrap();
    assert!(verifier.verify_retained_decision(&proofs[4]).is_err());
}

#[test]
fn decision_window_preserves_genesis_and_checkpoint_floor() {
    let mut fixture = test_fixtures::NativeFinalityFixture::start("retained-floor");
    let mut verifier = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        fixture.genesis_proof().committee.clone(),
    )
    .unwrap();
    verifier.retain_recent_decisions(0);
    assert!(verifier.decisions.is_empty());
    verifier.verify(fixture.genesis_proof()).unwrap();

    loop {
        let tip = fixture.latest();
        let original = verifier
            .export_checkpoint(tip)
            .unwrap()
            .encode_canonical()
            .unwrap();
        for count in 0..=3 {
            verifier.retain_recent_decisions(count);
            assert_eq!(verifier.decisions.len(), tip.height().min(3) as usize);
            assert_eq!(verifier.genesis.hash(), fixture.genesis().hash());
            assert_eq!(verifier.chain_id(), fixture.chain_id());
            assert_eq!(verifier.instance(), fixture.verifier().instance());
            assert_eq!(verifier.initial_epoch(), fixture.verifier().initial_epoch());
            assert_eq!(verifier.root_scope(), fixture.verifier().root_scope());
            assert_eq!(
                verifier
                    .export_checkpoint(tip)
                    .unwrap()
                    .encode_canonical()
                    .unwrap(),
                original
            );
        }
        if tip.height() == 4 {
            let checkpoint = SumeragiFinalityCheckpoint::decode_canonical(&original).unwrap();
            verifier = SumeragiFinalityVerifier::from_trusted_checkpoint(
                &checkpoint,
                &fixture.network_id(),
                fixture.chain_id(),
            )
            .unwrap();
            let block = fixture.block_with_submitted_work(fixture.next_header());
            let next = fixture.certify(block);
            verifier.verify(&next).unwrap();
            verifier.retain_recent_decisions(0);
            assert_eq!(
                verifier.export_checkpoint(&next).unwrap(),
                fixture.checkpoint()
            );
            break;
        }
        let block = fixture.block_with_submitted_work(fixture.next_header());
        let next = fixture.certify(block);
        verifier.verify(&next).unwrap();
    }
}

// As in the existing certified-beacon tests, the nonzero G1 point isolates public pulse shape.
// Only the genuine native CommitQC authenticates this synthetic execution result; this fixture
// neither executes World nor claims threshold-beacon verification or deployment authority.
fn proof_with_certified_beacon(fixture: &Fixture) -> SumeragiFinalityProof {
    let mut proof = fixture.second.clone();
    let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let availability = certificate.availability().to_vec();
    let native_header: CoreHeader = norito::decode_canonical(&header).unwrap();
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    let (original_x, mut value) = CertifiedResultV1::decode(
        certificate.result_preimage(),
        CertifiedResultScope::TairaGlobal,
    )
    .unwrap()
    .into_parts();
    let (_, signature) = fixture.keys[0].public_key().try_to_bytes().unwrap();
    let mut pulse = FinalizedGlobalThresholdBeaconPulseV1 {
        version: GLOBAL_THRESHOLD_BEACON_VERSION_V1,
        network_id: fixture.network,
        session_id: [1; 32],
        roster_hash: [2; 32],
        transcript_hash: [3; 32],
        context: GlobalThresholdBeaconPulseContextV1 {
            instance: native_header.instance.0,
            epoch: value.schedule.current.authorization.epoch,
            epoch_context_id: native_header.epoch.context.0,
            parent_consensus_hash: native_header.parent_hash.0,
            parent_result: native_header.parent_result.0,
        },
        height: proof.height(),
        round: 0,
        finalized_chain_anchor: GlobalThresholdBeaconChainAnchorV1 {
            height: fixture.first.height(),
            block_hash: fixture.first.block_header.hash(),
        },
        signature: signature.try_into().unwrap(),
        seed: [4; 32],
        pulse_id: [0; 32],
    };
    pulse.pulse_id = global_threshold_beacon_pulse_id_v1(&pulse, pulse.seed);
    value.beacon = Some(pulse);
    value.validate().unwrap();
    let value = CertifiedResultV1::from_parts_unvalidated(original_x, value);
    qc.result = value.result().unwrap();
    super::tests::sign_qc(&mut qc, &fixture.keys, &[0, 1, 2]);
    block.set_commit_certificate(Some(crate::block::CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&qc).unwrap(),
        value.preimage().unwrap(),
        availability,
    )));
    proof.block_wire = block.encode_wire().unwrap();
    proof
}

fn retained_prefix(fixture: &Fixture, proof: &SumeragiFinalityProof) -> SumeragiFinalityVerifier {
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(proof).unwrap();
    verifier
}

fn assert_same_execution(verifier: &SumeragiFinalityVerifier, proof: &SumeragiFinalityProof) {
    let expected = verifier.verify_retained_decision(proof).unwrap();
    let same = verifier.verify_same_decision(proof, proof).unwrap();
    assert_eq!(same.header(), expected.header());
    assert_eq!(same.core_hash(), expected.core_hash());
    assert_eq!(same.result(), expected.result());
    assert_eq!(same.commitment(), expected.commitment());
    assert_eq!(
        same.canonical_executed_wire().unwrap(),
        expected.canonical_executed_wire().unwrap()
    );
}

#[test]
fn retained_decision_borrowed_comparison_rejects_each_changed_authenticated_field() {
    let fixture = Fixture::new();
    let proof = proof_with_certified_beacon(&fixture);
    let verifier = retained_prefix(&fixture, &proof);
    let original = verifier.export_checkpoint(&proof).unwrap();
    let source = norito::encode_canonical(&proof).unwrap();
    assert_same_execution(&verifier, &proof);

    for field in [
        "block_hash",
        "core_hash",
        "result",
        "committee_digest",
        "schedule",
        "beacon",
        "executed_hash",
        "executed_len",
    ] {
        // Only this independent test-owned expected H2 decision changes. Its original parent,
        // offered canonical frame, all original PoPs, native QC and signed RS16 table stay exact.
        let mut selected = verifier.clone();
        let expected = selected.decisions.get_mut(&proof.height()).unwrap();
        match field {
            "block_hash" => {
                expected.block_hash = HashOf::from_untyped_unchecked(Hash::new(b"different block"));
            }
            "core_hash" => expected.core_hash.0[0] ^= 1,
            "result" => expected.result.0[0] ^= 1,
            "committee_digest" => expected.committee_digest[0] ^= 1,
            "schedule" => expected.schedule.height += 1,
            "beacon" => {
                assert!(expected.beacon.is_some());
                expected.beacon = None;
            }
            "executed_hash" => expected.executed_hash = Hash::new(b"different executed wire"),
            "executed_len" => expected.executed_len += 1,
            _ => unreachable!(),
        }
        // This exact error proves the authentic candidate passed complete check(), then failed
        // its selected retained decision rather than an unrelated parser or parent check.
        let rejected = FinalityError("proof differs from retained authenticated decision".into());
        assert_eq!(
            selected
                .verify_retained_decision(&proof)
                .map_err(invalid_read_error)
                .unwrap_err(),
            rejected,
            "{field}"
        );
        assert_eq!(
            selected
                .verify_same_decision(&proof, &proof)
                .map_err(invalid_read_error)
                .unwrap_err(),
            rejected,
            "same witness: {field}"
        );
        assert_eq!(norito::encode_canonical(&proof).unwrap(), source, "{field}");
        assert_eq!(
            verifier.export_checkpoint(&proof).unwrap(),
            original,
            "{field}"
        );
        assert_same_execution(&verifier, &proof);
    }

    let empty = fixture.verifier();
    let outside = FinalityError("decision is outside authenticated prefix".into());
    assert_eq!(
        empty
            .verify_retained_decision(&proof)
            .map_err(invalid_read_error)
            .unwrap_err(),
        outside
    );
    assert_eq!(
        empty
            .verify_same_decision(&proof, &proof)
            .map_err(invalid_read_error)
            .unwrap_err(),
        outside
    );
    assert_eq!(norito::encode_canonical(&proof).unwrap(), source);
    assert_eq!(verifier.export_checkpoint(&proof).unwrap(), original);
}

#[test]
fn retained_decision_same_witness_rechecks_actual_native_signature() {
    let fixture = Fixture::new();
    let proof = &fixture.second;
    let verifier = retained_prefix(&fixture, proof);
    let original = verifier.export_checkpoint(proof).unwrap();
    let source = norito::encode_canonical(proof).unwrap();
    let mut bad = proof.clone();
    let mut block = decode_framed_signed_block(&bad.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    qc.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(crate::block::CommitCertificate::from_untrusted_parts(
        header.clone(),
        norito::encode_canonical(&qc).unwrap(),
        result.clone(),
        availability.clone(),
    )));
    let changed = block.commit_certificate().unwrap();
    assert_eq!(changed.consensus_header(), header);
    assert_eq!(changed.result_preimage(), result);
    assert_eq!(changed.availability(), availability);
    bad.block_wire = block.encode_wire().unwrap();
    assert_eq!(bad.block_header, proof.block_header);
    assert_ne!(bad.block_wire, proof.block_wire);

    let expected = verifier
        .check(&bad)
        .map_err(invalid_read_error)
        .unwrap_err();
    assert!(expected.0.starts_with("commit certificate:"), "{expected}");
    assert_eq!(
        verifier
            .verify_retained_decision(&bad)
            .map_err(invalid_read_error)
            .unwrap_err(),
        expected
    );
    assert_eq!(
        verifier
            .verify_same_decision(&bad, &bad)
            .map_err(invalid_read_error)
            .unwrap_err(),
        expected
    );
    assert_eq!(
        verifier
            .verify_same_decision(proof, &bad)
            .map_err(invalid_read_error)
            .unwrap_err(),
        expected
    );
    assert_eq!(
        verifier
            .verify_same_decision(&bad, proof)
            .map_err(invalid_read_error)
            .unwrap_err(),
        expected
    );
    assert_eq!(norito::encode_canonical(proof).unwrap(), source);
    assert_eq!(verifier.export_checkpoint(proof).unwrap(), original);
    assert_same_execution(&verifier, proof);
}

#[test]
fn retained_decision_preserves_original_decoder_refusal_and_same_proof_retry() {
    let fixture = Fixture::new();
    let proof = &fixture.second;
    let verifier = retained_prefix(&fixture, proof);
    let original = verifier.export_checkpoint(proof).unwrap();
    let source = norito::encode_canonical(proof).unwrap();
    let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64);
    let producer = norito::with_decode_limits_scope(limits, || {
        norito::with_decode_limits_scope(
            norito::canonical_decode_limits(proof.block_wire.len()),
            || decode_framed_signed_block(&proof.block_wire),
        )
    })
    .unwrap_err();
    assert_eq!(
        producer.kind(),
        norito::core::DecodeAttemptErrorKind::EnclosingLimit
    );
    let kind = producer.kind();
    let resource = producer.into_error().decode_resource_error().unwrap();
    assert!(matches!(
        resource,
        norito::core::DecodeResourceError::TotalAllocationExceeded { attempted, limit: 0 }
            if attempted > 0
    ));
    let expected = ReadErrorObservation::Resource(kind, resource);
    assert_eq!(
        norito::with_decode_limits_scope(limits, || verifier.verify_retained_decision(proof))
            .map_err(observe_read_error)
            .unwrap_err(),
        expected
    );
    assert_eq!(
        norito::with_decode_limits_scope(limits, || verifier.verify_same_decision(proof, proof))
            .map_err(observe_read_error)
            .unwrap_err(),
        expected
    );
    assert_eq!(norito::encode_canonical(proof).unwrap(), source);
    assert_eq!(verifier.export_checkpoint(proof).unwrap(), original);
    assert_same_execution(&verifier, proof);
}

#[test]
fn borrowed_trusted_check_keeps_authentic_parent_refusal_before_retained_comparison() {
    let fixture = Fixture::new();
    let proof = &fixture.second;
    // The same original canonical H2, exact BLS quorum and signed RS16 source remain intact.
    // Only independent test-owned selected parent commitments below are changed or removed.
    let source = norito::encode_canonical(proof).unwrap();
    proof
        .decode_checked(CertifiedResultScope::TairaGlobal)
        .unwrap();
    let retained = retained_prefix(&fixture, proof);
    let original = retained.export_checkpoint(proof).unwrap();
    let mut ordinary = fixture.verifier();
    ordinary.verify(&fixture.first).unwrap();
    let original_parent = ordinary.export_checkpoint(&fixture.first).unwrap();
    let original_result = ordinary.decisions.get(&1).unwrap().result;
    let wrong_result = Hash32([0xA5; 32]);
    assert_ne!(original_result, wrong_result);
    let parent_binding = FinalityError(
        "proof breaks authenticated instance, parent/result or authenticated epoch binding".into(),
    );

    let mut selected = retained.clone();
    selected.decisions.get_mut(&1).unwrap().result = wrong_result;
    ordinary.decisions.get_mut(&1).unwrap().result = wrong_result;
    assert_eq!(
        ordinary
            .verify(proof)
            .map_err(invalid_read_error)
            .unwrap_err(),
        parent_binding
    );
    assert_eq!(
        selected
            .verify_retained_decision(proof)
            .map_err(invalid_read_error)
            .unwrap_err(),
        parent_binding
    );
    assert_eq!(ordinary.decisions.len(), 1, "refusal cannot insert H2");
    assert_eq!(selected.decisions.len(), 2);
    assert_eq!(ordinary.decisions.get(&1).unwrap().result, wrong_result);
    assert_eq!(selected.decisions.get(&1).unwrap().result, wrong_result);
    assert_eq!(norito::encode_canonical(proof).unwrap(), source);
    // Correct only the independently selected parent, then retry the same unchanged witness.
    ordinary.decisions.get_mut(&1).unwrap().result = original_result;
    selected.decisions.get_mut(&1).unwrap().result = original_result;
    assert_eq!(
        ordinary.export_checkpoint(&fixture.first).unwrap(),
        original_parent
    );
    assert_eq!(selected.export_checkpoint(proof).unwrap(), original);
    let admitted = ordinary.verify(proof).unwrap();
    let retained_tip = selected.verify_retained_decision(proof).unwrap();
    assert_eq!(admitted.commitment(), retained_tip.commitment());
    assert_eq!(admitted.block().encode_wire().unwrap(), proof.block_wire);
    let executed = admitted.canonical_executed_wire().unwrap();
    assert_ne!(
        executed, proof.block_wire,
        "the certificate is excluded from executed identity"
    );
    assert_eq!(
        Hash::new(&executed),
        admitted.commitment().execution.executed_block_wire_hash,
    );
    assert_eq!(
        u64::try_from(executed.len()).unwrap(),
        admitted.commitment().execution.executed_block_wire_len,
    );
    assert_eq!(executed, retained_tip.canonical_executed_wire().unwrap());
    assert_eq!(ordinary.export_checkpoint(proof).unwrap(), original);

    let mut selected = retained.clone();
    let parent = selected.decisions.remove(&1).unwrap();
    assert_eq!(
        selected
            .verify_retained_decision(proof)
            .map_err(invalid_read_error)
            .unwrap_err(),
        FinalityError("authenticated parent is missing".into()),
    );
    assert_eq!(selected.decisions.len(), 1);
    assert!(selected.decisions.insert(1, parent).is_none());
    assert_eq!(selected.export_checkpoint(proof).unwrap(), original);
    assert_same_execution(&selected, proof);

    // The early selected-decision gate must still win over decoding malformed offered bytes.
    let mut malformed = proof.clone();
    malformed.block_wire.clear();
    let empty = fixture.verifier();
    assert_eq!(
        empty
            .verify_retained_decision(&malformed)
            .map_err(invalid_read_error)
            .unwrap_err(),
        FinalityError("decision is outside authenticated prefix".into()),
    );
    assert_eq!(norito::encode_canonical(proof).unwrap(), source);
    assert_eq!(retained.export_checkpoint(proof).unwrap(), original);
}
