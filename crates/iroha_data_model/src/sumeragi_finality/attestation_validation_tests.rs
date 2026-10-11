//! One-statement epoch reuse preserves every attestation proof and cumulative decoder gate.

use super::{tests::Fixture, *};
use crate::{block::CommitCertificate, sumeragi::epoch::validation_counts};
use norito::core::DecodeBudgetContext;

const TEST_ALLOCATION_CEILING: usize = 64 * 1024 * 1024;

fn body(fixture: &Fixture) -> SumeragiFinalityAttestationBody {
    let node_id = PeerId::new(fixture.keys[0].public_key().clone());
    SumeragiFinalityAttestationBody {
        observed_at_unix_ms: 1_000_000,
        challenge: [7; 32],
        network_id: fixture.network,
        node_fingerprint: Hash::new(node_id.encode()),
        node_id,
        build_fingerprint: Hash::new(b"compiled build"),
        config_fingerprint: Hash::new(b"effective config"),
        genesis_block_hash: fixture.genesis.hash(),
        genesis_finality_proof: fixture.first.clone(),
        status: SumeragiStatus {
            protocol_version: crate::sumeragi::PROTOCOL_VERSION,
            config_fingerprint: Hash::new(b"effective config"),
            beacon_horizon: None,
            instance: fixture.verifier().instance().0,
            height: 3,
            view: 0,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 100,
            committed_height: 2,
            applied_height: 2,
            awaiting: false,
            signer: Some(fixture.keys[0].public_key().clone()),
            unanchored: false,
            abstaining: false,
            halted: None,
            footprint: crate::sumeragi::SumeragiFootprint::default(),
        },
        finality_proof: fixture.second.clone(),
    }
}

// The original recipe calls the same complete native proof decoder twice. It preserves
// the exact duplicate-binding and error order without implementing another proof verifier.
fn independent(body: &SumeragiFinalityAttestationBody) -> Result<(), FinalityError> {
    need(
        body.challenge != [0; 32]
            && body.observed_at_unix_ms != 0
            && body.node_fingerprint == Hash::new(body.node_id.encode())
            && body.node_id.public_key().algorithm() == Algorithm::BlsNormal
            && body.network_id == NetworkId::from_genesis_hash(body.genesis_block_hash)
            && body.genesis_finality_proof.height() == 1
            && body.genesis_finality_proof.block_header.hash() == body.genesis_block_hash
            && body.status.protocol_version == crate::sumeragi::PROTOCOL_VERSION
            && body.status.halted.is_none()
            && body
                .status
                .signer
                .as_ref()
                .is_none_or(|key| key == body.node_id.public_key())
            && body.status.committed_height == body.finality_proof.height()
            && body.status.applied_height == body.status.committed_height,
        "attestation challenge, identity or durable-tip binding differs",
    )?;
    let genesis = body.genesis_finality_proof.decode_checked()?;
    let tip = body.finality_proof.decode_checked()?;
    if let Some(header) = tip.header.as_ref() {
        need(
            header.instance.0 == body.status.instance,
            "attestation status instance differs",
        )?;
    } else {
        need(
            tip.core_hash == genesis.core_hash
                && tip.result == genesis.result
                && tip.commitment == genesis.commitment,
            "height-one attestation carries different genesis execution",
        )?;
    }
    Ok(())
}

fn signed(fixture: &Fixture, body: SumeragiFinalityAttestationBody) -> SumeragiFinalityAttestation {
    SumeragiFinalityAttestation {
        signature: SignatureOf::try_from_hash(fixture.keys[0].private_key(), body.signing_hash())
            .unwrap(),
        body,
    }
}

fn replace_result(proof: &mut SumeragiFinalityProof, result: &ExecutionResultCommitment) {
    let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let qc = certificate.commit_qc().to_vec();
    let availability = certificate.availability().to_vec();
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        qc,
        result.preimage().unwrap(),
        availability,
    )));
    proof.block_wire = block.encode_wire().unwrap();
}

fn corrupt_qc(proof: &mut SumeragiFinalityProof) {
    let mut block = decode_framed_signed_block(&proof.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    qc.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&qc).unwrap(),
        result,
        availability,
    )));
    proof.block_wire = block.encode_wire().unwrap();
}

#[test]
fn attestation_epoch_work_is_one_statement_and_preserves_signed_bytes() {
    let fixture = Fixture::new();
    let body = body(&fixture);
    let before = validation_counts::calls();
    independent(&body).unwrap();
    let original_count = validation_counts::calls() - before;
    assert!(original_count > 1);
    let attestation = signed(&fixture, body);
    let wire = norito::encode_canonical(&attestation).unwrap();
    assert!(!norito::core::decode_limits_active());
    for _ in 0..2 {
        let before = validation_counts::calls();
        attestation.verify().unwrap();
        assert_eq!(validation_counts::calls() - before, 1);
        assert_eq!(norito::encode_canonical(&attestation).unwrap(), wire);
    }
    // Neither the returned statement nor an earlier successful call retains the workspace.
    let before = validation_counts::calls();
    independent(&attestation.body).unwrap();
    assert_eq!(validation_counts::calls() - before, original_count);
    let mut changed_signature = attestation.clone();
    changed_signature.body.build_fingerprint = Hash::new(b"another executable");
    changed_signature.body.validate_consistency().unwrap();
    assert!(changed_signature.verify().is_err());

    let mut genesis_only = attestation.body.clone();
    genesis_only.finality_proof = fixture.first.clone();
    genesis_only.status.committed_height = 1;
    genesis_only.status.applied_height = 1;
    assert_eq!(
        genesis_only.validate_consistency(),
        independent(&genesis_only)
    );
    signed(&fixture, genesis_only.clone()).verify().unwrap();
    let mut different_genesis = genesis_only;
    let mut result = fixture.first.decode_checked().unwrap().commitment;
    result.execution.parent_state_root = Hash::new(b"different genesis parent state");
    replace_result(&mut different_genesis.finality_proof, &result);
    let expected = independent(&different_genesis).unwrap_err();
    assert_eq!(
        different_genesis.validate_consistency().unwrap_err(),
        expected
    );
    assert_eq!(
        signed(&fixture, different_genesis).verify().unwrap_err(),
        expected
    );
    let mut alternate = attestation.body;
    alternate.finality_proof = fixture.alternate();
    assert_eq!(alternate.validate_consistency(), independent(&alternate));
    signed(&fixture, alternate).verify().unwrap();
}

#[test]
fn attestation_rechecks_every_proof_and_preserves_first_error_order() {
    let fixture = Fixture::new();
    let original = body(&fixture);
    original.validate_consistency().unwrap();
    for mutation in 0..9 {
        let mut changed = original.clone();
        match mutation {
            0 => changed.genesis_finality_proof.block_wire.push(0),
            1 => changed.genesis_finality_proof.committee[0].proof_of_possession[0] ^= 1,
            2 => changed.finality_proof.block_wire.push(0),
            3 => changed.finality_proof.committee[0].proof_of_possession[0] ^= 1,
            4 => corrupt_qc(&mut changed.finality_proof),
            5 => changed.status.instance[0] ^= 1,
            6 => changed.status.applied_height += 1,
            7 => changed.challenge = [0; 32],
            _ => changed.status.protocol_version = 0,
        }
        let bytes = norito::encode_canonical(&changed).unwrap();
        let expected = independent(&changed).unwrap_err();
        assert_eq!(
            changed.validate_consistency().unwrap_err(),
            expected,
            "mutation {mutation}"
        );
        assert_eq!(
            signed(&fixture, changed.clone()).verify().unwrap_err(),
            expected
        );
        assert_eq!(norito::encode_canonical(&changed).unwrap(), bytes);
        original.validate_consistency().unwrap();
    }
    let mut both = original.clone();
    both.genesis_finality_proof.block_wire.push(0);
    corrupt_qc(&mut both.finality_proof);
    let genesis_error = both.genesis_finality_proof.decode_checked().unwrap_err();
    assert_ne!(
        genesis_error,
        both.finality_proof.decode_checked().unwrap_err()
    );
    assert_eq!(both.validate_consistency().unwrap_err(), genesis_error);
    both.challenge = [0; 32];
    let binding_error = independent(&both).unwrap_err();
    assert_ne!(binding_error, genesis_error);
    assert_eq!(both.validate_consistency().unwrap_err(), binding_error);
}

#[test]
fn attestation_epoch_reuse_requires_complete_context_and_current_certificate() {
    let fixture = Fixture::new();
    let original = body(&fixture);
    let result = fixture.second.decode_checked().unwrap().commitment;
    original.validate_consistency().unwrap();
    for mutation in 0..4 {
        let mut changed_result = result.clone();
        let current = &mut changed_result.schedule.current;
        match mutation {
            0 => current.leader_seed[0] ^= 1,
            1 => current.authorization.epoch += 1,
            2 => current.authorization.authority_generation += 1,
            _ => current.committee[0].proof_of_possession[0] ^= 1,
        }
        for slot in [
            &mut changed_result.schedule.next,
            &mut changed_result.schedule.after_next,
        ] {
            let ScheduledSlot::Ready(selected) = slot else {
                panic!("fixture has ordinary ready successors");
            };
            selected.epoch = current.clone();
        }
        if mutation == 0 {
            assert_eq!(
                current.authorization.epoch,
                result.schedule.current.authorization.epoch
            );
        }
        let mut changed = original.clone();
        replace_result(&mut changed.finality_proof, &changed_result);
        let expected = independent(&changed).unwrap_err();
        let before = validation_counts::calls();
        assert_eq!(
            changed.validate_consistency().unwrap_err(),
            expected,
            "mutation {mutation}"
        );
        if mutation == 0 {
            assert_eq!(validation_counts::calls() - before, 2);
        }
        // A new node signature cannot authenticate a changed native certificate or context.
        assert_eq!(signed(&fixture, changed).verify().unwrap_err(), expected);
        original.validate_consistency().unwrap();
    }
}

fn under_caller(
    allocation: usize,
    operation: impl FnOnce() -> Result<(), FinalityError>,
) -> (Result<(), FinalityError>, u64, usize) {
    let limits = norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        allocation,
        64,
    );
    let budget = DecodeBudgetContext::new(limits);
    let before = validation_counts::calls();
    let result = budget.with(operation);
    (
        result,
        budget.consumed_allocated_bytes(),
        validation_counts::calls() - before,
    )
}

#[test]
fn active_attestation_keeps_both_original_decodes_charges_and_refusals() {
    let fixture = Fixture::new();
    let body = body(&fixture);
    // Warm the inactive entry first; the later caller still owns two original decodes.
    body.validate_consistency().unwrap();
    let expected = under_caller(TEST_ALLOCATION_CEILING, || independent(&body));
    assert!(expected.0.is_ok());
    assert!(expected.1 > 1);
    assert!(expected.2 > 1);
    assert_eq!(
        under_caller(TEST_ALLOCATION_CEILING, || body.validate_consistency()),
        expected
    );
    let charge = usize::try_from(expected.1).unwrap();
    assert!(charge < TEST_ALLOCATION_CEILING);
    for cap in [1, charge / 2, charge - 1, charge] {
        let expected = under_caller(cap, || independent(&body));
        if cap == 1 {
            assert!(
                expected.0.is_err(),
                "mandatory canonical decode must refuse"
            );
        }
        assert_eq!(
            under_caller(cap, || body.validate_consistency()),
            expected,
            "cap {cap}"
        );
    }
    let mut changed = body.clone();
    corrupt_qc(&mut changed.finality_proof);
    for cap in [1, charge, TEST_ALLOCATION_CEILING] {
        assert_eq!(
            under_caller(cap, || changed.validate_consistency()),
            under_caller(cap, || independent(&changed))
        );
    }
    assert!(!norito::core::decode_limits_active());
    let before = validation_counts::calls();
    body.validate_consistency().unwrap();
    assert_eq!(validation_counts::calls() - before, 1);
}
