//! Single-pass checkpoint production preserves native authority and enclosing admission.

use super::super::tests::{Fixture, author_payload, sign_qc};
use super::*;
use crate::{block::CommitCertificate, sumeragi::epoch::validation_counts};
use norito::core::DecodeBudgetContext;

const CHAIN: &str = "portable-finality-test";
const TEST_ALLOCATION_CEILING: usize = 64 * 1024 * 1024;

fn parent(fixture: &Fixture) -> SumeragiFinalityVerifier {
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier
}

// Exact previous caller recipe, using the same complete native producers independently.
fn independent_advance(
    mut verifier: SumeragiFinalityVerifier,
    tip: &SumeragiFinalityProof,
) -> Result<(SumeragiFinalityCheckpoint, VerifiedSumeragiBlock), SumeragiCheckpointAdvanceError> {
    drop(
        verifier
            .verify(tip)
            .map_err(SumeragiCheckpointAdvanceError::Verify)?,
    );
    verifier
        .export_checkpoint_with_tip(tip)
        .map_err(SumeragiCheckpointAdvanceError::Export)
}

#[test]
fn advance_keeps_exact_original_and_alternate_witness_with_canonical_roundtrip() {
    let fixture = Fixture::new();
    let alternate = fixture.alternate();
    for tip in [&fixture.first, &fixture.second, &alternate] {
        let verifier = if tip.height() == 1 {
            fixture.verifier()
        } else {
            parent(&fixture)
        };
        let original = norito::encode_canonical(tip).unwrap();
        let (expected, expected_tip) = independent_advance(verifier.clone(), tip).unwrap();
        let (actual, actual_tip) = verifier.advance_checkpoint_with_tip(tip).unwrap();
        assert_eq!(actual, expected);
        let bytes = actual.encode_canonical().unwrap();
        assert_eq!(bytes, expected.encode_canonical().unwrap());
        assert_eq!(
            SumeragiFinalityCheckpoint::decode_canonical(&bytes).unwrap(),
            actual
        );
        assert_eq!(actual.tip(), tip);
        assert_eq!(actual_tip.block().encode_wire().unwrap(), tip.block_wire);
        assert_eq!(actual_tip.context_id(), expected_tip.context_id());
        assert_eq!(actual_tip.root_scope(), expected_tip.root_scope());
        let (_, restored_tip) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &actual,
            &fixture.network,
            CHAIN,
        )
        .unwrap();
        assert_eq!(restored_tip.context_id(), actual_tip.context_id());
        assert_eq!(restored_tip.block().encode_wire().unwrap(), tip.block_wire);
        assert_eq!(norito::encode_canonical(tip).unwrap(), original);
    }
}

#[test]
fn advance_keeps_private_root_and_bounded_three_decision_restart_context() {
    use crate::block::consensus::SumeragiRootScope;
    use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let network = Fixture::new().network;
    for scope in [
        SumeragiRootScope::Global,
        SumeragiRootScope::Dataspace {
            parent_network_id: network,
            dataspace_id: iroha_model_base::topology::DataSpaceId::new(u64::MAX - 14),
        },
    ] {
        let mut native = NativeFinalityFixture::start_with_scope("checkpoint-advance-scope", scope);
        for height in 2..=4 {
            let before = native.verifier();
            let block = native.block_with_submitted_work(native.next_header());
            let tip = native.certify(block);
            let (expected, _) = independent_advance(before.clone(), &tip).unwrap();
            let (checkpoint, verified) = before.advance_checkpoint_with_tip(&tip).unwrap();
            assert_eq!(checkpoint, expected);
            assert_eq!(checkpoint.decisions.len(), height.min(3));
            assert_eq!(verified.root_scope(), scope);
            let (restored, retained) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
                &checkpoint,
                &native.network_id(),
                native.chain_id(),
            )
            .unwrap();
            assert_eq!(restored.root_scope(), scope);
            assert_eq!(retained.block().encode_wire().unwrap(), tip.block_wire);
            assert_eq!(retained.context_id(), verified.context_id());
        }
    }
}

fn observe_stage(error: SumeragiCheckpointAdvanceError) -> (bool, ReadErrorObservation) {
    match error {
        SumeragiCheckpointAdvanceError::Verify(original) => (false, observe_read_error(original)),
        SumeragiCheckpointAdvanceError::Export(original) => (true, observe_read_error(original)),
    }
}

fn assert_invalid_parity(
    verifier: SumeragiFinalityVerifier,
    tip: &SumeragiFinalityProof,
    export: bool,
) {
    let original = norito::encode_canonical(tip).unwrap();
    let expected = observe_stage(independent_advance(verifier.clone(), tip).unwrap_err());
    assert_eq!(expected.0, export);
    assert!(matches!(expected.1, ReadErrorObservation::Invalid(_)));
    assert_eq!(
        observe_stage(verifier.advance_checkpoint_with_tip(tip).unwrap_err()),
        expected
    );
    assert_eq!(norito::encode_canonical(tip).unwrap(), original);
}

#[test]
fn advance_rejects_native_quorum_result_roster_parent_and_availability_mutations() {
    let fixture = Fixture::new();
    let verifier = parent(&fixture);
    for mutation in 0..9 {
        let mut bad = fixture.second.clone();
        let mut block = decode_framed_signed_block(&bad.block_wire).unwrap();
        let certificate = block.commit_certificate().unwrap();
        let mut consensus_header = certificate.consensus_header().to_vec();
        let mut result_preimage = certificate.result_preimage().to_vec();
        let mut availability = certificate.availability().to_vec();
        let mut qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
        match mutation {
            0 => qc.agg_sig.0[0] ^= 1,
            1 => qc.result = Hash32([9; 32]),
            2 => bad.committee[0].proof_of_possession[0] ^= 1,
            3 => {
                // Re-sign a genuinely authored availability/QC witness with the wrong parent
                // result. The failure must come from the selected native prefix binding.
                let mut header: CoreHeader = norito::decode_canonical(&consensus_header).unwrap();
                header.parent_result = Hash32([9; 32]);
                let epoch = verifier.initial_epoch();
                let payload = block
                    .canonical_resultless_proposal()
                    .unwrap()
                    .encode_wire()
                    .unwrap();
                let authored = author_payload(header, &payload, epoch, &fixture.keys);
                let header = authored.body.header();
                availability = norito::encode_canonical(authored.body.availability()).unwrap();
                let (crypto, _) = ProofCrypto::new(&fixture.validators).unwrap();
                qc.block_hash = header.hash(&crypto);
                sign_qc(&mut qc, &fixture.keys, &[0, 1, 2]);
                consensus_header = norito::encode_canonical(header).unwrap();
            }
            4 => sign_qc(&mut qc, &fixture.keys, &[0, 1]),
            5 => result_preimage.push(0),
            6 => availability.clear(),
            7 => *availability.last_mut().unwrap() ^= 1,
            _ => sign_qc(&mut qc, &fixture.keys, &[0, 1, 2, 3]),
        }
        block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
            consensus_header,
            norito::encode_canonical(&qc).unwrap(),
            result_preimage,
            availability,
        )));
        bad.block_wire = block.encode_wire().unwrap();
        assert_invalid_parity(verifier.clone(), &bad, false);
    }
    let mut trailing = fixture.second.clone();
    trailing.block_wire.push(0);
    assert_invalid_parity(verifier.clone(), &trailing, false);
    assert_invalid_parity(verifier, &fixture.first, false);
    assert_invalid_parity(fixture.verifier(), &fixture.second, false);
}

#[test]
fn advance_retains_parent_schedule_and_export_bounds_failure_stages() {
    let fixture = Fixture::new();
    let verifier = parent(&fixture);
    for mutation in 0..5 {
        let mut changed = verifier.clone();
        let retained = changed.decisions.get_mut(&1).unwrap();
        match mutation {
            0 => retained.block_hash = HashOf::from_untyped_unchecked(Hash::new(b"changed parent")),
            1 => retained.core_hash.0[0] ^= 1,
            2 => retained.result.0[0] ^= 1,
            3 => retained.schedule.height += 1,
            _ => retained.schedule.current.committee[0].proof_of_possession[0] ^= 1,
        }
        assert_invalid_parity(changed, &fixture.second, false);
    }
    for mutation in 0..3 {
        let mut changed = verifier.clone();
        // These bound fields are not candidate native authority. The candidate fully verifies,
        // but no checkpoint or verified graph may escape the failing export.
        match mutation {
            0 => changed.chain_id.clear(),
            1 => changed.genesis_committee.clear(),
            _ => changed.decisions.get_mut(&1).unwrap().executed_len = 0,
        }
        assert_invalid_parity(changed, &fixture.second, true);
    }
}

fn under_caller(
    allocation: usize,
    operation: impl FnOnce() -> Result<
        (SumeragiFinalityCheckpoint, VerifiedSumeragiBlock),
        SumeragiCheckpointAdvanceError,
    >,
) -> (
    Result<SumeragiFinalityCheckpoint, (bool, ReadErrorObservation)>,
    u64,
    usize,
) {
    let budget = DecodeBudgetContext::new(norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        allocation,
        64,
    ));
    let before = validation_counts::calls();
    let result = budget
        .with(|| {
            let result = operation();
            if let Err(
                SumeragiCheckpointAdvanceError::Verify(FinalityReadError::DecodeResource(cause))
                | SumeragiCheckpointAdvanceError::Export(FinalityReadError::DecodeResource(cause)),
            ) = &result
            {
                if cause.kind() == norito::core::DecodeAttemptErrorKind::EnclosingLimit {
                    // The decoder observer has retired, while this cumulative budget
                    // remains installed. Retention must preserve its original identity;
                    // it must not mint authority in a new or absent observer.
                    assert!(!norito::core::decode_error_matches_active_limits(
                        cause.error()
                    ));
                    let retained = cause.local_refusal().expect("retain original refusal");
                    assert_eq!(
                        retained.kind(),
                        norito::core::DecodeLocalRefusalKind::EnclosingLimit
                    );
                    let norito::Error::ScopedDecodeResource(actual) = retained.into_error() else {
                        panic!("retained refusal must preserve opaque scope provenance");
                    };
                    let norito::Error::ScopedDecodeResource(expected) = cause.error() else {
                        panic!("enclosing refusal must contain opaque scope provenance");
                    };
                    assert_eq!(&actual, expected);
                }
            }
            result
        })
        .map(|(checkpoint, _)| checkpoint)
        .map_err(observe_stage);
    (
        result,
        budget.consumed_allocated_bytes(),
        validation_counts::calls() - before,
    )
}

#[test]
fn advance_under_active_owner_keeps_both_attempts_charges_and_refusal_stage() {
    let fixture = Fixture::new();
    let verifier = parent(&fixture);
    let tip = &fixture.second;
    let expected = under_caller(TEST_ALLOCATION_CEILING, || {
        independent_advance(verifier.clone(), tip)
    });
    assert!(expected.0.is_ok());
    let charge = usize::try_from(expected.1).unwrap();
    assert!(charge > 1 && charge < TEST_ALLOCATION_CEILING);
    assert_eq!(
        under_caller(TEST_ALLOCATION_CEILING, || verifier
            .clone()
            .advance_checkpoint_with_tip(tip)),
        expected
    );
    // The first pass alone succeeds at this exact allocation ceiling; the second decode must
    // still refuse in the Export stage. This distinguishes fallback from merely equal outputs.
    let first_budget = DecodeBudgetContext::new(norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        TEST_ALLOCATION_CEILING,
        64,
    ));
    first_budget.with(|| verifier.clone().verify(tip)).unwrap();
    let first_charge = usize::try_from(first_budget.consumed_allocated_bytes()).unwrap();
    assert!(first_charge > 0 && first_charge < charge);
    for cap in [1, first_charge, charge - 1, charge] {
        let expected = under_caller(cap, || independent_advance(verifier.clone(), tip));
        if cap == first_charge {
            assert!(matches!(
                expected.0,
                Err((true, ReadErrorObservation::Resource(_, _)))
            ));
        }
        assert_eq!(
            under_caller(cap, || verifier.clone().advance_checkpoint_with_tip(tip)),
            expected,
            "cap {cap}"
        );
    }
    let mut invalid = tip.clone();
    invalid.committee[0].proof_of_possession[0] ^= 1;
    for cap in [1, TEST_ALLOCATION_CEILING] {
        assert_eq!(
            under_caller(cap, || verifier
                .clone()
                .advance_checkpoint_with_tip(&invalid)),
            under_caller(cap, || independent_advance(verifier.clone(), &invalid)),
        );
    }
    assert!(!norito::core::decode_limits_active());
    assert_eq!(
        verifier.clone().advance_checkpoint_with_tip(tip).unwrap().0,
        independent_advance(verifier, tip).unwrap().0,
    );
}

/// Host native-finality diagnostic only: no phone latency or measured live-memory claim.
#[test]
#[ignore = "host timing diagnostic; run explicitly with --ignored --nocapture"]
fn advance_single_pass_host_timing() {
    use std::time::{Duration, Instant};
    let fixture = Fixture::new();
    let verifier = parent(&fixture);
    let tip = &fixture.second;
    let expected = independent_advance(verifier.clone(), tip).unwrap().0;
    let mut repeated = Duration::ZERO;
    let mut combined = Duration::ZERO;
    for sample in 0..6 {
        for old_path in if sample % 2 == 0 {
            [true, false]
        } else {
            [false, true]
        } {
            let owner = verifier.clone();
            let start = Instant::now();
            let (checkpoint, decision) = if old_path {
                independent_advance(owner, tip).unwrap()
            } else {
                owner.advance_checkpoint_with_tip(tip).unwrap()
            };
            let elapsed = start.elapsed();
            assert_eq!(checkpoint, expected);
            assert_eq!(decision.block().encode_wire().unwrap(), tip.block_wire);
            if sample != 0 {
                if old_path {
                    repeated += elapsed;
                } else {
                    combined += elapsed;
                }
            }
        }
    }
    eprintln!(
        "UNLOAD_ADVANCE samples=5 block_bytes={} repeated_ms={:.3} combined_ms={:.3} speedup={:.3}",
        tip.block_wire.len(),
        repeated.as_secs_f64() * 200.0,
        combined.as_secs_f64() * 200.0,
        repeated.as_secs_f64() / combined.as_secs_f64(),
    );
}

// The existing fixture signs real native QCs/availability across a short NPoS boundary.
// Its execution roots and beacon output are synthetic, not threshold-ceremony evidence.
#[test]
fn advance_crosses_real_native_epoch_boundary_and_restores_each_exact_checkpoint() {
    use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let (fixture, proofs) = NativeFinalityFixture::short_npos_boundary_chain(4);
    assert_eq!(proofs.len(), 4);
    let mut selected = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        proofs[0].committee.clone(),
    )
    .unwrap();
    let initial_epoch = selected.initial_epoch().authorization.epoch;
    for tip in &proofs {
        let original = norito::encode_canonical(tip).unwrap();
        let (expected, expected_tip) = independent_advance(selected.clone(), tip).unwrap();
        let (actual, actual_tip) = selected.advance_checkpoint_with_tip(tip).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            actual.encode_canonical().unwrap(),
            expected.encode_canonical().unwrap()
        );
        assert_eq!(actual.decisions.len(), tip.height().min(3) as usize);
        assert_eq!(actual_tip.commitment(), expected_tip.commitment());
        assert_eq!(actual_tip.context_id(), expected_tip.context_id());
        assert_eq!(actual_tip.root_scope(), fixture.root_scope());
        assert_eq!(actual_tip.block().encode_wire().unwrap(), tip.block_wire);
        match tip.height() {
            2 => {
                assert!(actual_tip.commitment().beacon.is_some());
                assert!(matches!(
                    actual_tip.commitment().schedule.after_next,
                    ScheduledSlot::PendingBoundary { .. }
                ));
            }
            3 => assert!(actual_tip.commitment().schedule.boundary.is_some()),
            4 => {
                assert_ne!(
                    actual_tip.commitment().schedule.current.authorization.epoch,
                    initial_epoch
                );
                assert!(actual_tip.commitment().schedule.boundary.is_none());
            }
            _ => {}
        }
        // The next iteration starts from this exact exported bounded restart context,
        // so both boundary admission and the following new-epoch proof cross a restore.
        let (restored, retained) = SumeragiFinalityVerifier::from_trusted_checkpoint_with_tip(
            &actual,
            &fixture.network_id(),
            fixture.chain_id(),
        )
        .unwrap();
        assert_eq!(retained.commitment(), actual_tip.commitment());
        assert_eq!(retained.block().encode_wire().unwrap(), tip.block_wire);
        assert_eq!(norito::encode_canonical(tip).unwrap(), original);
        selected = restored;
    }
    assert_eq!(selected.authenticated_height(), Some(4));
}

#[test]
fn advance_epoch_boundary_keeps_parent_beacon_barrier_and_successor_refusals() {
    use crate::sumeragi_finality::test_fixtures::NativeFinalityFixture;
    let (fixture, proofs) = NativeFinalityFixture::short_npos_boundary_chain(4);
    let mut selected = SumeragiFinalityVerifier::new(
        fixture.genesis(),
        fixture.chain_id(),
        proofs[0].committee.clone(),
    )
    .unwrap();
    for tip in &proofs[..2] {
        selected.verify(tip).unwrap();
    }
    for mutation in 0..4 {
        let mut changed = selected.clone();
        let parent = changed.decisions.get_mut(&2).unwrap();
        match mutation {
            0 => parent.beacon = None,
            1 => parent.beacon.as_mut().unwrap().seed[0] ^= 1,
            2 => {
                parent.block_hash =
                    HashOf::from_untyped_unchecked(Hash::new(b"other boundary parent"))
            }
            _ => {
                // Replace the required barrier with a superficially ready incumbent slot.
                let ScheduledSlot::Ready(ready) = &parent.schedule.next else {
                    panic!("the native preboundary has a ready boundary slot");
                };
                let mut premature = ready.clone();
                premature.height = 4;
                parent.schedule.after_next = ScheduledSlot::Ready(premature);
            }
        }
        assert_invalid_parity(changed, &proofs[2], false);
    }
    selected.verify(&proofs[2]).unwrap();
    for mutation in 0..2 {
        let mut changed = selected.clone();
        let parent = changed.decisions.get_mut(&3).unwrap();
        if mutation == 0 {
            let ScheduledSlot::Ready(ready) = &mut parent.schedule.next else {
                panic!("the native boundary installs its successor");
            };
            ready.epoch = parent.schedule.current.clone();
        } else {
            parent.schedule.boundary.as_mut().unwrap().next.leader_seed[0] ^= 1;
        }
        assert_invalid_parity(changed, &proofs[3], false);
    }
    // This is also a real two-epoch input to the active-owner fallback, not just a
    // single-epoch output comparison. Exact validation calls and charges must agree.
    let expected = under_caller(TEST_ALLOCATION_CEILING, || {
        independent_advance(selected.clone(), &proofs[3])
    });
    assert!(expected.0.is_ok());
    assert_eq!(
        under_caller(TEST_ALLOCATION_CEILING, || selected
            .clone()
            .advance_checkpoint_with_tip(&proofs[3])),
        expected
    );
}
