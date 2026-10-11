//! Producer-local epoch reuse preserves native witnesses, bytes and enclosing admission.

use super::super::tests::Fixture;
use super::*;
use crate::{block::CommitCertificate, sumeragi::epoch::validation_counts};
use norito::core::DecodeBudgetContext;

const CHAIN: &str = "portable-finality-test";
const TEST_ALLOCATION_CEILING: usize = 64 * 1024 * 1024;

fn selected(fixture: &Fixture) -> SumeragiFinalityVerifier {
    let mut verifier = fixture.verifier();
    verifier.verify(&fixture.first).unwrap();
    verifier.verify(&fixture.second).unwrap();
    verifier
}

// The original export recipe is the active-admission reference. It calls the same native
// producers; it does not implement another proof verifier or relax any certificate check.
fn independent_export(
    verifier: &SumeragiFinalityVerifier,
    tip: &SumeragiFinalityProof,
) -> Result<SumeragiFinalityCheckpoint, FinalityError> {
    need(
        verifier
            .decisions
            .last_key_value()
            .map(|(height, _)| *height)
            == Some(tip.height()),
        "checkpoint must export the authenticated tip",
    )?;
    verifier.verify_retained_decision(tip)?;
    let first = tip.height().saturating_sub(2).max(1);
    let checkpoint = SumeragiFinalityCheckpoint {
        network_id: NetworkId::from_genesis_hash(verifier.genesis.hash()),
        chain_id: verifier.chain_id.clone(),
        genesis_wire: verifier
            .genesis
            .canonical_resultless_proposal()
            .map_err(malformed)?
            .encode_wire()
            .map_err(malformed)?,
        genesis_committee: verifier.genesis_committee.clone(),
        decisions: verifier
            .decisions
            .range(first..)
            .map(|(height, decision)| CheckpointDecision::capture(*height, decision))
            .collect(),
        tip: tip.clone(),
    };
    checkpoint.validate_bounds()?;
    Ok(checkpoint)
}

fn independent_encoding(checkpoint: &SumeragiFinalityCheckpoint) -> Result<Vec<u8>, FinalityError> {
    checkpoint.validate_bounds()?;
    norito::encode_canonical(checkpoint).map_err(malformed)
}

#[test]
fn producer_epoch_work_is_local_and_repeated_calls_keep_identical_bytes() {
    let fixture = Fixture::new();
    let verifier = selected(&fixture);
    let before = validation_counts::calls();
    let expected = independent_export(&verifier, &fixture.second).unwrap();
    assert!(validation_counts::calls() - before > 1);
    let before = validation_counts::calls();
    let bytes = independent_encoding(&expected).unwrap();
    assert_eq!(
        validation_counts::calls() - before,
        expected.decisions.len()
    );
    let proof_bytes = norito::encode_canonical(&fixture.second).unwrap();
    assert!(!norito::core::decode_limits_active());

    for _ in 0..2 {
        let before = validation_counts::calls();
        let actual = verifier.export_checkpoint(&fixture.second).unwrap();
        assert_eq!(validation_counts::calls() - before, 1);
        assert_eq!(actual, expected);
        let before = validation_counts::calls();
        assert_eq!(actual.encode_canonical().unwrap(), bytes);
        assert_eq!(validation_counts::calls() - before, 1);
    }
    // A returned DTO, an earlier producer call and its encoded bytes confer no workspace
    // on the public witness verifier or the independent checkpoint importer.
    let before = validation_counts::calls();
    verifier.verify_retained_decision(&fixture.second).unwrap();
    assert_eq!(validation_counts::calls() - before, 4);
    let before = validation_counts::calls();
    SumeragiFinalityVerifier::from_trusted_checkpoint(&expected, &fixture.network, CHAIN).unwrap();
    assert_eq!(validation_counts::calls() - before, 1);
    assert_eq!(
        norito::encode_canonical(&fixture.second).unwrap(),
        proof_bytes
    );
}

#[test]
fn encoding_rechecks_changed_contexts_and_every_later_decision_bound() {
    let fixture = Fixture::new();
    let verifier = selected(&fixture);
    let checkpoint = verifier.export_checkpoint(&fixture.second).unwrap();
    let original = checkpoint.encode_canonical().unwrap();
    for mutation in 0..10 {
        let mut changed = checkpoint.clone();
        // H1 warms the original context before H2 checks the changed input. Neither equal
        // epoch numbers nor an earlier successful encoding can substitute for full equality.
        let later = &mut changed.decisions[1];
        match mutation {
            0 => later.schedule.current.committee[0].proof_of_possession[0] ^= 1,
            1 => later.schedule.current.authorization.authority_generation += 1,
            2 => later.schedule.current.leader_seed[0] ^= 1,
            3 => later.schedule.height += 1,
            4 => {
                let ScheduledSlot::Ready(next) = &mut later.schedule.next else {
                    panic!("fixture has an ordinary ready successor");
                };
                next.height += 1;
            }
            5 => later.core_hash = [0; 32],
            6 => later.result = [0; 32],
            7 => later.committee_digest = [0; 32],
            8 => later.executed_len = 0,
            _ => later.height += 1,
        }
        let source = norito::encode_canonical(&changed).unwrap();
        let expected = independent_encoding(&changed).unwrap_err();
        assert_eq!(
            changed.encode_canonical().unwrap_err(),
            expected,
            "{mutation}"
        );
        assert_eq!(norito::encode_canonical(&changed).unwrap(), source);
        assert_eq!(checkpoint.encode_canonical().unwrap(), original);
    }

    let mut different = checkpoint.clone();
    let later = &mut different.decisions[1].schedule;
    later.current.leader_seed[0] ^= 1;
    for slot in [&mut later.next, &mut later.after_next] {
        let ScheduledSlot::Ready(selected) = slot else {
            panic!("fixture has ordinary ready successors");
        };
        selected.epoch = later.current.clone();
    }
    assert_eq!(
        different.decisions[0].schedule.current.authorization.epoch,
        different.decisions[1].schedule.current.authorization.epoch
    );
    let expected = independent_encoding(&different).unwrap();
    let before = validation_counts::calls();
    assert_eq!(different.encode_canonical().unwrap(), expected);
    assert_eq!(validation_counts::calls() - before, 2);
    assert_ne!(expected, original);
    // Structural encoding never turns the changed schedule into a certified decision.
    assert!(
        SumeragiFinalityVerifier::from_trusted_checkpoint(&different, &fixture.network, CHAIN)
            .is_err()
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

#[test]
fn export_rechecks_native_qc_roster_tip_and_retained_decision_after_reuse() {
    let fixture = Fixture::new();
    let verifier = selected(&fixture);
    let checkpoint = verifier.export_checkpoint(&fixture.second).unwrap();
    let original = checkpoint.encode_canonical().unwrap();
    let mut wrong_roster = fixture.second.clone();
    wrong_roster.committee[0].proof_of_possession[0] ^= 1;
    let mut wrong_quorum = fixture.second.clone();
    let mut block = decode_framed_signed_block(&wrong_quorum.block_wire).unwrap();
    let certificate = block.commit_certificate().unwrap();
    let header = certificate.consensus_header().to_vec();
    let result = certificate.result_preimage().to_vec();
    let availability = certificate.availability().to_vec();
    let mut quorum: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
    quorum.agg_sig.0[0] ^= 1;
    block.set_commit_certificate(Some(CommitCertificate::from_untrusted_parts(
        header,
        norito::encode_canonical(&quorum).unwrap(),
        result,
        availability,
    )));
    wrong_quorum.block_wire = block.encode_wire().unwrap();
    assert_eq!(wrong_quorum.block_header, fixture.second.block_header);
    for changed in [&wrong_roster, &wrong_quorum, &fixture.first] {
        let source = norito::encode_canonical(changed).unwrap();
        let expected = independent_export(&verifier, changed).unwrap_err();
        assert_eq!(verifier.export_checkpoint(changed).unwrap_err(), expected);
        assert_eq!(norito::encode_canonical(changed).unwrap(), source);
        assert_eq!(
            verifier.export_checkpoint(&fixture.second).unwrap(),
            checkpoint
        );
    }
    for field in [
        "block_hash",
        "core_hash",
        "result",
        "committee_digest",
        "schedule",
        "executed_hash",
        "executed_len",
        "parent",
    ] {
        let mut changed = verifier.clone();
        if field == "parent" {
            changed.decisions.remove(&fixture.first.height());
        } else {
            let retained = changed.decisions.get_mut(&fixture.second.height()).unwrap();
            match field {
                "block_hash" => {
                    retained.block_hash =
                        HashOf::from_untyped_unchecked(Hash::new(b"producer changed block"));
                }
                "core_hash" => retained.core_hash.0[0] ^= 1,
                "result" => retained.result.0[0] ^= 1,
                "committee_digest" => retained.committee_digest[0] ^= 1,
                "schedule" => retained.schedule.height += 1,
                "executed_hash" => retained.executed_hash = Hash::new(b"changed execution"),
                "executed_len" => retained.executed_len += 1,
                _ => unreachable!(),
            }
        }
        let expected = independent_export(&changed, &fixture.second).unwrap_err();
        assert_eq!(
            changed.export_checkpoint(&fixture.second).unwrap_err(),
            expected,
            "{field}"
        );
        assert_eq!(
            verifier.export_checkpoint(&fixture.second).unwrap(),
            checkpoint
        );
    }
    let alternate = fixture.alternate();
    assert_eq!(
        verifier.export_checkpoint(&alternate).unwrap(),
        independent_export(&verifier, &alternate).unwrap()
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}

fn caller_limits(allocation: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        1024 * 1024,
        MAX_FINALITY_CHECKPOINT_BYTES,
        8 * 1024 * 1024,
        allocation,
        64,
    )
}

fn under_caller<T>(
    allocation: usize,
    operation: impl FnOnce() -> Result<T, FinalityError>,
) -> (Result<T, FinalityError>, u64, usize) {
    let budget = DecodeBudgetContext::new(caller_limits(allocation));
    let before = validation_counts::calls();
    let result = budget.with(operation);
    (
        result,
        budget.consumed_allocated_bytes(),
        validation_counts::calls() - before,
    )
}

fn assert_original_admission<T: std::fmt::Debug + PartialEq>(
    original: impl Fn() -> Result<T, FinalityError>,
    candidate: impl Fn() -> Result<T, FinalityError>,
    positive_limit_refuses: bool,
) {
    let expected = under_caller(TEST_ALLOCATION_CEILING, &original);
    assert!(expected.0.is_ok());
    assert!(expected.1 > 1);
    assert!(expected.2 > 1);
    assert_eq!(under_caller(TEST_ALLOCATION_CEILING, &candidate), expected);
    let charge = usize::try_from(expected.1).unwrap();
    assert!(charge < TEST_ALLOCATION_CEILING);
    for cap in [1, charge / 2, charge - 1, charge] {
        let expected = under_caller(cap, &original);
        if cap == 1 {
            assert_eq!(
                expected.0.is_err(),
                positive_limit_refuses,
                "mandatory decoding refuses; optional memo insertion may decline"
            );
        }
        assert_eq!(under_caller(cap, &candidate), expected, "cap {cap}");
    }
}

#[test]
fn active_producers_preserve_original_results_charges_and_positive_refusals() {
    let fixture = Fixture::new();
    let verifier = selected(&fixture);
    let checkpoint = verifier.export_checkpoint(&fixture.second).unwrap();
    let original = checkpoint.encode_canonical().unwrap();
    // Warming both public calls outside the owner cannot alter a later cumulative owner.
    assert_original_admission(
        || independent_export(&verifier, &fixture.second),
        || verifier.export_checkpoint(&fixture.second),
        true,
    );
    // Encoding validates an already decoded DTO. A tiny decode budget can decline the
    // optional epoch memo while validation and ordinary canonical encoding still succeed.
    assert_original_admission(
        || independent_encoding(&checkpoint),
        || checkpoint.encode_canonical(),
        false,
    );
    assert!(!norito::core::decode_limits_active());
    assert_eq!(
        verifier.export_checkpoint(&fixture.second).unwrap(),
        checkpoint
    );
    assert_eq!(checkpoint.encode_canonical().unwrap(), original);
}
