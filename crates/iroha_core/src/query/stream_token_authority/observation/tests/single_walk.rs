//! Real certified relation controls for the coalesced role-11 execution/history walk.

use super::*;
use crate::{
    execution_attempt::ExecutionAttemptError,
    query::signer_check::{NativeCheckErrorV1, PreparedCheckExecutionV1, SignerCertifiedWalkV1},
    sumeragi::certified_chain::relation_counts,
};

fn assert_one_walk(pending: PendingStreamTokenCheckV1, height: u64) {
    let start = match &pending.prepared.expected.phase {
        Phase::Current(_) => pending.prepared.expected.floor.height,
        _ => 4,
    };
    let (result, counts) = relation_counts::measure(|| pending.verify_finalized(now));
    let verified = result.expect("actual successful certified Check");
    assert_eq!(verified.applied_floor().height, height);
    assert_eq!(counts.qcs, (start..=height).collect::<Vec<_>>());
    let mut frames: Vec<_> = counts
        .frames
        .into_iter()
        .filter(|height| *height > 1)
        .collect();
    frames.sort_unstable();
    assert_eq!(
        frames,
        {
            let mut expected: Vec<_> = (start - 1..=height)
                .chain(start..=height)
                .chain(start..height)
                .collect();
            expected.sort_unstable();
            expected
        },
        "one original reverse acquisition, one ascending pass and bounded retained parent decode"
    );
}

fn reserved(fixture: &mut Fixture) -> StreamTokenCheckExpectedV1 {
    let initial = fixture.expected();
    let request = StreamTokenAuthorityRequestV1 {
        network_id: fixture.policy.binding.network_id,
        provider_id: fixture.provider,
        expected_control_revision: initial.control_revision,
        expected_control_digest: initial.control_digest,
        action: Action::Reserve(initial.reviewed),
    };
    let signed = fixture::sign(
        &fixture.state,
        MutateSorafsStreamTokenAuthority { request }.into(),
        2,
        2_000,
    );
    let outputs = fixture::commit(&mut fixture.chain, 2_000, vec![signed]);
    assert_eq!(outputs, [true]);
    let row = read_slot(
        fixture.state.view().world(),
        fixture.provider,
        initial.reviewed.request.operation_id,
    )
    .unwrap()
    .unwrap();
    let mut expected = fixture.expected();
    expected.phase = Phase::BeforeProvider(row.operation);
    expected
}

#[test]
fn current_reserved_and_completed_checks_each_use_one_native_continuation() {
    let mut fixture = Fixture::new();
    let pending = fixture.pending(fixture.expected());
    fixture.apply(&pending, true);
    assert_one_walk(pending, 4);

    let mut fixture = Fixture::new();
    let expected = reserved(&mut fixture);
    assert_eq!(expected.floor.height, 4); // Reserve and floor coalesce.
    let pending = fixture.pending(expected);
    fixture.apply(&pending, true);
    assert_one_walk(pending, 5);

    let mut fixture = Fixture::new();
    let expected = fixture.complete();
    assert_eq!(expected.floor.height, 5); // Complete and floor coalesce.
    let pending = fixture.pending(expected);
    fixture.apply(&pending, true);
    assert_one_walk(pending, 6); // Check and applied tip coalesce.
}

#[test]
fn advanced_tip_is_certified_after_the_exact_check_target() {
    let mut fixture = Fixture::new();
    let expected = fixture.complete();
    let pending = fixture.pending(expected);
    fixture.apply(&pending, true);
    fixture::commit(&mut fixture.chain, NOW + 1, Vec::new());
    assert_one_walk(pending, 7);
}

#[test]
fn each_required_or_intermediate_frame_remains_mandatory() {
    // Original starting parent, Reserve, terminal/floor, and Check/applied tip.
    for height in [3, 4, 5, 6] {
        let mut fixture = Fixture::new();
        let expected = fixture.complete();
        let pending = fixture.pending(expected);
        fixture.apply(&pending, true);
        fixture
            .state
            .kura()
            .corrupt_canonical_body_for_testing(core::num::NonZeroUsize::new(height).unwrap())
            .unwrap();
        assert_eq!(
            pending
                .verify_finalized(now)
                .err()
                .and_then(|failure| failure.rejection()),
            Some(Error::Finality),
            "missing height {height}"
        );
    }
}

#[test]
fn a_successful_reserve_with_below_quorum_certificate_is_not_history() {
    let mut fixture = Fixture::new();
    let expected = reserved(&mut fixture);
    let reserve_height = fixture.chain.height();
    let pending = fixture.pending(expected);
    fixture.apply(&pending, true);
    // The valid descendant already exists; now corrupt only its source's local QC.
    fixture.chain.corrupt_local_quorum_for_test(
        reserve_height,
        crate::sumeragi::test_chain::Signers::BelowQuorum,
    );
    assert_eq!(
        pending
            .verify_finalized(now)
            .err()
            .and_then(|failure| failure.rejection()),
        Some(Error::Finality)
    );
}

#[test]
fn changed_floor_and_original_operation_claim_do_not_authorize() {
    for change in 0..3 {
        let mut fixture = Fixture::new();
        let expected = fixture.complete();
        let mut pending = fixture.pending(expected);
        fixture.apply(&pending, true);
        if change == 0 {
            pending.prepared.expected.floor.block_hash[0] ^= 1;
        } else {
            let Phase::BeforeRelease(row) = &mut pending.prepared.expected.phase else {
                panic!("complete phase")
            };
            if change == 1 {
                row.reserved_execution.entry_index += 1;
            } else {
                row.terminal_execution.as_mut().unwrap().height = row.reserved_execution.height;
            }
        }
        assert_eq!(
            pending
                .verify_finalized(now)
                .err()
                .and_then(|failure| failure.rejection()),
            Some(Error::Execution)
        );
    }
}

#[test]
fn zero_floor_and_omitted_applied_check_reject_before_release() {
    let fixture = Fixture::new();
    let mut expected = fixture.expected();
    expected.floor.height = 0;
    assert_eq!(
        begin_stream_token_check_v1(fixture.state.clone(), expected, Duration::from_secs(60)).err(),
        Some(Error::Invalid)
    );
    let pending = fixture.pending(fixture.expected());
    assert_eq!(
        pending
            .verify_finalized(now)
            .err()
            .and_then(|failure| failure.rejection()),
        Some(Error::NotApplied)
    );
}

#[test]
fn misplaced_check_membership_and_an_uncertified_later_tip_reject() {
    for height in [1, 3] {
        let mut fixture = Fixture::new();
        let pending = fixture.pending(fixture.expected());
        fixture.apply(&pending, true);
        fixture
            .state
            .transactions
            .overwrite_committed_entrypoint_membership_for_tests(
                pending.signed_transaction().hash_as_entrypoint(),
                core::num::NonZeroUsize::new(height).unwrap(),
            );
        assert_eq!(
            pending
                .verify_finalized(now)
                .err()
                .and_then(|failure| failure.rejection()),
            Some(Error::NotApplied)
        );
    }

    let mut fixture = Fixture::new();
    let expected = fixture.complete();
    let pending = fixture.pending(expected);
    fixture.apply(&pending, true);
    fixture::commit_uncertified(&mut fixture.chain, NOW + 1, Vec::new());
    assert_eq!(
        pending
            .verify_finalized(now)
            .err()
            .and_then(|failure| failure.rejection()),
        Some(Error::Finality)
    );
}

#[test]
fn history_relation_requires_its_exact_view_complete_window_and_floor() {
    use crate::query::stream_token_authority::historical_execution::{
        PreparedStreamTokenHistoryV1, authenticate_stream_token_history_to_floor_v1,
    };
    let mut fixture = Fixture::new();
    let expected = fixture.complete();
    let view = fixture.state.view();
    let make = || {
        PreparedStreamTokenHistoryV1::new(
            &view,
            fixture.provider,
            expected.reviewed.request.operation_id,
            expected.floor,
        )
        .unwrap()
    };
    assert!(make().finish().is_err());
    let chain = SignerCertifiedWalkV1::new(&view).unwrap();
    let reserve = chain.walk(4, 4).next().unwrap().unwrap();
    let mut omitted = make();
    omitted.consume(&reserve).unwrap();
    assert!(omitted.finish().is_err());
    let mut duplicate = make();
    duplicate.consume(&reserve).unwrap();
    assert!(duplicate.consume(&reserve).is_err());
    assert!(duplicate.finish().is_err());
    let mut other = Fixture::new();
    fixture::commit(&mut other.chain, 2_000, Vec::new());
    let other_view = other.state.view();
    let foreign = SignerCertifiedWalkV1::new(&other_view)
        .unwrap()
        .walk(4, 4)
        .next()
        .unwrap()
        .unwrap();
    let mut wrong_source = make();
    assert!(wrong_source.consume(&foreign).is_err());
    assert!(wrong_source.finish().is_err());
    let (result, counts) = relation_counts::measure(|| {
        authenticate_stream_token_history_to_floor_v1(
            &view,
            fixture.provider,
            expected.reviewed.request.operation_id,
            expected.floor,
        )
    });
    assert!(result.is_ok());
    assert_eq!(counts.qcs, vec![4, 5]);
}

#[test]
fn borrowed_check_relation_rejects_omission_duplicate_and_foreign_fork() {
    for mode in 0..3 {
        let mut fixture = Fixture::new();
        let pending = fixture.pending(fixture.expected());
        fixture.apply(&pending, true);
        let view = fixture.state.view();
        let mut bound = Some(pending.bound);
        let mut proof = PreparedCheckExecutionV1::new(
            &view,
            NativeCustodyCheckPurposeV1::StreamToken,
            &mut bound,
            &pending.prepared.round,
        )
        .unwrap();
        let chain = SignerCertifiedWalkV1::new(&view).unwrap();
        let floor = chain.walk(3, 3).next().unwrap().unwrap();
        proof.consume(&floor).unwrap();
        match mode {
            0 => assert_eq!(
                proof.finish().err(),
                Some(ExecutionAttemptError::Rejected(
                    NativeCheckErrorV1::Execution
                ))
            ),
            1 => {
                assert_eq!(
                    proof.consume(&floor),
                    Err(ExecutionAttemptError::Rejected(
                        NativeCheckErrorV1::Finality
                    ))
                );
                assert_eq!(
                    proof.finish().err(),
                    Some(ExecutionAttemptError::Rejected(
                        NativeCheckErrorV1::Execution
                    ))
                );
            }
            _ => {
                let mut other = Fixture::new();
                fixture::commit(&mut other.chain, NOW, Vec::new());
                let other_view = other.state.view();
                let foreign = SignerCertifiedWalkV1::new(&other_view)
                    .unwrap()
                    .walk(4, 4)
                    .next()
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    proof.consume(&foreign),
                    Err(ExecutionAttemptError::Rejected(
                        NativeCheckErrorV1::Finality
                    ))
                );
                assert_eq!(
                    proof.finish().err(),
                    Some(ExecutionAttemptError::Rejected(
                        NativeCheckErrorV1::Execution
                    ))
                );
            }
        }
    }
}

/// Same canonical bodies, executed results, epoch contexts and network, but another
/// State/Kura owns a distinct, genuinely valid three-of-four certificate at `height`.
fn alternate_qc_source(fixture: &Fixture, height: u64) -> Arc<State> {
    use crate::sumeragi::test_chain::Signers;
    let mut other = Fixture::new();
    other.chain.replay_from(&fixture.chain).unwrap();
    let (body, original) = other.chain.committed_body(height).unwrap().unwrap();
    let alternate = other.chain.commit_qc(
        height,
        original.block_hash,
        original.result,
        Signers::LastThree,
    );
    assert_eq!(
        alternate.signers.count_ones(),
        body.source().config().committee.q()
    );
    assert_ne!(alternate.signers, original.signers);
    other
        .chain
        .kura()
        .corrupt_commit_certificate_for_testing(
            core::num::NonZeroUsize::new(usize::try_from(height).unwrap()).unwrap(),
            Some(norito::encode_canonical(&alternate).unwrap()),
        )
        .unwrap();
    Arc::clone(&other.state)
}

#[test]
fn identical_body_and_context_with_another_valid_qc_cannot_change_check_source() {
    let mut fixture = Fixture::new();
    let pending = fixture.pending(fixture.expected());
    fixture.apply(&pending, true);
    let other = alternate_qc_source(&fixture, 4);
    let view = fixture.state.view();
    let other_view = other.view();
    let mut bound = Some(pending.bound);
    let mut proof = PreparedCheckExecutionV1::new(
        &view,
        NativeCustodyCheckPurposeV1::StreamToken,
        &mut bound,
        &pending.prepared.round,
    )
    .unwrap();
    let reader = SignerCertifiedWalkV1::new(&view).unwrap();
    let mut own_blocks = reader.walk(3, 4);
    let floor = own_blocks.next().unwrap().unwrap();
    let own = own_blocks.next().unwrap().unwrap();
    let foreign = SignerCertifiedWalkV1::new(&other_view)
        .unwrap()
        .walk(4, 4)
        .next()
        .unwrap()
        .unwrap();
    let left = own.in_view(&view).unwrap();
    let right = foreign.in_view(&other_view).unwrap();
    assert_eq!(left.block_hash(), right.block_hash());
    assert_eq!(left.id(), right.id());
    assert_eq!(left.result(), right.result());
    assert_eq!(left.commitment(), right.commitment());
    assert_ne!(
        left.block().commit_certificate(),
        right.block().commit_certificate()
    );
    proof.consume(&floor).unwrap();
    assert_eq!(
        proof.consume(&foreign),
        Err(ExecutionAttemptError::Rejected(
            NativeCheckErrorV1::Finality
        ))
    );
    assert_eq!(
        proof.finish().err(),
        Some(ExecutionAttemptError::Rejected(
            NativeCheckErrorV1::Execution
        ))
    );
}

#[test]
fn history_and_fresh_views_reject_equal_bytes_from_another_source_owner() {
    use crate::query::stream_token_authority::historical_execution::PreparedStreamTokenHistoryV1;
    let mut fixture = Fixture::new();
    let expected = fixture.complete();
    let other = alternate_qc_source(&fixture, 4);
    let view = fixture.state.view();
    let other_view = other.view();
    let foreign = SignerCertifiedWalkV1::new(&other_view)
        .unwrap()
        .walk(4, 4)
        .next()
        .unwrap()
        .unwrap();
    let own = SignerCertifiedWalkV1::new(&view)
        .unwrap()
        .walk(4, 4)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        own.in_view(&view).unwrap().block_hash(),
        foreign.in_view(&other_view).unwrap().block_hash()
    );
    assert_eq!(
        own.in_view(&view).unwrap().id(),
        foreign.in_view(&other_view).unwrap().id()
    );
    assert!(foreign.in_view(&view).is_err());
    let mut history = PreparedStreamTokenHistoryV1::new(
        &view,
        fixture.provider,
        expected.reviewed.request.operation_id,
        expected.floor,
    )
    .unwrap();
    assert!(history.consume(&foreign).is_err());
    assert!(history.finish().is_err());

    // Even a fresh view of the same State/Kura is not silently substituted for the borrowed cut.
    let fresh = fixture.state.view();
    let same_bytes = SignerCertifiedWalkV1::new(&fresh)
        .unwrap()
        .walk(4, 4)
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(
        own.in_view(&view).unwrap().block().commit_certificate(),
        same_bytes
            .in_view(&fresh)
            .unwrap()
            .block()
            .commit_certificate()
    );
    assert!(same_bytes.in_view(&view).is_err());
    assert!(own.in_view(&fresh).is_err());
}
