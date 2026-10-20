//! Real publication attempts retain one source, charged tables and independent work grants.

use super::*;
use crate::state::{
    StatePublicationOutcome,
    publication::musubi_materializer_test_support::{fixture, staged_block},
};
use iroha_config::parameters::actual::StateCapture;

fn plan<'a>(block: &'a StateBlock<'_>) -> &'a RetainedMusubiGroupRead {
    block
        .publication
        .as_ref()
        .unwrap()
        .musubi_group_read
        .as_ref()
        .unwrap()
}
fn tables<'a>(
    block: &'a StateBlock<'_>,
) -> &'a crate::state::authority_registry::OriginalMusubiMaterializers {
    plan(block)
        .admission
        .as_ref()
        .expect("canonical nodes must survive original source-reader retirement")
        .as_slice()[0]
        .materializers
        .as_ref()
        .unwrap()
}
fn complete(block: &StateBlock<'_>) -> bool {
    plan(block)
        .admission
        .as_ref()
        .is_some_and(|original| original.as_slice()[0].validated())
}
fn assert_free(state: &State) {
    assert_eq!(state.publication_fences_available_for_test(), (true, true));
    drop(state.world.parameters.block());
    drop(state.canonical_runtime.block());
    drop(state.transactions.block());
}

#[test]
fn real_publication_small_grants_keep_the_same_original_source_until_complete() {
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    original.pipeline.state_capture.native_work_per_attempt = 512;
    original.pipeline.state_capture.encoding_work_per_attempt = 4096;
    original.pipeline.state_capture.table_payload_bytes = 4096;
    let owner = std::ptr::from_ref(&*original);
    let mut deferred = 0;
    let mut original_generation = None;
    let mut control = None;
    let mut work = 0;
    for _ in 0..4096 {
        match original.try_publish() {
            StatePublicationOutcome::Published => {
                assert!(deferred > 1);
                assert_eq!(std::ptr::from_ref(&*original), owner);
                assert!(plan(&original).retired);
                assert!(
                    tables(&original)
                        .progress()
                        .iter()
                        .all(|table| table.complete)
                );
                assert_eq!(state.world.musubi_public_directory.view().len(), 1);
                return;
            }
            StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(reason)) => {
                assert!(reason.release_wait().is_none());
                assert!(reason.allocation_refusal().is_none());
                let retained = plan(&original);
                let generation = *original_generation.get_or_insert(retained.generation);
                assert_eq!(retained.generation, generation);
                let pointer = retained.data.as_ref().unwrap().as_slice().as_ptr();
                assert_eq!(pointer, *control.get_or_insert(pointer));
                assert!(retained.work >= work);
                work = retained.work;
                deferred += 1;
                assert_eq!(std::ptr::from_ref(&*original), owner);
                assert_free(&state);
            }
            other => panic!("real small-grant capture did not retain its original: {other:?}"),
        }
    }
    panic!("configured production quanta must finish the same original capture");
}

#[test]
fn real_publication_grants_native_work_after_semantics_complete() {
    let (state, proposal) = fixture();
    let semantic_work = {
        let mut probe = Box::new(staged_block(&state, proposal.header(), false, true));
        probe.pipeline.state_capture.native_work_per_attempt = 64 * 1024 * 1024;
        probe.pipeline.state_capture.encoding_work_per_attempt = 0;
        assert!(matches!(
            probe.try_publish(),
            StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_))
        ));
        assert!(complete(&probe));
        let measured = plan(&probe).work;
        assert!(measured > 0);
        measured
    };
    // Select an exact independently configured boundary from the earlier real
    // control. This is test policy, never a production grant inferred from work.
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    original.pipeline.state_capture.native_work_per_attempt = semantic_work;
    original.pipeline.state_capture.encoding_work_per_attempt = 64 * 1024 * 1024;
    let failure = original.try_publish();
    assert!(complete(&original));
    let StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(reason)) =
        failure
    else {
        panic!(
            "exact semantic allowance must refuse a later materializer source read: {failure:?}"
        );
    };
    assert!(reason.native_work().is_some());
    let before = plan(&original).native_work_granted;
    assert_eq!(before, semantic_work);
    assert!(
        matches!(original.try_publish(), StatePublicationOutcome::Published),
        "completed semantics must still receive independent native grants for materialization"
    );
    assert_eq!(plan(&original).native_work_granted, 2 * semantic_work);
    assert!(
        tables(&original)
            .progress()
            .iter()
            .all(|table| table.complete)
    );
}

#[test]
fn real_publication_encoding_wait_does_not_repeat_paid_source_reborrows() {
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    original.pipeline.state_capture.native_work_per_attempt = 1024 * 1024;
    original.pipeline.state_capture.encoding_work_per_attempt = 4096;
    original.pipeline.state_capture.table_payload_bytes = 4096;
    for _ in 0..4096 {
        let outcome = original.try_publish();
        match outcome {
            StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(reason)) => {
                let retained = plan(&original);
                if reason.encoding_work().is_some()
                    && retained
                        .admission
                        .as_ref()
                        .and_then(|original| original.as_slice()[0].materializers.as_ref())
                        .is_some_and(|tables| {
                            tables.progress().iter().any(|table| table.pending_key)
                        })
                {
                    let used = retained.work;
                    let encoded: usize = tables(&original)
                        .progress()
                        .iter()
                        .map(|table| table.work)
                        .sum();
                    let next = retained.encoding_work_granted + 4096;
                    if encoded + retained.encoding_retry_minimum > next {
                        assert!(matches!(
                            original.try_publish(),
                            StatePublicationOutcome::Deferred(
                                TransactionsBlockError::CaptureDeferred(_)
                            )
                        ));
                        assert_eq!(
                            plan(&original).work,
                            used,
                            "unmet encoding demand must wait without repeating paid original source reborrows"
                        );
                        assert_eq!(plan(&original).encoding_work_granted, next);
                        assert_free(&state);
                        return;
                    }
                }
            }
            other => panic!("expected a genuine finite encoding wait before completion: {other:?}"),
        }
    }
    panic!("bounded production capture must reach its first retained-key encoding wait");
}

#[test]
fn real_publication_retires_sources_but_retains_canonical_nodes_after_late_refusal() {
    use crate::test_allocations::refuse_one_layout_during;
    use iroha_allocation::ChargedBufferError;

    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    assert_eq!(original.pipeline.state_capture, StateCapture::default());
    // The executing block still owns every original Cell writer. First reach a
    // real capture refusal, which freezes those fields and releases the writers;
    // only then may this thread acquire the deliberate late writer blocker.
    let layout = std::alloc::Layout::array::<OriginalMusubiAdmissionPair>(1).unwrap();
    let (outcome, denied) = refuse_one_layout_during(layout, || original.try_publish());
    assert!(
        denied,
        "the initial attempt must reach original capture admission"
    );
    let StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(reason)) =
        outcome
    else {
        panic!("capture must defer before acquiring the late writer blocker: {outcome:?}");
    };
    assert!(
        matches!(reason.buffer_refusal(), Some(ChargedBufferError::Allocator { requested_bytes }) if *requested_bytes == layout.size())
    );
    assert!(reason.release_wait().is_none());
    assert!(reason.allocation_refusal().is_none());
    assert!(original.publication.as_ref().unwrap().fields_frozen);
    assert!(plan(&original).scheduled);
    assert!(!plan(&original).retired);
    assert!(plan(&original).admission.is_none());
    assert_free(&state);
    let blocker = state.world.governance_last_unlock_sweep_height.block();
    let mut late = false;
    for _ in 0..256 {
        match original.try_publish() {
            StatePublicationOutcome::Deferred(TransactionsBlockError::PublicationBusy(_)) => {
                late = true;
                break;
            }
            StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_)) => {}
            other => panic!("expected retained capture or actual late writer refusal: {other:?}"),
        }
    }
    assert!(late);
    assert!(plan(&original).retired);
    assert!(plan(&original).data.is_none());
    let pointer = std::ptr::from_ref(tables(&original));
    let progress = tables(&original).progress();
    assert!(progress.iter().all(|table| table.complete));
    let grants = (
        plan(&original).native_work_granted,
        plan(&original).encoding_work_granted,
    );
    for _ in 0..3 {
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(TransactionsBlockError::PublicationBusy(_))
        ));
        assert_eq!(
            std::ptr::from_ref(tables(&original)),
            pointer,
            "canonical nodes must survive original source-reader retirement"
        );
        assert_eq!(tables(&original).progress(), progress);
        assert_eq!(
            (
                plan(&original).native_work_granted,
                plan(&original).encoding_work_granted
            ),
            grants
        );
        assert_free(&state);
    }
    drop(blocker);
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert_eq!(std::ptr::from_ref(tables(&original)), pointer);
}

#[test]
fn real_publication_empty_group_still_builds_all_three_canonical_tables() {
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, false));
    assert_eq!(original.pipeline.state_capture, StateCapture::default());
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert!(complete(&original));
    assert!(plan(&original).retired);
    let progress = tables(&original).progress();
    assert!(
        progress
            .iter()
            .all(|table| table.complete && table.rows == 0 && table.work > 0)
    );
}

#[test]
fn real_publication_zero_work_policy_is_pinned_and_releases_every_physical_fence() {
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    original.pipeline.state_capture.native_work_per_attempt = 0;
    for _ in 0..3 {
        let StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(reason)) =
            original.try_publish()
        else {
            panic!("zero capture work must remain an exact local refusal");
        };
        assert_eq!(reason.native_work().unwrap().2, 0);
        assert!(reason.release_wait().is_none());
        assert_eq!(plan(&original).native_work_granted, 0);
        assert_eq!(plan(&original).work, 0);
        assert_eq!(
            original
                .publication
                .as_ref()
                .unwrap()
                .capture_policy
                .native_work_per_attempt,
            0
        );
        assert_free(&state);
    }
}

#[test]
fn real_publication_reader_retirement_refusal_resumes_without_reopening_source() {
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
    original.pipeline.state_capture.encoding_work_per_attempt = 4096;
    original.pipeline.state_capture.table_payload_bytes = 4096;
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_))
    ));
    let outside = original.retain_group_package_reader_for_test().unwrap();
    let mut retiring = false;
    for _ in 0..4096 {
        let StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_)) =
            original.try_publish()
        else {
            panic!("retained outside reader must prevent original publication");
        };
        if plan(&original).data.is_none() {
            retiring = true;
            break;
        }
    }
    assert!(retiring);
    assert!(!plan(&original).retired);
    let pointer = std::ptr::from_ref(tables(&original));
    let work = plan(&original).work;
    let grants = (
        plan(&original).native_work_granted,
        plan(&original).encoding_work_granted,
    );
    for _ in 0..3 {
        assert!(
            matches!(
                original.try_publish(),
                StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_))
            ),
            "reader retirement must resume directly after source descriptors retire"
        );
        assert_eq!(std::ptr::from_ref(tables(&original)), pointer);
        assert_eq!(plan(&original).work, work);
        assert_eq!(
            (
                plan(&original).native_work_granted,
                plan(&original).encoding_work_granted
            ),
            grants
        );
        assert!(plan(&original).data.is_none());
        assert_free(&state);
    }
    drop(outside);
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert_eq!(std::ptr::from_ref(tables(&original)), pointer);
}

#[test]
fn real_publication_capture_never_rebases_changed_generation_or_equal_revision() {
    for change_generation in [false, true] {
        let (state, proposal) = fixture();
        let mut original = Box::new(staged_block(&state, proposal.header(), false, true));
        original.pipeline.state_capture.encoding_work_per_attempt = 0;
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_))
        ));
        let generation = plan(&original).generation;
        let work = plan(&original).work;
        let pointer = plan(&original).data.as_ref().unwrap().as_slice().as_ptr();
        if change_generation {
            let mut notice = state.state_view_publication();
            let writer = state.state_write_lock.lock();
            drop(notice.begin());
            drop(writer);
            drop(notice);
        } else {
            // A real equal-value publication changes the exact lower predecessor.
            state.world.musubi_resolver_index_revision.block().commit();
            assert_eq!(state.state_view_generation(), generation);
        }
        assert!(matches!(
            original.try_publish(),
            StatePublicationOutcome::RecoveryRequired(
                TransactionsBlockError::SnapshotObservationChanged
            )
        ));
        assert_eq!(plan(&original).generation, generation);
        assert_eq!(plan(&original).work, work);
        assert_eq!(
            plan(&original).data.as_ref().unwrap().as_slice().as_ptr(),
            pointer
        );
        assert!(state.world.musubi_public_directory.view().is_empty());
        assert_free(&state);
    }
}

#[test]
fn real_publication_capture_retains_original_scope_after_physical_control_refusal() {
    assert_original_scope_after_physical_control_refusal(
        std::alloc::Layout::array::<OriginalMusubiAdmissionPair>(1).unwrap(),
    );
}

#[test]
fn real_publication_capture_refunds_control_after_physical_live_refusal() {
    assert_original_scope_after_physical_control_refusal(
        original_musubi_admission_live_layout_for_test(),
    );
}

fn assert_original_scope_after_physical_control_refusal(layout: std::alloc::Layout) {
    use crate::test_allocations::refuse_one_layout_during;
    use iroha_allocation::ChargedBufferError;
    let (state, proposal) = fixture();
    let mut original = Box::new(staged_block(&state, proposal.header(), false, false));
    let (outcome, denied) = refuse_one_layout_during(layout, || original.try_publish());
    assert!(denied);
    let StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(reason)) =
        outcome
    else {
        panic!("original source control allocation must remain local: {outcome:?}");
    };
    assert!(
        matches!(reason.buffer_refusal(), Some(ChargedBufferError::Allocator { requested_bytes }) if *requested_bytes == layout.size())
    );
    assert!(reason.release_wait().is_none());
    assert!(reason.allocation_refusal().is_none());
    let pointer = plan(&original).data.as_ref().unwrap().as_slice().as_ptr();
    assert!(
        plan(&original)
            .scope
            .belongs_to(&state.ivm_execution_budget())
    );
    assert!(plan(&original).admission.is_none());
    assert_free(&state);
    let retained_credit = state.ivm_execution_budget().reserved_bytes();
    let (repeat, denied_again) = refuse_one_layout_during(layout, || original.try_publish());
    assert!(denied_again);
    assert!(matches!(
        repeat,
        StatePublicationOutcome::Deferred(TransactionsBlockError::CaptureDeferred(_))
    ));
    assert_eq!(
        plan(&original).data.as_ref().unwrap().as_slice().as_ptr(),
        pointer
    );
    assert!(
        plan(&original)
            .scope
            .belongs_to(&state.ivm_execution_budget())
    );
    assert_free(&state);
    assert!(plan(&original).admission.is_none());
    assert_eq!(
        state.ivm_execution_budget().reserved_bytes(),
        retained_credit
    );
    // Empty-table setup completes under the unchanged default encoding quantum.
    assert!(matches!(
        original.try_publish(),
        StatePublicationOutcome::Published
    ));
    assert!(plan(&original).retired);
    assert!(
        plan(&original)
            .final_progress
            .unwrap()
            .iter()
            .all(|table| table.complete)
    );
    assert!(
        tables(&original)
            .progress()
            .iter()
            .all(|table| table.complete)
    );
}
