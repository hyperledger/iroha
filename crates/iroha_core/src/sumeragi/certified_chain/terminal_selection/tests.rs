//! Actual source, certifier and schedule refusals around one retained terminal native selection.

use std::sync::{Arc, Mutex};

use super::*;
use crate::{
    state::World,
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};

fn chain() -> CertifiedTestChain {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    chain.commit_at(3_000, Vec::new());
    chain
}

#[test]
fn terminal_result_scope_comes_from_the_signed_root() {
    let chain = chain();
    let view = chain.state().view();
    let context = decoder(&view.execution_budget());
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let terminal = context.with(|| reader.certified_terminal_amx(3)).unwrap();
    assert_eq!(
        iroha_data_model::sumeragi_finality::CertifiedResultScope::from(
            terminal.committed().root_scope()
        ),
        CertifiedResultScope::TairaGlobal
    );
    assert_eq!(terminal.committed().result(), chain.committed(3).result());
}

fn decoder(budget: &AllocationBudget) -> norito::core::DecodeBudgetContext {
    norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        budget,
    )
    .unwrap()
}
fn pressure<V: StateReadOnly + ?Sized>(
    reader: &mut CertifiedChain<'_, V>,
    budget: &AllocationBudget,
) -> Arc<Mutex<Option<iroha_allocation::AllocationReservation>>> {
    let loan = Arc::new(Mutex::new(None));
    let held = Arc::clone(&loan);
    let original = budget.clone();
    reader
        .probe_terminal_target_once(move |_| {
            *held.lock().unwrap() = Some(
                original
                    .try_reserve_bytes(original.limit_bytes() - original.reserved_bytes())
                    .unwrap(),
            );
        })
        .unwrap();
    loan
}
fn target_pointer<V: StateReadOnly + ?Sized>(
    reader: &CertifiedChain<'_, V>,
) -> *const CommittedBlock {
    reader
        .terminal_target_for_test()
        .expect("actual retained target")
}

#[test]
fn terminal_certifier_refusal_retains_original_target_gap_decoder_and_public_reset() {
    let chain = chain();
    let view = chain.state().view();
    let budget = view.execution_budget();
    let context = decoder(&budget);
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let loan = pressure(&mut reader, &budget);
    let refused = context.with(|| reader.certified_terminal_amx(3));
    assert!(
        matches!(refused, Err(ExecutionAttemptError::Deferred(ref local))
        if matches!(local.allocation_refusal(), Some(iroha_allocation::AllocationRefusal::Capacity { .. })))
    );
    let target = target_pointer(&reader);
    drop(loan.lock().unwrap().take());
    // Decode the genuine original gap in the same production owner, before imposing a
    // tighter inherited decoder layer specifically on the sole certificate verifier.
    let verifier = PrefixVerifierContext {
        instance: reader.instance,
        root_scope: reader.root_scope,
    };
    let mut cursor = reader.prefix.lock();
    let prefix = cursor.as_mut().unwrap();
    let pending = reader.terminal.as_mut().unwrap();
    let gap = pending.gap.as_mut().unwrap();
    context.with(|| gap.decode(2, prefix, &budget)).unwrap();
    let original_gap: *const CommittedBlock = gap.borrowed();
    let original_committee = gap
        .borrowed()
        .commitment()
        .schedule
        .current
        .committee
        .as_ptr();
    let consumed = context.consumed_allocated_bytes();
    let refused = context.with(|| {
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, 0, usize::MAX, usize::MAX, 128),
            || verifier.prepare_advance(prefix, gap.borrowed(), None),
        )
    });
    assert!(
        matches!(refused, Err(ExecutionAttemptError::Deferred(_))),
        "actual certificate decoder must keep local refusal distinct from rejection"
    );
    assert_eq!(prefix.tip.height(), 1);
    assert!(std::ptr::eq::<CommittedBlock>(gap.borrowed(), original_gap));
    assert_eq!(
        gap.borrowed()
            .commitment()
            .schedule
            .current
            .committee
            .as_ptr(),
        original_committee
    );
    assert!(context.consumed_allocated_bytes() >= consumed);
    drop(cursor);
    assert!(std::ptr::eq::<CommittedBlock>(
        reader.terminal_target_for_test().unwrap(),
        target
    ));
    let (delivered, counts) =
        relation_counts::measure(|| context.with(|| reader.certified_terminal_amx(3)));
    let delivered = delivered.unwrap();
    assert!(
        counts.frames.is_empty(),
        "original target and gap result decoders must not restart"
    );
    assert_eq!(counts.qcs, [2, 3]);
    assert_eq!(delivered.height(), 3);
    assert_eq!(
        reader.prefix.lock().as_ref().unwrap().tip.height(),
        2,
        "terminal target is not duplicated as another cursor tip"
    );
    assert!(reader.certified_terminal_amx(3).is_err());
    assert_eq!(
        context.with(|| reader.certified(1)).unwrap().verification(),
        QcVerification::Genesis
    );
    let receipts = context
        .with(|| reader.walk(1, 3).collect::<Result<Vec<_>, _>>())
        .unwrap();
    assert_eq!(
        receipts
            .iter()
            .map(|block| block.height())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(reader.prefix.lock().as_ref().unwrap().tip.height(), 3);
}

#[test]
fn terminal_source_substitution_and_other_height_refuse_without_replacing_original() {
    let chain = chain();
    let view = chain.state().view();
    let budget = view.execution_budget();
    let context = decoder(&budget);
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let loan = pressure(&mut reader, &budget);
    assert!(matches!(
        context.with(|| reader.certified_terminal_amx(3)),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    let target = target_pointer(&reader);
    let consumed = context.consumed_allocated_bytes();
    assert!(matches!(
        context.with(|| reader.certified_terminal_amx(2)),
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 2
        }))
    ));
    let foreign = AllocationBudget::new(budget.limit_bytes());
    assert!(matches!(
        context.with(|| reader.select_terminal_amx(3, &foreign)),
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 3
        }))
    ));
    assert!(std::ptr::eq::<CommittedBlock>(
        reader.terminal_target_for_test().unwrap(),
        target
    ));
    assert_eq!(foreign.reserved_bytes(), 0);
    assert_eq!(
        context.consumed_allocated_bytes(),
        consumed,
        "foreign height/pool cannot start another acquisition or clobber pending original work"
    );
    assert!(
        reader.certified(1).is_err(),
        "ordinary reset cannot discard a live pending terminal job"
    );
    drop(loan.lock().unwrap().take());
    let path = Kura::canonical_storage_path(&chain.kura().store_root()).join("blocks.data");
    let original_path = path.with_extension("terminal-original");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::rename(&path, &original_path).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let refused = context.with(|| reader.certified_terminal_amx(3));
    // Restore the exact original inode before any assertion can unwind this genuine fixture.
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(&original_path, &path).unwrap();
    assert!(matches!(
        refused,
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 3
        }))
    ));
    assert!(std::ptr::eq::<CommittedBlock>(
        reader.terminal_target_for_test().unwrap(),
        target
    ));
    assert_eq!(
        context
            .with(|| reader.certified_terminal_amx(3))
            .unwrap()
            .height(),
        3
    );
}

#[test]
fn terminal_schedule_failure_after_valid_qc_cannot_deliver_original_target() {
    let chain = chain();
    let view = chain.state().view();
    let budget = view.execution_budget();
    let context = decoder(&budget);
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let loan = pressure(&mut reader, &budget);
    assert!(matches!(
        context.with(|| reader.certified_terminal_amx(3)),
        Err(ExecutionAttemptError::Deferred(_))
    ));
    drop(loan.lock().unwrap().take());
    let mut cursor = reader.prefix.lock();
    let prefix = cursor.as_mut().unwrap();
    let pending = reader.terminal.as_mut().unwrap();
    let gap = pending.gap.as_mut().unwrap();
    context.with(|| gap.decode(2, prefix, &budget)).unwrap();
    let prepared = context
        .with(|| {
            PrefixVerifierContext {
                instance: reader.instance,
                root_scope: reader.root_scope,
            }
            .prepare_advance(prefix, gap.borrowed(), None)
        })
        .unwrap();
    prefix.tip = gap.take();
    prefix.schedule = prepared.schedule;
    prefix.authority = prepared.authority;
    prefix.proof_source = prepared.proof_source;
    pending.gap = None;
    // Adversarial private-path corruption after frame validation leaves the genuine header/R
    // and QC untouched, so only the required later schedule advancement can reject this graph.
    let (original_x, mut corrupt_body) = pending
        .target
        .borrowed()
        .certified_result
        .clone()
        .into_parts();
    corrupt_body.schedule.height += 1;
    let original_result = std::mem::replace(
        &mut pending.target.committed.as_mut().unwrap().as_mut_slice()[0].certified_result,
        CertifiedResultV1::from_parts_unvalidated(original_x, corrupt_body),
    );
    drop(cursor);
    let (refused, counts) =
        relation_counts::measure(|| context.with(|| reader.certified_terminal_amx(3)));
    let pending = reader.terminal.as_mut().unwrap();
    pending.target.committed.as_mut().unwrap().as_mut_slice()[0].certified_result = original_result;
    assert!(matches!(
        refused,
        Err(ExecutionAttemptError::Rejected(ChainReadError::Committee {
            height: 3,
            ..
        }))
    ));
    assert_eq!(
        counts.qcs,
        [3],
        "actual valid QC must precede the fallible schedule guard"
    );
    assert!(
        !pending.delivered && pending.target.committed.as_ref().unwrap().as_slice().len() == 1,
        "terminal target cannot escape before successful schedule advancement"
    );
    assert_eq!(
        context
            .with(|| reader.certified_terminal_amx(3))
            .unwrap()
            .height(),
        3
    );
}

// The canonical scratch callback is shared by query and terminal-prefix readers. These
// controls isolate its two requests after the actual public terminal owner acquired the
// original target and retained the genuine predecessor after original-pool refusal.
fn terminal_amx_original_scratch_admission(rs16_only: bool) {
    use iroha_sumeragi::availability::AvailabilityFrame;

    let chain = chain();
    let view = chain.state().view();
    let budget = view.execution_budget();
    let context = decoder(&budget);
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let loan = pressure(&mut reader, &budget);
    assert!(matches!(
        context.with(|| reader.certified_terminal_amx(3)),
        Err(ExecutionAttemptError::Deferred(ref local))
            if matches!(local.allocation_refusal(),
                Some(iroha_allocation::AllocationRefusal::Capacity { .. }))
    ));
    let original_target = target_pointer(&reader);
    drop(loan.lock().unwrap().take());

    let verifier = PrefixVerifierContext {
        instance: reader.instance,
        root_scope: reader.root_scope,
    };
    let mut cursor = reader.prefix.lock();
    let prefix = cursor.as_mut().unwrap();
    let pending = reader.terminal.as_mut().unwrap();
    let gap = pending.gap.as_mut().unwrap();
    context.with(|| gap.decode(2, prefix, &budget)).unwrap();
    let original_gap: *const CommittedBlock = gap.borrowed();
    let original_body = gap.borrowed().block().clone();
    let original_authority = Arc::as_ptr(&prefix.authority);
    let original_tip = prefix.tip.id();
    let original_schedule = prefix.schedule.clone();
    let original_source = prefix.proof_source;

    // Warm only the existing exact-value validation workspace, without installing a
    // schedule, certificate, source or authority verdict. The measured certificate path
    // then has no optional epoch-cache decoder debit hiding its scratch request.
    let config = context.with(|| {
        let config = prefix
            .schedule
            .ready(2)
            .unwrap()
            .height_config_with_validation(&mut prefix.validation)
            .unwrap();
        prefix
            .schedule
            .advanced_with_validation(
                &gap.borrowed().commitment().schedule,
                &mut prefix.validation,
            )
            .unwrap();
        config
    });
    let certificate = original_body.commit_certificate().unwrap();
    let before_codec = context.consumed_allocated_bytes();
    let table: AvailabilityFrame = context.with(|| {
        let qc: Qc = norito::decode_canonical(certificate.commit_qc()).unwrap();
        assert_eq!(qc.height, 2);
        norito::decode_canonical(certificate.availability()).unwrap()
    });
    let codec = context.consumed_allocated_bytes() - before_codec;
    let header = gap.borrowed().header().unwrap();
    let verified = iroha_sumeragi::availability::verify_availability(
        header.instance,
        &config,
        header,
        table.as_slice(),
        &prefix.authority.crypto,
    )
    .unwrap();
    let shape = verified.shape();
    let scratch = shape
        .encoded_bytes()
        .checked_add(
            shape
                .workspace_words()
                .checked_mul(size_of::<u16>())
                .unwrap(),
        )
        .unwrap();
    let payload = usize::try_from(header.payload_len).unwrap();
    assert!(payload > 0 && scratch > 0);
    let codec = usize::try_from(codec).unwrap();
    let exact = if rs16_only {
        scratch
    } else {
        codec
            .checked_add(payload)
            .unwrap()
            .checked_add(scratch)
            .unwrap()
    };
    let refusal_limit = if rs16_only {
        scratch - 1
    } else {
        codec.checked_add(payload).unwrap() - 1
    };
    drop(verified);
    drop(table);

    // Only the RS16 control supplies the existing funded artifact owner; this eliminates
    // ordinary QC/table decoding and proposal projection without replacing any validator.
    // The other control takes the exact None-artifact branch used by terminal AMX.
    let artifacts = |prepared: bool| {
        prepared.then(|| {
            context.with(|| {
                artifacts::PrefixArtifactsRead::new(original_body.clone(), budget.clone())
                    .complete(&budget)
                    .unwrap_or_else(|(_, cause)| panic!("original artifacts: {cause}"))
            })
        })
    };
    let retained = budget.reserved_bytes();
    let refused_artifacts = artifacts(rs16_only);
    let refused = context.with(|| {
        norito::core::with_decode_limits_scope(
            norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, refusal_limit, 128),
            || verifier.prepare_advance(prefix, gap.borrowed(), refused_artifacts),
        )
    });
    let stage = if rs16_only { "RS16" } else { "payload" };
    assert!(
        matches!(&refused, Err(ExecutionAttemptError::Deferred(local))
            if local.reason() == ivm::error::ExecutionDeferral::ActiveMemoryCapacity),
        "terminal AMX prefix must refuse original {stage} admission before allocation: {:?}",
        refused.as_ref().err(),
    );
    assert_eq!(prefix.tip.id(), original_tip);
    assert_eq!(prefix.schedule, original_schedule);
    assert_eq!(Arc::as_ptr(&prefix.authority), original_authority);
    assert_eq!(prefix.proof_source, original_source);
    assert!(std::ptr::eq::<CommittedBlock>(gap.borrowed(), original_gap));
    assert!(SharedSignedBlock::ptr_eq(
        gap.borrowed().block(),
        &original_body
    ));
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(!pending.delivered);

    let admitted_artifacts = artifacts(rs16_only);
    let before = context.consumed_allocated_bytes();
    let prepared = context
        .with(|| {
            norito::core::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, exact, 128),
                || verifier.prepare_advance(prefix, gap.borrowed(), admitted_artifacts),
            )
        })
        .unwrap();
    assert_eq!(
        context.consumed_allocated_bytes() - before,
        u64::try_from(exact).unwrap(),
        "the exact canonical {stage} allowance must be debited to the original context",
    );
    assert_eq!(prepared.certificate.verification, QcVerification::Verified);
    assert_eq!(prepared.certificate.commit_qc.as_ref().unwrap().height, 2);
    assert_eq!(prefix.tip.id(), original_tip);
    assert_eq!(prefix.schedule, original_schedule);
    assert_eq!(Arc::as_ptr(&prefix.authority), original_authority);
    drop(prepared);
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(std::ptr::eq::<CommittedBlock>(gap.borrowed(), original_gap));
    assert!(!pending.delivered);
    drop(cursor);
    assert!(std::ptr::eq::<CommittedBlock>(
        reader.terminal_target_for_test().unwrap(),
        original_target,
    ));
    let (delivered, counts) =
        relation_counts::measure(|| context.with(|| reader.certified_terminal_amx(3)));
    let delivered = delivered.unwrap();
    assert_eq!(delivered.height(), 3);
    assert!(
        counts.frames.is_empty(),
        "completed original target/gap decoders never restart"
    );
    assert_eq!(counts.qcs, [2, 3]);
    assert_eq!(reader.prefix.lock().as_ref().unwrap().tip.height(), 2);
}

#[test]
fn terminal_amx_prefix_refuses_original_payload_scratch_without_advancing() {
    terminal_amx_original_scratch_admission(false);
}

#[test]
fn terminal_amx_prefix_refuses_original_rs16_scratch_without_advancing() {
    terminal_amx_original_scratch_admission(true);
}

// The genuine terminal reader owns the target and each missing predecessor. This control
// completes only earlier production stages before applying pressure at the actual receipt /
// result allocation boundary; it supplies no fabricated receipt, QC or authority.
fn terminal_late_result_slot(gap: bool, cancel: bool) {
    use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
    use std::{
        future::Future,
        mem::size_of,
        task::{Context, Poll},
    };

    // Only this operation or the explicit pressure owner may refund its measured pool.
    let _retirement_pin = crossbeam_epoch::pin();
    let chain = chain();
    let expected = chain.committed(3);
    let expected_hash = expected.block_hash();
    let expected_result = expected.result();
    drop(expected);
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let context = decoder(&budget);
    let mut reader = context.with(|| CertifiedChain::new(&view)).unwrap();
    let mut cursor = reader.prefix.lock();
    context
        .with(|| reader.prepare_certificate_prefix(&mut cursor, 3))
        .unwrap();
    let prefix = cursor.as_mut().unwrap();
    assert_eq!(prefix.tip.height(), 1);
    let original_tip = prefix.tip.id();
    let original_authority = Arc::as_ptr(&prefix.authority);
    let mut target = OriginalReceipt::new(&view, 3, &budget).unwrap();
    context.with(|| target.acquire_body()).unwrap();
    let target_body = target.body.as_ref().unwrap().clone();
    let mut original_gap = None;
    if gap {
        context.with(|| target.decode(3, prefix, &budget)).unwrap();
        let mut predecessor = OriginalReceipt::new(&view, 2, &budget).unwrap();
        context.with(|| predecessor.acquire_body()).unwrap();
        original_gap = Some(predecessor);
    }
    drop(cursor);
    reader.terminal = Some(TerminalSelection {
        target,
        gap: original_gap,
        height: 3,
        delivered: false,
        budget: budget.clone(),
    });
    let pending = reader.terminal.as_ref().unwrap();
    let selected = if gap {
        pending.gap.as_ref().unwrap()
    } else {
        &pending.target
    };
    let selected_body = selected.body.as_ref().unwrap().clone();
    let selected_wire = selected.acquisition.bytes_for_test().unwrap().as_slice();
    let wire_pointer = selected_wire.as_ptr();
    let wire_length = selected_wire.len();
    let mut prepaid = budget
        .try_reserve_bytes(ReleaseRegistration::allocation_layout().size())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    drop(prepaid);
    assert!(registration.belongs_to(&budget));
    let controls = budget.reserved_bytes();
    let receipt_bytes = size_of::<CommittedBlock>();
    let result_bytes = size_of::<CertifiedResultV1>();
    let occupied_bytes = budget.limit_bytes() - controls - receipt_bytes;
    let occupied = budget.try_reserve_bytes(occupied_bytes).unwrap();
    let AllocationRefusal::Capacity {
        release: expected_release,
        ..
    } = budget
        .try_reserve_bytes(receipt_bytes + result_bytes)
        .unwrap_err()
    else {
        panic!("the original pool has real temporary capacity pressure");
    };
    let Err(ExecutionAttemptError::Deferred(original)) =
        context.with(|| reader.certified_terminal_amx(3))
    else {
        panic!("the actual terminal result slot must refuse");
    };
    let Some(AllocationRefusal::Capacity {
        requested_bytes,
        reserved_bytes,
        limit_bytes,
        release,
    }) = original.allocation_refusal()
    else {
        panic!("preserve the original physical allocation refusal");
    };
    assert_eq!(*requested_bytes, result_bytes);
    assert_eq!(*reserved_bytes, budget.limit_bytes());
    assert_eq!(*limit_bytes, budget.limit_bytes());
    assert_eq!(release, &expected_release);
    let mut wait = Box::pin(release.clone().wait_for_release(&mut registration));
    let mut poll = Context::from_waker(std::task::Waker::noop());
    assert_eq!(
        wait.as_mut().poll(&mut poll),
        Poll::Pending,
        "a late terminal result refusal must retain its earlier receipt slot instead of self-waking"
    );
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
    let selected = if gap {
        reader.terminal.as_ref().unwrap().gap.as_ref().unwrap()
    } else {
        &reader.terminal.as_ref().unwrap().target
    };
    assert!(selected.committed.is_none());
    assert!(SharedSignedBlock::ptr_eq(
        selected.body.as_ref().unwrap(),
        &selected_body
    ));
    let wire = selected.acquisition.bytes_for_test().unwrap().as_slice();
    assert_eq!(wire.as_ptr(), wire_pointer);
    assert_eq!(wire.len(), wire_length);
    let cursor = reader.prefix.lock();
    assert_eq!(cursor.as_ref().unwrap().tip.id(), original_tip);
    assert_eq!(
        Arc::as_ptr(&cursor.as_ref().unwrap().authority),
        original_authority
    );
    drop(cursor);
    assert!(!reader.terminal.as_ref().unwrap().delivered);
    let Err(ExecutionAttemptError::Deferred(repeated)) =
        context.with(|| reader.certified_terminal_amx(3))
    else {
        panic!("the same original target must remain pending");
    };
    assert_eq!(repeated.allocation_refusal(), original.allocation_refusal());
    assert_eq!(wait.as_mut().poll(&mut poll), Poll::Pending);
    assert_eq!(budget.reserved_bytes(), budget.limit_bytes());

    if cancel {
        // Cancellation is the explicit retirement of this original operation. It is allowed
        // to wake the observed release, and must refund every real frame/slot/control owner.
        drop(reader);
        assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
        drop(wait);
        drop(registration);
        drop(context);
        drop(target_body);
        drop(selected_body);
        assert_eq!(budget.reserved_bytes(), baseline + occupied_bytes);
        drop(occupied);
        assert_eq!(budget.reserved_bytes(), baseline);
        return;
    }

    drop(occupied);
    assert_eq!(wait.as_mut().poll(&mut poll), Poll::Ready(()));
    drop(wait);
    let delivered = context.with(|| reader.certified_terminal_amx(3)).unwrap();
    assert_eq!(delivered.height(), 3);
    assert_eq!(delivered.block_hash(), expected_hash);
    assert_eq!(delivered.result(), expected_result);
    assert_eq!(delivered.verification(), QcVerification::Verified);
    assert!(SharedSignedBlock::ptr_eq(delivered.block(), &target_body));
    let cursor = reader.prefix.lock();
    assert_eq!(cursor.as_ref().unwrap().tip.height(), 2);
    if gap {
        assert!(SharedSignedBlock::ptr_eq(
            cursor.as_ref().unwrap().tip.block(),
            &selected_body
        ));
    }
    drop(cursor);
    assert!(matches!(
        context.with(|| reader.certified_terminal_amx(3)),
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 3
        }))
    ));
    drop(delivered);
    drop(reader);
    drop(context);
    drop(registration);
    drop(target_body);
    drop(selected_body);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn terminal_target_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel() {
    terminal_late_result_slot(false, false);
    terminal_late_result_slot(false, true);
}

#[test]
fn terminal_gap_result_slot_refusal_keeps_original_wait_and_refunds_on_cancel() {
    terminal_late_result_slot(true, false);
    terminal_late_result_slot(true, true);
}
