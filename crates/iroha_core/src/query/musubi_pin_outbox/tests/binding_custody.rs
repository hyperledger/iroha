//! Real original-State binding refusal, signed graph and charged frame lifetime controls.

use super::*;
use iroha_allocation::{AllocationBudget, AllocationRefusal, release::ReleaseRegistration};
use std::{
    future::Future as _,
    pin::Pin,
    task::{Context, Waker},
};

fn backing(signed: &SignedTransaction) -> *const InstructionBox {
    let iroha_data_model::transaction::Executable::Instructions(instructions) =
        signed.instructions()
    else {
        panic!("exact native Check fixture");
    };
    instructions.as_ptr()
}

#[test]
fn original_state_capacity_refusal_keeps_signed_graph_release_owner_and_deadline() {
    // Keep unrelated retired State generations live: neither their refunds nor their
    // release notifications may stand in for the explicit held-owner drop below.
    let _retirement_pin = crossbeam_epoch::pin();
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let signed = fixture.sign(prepared.instruction().clone().into());
    let signed_backing = backing(&signed);
    let original_wire = signed.encode_wire_v1().unwrap();
    let deadline = prepared.deadline();
    let challenge = prepared.instruction().challenge;
    let budget = fixture.chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let mut prepaid = budget
        .try_reserve(ReleaseRegistration::allocation_layout())
        .unwrap();
    let mut registration = ReleaseRegistration::from_reservation(&mut prepaid).unwrap();
    drop(prepaid);
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let failure = match prepared.bind_signed_transaction(signed) {
        Err(failure) => failure,
        Ok(_) => panic!("original State pool exhausted"),
    };
    assert!(failure.error().is_retryable());
    assert!(failure.rejection().is_none());
    assert_eq!(failure.deadline(), deadline);
    assert!(Arc::ptr_eq(
        &failure.0.prepared.state,
        fixture.chain.state()
    ));
    assert_eq!(failure.0.prepared.instruction.challenge, challenge);
    assert_eq!(
        backing(failure.0.signed.signed_transaction()),
        signed_backing
    );
    assert_eq!(
        failure
            .0
            .signed
            .signed_transaction()
            .encode_wire_v1()
            .unwrap(),
        original_wire
    );
    let NativeCheckBindingErrorV1::Deferred(original) = failure.error() else {
        panic!("State refusal lost");
    };
    let Some(AllocationRefusal::Capacity { release, .. }) = original.allocation_refusal() else {
        panic!("original release owner lost");
    };
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut context = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    let foreign = AllocationBudget::new(1);
    drop(foreign.try_reserve_bytes(1).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut context).is_pending());
    drop(held);
    assert!(Pin::new(&mut wait).poll(&mut context).is_ready());
    drop(wait);
    let pending = failure.retry().unwrap();
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(pending.prepared.instruction.challenge, challenge);
    assert!(Arc::ptr_eq(&pending.prepared.state, fixture.chain.state()));
    assert_eq!(backing(pending.signed_transaction()), signed_backing);
    assert_eq!(
        pending.signed_transaction().encode_wire_v1().unwrap(),
        original_wire
    );
    drop(registration);
    assert_eq!(
        budget.reserved_bytes(),
        baseline + pending.bound.canonical_external().len()
    );
    drop(pending);
    assert_eq!(budget.reserved_bytes(), baseline);
}

#[test]
fn original_codec_refusal_is_retained_and_retry_uses_canonical_flags() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let signed = fixture.sign(prepared.instruction().clone().into());
    let signed_backing = backing(&signed);
    let original =
        norito::encode_canonical(&TransactionEntrypoint::External(signed.clone())).unwrap();
    let deadline = prepared.deadline();
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let failure =
        match norito::with_decode_limits_scope(zero, || prepared.bind_signed_transaction(signed)) {
            Err(failure) => failure,
            Ok(_) => panic!("caller zero allocation scope must survive binding"),
        };
    assert!(matches!(
        failure.error(),
        NativeCheckBindingErrorV1::Codec {
            original: norito::Error::TotalAllocationExceeded { .. },
            local: Some(_)
        }
    ));
    assert_eq!(
        backing(failure.0.signed.signed_transaction()),
        signed_backing
    );
    assert_eq!(failure.deadline(), deadline);
    let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let guard = norito::core::DecodeFlagsGuard::enter(flags);
    let probe = vec![1_u64, 2, 3, 5, 8, 13];
    let ambient_frame = norito::core::to_bytes(&probe).unwrap();
    assert_ne!(ambient_frame, norito::encode_canonical(&probe).unwrap());
    let pending = failure.retry().unwrap();
    assert_eq!(
        norito::core::to_bytes(&probe).unwrap(),
        ambient_frame,
        "canonical binding must restore the caller's observable ambient layout"
    );
    assert_eq!(pending.bound.canonical_external(), original);
    assert_eq!(backing(pending.signed_transaction()), signed_backing);
    assert_eq!(pending.deadline(), deadline);
    drop(guard);
}

#[test]
fn expiry_after_refusal_returns_same_signed_owner_without_codec_or_pool_retry() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let signed = fixture.sign(prepared.instruction().clone().into());
    let signed_backing = backing(&signed);
    let zero = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 128);
    let mut failure =
        match norito::with_decode_limits_scope(zero, || prepared.bind_signed_transaction(signed)) {
            Err(failure) => failure,
            Ok(_) => panic!("original scope exhausted"),
        };
    failure.0.prepared.round.expire_for_test();
    let deadline = failure.deadline();
    let failure = match norito::with_decode_limits_scope(zero, || failure.retry()) {
        Err(failure) => failure,
        Ok(_) => panic!("original deadline remains expired"),
    };
    assert_eq!(failure.rejection(), Some(Error::Expired));
    assert!(!failure.error().is_retryable());
    assert_eq!(failure.deadline(), deadline);
    assert_eq!(
        backing(failure.0.signed.signed_transaction()),
        signed_backing
    );
    let failure = match failure.retry() {
        Err(failure) => failure,
        Ok(_) => panic!("terminal owner cannot restart"),
    };
    assert_eq!(failure.rejection(), Some(Error::Expired));
    assert_eq!(failure.deadline(), deadline);
    assert_eq!(
        backing(failure.0.signed.signed_transaction()),
        signed_backing
    );
}

#[test]
fn substituted_signature_is_terminal_and_retains_original_graph() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let mut wrong = prepared.instruction().clone();
    wrong.challenge[0] ^= 1;
    let signed = fixture.sign(wrong.into());
    let signed_backing = backing(&signed);
    let failure = match prepared.bind_signed_transaction(signed) {
        Err(failure) => failure,
        Ok(_) => panic!("challenge substitution"),
    };
    assert_eq!(failure.rejection(), Some(Error::Transaction));
    assert!(!failure.error().is_retryable());
    let failure = match failure.retry() {
        Err(failure) => failure,
        Ok(_) => panic!("cannot replace the original signed attempt"),
    };
    assert_eq!(failure.rejection(), Some(Error::Transaction));
    assert_eq!(
        backing(failure.0.signed.signed_transaction()),
        signed_backing
    );
}

#[test]
fn final_readback_moves_original_charged_frame_and_releases_only_on_final_drop() {
    // Isolate this exact frame lifetime from deferred reclamation of old State generations.
    // The real epoch guard neither changes the original pool nor admits extra capacity.
    let _retirement_pin = crossbeam_epoch::pin();
    let mut fixture = Fixture::new();
    let pending = fixture.applied();
    let budget = fixture.chain.state().ivm_execution_budget();
    let baseline = budget.reserved_bytes();
    let original_pointer = pending.bound.canonical_external().as_ptr();
    let original_len = pending.bound.canonical_external().len();
    let verified = pending.verify_finalized().unwrap();
    assert_eq!(
        verified.bound.canonical_external().as_ptr(),
        original_pointer
    );
    assert_eq!(budget.reserved_bytes(), baseline);
    let readback = verified.consume_current(fixture.chain.state()).unwrap();
    assert_eq!(readback.canonical_external().as_ptr(), original_pointer);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(readback);
    assert_eq!(budget.reserved_bytes(), baseline - original_len);
}

#[test]
fn allocated_original_check_retains_exact_graph_through_frame_refusal_and_native_readback() {
    use iroha_data_model::transaction::signed::pin_allocation::AllocatedPinTransactionV1;
    let _retirement_pin = crossbeam_epoch::pin();
    let mut fixture = Fixture::new();
    let prepared = fixture.prepare();
    let original = fixture.sign(prepared.instruction().clone().into());
    let exact = original.encode_wire_v1().unwrap();
    let deadline = prepared.deadline();
    let budget = fixture.chain.state().ivm_execution_budget();
    let before = budget.reserved_bytes();
    let allocated = AllocatedPinTransactionV1::copy_from(&original, &budget).unwrap();
    let graph_bytes = allocated.allocation_bytes().unwrap();
    let pointer = backing(allocated.signed());
    let held = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let failure = prepared
        .bind_allocated_transaction(allocated)
        .err()
        .expect("original State pool full");
    assert!(failure.error().is_retryable());
    assert_eq!(backing(failure.0.signed.signed_transaction()), pointer);
    assert_eq!(failure.deadline(), deadline);
    drop(held);
    assert_eq!(budget.reserved_bytes(), before + graph_bytes);
    let pending = failure.retry().unwrap();
    assert_eq!(backing(pending.signed_transaction()), pointer);
    assert_eq!(
        pending.signed_transaction().encode_wire_v1().unwrap(),
        exact
    );
    assert_eq!(pending.deadline(), deadline);
    assert_eq!(
        budget.reserved_bytes(),
        before + graph_bytes + pending.bound.canonical_external().len()
    );
    // Execute the separately retained original signed envelope, never a synthesized output.
    assert!(fixture.chain.commit(vec![original])[0]);
    let readback = pending
        .verify_finalized()
        .unwrap()
        .consume_current(fixture.chain.state())
        .unwrap();
    assert_eq!(readback.high_water(), None);
    assert_eq!(readback.applied_floor().height, fixture.chain.height());
    assert!(!readback.canonical_external().is_empty());
    // Native State itself now owns new generations. Only the graph/frame delta is asserted above;
    // this test does not equate State's later complete allocation total with its earlier cut.
}

#[test]
fn allocated_check_rejects_a_different_pool_before_frame_allocation_without_losing_custody() {
    use iroha_data_model::transaction::signed::pin_allocation::AllocatedPinTransactionV1;
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    let signed = fixture.sign(prepared.instruction().clone().into());
    let foreign = AllocationBudget::new(1024 * 1024);
    let allocated = AllocatedPinTransactionV1::copy_from(&signed, &foreign).unwrap();
    let bytes = allocated.allocation_bytes().unwrap();
    let pointer = backing(allocated.signed());
    let failure = prepared
        .bind_allocated_transaction(allocated)
        .err()
        .expect("foreign pool");
    assert_eq!(failure.rejection(), Some(Error::Transaction));
    assert!(!failure.error().is_retryable());
    assert_eq!(backing(failure.0.signed.signed_transaction()), pointer);
    assert_eq!(foreign.reserved_bytes(), bytes);
    drop(failure);
    assert_eq!(foreign.reserved_bytes(), 0);
}
