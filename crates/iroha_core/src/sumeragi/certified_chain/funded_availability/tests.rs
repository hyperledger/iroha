//! Exact RS16 scratch ownership, retry provenance and canonical-verifier parity.

use super::*;
use crate::{
    state::World,
    sumeragi::{
        certified_chain::artifacts::PrefixArtifactsRead,
        crypto::BlsCrypto,
        schedule::ScheduledSlot,
        test_chain::{CertifiedTestChain, TestChainConfig},
    },
    test_allocations::{allocations_during, refuse_one_layout_during},
};
use std::{
    future::Future as _,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Waker},
};

#[test]
fn availability_scratch_exact_layouts_move_without_allocation_and_retire_on_unwind() {
    let bytes = Scratch::demand(257, 131).unwrap();
    assert_eq!(bytes, 257 + 2 * 131);
    assert!(Scratch::demand(usize::MAX, 1).is_err());
    assert!(Scratch::demand(1, usize::MAX).is_err());
    let budget = AllocationBudget::new(bytes);
    let mut original = budget.try_reserve_bytes(bytes).unwrap();
    let mut scratch = None;
    let allocations = allocations_during(|| {
        scratch = Some(Scratch::from_reservation(257, 131, &budget, &mut original).unwrap());
    });
    assert_eq!(allocations, 2, "only the two exact scratch backings");
    assert_eq!(original.remaining_bytes(), 0);
    let scratch = scratch.unwrap();
    assert!(scratch.codeword.belongs_to(&budget) && scratch.workspace.belongs_to(&budget));
    assert_eq!(scratch.codeword.as_slice(), &[0; 257]);
    assert_eq!(scratch.workspace.as_slice(), &[0; 131]);
    let codeword = scratch.codeword.as_slice().as_ptr();
    let workspace = scratch.workspace.as_slice().as_ptr();
    drop(original);
    assert_eq!(budget.reserved_bytes(), bytes);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let moved = scratch;
        assert_eq!(moved.codeword.as_slice().as_ptr(), codeword);
        assert_eq!(moved.workspace.as_slice().as_ptr(), workspace);
        assert_eq!(budget.reserved_bytes(), bytes);
        panic!("controlled exact RS16 scratch unwind");
    }));
    assert!(unwind.is_err());
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn availability_scratch_rejects_foreign_reservation_before_partition() {
    let bytes = Scratch::demand(257, 131).unwrap();
    let original_pool = AllocationBudget::new(bytes);
    let foreign_pool = AllocationBudget::new(bytes);
    let mut original = original_pool.try_reserve_bytes(bytes).unwrap();
    let result = Scratch::from_reservation(257, 131, &foreign_pool, &mut original);
    assert!(
        result.is_err(),
        "RS16 scratch rejects a foreign original reservation before allocation"
    );
    assert_eq!(original.remaining_bytes(), bytes);
    assert_eq!(original_pool.reserved_bytes(), bytes);
    assert_eq!(foreign_pool.reserved_bytes(), 0);
    let error = result.err().unwrap();
    assert_eq!(
        error.reason(),
        ivm::error::ExecutionDeferral::LocalInvariantViolation
    );
    assert!(error.allocation_refusal().is_none());
}

#[test]
fn availability_scratch_each_allocator_failure_keeps_exact_physical_cause() {
    let bytes = Scratch::demand(257, 131).unwrap();
    let budget = AllocationBudget::new(bytes);
    for layout in [
        Layout::array::<u8>(257).unwrap(),
        Layout::array::<u16>(131).unwrap(),
    ] {
        let mut original = budget.try_reserve_bytes(bytes).unwrap();
        let (result, refused) = refuse_one_layout_during(layout, || {
            Scratch::from_reservation(257, 131, &budget, &mut original)
        });
        assert!(refused, "actual requested backing {layout:?}");
        let error = result.err().expect("physical failure stays local");
        assert_eq!(
            error.reason(),
            ivm::error::ExecutionDeferral::AllocationUnavailable
        );
        assert!(error.allocation_refusal().is_none());
        assert!(matches!(
            error.allocator_refusal().unwrap().buffer_from_charge_error(),
            Some(ChargedBufferFromChargeError::Allocator { layout: actual }) if *actual == layout
        ));
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut original = budget.try_reserve_bytes(bytes).unwrap();
        let retry = Scratch::from_reservation(257, 131, &budget, &mut original).unwrap();
        assert_eq!(original.remaining_bytes(), 0);
        drop(retry);
        drop(original);
        assert_eq!(budget.reserved_bytes(), 0);
    }
}

#[test]
fn funded_availability_keeps_canonical_relations_admission_order_and_original_release() {
    let mut chain =
        Box::new(CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap());
    chain.commit(Vec::new());
    check_canonical_source(&chain);
}

#[inline(never)]
fn check_canonical_source(chain: &CertifiedTestChain) {
    let parent = chain.committed(1);
    let ScheduledSlot::Ready(scheduled) = &parent.commitment().schedule.next else {
        panic!("genuine committed successor schedule")
    };
    let config = scheduled.height_config().unwrap();
    let source = chain
        .kura()
        .get_block(
            NonZeroUsize::new(2).unwrap(),
            &chain.state().ivm_execution_budget(),
        )
        .unwrap()
        .unwrap();
    let budget = AllocationBudget::new(1 << 26);
    let artifacts = PrefixArtifactsRead::new(source.clone(), budget.clone())
        .complete(&budget)
        .unwrap_or_else(|(_, error)| panic!("genuine canonical artifacts: {error}"));
    let header = artifacts.header().clone();
    let (_qc, table, payload) = artifacts
        .into_parts(
            &source,
            &crate::sumeragi::certified_chain::PrefixHeader::Funded(header.clone()),
        )
        .unwrap();
    let crypto = BlsCrypto::new();
    let shape = config
        .epoch
        .da_layout
        .shape(u64::from(header.payload_len))
        .unwrap();
    let bytes = Scratch::demand(shape.encoded_bytes(), shape.workspace_words()).unwrap();
    let retained = budget.reserved_bytes();
    let payload_pointer = payload.as_slice().as_ptr();
    let table_pointer = table.as_slice().as_ptr();
    let mut admitted = 0;
    verify(
        header.instance,
        &config,
        &header,
        &table,
        payload.as_slice(),
        &crypto,
        &budget,
        &mut |actual| {
            assert_eq!(actual, bytes);
            admitted += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(admitted, 1);
    assert_eq!(budget.reserved_bytes(), retained);
    iroha_data_model::sumeragi_finality::verify_payload_availability(
        header.instance,
        &config,
        &header,
        &table,
        payload.as_slice(),
        &crypto,
    )
    .unwrap();

    for layout in [
        Layout::array::<u8>(shape.encoded_bytes()).unwrap(),
        Layout::array::<u16>(shape.workspace_words()).unwrap(),
    ] {
        let (result, refused) = refuse_one_layout_during(layout, || {
            verify(
                header.instance,
                &config,
                &header,
                &table,
                payload.as_slice(),
                &crypto,
                &budget,
                &mut |_| Ok(()),
            )
        });
        assert!(refused);
        let Err(VerificationReadError::Deferred(original)) = result else {
            panic!("genuine signed availability preserves a physical scratch refusal")
        };
        assert!(original.allocation_refusal().is_none());
        assert!(matches!(
            original.allocator_refusal().unwrap().buffer_from_charge_error(),
            Some(ChargedBufferFromChargeError::Allocator { layout: actual }) if *actual == layout
        ));
        assert_eq!(budget.reserved_bytes(), retained);
        assert_eq!(payload.as_slice().as_ptr(), payload_pointer);
        assert_eq!(table.as_slice().as_ptr(), table_pointer);
    }

    let original_refusal = AllocationBudget::new(0)
        .try_reserve_bytes(bytes)
        .unwrap_err();
    let result = verify(
        header.instance,
        &config,
        &header,
        &table,
        payload.as_slice(),
        &crypto,
        &budget,
        &mut |_| Err(original_refusal.clone().into()),
    );
    let Err(VerificationReadError::Deferred(actual)) = result else {
        panic!("unchanged caller admission refusal")
    };
    assert_eq!(actual.allocation_refusal(), Some(&original_refusal));
    assert_eq!(budget.reserved_bytes(), retained);
    assert!(matches!(
        verify(
            Hash32([0; 32]),
            &config,
            &header,
            &table,
            payload.as_slice(),
            &crypto,
            &budget,
            &mut |_| panic!("invalid signed source must precede scratch admission"),
        ),
        Err(VerificationReadError::Source(_))
    ));
    let wrong_payload = &payload.as_slice()[1..];
    assert!(matches!(
        verify(
            header.instance,
            &config,
            &header,
            &table,
            wrong_payload,
            &crypto,
            &budget,
            &mut |_| Ok(()),
        ),
        Err(VerificationReadError::Source(_))
    ));
    assert!(
        iroha_data_model::sumeragi_finality::verify_payload_availability(
            header.instance,
            &config,
            &header,
            &table,
            wrong_payload,
            &crypto,
        )
        .is_err()
    );

    let registration_bytes =
        iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    let mut registration_credit = budget.try_reserve_bytes(registration_bytes).unwrap();
    let mut registration =
        iroha_allocation::release::ReleaseRegistration::from_reservation(&mut registration_credit)
            .unwrap();
    drop(registration_credit);
    let occupied = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
        .unwrap();
    let Err(VerificationReadError::Deferred(original)) = verify(
        header.instance,
        &config,
        &header,
        &table,
        payload.as_slice(),
        &crypto,
        &budget,
        &mut |_| Ok(()),
    ) else {
        panic!("HC959 RS16 scratch is charged to the captured original pool")
    };
    let Some(AllocationRefusal::Capacity {
        requested_bytes,
        release,
        ..
    }) = original.allocation_refusal()
    else {
        panic!("original pool release observation")
    };
    assert_eq!(*requested_bytes, bytes);
    let mut wait = release.clone().wait_for_release(&mut registration);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    let foreign = AllocationBudget::new(bytes);
    drop(foreign.try_reserve_bytes(bytes).unwrap());
    assert!(Pin::new(&mut wait).poll(&mut cx).is_pending());
    assert_eq!(payload.as_slice().as_ptr(), payload_pointer);
    assert_eq!(table.as_slice().as_ptr(), table_pointer);
    drop(occupied);
    assert!(Pin::new(&mut wait).poll(&mut cx).is_ready());
    drop(wait);
    verify(
        header.instance,
        &config,
        &header,
        &table,
        payload.as_slice(),
        &crypto,
        &budget,
        &mut |_| Ok(()),
    )
    .unwrap();
    drop(registration);
    assert_eq!(budget.reserved_bytes(), retained);
}
