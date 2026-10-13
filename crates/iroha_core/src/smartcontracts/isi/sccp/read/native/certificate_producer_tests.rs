//! Exact native certificate projection and original-pool destination custody.

use super::tests::{active_chain, control};
use super::*;
use crate::sumeragi::{certified_chain::CertifiedChain, test_chain::CertifiedTestChain};
use iroha_allocation::release::ReleaseRegistration;
use iroha_sccp::v1::finality::verify_certificate;
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    task::{Context, Poll, Waker},
};

// Construct the genuine native chain outside assertion-heavy frames, on the unchanged
// default stack. The fixture creates signed Log work; no empty block supplies authority.
#[inline(never)]
fn with_chain(assert_original: fn(&CertifiedTestChain)) {
    let mut chain = active_chain();
    chain.commit_at(2_000, Vec::new());
    let chain = Box::new(chain);
    assert_original(&chain);
}

#[test]
fn native_certificate_binds_exact_original_x_body_qc_and_historical_keys() {
    with_chain(|chain| {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let block = reader.certified(2).unwrap();
        assert!(block.block().network_entrypoint_count() > 0);
        let stop = AtomicBool::new(false);
        // The response owns its original request pool; asynchronous publication cleanup
        // in the separate State pool must not change this request's custody ledger.
        let budget = AllocationBudget::new(128 << 20);
        let occupied = budget.reserved_bytes();
        let retained = finality(&view, NonZeroU64::new(2), &budget, control(&stop)).unwrap();
        assert!(retained._charge.belongs_to(&budget));
        let certificate = retained.data();
        assert_eq!(certificate.height, block.height());
        assert_eq!(
            &certificate.header,
            block.certified_result().header().as_bytes()
        );
        let qc = block.commit_qc().unwrap();
        let fixed = QcFixedV1::parse(&certificate.qc).unwrap();
        assert_eq!(fixed.epoch, qc.epoch.epoch);
        assert_eq!(fixed.epoch_context, qc.epoch.context.0);
        assert_eq!(fixed.view, qc.view);
        assert_eq!(fixed.block_hash, qc.block_hash.0);
        assert_eq!(
            fixed.result_body,
            body_digest(&block.certificate().unwrap().result_preimage()[X_LEN..])
        );
        assert_eq!(
            fixed.signers,
            signers_from_bitmap(qc.signers.as_bytes(), certificate.committee.len()).unwrap()
        );
        assert_eq!(certificate.aggregate_signature, qc.agg_sig.0);
        assert_eq!(
            certificate.committee.len(),
            block.commitment().schedule.current.committee.len()
        );
        for (key, original) in certificate
            .committee
            .iter()
            .zip(&block.commitment().schedule.current.committee)
        {
            assert_eq!(
                key.as_slice(),
                original.validator.public_key().try_to_bytes().unwrap().1
            );
        }
        let verified = verify_certificate(
            &qc.instance.0,
            &certificate.qc,
            &certificate.header,
            &certificate.aggregate_signature,
            &certificate.committee,
        )
        .unwrap();
        assert_eq!(verified.result, block.result().0);
        let destination_bytes = size_of::<SccpCertificateV1>() + CERTIFICATE_HEAP_BYTES;
        assert_eq!(
            budget.reserved_bytes(),
            occupied + destination_bytes,
            "source and decoder scratch retire while the original response admission remains"
        );
        drop(retained);
        assert_eq!(budget.reserved_bytes(), occupied);
    });
}

#[test]
fn native_certificate_capacity_refusal_preserves_original_wait_and_retries_same_receipt() {
    with_chain(|chain| {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let block = reader.certified(2).unwrap();
        let original_x = *block.certified_result().header().as_bytes();
        let stop = AtomicBool::new(false);
        // The response owns its original request pool; asynchronous publication cleanup
        // in the separate State pool must not change this request's custody ledger.
        let budget = AllocationBudget::new(128 << 20);
        let mut reserve = budget
            .try_reserve(ReleaseRegistration::allocation_layout())
            .unwrap();
        let mut waiter = ReleaseRegistration::from_reservation(&mut reserve).unwrap();
        drop(reserve);
        let occupied = budget.reserved_bytes();
        let external = budget
            .try_reserve_bytes(budget.limit_bytes() - occupied)
            .unwrap();
        let error = finality(&view, NonZeroU64::new(2), &budget, control(&stop))
            .err()
            .expect("original pool refuses whole reservation");
        let SccpNativeReadError::Allocation(AllocationRefusal::Capacity {
            requested_bytes,
            reserved_bytes,
            limit_bytes,
            release,
        }) = &error
        else {
            panic!("original capacity refusal lost: {error:?}");
        };
        assert_eq!(
            *requested_bytes,
            size_of::<SccpCertificateV1>() + CERTIFICATE_HEAP_BYTES
        );
        assert_eq!(*reserved_bytes, budget.limit_bytes());
        assert_eq!(*limit_bytes, budget.limit_bytes());
        assert_eq!(budget.reserved_bytes(), budget.limit_bytes());
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Pending);
        assert_eq!(block.certified_result().header().as_bytes(), &original_x);
        drop(external);
        assert_eq!(waiter.poll_wait(release, &mut cx), Poll::Ready(()));
        let retained = finality(&view, NonZeroU64::new(2), &budget, control(&stop)).unwrap();
        assert!(retained._charge.belongs_to(&budget));
        assert_eq!(retained.data().header, original_x);
        drop(retained);
        assert_eq!(budget.reserved_bytes(), occupied);
        waiter.cancel();
    });
}

#[test]
fn native_certificate_owners_release_on_unwind_and_genesis_never_fabricates_qc() {
    with_chain(|chain| {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let genesis = reader.certified(1).unwrap();
        assert!(genesis.commit_qc().is_none());
        let stop = AtomicBool::new(false);
        // The response owns its original request pool; asynchronous publication cleanup
        // in the separate State pool must not change this request's custody ledger.
        let budget = AllocationBudget::new(128 << 20);
        let occupied = budget.reserved_bytes();
        assert!(matches!(
            finality(&view, NonZeroU64::new(1), &budget, control(&stop)),
            Err(SccpNativeReadError::Request(_))
        ));
        assert_eq!(budget.reserved_bytes(), occupied);
        let retained = finality(&view, NonZeroU64::new(2), &budget, control(&stop)).unwrap();
        let retained_bytes = budget.reserved_bytes();
        assert_eq!(
            retained_bytes,
            occupied + size_of::<SccpCertificateV1>() + CERTIFICATE_HEAP_BYTES
        );
        assert!(
            catch_unwind(AssertUnwindSafe(|| {
                let another = finality(&view, NonZeroU64::new(2), &budget, control(&stop)).unwrap();
                assert_eq!(another.data(), retained.data());
                assert_eq!(
                    budget.reserved_bytes(),
                    retained_bytes + size_of::<SccpCertificateV1>() + CERTIFICATE_HEAP_BYTES
                );
                panic!("unwind a separate original certificate owner");
            }))
            .is_err()
        );
        assert_eq!(budget.reserved_bytes(), retained_bytes);
        assert_eq!(retained.data().height, 2);
        drop(retained);
        assert_eq!(budget.reserved_bytes(), occupied);
    });
}

#[test]
fn native_latest_genesis_is_unavailable_until_first_commit() {
    let mut chain = active_chain();
    check_latest_genesis_then_commit(&mut chain);
}

#[inline(never)]
fn check_latest_genesis_then_commit(chain: &mut CertifiedTestChain) {
    let stop = AtomicBool::new(false);
    // The response owns its original request pool; asynchronous publication cleanup
    // in the separate State pool must not change this request's custody ledger.
    let budget = AllocationBudget::new(128 << 20);
    {
        let view = chain.state().view();
        let reader = CertifiedChain::new(&view).unwrap();
        let genesis = reader.certified(1).unwrap();
        let occupied = budget.reserved_bytes();
        assert!(genesis.commit_qc().is_none());
        assert_eq!(view.height(), 1);
        assert!(matches!(
            finality(&view, NonZeroU64::new(1), &budget, control(&stop)),
            Err(SccpNativeReadError::Request(_))
        ));
        assert_eq!(budget.reserved_bytes(), occupied);
        assert!(matches!(
            finality(&view, None, &budget, control(&stop)),
            Err(SccpNativeReadError::Unavailable(_))
        ));
        assert_eq!(budget.reserved_bytes(), occupied);
    }
    // The fixture commits a genuine signed Log entry when no caller transaction is supplied.
    chain.commit_at(2_000, Vec::new());
    let view = chain.state().view();
    let occupied = budget.reserved_bytes();
    let latest = finality(&view, None, &budget, control(&stop)).unwrap();
    let explicit = finality(&view, NonZeroU64::new(2), &budget, control(&stop)).unwrap();
    assert_eq!(latest.data().height, 2);
    assert_eq!(latest.data(), explicit.data());
    drop((latest, explicit));
    assert_eq!(budget.reserved_bytes(), occupied);
}
