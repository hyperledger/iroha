//! Same native acquisition, original prepaid body and cumulative decoder through refusal.

use super::*;
use crate::{
    state::{StateReadOnly, World},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_allocation::AllocationRefusal;
use norito::core::DecodeBudgetContext;

#[test]
fn original_prepaid_native_body_delivers_once_without_repeat_allocation_or_decode() {
    let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
    chain.commit_at(2_000, Vec::new());
    let view = chain.state().view();
    let budget = view.execution_budget();
    let baseline = budget.reserved_bytes();
    let decoder = DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, 128),
        &budget,
    )
    .unwrap();
    let index = NonZeroUsize::new(2).unwrap();
    let expected = *view.block_hashes().get(1).unwrap();
    let length = decoder
        .with(|| chain.kura().native_frame_read(2, expected))
        .unwrap()
        .unwrap()
        .wire_len();
    let length = usize::try_from(length).unwrap();
    let mut acquisition =
        NativeCarrierAcquisition::new(chain.kura(), index, expected, budget.clone(), length);
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes() - length)
        .unwrap();
    let refused = decoder.with(|| acquisition.complete());
    assert!(
        matches!(refused,
        Err(ExecutionAttemptError::Deferred(ref local))
            if matches!(local.allocation_refusal(), Some(AllocationRefusal::Capacity { .. }))),
        "original shared body shell must refuse before native body decoding"
    );
    let original_bytes = acquisition.bytes.as_ref().unwrap().as_slice().as_ptr();
    assert!(acquisition.bytes.as_ref().unwrap().belongs_to(&budget));
    assert!(acquisition.decoded.is_none() && acquisition.shell.is_none());
    drop(pressure);

    decoder.with(|| acquisition.prepare()).unwrap();
    let original = acquisition.decoded.as_ref().unwrap().clone();
    assert!(original.belongs_to(&budget));
    assert_eq!(original.hash(), expected);
    assert_eq!(original.header().height().get(), 2);
    assert!(acquisition.shell.is_none());
    assert_eq!(
        acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(),
        original_bytes
    );
    let retained = budget.reserved_bytes();
    let consumed = decoder.consumed_allocated_bytes();
    let pressure = budget
        .try_reserve_bytes(budget.limit_bytes() - retained)
        .unwrap();
    decoder.with(|| acquisition.decode_original_body()).unwrap();
    assert_eq!(
        decoder.consumed_allocated_bytes(),
        consumed,
        "completed original body must not repeat its decoder work"
    );
    assert_eq!(
        budget.reserved_bytes(),
        budget.limit_bytes(),
        "completed body must retain the same prepaid control under full original capacity"
    );
    assert!(SharedSignedBlock::ptr_eq(
        acquisition.decoded.as_ref().unwrap(),
        &original
    ));
    let delivered = decoder.with(|| acquisition.complete()).unwrap();
    assert!(
        SharedSignedBlock::ptr_eq(&delivered, &original),
        "delivery must move the same original prepaid shared body"
    );
    assert!(delivered.belongs_to(&budget));
    assert_eq!(
        acquisition.bytes.as_ref().unwrap().as_slice().as_ptr(),
        original_bytes
    );
    assert!(acquisition.delivered && acquisition.decoded.is_none() && acquisition.shell.is_none());
    assert!(matches!(
        decoder.with(|| acquisition.complete()),
        Err(ExecutionAttemptError::Rejected(ChainReadError::NotInView {
            height: 2
        }))
    ));
    drop(pressure);
    assert_eq!(budget.reserved_bytes(), retained);
    budget.with_deferred_refund_notifications(|_| {
        drop(acquisition);
        drop(original);
        drop(delivered);
    });
    drop(decoder);
    drop(view);
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "last original native source/body owner must refund the actual original pool"
    );
}
