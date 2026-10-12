//! Original epoch allocation custody through partial unwind and planner refusal.

use super::*;
use crate::{
    state::{World, WorldReadOnly as _},
    sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
};
use iroha_crypto::{Algorithm, KeyPair};
use std::cell::Cell;

fn source_schedule() -> crate::sumeragi::schedule::RetainedConsensusSchedule {
    let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1000)).unwrap();
    let original = chain.state().view().world().consensus_schedule().clone();
    original
}

fn partial_unwind(stage: ConstructionCheckpoint) {
    let source = source_schedule();
    let encoded = norito::encode_canonical(source.canonical()).unwrap();
    let budget = AllocationBudget::new(1024 * 1024);
    let original = retain_schedule(source.canonical(), &budget).unwrap();
    let original_entries = original.entries().as_ptr();
    let original_key = original.ready(2).unwrap().epoch.committee[0]
        .validator
        .public_key()
        .borrowed_parts()
        .unwrap()
        .1
        .as_ptr();
    let baseline = budget.reserved_bytes();
    assert!(baseline > 0);
    CONSTRUCTION_UNWIND.with(|requested| requested.set(Some(stage)));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _candidate = retain_schedule(source.canonical(), &budget).unwrap();
    }));
    assert!(
        unwind.is_err(),
        "actual retained schedule construction must unwind"
    );
    assert!(
        CONSTRUCTION_UNWIND.with(|requested| requested.get().is_none()),
        "the real nested allocation/publication stage must be reached"
    );
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "all partial payload allocations retired before their exact original credit refund"
    );
    assert_eq!(original.entries().as_ptr(), original_entries);
    assert_eq!(
        original.ready(2).unwrap().epoch.committee[0]
            .validator
            .public_key()
            .borrowed_parts()
            .unwrap()
            .1
            .as_ptr(),
        original_key
    );
    assert_eq!(
        norito::encode_canonical(original.canonical()).unwrap(),
        encoded
    );
    let retry = retain_schedule(source.canonical(), &budget).unwrap();
    assert_eq!(retry, original);
    drop(retry);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}

#[test]
fn partial_epoch_key_unwind_refunds_retired_nested_backing() {
    partial_unwind(ConstructionCheckpoint::NestedKey);
}

#[test]
fn partial_epoch_committee_unwind_refunds_retired_nested_backing() {
    partial_unwind(ConstructionCheckpoint::NestedCommitteeMember);
}

#[test]
fn complete_epoch_schedule_unwind_before_shared_publication_preserves_original_reader() {
    partial_unwind(ConstructionCheckpoint::BeforeSharedShell);
}

#[test]
fn epoch_partial_payload_retires_before_its_original_ledger() {
    struct ObserveRetirement<'a> {
        key: Option<PublicKey>,
        pool: &'a AllocationBudget,
        charged: usize,
        retired: &'a Cell<bool>,
        retained_while_live: &'a Cell<bool>,
        retained_after_free: &'a Cell<bool>,
    }
    impl Drop for ObserveRetirement<'_> {
        fn drop(&mut self) {
            self.retained_while_live
                .set(self.pool.reserved_bytes() == self.charged);
            drop(self.key.take());
            self.retained_after_free
                .set(self.pool.reserved_bytes() == self.charged);
            self.retired.set(true);
        }
    }
    let pair = KeyPair::from_seed(vec![73; 32], Algorithm::BlsNormal);
    let source = pair.public_key();
    assert!(source.retained_allocation_layout().size() > 0);
    let budget = AllocationBudget::new(1024 * 1024);
    let retired = Cell::new(false);
    let retained_while_live = Cell::new(false);
    let retained_after_free = Cell::new(false);
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut demand = Demand::default();
        demand.key(source).unwrap();
        let mut owner = Construction::new(demand, &budget).unwrap();
        let key = owner.key(source).unwrap();
        let _payload = ObserveRetirement {
            key: Some(key),
            pool: &budget,
            charged: budget.reserved_bytes(),
            retired: &retired,
            retained_while_live: &retained_while_live,
            retained_after_free: &retained_after_free,
        };
        panic!("controlled unwind after an actual nested compact-key allocation");
    }));
    assert!(unwind.is_err());
    assert!(retired.get(), "actual key backing must have retired");
    assert!(
        retained_while_live.get(),
        "the actual nested key must keep its original credit"
    );
    assert!(
        retained_after_free.get(),
        "key backing must retire before the outer ledger"
    );
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "retired backing must not leak pool credit"
    );
}

#[test]
fn epoch_key_ledger_mismatch_refunds_only_retired_backing() {
    let pair = KeyPair::from_seed(vec![74; 32], Algorithm::BlsNormal);
    let key = pair.public_key();
    let budget = AllocationBudget::new(1024 * 1024);
    let mut demand = Demand::default();
    demand.key(key).unwrap();
    demand.charges = 0;
    let mut owner = Construction::new(demand, &budget).unwrap();
    assert!(
        matches!(owner.key(key), Err(BoundaryCaptureError::Invalid(reason))
        if reason == "boundary charge ledger capacity changed")
    );
    drop(owner);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "refused compact-key backing has retired"
    );
}

#[test]
fn epoch_vector_ledger_mismatch_refunds_only_retired_backing() {
    let budget = AllocationBudget::new(1024 * 1024);
    let mut demand = Demand::default();
    demand.array::<u8>(17).unwrap();
    demand.charges = 0;
    let mut owner = Construction::new(demand, &budget).unwrap();
    let mut actual = owner.buffer(17).unwrap();
    actual.append(&[9_u8; 17]).unwrap();
    assert!(
        matches!(owner.vector(actual), Err(BoundaryCaptureError::Invalid(reason))
        if reason == "boundary charge ledger capacity changed")
    );
    drop(owner);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "refused Vec backing has retired"
    );
}

#[test]
fn epoch_quantity_ledger_mismatch_refunds_unmaterialized_credit() {
    let quantity = Quantity::from(u64::MAX);
    assert!(quantity.admission_clone_layout().unwrap().size() > 0);
    let budget = AllocationBudget::new(1024 * 1024);
    let mut demand = Demand::default();
    demand.quantity(&quantity).unwrap();
    demand.charges = 0;
    let mut owner = Construction::new(demand, &budget).unwrap();
    assert!(
        matches!(owner.quantity(&quantity), Err(BoundaryCaptureError::Invalid(reason))
        if reason == "boundary charge ledger capacity changed")
    );
    drop(owner);
    assert_eq!(
        budget.reserved_bytes(),
        0,
        "no quantity backing was materialized"
    );
}

#[test]
fn epoch_generation_continuation_and_boundary_unwind_refund_original_pool() {
    let schedule = source_schedule();
    let current = schedule.ready(1).unwrap();
    let budget = AllocationBudget::new(1024 * 1024);
    for generation in [true, false] {
        CONSTRUCTION_UNWIND
            .with(|requested| requested.set(Some(ConstructionCheckpoint::NestedKey)));
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if generation {
                generation_id(
                    current.epoch.network_id,
                    1,
                    &current.epoch.committee,
                    &budget,
                )
                .map(|_| ())
                .unwrap();
            } else {
                capture_continuation(&current.epoch, 1, None, current.params, &budget)
                    .map(|_| ())
                    .unwrap();
            }
        }));
        assert!(unwind.is_err());
        assert!(CONSTRUCTION_UNWIND.with(|requested| requested.get().is_none()));
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "the partial generation/continuation graph has retired"
        );
    }
    generation_id(
        current.epoch.network_id,
        1,
        &current.epoch.committee,
        &budget,
    )
    .unwrap();
    assert_eq!(budget.reserved_bytes(), 0);
    let retained = capture_continuation(&current.epoch, 1, None, current.params, &budget).unwrap();
    assert!(retained.belongs_to(&budget));
    assert_eq!(retained.get().schedule.current, current.epoch);
    drop(retained);
    assert_eq!(budget.reserved_bytes(), 0);

    // Existing independently checked candidate/stake/threshold-pulse fixture. This
    // covers the real boundary materializer, not full transaction/finality creation.
    let (world, policy, current, hashes) = super::super::tests::boundary_fixture(8);
    let original =
        super::super::freeze_boundary(&world.view(), &hashes, &current, &policy, 10, &budget)
            .unwrap()
            .unwrap();
    let baseline = budget.reserved_bytes();
    CONSTRUCTION_UNWIND
        .with(|requested| requested.set(Some(ConstructionCheckpoint::NestedCommitteeMember)));
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _candidate =
            super::super::freeze_boundary(&world.view(), &hashes, &current, &policy, 10, &budget)
                .unwrap()
                .unwrap();
    }));
    assert!(unwind.is_err());
    assert!(CONSTRUCTION_UNWIND.with(|requested| requested.get().is_none()));
    assert_eq!(
        budget.reserved_bytes(),
        baseline,
        "the partial boundary graph has retired"
    );
    assert_eq!(original.current(), &current);
    let retry =
        super::super::freeze_boundary(&world.view(), &hashes, &current, &policy, 10, &budget)
            .unwrap()
            .unwrap();
    assert_eq!(retry.boundary(), original.boundary());
    drop(retry);
    assert_eq!(budget.reserved_bytes(), baseline);
    drop(original);
    assert_eq!(budget.reserved_bytes(), 0);
}
