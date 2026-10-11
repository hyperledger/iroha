//! Exact original allocation identity, uniqueness and custody through frozen reads.

use super::*;
use crate::ebrcell::{EbrCell, ReservedEbrCell};
use std::sync::{
    atomic::{AtomicUsize, Ordering::SeqCst},
    Arc,
};

#[derive(Clone)]
struct Payload(Arc<AtomicUsize>);
impl Drop for Payload {
    fn drop(&mut self) {
        self.0.fetch_add(1, SeqCst);
    }
}
struct Charge {
    payload_drops: Arc<AtomicUsize>,
    charge_drops: Arc<AtomicUsize>,
}
impl Drop for Charge {
    fn drop(&mut self) {
        assert_eq!(
            self.payload_drops.load(SeqCst),
            1,
            "payload must retire before custody"
        );
        self.charge_drops.fetch_add(1, SeqCst);
    }
}

#[test]
fn frozen_cell_shares_original_backing_and_refuses_thaw_until_last_reader() {
    let backing = ReservedEbrCell::try_new(()).unwrap();
    let original = backing.initialize_owned(String::from("original"));
    let address = original.deref() as *const String;
    let frozen = original.freeze();
    let read = frozen.read();
    let another = read.clone();
    assert_eq!(read.deref() as *const String, address);
    assert!(frozen.matches_read(&read));
    assert!(read.same_source(&another));
    let frozen = match frozen.try_thaw() {
        Ok(_) => panic!("actual read must prevent thaw"),
        Err(original) => original,
    };
    assert!(frozen.matches_read(&read));
    drop(read);
    let frozen = match frozen.try_thaw() {
        Ok(_) => panic!("cloned read still prevents thaw"),
        Err(original) => original,
    };
    assert_eq!(another.as_str(), "original");
    drop(another);
    let original = match frozen.try_thaw() {
        Ok(original) => original,
        Err(_) => panic!("last reader has retired"),
    };
    assert_eq!(original.deref() as *const String, address);
    let frozen = original.freeze();
    assert_eq!(frozen.read().deref() as *const String, address);
    assert!(frozen.try_thaw().is_ok());
}

#[test]
fn frozen_cell_equal_foreign_and_empty_allocations_never_match() {
    let first = ReservedEbrCell::try_new(())
        .unwrap()
        .initialize_owned(())
        .freeze();
    let second = ReservedEbrCell::try_new(())
        .unwrap()
        .initialize_owned(())
        .freeze();
    assert!(ReservedEbrCell::<(), ()>::allocation_layout().size() > 0);
    let read = first.read();
    assert!(first.matches_read(&read));
    assert!(!second.matches_read(&read));
    assert!(!read.same_source(&second.read()));
    let address = read.deref() as *const ();
    drop(first);
    assert_eq!(read.deref() as *const (), address);
    assert!(!second.matches_read(&read));
}

#[test]
fn frozen_cell_last_reader_retains_original_charge_after_owner_drop() {
    let payload_drops = Arc::new(AtomicUsize::new(0));
    let charge_drops = Arc::new(AtomicUsize::new(0));
    let original = ReservedEbrCell::try_new(Charge {
        payload_drops: payload_drops.clone(),
        charge_drops: charge_drops.clone(),
    })
    .ok()
    .unwrap()
    .initialize_owned(Payload(payload_drops.clone()));
    let frozen = original.freeze();
    let read = frozen.read();
    let last = read.clone();
    drop(frozen);
    drop(read);
    assert_eq!(payload_drops.load(SeqCst), 0);
    assert_eq!(charge_drops.load(SeqCst), 0);
    std::thread::spawn(move || {
        assert_eq!(last.0.load(SeqCst), 0);
        drop(last);
    })
    .join()
    .unwrap();
    assert_eq!(payload_drops.load(SeqCst), 1);
    assert_eq!(charge_drops.load(SeqCst), 1);
}

#[test]
fn frozen_cell_original_survives_target_republication_and_restores_owned_installation() {
    let source = EbrCell::new(7_u64);
    let original = source.write().detach().freeze();
    let read = original.read();
    *source.write().get_mut() = 8; // Abandoned writer cannot alter the frozen allocation.
    let mut writer = source.write();
    *writer.get_mut() = 9;
    writer.commit();
    assert_eq!(*source.read(), 9);
    assert_eq!(*read, 7);
    drop(read);
    let original = original.try_thaw().ok().unwrap();
    let mut writer = source.try_write_owned(original).ok().unwrap();
    *writer.get_mut() = 11;
    writer.commit();
    assert_eq!(*source.read(), 11);
    // Low-level allocation custody grants no predecessor authority. MV is
    // responsible for rejecting a changed target before this installation API.
}

#[test]
fn frozen_cell_read_and_thaw_do_not_clone_payloads() {
    struct NoClone;
    impl Clone for NoClone {
        fn clone(&self) -> Self {
            panic!("payload clone forbidden")
        }
    }
    let original = ReservedEbrCell::try_new(())
        .unwrap()
        .initialize_owned(NoClone);
    let address = std::ptr::from_ref(&*original);
    let frozen = original.freeze();
    assert_eq!(std::ptr::from_ref(frozen.get()), address);
    let read = frozen.read();
    assert_eq!(std::ptr::from_ref(frozen.get()), std::ptr::from_ref(&*read));
    let another = read.clone();
    let frozen = frozen.try_thaw().err().unwrap();
    drop(read);
    drop(another);
    drop(frozen.try_thaw().ok().unwrap());
}

#[test]
fn frozen_cell_count_overflow_refuses_without_changing_original_custody() {
    let frozen = ReservedEbrCell::try_new(())
        .unwrap()
        .initialize_owned(1_u64)
        .freeze();
    // Private fault seam: no other handles or threads exist, and restore the
    // original count before the owner can be dropped or thawed.
    let count = &unsafe { frozen.original.pointer.as_ref() }.frozen_owners;
    count.store(isize::MAX as usize, Relaxed);
    let result = std::panic::catch_unwind(|| frozen.read());
    assert!(result.is_err());
    assert_eq!(count.load(Relaxed), isize::MAX as usize);
    count.store(1, Relaxed);
    assert_eq!(*frozen.try_thaw().ok().unwrap(), 1);
}

#[test]
fn frozen_cell_concurrent_clones_keep_unique_thaw_refused() {
    let frozen = ReservedEbrCell::try_new(())
        .unwrap()
        .initialize_owned(7_u64)
        .freeze();
    let read = frozen.read();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let gate = barrier.clone();
    let reader = std::thread::spawn(move || {
        gate.wait();
        for _ in 0..1000 {
            let next = read.clone();
            assert!(read.same_source(&next));
            assert_eq!(*next, 7);
            drop(next);
        }
        gate.wait();
        drop(read);
    });
    barrier.wait();
    let mut frozen = frozen;
    for _ in 0..1000 {
        frozen = match frozen.try_thaw() {
            Ok(_) => panic!("concurrent retained reader must prevent writable ownership"),
            Err(original) => original,
        };
    }
    barrier.wait();
    reader.join().unwrap();
    assert_eq!(*frozen.try_thaw().ok().unwrap(), 7);
}

#[test]
fn frozen_cell_last_reader_unwind_preserves_original_charge_without_false_refund() {
    use iroha_allocation::{AllocationBudget, AllocationCharge};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[derive(Clone)]
    struct PanicPayload(Arc<AtomicUsize>);
    impl Drop for PanicPayload {
        fn drop(&mut self) {
            self.0.fetch_add(1, SeqCst);
            panic!("original frozen payload destructor refusal");
        }
    }
    struct UnwindCharge {
        _original: AllocationCharge,
        drops: Arc<AtomicUsize>,
    }
    impl Drop for UnwindCharge {
        fn drop(&mut self) {
            self.drops.fetch_add(1, SeqCst);
        }
    }

    let payload_drops = Arc::new(AtomicUsize::new(0));
    let charge_drops = Arc::new(AtomicUsize::new(0));
    let layout = ReservedEbrCell::<PanicPayload, UnwindCharge>::allocation_layout();
    let budget = AllocationBudget::new(layout.size());
    let mut reservation = budget.try_reserve_layouts([layout]).unwrap();
    let original_charge = reservation.try_split(layout).unwrap();
    assert!(original_charge.belongs_to(&budget));
    assert_eq!(reservation.remaining_bytes(), 0);
    let original = ReservedEbrCell::try_new(UnwindCharge {
        _original: original_charge,
        drops: Arc::clone(&charge_drops),
    })
    .unwrap_or_else(|_| panic!("actual prepaid original backing"))
    .initialize_owned(PanicPayload(Arc::clone(&payload_drops)));
    let pointer = std::ptr::from_ref(&*original);
    let frozen = original.freeze();
    assert_eq!(std::ptr::from_ref(frozen.get()), pointer);
    let last = frozen.read();
    drop(frozen);
    assert_eq!(payload_drops.load(SeqCst), 0);
    assert_eq!(charge_drops.load(SeqCst), 0);
    assert_eq!(budget.reserved_bytes(), layout.size());
    let result = catch_unwind(AssertUnwindSafe(|| drop(last)));
    assert!(result.is_err());
    assert_eq!(
        payload_drops.load(SeqCst),
        1,
        "last handle enters the original payload destructor once"
    );
    assert_eq!(
        charge_drops.load(SeqCst),
        0,
        "unwind must not release original custody"
    );
    assert_eq!(
        budget.reserved_bytes(),
        layout.size(),
        "original physical-layout credit is conservatively retained after payload unwind"
    );
}
