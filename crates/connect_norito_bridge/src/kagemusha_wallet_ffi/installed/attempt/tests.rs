//! SOFTWARE DATA controls for ownership and acknowledgement; no installed authority.
use super::super::exports::{
    connect_norito_kagemusha_wallet_installation_begin_v1 as begin,
    connect_norito_kagemusha_wallet_installation_close_v1 as close,
    connect_norito_kagemusha_wallet_installation_register_v1 as register,
};
use super::*;
use open::installation_data;

#[test]
fn all_registration_refusals_retain_the_same_pair_until_single_real_registry_transfer() {
    let drops = Arc::new(Mutex::new(Vec::new()));
    let original = installation_data::owner(&drops);
    let mut attempt = WalletInstallationAttempt::new(Arc::clone(&original));
    let selected = Mutex::new(Registry::default());
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = selected.lock().unwrap();
        panic!("local DATA registry poison");
    }));
    assert_eq!(attempt.register(&selected).unwrap_err().status, INTERNAL);
    assert!(Arc::ptr_eq(attempt.owner.as_ref().unwrap(), &original));
    selected.clear_poison(); // Test-only restoration, no installer capacity permission.
    {
        let mut registry = selected.lock().unwrap();
        for id in 1..=MAX_OWNERS as u64 {
            registry.runtimes.insert(
                id,
                installation_data::owner(&Arc::new(Mutex::new(Vec::new()))),
            );
        }
    }
    assert_eq!(attempt.register(&selected).unwrap_err().status, RESOURCE);
    assert!(Arc::ptr_eq(attempt.owner.as_ref().unwrap(), &original));
    {
        let mut registry = selected.lock().unwrap();
        registry.runtimes.clear();
        registry.next = i64::MAX as u64;
    }
    assert_eq!(attempt.register(&selected).unwrap_err().status, RESOURCE);
    assert!(Arc::ptr_eq(attempt.owner.as_ref().unwrap(), &original));
    assert!(drops.lock().unwrap().is_empty());
    selected.lock().unwrap().next = 0; // Local DATA namespace, never a production reset.
    let id = attempt.register(&selected).unwrap();
    assert_eq!(id, 1);
    assert!(attempt.owner.is_none());
    assert!(Arc::ptr_eq(
        selected.lock().unwrap().runtimes.get(&id).unwrap(),
        &original
    ));
    assert_eq!(attempt.register(&selected).unwrap_err().status, CLOSED);
    assert_eq!(attempt.close().unwrap_err().status, CLOSED);
    assert_eq!(selected.lock().unwrap().runtimes.len(), 1);
    assert!(drops.lock().unwrap().is_empty());
    closing::close_with(&selected, id).unwrap();
    assert_eq!(*drops.lock().unwrap(), vec![1, 2]);
    assert!(selected.lock().unwrap().runtimes.is_empty());
}

#[test]
fn close_refusal_retains_both_owners_and_fences_registration_until_zero_ack() {
    for finished in [false, true] {
        let drops = Arc::new(Mutex::new(Vec::new()));
        let owner = installation_data::owner(&drops);
        let mut attempt = WalletInstallationAttempt::new(Arc::clone(&owner));
        installation_data::poison(&owner, finished);
        assert_eq!(attempt.close().unwrap_err().status, INTERNAL);
        assert!(Arc::ptr_eq(attempt.owner.as_ref().unwrap(), &owner));
        assert!(drops.lock().unwrap().is_empty());
        assert_eq!(
            attempt
                .register(&Mutex::new(Registry::default()))
                .unwrap_err()
                .status,
            CLOSED
        );
        installation_data::repair(&owner); // DATA fault reset only; no public poison bypass.
        attempt.close().unwrap();
        assert!(attempt.owner.is_none());
        assert_eq!(*drops.lock().unwrap(), vec![1, 2]);
        assert_eq!(attempt.close().unwrap_err().status, CLOSED);
    }
}

#[test]
fn c_close_clears_the_exact_slot_only_after_acknowledged_same_owner_join() {
    let drops = Arc::new(Mutex::new(Vec::new()));
    let owner = installation_data::owner(&drops);
    let mut slot = Box::into_raw(Box::new(WalletInstallationAttempt::new(Arc::clone(&owner))));
    let original = slot;
    installation_data::poison(&owner, true);
    // SAFETY: unique Native-shaped DATA allocation and exclusive pointer slot; no installation.
    assert_eq!(unsafe { close(&mut slot) }, INTERNAL);
    assert_eq!(slot, original);
    assert!(drops.lock().unwrap().is_empty());
    installation_data::repair(&owner);
    // SAFETY: same live allocation/slot, consumed only on actual zero acknowledgement.
    assert_eq!(unsafe { close(&mut slot) }, 0);
    assert!(slot.is_null());
    assert_eq!(*drops.lock().unwrap(), vec![1, 2]);
    assert_eq!(unsafe { close(&mut slot) }, INVALID);
}

#[test]
fn invalid_c_outputs_and_absent_attempts_never_acquire_or_register_custody() {
    let mut slot = std::ptr::null_mut();
    let mut runtime = 99;
    // SAFETY: nulls are admitted negative grammar, declared writable output slots are valid.
    unsafe {
        assert_eq!(
            begin(std::ptr::null(), std::ptr::null(), std::ptr::null_mut()),
            INVALID
        );
        assert_eq!(
            begin(std::ptr::null(), std::ptr::null(), &mut slot),
            INVALID
        );
        assert!(slot.is_null());
        assert_eq!(register(std::ptr::null_mut(), &mut runtime), INVALID);
        assert_eq!(runtime, 0);
        assert_eq!(register(&mut slot, std::ptr::null_mut()), INVALID);
        assert!(slot.is_null());
        assert_eq!(close(std::ptr::null_mut()), INVALID);
        assert_eq!(close(&mut slot), INVALID);
    }
}
