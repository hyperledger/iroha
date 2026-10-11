//! Fault and race tests of the actual Native registry close path; no financial fixture.

use super::*;
use std::sync::{atomic::AtomicUsize, mpsc};

fn local_owner() -> (
    Arc<Mutex<Registry>>,
    Arc<Owner>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let calls = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = Arc::new(Owner {
        background: background::Background::default(),
        closing: Arc::new(CloseState::default()),
        scheduler: state::Scheduler::new(),
        wallet: Mutex::new(Some(Box::new(super::super::tests::TestWallet {
            calls: Arc::clone(&calls),
            drops: Arc::clone(&drops),
            expected_request: None,
        }))),
    });
    let mut registry = Registry::default();
    registry.owners.insert(1, Arc::clone(&owner));
    (Arc::new(Mutex::new(registry)), owner, calls, drops)
}

#[test]
fn refused_wallet_close_keeps_the_real_id_and_blocks_stale_calls_until_actual_join() {
    let (registry, owner, calls, drops) = local_owner();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = owner.wallet.lock().unwrap();
        panic!("injected actual wallet lock refusal");
    }));
    for _ in 0..2 {
        assert_eq!(close_with(&registry, 1).unwrap_err().status, INTERNAL);
        assert!(
            registry
                .lock()
                .unwrap()
                .owners
                .get(&1)
                .is_some_and(|actual| Arc::ptr_eq(actual, &owner))
        );
        assert_eq!(
            with_wallet_owner(Arc::clone(&owner), false, |wallet| wallet.resume())
                .unwrap_err()
                .status,
            CLOSED
        );
        assert_eq!(drops.load(Ordering::SeqCst), 0);
    }
    owner.wallet.clear_poison(); // Test-only repair of the injected refusal.
    close_with(&registry, 1).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(registry.lock().unwrap().owners.is_empty());
    assert_eq!(close_with(&registry, 1).unwrap_err().status, CLOSED);
}

#[test]
fn close_retains_platform_owner_while_an_accepted_call_finishes_and_blocks_new_calls() {
    let (registry, owner, _, drops) = local_owner();
    let (entered_send, entered) = mpsc::channel();
    let (resume, resume_receive) = mpsc::channel();
    let calling = {
        let owner = Arc::clone(&owner);
        std::thread::spawn(move || {
            with_wallet_owner(owner, false, |_| {
                entered_send.send(()).unwrap();
                resume_receive.recv().unwrap();
                Ok(())
            })
        })
    };
    entered.recv().unwrap();
    let closing = {
        let registry = Arc::clone(&registry);
        std::thread::spawn(move || close_with(&registry, 1))
    };
    let timeout = std::time::Instant::now();
    while owner.closing.require_open().is_ok() {
        assert!(timeout.elapsed() < std::time::Duration::from_secs(5));
        std::thread::yield_now();
    }
    assert!(
        registry
            .lock()
            .unwrap()
            .owners
            .get(&1)
            .is_some_and(|actual| Arc::ptr_eq(actual, &owner))
    );
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(
        with_wallet_owner(Arc::clone(&owner), false, |_| Ok(()))
            .unwrap_err()
            .status,
        CLOSED
    );
    resume.send(()).unwrap();
    calling.join().unwrap().unwrap();
    closing.join().unwrap().unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
}

#[test]
fn genuine_join_retries_registry_retirement_without_repeating_cleanup() {
    let (registry, owner, _, drops) = local_owner();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.closing.begin();
        owner
            .closing
            .join(|| {
                drop(owner.wallet.lock().unwrap().take());
                Ok(())
            })
            .unwrap();
        let _guard = registry.lock().unwrap();
        panic!("injected registry retirement refusal after actual join");
    }));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(close_with(&registry, 1).unwrap_err().status, INTERNAL);
    registry.clear_poison();
    close_with(&registry, 1).unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(registry.lock().unwrap().owners.is_empty());
}

#[test]
fn cleanup_panic_never_marks_joined_or_turns_same_id_retry_into_release() {
    let (registry, owner, _, drops) = local_owner();
    owner.closing.begin();
    assert_eq!(
        run(|| owner.closing.join(|| panic!("injected cleanup panic")))
            .unwrap_err()
            .status,
        INTERNAL
    );
    assert_eq!(close_with(&registry, 1).unwrap_err().status, INTERNAL);
    assert!(registry.lock().unwrap().owners.contains_key(&1));
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(owner.closing.require_open().unwrap_err().status, CLOSED);
    // Test teardown only: the quarantined real owner remains until its process exits.
}
