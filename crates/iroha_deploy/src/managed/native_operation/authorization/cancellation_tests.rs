//! A real issued Lease closes cancellation after its original and epoch native reads.

use super::*;
use iroha_data_model::{asset::AssetDefinitionId, transaction::FeePaymentIntent};
use iroha_fs::PublishMode;
use iroha_primitives::numeric::Quantity;
use iroha_wallet::operations::BoundedTransactionOptions;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc, time::Duration};

thread_local! {
    static CHECK_HOOK: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}

pub(super) fn after_native_reads() {
    let action = CHECK_HOOK.with(|hook| hook.borrow_mut().take());
    if let Some(action) = action {
        action();
    }
}

struct CheckHookGuard;
impl CheckHookGuard {
    fn install(action: impl FnOnce() + 'static) -> Self {
        CHECK_HOOK.with(|hook| assert!(hook.borrow_mut().replace(Box::new(action)).is_none()));
        Self
    }
}
impl Drop for CheckHookGuard {
    fn drop(&mut self) {
        CHECK_HOOK.with(|hook| *hook.borrow_mut() = None);
    }
}

#[test]
fn lease_check_rejects_cancellation_during_native_reads_and_keeps_expiry_precedence() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("intent")).unwrap();
    let original = b"actual retained original".to_vec();
    directory
        .write_atomic("original.nrt", &original, PublishMode::CreateNew)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let fees = Fees::from_options(&BoundedTransactionOptions {
        fee_payment: FeePaymentIntent::authority(Vec::new(), None),
        max_total_fees: BTreeMap::from([(
            AssetDefinitionId::parse_address_literal(
                crate::genesis::profile::TAIRA_XOR_ASSET_DEFINITION_ID,
            )
            .unwrap(),
            Quantity::from(1_000u64),
        )]),
        deadline,
    })
    .unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let lease = Lease::issue(
        directory,
        original.clone(),
        &fees,
        Scope::Renewal {
            provider: ProviderId::new([7; 32]),
            sequence: 2,
        },
        now_ms().unwrap().checked_add(300_000).unwrap(),
        deadline,
        Arc::clone(&cancelled),
    )
    .unwrap();
    let epochs = lease.directory.open_child("epochs").unwrap();
    let names = epochs.entries(MAX_EPOCHS * 2).unwrap();
    let epoch_bytes = epochs.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap();
    lease.check(deadline).unwrap();

    // All actual original/epoch reads and lineage checks run before this one-shot boundary.
    let observed = Rc::new(Cell::new(false));
    let observation = Rc::clone(&observed);
    let cancellation = Arc::clone(&cancelled);
    let hook = CheckHookGuard::install(move || {
        observation.set(true);
        cancellation.store(true, Ordering::Release);
    });
    assert!(matches!(
        lease.check(deadline),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::Cancelled
        ))
    ));
    drop(hook);
    assert!(observed.get());
    cancelled.store(false, Ordering::Release);
    lease.check(deadline).unwrap();

    // An already successful native read that crosses its real caller deadline still expires
    // before the new cancellation exit, preserving the original failure priority.
    let short_deadline = Instant::now() + Duration::from_secs(10);
    let observed = Rc::new(Cell::new(false));
    let observation = Rc::clone(&observed);
    let cancellation = Arc::clone(&cancelled);
    let hook = CheckHookGuard::install(move || {
        assert!(Instant::now() < short_deadline);
        observation.set(true);
        cancellation.store(true, Ordering::Release);
        while Instant::now() <= short_deadline {
            std::thread::park_timeout(Duration::from_millis(10));
        }
    });
    assert!(matches!(
        lease.check(short_deadline),
        Err(crate::managed::Error::Bootstrap(
            ManagedBootstrapFailure::AuthorizationExpired
        ))
    ));
    drop(hook);
    assert!(observed.get());
    cancelled.store(false, Ordering::Release);
    lease.check(deadline).unwrap();
    assert_eq!(
        lease
            .directory
            .read("original.nrt", original.len())
            .unwrap()
            .as_slice(),
        original.as_slice()
    );
    assert_eq!(epochs.entries(MAX_EPOCHS * 2).unwrap(), names);
    assert_eq!(
        epochs.read("0001.nrt", attempts::MAX_RECORD_BYTES).unwrap(),
        epoch_bytes
    );
}
