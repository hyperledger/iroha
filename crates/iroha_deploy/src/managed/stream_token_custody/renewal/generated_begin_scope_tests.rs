//! Genuine generated Begin source refusal, lexical scope and original outer admission.

use super::*;
use crate::managed::native_operation::test_support::UnavailablePeers;
use crate::managed::stream_token_custody::renewal_tests::{Fixture, wait_until};
use std::path::PathBuf;

fn fixture_with_renewal_body() -> Fixture {
    let fixture = Fixture::enrolled(4_000);
    wait_until(
        fixture.initial.issued_at_unix_ms + 2_000,
        Duration::from_secs(4),
    );
    let (checkpoint, current) = fixture.current();
    let utc = now_ms().unwrap() + 60_000;
    let terms = Terms::new(utc, &fixture.options).unwrap();
    let unsigned = fixture
        .owner
        .select_renewal_unsigned(
            2,
            &fixture.policy,
            &current,
            &checkpoint,
            &terms,
            fixture.options.deadline,
        )
        .unwrap();
    let history = fixture.owner.bootstrap_native_body(
        &fixture.native,
        &current,
        CustodyPurpose::Renewal(2),
        unsigned,
        utc,
        &fixture.options,
    );
    assert_eq!(
        history.purpose(),
        Purpose::CustodyRenewal {
            provider: fixture.owner.authority.provider_id().unwrap(),
            sequence: 2,
        }
    );
    assert_eq!(fixture.native.chain.height(), 4);
    fixture
}

fn begin(
    fixture: &Fixture,
    floor: ManagedTransactionFinality,
    scoped: bool,
    deadline: Instant,
) -> Result<GeneratedRenewalTurn> {
    let fees = Fees::from_options(&fixture.options)?;
    let cancelled = Arc::new(AtomicBool::new(false));
    if scoped {
        GeneratedRenewalTurn::begin(
            &fixture.owner,
            &fixture.policy,
            fees,
            floor,
            deadline,
            cancelled,
        )
    } else {
        // Exactly the same canonical Begin and inventory gates with independent imports.
        GeneratedRenewalTurn::begin_with_imports(
            &fixture.owner,
            &fixture.policy,
            fees,
            floor,
            deadline,
            cancelled,
            &mut CheckpointImports::new(&fixture.owner.authority, None),
        )
    }
}

fn assert_same(actual: &GeneratedRenewalTurn, expected: &GeneratedRenewalTurn) {
    assert_eq!(actual.prepared, expected.prepared);
    assert_eq!(actual.provider, expected.provider);
    assert_eq!(actual.policy, expected.policy);
    assert!(actual.fees == expected.fees);
    assert_eq!(actual.floor, expected.floor);
    assert_eq!(actual.deadline, expected.deadline);
    assert!(actual.authorization.is_none() && expected.authorization.is_none());
    assert!(!actual.issuance_consumed && !expected.issuance_consumed);
    assert!(!actual.cancelled.load(std::sync::atomic::Ordering::Acquire));
    assert!(!norito::core::decode_limits_active());
}

fn retained_sources(fixture: &Fixture) -> Vec<(PathBuf, &'static str, usize)> {
    let configured = fixture
        .owner
        .authority
        .directory
        .open_child("configure")
        .unwrap();
    let configured = journal::required_original(&configured).unwrap();
    let initial = BodyHistory::open(&fixture.owner, CustodyPurpose::InitialEnroll)
        .unwrap()
        .unwrap()
        .into_selected()
        .unwrap();
    let renewal = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    vec![
        (
            configured.directory().path().to_path_buf(),
            "carrier.nrt",
            MAX_CHECKPOINT_BYTES,
        ),
        (
            initial.directory().path().to_path_buf(),
            "carrier.nrt",
            MAX_CHECKPOINT_BYTES,
        ),
        (
            initial.directory().path().join("transaction"),
            "operation.json",
            4 * 1024 * 1024,
        ),
        (
            renewal.root().path().join("bodies/0001"),
            "reserved.nrt",
            journal::MAX_ORIGINAL_BYTES + 128 * 1024,
        ),
    ]
}

#[test]
fn begin_epoch_workspace_preserves_paid_sources_inventory_error_order_and_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = fixture_with_renewal_body();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    // Capture the already authenticated initial floor before mutation or budget measurement.
    let floor = *fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
        .unwrap()
        .finalized();
    let expected = begin(&fixture, floor, false, deadline).unwrap();
    assert_same(&begin(&fixture, floor, true, deadline).unwrap(), &expected);
    // These original paid Configure/Enroll and reserved renewal records stay independent
    // native reads even after the original exact checkpoint byte cache has been warmed.
    for (path, name, maximum) in retained_sources(&fixture) {
        let directory = PrivateDirectory::open_exact(&path).unwrap();
        let bytes = directory.read(name, maximum).unwrap();
        directory
            .write_atomic(name, &[0xff], PublishMode::Replace)
            .unwrap();
        let original = begin(&fixture, floor, false, deadline)
            .err()
            .expect("original source refuses");
        let actual = begin(&fixture, floor, true, deadline)
            .err()
            .expect("shared source refuses");
        assert_eq!(actual.to_string(), original.to_string());
        directory
            .write_atomic(name, &bytes, PublishMode::Replace)
            .unwrap();
        assert_eq!(directory.read(name, maximum).unwrap(), bytes);
        assert_same(&begin(&fixture, floor, true, deadline).unwrap(), &expected);
    }
    // A present later renewal namespace cannot be skipped after validating sequence two.
    let unexpected = fixture
        .owner
        .authority
        .directory
        .create_child(&CustodyPurpose::Renewal(3).directory_name().unwrap())
        .unwrap();
    let original = begin(&fixture, floor, false, deadline)
        .err()
        .expect("original full census refuses");
    let actual = begin(&fixture, floor, true, deadline)
        .err()
        .expect("shared full census refuses");
    assert_eq!(actual.to_string(), original.to_string());
    unexpected.remove_empty().unwrap();
    assert_same(&begin(&fixture, floor, true, deadline).unwrap(), &expected);
    let expired = Instant::now();
    assert!(matches!(
        begin(&fixture, floor, true, expired),
        Err(crate::managed::Error::NativeDeadline)
    ));
    assert_eq!(
        begin(&fixture, floor, true, expired)
            .err()
            .unwrap()
            .to_string(),
        begin(&fixture, floor, false, expired)
            .err()
            .unwrap()
            .to_string()
    );
    assert_same(&begin(&fixture, floor, true, deadline).unwrap(), &expected);
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn begin_epoch_workspace_preserves_late_finite_outer_charge_refusal_and_retry() {
    use norito::core::DecodeBudgetContext;
    fn limits(allocation: usize) -> norito::DecodeLimits {
        norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            allocation,
            64,
        )
    }
    let _guard = crate::managed::native_test_guard();
    let fixture = fixture_with_renewal_body();
    let mut peers = UnavailablePeers::start(&fixture.prepared);
    let deadline = fixture.options.deadline;
    // Capture the already authenticated initial floor before mutation or budget measurement.
    let floor = *fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
        .unwrap()
        .finalized();
    let warm = begin(&fixture, floor, true, deadline).unwrap();
    let ceiling = 256 * 1024 * 1024;
    let baseline = DecodeBudgetContext::new(limits(ceiling));
    let expected = baseline
        .with(|| begin(&fixture, floor, false, deadline))
        .unwrap();
    let charge = baseline.consumed_allocated_bytes();
    assert!(charge > 0 && charge < ceiling as u64);
    let exact = DecodeBudgetContext::new(limits(usize::try_from(charge).unwrap()));
    let actual = exact
        .with(|| begin(&fixture, floor, true, deadline))
        .unwrap();
    assert_eq!(exact.consumed_allocated_bytes(), charge);
    assert_same(&actual, &expected);
    assert_same(&actual, &warm);
    for allocation in [0, 1] {
        let original = DecodeBudgetContext::new(limits(allocation));
        let expected = original
            .with(|| begin(&fixture, floor, false, deadline))
            .err()
            .expect("original budget refuses");
        let budget = DecodeBudgetContext::new(limits(allocation));
        let actual = budget
            .with(|| begin(&fixture, floor, true, deadline))
            .err()
            .expect("shared budget refuses");
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(
            budget.consumed_allocated_bytes(),
            original.consumed_allocated_bytes()
        );
        assert!(!norito::core::decode_limits_active());
        assert_same(&begin(&fixture, floor, true, deadline).unwrap(), &warm);
    }
    assert_eq!(fixture.native.chain.height(), 4);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

// This one-shot hook exists only in libtest, at the real lease-root selection boundary.
// It cannot change shipping authorization, resource limits or source validation.
std::thread_local! {
    static LEASE_ROOT_SELECTION_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {
        std::cell::RefCell::new(None)
    };
}

/// Execute and remove the test-owned one-shot hook at the genuine lease selection seam.
pub(super) fn before_lease_root_selection() {
    let hook = LEASE_ROOT_SELECTION_HOOK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

fn with_lease_root_selection_hook<T>(hook: impl FnOnce() + 'static, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            LEASE_ROOT_SELECTION_HOOK.with(|slot| slot.borrow_mut().take());
        }
    }
    LEASE_ROOT_SELECTION_HOOK.with(|slot| {
        assert!(slot.borrow().is_none(), "lease-root hook must not overlap");
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    let _reset = Reset;
    run()
}

#[test]
fn renewal_lease_keeps_original_root_material_and_same_source_retry() {
    let _guard = crate::managed::native_test_guard();
    let fixture = fixture_with_renewal_body();
    let deadline = fixture.options.deadline;
    let floor = *fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
        .unwrap()
        .finalized();
    let history = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    let identity = history.root().identity().unwrap();
    let bytes = history.outer_bytes().unwrap();
    let before = history.root().read("original.nrt", bytes.len()).unwrap();
    assert_eq!(before.as_slice(), bytes);
    let mut turn = begin(&fixture, floor, true, deadline).unwrap();
    let called = std::rc::Rc::new(std::cell::Cell::new(false));
    let observed = std::rc::Rc::clone(&called);
    #[cfg(windows)]
    let root_path = history.root().path().to_path_buf();
    #[cfg(windows)]
    let displaced = root_path.with_file_name("held-renewal-original");
    with_lease_root_selection_hook(
        move || {
            observed.set(true);
            #[cfg(windows)]
            assert!(std::fs::rename(&root_path, &displaced).is_err());
        },
        || {
            let authorization = turn
                .authorize_retained(&fixture.owner, &history, deadline)
                .unwrap();
            assert_eq!(authorization.lease.directory.identity().unwrap(), identity);
            assert_eq!(authorization.lease.directory.path(), history.root().path());
            assert_eq!(
                authorization
                    .lease
                    .directory
                    .read("original.nrt", bytes.len())
                    .unwrap(),
                before,
            );
            authorization.lease.check(deadline).unwrap();
            history
                .root()
                .write_atomic("original.nrt", &[0xff], PublishMode::Replace)
                .unwrap();
            assert!(authorization.lease.check(deadline).is_err());
            history
                .root()
                .write_atomic("original.nrt", &bytes, PublishMode::Replace)
                .unwrap();
            assert_eq!(history.root().identity().unwrap(), identity);
            assert_eq!(
                history.root().read("original.nrt", bytes.len()).unwrap(),
                before
            );
            authorization.lease.check(deadline).unwrap();
        },
    );
    assert!(called.get());
    assert!(LEASE_ROOT_SELECTION_HOOK.with(|slot| slot.borrow().is_none()));
    assert_eq!(fixture.native.chain.height(), 4);
}

#[cfg(unix)]
#[test]
fn renewal_lease_refuses_same_byte_root_replacement_and_retries_original() {
    let _guard = crate::managed::native_test_guard();
    let fixture = fixture_with_renewal_body();
    let deadline = fixture.options.deadline;
    let floor = *fixture
        .owner
        .retained_initial_enrollment(&fixture.policy, fixture.initial, deadline)
        .unwrap()
        .finalized();
    let history = BodyHistory::open(&fixture.owner, CustodyPurpose::Renewal(2))
        .unwrap()
        .unwrap();
    let identity = history.root().identity().unwrap();
    let bytes = history.outer_bytes().unwrap();
    let root_path = history.root().path().to_path_buf();
    let displaced = root_path.with_file_name("held-renewal-original");
    let hook_path = root_path.clone();
    let hook_displaced = displaced.clone();
    let hook_bytes = bytes.clone();
    let mut turn = begin(&fixture, floor, true, deadline).unwrap();
    let refusal = with_lease_root_selection_hook(
        move || {
            std::fs::rename(&hook_path, &hook_displaced).unwrap();
            let replacement = PrivateDirectory::open_or_create(&hook_path).unwrap();
            replacement
                .write_atomic("original.nrt", &hook_bytes, PublishMode::CreateNew)
                .unwrap();
        },
        || {
            turn.authorize_retained(&fixture.owner, &history, deadline)
                .map(|_| ())
        },
    );
    assert!(
        matches!(&refusal, Err(crate::managed::Error::Io(_))),
        "{refusal:?}"
    );
    assert!(turn.authorization.is_none());
    assert!(turn.issuance_consumed);
    assert!(LEASE_ROOT_SELECTION_HOOK.with(|slot| slot.borrow().is_none()));
    let replacement = PrivateDirectory::open_exact(&root_path).unwrap();
    assert_ne!(replacement.identity().unwrap(), identity);
    assert_eq!(
        replacement
            .read("original.nrt", bytes.len())
            .unwrap()
            .as_slice(),
        bytes
    );
    assert_eq!(
        replacement.entries(1).unwrap(),
        vec![std::ffi::OsString::from("original.nrt")]
    );
    assert!(!root_path.join("epochs").exists());
    drop(replacement);
    std::fs::remove_dir_all(&root_path).unwrap();
    std::fs::rename(&displaced, &root_path).unwrap();
    assert_eq!(history.root().identity().unwrap(), identity);
    assert_eq!(
        history
            .root()
            .read("original.nrt", bytes.len())
            .unwrap()
            .as_slice(),
        bytes
    );
    // Failed issuance consumes its original turn; source restoration uses a fresh genuine Begin.
    let mut retry = begin(&fixture, floor, true, deadline).unwrap();
    let authorization = retry
        .authorize_retained(&fixture.owner, &history, deadline)
        .unwrap();
    assert_eq!(authorization.lease.directory.identity().unwrap(), identity);
    authorization.lease.check(deadline).unwrap();
    assert_eq!(fixture.native.chain.height(), 4);
}
