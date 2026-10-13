//! Native owner handoff preserves finite authorization, fresh source fences and purpose locks.

use super::*;
use crate::managed::service_authority::{
    ServiceAuthority, ServiceChildInventory, profile_validation_test_support,
};
use iroha_fs::{FileIdentity, PrivateDirectory, PublishMode};
use norito::core::DecodeBudgetContext;
use std::{cell::Cell, path::PathBuf, rc::Rc};

fn purpose_path(prepared: &PreparedLocalnet, purpose: &str) -> PathBuf {
    prepared
        .context
        .client_config
        .parent()
        .unwrap()
        .join("runtime/service-operations/network")
        .join(purpose)
}
fn cold_captures<T>(action: impl FnOnce() -> T) -> (T, usize) {
    crate::localnet::service_authorities::count_profile_validations(action)
}
fn assert_held(path: &std::path::Path) {
    let directory = PrivateDirectory::open_exact(path).unwrap();
    match directory.open_existing_lock("operation.lock") {
        Ok(lock) => assert!(lock.try_lock().is_err()),
        Err(error) => {
            assert!(cfg!(windows));
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        }
    }
}
fn assert_free(path: &std::path::Path) {
    let directory = PrivateDirectory::open_exact(path).unwrap();
    let lock = directory.open_existing_lock("operation.lock").unwrap();
    lock.try_lock().unwrap();
}
fn limits(allocated: usize) -> norito::DecodeLimits {
    let finite = 64 * 1024 * 1024;
    norito::DecodeLimits::new(finite, finite, finite, allocated, 64)
}

#[test]
fn consuming_handoff_reuses_one_capture_and_releases_bootstrap_before_catalog() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let selected = budget();
    let mut parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    let authorization = parent
        .authorize_generated_startup(
            selected.deadline().unwrap(),
            Arc::clone(&selected.cancelled),
        )
        .unwrap()
        .unwrap();
    let bootstrap_path = purpose_path(&prepared, "service-bootstrap");
    let renderer_path = purpose_path(&prepared, "generated-service-runtime");
    let bootstrap = PrivateDirectory::open_exact(&bootstrap_path).unwrap();
    let original = bootstrap.open_child("initial").unwrap();
    let original_bytes = original.read("original.nrt", 512 * 1024).unwrap();
    let epochs = original.open_child("epochs").unwrap();
    let epoch_bytes = epochs.read("0001.nrt", 64 * 1024).unwrap();
    let bootstrap_identity = bootstrap.identity().unwrap();
    let (((owner, captures), opens), checks) = profile_validation_test_support::count(|| {
        ServiceChildInventory::test_count_authority_opens(|| {
            cold_captures(|| parent.into_generated_runtime())
        })
    });
    let owner = owner.unwrap();
    assert_eq!((captures, opens, checks), (0, 1, 2));
    assert_free(&bootstrap_path);
    assert_held(&renderer_path);
    let renderer = PrivateDirectory::open_exact(&renderer_path).unwrap();
    let renderer_identity = renderer.identity().unwrap();
    let renderer_lock = FileIdentity::of(&renderer.open_read("operation.lock").unwrap()).unwrap();
    assert!(GeneratedServiceRuntime::open(&prepared).is_err());
    let reopened = ManagedServiceBootstrap::open(&prepared).unwrap();
    assert!(
        owner.prepare_catalog(selected.deadline().unwrap()).is_err(),
        "catalog must really reacquire the original Bootstrap purpose"
    );
    drop(reopened);
    let revision = owner.prepare_catalog(selected.deadline().unwrap()).unwrap();
    assert_eq!(revision.stage(), GeneratedRuntimeStage::Catalog);
    assert!(revision.required_transactions().is_empty());
    owner.validate_for(&prepared, &revision).unwrap();
    assert!(owner.prepare_catalog(Instant::now()).is_err());
    assert_eq!(authorization.test_ordinal(), 1);
    assert_eq!(
        original.read("original.nrt", 512 * 1024).unwrap(),
        original_bytes
    );
    assert_eq!(epochs.read("0001.nrt", 64 * 1024).unwrap(), epoch_bytes);
    assert_eq!(
        epochs.entries(128).unwrap(),
        vec![std::ffi::OsString::from("0001.nrt")]
    );
    assert_eq!(bootstrap.identity().unwrap(), bootstrap_identity);
    drop(owner);
    assert_free(&renderer_path);
    let cold = GeneratedServiceRuntime::open(&prepared).unwrap();
    assert_eq!(renderer.identity().unwrap(), renderer_identity);
    assert_eq!(
        FileIdentity::of(&renderer.open_read("operation.lock").unwrap()).unwrap(),
        renderer_lock
    );
    cold.validate_for(&prepared, &revision).unwrap();
    drop(cold);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn handoff_source_entry_and_ordinary_error_exit_preserve_native_ownership() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let bootstrap_path = purpose_path(&prepared, "service-bootstrap");
    let renderer_path = purpose_path(&prepared, "generated-service-runtime");
    let generation =
        PrivateDirectory::open_exact(prepared.context.client_config.parent().unwrap()).unwrap();
    let original = generation.read("peer3.toml", 1024 * 1024).unwrap();
    let mut changed = zeroize::Zeroizing::new(original.to_vec());
    changed.extend_from_slice(b"\n# changed original constructor image\n");
    let parent = ManagedServiceBootstrap::open(&prepared).unwrap();
    generation
        .write_atomic("peer3.toml", &changed, PublishMode::Replace)
        .unwrap();
    let (refused, captures) = cold_captures(|| parent.into_generated_runtime());
    assert_eq!(captures, 0);
    let source_error = refused.err().unwrap().to_string();
    assert!(!renderer_path.exists());
    assert_free(&bootstrap_path);
    generation
        .write_atomic("peer3.toml", &original, PublishMode::Replace)
        .unwrap();
    for blocked in [false, true] {
        let blocker = blocked.then(|| GeneratedServiceRuntime::open(&prepared).unwrap());
        let parent = ManagedServiceBootstrap::open(&prepared).unwrap();
        let reached = Rc::new(Cell::new(false));
        let mark = Rc::clone(&reached);
        let source = generation.retain().unwrap();
        let replacement = zeroize::Zeroizing::new(changed.to_vec());
        let parent_path = bootstrap_path.clone();
        let child_path = renderer_path.clone();
        let _hook = ServiceAuthority::test_on_creating_child_exit(move || {
            mark.set(true);
            assert_held(&parent_path);
            assert_held(&child_path);
            source
                .write_atomic("peer3.toml", &replacement, PublishMode::Replace)
                .unwrap();
        });
        let (((refused, captures), opens), checks) = profile_validation_test_support::count(|| {
            ServiceChildInventory::test_count_authority_opens(|| {
                cold_captures(|| parent.into_generated_runtime())
            })
        });
        assert!(reached.get());
        assert_eq!((captures, opens, checks), (0, 1, 2));
        assert_eq!(
            refused.err().unwrap().to_string(),
            source_error,
            "source exit failure supersedes successful and ordinary-busy child results"
        );
        assert_free(&bootstrap_path);
        if blocked {
            assert_held(&renderer_path);
        }
        drop(blocker);
        assert_free(&renderer_path);
        generation
            .write_atomic("peer3.toml", &original, PublishMode::Replace)
            .unwrap();
        let parent = ManagedServiceBootstrap::open(&prepared).unwrap();
        let (retry, captures) = cold_captures(|| parent.into_generated_runtime());
        assert_eq!(captures, 0);
        drop(retry.unwrap());
    }
    assert_eq!(
        generation.read("peer3.toml", 1024 * 1024).unwrap(),
        original
    );
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn handoff_keeps_literal_active_decode_and_owned_parent_cold_admission() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let ample = 64 * 1024 * 1024;
    for inherited in [false, true] {
        let parent = inherited.then(|| ManagedServiceBootstrap::open(&prepared).unwrap());
        let context = DecodeBudgetContext::new(limits(ample));
        let (owner, count) = cold_captures(|| {
            context.with(|| match parent {
                Some(parent) => parent.into_generated_runtime(),
                None => GeneratedServiceRuntime::open(&prepared),
            })
        });
        assert_eq!(count, 1);
        let owner = owner.unwrap();
        let charge = context.consumed_allocated_bytes();
        assert!(charge > 0 && charge <= ample as u64);
        assert_held(&purpose_path(&prepared, "generated-service-runtime"));
        drop(owner);
    }
    for allocated in [0, 1] {
        let parent = ManagedServiceBootstrap::open(&prepared).unwrap();
        let baseline = DecodeBudgetContext::new(limits(allocated));
        let (expected, expected_captures) =
            cold_captures(|| baseline.with(|| GeneratedServiceRuntime::open(&prepared)));
        let context = DecodeBudgetContext::new(limits(allocated));
        let (actual, actual_captures) =
            cold_captures(|| context.with(|| parent.into_generated_runtime()));
        assert_eq!((expected_captures, actual_captures), (1, 1));
        assert_eq!(
            actual.err().unwrap().to_string(),
            expected.err().unwrap().to_string()
        );
        assert_eq!(
            context.consumed_allocated_bytes(),
            baseline.consumed_allocated_bytes()
        );
        assert_free(&purpose_path(&prepared, "service-bootstrap"));
    }
    let admission = DecodeBudgetContext::new(limits(ample));
    let parent = admission
        .with(|| ManagedServiceBootstrap::open(&prepared))
        .unwrap();
    assert!(!norito::core::decode_limits_active());
    let (owner, count) = cold_captures(|| parent.into_generated_runtime());
    assert_eq!(
        count, 1,
        "the Owned parent cannot become a shared capture verdict"
    );
    drop(owner.unwrap());
    assert_free(&purpose_path(&prepared, "service-bootstrap"));
    assert_free(&purpose_path(&prepared, "generated-service-runtime"));
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}

#[test]
fn activation_cancellation_after_handoff_retains_epoch_and_releases_both_locks() {
    let _guard = crate::managed::native_test_guard();
    let (_temporary, prepared) = fixture(LocalnetServiceProfile::StreamTokenAuthorities);
    let mut peers = UnavailablePeers::start(&prepared);
    let selected = budget();
    let cancelled = Arc::clone(&selected.cancelled);
    let bootstrap_path = purpose_path(&prepared, "service-bootstrap");
    let renderer_path = purpose_path(&prepared, "generated-service-runtime");
    let initial_path = bootstrap_path.join("initial");
    let saved = Rc::new(std::cell::RefCell::new(None));
    let observed = Rc::clone(&saved);
    let parent_path = bootstrap_path.clone();
    let child_path = renderer_path.clone();
    let _hook = ServiceAuthority::test_on_creating_child_exit(move || {
        assert_held(&parent_path);
        assert_held(&child_path);
        let initial = PrivateDirectory::open_exact(&initial_path).unwrap();
        *observed.borrow_mut() = Some((
            initial.read("original.nrt", 512 * 1024).unwrap(),
            initial
                .open_child("epochs")
                .unwrap()
                .read("0001.nrt", 64 * 1024)
                .unwrap(),
        ));
        cancelled.store(true, Ordering::Release);
    });
    let (result, captures) = cold_captures(|| prepare(&prepared, &selected));
    assert!(matches!(result, Err(failure) if failure == selected.progress.cancelled()));
    assert_eq!(captures, 1);
    let (original, epoch) = saved.borrow_mut().take().unwrap();
    let initial = PrivateDirectory::open_exact(&bootstrap_path.join("initial")).unwrap();
    assert_eq!(initial.read("original.nrt", 512 * 1024).unwrap(), original);
    let epochs = initial.open_child("epochs").unwrap();
    assert_eq!(epochs.read("0001.nrt", 64 * 1024).unwrap(), epoch);
    assert_eq!(
        epochs.entries(128).unwrap(),
        vec![std::ffi::OsString::from("0001.nrt")]
    );
    assert_free(&bootstrap_path);
    assert_free(&renderer_path);
    assert!(peers.requests.lock().unwrap().is_empty());
    peers.finish();
}
