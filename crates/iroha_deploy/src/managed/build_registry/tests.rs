//! Original generation admission and exact closing checks for lazy build registry lookup.

use super::*;
use crate::{
    localnet::LocalnetServiceProfile,
    managed::{LocalnetPorts, LocalnetRequest, RootKind, generation, store},
};
use iroha_fs::{PrivateDirectory, PublishMode};
use std::{cell::RefCell, fs, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResolutionKind {
    Some,
    None,
    Error,
}

thread_local! {
    static AFTER_RESOLUTION: RefCell<Option<Box<dyn FnOnce(ResolutionKind)>>> = RefCell::new(None);
}

pub(super) fn after_resolution<T>(result: &Result<Option<T>>) {
    let action = AFTER_RESOLUTION.with(|slot| slot.borrow_mut().take());
    if let Some(action) = action {
        action(match result {
            Ok(Some(_)) => ResolutionKind::Some,
            Ok(None) => ResolutionKind::None,
            Err(_) => ResolutionKind::Error,
        });
    }
}

pub(super) struct ClearHook;

impl Drop for ClearHook {
    fn drop(&mut self) {
        let _ = AFTER_RESOLUTION.with(|slot| slot.borrow_mut().take());
    }
}

pub(super) fn on_resolution(action: impl FnOnce(ResolutionKind) + 'static) -> ClearHook {
    AFTER_RESOLUTION.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(action)).is_none());
    });
    ClearHook
}

fn runtime(root: &Path) -> InstalledRuntime {
    let directory = PrivateDirectory::open_or_create(root).unwrap();
    for name in ["kagami", "iroha3d"] {
        fs::copy(
            std::env::current_exe().unwrap(),
            directory
                .path()
                .join(format!("{name}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    InstalledRuntime::from_directory(directory.path()).unwrap()
}

fn prepare(store: &ManagedStore, request: &LocalnetRequest) -> PreparedLocalnet {
    let networks = PrivateDirectory::open(store.root().join("networks")).unwrap();
    let directory = networks.ensure_child(&request.name).unwrap();
    let _operation = store::acquire(&directory, "operation.lock", &request.name).unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    generation::prepare(
        &directory,
        request,
        RootKind::Global,
        store::pin_binary(&request.launcher).unwrap(),
        store::pin_binary(&request.daemon).unwrap(),
        &ports,
    )
    .unwrap()
    .prepared
}

fn request(runtime: &InstalledRuntime) -> LocalnetRequest {
    let mut request = runtime.localnet_request("registry", Duration::from_secs(30));
    request.service_profile = LocalnetServiceProfile::Standard;
    request
}

fn require_no_effects(store: &ManagedStore, prepared: &PreparedLocalnet) {
    let directory = store.directory(&prepared.context.name).unwrap();
    for name in ["worker.json", "status.json", "supervisor.log", ".preparing"] {
        assert!(!directory.path().join(name).exists(), "{name}");
    }
    assert!(!prepared.build_cache_root().exists());
    assert!(!store.root().join("deployments").exists());
    assert!(!store.root().join("releases").exists());
}

#[test]
fn selected_registry_rejects_removed_recreated_or_changed_preparation_before_resolution() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let runtime = runtime(&temporary.path().join("bin"));
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let request = request(&runtime);
    let original = prepare(&store, &request);
    store.select(&request.name).unwrap();
    let selection = fs::read(store.root().join("active.json")).unwrap();
    let deadline = || Instant::now() + Duration::from_secs(30);
    assert!(
        store
            .build_registry(&runtime, &original, deadline())
            .unwrap()
            .is_none()
    );
    let mut changed = original.clone();
    changed.peers[0].log_name = "different.log".into();
    assert_eq!(changed.context, original.context);
    let _hook = on_resolution(|_| panic!("changed generation reached registry resolution"));
    let error = store
        .build_registry(&runtime, &changed, deadline())
        .unwrap_err();
    assert!(matches!(error, Error::Invalid(message) if message ==
            "selected build registry generation changed"));
    store.reset(&request.name).unwrap();
    assert!(
        store
            .build_registry(&runtime, &original, deadline())
            .is_err()
    );
    let replacement = prepare(&store, &request);
    assert_ne!(replacement.context.network_id, original.context.network_id);
    assert_ne!(replacement.context.account_id, original.context.account_id);
    let error = store
        .build_registry(&runtime, &original, deadline())
        .unwrap_err();
    assert!(matches!(error, Error::Invalid(message) if message ==
            "selected build registry generation changed"));
    assert_eq!(store.prepared(&request.name).unwrap(), replacement);
    assert_eq!(
        fs::read(store.root().join("active.json")).unwrap(),
        selection
    );
    require_no_effects(&store, &replacement);
    drop(_hook);
    assert!(
        store
            .build_registry(&runtime, &replacement, deadline())
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .build_registry(&runtime, &replacement, Instant::now())
            .is_err()
    );
}

#[cfg(unix)]
fn copy_generation(source: &Path, destination: &Path) {
    let destination = PrivateDirectory::open_or_create(destination).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let target = destination.path().join(entry.file_name());
        if kind.is_dir() {
            copy_generation(&entry.path(), &target);
        } else {
            assert!(kind.is_file());
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[cfg(unix)]
#[test]
fn selected_registry_exit_closes_none_and_original_errors_against_actual_replacement() {
    let _resources = crate::managed::native_test_guard();
    for ordinary_error in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = runtime(&temporary.path().join("bin"));
        let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
        let request = request(&runtime);
        let original = prepare(&store, &request);
        store.select(&request.name).unwrap();
        let selection = fs::read(store.root().join("active.json")).unwrap();
        if ordinary_error {
            let attachment = PrivateDirectory::open_or_create(
                store.root().join("attachments").join(&request.name),
            )
            .unwrap();
            attachment
                .write_atomic("binding.json", b"invalid binding", PublishMode::CreateNew)
                .unwrap();
        }
        let deadline = || Instant::now() + Duration::from_secs(30);
        let baseline = store.build_registry(&runtime, &original, deadline());
        let baseline_error = if ordinary_error {
            Some(baseline.unwrap_err().to_string())
        } else {
            assert!(baseline.unwrap().is_none());
            None
        };
        let root = store.root().to_path_buf();
        let replace_request = request.clone();
        let saved = temporary.path().join("original-generation");
        let saved_hook = saved.clone();
        let original_hook = original.clone();
        let _hook = on_resolution(move |kind| {
            assert_eq!(
                kind,
                if ordinary_error {
                    ResolutionKind::Error
                } else {
                    ResolutionKind::None
                }
            );
            let store = ManagedStore::open(&root).unwrap();
            fs::rename(
                original_hook.context.client_config.parent().unwrap(),
                &saved_hook,
            )
            .unwrap();
            let replacement = prepare(&store, &replace_request);
            assert_ne!(
                replacement.context.network_id,
                original_hook.context.network_id
            );
        });
        let error = store
            .build_registry(&runtime, &original, deadline())
            .unwrap_err();
        assert!(saved.is_dir(), "the actual resolution boundary was reached");
        if let Some(baseline_error) = &baseline_error {
            assert_ne!(error.to_string(), *baseline_error);
        }
        let replacement = store.prepared(&request.name).unwrap();
        assert_ne!(replacement, original);
        require_no_effects(&store, &replacement);
        assert_eq!(
            fs::read(store.root().join("active.json")).unwrap(),
            selection
        );
        store.reset(&request.name).unwrap();
        fs::rename(saved, original.context.client_config.parent().unwrap()).unwrap();
        assert_eq!(store.prepared(&request.name).unwrap(), original);
        let retry = store.build_registry(&runtime, &original, deadline());
        if let Some(baseline_error) = baseline_error {
            assert_eq!(retry.unwrap_err().to_string(), baseline_error);
        } else {
            assert!(retry.unwrap().is_none());
        }
        require_no_effects(&store, &original);
    }
}

#[cfg(unix)]
#[test]
fn selected_registry_exit_refuses_equal_metadata_in_a_replaced_native_directory() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let runtime = runtime(&temporary.path().join("bin"));
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let request = request(&runtime);
    let original = prepare(&store, &request);
    let saved = temporary.path().join("original-generation");
    let saved_hook = saved.clone();
    let root = store.root().to_path_buf();
    let selected = original.clone();
    let _hook = on_resolution(move |kind| {
        assert_eq!(kind, ResolutionKind::None);
        let path = selected.context.client_config.parent().unwrap();
        fs::rename(path, &saved_hook).unwrap();
        copy_generation(&saved_hook, path);
        assert_eq!(
            ManagedStore::open(&root)
                .unwrap()
                .prepared(&selected.context.name)
                .unwrap(),
            selected
        );
    });
    let deadline = || Instant::now() + Duration::from_secs(30);
    assert!(
        store
            .build_registry(&runtime, &original, deadline())
            .is_err()
    );
    assert!(saved.is_dir(), "the actual resolution boundary was reached");
    assert_eq!(store.prepared(&request.name).unwrap(), original);
    store.reset(&request.name).unwrap();
    fs::rename(saved, original.context.client_config.parent().unwrap()).unwrap();
    assert!(
        store
            .build_registry(&runtime, &original, deadline())
            .unwrap()
            .is_none()
    );
    require_no_effects(&store, &original);
}

#[test]
fn selected_registry_exit_enforces_original_deadline_without_replacing_original_errors() {
    let _resources = crate::managed::native_test_guard();
    for ordinary_error in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = runtime(&temporary.path().join("bin"));
        let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
        let request = request(&runtime);
        let original = prepare(&store, &request);
        if ordinary_error {
            let attachment = PrivateDirectory::open_or_create(
                store.root().join("attachments").join(&request.name),
            )
            .unwrap();
            attachment
                .write_atomic("binding.json", b"invalid binding", PublishMode::CreateNew)
                .unwrap();
        }
        let baseline = store.build_registry(
            &runtime,
            &original,
            Instant::now() + Duration::from_secs(30),
        );
        let original_error = if ordinary_error {
            Some(baseline.unwrap_err().to_string())
        } else {
            assert!(baseline.unwrap().is_none());
            None
        };
        let reached = std::rc::Rc::new(std::cell::Cell::new(false));
        let observed = reached.clone();
        let deadline = Instant::now() + Duration::from_secs(2);
        let _hook = on_resolution(move |kind| {
            assert_eq!(
                kind,
                if ordinary_error {
                    ResolutionKind::Error
                } else {
                    ResolutionKind::None
                }
            );
            observed.set(true);
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            assert!(Instant::now() >= deadline);
        });
        let error = store
            .build_registry(&runtime, &original, deadline)
            .unwrap_err();
        assert!(
            reached.get(),
            "the original result reached its closing boundary"
        );
        if let Some(original_error) = &original_error {
            assert_eq!(error.to_string(), *original_error);
        } else {
            assert!(matches!(error, Error::NativeDeadline));
        }
        assert_eq!(store.prepared(&request.name).unwrap(), original);
        require_no_effects(&store, &original);
        let retry = store.build_registry(
            &runtime,
            &original,
            Instant::now() + Duration::from_secs(30),
        );
        if let Some(original_error) = original_error {
            assert_eq!(retry.unwrap_err().to_string(), original_error);
        } else {
            assert!(retry.unwrap().is_none());
        }
    }
}
