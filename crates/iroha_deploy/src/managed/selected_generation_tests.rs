//! Exact selected-generation admission before native startup effects.

use super::*;
use std::{cell::RefCell, rc::Rc};

type StartupHook = Box<dyn FnOnce(&PreparedLocalnet) -> Result<()>>;

thread_local! {
    static BEFORE_OPERATION: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    static BEFORE_STARTUP: RefCell<Option<StartupHook>> = RefCell::new(None);
}

pub(super) fn before_operation() {
    let hook = BEFORE_OPERATION.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}

pub(super) fn before_startup(prepared: &PreparedLocalnet) -> Result<()> {
    let hook = BEFORE_STARTUP.with(|slot| slot.borrow_mut().take());
    hook.map_or(Ok(()), |hook| hook(prepared))
}

struct ClearHooks;

impl Drop for ClearHooks {
    fn drop(&mut self) {
        let _ = BEFORE_OPERATION.with(|slot| slot.borrow_mut().take());
        let _ = BEFORE_STARTUP.with(|slot| slot.borrow_mut().take());
    }
}

fn runtime(root: &Path) -> InstalledRuntime {
    fs::create_dir(root).unwrap();
    for name in ["kagami", "iroha3d"] {
        fs::copy(
            std::env::current_exe().unwrap(),
            root.join(format!("{name}{}", std::env::consts::EXE_SUFFIX)),
        )
        .unwrap();
    }
    InstalledRuntime::from_directory(root).unwrap()
}

fn prepare(store: &ManagedStore, request: &LocalnetRequest) -> PreparedLocalnet {
    let directory = store.networks.ensure_child(&request.name).unwrap();
    let _operation = acquire(&directory, "operation.lock", &request.name).unwrap();
    let ports = LocalnetPorts::reserve().unwrap();
    let (launcher, daemon) = request.admit_programs().unwrap().pins().unwrap();
    generation::prepare(
        &directory,
        request,
        RootKind::Global,
        launcher,
        daemon,
        &ports,
    )
    .unwrap()
    .prepared
}

fn require_no_startup(store: &ManagedStore, name: &str) {
    let directory = store.directory(name).unwrap();
    assert!(!runtime_owned(&directory).unwrap());
    for path in [WORKER, STATUS, "supervisor.log"] {
        assert!(!directory.path().join(path).exists(), "{path}");
    }
    assert!(!directory.path().join(".preparing").exists());
}

fn stop_before_startup(store: &ManagedStore) -> Rc<RefCell<Option<PreparedLocalnet>>> {
    let observed = Rc::new(RefCell::new(None));
    let capture = Rc::clone(&observed);
    let root = store.root().to_path_buf();
    BEFORE_STARTUP.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move |prepared| {
            let store = ManagedStore::open(&root).unwrap();
            let directory = store.directory(&prepared.context.name).unwrap();
            assert!(matches!(
                acquire(&directory, "operation.lock", &prepared.context.name),
                Err(Error::Busy(_))
            ));
            assert_eq!(store.prepared(&prepared.context.name).unwrap(), *prepared);
            require_no_startup(&store, &prepared.context.name);
            *capture.borrow_mut() = Some(prepared.clone());
            Err(Error::Invalid("test stopped before native startup".into()))
        }));
    });
    observed
}

fn require_stopped(result: Result<ManagedStatus>) {
    assert!(matches!(
        result,
        Err(Error::Invalid(message)) if message == "test stopped before native startup"
    ));
}

#[test]
fn selected_generation_replacement_is_refused_before_startup_or_selection() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let _hooks = ClearHooks;
    let runtime = runtime(&temporary.path().join("bin"));
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let mut request = runtime.localnet_request("local", Duration::from_secs(30));
    request.service_profile = crate::localnet::LocalnetServiceProfile::Standard;
    let original = prepare(&store, &request);
    store.select("local").unwrap();
    let selection = store
        .root
        .read("active.json", MAX_METADATA)
        .unwrap()
        .to_vec();

    // Replacement before up_retained's initial metadata read must still be compared with
    // the caller's earlier selection, rather than adopted as a fresh expected identity.
    store.reset("local").unwrap();
    let replacement = prepare(&store, &request);
    assert_ne!(replacement.context.network_id, original.context.network_id);
    assert_ne!(replacement.context.account_id, original.context.account_id);
    let reached = stop_before_startup(&store);
    let error = store.up_retained(&request, &original.context).unwrap_err();
    assert!(matches!(error, Error::Invalid(message) if message ==
        "retained managed generation changed before startup"));
    assert!(reached.borrow().is_none());
    assert_eq!(store.prepared("local").unwrap(), replacement);
    require_no_startup(&store, "local");

    // Exercise both implicit selection and explicit context resolution through the real
    // workspace API. Reset/recreate runs exactly before operation.lock, without scheduling.
    for requested in [None, Some("local")] {
        let expected = store.context(requested).unwrap();
        let root = store.root().to_path_buf();
        let replace_request = request.clone();
        BEFORE_OPERATION.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let store = ManagedStore::open(&root).unwrap();
                store.reset("local").unwrap();
                let replacement = prepare(&store, &replace_request);
                assert_ne!(replacement.context.network_id, expected.network_id);
                assert_ne!(replacement.context.account_id, expected.account_id);
            }));
        });
        let reached = stop_before_startup(&store);
        let error = store
            .ensure_selected(&runtime, requested, Duration::from_secs(30))
            .unwrap_err();
        assert!(matches!(error, Error::Invalid(message) if message ==
            "retained managed generation changed before startup"));
        assert!(reached.borrow().is_none());
        assert_eq!(
            &*store.root.read("active.json", MAX_METADATA).unwrap(),
            &selection
        );
        require_no_startup(&store, "local");
    }
}

#[test]
fn missing_selected_generation_is_not_recreated_after_original_admission() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let _hooks = ClearHooks;
    let runtime = runtime(&temporary.path().join("bin"));
    let store = ManagedStore::open(&temporary.path().join("managed")).unwrap();
    let mut request = runtime.localnet_request("local", Duration::from_secs(30));
    request.service_profile = crate::localnet::LocalnetServiceProfile::Standard;
    let original = prepare(&store, &request);
    store.select("local").unwrap();
    let selection = store
        .root
        .read("active.json", MAX_METADATA)
        .unwrap()
        .to_vec();
    let root = store.root().to_path_buf();
    BEFORE_OPERATION.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(move || {
            ManagedStore::open(&root).unwrap().reset("local").unwrap();
        }));
    });
    let reached = stop_before_startup(&store);
    assert!(matches!(
        store.up_retained(&request, &original.context),
        Err(Error::Invalid(message)) if message ==
            "retained managed generation disappeared; refusing to replace its identity"
    ));
    assert!(reached.borrow().is_none());
    assert!(store.context(None).is_err());
    let error = store
        .ensure_selected(&runtime, None, Duration::from_secs(30))
        .unwrap_err();
    assert!(matches!(error, Error::Io(error) if error.kind() == std::io::ErrorKind::NotFound));
    assert!(
        !store
            .directory("local")
            .unwrap()
            .path()
            .join("generation")
            .exists()
    );
    assert_eq!(
        &*store.root.read("active.json", MAX_METADATA).unwrap(),
        &selection
    );
    require_no_startup(&store, "local");
}

#[test]
fn fresh_and_exact_selected_generations_reach_locked_startup_without_replacement() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let _hooks = ClearHooks;
    let runtime = runtime(&temporary.path().join("bin"));
    // Both the direct localnet entry point and empty-workspace default retain the ordinary
    // CreateOrRetain policy. Stop only after genuine signed generation publication/admission.
    for direct in [true, false] {
        let store =
            ManagedStore::open(
                &temporary
                    .path()
                    .join(if direct { "direct" } else { "default" }),
            )
            .unwrap();
        let request = runtime.localnet_request("local", Duration::from_secs(30));
        let reached = stop_before_startup(&store);
        require_stopped(if direct {
            store.up(&request)
        } else {
            store.ensure_selected(&runtime, None, Duration::from_secs(30))
        });
        let original = reached.borrow_mut().take().unwrap();
        assert_eq!(original.context.name, "local");
        assert_eq!(
            original.service_profile,
            crate::localnet::LocalnetServiceProfile::StreamTokenAuthorities
        );
        assert!(original.stream_token_authorities().unwrap().is_some());
        assert!(matches!(store.context(None), Err(Error::NoSelection)));
        let reached = stop_before_startup(&store);
        require_stopped(store.up_retained(&request, &original.context));
        assert_eq!(reached.borrow_mut().take().unwrap(), original);
        assert!(matches!(store.context(None), Err(Error::NoSelection)));
        let reached = stop_before_startup(&store);
        require_stopped(store.ensure_selected(&runtime, Some("local"), Duration::from_secs(30)));
        assert_eq!(reached.borrow_mut().take().unwrap(), original);
        assert_eq!(store.prepared("local").unwrap(), original);
        assert!(matches!(store.context(None), Err(Error::NoSelection)));
        require_no_startup(&store, "local");
    }
}
