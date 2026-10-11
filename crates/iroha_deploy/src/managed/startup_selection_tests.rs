//! Selection finalization at the existing identity/deadline observation boundary.
//!
//! These unit controls use genuine retained generation metadata and status DTOs. They do not
//! prove validator readiness, run a worker, change a production clock, or extend its budget.

use super::*;
use std::cell::Cell;

fn ready(context: &ManagedContext) -> ManagedStatus {
    ManagedStatus {
        context: context.clone(),
        phase: ManagedPhase::Ready,
        running_peers: 4,
        failure: None,
    }
}

fn selected_image(store: &ManagedStore) -> Option<Vec<u8>> {
    store
        .root
        .read_optional("active.json", MAX_METADATA)
        .unwrap()
        .map(|bytes| bytes.to_vec())
}

#[test]
fn startup_selection_refuses_expiry_and_nonready_before_publication() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    for selected in [false, true] {
        let root = temporary
            .path()
            .join(if selected { "selected" } else { "absent" });
        let (store, _, _) = crate::managed::tests::fixture(&root, "a");
        let (_, directory, prepared) = crate::managed::tests::fixture(&root, "b");
        if selected {
            store.select("a").unwrap();
        }
        let original = selected_image(&store);
        let _operation = acquire(&directory, "operation.lock", "b").unwrap();
        // Both old-worker and newly-started observation paths must refuse an already
        // expired original deadline before any selection write. No worker is fabricated:
        // the latter's cancellation observation has no live owner and returns Timeout.
        for initial in [true, false] {
            let error = StartupSelection::Select
                .apply(&store, &prepared.context, || {
                    observe_startup_status(
                        &directory,
                        &prepared.context,
                        ready(&prepared.context),
                        Instant::now(),
                        Duration::from_secs(30),
                        0,
                        initial,
                    )
                })
                .unwrap_err();
            assert!(matches!(error, Error::Timeout(value) if value == Duration::from_secs(30)));
            assert_eq!(selected_image(&store), original);
        }
        for phase in [
            ManagedPhase::Starting,
            ManagedPhase::Stopped,
            ManagedPhase::Failed,
        ] {
            let observed = ManagedStatus {
                context: prepared.context.clone(),
                phase,
                running_peers: 0,
                failure: None,
            };
            let result = StartupSelection::Select
                .apply(&store, &prepared.context, || {
                    let started = Instant::now();
                    let timeout = Duration::from_secs(30);
                    observe_startup_status(
                        &directory,
                        &prepared.context,
                        observed.clone(),
                        started,
                        timeout,
                        runtime::startup_deadline(started, timeout)?,
                        true,
                    )
                })
                .unwrap();
            assert_eq!(result, observed);
            assert_eq!(selected_image(&store), original);
        }
        let error = StartupSelection::Select
            .apply(&store, &prepared.context, || {
                Err(Error::Invalid("original observation failed".into()))
            })
            .unwrap_err();
        assert!(
            matches!(error, Error::Invalid(message) if message == "original observation failed")
        );
        assert_eq!(selected_image(&store), original);
        assert!(!directory.path().join(WORKER).exists());
        assert!(!directory.path().join(STATUS).exists());
    }
}

#[test]
fn startup_selection_finishes_admitted_ready_after_the_original_clock_crosses() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    for selected in [false, true] {
        let root = temporary
            .path()
            .join(if selected { "selected" } else { "absent" });
        let (store, _, _) = crate::managed::tests::fixture(&root, "a");
        let (_, directory, prepared) = crate::managed::tests::fixture(&root, "b");
        let _operation = acquire(&directory, "operation.lock", "b").unwrap();
        for initial in [true, false] {
            store.root.remove_private("active.json").unwrap();
            if selected {
                store.select("a").unwrap();
            }
            let previous = selected_image(&store);
            let observations = Cell::new(0);
            let status = StartupSelection::Select
                .apply(&store, &prepared.context, || {
                    assert_eq!(selected_image(&store), previous);
                    observations.set(observations.get() + 1);
                    // This short unit interval begins only at the isolated observation
                    // boundary. Production still supplies its original startup deadline.
                    let started = Instant::now();
                    let timeout = Duration::from_secs(1);
                    let deadline = runtime::startup_deadline(started, timeout)?;
                    let admitted = observe_startup_status(
                        &directory,
                        &prepared.context,
                        ready(&prepared.context),
                        started,
                        timeout,
                        deadline,
                        initial,
                    )?;
                    // Cross the actual original native deadline after successful admission,
                    // without replacing either clock or accepting a late Ready observation.
                    while runtime::continuous_remaining(deadline)?.is_some() {
                        thread::sleep(Duration::from_millis(1));
                    }
                    assert!(matches!(
                        runtime::startup_remaining_until(started, timeout, deadline),
                        Err(Error::Timeout(value)) if value == timeout
                    ));
                    Ok(admitted)
                })
                .unwrap();
            assert_eq!(observations.get(), 1);
            assert_eq!(status, ready(&prepared.context));
            assert_eq!(store.context(None).unwrap(), prepared.context);
            assert_eq!(store.prepared("b").unwrap(), prepared);
            assert!(!directory.path().join(WORKER).exists());
            assert!(!directory.path().join(STATUS).exists());
        }
    }
}

#[test]
fn startup_selection_retains_generation_and_publication_error_precedence() {
    let _resources = crate::managed::native_test_guard();
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("managed");
    let (store, _, _) = crate::managed::tests::fixture(&root, "a");
    let (_, directory, prepared) = crate::managed::tests::fixture(&root, "b");
    store.select("a").unwrap();
    let previous = selected_image(&store);
    let _operation = acquire(&directory, "operation.lock", "b").unwrap();
    let observed = Cell::new(false);
    let mut foreign = prepared.context.clone();
    foreign.network_id.push('x');
    let error = StartupSelection::Select
        .apply(&store, &foreign, || {
            observed.set(true);
            Ok(ready(&foreign))
        })
        .unwrap_err();
    assert!(matches!(error, Error::Invalid(message) if message ==
        "managed generation changed before startup selection"));
    assert!(!observed.get());
    assert_eq!(selected_image(&store), previous);

    // The fresh preparation remains mandatory and precedes even the deadline observer.
    let generation = directory.open_child(generation::DIRECTORY).unwrap();
    let manifest = generation.read(MANIFEST, MAX_METADATA).unwrap();
    generation
        .write_atomic(MANIFEST, b"invalid", PublishMode::Replace)
        .unwrap();
    assert!(
        StartupSelection::Select
            .apply(&store, &prepared.context, || {
                observed.set(true);
                Ok(ready(&prepared.context))
            })
            .is_err()
    );
    assert!(!observed.get());
    assert_eq!(selected_image(&store), previous);
    generation
        .write_atomic(MANIFEST, &manifest, PublishMode::Replace)
        .unwrap();

    // An ordinary publication refusal is still returned after an admitted observation.
    // Native publication may also succeed before a later durability failure; no rollback
    // is introduced, and this test does not pretend to simulate uncertain publication.
    store.root.remove_private("active.json").unwrap();
    let obstruction = store.root.create_child("active.json").unwrap();
    let error = StartupSelection::Select
        .apply(&store, &prepared.context, || {
            observed.set(true);
            let started = Instant::now();
            let timeout = Duration::from_secs(30);
            observe_startup_status(
                &directory,
                &prepared.context,
                ready(&prepared.context),
                started,
                timeout,
                runtime::startup_deadline(started, timeout)?,
                true,
            )
        })
        .unwrap_err();
    assert!(observed.get());
    assert!(matches!(error, Error::Io(_)));
    obstruction.revalidate().unwrap();
    assert_eq!(store.prepared("b").unwrap(), prepared);
}
