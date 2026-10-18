//! The read-only journal bracket preserves lock and callback fences with less repeated ancestry.
use super::*;
use iroha_fs::CustodyWorkV1;
#[cfg(unix)]
use std::cell::Cell;
use std::cell::RefCell;

thread_local! {
    static AFTER_ENTRY_LOCK: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
}

// One private test-only boundary, after the actual native entry-lock outcome exists.
// Production has no hook or additional public API.
pub(super) fn after_entry_lock<T>(result: Result<T>) -> Result<T> {
    let hook = AFTER_ENTRY_LOCK.with(|slot| slot.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
    result
}

#[cfg(unix)]
fn with_entry_hook<T>(hook: impl FnOnce() + 'static, read: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            AFTER_ENTRY_LOCK.with(|slot| *slot.borrow_mut() = None);
        }
    }
    AFTER_ENTRY_LOCK.with(|slot| {
        assert!(slot.borrow().is_none());
        *slot.borrow_mut() = Some(Box::new(hook));
    });
    let _reset = Reset;
    let result = read();
    assert!(AFTER_ENTRY_LOCK.with(|slot| slot.borrow().is_none()));
    result
}

// Exact previous with_read_custody body, with the same private observation hook.
// A failed revalidate returns before entering the directory callback scope.
#[cfg(unix)]
fn original_with_entry_hook<T>(
    journal: &Journal,
    read: impl for<'read, 'scope> FnOnce(&mut NativeJournalReadScope<'read, 'scope>) -> Result<T>,
) -> Result<T> {
    after_entry_lock(journal.revalidate())?;
    let result = journal
        .directory
        .read_scope(|reader| read(&mut NativeJournalReadScope { journal, reader }));
    if let Err(error) = journal.revalidate() {
        drop(result);
        return Err(error);
    }
    result
}

fn original<T>(
    journal: &Journal,
    read: impl for<'read, 'scope> FnOnce(&mut NativeJournalReadScope<'read, 'scope>) -> Result<T>,
) -> Result<T> {
    journal.with_read_custody(|| {
        journal
            .directory
            .read_scope(|reader| read(&mut NativeJournalReadScope { journal, reader }))
    })
}
fn measured<T>(read: impl FnOnce() -> T) -> (T, CustodyWorkV1) {
    let before = CustodyWorkV1::current_thread();
    let result = read();
    (result, CustodyWorkV1::current_thread().since(before))
}
fn outcome<T>(result: Result<T>) -> std::result::Result<T, String> {
    result.map_err(|error| format!("{error:#}"))
}

#[test]
fn journal_scope_preserves_bytes_and_replaces_only_two_adjacent_ancestry_walks() {
    let temporary = tempfile::tempdir().unwrap();
    let request = norito::json!({"request": 17});
    let journal = Journal::create_preparation(&temporary.path().join("journal"), &request).unwrap();
    let old = measured(|| original(&journal, |_| Ok(())));
    let new = measured(|| journal.read_native_scope(|_| Ok(())));
    old.0.unwrap();
    new.0.unwrap();
    assert_eq!((old.1.ancestry_walks, new.1.ancestry_walks), (6, 4));
    assert_eq!(old.1.ancestry_opens * 2, new.1.ancestry_opens * 3);
    for allocation in [0, 1, usize::MAX] {
        let limits = norito::DecodeLimits::new(0, 0, 0, allocation, 0);
        let old = norito::core::with_decode_limits_measured(limits, || {
            outcome(original(&journal, |reader| {
                reader.read_native::<norito::json::Value>(NativeRecord::Request)
            }))
        });
        let new = norito::core::with_decode_limits_measured(limits, || {
            outcome(journal.read_native_scope(|reader| {
                reader.read_native::<norito::json::Value>(NativeRecord::Request)
            }))
        });
        assert_eq!(old, new);
        if allocation == usize::MAX {
            assert_eq!(new.0, Ok(Some(request.clone())));
        } else {
            assert!(new.0.is_err());
        }
    }
}

#[cfg(unix)]
#[test]
fn journal_scope_keeps_lock_refusal_before_callback_and_at_ordinary_error_exit() {
    let temporary = tempfile::tempdir().unwrap();
    let journal = Journal::create_preparation(
        &temporary.path().join("journal"),
        &norito::json!({"request": 17}),
    )
    .unwrap();
    let path = journal.path().join("lock");
    let held = journal.path().join("held-lock");
    std::fs::rename(&path, &held).unwrap();
    let called = Cell::new(false);
    let old = outcome(original(&journal, |_| {
        called.set(true);
        Ok(())
    }));
    let new = outcome(journal.read_native_scope(|_| {
        called.set(true);
        Ok(())
    }));
    assert!(old.is_err());
    assert_eq!(old, new);
    assert!(!called.get());
    std::fs::rename(&held, &path).unwrap();
    let mutate = |_: &mut NativeJournalReadScope<'_, '_>| -> Result<()> {
        std::fs::rename(&path, &held).unwrap();
        Err(eyre!("ordinary callback error"))
    };
    let old = outcome(original(&journal, mutate));
    std::fs::rename(&held, &path).unwrap();
    let new = outcome(journal.read_native_scope(mutate));
    std::fs::rename(&held, &path).unwrap();
    assert!(old.is_err());
    assert_eq!(old, new);
    assert!(!new.unwrap_err().contains("ordinary callback error"));
    journal.read_native_scope(|_| Ok(())).unwrap();
    assert!(Journal::open(journal.path()).is_err());
}

#[cfg(unix)]
#[test]
fn journal_scope_keeps_directory_refusal_above_lock_and_callback_errors() {
    use std::os::unix::fs::PermissionsExt as _;
    let temporary = tempfile::tempdir().unwrap();
    let journal = Journal::create_preparation(
        &temporary.path().join("journal"),
        &norito::json!({"request": 17}),
    )
    .unwrap();
    let path = journal.path().join("lock");
    let held = journal.path().join("held-lock");
    let mutate = |_: &mut NativeJournalReadScope<'_, '_>| -> Result<()> {
        std::fs::rename(&path, &held).unwrap();
        std::fs::set_permissions(journal.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        Err(eyre!("ordinary callback error"))
    };
    let restore = || {
        std::fs::set_permissions(journal.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&held, &path).unwrap();
    };
    let old = outcome(original(&journal, mutate));
    restore();
    let new = outcome(journal.read_native_scope(mutate));
    restore();
    assert!(old.is_err());
    assert_eq!(old, new);
    assert!(!new.unwrap_err().contains("ordinary callback error"));
    journal.read_native_scope(|_| Ok(())).unwrap();
}

#[cfg(unix)]
#[test]
fn journal_scope_entry_failure_closes_changed_directory_before_return_and_restores_original_owner()
{
    use std::{io, os::unix::fs::PermissionsExt as _};
    let temporary = tempfile::tempdir().unwrap();
    let request = norito::json!({"request": 17});
    let journal = Journal::create_preparation(&temporary.path().join("journal"), &request).unwrap();
    let lock_identity = FileIdentity::of(&journal.lock).unwrap();
    let directory_identity = journal.directory.identity().unwrap();
    let request_bytes = std::fs::read(journal.path().join("preparation.json")).unwrap();
    let lock = journal.path().join("lock");
    let held = journal.path().join("held-lock");
    for original in [true, false] {
        std::fs::rename(&lock, &held).unwrap();
        let directory = journal.path().to_owned();
        let called = Cell::new(false);
        let read = |_: &mut NativeJournalReadScope<'_, '_>| -> Result<()> {
            called.set(true);
            Ok(())
        };
        let result = with_entry_hook(
            move || {
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
            },
            || {
                if original {
                    original_with_entry_hook(&journal, read)
                } else {
                    journal.read_native_scope(read)
                }
            },
        );
        let error = result.unwrap_err();
        assert!(
            !called.get(),
            "native entry failure must precede the callback"
        );
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            if original {
                io::ErrorKind::NotFound
            } else {
                io::ErrorKind::PermissionDenied
            },
            "the new ordinary-result ancestry exit deliberately dominates native entry failure"
        );
        std::fs::set_permissions(journal.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&held, &lock).unwrap();
        assert_eq!(FileIdentity::of(&journal.lock).unwrap(), lock_identity);
        assert_eq!(journal.directory.identity().unwrap(), directory_identity);
        assert_eq!(
            std::fs::read(journal.path().join("preparation.json")).unwrap(),
            request_bytes
        );
        assert_eq!(
            journal
                .read_native_scope(
                    |reader| reader.read_native::<norito::json::Value>(NativeRecord::Request)
                )
                .unwrap(),
            Some(request.clone())
        );
        assert!(
            Journal::open(journal.path()).is_err(),
            "original exclusive lock remains owned"
        );
    }
}
