//! Genuine journal reads measure ancestry consolidation and preserve fresh leaf/error boundaries.
use super::*;
use iroha_fs::CustodyWorkV1;
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Work {
    leaves: usize,
    locks: usize,
    entries: usize,
    decodes: usize,
}
thread_local! {
    static WORK: Cell<Option<Work>> = const { Cell::new(None) };
}
fn record(change: impl FnOnce(&mut Work)) {
    WORK.with(|slot| {
        if let Some(mut work) = slot.get() {
            change(&mut work);
            slot.set(Some(work));
        }
    });
}
pub(super) fn record_leaf() {
    record(|work| work.leaves += 1);
}
pub(super) fn record_lock() {
    record(|work| work.locks += 1);
}
pub(super) fn record_inventory_entry() {
    record(|work| work.entries += 1);
}
pub(super) fn record_decode() {
    record(|work| work.decodes += 1);
}
fn measured<T>(read: impl FnOnce() -> T) -> (T, Work, CustodyWorkV1) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            WORK.with(|slot| slot.set(None));
        }
    }
    WORK.with(|slot| {
        assert!(slot.get().is_none());
        slot.set(Some(Work::default()));
    });
    let _reset = Reset;
    let before = CustodyWorkV1::current_thread();
    let result = read();
    (
        result,
        WORK.with(|slot| slot.get().unwrap()),
        CustodyWorkV1::current_thread().since(before),
    )
}
fn original<T>(
    journal: &Journal,
    read: impl for<'read, 'scope> FnOnce(&mut NativeJournalReadScope<'read, 'scope>) -> Result<T>,
) -> Result<T> {
    journal.verify_native_inventory()?;
    journal.read_native_scope(read)
}
fn read_records(
    reader: &mut NativeJournalReadScope<'_, '_>,
) -> Result<(Vec<Option<json::Value>>, bool)> {
    let mut records = Vec::new();
    for record in [
        NativeRecord::Request,
        NativeRecord::Payload,
        NativeRecord::Operation,
        NativeRecord::Retired,
    ] {
        records.push(reader.read_native(record)?);
    }
    Ok((records, reader.has_dispatch_evidence()?))
}
fn outcome<T>(result: Result<T>) -> std::result::Result<T, String> {
    result.map_err(|error| format!("{error:#}"))
}

#[test]
fn journal_inventory_scope_preserves_actual_leaf_lock_decode_work_and_budgets() {
    let root = tempfile::tempdir().unwrap();
    let value = norito::json!({"request": 17});
    let journal = Journal::create_preparation(&root.path().join("journal"), &value).unwrap();
    journal.write_native(NativeRecord::Retired, &value).unwrap();
    let old = measured(|| outcome(original(&journal, read_records)));
    let new = measured(|| outcome(journal.read_native_inventory_scope(read_records)));
    assert_eq!(old.0, new.0);
    assert_eq!(
        new.0.unwrap(),
        (vec![Some(value.clone()), None, None, Some(value)], false)
    );
    assert_eq!(old.1, new.1);
    assert_eq!(
        new.1,
        Work {
            leaves: 6,
            locks: 18,
            entries: 3,
            decodes: 2
        }
    );
    #[cfg(unix)]
    {
        assert_eq!((old.2.ancestry_walks, new.2.ancestry_walks), (10, 3));
        assert_eq!(old.2.ancestry_opens * 3, new.2.ancestry_opens * 10);
    }
    #[cfg(windows)]
    assert_eq!(old.2, new.2);
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let (_, wide) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        journal.read_native_inventory_scope(read_records).unwrap()
    });
    let exact = wide.total_allocated_bytes();
    assert!(exact > 1);
    for allocation in [0, 1, exact - 1, exact] {
        let old = norito::core::with_decode_limits_measured(limits(allocation), || {
            measured(|| outcome(original(&journal, read_records)))
        });
        let new = norito::core::with_decode_limits_measured(limits(allocation), || {
            measured(|| outcome(journal.read_native_inventory_scope(read_records)))
        });
        assert_eq!(old.0.0, new.0.0);
        assert_eq!(old.0.1, new.0.1);
        assert_eq!(old.1, new.1);
        assert_eq!(new.0.0.is_ok(), allocation == exact);
    }
}

#[cfg(unix)]
#[test]
fn journal_inventory_scope_keeps_native_precedence_fresh_bytes_and_original_retry() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let root = tempfile::tempdir().unwrap();
    let created = Journal::create_preparation(
        &root.path().join("journal"),
        &norito::json!({"request": 17}),
    )
    .unwrap();
    drop(created);
    let parent = PrivateDirectory::open(root.path()).unwrap();
    let journal = Journal::open_optional_child(&parent, "journal")
        .unwrap()
        .unwrap();
    let directory_id = journal.directory.identity().unwrap();
    let lock_id = FileIdentity::of(&journal.lock).unwrap();
    let request = fs::read(journal.path().join("preparation.json")).unwrap();
    let lock = journal.path().join("lock");
    let held = root.path().join("held-lock");
    for attack in ["none", "parent", "directory", "lock", "both", "request"] {
        for ordinary_error in [false, true] {
            let run = |old| {
                let read = |reader: &mut NativeJournalReadScope<'_, '_>| -> Result<()> {
                    assert!(
                        reader
                            .read_native::<json::Value>(NativeRecord::Request)?
                            .is_some()
                    );
                    if attack == "parent" {
                        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                    if attack == "directory" || attack == "both" {
                        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o755))
                            .unwrap();
                    }
                    if attack == "lock" || attack == "both" {
                        fs::rename(&lock, &held).unwrap();
                    }
                    if attack == "request" {
                        fs::write(journal.path().join("preparation.json"), b"{").unwrap();
                        reader.read_native::<json::Value>(NativeRecord::Request)?;
                    }
                    if ordinary_error {
                        Err(eyre!("ordinary callback refusal"))
                    } else {
                        Ok(())
                    }
                };
                let result = if old {
                    original(&journal, read)
                } else {
                    journal.read_native_inventory_scope(read)
                };
                fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o700)).unwrap();
                if held.exists() {
                    fs::rename(&held, &lock).unwrap();
                }
                fs::write(journal.path().join("preparation.json"), &request).unwrap();
                outcome(result)
            };
            let old = run(true);
            let new = run(false);
            assert_eq!(old, new, "attack={attack}, ordinary_error={ordinary_error}");
            assert_eq!(new.is_ok(), attack == "none" && !ordinary_error);
            if attack != "none" {
                assert!(!new.unwrap_err().contains("ordinary callback refusal"));
            }
            journal.read_native_inventory_scope(read_records).unwrap();
            assert_eq!(journal.directory.identity().unwrap(), directory_id);
            assert_eq!(FileIdentity::of(&journal.lock).unwrap(), lock_id);
            assert!(
                Journal::open(journal.path()).is_err(),
                "original exclusive lock remains held"
            );
        }
    }
    // Unknown native names must refuse before entering the read callback.
    let extra = journal.directory.create_lock("foreign").unwrap();
    let called = Cell::new(false);
    let refused = journal.read_native_inventory_scope(|_| {
        called.set(true);
        Ok(())
    });
    assert!(refused.is_err());
    assert!(!called.get());
    drop(extra);
    fs::remove_file(journal.path().join("foreign")).unwrap();
    journal.read_native_inventory_scope(read_records).unwrap();
}

#[cfg(unix)]
#[test]
fn journal_inventory_scope_closes_nested_entry_and_error_before_original_owner_can_restore() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let root = tempfile::tempdir().unwrap();
    let journal = Journal::create_preparation(
        &root.path().join("journal"),
        &norito::json!({"request": 17}),
    )
    .unwrap();
    iroha_fs::custody_transaction(|| -> Result<()> {
        journal.directory.join_custody_transaction()?;
        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let called = Cell::new(false);
        let refused = journal.read_native_inventory_scope(|_| {
            called.set(true);
            Ok(())
        });
        assert!(refused.is_err());
        assert!(
            !called.get(),
            "a joined outer owner cannot lend stale entry custody"
        );
        fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o700)).unwrap();
        journal.read_native_inventory_scope(read_records)?;
        Ok(())
    })
    .unwrap();
    for ordinary_error in [false, true] {
        iroha_fs::custody_transaction(|| -> Result<()> {
            journal.directory.join_custody_transaction()?;
            let refused = journal.read_native_inventory_scope(|reader| {
                read_records(reader)?;
                fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o755)).unwrap();
                if ordinary_error {
                    Err(eyre!("ordinary nested refusal"))
                } else {
                    Ok(())
                }
            });
            let error = outcome(refused).unwrap_err();
            assert!(!error.contains("ordinary nested refusal"));
            // Restoration occurs only after the inner boundary returned its native refusal.
            fs::set_permissions(journal.path(), fs::Permissions::from_mode(0o700)).unwrap();
            journal.read_native_inventory_scope(read_records)?;
            Ok(())
        })
        .unwrap();
    }
}

#[cfg(unix)]
#[test]
fn journal_inventory_scope_respects_surrounding_roots_at_both_fences() {
    use std::{fs, os::unix::fs::PermissionsExt as _};
    let root = tempfile::tempdir().unwrap();
    let journal = Journal::create_preparation(
        &root.path().join("journal"),
        &norito::json!({"request": 17}),
    )
    .unwrap();
    let other = PrivateDirectory::open_or_create(&root.path().join("other")).unwrap();
    for at_entry in [false, true] {
        iroha_fs::custody_transaction(|| -> Result<()> {
            other.join_custody_transaction()?;
            if at_entry {
                fs::set_permissions(other.path(), fs::Permissions::from_mode(0o755)).unwrap();
            }
            let called = Cell::new(false);
            let refused = journal.read_native_inventory_scope(|reader| -> Result<()> {
                called.set(true);
                read_records(reader)?;
                fs::set_permissions(other.path(), fs::Permissions::from_mode(0o755)).unwrap();
                Err(eyre!("ordinary callback refusal"))
            });
            assert_eq!(called.get(), !at_entry);
            assert!(
                !outcome(refused)
                    .unwrap_err()
                    .contains("ordinary callback refusal")
            );
            // Global fences close before the outer caller can restore its unrelated root.
            fs::set_permissions(other.path(), fs::Permissions::from_mode(0o700)).unwrap();
            journal.read_native_inventory_scope(read_records)?;
            Ok(())
        })
        .unwrap();
    }
}
