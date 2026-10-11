//! Filesystem authentication and immutable durable record regressions.
use super::*;
use iroha_fs::FileIdentity;
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};

#[test]
fn journal_roundtrip_is_immutable_and_exclusively_locked() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("journal");
    let journal = Journal::open(&path, true)?;
    journal.put_exact("plan.json", &vec!["original"])?;
    journal.put_exact("plan.json", &vec!["original"])?;
    assert!(
        journal
            .put_exact("plan.json", &vec!["substitution"])
            .is_err()
    );
    assert_eq!(journal.read::<Vec<String>>("plan.json")?, vec!["original"]);
    assert!(Journal::open(&path, false).is_err());
    drop(journal);
    assert!(Journal::open(&path, false)?.exists("plan.json")?);
    assert!(validate_name("../elsewhere").is_err());
    assert!(validate_name("..").is_err());
    Ok(())
}

#[test]
#[cfg(unix)]
fn journal_rejects_symlink_hardlink_and_nonprivate_records() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("journal");
    let journal = Journal::open(&path, true)?;
    journal.put_exact("original.json", &"evidence")?;
    symlink(path.join("original.json"), path.join("symlink.json"))?;
    assert!(journal.read::<String>("symlink.json").is_err());
    std::fs::hard_link(path.join("original.json"), path.join("hardlink.json"))?;
    assert!(journal.read::<String>("original.json").is_err());
    assert!(journal.read::<String>("hardlink.json").is_err());
    std::fs::remove_file(path.join("hardlink.json"))?;
    std::fs::set_permissions(
        path.join("original.json"),
        std::fs::Permissions::from_mode(0o644),
    )?;
    assert!(journal.read::<String>("original.json").is_err());
    symlink(&path, root.path().join("linked-journal"))?;
    assert!(Journal::open(&root.path().join("linked-journal"), false).is_err());
    drop(journal);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    assert!(Journal::open(&path, false).is_err());
    Ok(())
}

#[test]
fn journal_rejects_truncated_and_oversized_evidence() -> Result<()> {
    use std::io::Write as _;
    let root = tempfile::tempdir()?;
    let path = root.path().join("journal");
    let journal = Journal::open(&path, true)?;
    let mut file = journal.directory.open_lock("partial.json")?;
    file.write_all(b"{\"partial\":")?;
    file.sync_all()?;
    assert!(journal.read::<norito::json::Value>("partial.json").is_err());
    assert!(journal.put_exact("partial.json", &"replacement").is_err());
    file.set_len(MAX_RECORD_BYTES as u64 + 1)?;
    assert!(journal.exists("partial.json").is_err());
    Ok(())
}

#[test]
fn journal_inspection_never_creates_missing_custody_and_cancellation_rejects_unknown_evidence()
-> Result<()> {
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("journal");
    assert!(Journal::open(&path, false).is_err());
    assert!(!path.exists());
    let directory = PrivateDirectory::open_or_create(&path)?;
    assert!(Journal::open(&path, false).is_err());
    assert!(directory.entries(10)?.is_empty());
    let journal = Journal::open(&path, true)?;
    journal.require_unattempted()?;
    journal.put_exact("plan.json", &"signed exact plan")?;
    journal.require_unattempted()?;
    journal.put_exact("attempt.json", &"ambiguous dispatch")?;
    assert!(journal.require_unattempted().is_err());
    Ok(())
}

#[test]
fn atomic_plan_publication_is_complete_exact_and_exclusively_locked() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("atomic-journal");
    let plan = vec!["exact signed plan"];
    let journal = Journal::persist_plan(&path, &plan)?;
    assert_eq!(
        journal.directory.entries(4)?,
        vec![
            std::ffi::OsString::from("lock"),
            std::ffi::OsString::from("plan.json")
        ]
    );
    journal.require_exact("plan.json", &plan)?;
    assert!(Journal::persist_plan(&path, &plan).is_err());
    let original_lock = FileIdentity::of(&journal.lock)?;
    let original_plan = FileIdentity::of(&journal.directory.open_read("plan.json")?)?;
    drop(journal);
    let reopened = Journal::persist_plan(&path, &plan)?;
    assert_eq!(FileIdentity::of(&reopened.lock)?, original_lock);
    assert_eq!(
        FileIdentity::of(&reopened.directory.open_read("plan.json")?)?,
        original_plan,
    );
    assert_eq!(reopened.read::<Vec<String>>("plan.json")?, plan);
    drop(reopened);
    assert!(Journal::persist_plan(&path, &vec!["other signed plan"]).is_err());
    assert_eq!(
        std::fs::read(path.join("plan.json"))?,
        norito::json::to_vec(&plan)?
    );
    assert!(Journal::persist_plan(Path::new(""), &plan).is_err());
    Ok(())
}

#[test]
fn atomic_plan_publication_never_repairs_an_occupied_partial_directory() -> Result<()> {
    let root = tempfile::tempdir()?;
    for state in ["empty", "lock-only", "plan-only", "partial-plan"] {
        let path = root.path().join(state);
        let directory = PrivateDirectory::open_or_create(&path)?;
        if matches!(state, "lock-only" | "partial-plan") {
            directory.open_lock("lock")?;
        }
        if matches!(state, "plan-only" | "partial-plan") {
            directory.write_atomic("plan.json", b"incomplete plan", PublishMode::CreateNew)?;
        }
        let before = directory.entries(4)?;
        assert!(
            Journal::persist_plan(&path, &vec!["complete plan"]).is_err(),
            "{state}"
        );
        assert_eq!(directory.entries(4)?, before, "{state}");
        if matches!(state, "plan-only" | "partial-plan") {
            assert_eq!(std::fs::read(path.join("plan.json"))?, b"incomplete plan");
        }
    }
    Ok(())
}

#[test]
fn exact_plan_requirement_never_creates_an_absent_record() -> Result<()> {
    let root = tempfile::tempdir()?;
    let journal = Journal::open(&root.path().join("journal"), true)?;
    assert!(journal.require_exact("plan.json", &vec!["plan"]).is_err());
    assert!(!journal.exists("plan.json")?);
    assert!(
        journal
            .require_exact("../plan.json", &vec!["plan"])
            .is_err()
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn replaced_original_lock_refuses_journal_reads_and_writes() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("journal");
    let journal = Journal::persist_plan(&path, &vec!["original"])?;
    std::fs::rename(path.join("lock"), path.join("retired-lock"))?;
    journal.directory.open_lock("lock")?;
    assert!(journal.revalidate().is_err());
    assert!(journal.exists("plan.json").is_err());
    assert!(journal.read::<Vec<String>>("plan.json").is_err());
    assert!(
        journal
            .require_exact("plan.json", &vec!["original"])
            .is_err()
    );
    assert!(journal.require_unattempted().is_err());
    assert!(
        journal
            .put_exact("attempt.json", &"must not dispatch")
            .is_err()
    );
    assert!(
        journal
            .put_exact_limited("bounded.json", &"must not dispatch", 128)
            .is_err()
    );
    assert!(
        journal
            .read_limited::<Vec<String>>(
                "plan.json",
                128,
                norito::DecodeLimits::new(8, 128, 8, 256, 8)
            )
            .is_err()
    );
    assert!(!path.join("attempt.json").exists());
    assert!(!path.join("bounded.json").exists());
    Ok(())
}

#[test]
#[cfg(unix)]
fn same_inode_lock_mutation_refuses_original_journal_custody() -> Result<()> {
    use std::io::Write as _;
    let root = tempfile::tempdir()?;
    let path = root.path().join("journal");
    let journal = Journal::persist_plan(&path, &vec!["original"])?;
    let identity = FileIdentity::of(&journal.lock)?;
    let mut changed = journal.directory.open_existing_lock("lock")?;
    changed.write_all(b"changed original lock")?;
    changed.sync_all()?;
    assert_eq!(FileIdentity::of(&changed)?, identity);
    assert!(journal.revalidate().is_err());
    assert!(journal.exists("plan.json").is_err());
    assert!(
        journal
            .put_exact("cancelled.json", &"must not cancel")
            .is_err()
    );
    assert!(!path.join("cancelled.json").exists());
    Ok(())
}

#[test]
#[cfg(windows)]
fn held_journal_lock_natively_refuses_name_replacement() -> Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("journal");
    let journal = Journal::persist_plan(&path, &vec!["original"])?;
    // Native private opens exclude delete sharing for the complete held lifetime.
    assert!(std::fs::rename(path.join("lock"), path.join("retired-lock")).is_err());
    journal.revalidate()?;
    journal.require_exact("plan.json", &vec!["original"])?;
    assert!(!path.join("retired-lock").exists());
    Ok(())
}
