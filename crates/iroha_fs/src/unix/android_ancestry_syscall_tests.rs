//! Actual Android kernel tests. Execute under the app UID with TMPDIR set from the
//! Context-selected canonical private cache path, never adb shell/root or synthetic owners.
use super::*;
use std::os::unix::fs::{PermissionsExt as _, symlink};

struct RestoreModes(Vec<PathBuf>);
impl Drop for RestoreModes {
    fn drop(&mut self) {
        for path in &self.0 {
            if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
                let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            }
        }
    }
}
struct Fixture {
    // Restore before TempDir removes the search-only fixture.
    restore: RestoreModes,
    temporary: tempfile::TempDir,
    search: PathBuf,
    leaf: PathBuf,
}
fn fixture() -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let search = temporary.path().join("search-only");
    let leaf = search.join("wallet");
    fs::create_dir(&search).unwrap();
    fs::create_dir(&leaf).unwrap();
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&search, fs::Permissions::from_mode(0o111)).unwrap();
    Fixture {
        restore: RestoreModes(vec![search.clone()]),
        temporary,
        search,
        leaf,
    }
}

#[test]
fn android_kernel_search_only_ancestry_keeps_leaf_read_sync_and_0400_files_usable() {
    let fixture = fixture();
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "root cannot qualify search permission"
    );
    assert!(open_directory(&fixture.search, DirectoryAccess::Read).is_err());
    let directory = Directory::open(&fixture.leaf, false).unwrap();
    assert_eq!(directory.current().access, DirectoryAccess::Read);
    assert_eq!(
        directory
            .links
            .iter()
            .find(|link| link.path == fixture.search)
            .unwrap()
            .access,
        DirectoryAccess::Search
    );
    directory.revalidate().unwrap();
    directory.sync().unwrap();
    assert!(directory.entries(8).unwrap().is_empty());
    let mut writer = directory
        .create_retained_private(OsStr::new("original"))
        .unwrap();
    writer.file_mut().write_all(b"canonical").unwrap();
    let sealed = writer.seal_read_only().unwrap();
    assert_eq!(sealed.file().metadata().unwrap().mode() & 0o7777, 0o400);
    assert_eq!(sealed.file().metadata().unwrap().nlink(), 1);
    assert_eq!(
        directory
            .open_retained_read_only(OsStr::new("original"))
            .unwrap()
            .snapshot()
            .unwrap()
            .length,
        9
    );
}

#[test]
fn android_kernel_search_ancestor_replacement_and_alias_are_rejected() {
    let mut fixture = fixture();
    let directory = Directory::open(&fixture.leaf, false).unwrap();
    let retired = fixture.temporary.path().join("retired");
    fixture.restore.0.push(retired.clone());
    fs::rename(&fixture.search, &retired).unwrap();
    fs::create_dir(&fixture.search).unwrap();
    fs::create_dir(&fixture.leaf).unwrap();
    fs::set_permissions(&fixture.leaf, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o111)).unwrap();
    assert!(directory.revalidate().is_err());
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(&fixture.leaf).unwrap();
    fs::remove_dir(&fixture.search).unwrap();
    symlink(&retired, &fixture.search).unwrap();
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
}

#[test]
fn android_kernel_parent_sync_after_create_publish_and_remove_uses_readable_handle() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("stage");
    let directory = Directory::open(&path, true).unwrap();
    assert_eq!(directory.current().access, DirectoryAccess::Read);
    assert_eq!(
        directory.links[directory.links.len() - 2].access,
        DirectoryAccess::Search
    );
    directory.sync().unwrap();
    let published = directory
        .rename_to_sibling(OsStr::new("published"), PublishMode::CreateNew)
        .unwrap();
    published.revalidate().unwrap();
    published.remove_empty().unwrap();
    assert!(!temporary.path().join("published").exists());
}

#[test]
fn android_kernel_leaf_or_app_ancestor_shared_mode_is_rejected() {
    let fixture = fixture();
    let directory = Directory::open_exact(&fixture.leaf).unwrap();
    fs::set_permissions(&fixture.leaf, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
    fs::set_permissions(&fixture.leaf, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
}
