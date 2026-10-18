//! Darwin kernel checks for search-only ancestors and readable selected directories.
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
    _temporary: tempfile::TempDir,
    root: PathBuf,
    search: PathBuf,
    leaf: PathBuf,
}
fn fixture() -> Fixture {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "root cannot qualify search permission"
    );
    let temporary = tempfile::tempdir().unwrap();
    // Exact ancestry must not encounter the operating-system /var alias.
    let root = temporary.path().canonicalize().unwrap();
    let search = root.join("search-only");
    let leaf = search.join("wallet");
    fs::create_dir(&search).unwrap();
    fs::create_dir(&leaf).unwrap();
    fs::set_permissions(&leaf, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&search, fs::Permissions::from_mode(0o100)).unwrap();
    Fixture {
        restore: RestoreModes(vec![search.clone(), leaf.clone()]),
        _temporary: temporary,
        root,
        search,
        leaf,
    }
}

#[test]
fn apple_kernel_search_only_ancestry_keeps_selected_directory_and_originals_usable() {
    let fixture = fixture();
    assert!(open_directory(&fixture.search, DirectoryAccess::Read).is_err());
    let directory = Directory::open_exact(&fixture.leaf).unwrap();
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
    let child = directory.child(OsStr::new("child"), true, true).unwrap();
    assert_eq!(child.current().access, DirectoryAccess::Read);
    assert_eq!(
        directory
            .child_reader(OsStr::new("child"))
            .unwrap()
            .current()
            .access,
        DirectoryAccess::Read
    );
    assert_eq!(
        directory
            .child_owned(OsStr::new("child"), false, false)
            .unwrap()
            .current()
            .access,
        DirectoryAccess::Read
    );
}

#[test]
fn apple_kernel_revoked_search_and_readless_selected_directory_are_rejected() {
    let fixture = fixture();
    let directory = Directory::open_exact(&fixture.leaf).unwrap();
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o0)).unwrap();
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o100)).unwrap();
    directory.revalidate().unwrap();
    // Even non-private public readers and owned roots still require read access.
    assert!(Directory::open_reader(&fixture.search).is_err());
    assert!(Directory::open_owned(&fixture.search, false).is_err());
    fs::set_permissions(&fixture.leaf, fs::Permissions::from_mode(0o100)).unwrap();
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
}

#[test]
fn apple_kernel_search_ancestor_replacement_and_alias_are_rejected() {
    let mut fixture = fixture();
    let directory = Directory::open_exact(&fixture.leaf).unwrap();
    let retired = fixture.root.join("retired");
    fixture.restore.0.push(retired.clone());
    fs::rename(&fixture.search, &retired).unwrap();
    fs::create_dir(&fixture.search).unwrap();
    fs::create_dir(&fixture.leaf).unwrap();
    fs::set_permissions(&fixture.leaf, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o100)).unwrap();
    assert!(directory.revalidate().is_err());
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir(&fixture.leaf).unwrap();
    fs::remove_dir(&fixture.search).unwrap();
    symlink(&retired, &fixture.search).unwrap();
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
}

#[test]
fn apple_kernel_write_search_parent_syncs_create_publish_and_remove() {
    let fixture = fixture();
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o300)).unwrap();
    assert!(open_directory(&fixture.search, DirectoryAccess::Read).is_err());
    let path = fixture.search.join("stage");
    let directory = Directory::open(&path, true).unwrap();
    assert_eq!(directory.current().access, DirectoryAccess::Read);
    assert_eq!(
        directory.links[directory.links.len() - 2].access,
        DirectoryAccess::Search
    );
    directory.links[directory.links.len() - 2].sync().unwrap();
    directory.sync().unwrap();
    let published = directory
        .rename_to_sibling(OsStr::new("published"), PublishMode::CreateNew)
        .unwrap();
    published.revalidate().unwrap();
    published.remove_empty().unwrap();
    assert!(!fixture.search.join("published").exists());
    fs::set_permissions(&fixture.search, fs::Permissions::from_mode(0o100)).unwrap();
    assert!(Directory::open(&path, true).is_err());
    assert!(!path.exists());
}

#[test]
fn apple_kernel_shared_leaf_and_writable_ancestor_are_rejected() {
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

#[cfg(target_os = "macos")]
#[test]
fn apple_kernel_search_ancestor_extended_mutation_grant_is_rejected() {
    let fixture = fixture();
    let directory = Directory::open_exact(&fixture.leaf).unwrap();
    assert!(
        std::process::Command::new("chmod")
            .args(["+a", "everyone allow add_file"])
            .arg(&fixture.search)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        fs::metadata(&fixture.search).unwrap().mode() & 0o7777,
        0o100
    );
    assert!(directory.revalidate().is_err());
    assert!(Directory::open_exact(&fixture.leaf).is_err());
    assert!(
        std::process::Command::new("chmod")
            .args(["-N"])
            .arg(&fixture.search)
            .status()
            .unwrap()
            .success()
    );
    directory.revalidate().unwrap();
}
