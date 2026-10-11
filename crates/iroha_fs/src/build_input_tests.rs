//! Distinct Cargo input custody keeps legitimate hardlinks without installed authority.

use super::*;
use std::{fs, io::SeekFrom};

fn linked_input(root: &Path, name: &str, bytes: &[u8]) -> (PathBuf, PathBuf) {
    let path = root.join(name);
    let alias = root.join(format!("{name}-cargo-alias"));
    fs::write(&path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::hard_link(&path, &alias).unwrap();
    (path, alias)
}

#[test]
fn retained_build_input_reads_real_hardlinks_without_granting_strict_file_authority() {
    let temporary = tempfile::tempdir().unwrap();
    let (path, alias) = linked_input(temporary.path(), "binary", b"original");
    let mut input = RetainedBuildInput::open(&path).unwrap();
    let before = input.snapshot().unwrap();
    assert_eq!(input.len().unwrap(), 8);
    assert!(!input.is_empty().unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        assert_eq!(fs::metadata(&path).unwrap().nlink(), 2);
        assert_eq!(input.permissions().unwrap().mode() & 0o7777, 0o600);
    }
    #[cfg(windows)]
    assert!(!input.permissions().unwrap().readonly());
    let mut prefix = [0; 4];
    input.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"orig");
    input.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"original");
    input.revalidate().unwrap();
    assert_eq!(input.snapshot().unwrap(), before);
    assert!(RetainedFile::open_regular(&path).is_err());
    assert!(RetainedFile::open_private(&alias).is_err());
    assert!(SelectedRegularFile::capture(&path).is_err());
    let (empty, _) = linked_input(temporary.path(), "empty", b"");
    assert!(RetainedBuildInput::open(empty).unwrap().is_empty().unwrap());
}

#[cfg(unix)]
#[test]
fn retained_build_input_refuses_alias_bytes_links_and_named_identity_changes() {
    use std::os::unix::fs::MetadataExt;
    for attack in ["bytes", "links", "name"] {
        let temporary = tempfile::tempdir().unwrap();
        let (path, alias) = linked_input(temporary.path(), "binary", b"original");
        let identity = fs::metadata(&path).unwrap().ino();
        let input = RetainedBuildInput::open(&path).unwrap();
        let before = input.snapshot().unwrap();
        let away = temporary.path().join("held-original");
        match attack {
            "bytes" => fs::write(&alias, b"changed!").unwrap(),
            "links" => fs::hard_link(&path, temporary.path().join("third-link")).unwrap(),
            "name" => {
                fs::rename(&path, &away).unwrap();
                fs::write(&path, b"original").unwrap();
            }
            _ => unreachable!(),
        }
        assert!(input.revalidate().is_err(), "{attack}");
        assert!(input.snapshot().is_err(), "{attack}: {before:?}");
        drop(input);
        if attack == "name" {
            fs::remove_file(&path).unwrap();
            fs::rename(&away, &path).unwrap();
        } else if attack == "bytes" {
            fs::write(&alias, b"original").unwrap();
        }
        // A fresh capture may adopt restored same-object bytes and the current link count;
        // the old snapshot is never refreshed or treated as valid after the mutation.
        assert_eq!(fs::metadata(&path).unwrap().ino(), identity);
        let mut retry = RetainedBuildInput::open(&path).unwrap();
        let mut restored = Vec::new();
        retry.read_to_end(&mut restored).unwrap();
        retry.revalidate().unwrap();
        assert_eq!(restored, b"original");
    }
}

#[cfg(unix)]
#[test]
fn retained_build_input_refuses_unsafe_permissions_and_indirect_leaves() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir().unwrap();
    let (path, _) = linked_input(temporary.path(), "binary", b"original");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o622)).unwrap();
    assert!(RetainedBuildInput::open(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = temporary.path().join("symlink");
    symlink(&path, &link).unwrap();
    assert!(RetainedBuildInput::open(link).is_err());
    assert!(RetainedBuildInput::open(temporary.path()).is_err());
    RetainedBuildInput::open(path)
        .unwrap()
        .revalidate()
        .unwrap();
}

#[cfg(windows)]
#[test]
fn retained_build_input_deny_sharing_blocks_real_alias_writes_and_rename() {
    let temporary = tempfile::tempdir().unwrap();
    let (path, alias) = linked_input(temporary.path(), "binary", b"original");
    let input = RetainedBuildInput::open(&path).unwrap();
    let before = input.snapshot().unwrap();
    assert!(fs::OpenOptions::new().write(true).open(&alias).is_err());
    assert!(fs::rename(&path, temporary.path().join("moved")).is_err());
    assert_eq!(input.snapshot().unwrap(), before);
    drop(input);
    fs::write(&alias, b"changed!").unwrap();
    let mut fresh = RetainedBuildInput::open(&path).unwrap();
    let mut actual = Vec::new();
    fresh.read_to_end(&mut actual).unwrap();
    fresh.revalidate().unwrap();
    assert_eq!(actual, b"changed!");
}

#[cfg(unix)]
#[test]
fn retained_build_input_checks_real_ancestor_replacement_and_permission_changes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    for replace in [false, true] {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().join("source");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        let (path, _) = linked_input(&parent, "binary", b"original");
        let identity = fs::metadata(&path).unwrap().ino();
        let input = RetainedBuildInput::open(&path).unwrap();
        let away = temporary.path().join("held-directory");
        if replace {
            fs::rename(&parent, &away).unwrap();
            fs::create_dir(&parent).unwrap();
            fs::write(parent.join("binary"), b"original").unwrap();
        } else {
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        }
        assert!(input.revalidate().is_err());
        assert!(input.len().is_err());
        drop(input);
        if replace {
            fs::remove_file(parent.join("binary")).unwrap();
            fs::remove_dir(&parent).unwrap();
            fs::rename(&away, &parent).unwrap();
        } else {
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(fs::metadata(&path).unwrap().ino(), identity);
        RetainedBuildInput::open(path)
            .unwrap()
            .revalidate()
            .unwrap();
    }
}

#[cfg(windows)]
#[test]
fn retained_build_input_checks_actual_extra_link_or_native_denial() {
    let temporary = tempfile::tempdir().unwrap();
    let (path, _) = linked_input(temporary.path(), "binary", b"original");
    let input = RetainedBuildInput::open(&path).unwrap();
    let before = input.snapshot().unwrap();
    let third = temporary.path().join("third-link");
    match fs::hard_link(&path, &third) {
        Ok(()) => {
            assert!(third.is_file());
            assert!(input.revalidate().is_err());
            assert!(input.snapshot().is_err());
        }
        Err(_) => {
            // A held read-only source may make the native link operation impossible.
            // Observe that denial and unchanged custody; do not pretend a mutation occurred.
            assert!(!third.exists());
            assert_eq!(input.snapshot().unwrap(), before);
        }
    }
}
