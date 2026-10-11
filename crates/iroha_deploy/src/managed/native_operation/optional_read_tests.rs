//! Fresh native custody and exact bytes at the shared optional-file ownership boundary.

use super::{Error, PrivateDirectory, PublishMode, read_optional};

fn require_native_refusal(directory: &PrivateDirectory, name: &str, maximum: usize) {
    let original = directory.read(name, maximum).unwrap_err();
    let observed = read_optional(directory, name, maximum).unwrap_err();
    let Error::Io(observed) = observed else {
        panic!("optional read changed the original native I/O refusal");
    };
    assert_eq!(observed.kind(), original.kind());
    assert_eq!(observed.raw_os_error(), original.raw_os_error());
    assert_eq!(observed.to_string(), original.to_string());
}

#[test]
fn optional_reads_keep_exact_empty_and_bounded_original_bytes_and_absence() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    assert_eq!(read_optional(&directory, "absent", 0).unwrap(), None);
    directory
        .write_atomic("empty", b"", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        read_optional(&directory, "empty", 0).unwrap(),
        Some(Vec::new())
    );
    let original = [0, 0xff, 0x80, 7, 0, 31];
    directory
        .write_atomic("original", &original, PublishMode::CreateNew)
        .unwrap();
    let bytes: Vec<u8> = read_optional(&directory, "original", original.len())
        .unwrap()
        .unwrap();
    assert_eq!(bytes, original);
    assert_eq!(
        directory
            .read("original", original.len())
            .unwrap()
            .as_slice(),
        original
    );
    assert_eq!(directory.entries(2).unwrap().len(), 2);
}

#[test]
fn optional_reads_keep_original_size_refusal_retry_and_fresh_replacement_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    directory
        .write_atomic("original", b"first", PublishMode::CreateNew)
        .unwrap();
    require_native_refusal(&directory, "original", 4);
    assert_eq!(
        read_optional(&directory, "original", 5).unwrap().unwrap(),
        b"first"
    );
    directory
        .write_atomic("original", b"next exact image", PublishMode::Replace)
        .unwrap();
    require_native_refusal(&directory, "original", 5);
    assert_eq!(
        read_optional(&directory, "original", 16).unwrap().unwrap(),
        b"next exact image"
    );
    assert_eq!(directory.entries(1).unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn optional_reads_keep_native_link_permission_and_replaced_directory_refusals() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    for attack in ["symlink", "hardlink", "mode", "directory"] {
        let temporary = tempfile::tempdir().unwrap();
        let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
        directory
            .write_atomic("original", b"exact retained bytes", PublishMode::CreateNew)
            .unwrap();
        let original = directory.path().join("original");
        let name = match attack {
            "symlink" => {
                symlink("original", directory.path().join("selected")).unwrap();
                "selected"
            }
            "hardlink" => {
                std::fs::hard_link(&original, directory.path().join("selected")).unwrap();
                "selected"
            }
            "mode" => {
                std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o644))
                    .unwrap();
                "original"
            }
            "directory" => {
                std::fs::rename(directory.path(), temporary.path().join("retained")).unwrap();
                std::fs::create_dir(directory.path()).unwrap();
                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                    .unwrap();
                "original"
            }
            _ => unreachable!(),
        };
        require_native_refusal(&directory, name, 20);
        if attack == "mode" {
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                read_optional(&directory, name, 20).unwrap().unwrap(),
                b"exact retained bytes"
            );
        }
    }
}
