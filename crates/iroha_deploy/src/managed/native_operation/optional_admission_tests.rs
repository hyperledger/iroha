//! Shared optional-leaf admission keeps original bytes and missing-ancestor errors distinct.

use super::*;

#[test]
fn shared_optional_native_read_keeps_initial_absence_and_original_ancestor_refusal() {
    let temporary = tempfile::tempdir().unwrap();
    let directory = PrivateDirectory::open_or_create(temporary.path().join("private")).unwrap();
    assert!(read_optional(&directory, "missing", 0).unwrap().is_none());
    assert!(read_optional(&directory, "../invalid", 0).is_err());
    directory
        .write_atomic("record", b"original", PublishMode::CreateNew)
        .unwrap();
    assert_eq!(
        read_optional(&directory, "record", 8).unwrap().unwrap(),
        b"original"
    );
    assert!(
        matches!(read_optional(&directory, "record", 7), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput)
    );
    #[cfg(unix)]
    {
        let displaced = temporary.path().join("displaced");
        std::fs::rename(directory.path(), &displaced).unwrap();
        assert!(
            matches!(read_optional(&directory, "missing", 0), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound)
        );
        std::fs::rename(&displaced, directory.path()).unwrap();
    }
    assert!(read_optional(&directory, "missing", 0).unwrap().is_none());
    assert_eq!(
        read_optional(&directory, "record", 8).unwrap().unwrap(),
        b"original"
    );
}
