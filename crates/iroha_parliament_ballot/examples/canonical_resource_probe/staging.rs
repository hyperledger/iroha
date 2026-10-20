//! Separately bounded regular-file retrieval before the worker's charged interval.

use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

/// A retrieval failure owns no heap object across the worker boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError {
    Open,
    Metadata,
    NotRegular,
    TooLarge,
    Read,
    LengthChanged,
}

impl StageError {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Open => "staging_open",
            Self::Metadata => "staging_metadata",
            Self::NotRegular => "staging_not_regular",
            Self::TooLarge => "staging_size",
            Self::Read => "staging_read",
            Self::LengthChanged => "staging_length_changed",
        }
    }
}

fn read_bounded(reader: &mut impl Read, length: usize, cap: usize) -> Result<Vec<u8>, StageError> {
    if length > cap {
        return Err(StageError::TooLarge);
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| StageError::Read)?;
    match reader.read(&mut [0; 1]) {
        Ok(0) => Ok(bytes),
        Ok(_) => Err(StageError::LengthChanged),
        Err(_) => Err(StageError::Read),
    }
}

pub fn from_path(path: &Path, cap: usize) -> Result<Vec<u8>, StageError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| StageError::Open)?;
    let metadata = file.metadata().map_err(|_| StageError::Metadata)?;
    if !metadata.is_file() {
        return Err(StageError::NotRegular);
    }
    let length = usize::try_from(metadata.len()).map_err(|_| StageError::TooLarge)?;
    // The file and every error are dropped before this function returns its bytes.
    read_bounded(&mut file, length, cap)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    struct Refuse;
    impl Read for Refuse {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected retrieval error"))
        }
    }

    #[test]
    fn bounded_reader_checks_actual_bytes_and_does_not_read_over_cap() {
        assert_eq!(
            read_bounded(&mut Cursor::new(b"abc"), 3, 3),
            Ok(b"abc".to_vec())
        );
        assert_eq!(read_bounded(&mut Cursor::new(b""), 0, 0), Ok(Vec::new()));
        assert_eq!(
            read_bounded(&mut Cursor::new(b"abc"), 2, 3),
            Err(StageError::LengthChanged)
        );
        assert_eq!(
            read_bounded(&mut Cursor::new(b"a"), 2, 3),
            Err(StageError::Read)
        );
        assert_eq!(read_bounded(&mut Refuse, 0, 3), Err(StageError::Read));
        assert_eq!(read_bounded(&mut Refuse, 4, 3), Err(StageError::TooLarge));
        assert_eq!(
            read_bounded(&mut Refuse, usize::MAX, 3),
            Err(StageError::TooLarge)
        );
    }

    #[test]
    fn retrieval_owns_bytes_and_rejects_nonfiles() {
        let path =
            std::env::temp_dir().join(format!("parliament-canonical-stage-{}", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        drop(file);
        std::fs::write(&path, b"abc").unwrap();
        assert_eq!(from_path(&path, 3), Ok(b"abc".to_vec()));
        assert_eq!(from_path(&path, 2), Err(StageError::TooLarge));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(from_path(&path, 3), Err(StageError::Open));
        assert_eq!(
            from_path(&std::env::temp_dir(), 3),
            Err(StageError::NotRegular)
        );
        let cases = [
            StageError::Open,
            StageError::Metadata,
            StageError::NotRegular,
            StageError::TooLarge,
            StageError::Read,
            StageError::LengthChanged,
        ];
        for (index, case) in cases.iter().enumerate() {
            assert!(
                cases[..index]
                    .iter()
                    .all(|other| case.label() != other.label())
            );
        }
    }
}
