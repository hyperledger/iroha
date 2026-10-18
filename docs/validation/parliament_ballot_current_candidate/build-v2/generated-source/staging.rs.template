//! Bounded regular-file retrieval before the verifier's charged invocation.
//!
//! Retrieval can block or retry: no verification-time bound applies here. The
//! returned caller-owned bytes remain outside the verifier arena until its
//! bounded copy. The File is dropped before this module returns the bytes.

use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};

use crate::budget::MAX_INPUT_BYTES;

/// A fixed-size staging refusal; no I/O error owner crosses the worker boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError {
    /// Opening the regular file failed.
    Open,
    /// Reading metadata failed.
    Metadata,
    /// The opened object is not a regular file.
    NotRegular,
    /// The announced length exceeds the bounded retrieval cap.
    TooLarge,
    /// Retrieval stopped early or reported an I/O failure.
    Read,
    /// An extra byte followed the announced length.
    LengthChanged,
}

impl StageError {
    /// Stable diagnostic label, without OS-dependent formatting or allocation.
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

/// Retrieve at most the declared bounded bytes and check for an extra byte.
///
/// This operation deliberately happens outside charged verification. Even an
/// interrupted read is not assigned a finite completion time. The one-byte
/// trailing check never extends the owned buffer beyond the cap.
fn read_bounded(reader: &mut impl Read, length: usize) -> Result<Vec<u8>, StageError> {
    if length > MAX_INPUT_BYTES {
        return Err(StageError::TooLarge);
    }
    let mut record = vec![0u8; length];
    reader
        .read_exact(&mut record)
        .map_err(|_| StageError::Read)?;
    match reader.read(&mut [0u8; 1]) {
        Ok(0) => Ok(record),
        Ok(_) => Err(StageError::LengthChanged),
        Err(_) => Err(StageError::Read),
    }
}

/// Retrieve a regular file and close it before yielding the immutable staging
/// owner. The caller must keep that owner alive through the synchronous worker
/// join, then drop it outside the charged interval.
pub fn from_path(path: &Path) -> Result<Vec<u8>, StageError> {
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
    let result = read_bounded(&mut file, length);
    // All paths above also drop by RAII; successful bytes never retain File.
    drop(file);
    result
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
    fn bounded_reader_preserves_exact_bytes_and_empty_input() {
        assert_eq!(
            read_bounded(&mut Cursor::new(b"record"), 6),
            Ok(b"record".to_vec())
        );
        assert_eq!(read_bounded(&mut Cursor::new(b""), 0), Ok(Vec::new()));
        let largest = vec![7u8; MAX_INPUT_BYTES];
        let observed = read_bounded(&mut Cursor::new(&largest), largest.len());
        assert_eq!(observed, Ok(largest));
    }

    #[test]
    fn declared_lengths_never_hide_truncation_extra_bytes_or_read_errors() {
        assert_eq!(
            read_bounded(&mut Cursor::new(b"x"), 2),
            Err(StageError::Read)
        );
        assert_eq!(
            read_bounded(&mut Cursor::new(b"xy"), 1),
            Err(StageError::LengthChanged)
        );
        assert_eq!(
            read_bounded(&mut Cursor::new(b"x"), 0),
            Err(StageError::LengthChanged)
        );
        assert_eq!(read_bounded(&mut Refuse, 1), Err(StageError::Read));
        assert_eq!(read_bounded(&mut Refuse, 0), Err(StageError::Read));
        // Refuse would return Read if called; the size check runs first.
        assert_eq!(
            read_bounded(&mut Refuse, MAX_INPUT_BYTES + 1),
            Err(StageError::TooLarge)
        );
        assert_eq!(
            read_bounded(&mut Refuse, usize::MAX),
            Err(StageError::TooLarge)
        );
    }

    #[test]
    fn regular_file_staging_returns_owned_bytes_and_refuses_nonfiles() {
        let path =
            std::env::temp_dir().join(format!("parliament-memory-stage-{}", std::process::id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("unique test path");
        drop(file);
        std::fs::write(&path, b"staged").expect("write fixture");
        let staged = from_path(&path).expect("regular bounded input");
        std::fs::remove_file(&path).expect("remove fixture");
        assert_eq!(staged, b"staged");
        assert_eq!(from_path(&path), Err(StageError::Open));
        assert_eq!(
            from_path(&std::env::temp_dir()),
            Err(StageError::NotRegular)
        );
    }

    #[test]
    fn every_error_has_a_distinct_static_stage_label() {
        let errors = [
            StageError::Open,
            StageError::Metadata,
            StageError::NotRegular,
            StageError::TooLarge,
            StageError::Read,
            StageError::LengthChanged,
        ];
        for (index, error) in errors.iter().enumerate() {
            assert!(error.label().starts_with("staging_"));
            assert!(
                errors[..index]
                    .iter()
                    .all(|other| other.label() != error.label())
            );
        }
    }
}
