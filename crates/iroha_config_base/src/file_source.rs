//! Explicit bounded bytes for configuration references, independent of their storage owner.
//!
//! The source admits file custody; the canonical configuration parser validates record contents.
//! A source error is final and must never trigger a fallback to another file or source.

use std::{io, path::Path};
use zeroize::Zeroizing;

/// Native custody requested for a referenced configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFileAccess {
    /// Public configuration material; its source still admits regular-file custody.
    Public,
    /// Private signing material whose source must admit private-file custody.
    Private,
}

/// A parser-owned admission and allocation bound for one referenced file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigFileRequest {
    /// The required native access category.
    pub access: ConfigFileAccess,
    /// Maximum number of encoded bytes the canonical parser accepts.
    pub maximum: usize,
}

/// An explicit owner of bytes consumed by the canonical configuration parser.
///
/// Implementations may read a native file or supply an already admitted immutable image. Paths
/// retain their original configuration provenance. A source must never silently substitute another
/// path or fall back to a different source when its selected input is absent or invalid.
pub trait ConfigFileSource {
    /// Read the exact selected file within its required custody and byte bound.
    ///
    /// # Errors
    /// Refuses missing input, unsafe custody, excessive size, or native read failures.
    fn read(&self, path: &Path, request: ConfigFileRequest) -> io::Result<Zeroizing<Vec<u8>>>;
}

/// Read referenced bytes and enforce the parser's bound independently of the source.
///
/// # Errors
/// Returns the source's error or rejects a source response exceeding the caller's byte bound.
pub fn read_checked(
    source: &dyn ConfigFileSource,
    path: &Path,
    request: ConfigFileRequest,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let bytes = source.read(path, request)?;
    if bytes.len() > request.maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration file exceeds the parser byte bound",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Source {
        calls: Cell<usize>,
        bytes: Vec<u8>,
        fails: bool,
    }
    impl ConfigFileSource for Source {
        fn read(&self, path: &Path, request: ConfigFileRequest) -> io::Result<Zeroizing<Vec<u8>>> {
            assert_eq!(path, Path::new("original/identity"));
            assert_eq!(request.access, ConfigFileAccess::Public);
            assert_eq!(request.maximum, 3);
            self.calls.set(self.calls.get() + 1);
            if self.fails {
                return Err(io::ErrorKind::NotFound.into());
            }
            Ok(Zeroizing::new(self.bytes.clone()))
        }
    }

    #[test]
    fn bounded_source_preserves_original_request_and_rejects_oversized_responses() {
        let request = ConfigFileRequest {
            access: ConfigFileAccess::Public,
            maximum: 3,
        };
        for (bytes, succeeds) in [(vec![1, 2, 3], true), (vec![1, 2, 3, 4], false)] {
            let source = Source {
                calls: Cell::new(0),
                bytes,
                fails: false,
            };
            let result = read_checked(&source, Path::new("original/identity"), request);
            assert_eq!(result.is_ok(), succeeds);
            if succeeds {
                assert_eq!(result.unwrap().as_slice(), &[1, 2, 3]);
            } else {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
            assert_eq!(source.calls.get(), 1);
        }
    }

    #[test]
    fn selected_source_failure_is_returned_without_another_read() {
        let source = Source {
            calls: Cell::new(0),
            bytes: vec![1],
            fails: true,
        };
        let error = read_checked(
            &source,
            Path::new("original/identity"),
            ConfigFileRequest {
                access: ConfigFileAccess::Public,
                maximum: 3,
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert_eq!(source.calls.get(), 1);
    }
}
