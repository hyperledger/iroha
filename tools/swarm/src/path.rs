//! Path utils.

/// Absolute filesystem path.
#[derive(serde::Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(transparent)]
pub struct AbsolutePath(std::path::PathBuf);

/// Relative filesystem path.
#[derive(serde::Serialize, Clone, PartialEq, Eq, Debug)]
#[serde(transparent)]
pub struct RelativePath(std::path::PathBuf);

#[derive(displaydoc::Display, Debug)]
pub enum Error {
    /// Failed to construct an absolute path: {0}.
    AbsolutePath(std::io::Error),
    /// Failed to construct a relative path.
    RelativePath,
}

impl std::error::Error for Error {}

impl AbsolutePath {
    pub fn new(path: &std::path::Path) -> Result<Self, Error> {
        Ok(Self(if path.is_absolute() {
            path.to_path_buf()
        } else {
            path_absolutize::Absolutize::absolutize(path)
                .map_err(Error::AbsolutePath)?
                .to_path_buf()
        }))
    }

    #[allow(dead_code)]
    fn with_virtual_root(
        path: &std::path::Path,
        virtual_root: &std::path::Path,
    ) -> Result<Self, Error> {
        Ok(Self(
            path_absolutize::Absolutize::absolutize_virtually(path, virtual_root)
                .map_err(Error::AbsolutePath)?
                .to_path_buf(),
        ))
    }

    pub fn relative_to(&self, to: &Self) -> Result<RelativePath, Error> {
        let path = pathdiff::diff_paths(&self.0, &to.0).ok_or(Error::RelativePath)?;
        Ok(RelativePath(if path.starts_with("..") {
            path
        } else {
            std::path::Path::new("./").join(path)
        }))
    }

    pub fn parent(&self) -> Option<Self> {
        Some(Self(self.0.parent()?.to_path_buf()))
    }
}

impl AsRef<std::path::Path> for AbsolutePath {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

impl AsRef<std::path::Path> for RelativePath {
    fn as_ref(&self) -> &std::path::Path {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::{AbsolutePath, RelativePath};

    #[test]
    fn relative_inner_path_starts_with_dot() {
        let root = "/".as_ref();
        let a = AbsolutePath::with_virtual_root("./a/b/c".as_ref(), root).unwrap();
        let b = AbsolutePath::with_virtual_root("./".as_ref(), root).unwrap();

        assert_eq!(
            a.relative_to(&b).unwrap(),
            RelativePath(std::path::PathBuf::from("./a/b/c"))
        );
    }

    #[test]
    fn relative_outer_path_starts_with_dots() {
        let root = "/".as_ref();
        let a = AbsolutePath::with_virtual_root("./a/b/c".as_ref(), root).unwrap();
        let b = AbsolutePath::with_virtual_root("./cde".as_ref(), root).unwrap();

        assert_eq!(
            b.relative_to(&a).unwrap(),
            RelativePath(std::path::PathBuf::from("../../../cde"))
        );
    }
}
