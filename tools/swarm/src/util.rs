use std::{
    ffi::OsStr,
    ops::Deref,
    path::{Path, PathBuf},
};

use color_eyre::{eyre::eyre, Report};
use path_absolutize::Absolutize;

#[derive(Clone, Debug)]
pub struct AbsolutePath {
    pub path: PathBuf,
}

impl Deref for AbsolutePath {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<Path> for AbsolutePath {
    fn as_ref(&self) -> &Path {
        self.path.as_path()
    }
}

impl AsRef<OsStr> for AbsolutePath {
    fn as_ref(&self) -> &OsStr {
        self.path.as_ref()
    }
}

impl TryFrom<PathBuf> for AbsolutePath {
    type Error = Report;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        Self::absolutize(&value)
    }
}

impl AbsolutePath {
    pub fn absolutize(path: &PathBuf) -> color_eyre::Result<Self> {
        Ok(Self {
            path: if path.is_absolute() {
                path.clone()
            } else {
                path.absolutize()?.to_path_buf()
            },
        })
    }

    /// Relative path from self to other.
    pub fn relative_to(&self, other: &(impl AsRef<Path> + ?Sized)) -> color_eyre::Result<PathBuf> {
        pathdiff::diff_paths(self, other)
                .ok_or_else(|| {
                    eyre!(
                        "failed to build relative path from {} to {}",
                        other.as_ref().display(),
                        self.display(),
                    )
                })
                // docker-compose might not like "test" path, but "./test" instead 
                .map(|rel| {
                    if rel.starts_with("..") {
                        rel
                    } else {
                        Path::new("./").join(rel)

                    }
                })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_inner_path_starts_with_dot() {
        let root = PathBuf::from("/");
        let a = AbsolutePath::from_virtual(&PathBuf::from("./a/b/c"), &root);
        let b = AbsolutePath::from_virtual(&PathBuf::from("./"), &root);

        assert_eq!(a.relative_to(&b).unwrap(), PathBuf::from("./a/b/c"));
    }

    #[test]
    fn relative_outer_path_starts_with_dots() {
        let root = Path::new("/");
        let a = AbsolutePath::from_virtual(&PathBuf::from("./a/b/c"), root);
        let b = AbsolutePath::from_virtual(&PathBuf::from("./cde"), root);

        assert_eq!(b.relative_to(&a).unwrap(), PathBuf::from("../../../cde"));
    }
}
