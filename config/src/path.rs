//! Module with configuration path related structures.

extern crate alloc;

use alloc::borrow::Cow;
use std::path::PathBuf;

// TODO: replace with `std::fs::absolute` when it's stable.
// use path_absolutize::Absolutize as _;
use InnerPath::*;

/// Allowed configuration file extension that user can provide.
pub const ALLOWED_CONFIG_EXTENSIONS: [&str; 2] = ["json", "json5"];

/// Error type for [`Path`].
#[derive(Debug, Clone, thiserror::Error, displaydoc::Display)]
pub enum ExtensionError {
    /// No valid file extension found. Allowed file extensions are: {ALLOWED_CONFIG_EXTENSIONS:?}
    Missing,
    /// Provided config file has an unsupported file extension `{0}`, allowed extensions are: {ALLOWED_CONFIG_EXTENSIONS:?}.
    Invalid(String),
}

/// Result type for [`Path`] constructors.
pub type Result<T> = std::result::Result<T, ExtensionError>;

/// Inner helper struct.
///
/// With this struct, we force to use [`Path`]'s constructors instead of constructing it directly.
#[derive(Debug, Clone, PartialEq)]
enum InnerPath {
    /// Contains path without an extension, so that it will try to resolve
    /// using [`ALLOWED_CONFIG_EXTENSIONS`]
    TryExtensions(PathBuf),
    /// Contains full path, with extension
    Strict(PathBuf),
}

/// Wrapper around path to config file (e.g. `config.json`).
///
/// Provides abstraction above user-provided config and default ones.
#[derive(Debug, Clone, PartialEq)]
pub struct Path(InnerPath);

impl core::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            TryExtensions(path) => {
                write!(
                    f,
                    "{}.{{{}}}",
                    path.display(),
                    ALLOWED_CONFIG_EXTENSIONS.join(",")
                )
            }
            Strict(path) => write!(f, "{}", path.display()),
        }
    }
}

impl Path {
    /// Construct new [`Path`] which will try to resolve multiple allowed extensions.
    ///
    /// # Errors
    /// If `path` contains extension.
    pub fn try_extensions(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        match path.extension() {
            Some(ext) => Err(ExtensionError::Invalid(ext.to_string_lossy().into_owned())),
            None => Ok(Self(TryExtensions(path))),
        }
    }

    /// Construct new [`Path`] from user-provided `path`.
    ///
    /// # Errors
    /// If `path`'s extension is absent or unsupported.
    pub fn strict(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        let extension = path
            .extension()
            .ok_or(ExtensionError::Missing)?
            .to_string_lossy();
        if !ALLOWED_CONFIG_EXTENSIONS.contains(&extension.as_ref()) {
            return Err(ExtensionError::Invalid(extension.into_owned()));
        }

        Ok(Self(Strict(path)))
    }

    /// Try to get first existing path by applying possible extensions if there are any.
    pub fn try_resolve(&self) -> Option<Cow<PathBuf>> {
        match &self.0 {
            TryExtensions(path) => ALLOWED_CONFIG_EXTENSIONS.iter().find_map(|extension| {
                let path_ext = path.with_extension(extension);
                path_ext.exists().then_some(Cow::Owned(path_ext))
            }),
            Strict(path) => path.exists().then_some(Cow::Borrowed(path)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_multi_extensions() {
        let path =
            Path::try_extensions("config").expect("Should be valid since doesn't have extension");

        let display = format!("{path}");

        assert_eq!(display, "config.{json,json5}")
    }

    #[test]
    fn display_strict_extension() {
        let path = Path::strict("config.json").expect("Should be valid since extension is valid");

        let display = format!("{path}");

        assert_eq!(display, "config.json")
    }
}
