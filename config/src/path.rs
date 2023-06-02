//! Module with configuration path related structures.

extern crate alloc;

use alloc::borrow::Cow;
use std::path::PathBuf;

// TODO: replace with `std::fs::absolute` when it's stable.
use path_absolutize::Absolutize as _;
use InnerPath::*;

/// Allowed configuration file extension that user can provide.
pub const ALLOWED_CONFIG_EXTENSIONS: [&str; 2] = ["json", "json5"];

/// Error type for [`Path`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtensionError {
    /// User provided config file without extension.
    #[error(
        "No valid file extension found. Allowed file extensions are: {:?}.",
        ALLOWED_CONFIG_EXTENSIONS
    )]
    Missing,
    /// User provided config file with unsupported extension.
    #[error(
        "Provided config file has an unsupported file extension `{0}`, \
        allowed extensions are: {:?}.",
        ALLOWED_CONFIG_EXTENSIONS
    )]
    Invalid(String),
}

/// Result type for [`Path`] constructors.
pub type Result<T> = std::result::Result<T, ExtensionError>;

/// Inner helper struct.
///
/// With this struct, we force to use [`Path`]'s constructors instead of constructing it directly.
#[derive(Debug, Clone)]
enum InnerPath {
    Default(PathBuf),
    UserProvided(PathBuf),
}

/// Wrapper around path to config file (e.g. `config.json`).
///
/// Provides abstraction above user-provided config and default ones.
#[derive(Debug, Clone)]
pub struct Path(InnerPath);

impl core::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Default(pth) => write!(
                f,
                "{:?} (default)",
                pth.with_extension("json")
                    .absolutize()
                    .expect("Malformed default path")
            ),
            UserProvided(pth) => write!(
                f,
                "{:?} (user-provided)",
                pth.with_extension("json")
                    .absolutize()
                    .expect("Malformed user-provided path")
            ),
        }
    }
}

impl Path {
    /// Construct new [`Path`] from the default `path`.
    ///
    /// # Panics
    ///
    /// Panics if `path` contains an extension.
    #[allow(clippy::panic)]
    pub fn default(path: &'static std::path::Path) -> Self {
        assert!(
            path.extension().is_none(),
            "Default configuration path should have no extension"
        );

        Self(Default(path.to_owned()))
    }

    /// Construct new [`Path`] from user-provided `path`.
    ///
    /// # Errors
    ///
    /// An error will be returned if `path` contains no file extension
    /// or contains unsupported one.
    pub fn user_provided(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        let extension = path
            .extension()
            .ok_or(ExtensionError::Missing)?
            .to_string_lossy();
        if !ALLOWED_CONFIG_EXTENSIONS.contains(&extension.as_ref()) {
            return Err(ExtensionError::Invalid(extension.into_owned()));
        }

        Ok(Self(UserProvided(path)))
    }

    /// Try to get first existing path by applying possible extensions if there are any.
    pub fn first_existing(&self) -> Option<Cow<PathBuf>> {
        match &self.0 {
            Default(path) => ALLOWED_CONFIG_EXTENSIONS.iter().find_map(|extension| {
                let path_ext = path.with_extension(extension);
                path_ext.exists().then_some(Cow::Owned(path_ext))
            }),
            UserProvided(path) => path.exists().then_some(Cow::Borrowed(path)),
        }
    }

    /// Check if config path exists by applying allowed extensions if there are any.
    pub fn exists(&self) -> bool {
        match &self.0 {
            Default(path) => ALLOWED_CONFIG_EXTENSIONS
                .iter()
                .any(|extension| path.with_extension(extension).exists()),
            UserProvided(path) => path.exists(),
        }
    }
}
