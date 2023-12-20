//! Module with configuration path related structures.

extern crate alloc;

use alloc::borrow::Cow;
use std::path::PathBuf;

use InnerPath::*;

/// Allowed configuration file extension that user can provide.
pub const ALLOWED_CONFIG_EXTENSIONS: [&str; 2] = ["json", "json5"];

/// Error type for [`Path`].
#[derive(Debug, Clone, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// File doesn't have an extension. Allowed file extensions are: {ALLOWED_CONFIG_EXTENSIONS:?}
    MissingExtension,
    /// Provided config file has an unsupported file extension `{0}`. Allowed extensions are: {ALLOWED_CONFIG_EXTENSIONS:?}.
    InvalidExtension(String),
    /// User-provided file `{0}` is not found.
    FileNotFound(String),
}

/// Result type for [`Path`] constructors.
pub type Result<T> = std::result::Result<T, Error>;

/// Inner helper struct.
///
/// With this struct, we force to use [`Path`]'s constructors instead of constructing it directly.
#[derive(Debug, Clone, PartialEq)]
enum InnerPath {
    /// Contains path without an extension, so that it will try to resolve
    /// using [`ALLOWED_CONFIG_EXTENSIONS`]. [`Path::try_resolve()`] will not fail if file isn't
    /// found.
    Default(PathBuf),
    /// Contains full path, with extension. [`Path::try_resolve()`] will fail if not found.
    UserProvided(PathBuf),
}

/// Wrapper around path to config file (e.g. `config.json`).
///
/// Provides abstraction above user-provided config and default ones.
#[derive(Debug, Clone, PartialEq)]
pub struct Path(InnerPath);

impl core::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Default(path) => {
                write!(
                    f,
                    "{}.{{{}}}",
                    path.display(),
                    ALLOWED_CONFIG_EXTENSIONS.join(",")
                )
            }
            UserProvided(path) => write!(f, "{}", path.display()),
        }
    }
}

impl Path {
    /// Construct new [`Path`] which will try to resolve multiple allowed extensions and will not
    /// fail resolution ([`Self::try_resolve()`]) if file is not found.
    ///
    /// **Note:** make sure to provide `path` without an extension:
    ///
    /// ```
    /// use iroha_config::path::Path;
    ///
    /// // Will look for `config.<allowed extensions>`
    /// let _ = Path::default("config");
    ///
    /// // Will look for `config.json.<allowed extensions>`
    /// let _ = Path::default("config.json");
    /// ```
    pub fn default(path: impl AsRef<std::path::Path>) -> Self {
        Self(Default(path.as_ref().to_path_buf()))
    }

    /// Construct new [`Path`] from user-provided `path` which will fail to [`Self::try_resolve()`]
    /// if file is not found.
    ///
    /// # Errors
    /// If `path`'s extension is absent or unsupported.
    pub fn user_provided(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let path = path.as_ref();

        let extension = path
            .extension()
            .ok_or(Error::MissingExtension)?
            .to_string_lossy();
        if !ALLOWED_CONFIG_EXTENSIONS.contains(&extension.as_ref()) {
            return Err(Error::InvalidExtension(extension.into_owned()));
        }

        Ok(Self(UserProvided(path.to_path_buf())))
    }

    /// Same as [`Self::user_provided()`], but accepts `&str` (useful for clap)
    ///
    /// # Errors
    /// See [`Self::user_provided()`]
    pub fn user_provided_str(raw: &str) -> Result<Self> {
        Self::user_provided(raw)
    }

    /// Try to get first existing path by applying possible extensions if there are any.
    ///
    /// # Errors
    /// If user-provided path is not found
    pub fn try_resolve(&self) -> Result<Option<Cow<PathBuf>>> {
        match &self.0 {
            Default(path) => {
                let maybe = ALLOWED_CONFIG_EXTENSIONS.iter().find_map(|extension| {
                    let path_ext = path.with_extension(extension);
                    path_ext.exists().then_some(Cow::Owned(path_ext))
                });
                Ok(maybe)
            }
            UserProvided(path) => {
                if path.exists() {
                    Ok(Some(Cow::Borrowed(path)))
                } else {
                    Err(Error::FileNotFound(path.to_string_lossy().into_owned()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_multi_extensions() {
        let path = Path::default("config");

        let display = format!("{path}");

        assert_eq!(display, "config.{json,json5}")
    }

    #[test]
    fn display_strict_extension() {
        let path =
            Path::user_provided("config.json").expect("Should be valid since extension is valid");

        let display = format!("{path}");

        assert_eq!(display, "config.json")
    }
}
