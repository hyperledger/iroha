//! Module with configuration path related structures.

use std::{borrow::Cow, path::PathBuf};

use InnerPath::*;

pub const ALLOWED_CONFIG_EXTENSIONS: [&str; 2] = ["json", "json5"];

/// Error type for [`Path`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    #[error(
        "Provided config file has no extension, allowed extensions are: {:?}.",
        ALLOWED_CONFIG_EXTENSIONS
    )]
    UserProvidedConfigFileHasNoExtension,
    #[error(
        "Provided config file has invalid extension `{0}`, \
        allowed extensions are: {:?}.",
        ALLOWED_CONFIG_EXTENSIONS
    )]
    InvalidExtensionError(String),
    #[error("Provided by default config file has extension when it should not have one.")]
    DefaultConfigFileHasExtension,
}

pub type Result<T> = std::result::Result<T, Error>;

/// Inner helper struct.
///
/// This could be [`Path`] itself, but it is not because enum can be constructed directly and
/// we need checked way to construct it with written constructors.
#[derive(Debug, Clone)]
enum InnerPath {
    Default(PathBuf),
    UserProvided(PathBuf),
}

/// Wrapper around path to config file (i.e. config.json, genesis.json).
///
/// Provides abstraction above user-provided config and default ones.
#[derive(Debug, Clone)]
pub struct Path(InnerPath);

impl Path {
    /// Construct new [`Path`] from the default `path`.
    ///
    /// `path` should not contain any extension.
    pub fn default(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        if path.extension().is_some() {
            return Err(Error::DefaultConfigFileHasExtension);
        }

        Ok(Self(Default(path)))
    }

    /// Construct new [`Path`] from user-provided `path`.
    ///
    /// `path` should contain one of the allowed extensions.
    pub fn user_provided(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        let extension = path
            .extension()
            .ok_or_else(|| Error::UserProvidedConfigFileHasNoExtension)?
            .to_string_lossy();
        if !ALLOWED_CONFIG_EXTENSIONS.contains(&extension.as_ref()) {
            return Err(Error::InvalidExtensionError(extension.into_owned()));
        }

        Ok(Self(UserProvided(path)))
    }

    /// Try to get first existing path applying possible extensions if there are some.
    pub fn first_existing_path(&self) -> Option<Cow<PathBuf>> {
        match &self.0 {
            Default(path) => ALLOWED_CONFIG_EXTENSIONS.iter().find_map(|extension| {
                let path_ext = path.with_extension(extension);
                path_ext.exists().then_some(Cow::Owned(path_ext))
            }),
            UserProvided(path) => path.exists().then_some(Cow::Borrowed(&path)),
        }
    }

    /// Check if config path exists applying possible extensions if there are some.
    pub fn exists(&self) -> bool {
        match &self.0 {
            Default(path) => ALLOWED_CONFIG_EXTENSIONS
                .iter()
                .any(|extension| path.with_extension(extension).exists()),
            UserProvided(path) => path.exists(),
        }
    }
}
