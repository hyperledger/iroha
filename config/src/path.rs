//! Module with configuration path related structures.

use std::{borrow::Cow, path::PathBuf};

use InnerPath::*;

/// Extensions which are permissible as input file extensions.
pub const ALLOWED_CONFIG_EXTENSIONS: [&str; 2] = ["json", "json5"];

/// Error type for [`Path`].
#[derive(Debug, Clone, thiserror::Error)]
pub enum ExtensionError {
    /// Provided config file has no extension.
    #[error(
        "Provided config file has no extension, allowed extensions are: {:?}.",
        ALLOWED_CONFIG_EXTENSIONS
    )]
    UserConfigHasNone,

    /// Provided configuration file doesn't have the two allowed extensions: [`ALLOWED_CONFIG_EXTENSIONS`]
    #[error(
        "Provided config file has invalid extension `{0}`, \
        allowed extensions are: {:?}.",
        ALLOWED_CONFIG_EXTENSIONS
    )]
    Invalid(String),

    /// Default configuration file should not have an extension and in this case an extension was provided.
    #[error("Provided by default config file has extension when it should not have one.")]
    DefaultHasSome,
}

/// Result type used in this crate.
pub type Result<T> = core::result::Result<T, ExtensionError>;

/// Inner helper struct.
///
/// With this struct, we force to use [`Path`]'s constructors instead of constructing it directly.
#[derive(Debug, Clone)]
enum InnerPath {
    Default(PathBuf),
    User(PathBuf),
}

/// Wrapper around path to config file (i.e. config.json, genesis.json).
///
/// Provides abstraction above user-provided config and default ones.
#[derive(Debug, Clone)]
pub struct ConfigPath(InnerPath);

impl ConfigPath {
    /// Construct new [`Path`] from the default `path`.
    ///
    /// # Errors
    /// - If `path` contains an extension
    pub fn default(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        if path.extension().is_some() {
            return Err(ExtensionError::DefaultHasSome);
        }

        Ok(Self(Default(path)))
    }

    /// Construct new [`Path`] from user-provided `path`.
    ///
    /// `path` should contain one of the allowed extensions.
    ///
    /// # Errors
    /// - If the file has no extension
    /// - If the file has extensions other than [`ALLOWED_CONFIG_EXTENSIONS`]
    pub fn user_provided(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();

        let extension = path
            .extension()
            .ok_or(Error::UserProvidedConfigFileHasNoExtension)?
            .to_string_lossy();
        if !ALLOWED_CONFIG_EXTENSIONS.contains(&extension.as_ref()) {
            return Err(ExtensionError::Invalid(extension.into_owned()));
        }

        Ok(Self(User(path)))
    }

    /// Try to get first existing path by applying possible extensions if there are any.
    pub fn first_existing_path(&self) -> Option<Cow<PathBuf>> {
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
            User(path) => path.exists(),
        }
    }
}
