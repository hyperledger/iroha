#![doc = include_str!("lib_docs/overview.md")]
#![deny(missing_docs)]
pub mod attach;
pub mod env;
pub mod file_source;
pub mod read;
pub mod toml;
pub mod util;
use crate::attach::ConfigValueAndOrigin;
pub use iroha_derive::ReadConfig;
use std::{
    fmt::{Debug, Display, Formatter},
    path::{Path, PathBuf},
};
#[doc = include_str!("lib_docs/parameter_id.md")]
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ParameterId {
    segments: Vec<String>,
}
impl Display for ParameterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut print_dot = false;
        for i in &self.segments {
            if print_dot {
                write!(f, ".")?;
            } else {
                print_dot = true;
            }
            write!(f, "{i}")?;
        }
        Ok(())
    }
}
impl Debug for ParameterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ParameterId({self})")
    }
}
impl<P> From<P> for ParameterId
where
    P: IntoIterator,
    <P as IntoIterator>::Item: AsRef<str>,
{
    fn from(value: P) -> Self {
        Self {
            segments: value.into_iter().map(|x| x.as_ref().to_string()).collect(),
        }
    }
}
/// Indicates the origin where a configuration parameter value came from.
#[derive(Debug, Clone)]
pub enum ParameterOrigin {
    /// Value came from a file.
    File {
        /// Parameter identifier.
        id: ParameterId,
        /// Path to the configuration file where it was read.
        path: PathBuf,
    },
    /// Value came from an environment variable.
    Env {
        /// Parameter identifier.
        id: ParameterId,
        /// Name of the environment variable.
        var: String,
    },
    /// It is a default value of a parameter.
    Default {
        /// Parameter identifier.
        id: ParameterId,
    },
    /// Custom origin.
    Custom {
        /// Free-form description of the origin.
        message: String,
    },
}
impl ParameterOrigin {
    /// Construct [`Self::File`]
    pub fn file(id: ParameterId, path: PathBuf) -> Self {
        Self::File { id, path }
    }
    /// Construct [`Self::Env`]
    pub fn env(id: ParameterId, var: String) -> Self {
        Self::Env { var, id }
    }
    /// Construct [`Self::Default`]
    pub fn default(id: ParameterId) -> Self {
        Self::Default { id }
    }
    /// Construct [`Self::Custom`]
    pub fn custom(message: String) -> Self {
        Self::Custom { message }
    }
}
/// A container with information on where the value came from, in terms of [`ParameterOrigin`]
#[derive(Debug, Clone)]
pub struct WithOrigin<T> {
    value: T,
    origin: ParameterOrigin,
}
impl<T> WithOrigin<T> {
    /// Constructor
    pub fn new(value: T, origin: ParameterOrigin) -> Self {
        Self { value, origin }
    }
    /// Construct, using caller's location as the origin.
    ///
    /// Primarily for testing purposes.
    #[track_caller]
    pub fn inline(value: T) -> Self {
        Self::new(
            value,
            ParameterOrigin::custom(format!("inlined at `{}`", std::panic::Location::caller())),
        )
    }
    /// Borrow the value
    pub fn value(&self) -> &T {
        &self.value
    }
    /// Exclusively borrow the value
    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }
    /// Extract the value, dropping the origin.
    ///
    /// Use [`Self::into_tuple`] to extract both the value and the origin.
    pub fn into_value(self) -> T {
        self.value
    }
    /// Extract the value and the origin.
    ///
    /// Use [`Self::into_value`] to extract only the value.
    pub fn into_tuple(self) -> (T, ParameterOrigin) {
        (self.value, self.origin)
    }
    /// Borrow the origin
    pub fn origin(&self) -> &ParameterOrigin {
        &self.origin
    }
    /// Construct [`ConfigValueAndOrigin`] attachment to use with [`error_stack::Report::attach_printable`].
    pub fn into_attachment(self) -> ConfigValueAndOrigin<T> {
        ConfigValueAndOrigin::new(self.value, self.origin)
    }
    /// Convert the value with a function
    pub fn map<F, U>(self, fun: F) -> WithOrigin<U>
    where
        F: FnOnce(T) -> U,
    {
        let Self { value, origin } = self;
        WithOrigin {
            value: fun(value),
            origin,
        }
    }
}
impl<T> norito::json::JsonSerialize for WithOrigin<T>
where
    T: norito::json::JsonSerialize,
{
    fn json_serialize(&self, out: &mut String) {
        self.value.json_serialize(out);
    }
}
impl<T> norito::json::JsonDeserialize for WithOrigin<T>
where
    T: norito::json::JsonDeserialize,
{
    fn json_deserialize(p: &mut norito::json::Parser<'_>) -> Result<Self, norito::json::Error> {
        let value = T::json_deserialize(p)?;
        Ok(WithOrigin::inline(value))
    }
    fn json_from_value(value: &norito::json::Value) -> Result<Self, norito::json::Error> {
        let inner = T::json_from_value(value)?;
        Ok(WithOrigin::inline(inner))
    }
}
impl<T: AsRef<Path>> WithOrigin<T> {
    /// If the origin is [`ParameterOrigin::File`], will resolve the contained path relative to the origin.
    /// Otherwise, will return the value as-is.
    pub fn resolve_relative_path(&self) -> PathBuf {
        match &self.origin {
            ParameterOrigin::File { path, .. } => path
                .parent()
                .expect("if it is a file, it should have a parent path")
                .join(self.value.as_ref()),
            _ => self.value.as_ref().to_path_buf(),
        }
    }
}
