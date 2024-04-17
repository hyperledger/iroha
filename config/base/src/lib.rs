//! Tools to work with file- and environment-based configuration.

#![allow(missing_docs)]

pub mod attach;
pub mod env;
pub mod read;
pub mod toml;
pub mod util;

use std::{
    fmt::{Debug, Display, Formatter},
    path::PathBuf,
};

pub use iroha_config_base_derive::ReadConfig;

use crate::attach::ConfigValueAndOrigin;

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

#[derive(Debug, Clone)]
pub enum ParameterOrigin {
    File { id: ParameterId, path: PathBuf },
    Env { id: ParameterId, var: String },
    EnvUnknown { id: ParameterId },
    Default { id: ParameterId },
    Custom { message: String },
}

impl ParameterOrigin {
    pub fn file(id: ParameterId, path: PathBuf) -> Self {
        Self::File { id, path }
    }

    pub fn env(id: ParameterId, var: String) -> Self {
        Self::Env { var, id }
    }

    pub fn env_unknown(id: ParameterId) -> Self {
        Self::EnvUnknown { id }
    }

    pub fn default(id: ParameterId) -> Self {
        Self::Default { id }
    }

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
    pub fn new(value: T, origin: ParameterOrigin) -> Self {
        Self { value, origin }
    }

    #[track_caller]
    pub fn inline(value: T) -> Self {
        Self::new(
            value,
            ParameterOrigin::custom(format!("inlined at `{}`", std::panic::Location::caller())),
        )
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    pub fn into_value(self) -> T {
        self.value
    }

    pub fn into_tuple(self) -> (T, ParameterOrigin) {
        (self.value, self.origin)
    }

    pub fn origin(&self) -> &ParameterOrigin {
        &self.origin
    }

    pub fn into_attachment(self) -> ConfigValueAndOrigin<T> {
        ConfigValueAndOrigin::new(self.value, self.origin)
    }

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

impl WithOrigin<PathBuf> {
    /// If it is [`Self::File`], will resolve the contained value relative to the origin.
    /// Otherwise, will return the value as-is.
    pub fn resolve_relative_path(&self) -> PathBuf {
        match &self.origin {
            ParameterOrigin::File { path, .. } => path
                .parent()
                .expect("if it is a file, it should have a parent path")
                .join(&self.value),
            _ => self.value.clone(),
        }
    }
}
