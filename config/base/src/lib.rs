//! Tools to work with file- and environment-based configuration.

#![allow(missing_docs)]

pub mod env;
pub mod reader;
pub mod toml;
pub mod util;

use std::{
    fmt::{Debug, Display, Formatter},
    path::PathBuf,
};

pub use iroha_config_base_derive::ReadConfig;

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct ParameterId {
    segments: Vec<String>,
}

impl Display for ParameterId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut print_dot = false;
        for i in self.segments.iter() {
            if print_dot {
                write!(f, ".")?;
            } else {
                print_dot = true;
            }
            write!(f, "{}", i)?;
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
    File { path: PathBuf, id: ParameterId },
    Env { var: String, id: ParameterId },
    Default { id: ParameterId },
}

impl ParameterOrigin {
    pub fn file(id: ParameterId, path: PathBuf) -> Self {
        Self::File { id, path }
    }

    pub fn env(id: ParameterId, var: String) -> Self {
        Self::Env { id, var }
    }

    pub fn default(id: ParameterId) -> Self {
        Self::Default { id }
    }
}

impl Display for ParameterOrigin {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default { id } => write!(f, "default value for parameter `{}`", id),
            Self::File { path, id } => {
                write!(f, "parameter `{}` from file `{}`", id, path.display())
            }
            Self::Env { var, id } => {
                write!(f, "parameter `{}` from environment variable `{}`", id, var)
            }
        }
    }
}

#[derive(Debug)]
pub struct WithOrigin<T> {
    value: T,
    origin: ParameterOrigin,
}

impl<T> WithOrigin<T> {
    fn new(value: T, origin: ParameterOrigin) -> Self {
        Self { value, origin }
    }

    pub fn into_value(self) -> T {
        self.value
    }

    pub fn into_tuple(self) -> (T, ParameterOrigin) {
        (self.value, self.origin)
    }
}

impl WithOrigin<PathBuf> {
    /// If it is [`Self::File`], will resolve the contained value relative to the origin.
    /// Otherwise, will return the value as-is.
    pub fn resolve_relative_path(&self) -> PathBuf {
        todo!()
    }
}
