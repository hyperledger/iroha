use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, HashSet},
    ops::Sub,
    str::FromStr,
};

use error_stack::Context;

pub trait FromEnvStr {
    type Error: Context;

    fn from_env_str(value: Cow<'_, str>) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl<T> FromEnvStr for T
where
    T: FromStr,
    <T as FromStr>::Err: Context,
{
    type Error = <T as FromStr>::Err;

    fn from_env_str(value: Cow<'_, str>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Self::from_str(&value)
    }
}

pub trait ReadEnv {
    fn read_env(&self, key: &str) -> Option<Cow<'_, str>>;
}

impl<F> ReadEnv for F
where
    F: Fn(&str) -> Option<Cow<'static, str>>,
{
    fn read_env(&self, key: &str) -> Option<Cow<'static, str>> {
        self(key)
    }
}

pub fn std_env(key: &str) -> Option<Cow<'static, str>> {
    match std::env::var(key) {
        Ok(value) => Some(Cow::from(value)),
        Err(std::env::VarError::NotPresent) => None,
        Err(_) => {
            log::error!(
                "Found non-unicode characters in env var `{}`, ignoring",
                key
            );
            None
        }
    }
}

/// An implementation of [`ReadEnv`] for testing convenience.
#[derive(Default)]
pub struct TestEnv {
    map: HashMap<String, String>,
    visited: RefCell<HashSet<String>>,
}

impl TestEnv {
    /// Create new empty environment
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an environment with a given map
    pub fn with_map(map: HashMap<String, String>) -> Self {
        Self { map, ..Self::new() }
    }

    /// Set a key-value pair
    #[must_use]
    pub fn set(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        self.map
            .insert(key.as_ref().to_string(), value.as_ref().to_string());
        self
    }

    /// Get a set of keys not visited yet by [`ReadEnv::read_env`]
    pub fn unvisited(&self) -> HashSet<String> {
        let all_keys: HashSet<_> = self.map.keys().map(ToOwned::to_owned).collect();
        let visited: HashSet<_> = self.visited.borrow().clone();
        all_keys.sub(&visited)
    }
}

impl ReadEnv for TestEnv {
    fn read_env(&self, key: &str) -> Option<Cow<'_, str>> {
        self.visited.borrow_mut().insert(key.to_string());
        self.map.get(key).map(Cow::from)
    }
}
