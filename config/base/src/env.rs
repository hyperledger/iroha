//! Environment variables

use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, HashSet},
    ops::Sub,
    rc::Rc,
    str::FromStr,
};

use error_stack::Context;

/// Convertation from a string read from an environment variable to a specific value.
///
/// Has an implementation for any type that implements [`FromStr`] (with an error that is [Context]).
pub trait FromEnvStr {
    /// Error that might occur during conversion
    type Error: Context;

    /// The conversion itself.
    ///
    /// # Errors
    /// Up to an implementor.
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
        value.parse()
    }
}

/// Enables polymorphism for environment readers.
/// Has default implementations for plain functions,
/// thus it should work for closures as well.
pub trait ReadEnv {
    /// Read a value from an environment variable.
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

/// An adapter of [`std::env::var`] for [`ReadEnv`] trait.
/// Does not fail in case of [`std::env::VarError::NotUnicode`], but prints it as an error via
/// [log].
///
/// [`crate::read::ConfigReader`] uses it by default.
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
#[derive(Default, Clone)]
pub struct MockEnv {
    map: HashMap<String, String>,
    visited: Rc<RefCell<HashSet<String>>>,
}

impl MockEnv {
    /// Create new empty environment
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an environment with a given map
    pub fn with_map(map: HashMap<String, String>) -> Self {
        Self { map, ..Self::new() }
    }

    /// Get a set of keys not visited yet by [`ReadEnv::read_env`]
    ///
    /// Since [`Rc`] is used under the hood, should work on clones as well.
    pub fn unvisited(&self) -> HashSet<String> {
        self.known_keys().sub(&*self.visited.borrow())
    }

    /// Similar to [`Self::unvisited`], but gives requested entries
    /// that don't exist within the set of variables
    pub fn unknown(&self) -> HashSet<String> {
        self.visited.borrow().sub(&self.known_keys())
    }

    fn known_keys(&self) -> HashSet<String> {
        self.map.keys().map(ToOwned::to_owned).collect()
    }
}

impl<T, K, V> From<T> for MockEnv
where
    T: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    fn from(value: T) -> Self {
        Self::with_map(
            value
                .into_iter()
                .map(|(k, v)| (k.as_ref().to_string(), v.as_ref().to_string()))
                .collect(),
        )
    }
}

impl ReadEnv for MockEnv {
    fn read_env(&self, key: &str) -> Option<Cow<'_, str>> {
        self.visited.borrow_mut().insert(key.to_string());
        self.map.get(key).map(Cow::from)
    }
}
