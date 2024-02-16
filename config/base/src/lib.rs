//! Utilities behind Iroha configurations

use std::{
    borrow::Cow,
    cell::RefCell,
    collections::{HashMap, HashSet},
    convert::Infallible,
    env::VarError,
    error::Error,
    ffi::OsString,
    fmt::{Debug, Display, Formatter},
    ops::Sub,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use eyre::{eyre, Report, WrapErr};
pub use merge::Merge;
pub use serde;
use serde::{Deserialize, Serialize};

/// [`Duration`], but can parse a human-readable string.
/// TODO: currently deserializes just as [`Duration`]
#[serde_with::serde_as]
#[derive(Debug, Copy, Clone, Deserialize, Serialize, Ord, PartialOrd, Eq, PartialEq)]
pub struct HumanDuration(#[serde_as(as = "serde_with::DurationMilliSeconds")] pub Duration);

impl HumanDuration {
    /// Get the [`Duration`]
    pub fn get(self) -> Duration {
        self.0
    }
}

/// Representation of amount of bytes, parseable from a human-readable string.
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct HumanBytes<T: num_traits::int::PrimInt>(pub T);

impl<T: num_traits::int::PrimInt> HumanBytes<T> {
    /// Get the number of bytes
    pub fn get(self) -> T {
        self.0
    }
}

/// Error representing a missing field in the configuration
#[derive(thiserror::Error, Debug)]
#[error("missing field: `{path}`")]
pub struct MissingFieldError {
    path: String,
}

impl MissingFieldError {
    /// Create an instance
    pub fn new(s: &str) -> Self {
        Self { path: s.to_owned() }
    }
}

/// Provides environment variables
pub trait ReadEnv<E> {
    /// Read a value of an environment variable.
    ///
    /// This is a fallible operation, which might return an empty value if the given key is not
    /// present.
    ///
    /// [`Cow`] is used for flexibility. The read value might be given both as an owned and as a
    /// borrowed string depending on the structure that implements [`ReadEnv`]. On the receiving
    /// part, it might be convenient to parse the string while just borrowing it
    /// (e.g. with [`FromStr`]), but might be also convenient to own the value. [`Cow`] covers all
    /// of this.
    ///
    /// # Errors
    /// For any reason an implementor might have.
    fn read_env(&self, key: impl AsRef<str>) -> Result<Option<Cow<'_, str>>, E>;
}

/// Constructs from environment variables
pub trait FromEnv {
    /// Constructs from environment variables using [`ReadEnv`]
    ///
    /// # Errors
    /// For any reason an implementor might have.
    // `E: Error` so that it could be wrapped into a Report
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
    where
        Self: Sized;
}

/// Result of [`FromEnv::from_env`]. Intended to contain multiple possible errors at once.
pub type FromEnvResult<T> = eyre::Result<T, ErrorsCollection<Report>>;

/// Marker trait to implement [`FromEnv`] if a type implements [`Default`]
pub trait FromEnvDefaultFallback {}

impl<T> FromEnv for T
where
    T: FromEnvDefaultFallback + Default,
{
    fn from_env<E: Error, R: ReadEnv<E>>(_env: &R) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        Ok(Self::default())
    }
}

/// Simple collector of errors.
///
/// Will panic on [`Drop`] if contains errors that are not handled with [`Emitter::finish`].
pub struct Emitter<T: Debug> {
    errors: Vec<T>,
    bomb: drop_bomb::DropBomb,
}

impl<T: Debug> Emitter<T> {
    /// Create a new empty emitter
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            bomb: drop_bomb::DropBomb::new(
                "Errors emitter is dropped without consuming collected errors",
            ),
        }
    }

    /// Emit a single error
    pub fn emit(&mut self, error: T) {
        self.errors.push(error);
    }

    /// Emit a collection of errors
    pub fn emit_collection(&mut self, mut errors: ErrorsCollection<T>) {
        self.errors.append(&mut errors.0);
    }

    /// Transform the emitter into a [`Result`], containing an [`ErrorCollection`] if
    /// any errors were emitted.
    ///
    /// # Errors
    /// If any errors were emitted.
    pub fn finish(mut self) -> Result<(), ErrorsCollection<T>> {
        self.bomb.defuse();

        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(ErrorsCollection(self.errors))
        }
    }
}

impl<T: Debug> Default for Emitter<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl Emitter<MissingFieldError> {
    /// Shorthand to emit a [`MissingFieldError`].
    pub fn emit_missing_field(&mut self, field_name: impl AsRef<str>) {
        self.emit(MissingFieldError::new(field_name.as_ref()))
    }

    /// Tries to [`UnwrapPartial`], collecting errors on failure.
    ///
    /// This method is relevant for [`Emitter<MissingFieldError>`], because [`UnwrapPartial`]
    /// returns a collection of [`MissingFieldError`]s.
    pub fn try_unwrap_partial<P: UnwrapPartial>(&mut self, partial: P) -> Option<P::Output> {
        partial.unwrap_partial().map_or_else(
            |err| {
                self.emit_collection(err);
                None
            },
            Some,
        )
    }
}

/// An [`Error`] containing multiple errors inside
pub struct ErrorsCollection<T>(Vec<T>);

impl<T: Display + Debug> Error for ErrorsCollection<T> {}

/// Displays each error on a new line
impl<T> Display for ErrorsCollection<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{item}")?;
        }
        Ok(())
    }
}

impl<T> Debug for ErrorsCollection<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        for (i, item) in self.0.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(f, "{item:?}")?;
        }
        Ok(())
    }
}

impl<T> From<T> for ErrorsCollection<T> {
    fn from(value: T) -> Self {
        Self(vec![value])
    }
}

impl<T> IntoIterator for ErrorsCollection<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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

impl ReadEnv<Infallible> for TestEnv {
    fn read_env(&self, key: impl AsRef<str>) -> Result<Option<Cow<'_, str>>, Infallible> {
        self.visited.borrow_mut().insert(key.as_ref().to_string());
        Ok(self
            .map
            .get(key.as_ref())
            .map(String::as_str)
            .map(Cow::from))
    }
}

/// Implemented of [`ReadEnv`] on top of [`std::env::var`].
#[derive(Debug, Copy, Clone)]
pub struct StdEnv;

impl ReadEnv<StdEnvError> for StdEnv {
    fn read_env(&self, key: impl AsRef<str>) -> Result<Option<Cow<'_, str>>, StdEnvError> {
        match std::env::var(key.as_ref()) {
            Ok(value) => Ok(Some(value.into())),
            Err(VarError::NotPresent) => Ok(None),
            Err(VarError::NotUnicode(input)) => Err(StdEnvError::NotUnicode(input)),
        }
    }
}

/// An error that might occur while reading from std env.
///
/// - **Q: Why just [`VarError`] is not used?**
/// - A: Because [`VarError::NotPresent`] is `Ok(None)` in terms of [`ReadEnv`]
#[derive(Debug, thiserror::Error)]
pub enum StdEnvError {
    /// Reflects [`VarError::NotUnicode`]
    #[error("the specified environment variable was found, but it did not contain valid unicode data: {0:?}")]
    NotUnicode(OsString),
}

/// A tool that simplifies work with graceful parsing of multiple values in combination
/// with [`Emitter`]
pub enum ParseEnvResult<T> {
    /// Value was found and parsed
    Value(T),
    /// An error occurred while reading or parsing the environment
    Error,
    /// Value was not found, no error occurred
    None,
}

impl<T> ParseEnvResult<T>
where
    T: FromStr,
    <T as FromStr>::Err: Error + Send + Sync + 'static,
{
    /// _Simple_ parsing using [`FromStr`]
    pub fn parse_simple<E: Error>(
        emitter: &mut Emitter<Report>,
        env: &impl ReadEnv<E>,
        env_key: impl AsRef<str>,
        field_name: impl AsRef<str>,
    ) -> Self {
        // FIXME: errors handling is such a mess now
        let read = match env
            .read_env(env_key.as_ref())
            .map_err(|err| eyre!("{err}"))
            .wrap_err_with(|| eyre!("ooops"))
        {
            Ok(Some(value)) => value,
            Ok(None) => return Self::None,
            Err(report) => {
                emitter.emit(report);
                return Self::Error;
            }
        };

        match FromStr::from_str(read.as_ref()).wrap_err_with(|| {
            eyre!(
                "failed to parse `{}` field from `{}` env variable",
                field_name.as_ref(),
                env_key.as_ref()
            )
        }) {
            Ok(value) => Self::Value(value),
            Err(report) => {
                emitter.emit(report);
                Self::Error
            }
        }
    }
}

/// During this conversion, [`ParseEnvResult::Error`] is interpreted as [`None`].
impl<T> From<ParseEnvResult<T>> for Option<T> {
    fn from(value: ParseEnvResult<T>) -> Self {
        match value {
            ParseEnvResult::None | ParseEnvResult::Error => None,
            ParseEnvResult::Value(x) => Some(x),
        }
    }
}

/// Value container to be used in the partial layers.
///
/// In partial layers, values might be present or not.
/// Partial layers consisting from [`UserField`] might be _incomplete_,
/// merged into each other (with [`merge::Merge`]),
/// and finally unwrapped (with [`UnwrapPartial`]) into a _complete_ layer of data.
///
/// Partial layers might consist of fields other than [`UserField`], but their types should follow
/// the same conventions. This might be used e.g. to implement custom merge strategy.
#[derive(
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    derive_more::From,
    Clone,
    derive_more::Deref,
    derive_more::DerefMut,
)]
pub struct UserField<T>(Option<T>);

/// Delegating debug repr to [`Option`]
impl<T: Debug> Debug for UserField<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Empty user field
impl<T> Default for UserField<T> {
    fn default() -> Self {
        Self(None)
    }
}

/// The other's value takes precedence over the self's
impl<T> Merge for UserField<T> {
    fn merge(&mut self, other: Self) {
        if let Some(value) = other.0 {
            self.0 = Some(value)
        }
    }
}

impl<T> UserField<T> {
    /// Get the field value
    pub fn get(self) -> Option<T> {
        self.0
    }

    /// Set the field value
    pub fn set(&mut self, value: T) {
        self.0 = Some(value);
    }
}

impl<T> From<ParseEnvResult<T>> for UserField<T> {
    fn from(value: ParseEnvResult<T>) -> Self {
        let option: Option<T> = value.into();
        option.into()
    }
}

/// Conversion from a layer's partial state into its full state, with all required
/// fields presented.
pub trait UnwrapPartial {
    /// The output of unwrapping, i.e. the full layer
    type Output;

    /// Unwraps the partial into a structure with all required fields present.
    ///
    /// # Errors
    /// If there are absent fields, returns a bulk of [`MissingFieldError`]s.
    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output>;
}

/// Used for [`UnwrapPartial::unwrap_partial`]
pub type UnwrapPartialResult<T> = Result<T, ErrorsCollection<MissingFieldError>>;

/// A tool to implement "extends" mechanism, i.e. mixins.
///
/// It allows users to provide a path of other files that should be used as
/// a _base_ layer.
///
/// ```toml
/// # contents of this file will be merged into the contents of `base.toml`
/// extends = "./base.toml"
/// ```
///
/// It is possible to specify multiple extensions at once:
///
/// ```toml
/// # read `foo`, then merge `bar`, then merge `baz`, then merge this file's contents
/// extends = ["foo", "bar", "baz"]
/// ```
///
/// From the developer side, it should be used as a field on a partial layer:
///
/// ```
/// use iroha_config_base::ExtendsPaths;
///
/// struct SomePartial {
///     extends: Option<ExtendsPaths>,
///     // ..other fields
/// }
/// ```
///
/// When this layer is constructed from a file, `ExtendsPaths` should be handled e.g.
/// with [`ExtendsPaths::iter`].
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum ExtendsPaths {
    /// A single path to extend from
    Single(PathBuf),
    /// A chain of paths to extend from
    Chain(Vec<PathBuf>),
}

/// Iterator over [`ExtendsPaths`] for convenience
pub enum ExtendsPathsIter<'a> {
    #[allow(missing_docs)]
    Single(Option<&'a PathBuf>),
    #[allow(missing_docs)]
    Multiple(std::slice::Iter<'a, PathBuf>),
}

impl ExtendsPaths {
    /// Normalise into an iterator over chain of paths to extend from
    #[allow(clippy::iter_without_into_iter)] // extra for this case
    pub fn iter(&self) -> ExtendsPathsIter<'_> {
        match &self {
            Self::Single(x) => ExtendsPathsIter::Single(Some(x)),
            Self::Chain(vec) => ExtendsPathsIter::Multiple(vec.iter()),
        }
    }
}

impl<'a> Iterator for ExtendsPathsIter<'a> {
    type Item = &'a PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Single(x) => x.take(),
            Self::Multiple(iter) => iter.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_missing_field() {
        let mut emitter: Emitter<MissingFieldError> = Emitter::new();

        emitter.emit_missing_field("foo");

        let err = emitter.finish().unwrap_err();

        assert_eq!(format!("{err}"), "missing field: `foo`")
    }

    #[test]
    fn multiple_missing_fields() {
        let mut emitter: Emitter<MissingFieldError> = Emitter::new();

        emitter.emit_missing_field("foo");
        emitter.emit_missing_field("bar");

        let err = emitter.finish().unwrap_err();

        assert_eq!(
            format!("{err}"),
            "missing field: `foo`\nmissing field: `bar`"
        )
    }

    #[test]
    fn merging_user_fields_overrides_old_value() {
        let mut field = UserField(None);
        field.merge(UserField(Some(4)));
        assert_eq!(field, UserField(Some(4)));

        let mut field = UserField(Some(4));
        field.merge(UserField(Some(5)));
        assert_eq!(field, UserField(Some(5)));

        let mut field = UserField(Some(4));
        field.merge(UserField(None));
        assert_eq!(field, UserField(Some(4)));
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct TestExtends {
        extends: Option<ExtendsPaths>,
    }

    #[test]
    fn parse_empty_extends() {
        let value: TestExtends = toml::from_str("").expect("should be fine with empty input");

        assert_eq!(value.extends, None);
    }

    #[test]
    fn parse_single_extends_path() {
        let value: TestExtends = toml::toml! {
            extends = "./path"
        }
        .try_into()
        .unwrap();

        assert_eq!(value.extends, Some(ExtendsPaths::Single("./path".into())));
    }

    #[test]
    fn parse_multiple_extends_paths() {
        let value: TestExtends = toml::toml! {
            extends = ["foo", "bar", "baz"]
        }
        .try_into()
        .unwrap();

        assert_eq!(
            value.extends,
            Some(ExtendsPaths::Chain(vec![
                "foo".into(),
                "bar".into(),
                "baz".into()
            ]))
        );
    }

    #[test]
    fn iterating_over_extends() {
        impl ExtendsPaths {
            fn as_str_vec(&self) -> Vec<&str> {
                self.iter().map(|p| p.to_str().unwrap()).collect()
            }
        }

        let single = ExtendsPaths::Single("single".into());
        assert_eq!(single.as_str_vec(), vec!["single"]);

        let multi = ExtendsPaths::Chain(vec!["foo".into(), "bar".into(), "baz".into()]);
        assert_eq!(multi.as_str_vec(), vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn deserialize_human_duration() {
        #[derive(Deserialize)]
        struct Test {
            value: HumanDuration,
        }

        let Test { value } = toml::toml! {
            value = 10_500
        }
        .try_into()
        .expect("input is fine, should parse");

        assert_eq!(value.get(), Duration::from_millis(10_500));
    }
}
