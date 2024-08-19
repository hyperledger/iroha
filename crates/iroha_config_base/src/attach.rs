//! Various attachments for [`error_stack::Report::attach`] API.
// TODO: use `error_stack` hooks to enhance attachments with colors
// TODO: standardize more attachments used in `read.rs`

use std::{
    fmt::{Debug, Display, Formatter},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use derive_more::{Constructor, Display};

use crate::ParameterOrigin;

/// Attach a file path
#[derive(Constructor, Display, Debug)]
#[display(fmt = "file path: {}", "path.display()")]
pub struct FilePath {
    path: PathBuf,
}

/// Attach an actual value
#[derive(Constructor, Display, Debug)]
#[display(fmt = "actual value: {value}")]
pub struct ActualValue<T>
where
    T: Display + Debug,
{
    value: T,
}

/// Attach an expectation
#[derive(Constructor, Display, Debug)]
#[display(fmt = "expected: {message}")]
pub struct Expected<T>
where
    T: Display + Debug,
{
    message: T,
}

/// Attach a chain of extensions (see [`crate::util::ExtendsPaths`])
#[derive(Constructor, Display, Debug)]
#[display(
    fmt = "extending ({depth}): `{}` -> `{}`",
    "from.display()",
    "to.display()"
)]
pub struct ExtendsChain {
    from: PathBuf,
    to: PathBuf,
    depth: u8,
}

/// Attach an environment key-value entry
#[derive(Constructor, Display, Debug)]
#[display(fmt = "value: {var}={value}")]
pub struct EnvValue {
    var: String,
    value: String,
}

/// Attach config value and its origin.
///
/// Usually constructed via [`crate::WithOrigin::into_attachment`].
///
/// To support displaying values which don't implement [Display], it uses formats mechanism.
/// For example:
///
/// - For [Path], use [`ConfigValueAndOrigin::display_path`]
/// - For [Debug], use [`ConfigValueAndOrigin::display_as_debug`]
///
/// Example usage with a path:
///
/// ```
/// use std::path::PathBuf;
/// use error_stack::Report;
/// use iroha_config_base::{ParameterOrigin, WithOrigin};
///
/// let value = PathBuf::from("/path/to/somewhere");
/// let attachment = WithOrigin::new(
///     value,
///     ParameterOrigin::file(
///         ["a", "b"].into(),
///         PathBuf::from("/root/iroha/config.toml")
///     )
/// )
/// .into_attachment()
/// .display_path();
///
/// assert_eq!(
///     format!("{attachment}"),
///     "config origin: parameter `a.b` with value `/path/to/somewhere` in file `/root/iroha/config.toml`"
/// );
///
/// let _report = Report::new(std::io::Error::other("test")).attach(attachment);
/// ```
pub struct ConfigValueAndOrigin<T, Format = FormatDisplay<T>> {
    value: T,
    origin: ParameterOrigin,
    _f: PhantomData<Format>,
}

impl<T, F> Debug for ConfigValueAndOrigin<T, F>
where
    T: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigValueAndOrigin")
            .field("value", &self.value)
            .field("origin", &self.origin)
            .finish()
    }
}

impl<T, F> ConfigValueAndOrigin<T, F> {
    fn new_internal(value: T, origin: ParameterOrigin) -> Self {
        Self {
            value,
            origin,
            _f: PhantomData,
        }
    }
}

impl<T> ConfigValueAndOrigin<T> {
    /// Constructor
    pub fn new(value: T, origin: ParameterOrigin) -> Self {
        ConfigValueAndOrigin::new_internal(value, origin)
    }
}

impl<T: AsRef<Path>> ConfigValueAndOrigin<T> {
    /// Switch to [`FormatPath`]
    pub fn display_path(self) -> ConfigValueAndOrigin<T, FormatPath<T>> {
        ConfigValueAndOrigin::new_internal(self.value, self.origin)
    }
}

impl<T: Debug> ConfigValueAndOrigin<T> {
    /// Switch to [`FormatDebug`]
    pub fn display_as_debug(self) -> ConfigValueAndOrigin<T, FormatDebug<T>> {
        ConfigValueAndOrigin::new_internal(self.value, self.origin)
    }
}

/// Workaround that [`ConfigValueAndOrigin`] uses to display a value that doesn't
/// implement [`Display`] directly using some format, e.g. [`FormatPath`].
pub trait DisplayProxy {
    /// Associated type for which the implementor is proxying [`Display`] implementation.
    type Base: ?Sized;

    /// Similar to [`Display::fmt`], but uses an associated type instead of `self`.
    #[allow(clippy::missing_errors_doc)]
    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result;
}

/// Indicates formating of a value that implements [`Display`].
pub struct FormatDisplay<T>(PhantomData<T>);

impl<T: Display> DisplayProxy for FormatDisplay<T> {
    type Base = T;

    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{value}")
    }
}

/// Indicates formatting of a [`Path`] using [`Path::display`].
#[allow(missing_copy_implementations)]
pub struct FormatPath<T>(PhantomData<T>);

impl<T: AsRef<Path>> DisplayProxy for FormatPath<T> {
    type Base = T;

    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", value.as_ref().display())
    }
}

/// Indicates formatting using [`Debug`].
pub struct FormatDebug<T>(PhantomData<T>);

impl<T: Debug> DisplayProxy for FormatDebug<T> {
    type Base = T;

    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{value:?}")
    }
}

struct DisplayWithProxy<'a, T, F>(&'a T, PhantomData<F>);

impl<T, F> Display for DisplayWithProxy<'_, T, F>
where
    F: DisplayProxy<Base = T>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        <F as DisplayProxy>::fmt(self.0, f)
    }
}

impl<T, F> Display for ConfigValueAndOrigin<T, F>
where
    F: DisplayProxy<Base = T>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Self { origin, value, .. } = &self;
        let value = DisplayWithProxy(value, PhantomData::<F>);

        write!(f, "config origin: ")?;

        match origin {
            ParameterOrigin::File { id, path } => write!(
                f,
                "parameter `{id}` with value `{value}` in file `{}`",
                path.display()
            ),
            ParameterOrigin::Env { id, var } => write!(
                f,
                "parameter `{id}` with value `{value}` set from environment variable `{var}`"
            ),
            ParameterOrigin::EnvUnknown { id } => write!(
                f,
                "parameter `{id}` with value `{value}` set from environment variables"
            ),
            ParameterOrigin::Default { id } => {
                write!(f, "parameter `{id}` with default value `{value}`")
            }
            ParameterOrigin::Custom { message } => write!(f, "{message}"),
        }
    }
}
