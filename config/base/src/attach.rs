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

#[derive(Constructor, Display, Debug)]
#[display(fmt = "file path: {}", "path.display()")]
pub struct FilePath {
    path: PathBuf,
}

#[derive(Constructor, Display, Debug)]
#[display(fmt = "actual value: {value}")]
pub struct ActualValue<T>
where
    T: Display + Debug,
{
    value: T,
}

#[derive(Constructor, Display, Debug)]
#[display(fmt = "expected: {message}")]
pub struct Expected<T>
where
    T: Display + Debug,
{
    message: T,
}

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

#[derive(Constructor, Display, Debug)]
#[display(fmt = "value: {var}={value}")]
pub struct EnvValue {
    var: String,
    value: String,
}

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
    pub fn new(value: T, origin: ParameterOrigin) -> Self {
        ConfigValueAndOrigin::new_internal(value, origin)
    }
}

impl<T: AsRef<Path>> ConfigValueAndOrigin<T> {
    pub fn display_path(self) -> ConfigValueAndOrigin<T, FormatPath<T>> {
        ConfigValueAndOrigin::new_internal(self.value, self.origin)
    }
}

impl<T: Debug> ConfigValueAndOrigin<T> {
    pub fn display_as_debug(self) -> ConfigValueAndOrigin<T, FormatDebug<T>> {
        ConfigValueAndOrigin::new_internal(self.value, self.origin)
    }
}

pub trait DisplayProxy {
    type Base: ?Sized;

    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result;
}

pub struct FormatDisplay<T>(PhantomData<T>);

impl<T: Display> DisplayProxy for FormatDisplay<T> {
    type Base = T;

    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{value}")
    }
}

#[allow(missing_copy_implementations)]
pub struct FormatPath<T>(PhantomData<T>);

impl<T: AsRef<Path>> DisplayProxy for FormatPath<T> {
    type Base = T;

    fn fmt(value: &Self::Base, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", value.as_ref().display())
    }
}

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
