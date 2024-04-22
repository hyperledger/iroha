//! Configuration reader API.

use std::{
    collections::{BTreeMap, BTreeSet},
    convert::identity,
    fmt::Debug,
    path::{Path, PathBuf},
};

use drop_bomb::DropBomb;
use error_stack::{Context, Report, Result, ResultExt};
use serde::Deserialize;
use thiserror::Error;

use crate::{
    attach,
    attach::EnvValue,
    env::{FromEnvStr, ReadEnv},
    toml::TomlSource,
    util::{Emitter, ExtendsPaths},
    ParameterId, ParameterOrigin, WithOrigin,
};

/// A type that implements reading from [`ConfigReader`]
pub trait ReadConfig: Sized {
    /// Returns the [`FinalWrap`] with self and the reader itself, transformed
    /// throughout the process of reading.
    ///
    /// The wrap is guaranteed to unwrap safely if the reader emits
    /// no error upon [`ConfigReader::into_result`].
    fn read(reader: &mut ConfigReader) -> FinalWrap<Self>;
}

/// An umbrella error for various cases related to [`ConfigReader`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Failed to read configuration from file")]
    ReadFile,
    #[error("Invalid `extends` field")]
    InvalidExtends,
    #[error("Failed to extend configurations")]
    CannotExtend,
    #[error("Failed to parse parameter `{0}`")]
    ParseParameter(ParameterId),
    #[error("Errors occurred while reading from file: `{0}`")]
    InSourceFile(PathBuf),
    #[error("Errors occurred while reading from environment variables")]
    InEnvironment,
    #[error("Some required parameters are missing")]
    MissingParameters,
    #[error("Found unrecognised parameters")]
    UnknownParameters,
    #[error("{msg}")]
    Other { msg: String },
}

#[derive(Error, Debug)]
#[error("{0}")]
struct EnvError(String);

impl Error {
    /// Some other error message
    pub fn other(message: impl AsRef<str>) -> Self {
        Self::Other {
            msg: message.as_ref().to_string(),
        }
    }
}

/// The reader, which provides an API to accumulate config sources,
/// read parameters from them, override with environment variables, fallback to default values,
/// and finally, construct an exhaustive error report with as many errors, accumulated along the
/// way, as possible.
pub struct ConfigReader {
    /// The namespace this [`ConfigReader`] is handling. All the `ParameterId` handled will be prefixed with it.
    nesting: Vec<String>,
    /// File sources for the config
    sources: Vec<TomlSource>,
    /// Environment variables source for the config
    env: Box<dyn ReadEnv>,
    /// Errors accumulated per each file
    errors_by_source: BTreeMap<PathBuf, Vec<Report<Error>>>,
    /// Errors accumulated from the environment variables
    errors_in_env: Vec<Report<EnvError>>,
    /// A list of all the parameters that have been requested from this reader. Used to report unused (unknown) parameters in the toml file
    existing_parameters: BTreeSet<ParameterId>,
    /// A list of all required parameters that have been requested, but were not found
    missing_parameters: BTreeSet<ParameterId>,
    /// A runtime guard to prevent dropping the [`ConfigReader`] without handing errors
    bomb: DropBomb,
}

impl Debug for ConfigReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ConfigReader")
    }
}

impl Default for ConfigReader {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigReader {
    /// Constructor
    pub fn new() -> Self {
        Self {
            sources: <_>::default(),
            nesting: <_>::default(),
            errors_by_source: <_>::default(),
            errors_in_env: <_>::default(),
            existing_parameters: <_>::default(),
            missing_parameters: <_>::default(),
            bomb: DropBomb::new("forgot to call `ConfigReader::finish()`, didn't you?"),
            env: Box::new(crate::env::std_env),
        }
    }

    /// Replace default environment reader ([`std::env::var`]) with a custom one
    #[must_use]
    pub fn with_env(mut self, env: impl ReadEnv + 'static) -> Self {
        self.env = Box::new(env);
        self
    }

    /// Add a data source to read parameters from.
    #[must_use]
    pub fn with_toml_source(mut self, source: TomlSource) -> Self {
        self.sources.push(source);
        self
    }

    /// Reads a TOML file and handles its `extends` field, implementing mixins mechanism.
    ///
    /// # Errors
    ///
    /// If files reading error occurs
    pub fn read_toml_with_extends<P: AsRef<Path>>(mut self, path: P) -> Result<Self, Error> {
        fn recursion(
            reader: &mut ConfigReader,
            path: impl AsRef<Path>,
            depth: u8,
        ) -> Result<(), Error> {
            let mut source = TomlSource::from_file(path.as_ref())
                .attach_printable_lazy(|| attach::FilePath::new(path.as_ref().to_path_buf()))
                .change_context(Error::ReadFile)?;
            let table = source.table_mut();

            if let Some(extends) = table.remove("extends") {
                let parsed: ExtendsPaths = extends.clone()
                    .try_into()
                    .attach_printable_lazy(|| attach::Expected::new(r#"a single path ("./file.toml") or an array of paths (["a.toml", "b.toml", "c.toml"])"#))
                    .attach_printable_lazy(|| attach::ActualValue::new(extends))
                    .change_context(Error::InvalidExtends)?;
                log::trace!("found `extends`: {:?}", parsed);
                for extends_path in parsed.iter() {
                    let full_path = path
                        .as_ref()
                        .parent()
                        .expect("it cannot be root or empty")
                        .join(extends_path);

                    recursion(reader, &full_path, depth + 1).attach_printable_lazy(|| {
                        attach::ExtendsChain::new(path.as_ref().to_path_buf(), full_path, depth + 1)
                    })?;
                }
            };

            reader.sources.push(source);

            Ok(())
        }

        recursion(&mut self, path.as_ref(), 0).map_err(|err| {
            // error doesn't mean we need to panic
            self.bomb.defuse();
            err
        })?;

        Ok(self)
    }

    /// Instantiate a parameter reading pipeline.
    #[must_use]
    pub fn read_parameter<T>(&mut self, id: impl Into<ParameterId>) -> ReadingParameter<T>
    where
        for<'de> T: Deserialize<'de>,
    {
        let id = self.full_id(id);
        self.collect_parameter(&id);
        ReadingParameter::new(self, id).fetch()
    }

    /// Delegate reading to another implementor of [`ReadConfig`] under a certain namespace.
    /// All parameter IDs in it will be resolved within that namespace.
    #[must_use]
    pub fn read_nested<T: ReadConfig>(&mut self, namespace: impl AsRef<str>) -> FinalWrap<T> {
        self.nesting.push(namespace.as_ref().to_string());
        let value = T::read(self);
        self.nesting.pop();
        value
    }

    /// Finally, complete the reading procedure and emit a collective report
    /// in case if any error occurred along the reading process.
    ///
    /// # Errors
    /// If any occurred while reading of data.
    pub fn into_result(mut self) -> Result<(), Error> {
        self.bomb.defuse();
        let mut emitter = Emitter::new();

        if !self.missing_parameters.is_empty() {
            let mut report = Report::new(Error::MissingParameters);
            for i in self.missing_parameters {
                report = report.attach_printable(format!("missing parameter: `{i}`"));
            }
            emitter.emit(report);
        }

        // looking for unknown parameters
        for source in &self.sources {
            let unknown_parameters = source.find_unknown(self.existing_parameters.iter());
            if !unknown_parameters.is_empty() {
                let mut report = Report::new(Error::UnknownParameters);
                for i in unknown_parameters {
                    report = report.attach_printable(format!("unknown parameter: `{i}`"));
                }
                self.errors_by_source
                    .entry(source.path().clone())
                    .or_default()
                    .push(report);
            }
        }

        // emit reports by source
        for (source, reports) in self.errors_by_source {
            let mut local_emitter = Emitter::new();
            for report in reports {
                local_emitter.emit(report);
            }
            let report = local_emitter
                .into_result()
                .expect_err("there should be at least one error");
            emitter.emit(report.change_context(Error::InSourceFile(source)))
        }

        // environment parsing errors
        if !self.errors_in_env.is_empty() {
            let mut local_emitter = Emitter::new();
            for report in self.errors_in_env {
                local_emitter.emit(report);
            }
            let report = local_emitter
                .into_result()
                .expect_err("there should be at least one error");
            emitter.emit(report.change_context(Error::InEnvironment));
        }

        emitter.into_result()
    }

    /// A shorthand to "just read the config and get an error or the value".
    /// # Errors
    /// See [`Self::into_result`]
    pub fn read_and_complete<T: ReadConfig>(mut self) -> Result<T, Error> {
        let value = T::read(&mut self);
        self.into_result()?;
        Ok(value.unwrap())
    }

    fn full_id(&self, id: impl Into<ParameterId>) -> ParameterId {
        self.nesting.iter().chain(id.into().segments.iter()).into()
    }

    fn collect_deserialize_error<C: Context>(
        &mut self,
        source: &TomlSource,
        path: &ParameterId,
        report: Report<C>,
    ) {
        self.errors_by_source
            .entry(source.path().clone())
            .or_default()
            .push(report.change_context(Error::ParseParameter(path.clone())));
    }

    fn collect_env_error(&mut self, report: Report<EnvError>) {
        self.errors_in_env.push(report)
    }

    fn collect_parameter(&mut self, id: &ParameterId) {
        self.existing_parameters.insert(id.clone());
    }

    fn collect_missing_parameter(&mut self, id: &ParameterId) {
        self.missing_parameters.insert(id.clone());
    }

    fn fetch_parameter<T>(
        &mut self,
        id: &ParameterId,
    ) -> core::result::Result<Option<WithOrigin<T>>, ()>
    where
        for<'de> T: Deserialize<'de>,
    {
        self.collect_parameter(id);

        let mut errored = false;
        let mut value = None;
        let mut errors = Vec::default();

        for source in &self.sources {
            if let Some(toml_value) = source.fetch(id) {
                // FIXME: Avoid cloning.
                //        Currently cloning is performed for the sake of a better error message.
                //        In future, it might be replaced with a rendered source TOML and span to it
                let result: core::result::Result<T, _> = toml_value.clone().try_into();
                match (result, errored) {
                    (Ok(v), false) => {
                        if value.is_none() {
                            log::trace!("parameter `{id}`: found in `{}`", source.path().display());
                        } else {
                            log::trace!(
                                "parameter `{id}`: found in `{}`, overwriting previous value",
                                source.path().display()
                            );
                        }
                        value = Some(WithOrigin::new(
                            v,
                            ParameterOrigin::file(id.clone(), source.path().clone()),
                        ));
                    }
                    // we don't care if there was an error before
                    (Ok(_), true) => {}
                    (Err(error), _) => {
                        errored = true;
                        value = None;
                        errors.push((
                            Report::new(error).attach_printable(format!("value: {toml_value}")),
                            source.clone(),
                        ));
                    }
                }
            } else {
                log::trace!(
                    "parameter `{id}`: not found in `{}`",
                    source.path().display()
                )
            }
        }

        for (error, source) in errors {
            self.collect_deserialize_error(&source, id, error);
        }

        if errored {
            Err(())
        } else {
            Ok(value)
        }
    }
}

/// A thin layer for [`CustomEnvRead::read`].
#[derive(Debug)]
pub struct CustomEnvFetcher<'a> {
    reader: &'a mut ConfigReader,
    parameter: &'a ParameterId,
}

impl<'a> CustomEnvFetcher<'a> {
    fn new(reader: &'a mut ConfigReader, parameter: &'a ParameterId) -> Self {
        Self { reader, parameter }
    }

    /// Read and parse an environment variable
    /// # Errors
    /// If a parsing failure occurs.
    /// The reader collects the error itself, and this function returns blank [`FetchConsumedError`].
    pub fn fetch_env<T>(
        &mut self,
        var: impl AsRef<str>,
    ) -> core::result::Result<Option<WithOrigin<T>>, FetchConsumedError>
    where
        T: FromEnvStr,
    {
        let var = var.as_ref();
        if let Some(raw_str) = self.reader.env.read_env(var) {
            match T::from_env_str(raw_str.clone()) {
                Ok(value) => {
                    log::trace!(
                        "parameter `{}`: env var `{var}` found and parsed",
                        self.parameter
                    );
                    Ok(Some(WithOrigin::new(
                        value,
                        ParameterOrigin::env(self.parameter.clone(), var.to_string()),
                    )))
                }
                Err(error) => {
                    self.reader.collect_env_error(
                        Report::new(error)
                            .attach_printable(EnvValue::new(var.to_string(), raw_str.into_owned()))
                            .change_context(EnvError(format!(
                                "Failed to parse parameter `{}` from `{var}`",
                                self.parameter
                            ))),
                    );
                    Err(FetchConsumedError)
                }
            }
        } else {
            log::trace!("parameter `{}`: env var `{var}` not found", self.parameter);
            Ok(None)
        }
    }
}

/// Custom reading of a value from environment.
///
/// Gives a simplified API to read parameters from environment
/// (via [`CustomEnvFetcher`]), implementing parsing, error collection, and tracing under the
/// hood.
///
/// It allows implementing unusual logic such as composing a value from
/// multiple environment variables.
pub trait CustomEnvRead: Sized {
    /// [`Context`] of a possible error, given as [`CustomEnvReadError::Other`].
    /// Use [`std::convert::Infallible`] if you don't need one.
    type Context: Context;

    /// The reading using [`CustomEnvFetcher`] to access any env variable of choice
    /// through the API provided by the reader.
    /// # Errors
    /// Up to an implementor
    fn read<'a>(
        fetcher: &'a mut CustomEnvFetcher<'a>,
    ) -> core::result::Result<Option<Self>, CustomEnvReadError<Self::Context>>;
}

/// An error indicating what went wrong while [`CustomEnvRead::read`].
pub enum CustomEnvReadError<C> {
    /// An error occurred while fetching a value from [`CustomEnvFetcher`]
    WhileFetching,
    /// Some other error
    Other(Report<C>),
}

/// An error occurred and consumed within [`CustomEnvFetcher`].
///
/// If you face it within [`CustomEnvRead::read`], you only need to forward it with `?`
/// (which will transform it into [`CustomEnvReadError::WhileFetching`])
#[derive(Copy, Clone, Debug)]
pub struct FetchConsumedError;

impl<C> From<FetchConsumedError> for CustomEnvReadError<C> {
    fn from(_: FetchConsumedError) -> Self {
        Self::WhileFetching
    }
}

impl<C> From<Report<C>> for CustomEnvReadError<C> {
    fn from(err: Report<C>) -> Self {
        Self::Other(err)
    }
}

/// A state of reading a certain configuration parameter.
pub struct ReadingParameter<'reader, T> {
    reader: &'reader mut ConfigReader,
    id: ParameterId,
    value: Option<WithOrigin<T>>,
    errored: bool,
}

impl<'reader, T> ReadingParameter<'reader, T> {
    fn new(reader: &'reader mut ConfigReader, id: ParameterId) -> Self {
        Self {
            reader,
            id,
            value: None,
            errored: false,
        }
    }
}

impl<T> ReadingParameter<'_, T>
where
    for<'de> T: Deserialize<'de>,
{
    #[must_use]
    fn fetch(mut self) -> Self {
        match self.reader.fetch_parameter(&self.id) {
            Ok(value) => {
                self.value = value;
            }
            Err(()) => {
                self.errored = true;
            }
        }

        self
    }
}

impl<T> ReadingParameter<'_, T>
where
    T: FromEnvStr,
{
    /// Reads an environment variable and parses the value which is [`FromEnvStr`].
    #[must_use]
    pub fn env(mut self, var: impl AsRef<str>) -> Self {
        let var = var.as_ref();
        if let Some(raw_str) = self.reader.env.read_env(var) {
            match (T::from_env_str(raw_str.clone()), self.errored) {
                (Err(error), _) => {
                    self.errored = true;
                    self.reader.collect_env_error(
                        Report::new(error)
                            .attach_printable(EnvValue::new(var.to_string(), raw_str.into_owned()))
                            .change_context(EnvError(format!(
                                "Failed to parse parameter `{}` from `{var}`",
                                self.id,
                            ))),
                    );
                }
                (Ok(value), false) => {
                    if self.value.is_none() {
                        log::trace!("parameter `{}`: found `{var}` env var", self.id,);
                    } else {
                        log::trace!(
                            "parameter `{}`: found `{var}` env var, overwriting previous value",
                            self.id,
                        );
                    }
                    self.value = Some(WithOrigin::new(
                        value,
                        ParameterOrigin::env(self.id.clone(), var.to_string()),
                    ));
                }
                (Ok(_ignore), true) => {
                    log::trace!(
                        "parameter `{}`: env var `{var}` found, ignore due to previous errors",
                        self.id,
                    );
                }
            }
        } else {
            log::trace!("parameter `{}`: env var `{var}` not found", self.id)
        }

        self
    }
}

impl<T> ReadingParameter<'_, T>
where
    T: CustomEnvRead,
{
    /// Delegates reading of environment in a free way if the value type is [`CustomEnvRead`].
    #[must_use]
    pub fn env_custom(mut self) -> Self {
        let mut fetcher = CustomEnvFetcher::new(&mut self.reader, &self.id);

        match (T::read(&mut fetcher), self.errored) {
            (Ok(Some(value)), false) => {
                if self.value.is_none() {
                    log::trace!("parameter `{}`: found in env vars", self.id,);
                } else {
                    log::trace!(
                        "parameter `{}`: found in env vars, overwriting previous value",
                        self.id,
                    );
                }

                self.value = Some(WithOrigin::new(
                    value,
                    ParameterOrigin::env_unknown(self.id.clone()),
                ));
            }
            (Ok(Some(_)), true) => {
                log::trace!(
                    "parameter `{}`: found in env vars, ignore due to previous errors",
                    self.id,
                );
            }
            (Err(error), _) => {
                self.errored = true;

                match error {
                    CustomEnvReadError::WhileFetching => {}
                    CustomEnvReadError::Other(report) => {
                        self.reader
                            .collect_env_error(report.change_context(EnvError(format!(
                                "Failed to parse parameter `{}`",
                                self.id
                            ))));
                    }
                }
            }
            (Ok(None), _) => {}
        }

        self
    }
}

impl<T> ReadingParameter<'_, T> {
    /// Finish reading, and if the value is not read so far, it will be reported later on [`ConfigReader::into_result`].
    #[must_use]
    pub fn value_required(self) -> ReadingDone<T> {
        match (self.errored, self.value) {
            (false, Some(value)) => ReadingDone(ReadingDoneValue::Fine(value)),
            (false, None) => {
                self.reader.collect_missing_parameter(&self.id);
                ReadingDone(ReadingDoneValue::Errored)
            }
            (true, _) => ReadingDone(ReadingDoneValue::Errored),
        }
    }

    /// Finish reading, falling back to a default value if it is absent
    #[must_use]
    pub fn value_or_else<F: FnOnce() -> T>(self, fun: F) -> ReadingDone<T> {
        match (self.errored, self.value) {
            (false, Some(value)) => ReadingDone(ReadingDoneValue::Fine(value)),
            (false, None) => {
                log::trace!("parameter `{}`: fallback to default value", self.id);
                ReadingDone(ReadingDoneValue::Fine(WithOrigin::new(
                    fun(),
                    ParameterOrigin::default(self.id.clone()),
                )))
            }
            (true, _) => ReadingDone(ReadingDoneValue::Errored),
        }
    }

    /// Finish reading, allowing value to be not present
    #[must_use]
    pub fn value_optional(self) -> OptionReadingDone<T> {
        match (self.errored, self.value) {
            (false, value) => OptionReadingDone(ReadingDoneValue::Fine(value)),
            (true, _) => OptionReadingDone(ReadingDoneValue::Errored),
        }
    }
}

// TODO check lifetime redundancy
impl<T: Default> ReadingParameter<'_, T> {
    /// Equivalent of [`ReadingParameter::value_or_else`] with [`Default::default`].
    #[must_use]
    pub fn value_or_default(self) -> ReadingDone<T> {
        self.value_or_else(Default::default)
    }
}

enum ReadingDoneValue<T> {
    Errored,
    Fine(T),
}

impl<T> ReadingDoneValue<T> {
    fn into_final(self) -> FinalWrap<T> {
        self.into_final_with(identity)
    }

    fn into_final_with<F, U>(self, f: F) -> FinalWrap<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Self::Errored => FinalWrap(FinalWrapInner::Errored),
            Self::Fine(t) => FinalWrap(FinalWrapInner::Value(f(t))),
        }
    }
}

/// A state of reading when the parameter's value is read, and the next step is to finish it via
/// [`ReadingDone::finish`] or [`ReadingDone::finish_with_origin`]
pub struct ReadingDone<T>(ReadingDoneValue<WithOrigin<T>>);

/// Same as [`ReadingDone`], but holding an optional value.
pub struct OptionReadingDone<T>(ReadingDoneValue<Option<WithOrigin<T>>>);

impl<T> ReadingDone<T> {
    /// Finish with the value only.
    #[must_use]
    pub fn finish(self) -> FinalWrap<T> {
        self.0.into_final_with(WithOrigin::into_value)
    }

    /// Finish with the value and its origin
    #[must_use]
    pub fn finish_with_origin(self) -> FinalWrap<WithOrigin<T>> {
        self.0.into_final()
    }
}

impl<T> OptionReadingDone<T> {
    /// Finish with the value only
    #[must_use]
    pub fn finish(self) -> FinalWrap<Option<T>> {
        self.0.into_final_with(|x| x.map(WithOrigin::into_value))
    }

    /// Finish with the value and its origin
    #[must_use]
    pub fn finish_with_origin(self) -> FinalWrap<Option<WithOrigin<T>>> {
        self.0.into_final()
    }
}

/// A value that should be accessed only if overall configuration reading succeeded.
///
/// I.e. it is guaranteed that [`FinalWrap::unwrap`] will not panic after associated
/// [`ConfigReader::into_result`] returns [`Ok`].
#[allow(missing_docs)]
pub struct FinalWrap<T>(FinalWrapInner<T>);

/// Exists to not expose enum variants if they were in [`FinalWrap`]
enum FinalWrapInner<T> {
    Errored,
    Value(T),
    ValueFn(Box<dyn FnOnce() -> T>),
}

impl<T> FinalWrap<T> {
    /// Pass a closure that will emit the value on [`Self::unwrap`].
    pub fn value_fn<F>(fun: F) -> Self
    where
        F: FnOnce() -> T + 'static,
    {
        Self(FinalWrapInner::ValueFn(Box::new(fun)))
    }

    /// Unwrap the value inside.
    ///
    /// Can be safely called only after the [`ConfigReader::into_result`] returned [Ok].
    ///
    /// # Panics
    /// Might panic if an error occurred while reading of this certain value.
    pub fn unwrap(self) -> T {
        match self.0 {
            FinalWrapInner::Errored => panic!("`FinalWrap::unwrap` is supposed to be called only after `ConfigReader::into_result` returns OK; it is probably a bug"),
            FinalWrapInner::Value(value) => value,
            FinalWrapInner::ValueFn(fun) => fun()
        }
    }
}
