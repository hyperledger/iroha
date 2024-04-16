use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    marker::PhantomData,
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

pub trait ReadConfig: Sized {
    fn read(reader: ConfigReader) -> (OkAfterFinish<Self>, ConfigReader);
}

#[derive(Debug, thiserror::Error)]
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
    Custom { msg: String },
}

#[derive(Error, Debug)]
#[error("{0}")]
struct EnvError(String);

impl Error {
    pub fn custom(message: impl AsRef<str>) -> Self {
        Self::Custom {
            msg: message.as_ref().to_string(),
        }
    }
}

pub struct ConfigReader {
    sources: Vec<TomlSource>,
    nesting: Vec<String>,
    errors_by_source: BTreeMap<PathBuf, Vec<Report<Error>>>,
    errors_in_env: Vec<Report<EnvError>>,
    existing_parameters: BTreeSet<ParameterId>,
    missing_parameters: BTreeSet<ParameterId>,
    bomb: DropBomb,
    env: Box<dyn ReadEnv>,
}

impl std::fmt::Debug for ConfigReader {
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
    /// Create a new config reader
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
    pub fn read_parameter<T>(mut self, id: impl Into<ParameterId>) -> ParameterReader<T>
    where
        for<'de> T: Deserialize<'de>,
    {
        let id = self.full_id(id);
        self.collect_parameter(&id);
        ParameterReader::new(self, id).fetch()
    }

    /// Delegates reading to another implementor of [`ReadConfig`] under a certain namespace.
    /// All parameter IDs in it will be resolved within that namespace.
    #[must_use]
    pub fn read_nested<T: ReadConfig>(
        mut self,
        namespace: impl AsRef<str>,
    ) -> (OkAfterFinish<T>, Self) {
        self.nesting.push(namespace.as_ref().to_string());
        let (value, mut reader) = T::read(self);
        reader.nesting.pop();
        (value, reader)
    }

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

    pub fn read_and_complete<T: ReadConfig>(self) -> Result<T, Error> {
        let (value, reader) = T::read(self);
        reader.into_result()?;
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
            self.collect_deserialize_error(&source, id, error.into());
        }

        if errored {
            Err(())
        } else {
            Ok(value)
        }
    }
}

#[derive(Debug)]
pub struct CustomEnvFetcher<'a> {
    reader: &'a mut ConfigReader,
    parameter: &'a ParameterId,
}

impl<'a> CustomEnvFetcher<'a> {
    fn new(reader: &'a mut ConfigReader, parameter: &'a ParameterId) -> Self {
        Self { reader, parameter }
    }

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
    type Context: Context;

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

pub struct ParameterReader<T> {
    reader: ConfigReader,
    id: ParameterId,
    value: Option<WithOrigin<T>>,
    errored: bool,
}

impl<T> ParameterReader<T> {
    fn new(reader: ConfigReader, id: ParameterId) -> Self {
        Self {
            reader,
            id,
            value: None,
            errored: false,
        }
    }
}

impl<T> ParameterReader<T>
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

impl<T> ParameterReader<T>
where
    T: FromEnvStr,
{
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

impl<T> ParameterReader<T>
where
    T: CustomEnvRead,
{
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

impl<T> ParameterReader<T> {
    /// [`None`] here means that the error of the parameter absense is stored in the reader.
    #[must_use]
    pub fn value_required(mut self) -> ParameterWithValue<T> {
        match (self.errored, self.value) {
            (false, Some(value)) => ParameterWithValue::with_value(self.reader, value),
            (false, None) => {
                self.reader.collect_missing_parameter(&self.id);
                ParameterWithValue::errored(self.reader)
            }
            (true, _) => ParameterWithValue::errored(self.reader),
        }
    }

    #[must_use]
    pub fn value_or_else<F: FnOnce() -> T>(self, fun: F) -> ParameterWithValue<T> {
        match (self.errored, self.value) {
            (false, Some(value)) => ParameterWithValue::with_value(self.reader, value),
            (false, None) => {
                log::trace!("parameter `{}`: fallback to default value", self.id);
                ParameterWithValue::with_value(
                    self.reader,
                    WithOrigin::new(fun(), ParameterOrigin::default(self.id.clone())),
                )
            }
            (true, _) => ParameterWithValue::errored(self.reader),
        }
    }

    #[must_use]
    pub fn value_optional(self) -> ParameterWithValue<T, FinishOptional> {
        match (self.errored, self.value) {
            (false, value) => ParameterWithValue::with_optional_value(self.reader, value),
            (true, _) => ParameterWithValue::errored(self.reader),
        }
    }
}

impl<T: Default> ParameterReader<T> {
    /// Equivalent of [`ParameterReader::value_or_else`] with [`Default::default`].
    #[must_use]
    pub fn value_or_default(self) -> ParameterWithValue<T> {
        self.value_or_else(Default::default)
    }
}

#[allow(missing_copy_implementations)]
pub struct FinishOptional;

#[allow(missing_copy_implementations)]
pub struct FinishRequired;

pub enum ParameterWithValue<T, Finish = FinishRequired> {
    Errored {
        reader: ConfigReader,
        _f: PhantomData<Finish>,
    },
    WithValue {
        reader: ConfigReader,
        value: WithOrigin<T>,
    },
    WithOptionalValue {
        reader: ConfigReader,
        value: Option<WithOrigin<T>>,
    },
}

impl<T, Finish> ParameterWithValue<T, Finish> {
    fn errored(reader: ConfigReader) -> Self {
        Self::Errored {
            reader,
            _f: PhantomData,
        }
    }
}

impl<T> ParameterWithValue<T, FinishOptional> {
    fn with_optional_value(reader: ConfigReader, value: Option<WithOrigin<T>>) -> Self {
        Self::WithOptionalValue { reader, value }
    }

    #[must_use]
    pub fn finish(self) -> (OkAfterFinish<Option<T>>, ConfigReader) {
        match self {
            Self::Errored { reader, .. } => (OkAfterFinish::errored(), reader),
            Self::WithOptionalValue { reader, value } => (
                OkAfterFinish::value(value.map(WithOrigin::into_value)),
                reader,
            ),
            Self::WithValue { .. } => unreachable!(),
        }
    }

    #[must_use]
    pub fn finish_with_origin(self) -> (OkAfterFinish<Option<WithOrigin<T>>>, ConfigReader) {
        match self {
            Self::Errored { reader, .. } => (OkAfterFinish::errored(), reader),
            Self::WithOptionalValue { reader, value } => (OkAfterFinish::value(value), reader),
            Self::WithValue { .. } => unreachable!(),
        }
    }
}

impl<T> ParameterWithValue<T, FinishRequired> {
    fn with_value(reader: ConfigReader, value: WithOrigin<T>) -> Self {
        Self::WithValue { reader, value }
    }

    #[must_use]
    pub fn finish(self) -> (OkAfterFinish<T>, ConfigReader) {
        match self {
            Self::Errored { reader, .. } => (OkAfterFinish::errored(), reader),
            Self::WithOptionalValue { .. } => unreachable!(),
            Self::WithValue { reader, value } => (OkAfterFinish::value(value.into_value()), reader),
        }
    }

    #[must_use]
    pub fn finish_with_origin(self) -> (OkAfterFinish<WithOrigin<T>>, ConfigReader) {
        match self {
            Self::Errored { reader, .. } => (OkAfterFinish::errored(), reader),
            Self::WithOptionalValue { .. } => unreachable!(),
            Self::WithValue { reader, value } => (OkAfterFinish::value(value), reader),
        }
    }
}

/// A value that should be accessed only if overall configuration reading succeeded.
///
/// I.e. it is guaranteed that [`OkAfterFinish::unwrap`] will not panic after associated
/// [`ConfigReader::into_result`] returns [`Ok`].
pub enum OkAfterFinish<T> {
    Errored,
    Value(T),
    ValueFn(Box<dyn FnOnce() -> T>),
}

impl<T> OkAfterFinish<T> {
    fn errored() -> Self {
        Self::Errored
    }

    fn value(value: T) -> Self {
        Self::Value(value)
    }

    pub fn value_fn<F>(fun: F) -> Self
    where
        F: FnOnce() -> T + 'static,
    {
        Self::ValueFn(Box::new(fun))
    }

    pub fn unwrap(self) -> T {
        match self {
            Self::Errored => panic!("`OkAfterFinish::unwrap` is supposed to be called only after `ConfigReader::into_result` returns OK; it is probably a bug"),
            Self::Value(value) => value,
            Self::ValueFn(fun) => fun()
        }
    }
}
