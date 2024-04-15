use std::{
    collections::{BTreeMap, BTreeSet},
    marker::PhantomData,
    path::{Path, PathBuf},
};

use drop_bomb::DropBomb;
use error_stack::{Context, Report, Result, ResultExt};
use serde::Deserialize;

use crate::{
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
    #[error("Failed to read configuration")]
    Root,
    #[error("Unable to read TOML from file")]
    TomlFromFile,
    #[error("Invalid `extends` field")]
    InvalidExtends,
    #[error("Failed to extend from another file")]
    CannotExtend,
    #[error("Failed to parse parameter `{0}`")]
    ParseParameter(ParameterId),
    #[error("Error while reading `{id}` parameter from `{var}` environment variable")]
    FromEnvWithId { id: ParameterId, var: String },
    #[error("Error while reading `{var}` environment variable")]
    FromEnv { var: String },
    #[error("Errors occurred while reading from file")]
    InSourceFile,
    #[error("Errors occurred while reading from environment variables")]
    InEnvironment,
    #[error("Some required parameters are missing")]
    MissingParameters,
    #[error("Some parameters aren't recognised")]
    UnknownParameters,
    #[error("{msg}")]
    Custom { msg: String },
}

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
    errors_in_env: Vec<Report<Error>>,
    errors_custom: Vec<Report<Error>>,
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
            errors_custom: <_>::default(),
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
        fn recursion(reader: &mut ConfigReader, path: impl AsRef<Path>) -> Result<(), Error> {
            let mut source =
                TomlSource::from_file(path.as_ref()).change_context(Error::TomlFromFile)?;
            let table = source.table_mut();

            if let Some(extends) = table.remove("extends") {
                let parsed: ExtendsPaths = extends.clone()
                    .try_into()
                    .attach_printable(r#"expected: a single path ("./file.toml") or an array of paths (["a.toml", "b.toml", "c.toml"])"#)
                    .attach_printable_lazy(|| format!("actual: {extends}"))
                    .change_context(Error::InvalidExtends)?;
                log::trace!("found `extends`: {:?}", parsed);
                for extends_path in parsed.iter() {
                    let full_path = path
                        .as_ref()
                        .parent()
                        .expect("it cannot be root or empty")
                        .join(extends_path);

                    recursion(reader, &full_path)
                        .change_context(Error::CannotExtend)
                        .attach_printable_lazy(|| {
                            format!("extending from: `{}`", full_path.display())
                        })?;
                }
            };

            reader.sources.push(source);

            Ok(())
        }

        recursion(&mut self, path.as_ref())
            .change_context(Error::Root)
            .map_err(|err| {
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

    /// A custom reading pipeline. See [`CustomValueRead`].
    #[must_use]
    pub fn read_custom<T: CustomValueRead>(mut self) -> (OkAfterFinish<T>, Self) {
        let mut fetcher = ConfigValueFetcher::new(&mut self);
        let result = T::read(&mut fetcher);

        let val = match result {
            Ok(value) => OkAfterFinish::value(value),
            Err(CustomValueReadError::WhileFetching) => OkAfterFinish::errored(),
            Err(CustomValueReadError::Other(error)) => {
                self.collect_custom_error(error);
                OkAfterFinish::errored()
            }
        };

        (val, self)
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
            emitter.emit(
                report
                    .change_context(Error::InSourceFile)
                    .attach_printable(format!("in file `{}`", source.display())),
            )
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

        for i in self.errors_custom {
            emitter.emit(i);
        }

        emitter.into_result().change_context(Error::Root)
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

    fn collect_env_error<C: Context>(
        &mut self,
        var: String,
        report: Report<C>,
        id: Option<ParameterId>,
    ) {
        self.errors_in_env
            .push(report.change_context(if let Some(id) = id {
                Error::FromEnvWithId { id, var }
            } else {
                Error::FromEnv { var }
            }))
    }

    fn collect_parameter(&mut self, id: &ParameterId) {
        self.existing_parameters.insert(id.clone());
    }

    fn collect_missing_parameter(&mut self, id: &ParameterId) {
        self.missing_parameters.insert(id.clone());
    }

    fn collect_custom_error(&mut self, report: Report<Error>) {
        self.errors_custom.push(report);
    }
}

#[derive(Debug)]
pub struct ConfigValueFetcher<'a> {
    reader: &'a mut ConfigReader,
}

impl<'a> ConfigValueFetcher<'a> {
    fn new(reader: &'a mut ConfigReader) -> Self {
        Self { reader }
    }

    pub fn fetch_parameter<T>(
        &mut self,
        id: &ParameterId,
    ) -> core::result::Result<Option<WithOrigin<T>>, FetchConsumedError>
    where
        for<'de> T: Deserialize<'de>,
    {
        self.reader.collect_parameter(id);

        let mut errored = false;
        let mut value = None;
        let mut deser_errors = Vec::default();

        for source in &self.reader.sources {
            if let Some(toml_value) = source.fetch(id) {
                let result: core::result::Result<T, _> = toml_value.try_into();
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
                        deser_errors.push((error, source.clone()));
                    }
                }
            } else {
                log::trace!(
                    "parameter `{id}`: not found in `{}`",
                    source.path().display()
                )
            }
        }

        for (error, source) in deser_errors {
            self.reader
                .collect_deserialize_error(&source, id, error.into());
        }

        if errored {
            Err(FetchConsumedError)
        } else {
            Ok(value)
        }
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
            match T::from_env_str(raw_str) {
                Ok(value) => {
                    log::trace!("parameterless environment read: `{var}` found and parsed");
                    Ok(Some(WithOrigin::new(
                        value,
                        ParameterOrigin::env(var.to_string(), None),
                    )))
                }
                Err(error) => {
                    self.reader
                        .collect_env_error(var.to_string(), error.into(), None);
                    Err(FetchConsumedError)
                }
            }
        } else {
            log::trace!("parameterless environment read: `{var}` not found");
            Ok(None)
        }
    }
}

/// Custom reading of a value from the config.
///
/// Gives a simplified API to read parameters from sources and environment
/// (via [`ConfigValueFetcher`]), implementing parsing, error collection, and tracing under the
/// hood.
///
/// It allows implementing unusual logic such as composing a value from
/// multiple environment variables.
pub trait CustomValueRead: Sized {
    fn read<'a>(
        fetcher: &'a mut ConfigValueFetcher<'a>,
    ) -> core::result::Result<Self, CustomValueReadError>;
}

/// An error indicating what went wrong while [`CustomValueRead::read`].
pub enum CustomValueReadError {
    /// An error occured while fetching a value from [`ConfigValueFetcher`]
    WhileFetching,
    /// Some other error. If nothing fits your case, look at [`Error::custom`].
    Other(Report<Error>),
}

/// An error occured and consumed within [`ConfigValueFetcher`].
///
/// If you face it within [`CustomValueRead::read`], you only need to forward it with `?`
/// (which will transform it into [`CustomValueReadError::WhileFetching`])
#[derive(Copy, Clone, Debug)]
pub struct FetchConsumedError;

impl From<FetchConsumedError> for CustomValueReadError {
    fn from(_: FetchConsumedError) -> Self {
        Self::WhileFetching
    }
}

impl From<Report<Error>> for CustomValueReadError {
    fn from(err: Report<Error>) -> Self {
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
        match ConfigValueFetcher::new(&mut self.reader).fetch_parameter(&self.id) {
            Ok(value) => {
                self.value = value;
            }
            Err(FetchConsumedError) => {
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
            match (T::from_env_str(raw_str), self.errored) {
                (Err(error), _) => {
                    self.errored = true;
                    self.reader.collect_env_error(
                        var.to_string(),
                        Report::new(error),
                        Some(self.id.clone()),
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
                        ParameterOrigin::env(var.to_string(), Some(self.id.clone())),
                    ));
                }
                (Ok(_ignore), true) => {
                    log::trace!(
                        "parameter `{}`: found `{var}` env var, ignore due to previous errors",
                        self.id,
                    );
                }
            }
        } else {
            log::trace!("parameter `{}`: not found `{var}` env var", self.id)
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
